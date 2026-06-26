import os
import random
import re
import secrets
import smtplib
import ssl
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import bcrypt
import ldap3
import pyotp
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import RedirectResponse
from pydantic import BaseModel
from ldap3.core.exceptions import LDAPException, LDAPOperationResult

from models import RESOURCE_CATALOG, ROLE_RESOURCES, RESOURCE_DUMMY_DATA, PeerStore, SESSION_TTL
import proxy as proxy_module
from proxy import ProxyRouter, ProxyRoute
from ad_auth import authenticate_ad_user, ADAuthError, ADConfig, _extract_group_cns, _resolve_role

APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")

app = FastAPI(title="Zero Trust IAM Gateway")
app.state.SECRET_KEY = APP_SECRET_KEY

store = PeerStore()
proxy_router = ProxyRouter()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ─── REVERSE PROXY MIDDLEWARE (Policy Enforcement Point) ────────────────

PROXY_EXEMPT_PATHS = {"/", "/login", "/admin", "/employee", "/email-verification", "/favicon.ico"}
PROXY_EXEMPT_PREFIXES = {"/api/"}


def _extract_session_token(request: Request) -> str:
    token = request.cookies.get("session") or ""
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    return token


def _render_forbidden(reason: str) -> HTMLResponse:
    body = proxy_module.FORBIDDEN_HTML.format(reason=reason)
    return HTMLResponse(content=body, status_code=403)


@app.middleware("http")
async def reverse_proxy_middleware(request: Request, call_next):
    path = request.url.path

    # ── Pass through non-proxy paths ────────────────────────────────────
    if path in PROXY_EXEMPT_PATHS or any(path.startswith(p) for p in PROXY_EXEMPT_PREFIXES):
        return await call_next(request)

    route = proxy_router.match(path)
    if route is None:
        return await call_next(request)

    # ── Step 1: Extract and validate session ────────────────────────────
    session_token = _extract_session_token(request)
    if not session_token:
        store.add_log("DENY", f"Proxy blocked (no session) → {path}")
        return _render_forbidden("No active session. Please log in.")

    session = store.get_session(session_token)
    if not session:
        response = _render_forbidden("Session expired. Please re-authenticate.")
        response.delete_cookie("session", path="/")
        store.add_log("DENY", f"Proxy blocked (expired session) → {path}")
        return response

    username = session["username"]

    # ── Step 2: Verify MFA was completed ────────────────────────────────
    if not session.get("mfa_verified"):
        store.add_log("DENY", f"'{username}' blocked (MFA not verified) → {path}")
        response = _render_forbidden("Multi-factor authentication not completed.")
        response.delete_cookie("session", path="/")
        return response

    # ── Step 3: Verify user exists in policy store ──────────────────────
    user = store.get_user(username)
    if not user:
        store.add_log("DENY", f"'{username}' not found in policy store → {path}")
        response = _render_forbidden("User account not found.")
        response.delete_cookie("session", path="/")
        return response

    # ── Step 4: Check resource authorization ────────────────────────────
    if route.resource_id not in user["allowed_resources"]:
        store.add_log("DENY", f"'{username}' unauthorized for {route.resource_id} → {path}")
        return _render_forbidden(
            f"You do not have permission to access this resource. "
            f"Contact your administrator to request access to "
            f"<strong>{route.resource_id}</strong>."
        )

    # ── Step 5: Device posture check (log-only, non-blocking) ───────────
    posture = store._device_posture.get(user.get("vpn_ip", ""))
    if posture and posture.get("firewall") == "Disabled":
        store.add_log("RISK", f"'{username}' non-compliant device accessing {route.resource_id}")

    # ── Step 6: Slide session expiry ────────────────────────────────────
    store.touch_session(session_token)

    # ── Step 7: Forward with identity ───────────────────────────────────
    identity = {
        "username": username,
        "role": user.get("role", ""),
        "email": user.get("email", ""),
        "groups": user.get("groups", []),
    }
    store.add_log("ACCESS", f"'{username}' proxied → {route.resource_id} ({route.backend}{path})")
    return await proxy_router.forward(request, route, identity=identity)


def _make_session_response(data: dict, token: str) -> JSONResponse:
    ACTIVE_SESSIONS[data["username"]] = {
        "token": token,
        "username": data["username"],
        "role": data.get("role", ""),
        "login_time": time.time(),
    }
    response = JSONResponse(content=data)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=SESSION_TTL,
        path="/",
    )
    return response


async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != os.environ.get("API_SECRET_KEY"):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API key")


class LoginRequest(BaseModel): username: str; password: str
class CreateUserRequest(BaseModel): username: str; password: str; vpn_ip: str; role: str
class ModifyPermRequest(BaseModel): username: str; resource_id: str; action: str
class AccessRequest(BaseModel): username: str; resource_id: str
class MFAVerifyRequest(BaseModel): username: str; token: str
class MFALoginVerifyRequest(BaseModel): preauth_token: str; token: str
class EmailOTPVerifyRequest(BaseModel): email_otp_token: str; otp: str
class BackupCodeVerifyRequest(BaseModel): preauth_token: str; backup_code: str
class SessionToken(BaseModel): token: str
class AdminResetPasswordRequest(BaseModel): username: str; new_password: str
class AdminActionRequest(BaseModel): username: str

_preauth_tokens: dict[str, dict] = {}

def _read_html(name):
    return HTMLResponse(content=(Path(__file__).parent / name).read_text(encoding="utf-8"))


# ─── PAGES ───

@app.get("/", include_in_schema=False)
async def root(): return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(): return _read_html("login.html")

@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_page(): return _read_html("admin.html")

@app.get("/employee", response_class=HTMLResponse, include_in_schema=False)
async def employee_page(): return _read_html("employee.html")

@app.get("/email-verification", response_class=HTMLResponse, include_in_schema=False)
async def email_verification_page(): return _read_html("email-verification.html")


# ─── AUTH ───

TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "Zero Trust IAM Gateway")
MFA_TOKEN_EXPIRY = 600  # 10 minutes

# ─── LDAP SYNC HELPERS ────────────────────────────────────────────────────


def _ldap_user_dn(username: str) -> str:
    base = os.environ.get("LDAP_BASE_DN", "dc=CHANGE_ME,dc=local")
    return f"uid={username},ou=Users,{base}"


def _get_ldap_admin_conn() -> Optional[ldap3.Connection]:
    """Return an LDAP connection bound with admin credentials, or None if LDAP is not configured."""
    if not ADConfig.is_configured():
        return None
    cfg = ADConfig.from_env()
    server = ldap3.Server(
        cfg.server,
        connect_timeout=cfg.connect_timeout,
    )
    try:
        conn = ldap3.Connection(
            server,
            user=cfg.bind_dn,
            password=cfg.bind_password,
            auto_bind=True,
            receive_timeout=cfg.receive_timeout,
        )
        return conn
    except LDAPException:
        store.add_log("LDAP_SYNC", "Failed to bind to LDAP server for admin operation")
        return None


# ─── DEMO USER FALLBACK DATA MAPS ────────────────────────────────────────

ACTIVE_SESSIONS: dict[str, dict] = {}

USER_RESOURCE_OVERRIDES: dict[str, list[str]] = {
    "jay": ["accounting_db", "crm_system", "analytics_dash", "it_assets", "document_vault"],
    "luffy": ["crm_system", "document_vault"],
    "zoro": ["devops_server", "it_assets"],
}

USER_OS_PROFILES: dict[str, str] = {
    "jay": "macOS 15.2",
    "luffy": "Windows 11 Enterprise",
    "zoro": "Ubuntu 24.04 LTS",
}


def _ldap_sync_create_user(username: str, password: str, email: str, display_name: str) -> None:
    conn = _get_ldap_admin_conn()
    if conn is None:
        return
    dn = _ldap_user_dn(username)
    try:
        conn.add(dn, attributes={
            "objectClass": ["inetOrgPerson", "top"],
            "uid": username,
            "cn": display_name or username,
            "sn": display_name or username,
            "userPassword": password,
            "mail": email or "",
        })
        if conn.result["result"] != 0:
            raise LDAPException(f"LDAP add failed: {conn.result['description']} — {conn.result['message']}")
        store.add_log("LDAP_SYNC", f"User '{username}' created in LDAP ({dn})")
    except LDAPException as exc:
        store.add_log("LDAP_SYNC_FAIL", f"Failed to create '{username}' in LDAP: {exc}")
        raise HTTPException(status_code=502, detail=f"LDAP sync failed: {exc}")
    finally:
        conn.unbind()


def _ldap_sync_delete_user(username: str) -> None:
    conn = _get_ldap_admin_conn()
    if conn is None:
        return
    dn = _ldap_user_dn(username)
    try:
        conn.delete(dn)
        if conn.result["result"] not in (0, 32):  # 32 = noSuchObject (already deleted)
            raise LDAPException(f"LDAP delete failed: {conn.result['description']} — {conn.result['message']}")
        store.add_log("LDAP_SYNC", f"User '{username}' deleted from LDAP ({dn})")
    except LDAPException as exc:
        store.add_log("LDAP_SYNC_FAIL", f"Failed to delete '{username}' from LDAP: {exc}")
        raise HTTPException(status_code=502, detail=f"LDAP sync failed: {exc}")
    finally:
        conn.unbind()


def _ldap_sync_change_password(username: str, new_password: str) -> None:
    conn = _get_ldap_admin_conn()
    if conn is None:
        return
    dn = _ldap_user_dn(username)
    try:
        conn.modify(dn, {"userPassword": [(ldap3.MODIFY_REPLACE, [new_password])]})
        if conn.result["result"] != 0:
            raise LDAPException(f"LDAP modify failed: {conn.result['description']} — {conn.result['message']}")
        store.add_log("LDAP_SYNC", f"Password updated in LDAP for '{username}'")
    except LDAPException as exc:
        store.add_log("LDAP_SYNC_FAIL", f"Failed to update password for '{username}' in LDAP: {exc}")
        raise HTTPException(status_code=502, detail=f"LDAP sync failed: {exc}")
    finally:
        conn.unbind()


def _ldap_seed_all_users() -> None:
    """Seed all users from LDAP into the local database at startup."""
    if not ADConfig.is_configured():
        return
    cfg = ADConfig.from_env()
    conn = _get_ldap_admin_conn()
    if conn is None:
        return
    try:
        conn.search(
            search_base=cfg.base_dn,
            search_filter="(objectClass=inetOrgPerson)",
            attributes=["uid", "displayName", "mail", "memberOf", "cn", "sn", "*"],
            time_limit=cfg.search_timeout,
        )
        if not conn.entries:
            store.add_log("LDAP_SYNC", "No LDAP users found to seed")
            return
        vpn_idx = 2
        for entry in conn.entries:
            if cfg.user_attr not in entry:
                continue
            username = str(entry[cfg.user_attr])
            if username == "admin":
                continue
            display_name = str(entry["displayName"]) if "displayName" in entry and entry["displayName"] is not None else username
            email = str(entry["mail"]) if "mail" in entry and entry["mail"] is not None else ""
            raw_member_of: list = list(entry["memberOf"]) if "memberOf" in entry else []
            groups = _extract_group_cns(raw_member_of) if raw_member_of else []
            if not groups:
                conn.search(
                    search_base=cfg.base_dn,
                    search_filter=f"(member={entry.entry_dn})",
                    attributes=["cn"],
                    time_limit=cfg.search_timeout,
                )
                groups = [str(e.cn) for e in conn.entries if "cn" in e]
            role = _resolve_role(groups)
            allowed_resources = list(ROLE_RESOURCES.get(role, []))
            if username in USER_RESOURCE_OVERRIDES:
                allowed_resources = USER_RESOURCE_OVERRIDES[username]
            vpn_ip = f"10.0.0.{vpn_idx}"
            vpn_idx += 1
            os_name = USER_OS_PROFILES.get(username, "Windows 11 Enterprise")
            store.upsert_from_ldap(
                username,
                {
                    "password": "",
                    "role": role,
                    "email": email,
                    "groups": groups,
                    "allowed_resources": allowed_resources,
                },
                vpn_ip=vpn_ip,
            )
            store._ensure_posture(username, vpn_ip)
            if username in USER_OS_PROFILES:
                store._conn.execute(
                    "UPDATE device_posture SET os=? WHERE vpn_ip=?",
                    (os_name, vpn_ip),
                )
                store._conn.commit()
            store.add_log("LDAP_SYNC", f"Seeded user '{username}' from LDAP (role: {role})")
    except LDAPException as exc:
        store.add_log("LDAP_SYNC_FAIL", f"LDAP seed failed: {exc}")
    finally:
        conn.unbind()


# ─── SMTP / EMAIL OTP CONFIG ─────────────────────────────────────────────
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "CHANGE_ME@CHANGE_ME.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")

EMAIL_OTP_LENGTH = 6
EMAIL_OTP_EXPIRY = 300  # 5 minutes

_email_otp_tokens: dict[str, dict] = {}


def _generate_preauth(username: str) -> str:
    token = secrets.token_hex(16)
    expires = time.time() + MFA_TOKEN_EXPIRY
    store.set_preauth_token(token, username, expires)
    return token


def _verify_totp(secret: str, token: str, username: str = "") -> bool:
    totp = pyotp.TOTP(secret)
    expected = totp.now()
    print(f"DEBUG: User: {username} | Expected Token: {expected} | Received Token: {token}", flush=True)
    return totp.verify(token, valid_window=2)


def _generate_email_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def _send_email_otp(recipient: str, otp: str) -> None:
    if not SMTP_HOST:
        store.add_log("EMAIL_OTP", f"SMTP not configured — logging OTP for {recipient}: {otp}")
        return

    msg = EmailMessage()
    msg["Subject"] = "Your Admin Verification Code — Zero Trust IAM Gateway"
    msg["From"] = SMTP_FROM
    msg["To"] = recipient
    msg.set_content(
        f"Security Alert: Admin Login Verification\n\n"
        f"Your one-time verification code is: {otp}\n\n"
        f"This code expires in 5 minutes. Do not share this code with anyone.\n"
        f"If you did not attempt to log in, please contact your security team immediately.\n\n"
        f"Zero Trust IAM Gateway"
    )

    try:
        ctx = ssl.create_default_context()
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls(context=ctx)
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=ctx) as server:
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        store.add_log("EMAIL_OTP", f"OTP sent to {recipient}")
    except Exception as exc:
        store.add_log("EMAIL_OTP_FAIL", f"Failed to send OTP to {recipient}: {exc}")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_password(stored: str, provided: str) -> bool:
    if not stored:
        return False
    if stored.startswith("$2b$") or stored.startswith("$2a$") or stored.startswith("$2y$"):
        return bcrypt.checkpw(provided.encode("utf-8"), stored.encode("utf-8"))
    return stored == provided


_PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*\d).{8,50}$")


def _validate_password_strength(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if len(password) > 128:
        return "Password must not exceed 128 characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"\d", password):
        return "Password must contain at least one digit"
    return None


def _provision_totp(username: str) -> tuple[str, str]:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=TOTP_ISSUER)
    return secret, uri


def _generate_backup_codes(count: int = 3) -> list[str]:
    codes: set[str] = set()
    while len(codes) < count:
        codes.add(f"{random.randint(0, 99999999):08d}")
    return sorted(codes)


def _store_and_return_backup_codes(username: str) -> list[str]:
    codes = _generate_backup_codes(3)
    store.set_backup_codes(username, codes)
    return codes


@app.post("/api/auth/login", dependencies=[Depends(verify_api_key)])
async def login(req: LoginRequest):
    if ADConfig.is_configured():
        try:
            ad_data = authenticate_ad_user(req.username, req.password)
        except ADAuthError as exc:
            user = store.get_user(req.username)
            if user and _check_password(user.get("password", ""), req.password):
                store.add_log("AUTH", f"User '{req.username}' authenticated (local fallback)")
                return _handle_post_auth(req.username, user["role"], user.get("vpn_ip", ""))
            store.add_log("AUTH_FAIL", f"AD auth failed for '{req.username}'")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        existing_user = store.get_user(req.username)
        allowed_resources = ad_data["allowed_resources"]
        if req.username in USER_RESOURCE_OVERRIDES:
            allowed_resources = USER_RESOURCE_OVERRIDES[req.username]
            store._conn.execute("UPDATE users SET allowed_resources='[]' WHERE username=?", (req.username,))
            store._conn.commit()
        store.upsert_from_ldap(
            req.username,
            {
                "password": "",
                "role": ad_data["role"],
                "vpn_ip": (existing_user or {}).get("vpn_ip", ""),
                "email": ad_data.get("email", ""),
                "groups": ad_data.get("groups", []),
                "allowed_resources": allowed_resources,
            },
            vpn_ip=(existing_user or {}).get("vpn_ip", ""),
        )
        store.add_log(
            "AUTH",
            f"User '{req.username}' authenticated via AD (role: {ad_data['role']})",
        )
        vpn = (existing_user or {}).get("vpn_ip", "")
        return _handle_post_auth(req.username, ad_data["role"], vpn)
    else:
        user = store.get_user(req.username)
        if not user or not _check_password(user.get("password", ""), req.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        store.add_log("AUTH", f"User '{req.username}' authenticated (local)")
        return _handle_post_auth(req.username, user["role"], user.get("vpn_ip", ""))


def _handle_post_auth(username: str, role: str, vpn_ip: str = "") -> dict:
    """Decide MFA flow based on role after successful authentication."""
    if role == "admin":
        existing_secret = store.get_mfa_secret(username)
        if not existing_secret:
            secret, provisioning_uri = _provision_totp(username)
            store.set_mfa_secret(username, secret)
            backup_codes = _store_and_return_backup_codes(username)
            store.add_log("MFA_PROVISION", f"MFA secret + backup codes provisioned for admin '{username}'")
            preauth_token = _generate_preauth(username)
            return {
                "mfa_required": True,
                "mfa_provisioning": True,
                "preauth_token": preauth_token,
                "username": username,
                "role": role,
                "mfa_secret": secret,
                "provisioning_uri": provisioning_uri,
                "backup_codes": backup_codes,
            }
        preauth_token = _generate_preauth(username)
        store.add_log("AUTH", f"Admin '{username}' authenticated — MFA required")
        return {
            "mfa_required": True,
            "mfa_provisioning": False,
            "preauth_token": preauth_token,
            "username": username,
            "role": role,
        }

    # Standard user
    if not store.has_mfa_secret(username):
        token = secrets.token_hex(16)
        store.create_session(token, username, mfa_verified=True)
        store.add_log("AUTH", f"User '{username}' authenticated (no MFA required)")
        user = store.get_user(username)
        data = {
            "token": token,
            "username": username,
            "role": role,
            "vpn_ip": vpn_ip or (user or {}).get("vpn_ip", ""),
        }
        return _make_session_response(data, token)

    store.add_log("AUTH", f"User '{username}' authenticated — MFA required")
    preauth_token = _generate_preauth(username)
    return {
        "mfa_required": True,
        "mfa_provisioning": False,
        "preauth_token": preauth_token,
        "username": username,
        "role": role,
    }


@app.post("/api/auth/verify-mfa", dependencies=[Depends(verify_api_key)])
async def verify_mfa_login(req: MFALoginVerifyRequest):
    data = store.pop_preauth_token(req.preauth_token)
    if not data:
        raise HTTPException(status_code=401, detail="Preauth token not found")
    if time.time() > data["expires"]:
        raise HTTPException(status_code=401, detail="Preauth token expired")

    username = data["username"]
    secret = store.get_mfa_secret(username)
    if not secret:
        store.add_log("MFA_FAIL", f"'{username}' attempted MFA but has no secret")
        raise HTTPException(status_code=400, detail="MFA not provisioned. Please log in again.")

    if not _verify_totp(secret, req.token, username):
        store.add_log("MFA_FAIL", f"'{username}' failed MFA on login (invalid token)")
        raise HTTPException(status_code=401, detail="Invalid MFA token. Try a fresh code from your authenticator app.")

    store.add_log("MFA_OK", f"'{username}' passed MFA on login")

    user = store.get_user(username)
    role = (user or {}).get("role", "")

    # ── Admin Layer 3: Email OTP required ───────────────────────────────
    if role == "admin":
        otp = _generate_email_otp()
        email_otp_token = secrets.token_hex(16)
        _email_otp_tokens[email_otp_token] = {
            "username": username,
            "otp": otp,
            "expires": time.time() + EMAIL_OTP_EXPIRY,
        }

        recipient = (user or {}).get("email") or ADMIN_EMAIL
        if not recipient:
            recipient = "admin@localhost"
            print("WARNING: No email configured for admin. "
                  f"Falling back to console logging. OTP={otp}", flush=True)

        _send_email_otp(recipient, otp)

        store.add_log("EMAIL_OTP", f"Admin '{username}' — email OTP dispatched")
        return {
            "email_otp_required": True,
            "email_otp_token": email_otp_token,
            "username": username,
            "role": role,
        }

    # ── Standard user: finalize session ─────────────────────────────────
    store.invalidate_user_sessions(username)
    token = secrets.token_hex(16)
    store.create_session(token, username, mfa_verified=True)
    data = {
        "token": token,
        "username": username,
        "role": role,
        "vpn_ip": (user or {}).get("vpn_ip", ""),
    }
    return _make_session_response(data, token)


@app.post("/api/auth/verify-backup-code", dependencies=[Depends(verify_api_key)])
async def verify_backup_code(req: BackupCodeVerifyRequest):
    data = store.pop_preauth_token(req.preauth_token)
    if not data:
        raise HTTPException(status_code=401, detail="Preauth token not found")
    if time.time() > data["expires"]:
        raise HTTPException(status_code=401, detail="Preauth token expired")

    username = data["username"]

    if not store.verify_backup_code(username, req.backup_code):
        store.add_log("MFA_FAIL", f"'{username}' failed backup code verification")
        raise HTTPException(status_code=401, detail="Invalid backup code.")

    store.add_log("MFA_OK", f"'{username}' passed MFA via backup code (1 remaining: {store.count_remaining_backup_codes(username)})")

    user = store.get_user(username)
    role = (user or {}).get("role", "")

    # ── Admin Layer 3: Email OTP required ───────────────────────────────
    if role == "admin":
        otp = _generate_email_otp()
        email_otp_token = secrets.token_hex(16)
        _email_otp_tokens[email_otp_token] = {
            "username": username,
            "otp": otp,
            "expires": time.time() + EMAIL_OTP_EXPIRY,
        }

        recipient = (user or {}).get("email") or ADMIN_EMAIL
        if not recipient:
            recipient = "admin@localhost"
            print("WARNING: No email configured for admin. "
                  f"Falling back to console logging. OTP={otp}", flush=True)

        _send_email_otp(recipient, otp)

        store.add_log("EMAIL_OTP", f"Admin '{username}' — email OTP dispatched (backup code used)")
        return {
            "email_otp_required": True,
            "email_otp_token": email_otp_token,
            "username": username,
            "role": role,
        }

    # ── Standard user: finalize session ─────────────────────────────────
    store.invalidate_user_sessions(username)
    token = secrets.token_hex(16)
    store.create_session(token, username, mfa_verified=True)
    data = {
        "token": token,
        "username": username,
        "role": role,
        "vpn_ip": (user or {}).get("vpn_ip", ""),
    }
    return _make_session_response(data, token)


@app.post("/api/auth/verify-email-otp", dependencies=[Depends(verify_api_key)])
async def verify_email_otp(req: EmailOTPVerifyRequest):
    data = _email_otp_tokens.pop(req.email_otp_token, None)
    if not data:
        raise HTTPException(status_code=401, detail="Email OTP token not found or already used")
    if time.time() > data["expires"]:
        raise HTTPException(status_code=401, detail="Email OTP has expired. Please log in again.")

    username = data["username"]

    if data["otp"] != req.otp:
        store.add_log("EMAIL_OTP_FAIL", f"'{username}' submitted wrong email OTP")
        raise HTTPException(status_code=401, detail="Invalid email verification code.")

    store.add_log("EMAIL_OTP_OK", f"'{username}' passed email OTP verification — full access granted")
    store.invalidate_user_sessions(username)
    token = secrets.token_hex(16)
    store.create_session(token, username, mfa_verified=True)
    user = store.get_user(username)
    data = {
        "token": token,
        "username": username,
        "role": (user or {}).get("role", ""),
        "vpn_ip": (user or {}).get("vpn_ip", ""),
    }
    return _make_session_response(data, token)


@app.post("/api/auth/resend-email-otp", dependencies=[Depends(verify_api_key)])
async def resend_email_otp(req: SessionToken):
    data = _email_otp_tokens.get(req.token)
    if not data:
        raise HTTPException(status_code=401, detail="Email OTP session not found or already verified")
    if time.time() > data["expires"]:
        _email_otp_tokens.pop(req.token, None)
        raise HTTPException(status_code=401, detail="Email OTP has expired. Please log in again.")

    username = data["username"]

    new_otp = _generate_email_otp()
    data["otp"] = new_otp
    data["expires"] = time.time() + EMAIL_OTP_EXPIRY

    user = store.get_user(username)
    recipient = (user or {}).get("email") or ADMIN_EMAIL
    if not recipient:
        recipient = "admin@localhost"
        print("WARNING: No email configured for admin. "
              f"Falling back to console logging. OTP={new_otp}", flush=True)

    _send_email_otp(recipient, new_otp)
    store.add_log("EMAIL_OTP", f"Admin '{username}' — email OTP resent")
    return {"status": "resent", "message": "A new verification code has been sent to your email."}


@app.post("/api/auth/change-password", dependencies=[Depends(verify_api_key)])
async def change_password(request: Request, old_password: str = Body(...), new_password: str = Body(...)):
    session_token = _extract_session_token(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="No active session")
    session = store.get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    if not session.get("mfa_verified"):
        raise HTTPException(status_code=403, detail="MFA must be completed before changing password")

    username = session["username"]
    user = store.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if ADConfig.is_configured() and not user.get("password"):
        raise HTTPException(
            status_code=400,
            detail="Your account is managed by Active Directory. "
            "Change your password through the domain controller.",
        )

    if not _check_password(user.get("password", ""), old_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    validation_error = _validate_password_strength(new_password)
    if validation_error:
        raise HTTPException(status_code=400, detail=validation_error)

    if old_password == new_password:
        raise HTTPException(status_code=400, detail="New password must differ from current password")

    _ldap_sync_change_password(username, new_password)
    user["password"] = _hash_password(new_password)
    store.invalidate_user_sessions(username)
    store._save()
    store.add_log("ADMIN", f"Password changed for '{username}'")
    response = JSONResponse({"status": "password_updated", "message": "Password changed. Please log in again."})
    response.delete_cookie("session", path="/")
    return response


@app.post("/api/auth/session", dependencies=[Depends(verify_api_key)])
async def verify_session(req: SessionToken):
    entry = store.get_session(req.token)
    if not entry:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    user = store.get_user(entry["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    expires_in = max(0, int(entry["expires"] - time.time()))
    return {"valid": True, "username": entry["username"], "role": user["role"], "vpn_ip": user.get("vpn_ip", ""), "expires_in": expires_in}


@app.get("/api/auth/me", dependencies=[Depends(verify_api_key)])
async def get_current_session(request: Request):
    session_token = request.cookies.get("session") or ""
    if not session_token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            session_token = auth[7:]
    if not session_token:
        raise HTTPException(status_code=401, detail="No session")
    entry = store.get_session(session_token)
    if not entry:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    user = store.get_user(entry["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    expires_in = max(0, int(entry["expires"] - time.time()))
    return {"valid": True, "username": entry["username"], "role": user["role"], "vpn_ip": user.get("vpn_ip", ""), "expires_in": expires_in}


@app.post("/api/auth/logout", dependencies=[Depends(verify_api_key)])
async def logout(req: SessionToken):
    entry = store.get_session(req.token)
    if entry:
        ACTIVE_SESSIONS.pop(entry["username"], None)
    store.delete_session(req.token)
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie("session", path="/")
    return response


# ─── ADMIN ───

@app.post("/api/admin/create-user", dependencies=[Depends(verify_api_key)])
async def admin_create_user(req: CreateUserRequest):
    if store.get_user(req.username):
        raise HTTPException(status_code=409, detail="User already exists")
    hashed = _hash_password(req.password)
    _ldap_sync_create_user(
        username=req.username,
        password=req.password,
        email=req.username,
        display_name=req.username,
    )
    store.create_user(req.username, hashed, req.vpn_ip, req.role)
    store.add_log("ADMIN", f"User '{req.username}' created ({req.role})")
    return {"status": "created", "username": req.username}


@app.post("/api/admin/modify-permissions", dependencies=[Depends(verify_api_key)])
async def admin_modify_permissions(req: ModifyPermRequest):
    user = store.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if req.action == "grant":
        store.grant_resource(req.username, req.resource_id)
        store.add_log("ADMIN", f"Granted {req.resource_id} -> '{req.username}'")
    elif req.action == "revoke":
        store.revoke_resource(req.username, req.resource_id)
        store.add_log("ADMIN", f"Revoked {req.resource_id} <- '{req.username}'")
    else:
        raise HTTPException(status_code=400, detail="Action must be 'grant' or 'revoke'")
    return {"status": "updated", "allowed_resources": user["allowed_resources"]}


@app.get("/api/admin/users", dependencies=[Depends(verify_api_key)])
async def admin_list_users():
    return {"users": {k: {"role": v["role"], "vpn_ip": v.get("vpn_ip", ""), "email": v.get("email", ""), "allowed_resources": v["allowed_resources"], "mfa_provisioned": bool(v.get("mfa_secret"))} for k, v in store._users.items()}}


@app.post("/api/admin/delete-user", dependencies=[Depends(verify_api_key)])
async def admin_delete_user(username: str):
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin")
    if not store.get_user(username):
        raise HTTPException(status_code=404, detail="User not found")
    _ldap_sync_delete_user(username)
    store.delete_user(username)
    store.add_log("ADMIN", f"User '{username}' deleted")
    return {"status": "deleted"}


@app.post("/api/admin/clear-logs", dependencies=[Depends(verify_api_key)])
async def admin_clear_logs():
    store.clear_event_log()
    store.add_log("ADMIN", "SIEM logs cleared")
    return {"status": "cleared"}


@app.post("/api/admin/purge-system", dependencies=[Depends(verify_api_key)])
async def admin_purge_system(req: AdminActionRequest):
    if req.username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can purge the system")
    store.clear_event_log()
    for username in store._get_all_usernames():
        if username == "admin":
            continue
        store.invalidate_user_sessions(username)
        ACTIVE_SESSIONS.pop(username, None)
    store._save()
    store.add_log("ADMIN", "System purged: event log wiped, all non-admin sessions invalidated")
    return {"status": "purged"}


@app.post("/api/admin/ldap-sync", dependencies=[Depends(verify_api_key)])
async def admin_ldap_sync():
    _ldap_seed_all_users()
    store.add_log("ADMIN", "Manual LDAP sync triggered")
    return {"status": "synced"}


@app.post("/api/admin/reset-password", dependencies=[Depends(verify_api_key)])
async def admin_reset_password(req: AdminResetPasswordRequest):
    if req.username == "admin":
        raise HTTPException(status_code=400, detail="Cannot reset admin password via this endpoint")
    user = store.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    validation_error = _validate_password_strength(req.new_password)
    if validation_error:
        raise HTTPException(status_code=400, detail=validation_error)
    _ldap_sync_change_password(req.username, req.new_password)
    user["password"] = _hash_password(req.new_password)
    store.invalidate_user_sessions(req.username)
    store._save()
    store.add_log("ADMIN", f"Admin reset password for '{req.username}'")
    return {"status": "password_reset", "message": f"Password reset for '{req.username}'. All sessions invalidated."}


@app.get("/api/admin/sessions", dependencies=[Depends(verify_api_key)])
async def admin_list_sessions():
    now = time.time()
    active = []
    stale = []
    for username, entry in list(ACTIVE_SESSIONS.items()):
        session = store.get_session(entry["token"])
        if not session:
            stale.append(username)
            continue
        user = store.get_user(username)
        active.append({
            "username": username,
            "role": (user or {}).get("role", "?"),
            "expires_in": int(session["expires"] - now),
            "token_preview": entry["token"][:8] + "...",
            "login_time": entry.get("login_time", 0),
        })
    for username in stale:
        ACTIVE_SESSIONS.pop(username, None)
    return {"sessions": active}


# ─── POSTURE ───

@app.post("/api/posture/toggle", dependencies=[Depends(verify_api_key)])
async def toggle_posture(vpn_ip: str):
    if vpn_ip not in store._device_posture:
        raise HTTPException(status_code=404, detail="Posture not found")
    p = store._device_posture[vpn_ip]
    if p["firewall"] == "Active":
        p["firewall"] = "Disabled"; p["compliant"] = False
        store.add_log("ALERT", f"Firewall DOWN on {vpn_ip}")
    else:
        p["firewall"] = "Active"; p["compliant"] = True
        store.add_log("RECOVER", f"Firewall UP on {vpn_ip}")
    return p


@app.get("/api/posture/{vpn_ip}", dependencies=[Depends(verify_api_key)])
async def get_posture(vpn_ip: str):
    posture = store._device_posture.get(vpn_ip)
    if posture:
        return posture
    user = store.get_user(vpn_ip)
    if user and user.get("vpn_ip"):
        posture = store._device_posture.get(user["vpn_ip"])
        if posture:
            return posture
    return {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True}


# ─── RESOURCE EVALUATION ───

@app.post("/api/resource/evaluate-access", dependencies=[Depends(verify_api_key)])
async def evaluate_access(req: AccessRequest):
    user = store.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if req.resource_id not in user["allowed_resources"]:
        store.add_log("DENY", f"'{req.username}' blocked from {req.resource_id} - unauthorized")
        return {"policy": "DENY", "reason": "No Admin Authorization Key"}
    posture = store._device_posture.get(user.get("vpn_ip", ""), {})
    if posture.get("firewall") == "Disabled":
        store.add_log("RISK", f"'{req.username}' challenged on {req.resource_id} - posture degraded")
        return {"policy": "CHALLENGE_MFA", "reason": "Host Posture Degradation"}
    store.add_log("ACCESS", f"'{req.username}' granted {req.resource_id}")
    return {"policy": "ALLOW"}


@app.get("/api/resource/{resource_id}/data", dependencies=[Depends(verify_api_key)])
async def get_resource_data(resource_id: str, username: str = ""):
    user = store.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if resource_id not in user["allowed_resources"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    if resource_id not in RESOURCE_DUMMY_DATA:
        raise HTTPException(status_code=404, detail="Resource not found")
    return {"resource_id": resource_id, "data": RESOURCE_DUMMY_DATA[resource_id]}


# ─── MFA ───

@app.post("/api/mfa/verify", dependencies=[Depends(verify_api_key)])
async def verify_mfa(req: MFAVerifyRequest):
    secret = store.get_mfa_secret(req.username)
    if not secret:
        raise HTTPException(status_code=400, detail="MFA not provisioned")
    if _verify_totp(secret, req.token, req.username):
        store.add_log("MFA_OK", f"'{req.username}' passed MFA")
        return {"status": "verified"}
    store.add_log("MFA_FAIL", f"'{req.username}' failed MFA")
    raise HTTPException(status_code=401, detail="Invalid MFA token")


@app.post("/api/mfa/provision", dependencies=[Depends(verify_api_key)])
async def provision_mfa(username: str, request: Request):
    session_token = _extract_session_token(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="No active session")
    session = store.get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")

    caller = store.get_user(session["username"])
    caller_role = (caller or {}).get("role", "")
    if caller_role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can provision MFA keys. Contact IT support.",
        )

    user = store.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret, provisioning_uri = _provision_totp(username)
    store.set_mfa_secret(username, secret)
    backup_codes = _store_and_return_backup_codes(username)
    store.add_log("ADMIN", f"Admin '{session['username']}' provisioned MFA for '{username}'")
    return {"secret": secret, "provisioning_uri": provisioning_uri, "username": username, "backup_codes": backup_codes}


# ─── ADMIN MFA MANAGEMENT ───

class AdminMFAViewRequest(BaseModel): username: str

@app.post("/api/admin/mfa/view", dependencies=[Depends(verify_api_key)])
async def admin_view_mfa(req: AdminMFAViewRequest, request: Request):
    session_token = _extract_session_token(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="No active session")
    session = store.get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    caller = store.get_user(session["username"])
    if (caller or {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    user = store.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = store.get_mfa_secret(req.username)
    store.add_log("ADMIN", f"Admin '{session['username']}' viewed MFA key for '{req.username}'")
    return {
        "username": req.username,
        "mfa_provisioned": secret is not None,
        "mfa_secret": secret if secret else None,
        "provisioning_uri": pyotp.TOTP(secret).provisioning_uri(name=req.username, issuer_name=TOTP_ISSUER) if secret else None,
    }


@app.post("/api/admin/mfa/reset", dependencies=[Depends(verify_api_key)])
async def admin_reset_mfa(req: AdminMFAViewRequest, request: Request):
    session_token = _extract_session_token(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="No active session")
    session = store.get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    caller = store.get_user(session["username"])
    if (caller or {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    user = store.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret, provisioning_uri = _provision_totp(req.username)
    store.set_mfa_secret(req.username, secret)
    backup_codes = _store_and_return_backup_codes(req.username)
    store.add_log("ADMIN", f"Admin '{session['username']}' reset MFA key for '{req.username}'")
    store.invalidate_user_sessions(req.username)
    ACTIVE_SESSIONS.pop(req.username, None)
    return {
        "username": req.username,
        "mfa_secret": secret,
        "provisioning_uri": provisioning_uri,
        "backup_codes": backup_codes,
        "message": f"MFA key reset for '{req.username}'. They will need to scan the new key and log in again.",
    }


# ─── STATUS ───

@app.get("/api/status", dependencies=[Depends(verify_api_key)])
async def get_status():
    return {"users": {k: {"role": v["role"], "vpn_ip": v.get("vpn_ip", ""), "email": v.get("email", ""), "allowed_resources": v["allowed_resources"], "mfa_provisioned": bool(v.get("mfa_secret"))} for k, v in store._users.items()}, "device_posture": store._device_posture, "event_log": store.event_log}


@app.get("/api/resources", dependencies=[Depends(verify_api_key)])
async def get_resources():
    return {"catalog": RESOURCE_CATALOG, "role_defaults": ROLE_RESOURCES}


# ─── STARTUP / SHUTDOWN ───

@app.on_event("startup")
async def startup():
    proxy_router.load_from_env()
    _ldap_seed_all_users()


@app.on_event("shutdown")
async def shutdown():
    await proxy_router.shutdown()


if __name__ == "__main__":
    import uvicorn
    os.environ.setdefault("API_SECRET_KEY", "")
    uvicorn.run(app, host="0.0.0.0", port=8443)
