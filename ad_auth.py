import logging
import os
import ssl
from dataclasses import dataclass
from typing import Optional

import ldap3
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPSocketOpenError,
    LDAPStartTLSError,
)

from models import _ad_group_to_role, ROLE_RESOURCES

logger = logging.getLogger(__name__)


class ADAuthError(Exception):
    """Raised when Active Directory authentication fails."""


@dataclass
class ADConfig:
    server: str = ""
    base_dn: str = ""
    domain: str = ""
    user_attr: str = "sAMAccountName"
    bind_dn: str = ""
    bind_password: str = ""
    use_tls: bool = True
    validate_cert: bool = True
    connect_timeout: int = 10
    receive_timeout: int = 10
    search_timeout: int = 10

    @classmethod
    def from_env(cls) -> "ADConfig":
        server = os.environ.get(
            "AD_LDAP_URL",
            os.environ.get("LDAP_SERVER", ""),
        )
        use_tls = server.startswith("ldaps://") or os.environ.get(
            "AD_USE_STARTTLS", "true"
        ).lower() in ("1", "true", "yes")
        validate = os.environ.get("AD_VALIDATE_CERT", "true").lower() in (
            "1",
            "true",
            "yes",
        )
        return cls(
            server=server,
            base_dn=os.environ.get("AD_BASE_DN", os.environ.get("LDAP_BASE_DN", "")),
            domain=os.environ.get("AD_DOMAIN", os.environ.get("LDAP_DOMAIN", "")),
            user_attr=os.environ.get("AD_USER_ATTR", os.environ.get("LDAP_USER_ATTR", "sAMAccountName")),
            bind_dn=os.environ.get("AD_BIND_DN", os.environ.get("LDAP_BIND_DN", "")),
            bind_password=os.environ.get("AD_BIND_PASSWORD", os.environ.get("LDAP_BIND_PASSWORD", "")),
            use_tls=use_tls,
            validate_cert=validate,
            connect_timeout=int(os.environ.get("AD_CONNECT_TIMEOUT", "10")),
            receive_timeout=int(os.environ.get("AD_RECEIVE_TIMEOUT", "10")),
            search_timeout=int(os.environ.get("AD_SEARCH_TIMEOUT", "10")),
        )

    @classmethod
    def is_configured(cls) -> bool:
        return bool(os.environ.get("AD_LDAP_URL") or os.environ.get("LDAP_SERVER"))


def _build_tls_config(validate_cert: bool) -> ldap3.Tls:
    if validate_cert:
        return ldap3.Tls(
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
    return ldap3.Tls(
        validate=ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )


def _extract_group_cns(member_of_values: list) -> list[str]:
    """Extract group Common-Names from memberOf DNs.

    Handles: CN=Finance,OU=Groups,DC=corp,DC=local → "Finance"
    Uses ldap3's DN parser for correctness with escaped characters.
    """
    groups: list[str] = []
    for raw_dn in member_of_values:
        try:
            parsed = ldap3.utils.dn.parse_dn(str(raw_dn))
            if parsed and parsed[0][0].lower() == "cn":
                groups.append(parsed[0][1])
        except Exception:
            parts = str(raw_dn).split(",")
            if parts and parts[0].startswith("CN="):
                groups.append(parts[0][3:])
    return groups


def _resolve_role(groups: list[str]) -> str:
    """Map AD groups to application role using the policy engine mapping.

    Priority: admin wins immediately; first non-admin match is used;
    falls back to 'Operations'.
    """
    role: Optional[str] = None
    for gcn in groups:
        mapped = _ad_group_to_role(gcn)
        if mapped == "admin":
            return "admin"
        if mapped and not role:
            role = mapped
    return role or "Operations"


def _bind_connection(
    server: ldap3.Server, config: ADConfig, user: str, password: str
) -> ldap3.Connection:
    conn = ldap3.Connection(
        server,
        user=user,
        password=password,
        auto_bind=True,
        receive_timeout=config.receive_timeout,
    )
    return conn


def _search_user_entry(
    conn: ldap3.Connection, config: ADConfig, username: str
) -> Optional[ldap3.Entry]:
    escaped = ldap3.utils.conv.escape_filter_chars(username)
    conn.search(
        search_base=config.base_dn,
        search_filter=f"({config.user_attr}={escaped})",
        attributes=["displayName", "mail", "memberOf", "*"],
        size_limit=1,
        time_limit=config.search_timeout,
    )
    return conn.entries[0] if conn.entries else None


def _resolve_groups(
    entry: ldap3.Entry, config: ADConfig, conn: Optional[ldap3.Connection] = None
) -> list[str]:
    raw_member_of: list = list(entry["memberOf"]) if "memberOf" in entry else []
    if raw_member_of:
        return _extract_group_cns(raw_member_of)
    if conn is not None:
        user_dn = str(entry.entry_dn)
        escaped = ldap3.utils.conv.escape_filter_chars(user_dn)
        conn.search(
            search_base=config.base_dn,
            search_filter=f"(member={escaped})",
            attributes=["cn"],
            time_limit=config.search_timeout,
        )
        return [str(e.cn) for e in conn.entries if "cn" in e]
    return []


def _extract_user_data(
    entry: ldap3.Entry, config: ADConfig, username: str,
    conn: Optional[ldap3.Connection] = None,
) -> dict:
    display_name = (
        str(entry["displayName"]) if "displayName" in entry and entry["displayName"] is not None else username
    )
    email = str(entry["mail"]) if "mail" in entry and entry["mail"] is not None else ""
    groups = _resolve_groups(entry, config, conn)
    role = _resolve_role(groups)
    allowed = list(ROLE_RESOURCES.get(role, []))
    logger.info("AD auth: uid=%s role=%s groups=%s display=%s", username, role, groups, display_name)
    return {
        "username": username,
        "role": role,
        "display_name": display_name,
        "email": email,
        "groups": groups,
        "allowed_resources": allowed,
    }


def authenticate_ad_user(username: str, password: str) -> dict:
    config = ADConfig.from_env()

    if not password:
        raise ADAuthError("Password is empty")

    if not username:
        raise ADAuthError("Username is empty")

    tls = _build_tls_config(config.validate_cert) if config.use_tls else None

    server = ldap3.Server(
        config.server,
        get_info=ldap3.NONE,
        connect_timeout=config.connect_timeout,
        tls=tls,
    )

    entry: Optional[ldap3.Entry] = None

    # ── Strategy A: service-account lookup + user DN bind ───────────────
    if config.bind_dn and config.bind_password:
        service_conn: Optional[ldap3.Connection] = None
        try:
            service_conn = _bind_connection(server, config, config.bind_dn, config.bind_password)
            entry = _search_user_entry(service_conn, config, username)
            if not entry:
                raise ADAuthError(f"User '{username}' not found in directory")

            user_dn = str(entry.entry_dn)

            # Verify password by binding as the user
            _bind_connection(server, config, user_dn, password).unbind()
            result = _extract_user_data(entry, config, username, conn=service_conn)
            service_conn.unbind()
            service_conn = None
            return result

        except LDAPBindError:
            raise ADAuthError("Invalid username or password")
        except ADAuthError:
            raise
        except LDAPSocketOpenError as exc:
            raise ADAuthError(f"Cannot reach Directory Server at {config.server}: {exc}")
        except LDAPException as exc:
            raise ADAuthError(str(exc))
        finally:
            if service_conn is not None:
                try:
                    service_conn.unbind()
                except Exception:
                    pass

    # ── Strategy B: direct UPN bind (Active Directory style) ────────────
    upn = f"{username}@{config.domain}"
    conn: Optional[ldap3.Connection] = None

    try:
        conn = _bind_connection(server, config, upn, password)
        entry = _search_user_entry(conn, config, username)
        if not entry:
            raise ADAuthError(
                f"User '{username}' authenticated but directory entry not found"
            )
        return _extract_user_data(entry, config, username, conn=conn)

    except LDAPBindError:
        raise ADAuthError("Invalid username or password")
    except LDAPSocketOpenError as exc:
        raise ADAuthError(f"Cannot reach Domain Controller at {config.server}: {exc}")
    except LDAPException as exc:
        raise ADAuthError(str(exc))
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass
