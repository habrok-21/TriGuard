import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

import bcrypt

DATA_FILE = Path(__file__).parent / "store_data.json"
SEED_LDIF = Path(__file__).parent / "ldap" / "seed.ldif"
DB_FILE = Path(__file__).parent / "store.db"
_save_lock = threading.Lock()

SESSION_TTL = int(os.environ.get("SESSION_TTL", "86400"))  # 24 hours


def _parse_ldif_entries(filepath: Path) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    try:
        text = filepath.read_text(encoding="utf-8")
    except Exception:
        return entries
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#") or line.startswith("version:"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            val = val.strip()
            current.setdefault(key.strip(), []).append(val)
    if current:
        entries.append(current)
    return entries


def _resolve_uid_from_dn(dn: str) -> str:
    m = re.search(r"(?:^|,)uid=([^,]+)", dn)
    return m.group(1) if m else dn


def _ad_group_to_role(group_cn: str) -> Optional[str]:
    match = {
        "Finance": "Finance",
        "HR": "HR",
        "Marketing": "Marketing",
        "Sales": "Sales",
        "Operations": "Operations",
        "Management": "Management",
        "IT_Security": "IT_Security",
        "Domain Admins": "admin",
        "Domain Users": "Operations",
    }
    return match.get(group_cn)


RESOURCE_CATALOG = {
    "accounting_db": {
        "name": "Accounting Database",
        "icon": "fa-solid fa-file-invoice-dollar",
        "desc": "Financial records, payroll, invoicing, tax documents",
    },
    "employee_db": {
        "name": "HR Employee Records",
        "icon": "fa-solid fa-users",
        "desc": "Personnel files, contracts, PTO tracking, performance reviews",
    },
    "devops_server": {
        "name": "DevOps Build Server",
        "icon": "fa-solid fa-code-branch",
        "desc": "CI/CD pipeline, source code repositories, deployment automation",
    },
    "crm_system": {
        "name": "CRM Platform",
        "icon": "fa-solid fa-handshake",
        "desc": "Customer relationships, sales pipeline, lead tracking, deals",
    },
    "it_assets": {
        "name": "IT Asset Manager",
        "icon": "fa-solid fa-server",
        "desc": "Device inventory, software licenses, hardware lifecycle, patches",
    },
    "document_vault": {
        "name": "Corporate Document Vault",
        "icon": "fa-solid fa-folder-lock",
        "desc": "Policies, legal contracts, NDAs, compliance documents",
    },
    "analytics_dash": {
        "name": "Business Analytics",
        "icon": "fa-solid fa-chart-line",
        "desc": "KPIs, revenue reports, growth metrics, board presentations",
    },
}

RESOURCE_DUMMY_DATA = {
    "accounting_db": {
        "title": "Accounting Database",
        "columns": ["Date", "Description", "Category", "Amount", "Status"],
        "rows": [
            ["2026-06-01", "Office supplies - Stationery", "Operations", "$1,240.00", "Approved"],
            ["2026-06-02", "Vendor payment - Cloud Services", "Infrastructure", "$12,500.00", "Pending"],
            ["2026-06-03", "Employee reimbursement - Travel", "Travel", "$3,420.00", "Approved"],
            ["2026-06-04", "Software license renewal", "IT", "$8,900.00", "Approved"],
            ["2026-06-05", "Q2 tax installment", "Tax", "$45,000.00", "Processing"],
            ["2026-06-06", "Client invoice #1042", "Revenue", "$28,300.00", "Paid"],
            ["2026-06-07", "Payroll - June Week 1", "Payroll", "$67,800.00", "Approved"],
        ],
    },
    "employee_db": {
        "title": "HR Employee Records",
        "columns": ["Employee", "Department", "Position", "Status", "Start Date"],
        "rows": [
            ["Aarav Sharma", "Finance", "Senior Accountant", "Active", "2022-03-15"],
            ["Bhavik Mehta", "Engineering", "DevOps Lead", "Active", "2021-07-01"],
            ["Chitra Iyer", "HR", "HR Director", "Active", "2020-01-10"],
            ["Deepak Joshi", "Marketing", "Marketing Manager", "Active", "2023-02-20"],
            ["Esha Verma", "Sales", "Sales Representative", "Probation", "2025-12-01"],
            ["Farhan Khan", "Operations", "Operations Analyst", "Active", "2024-06-15"],
            ["Gaurav Patel", "Management", "VP Operations", "Active", "2019-09-01"],
        ],
    },
    "devops_server": {
        "title": "DevOps Build Server",
        "columns": ["Pipeline", "Branch", "Commit", "Status", "Duration"],
        "rows": [
            ["api-gateway", "main", "a1b2c3d", "Passed", "4m 12s"],
            ["web-app", "develop", "e5f6g7h", "Running", "2m 34s"],
            ["mobile-backend", "feature/payments", "i9j0k1l", "Passed", "6m 01s"],
            ["infra-terraform", "main", "m2n3o4p", "Failed", "1m 45s"],
            ["auth-service", "release/v2.1", "q5r6s7t", "Queued", "-"],
        ],
    },
    "crm_system": {
        "title": "CRM Platform",
        "columns": ["Lead", "Company", "Stage", "Value", "Owner"],
        "rows": [
            ["Acme Corp", "Acme Inc.", "Negotiation", "$120,000", "Sarah L."],
            ["Globex", "Globex Industries", "Proposal", "$85,000", "Tom R."],
            ["Initech", "Initech LLC", "Qualified", "$45,000", "Nina P."],
            ["Hooli", "Hooli Technologies", "Discovery", "$200,000", "Eric S."],
            ["Pied Piper", "Pied Piper Inc.", "Closed Won", "$350,000", "Richard H."],
        ],
    },
    "it_assets": {
        "title": "IT Asset Manager",
        "columns": ["Asset", "Type", "Assigned To", "Status", "Last Audit"],
        "rows": [
            ["LAP-1042", "Laptop", "Aarav Sharma", "Active", "2026-05-15"],
            ["LAP-1043", "Laptop", "Bhavik Mehta", "Active", "2026-04-20"],
            ["MON-078", "Monitor", "Chitra Iyer", "Active", "2026-03-10"],
            ["SRV-022", "Server", "IT Dept", "Maintenance", "2026-06-01"],
            ["LIC-ADOBE", "License", "Marketing", "Expiring", "2026-07-30"],
            ["SW-365", "License", "All Users", "Active", "2026-12-31"],
        ],
    },
    "document_vault": {
        "title": "Corporate Document Vault",
        "columns": ["Document", "Category", "Version", "Last Modified", "Classification"],
        "rows": [
            ["Employee Handbook 2026", "HR Policy", "v3.2", "2026-01-15", "Internal"],
            ["Security Incident Response Plan", "IT Security", "v2.1", "2026-03-22", "Confidential"],
            ["Annual Financial Report 2025", "Finance", "v1.0", "2026-02-28", "Confidential"],
            ["ISO 27001 Compliance Checklist", "Compliance", "v4.0", "2026-04-10", "Restricted"],
            ["Vendor NDA Template", "Legal", "v1.3", "2025-11-05", "Internal"],
            ["Business Continuity Plan", "Operations", "v2.0", "2026-05-01", "Confidential"],
        ],
    },
    "analytics_dash": {
        "title": "Business Analytics",
        "columns": ["Metric", "Current", "Previous", "Change", "Target"],
        "rows": [
            ["Revenue (QTD)", "$2.4M", "$2.1M", "+14.3%", "$3.0M"],
            ["Active Users", "1,847", "1,621", "+13.9%", "2,000"],
            ["Customer Churn", "3.2%", "3.8%", "-15.8%", "<3%"],
            ["Avg Order Value", "$847", "$792", "+6.9%", "$900"],
            ["Employee Satisfaction", "84%", "79%", "+6.3%", "85%"],
            ["Project Velocity", "92%", "88%", "+4.5%", "95%"],
        ],
    },
}

ROLE_RESOURCES = {
    "Finance": ["accounting_db", "document_vault", "analytics_dash"],
    "HR": ["employee_db", "document_vault"],
    "Marketing": ["crm_system", "analytics_dash", "document_vault"],
    "Sales": ["crm_system", "analytics_dash"],
    "Operations": ["it_assets", "document_vault", "analytics_dash"],
    "Management": [
        "accounting_db",
        "employee_db",
        "crm_system",
        "analytics_dash",
        "document_vault",
    ],
    "IT_Security": [
        "devops_server",
        "it_assets",
        "accounting_db",
        "document_vault",
        "analytics_dash",
    ],
}

USER_POSTURE_PROFILES = {
    "admin": {"os": "macOS 15.2", "firewall": "Active", "compliant": True},
    "jay": {"os": "macOS 15.2", "firewall": "Active", "compliant": True},
    "luffy": {"os": "Ubuntu 24.04 LTS", "firewall": "Active", "compliant": True},
    "ash": {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True},
    "brock": {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True},
    "sanji": {"os": "macOS 15.2", "firewall": "Active", "compliant": True},
    "zoro": {"os": "Ubuntu 24.04 LTS", "firewall": "Active", "compliant": True},
    "kido": {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True},
    "ace": {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True},
    "shanks": {"os": "macOS 15.2", "firewall": "Active", "compliant": True},
}


class PeerStore:
    def __init__(self):
        self._local = threading.local()
        self._init_db()
        self._load()

    @property
    def _conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'Operations',
                vpn_ip TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                mfa_secret TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                allowed_resources TEXT NOT NULL DEFAULT '[]',
                groups TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                mfa_verified INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_posture (
                vpn_ip TEXT PRIMARY KEY,
                os TEXT NOT NULL DEFAULT 'Windows 11',
                firewall TEXT NOT NULL DEFAULT 'Active',
                compliant INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS preauth_tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires REAL NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    def _load(self):
        seed_needed = False
        cursor = self._conn.execute("SELECT COUNT(*) as cnt FROM users")
        row = cursor.fetchone()
        if row["cnt"] == 0:
            seed_needed = True
            self._seed_default_admin()

        if not os.environ.get("LDAP_SERVER") and not os.environ.get("AD_LDAP_URL"):
            self._seed_from_ldif()

        if seed_needed:
            self._conn.commit()

    def _seed_default_admin(self):
        hashed = bcrypt.hashpw(b"CHANGE_ME", bcrypt.gensalt()).decode("utf-8")
        self._conn.execute(
            "INSERT OR IGNORE INTO users (username, password, role, vpn_ip, email, allowed_resources) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", hashed, "admin", "10.0.0.1", "admin@CHANGE_ME.local", json.dumps(list(RESOURCE_CATALOG.keys()))),
        )
        self._ensure_posture("admin", "10.0.0.1")

    def _seed_from_ldif(self):
        entries = _parse_ldif_entries(SEED_LDIF)
        if not entries:
            return

        parsed_users: dict[str, dict] = {}
        group_members: dict[str, list[str]] = {}

        for entry in entries:
            dn = entry.get("dn", [""])[0]
            if not dn:
                continue
            if "uid" in entry and "userPassword" in entry:
                uid = entry["uid"][0]
                parsed_users[uid] = {
                    "dn": dn,
                    "password": entry["userPassword"][0],
                    "email": entry.get("mail", [""])[0],
                    "displayName": entry.get("displayName", [uid])[0],
                    "groups": [],
                }
            if "cn" in entry and "member" in entry:
                cn = entry["cn"][0]
                group_members[cn] = [_resolve_uid_from_dn(m) for m in entry["member"]]

        for group_cn, member_uids in group_members.items():
            for uid in member_uids:
                if uid in parsed_users:
                    parsed_users[uid]["groups"].append(group_cn)

        existing = {r["username"] for r in self._conn.execute("SELECT username FROM users").fetchall()}
        vpn_idx = 2
        for uid, pu in parsed_users.items():
            if uid in existing:
                continue
            role = "Operations"
            for gcn in pu["groups"]:
                mapped = _ad_group_to_role(gcn)
                if mapped == "admin":
                    role = "admin"
                    break
                if mapped:
                    role = mapped
            vpn_ip = f"10.0.0.{vpn_idx}"
            vpn_idx += 1
            self._conn.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password, role, vpn_ip, email, display_name, allowed_resources, groups) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    uid,
                    pu["password"],
                    role,
                    vpn_ip,
                    pu["email"],
                    pu["displayName"],
                    json.dumps(list(ROLE_RESOURCES.get(role, []))),
                    json.dumps(pu["groups"]),
                ),
            )
            self._ensure_posture(uid, vpn_ip)
        self._conn.commit()

    def _ensure_posture(self, username: str, vpn_ip: str):
        profile = USER_POSTURE_PROFILES.get(username, {"os": "Windows 11 Enterprise", "firewall": "Active", "compliant": True})
        self._conn.execute(
            "INSERT OR IGNORE INTO device_posture (vpn_ip, os, firewall, compliant) VALUES (?, ?, ?, ?)",
            (vpn_ip, profile["os"], profile["firewall"], 1 if profile["compliant"] else 0),
        )

    def _save(self):
        pass

    def add_log(self, status: str, message: str):
        self._conn.execute(
            "INSERT INTO event_log (timestamp, status, message) VALUES (?, ?, ?)",
            (time.time(), status, message),
        )
        self._conn.commit()

    @property
    def event_log(self):
        rows = self._conn.execute(
            "SELECT timestamp, status, message FROM event_log ORDER BY id DESC LIMIT 500"
        ).fetchall()
        return [dict(r) for r in rows]

    @event_log.setter
    def event_log(self, value):
        pass

    def clear_event_log(self):
        self._conn.execute("DELETE FROM event_log")
        self._conn.commit()

    def delete_session(self, token: str):
        self._conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self._conn.commit()

    def get_user(self, username: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        return self._row_to_user(row)

    def _get_all_usernames(self) -> list[str]:
        return [r["username"] for r in self._conn.execute("SELECT username FROM users").fetchall()]

    def _row_to_user(self, row: sqlite3.Row) -> dict:
        user = dict(row)
        user["allowed_resources"] = json.loads(user.get("allowed_resources", "[]"))
        user["groups"] = json.loads(user.get("groups", "[]"))
        return user

    def upsert_from_ldap(self, username: str, ldap_data: dict, vpn_ip: str = "") -> dict:
        existing = self.get_user(username)
        if existing:
            merged = set(existing["allowed_resources"])
            merged.update(ldap_data.get("allowed_resources", []))
            self._conn.execute(
                "UPDATE users SET role=?, password=?, email=?, groups=?, allowed_resources=?, vpn_ip=COALESCE(NULLIF(?,''), vpn_ip) WHERE username=?",
                (
                    ldap_data["role"],
                    ldap_data.get("password", ""),
                    ldap_data.get("email", ""),
                    json.dumps(ldap_data.get("groups", [])),
                    json.dumps(list(merged)),
                    vpn_ip,
                    username,
                ),
            )
            self._conn.commit()
            return self.get_user(username) or ldap_data

        default_resources = list(ROLE_RESOURCES.get(ldap_data["role"], []))
        self._conn.execute(
            "INSERT OR REPLACE INTO users (username, password, role, vpn_ip, email, groups, allowed_resources) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                ldap_data.get("password", ""),
                ldap_data["role"],
                vpn_ip,
                ldap_data.get("email", ""),
                json.dumps(ldap_data.get("groups", [])),
                json.dumps(default_resources),
            ),
        )
        if vpn_ip:
            self._conn.execute(
                "INSERT OR IGNORE INTO device_posture (vpn_ip) VALUES (?)",
                (vpn_ip,),
            )
        self._conn.commit()
        return self.get_user(username) or ldap_data

    def create_user(self, username: str, password: str, vpn_ip: str, role: str):
        default_resources = list(ROLE_RESOURCES.get(role, []))
        self._conn.execute(
            "INSERT OR REPLACE INTO users (username, password, role, vpn_ip, allowed_resources) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password, role, vpn_ip, json.dumps(default_resources)),
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO device_posture (vpn_ip) VALUES (?)",
            (vpn_ip,),
        )
        self._conn.commit()

    def grant_resource(self, username: str, resource_id: str) -> bool:
        user = self.get_user(username)
        if not user:
            return False
        if resource_id not in user["allowed_resources"]:
            user["allowed_resources"].append(resource_id)
            self._conn.execute(
                "UPDATE users SET allowed_resources=? WHERE username=?",
                (json.dumps(user["allowed_resources"]), username),
            )
            self._conn.commit()
            return True
        return False

    def revoke_resource(self, username: str, resource_id: str) -> bool:
        user = self.get_user(username)
        if not user:
            return False
        if resource_id in user["allowed_resources"]:
            user["allowed_resources"].remove(resource_id)
            self._conn.execute(
                "UPDATE users SET allowed_resources=? WHERE username=?",
                (json.dumps(user["allowed_resources"]), username),
            )
            self._conn.commit()
            return True
        return False

    def delete_user(self, username: str) -> bool:
        cursor = self._conn.execute("DELETE FROM users WHERE username=?", (username,))
        if cursor.rowcount == 0:
            return False
        self._conn.execute("DELETE FROM sessions WHERE username=?", (username,))
        self._conn.execute("DELETE FROM backup_codes WHERE username=?", (username,))
        self._conn.execute("DELETE FROM device_posture WHERE vpn_ip NOT IN (SELECT vpn_ip FROM users WHERE vpn_ip!='')")
        self._conn.commit()
        return True

    def get_session(self, token: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE token=? AND expires>?",
            (token, time.time()),
        ).fetchone()
        if not row:
            self._conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            self._conn.commit()
            return None
        return dict(row)

    def touch_session(self, token: str):
        row = self._conn.execute(
            "SELECT created_at FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if not row:
            return
        now = time.time()
        created = row["created_at"]
        new_expiry = min(now + SESSION_TTL, created + self.MAX_SESSION_LIFETIME)
        self._conn.execute(
            "UPDATE sessions SET expires=? WHERE token=?",
            (new_expiry, token),
        )
        self._conn.commit()

    def invalidate_user_sessions(self, username: str):
        self._conn.execute("DELETE FROM sessions WHERE username=?", (username,))
        self._conn.commit()

    def create_session(self, token: str, username: str, mfa_verified: bool = False):
        now = time.time()
        self._conn.execute(
            "INSERT INTO sessions (token, username, mfa_verified, created_at, expires) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, username, 1 if mfa_verified else 0, now, now + SESSION_TTL),
        )
        self._conn.commit()

    def has_mfa_secret(self, username: str) -> bool:
        row = self._conn.execute(
            "SELECT mfa_secret FROM users WHERE username=? AND mfa_secret!=''",
            (username,),
        ).fetchone()
        return row is not None

    def set_mfa_secret(self, username: str, secret: str):
        self._conn.execute(
            "UPDATE users SET mfa_secret=? WHERE username=?",
            (secret, username),
        )
        self._conn.commit()

    def get_mfa_secret(self, username: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT mfa_secret FROM users WHERE username=?", (username,)
        ).fetchone()
        if row and row["mfa_secret"]:
            return row["mfa_secret"]
        return None

    def admin_get_mfa_secret(self, username: str) -> Optional[str]:
        return self.get_mfa_secret(username)

    def admin_set_mfa_secret(self, username: str, secret: str):
        self.set_mfa_secret(username, secret)

    # ── Backup Recovery Codes ────────────────────────────────────────

    def set_backup_codes(self, username: str, codes: list[str]) -> None:
        self._conn.execute("DELETE FROM backup_codes WHERE username=? AND used=0", (username,))
        for code in codes:
            hashed = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            self._conn.execute(
                "INSERT INTO backup_codes (username, code_hash, used) VALUES (?, ?, 0)",
                (username, hashed),
            )
        self._conn.commit()

    def verify_backup_code(self, username: str, code: str) -> bool:
        rows = self._conn.execute(
            "SELECT id, code_hash FROM backup_codes WHERE username=? AND used=0",
            (username,),
        ).fetchall()
        for row in rows:
            if bcrypt.checkpw(code.encode("utf-8"), row["code_hash"].encode("utf-8")):
                self._conn.execute("UPDATE backup_codes SET used=1 WHERE id=?", (row["id"],))
                self._conn.commit()
                return True
        return False

    def count_remaining_backup_codes(self, username: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM backup_codes WHERE username=? AND used=0",
            (username,),
        ).fetchone()
        return row["cnt"] if row else 0

    def clear_backup_codes(self, username: str) -> None:
        self._conn.execute("DELETE FROM backup_codes WHERE username=?", (username,))
        self._conn.commit()

    def get_backup_codes(self, username: str) -> list[str]:
        """Return the raw code_hashes — used by manage_users.py for inspection."""
        rows = self._conn.execute(
            "SELECT id, code_hash FROM backup_codes WHERE username=? AND used=0",
            (username,),
        ).fetchall()
        return [dict(r) for r in rows]

    def set_preauth_token(self, token: str, username: str, expires: float) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO preauth_tokens (token, username, expires) VALUES (?, ?, ?)",
            (token, username, expires),
        )
        self._conn.commit()

    def pop_preauth_token(self, token: str) -> Optional[dict]:
        self._conn.execute("DELETE FROM preauth_tokens WHERE expires<?", (time.time(),))
        row = self._conn.execute(
            "SELECT * FROM preauth_tokens WHERE token=?", (token,)
        ).fetchone()
        if row:
            self._conn.execute("DELETE FROM preauth_tokens WHERE token=?", (token,))
            self._conn.commit()
            return {"username": row["username"], "expires": row["expires"]}
        self._conn.commit()
        return None

    MAX_SESSION_LIFETIME = int(os.environ.get("MAX_SESSION_LIFETIME", "604800"))  # 7 days

    @property
    def _users(self):
        rows = self._conn.execute("SELECT * FROM users").fetchall()
        return {r["username"]: self._row_to_user(r) for r in rows}

    @_users.setter
    def _users(self, value):
        pass

    @property
    def _sessions(self):
        rows = self._conn.execute("SELECT * FROM sessions WHERE expires>?", (time.time(),)).fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            d["mfa_verified"] = bool(d["mfa_verified"])
            result[d.pop("token")] = d
        return result

    @_sessions.setter
    def _sessions(self, value):
        pass

    @property
    def _device_posture(self):
        rows = self._conn.execute("SELECT * FROM device_posture").fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            d["compliant"] = bool(d["compliant"])
            result[d.pop("vpn_ip")] = d
        return result

    @_device_posture.setter
    def _device_posture(self, value):
        pass
