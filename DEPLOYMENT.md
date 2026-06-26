# Deployment Guide

## Prerequisites

- Docker & Docker Compose
- Git

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/habrok-21/TriGuard.git
cd TriGuard

# 2. Replace all CHANGE_ME values (see checklist below), then:
# 3. Start the stack
docker compose up -d

# 4. Open the app
open http://localhost:8443
```

**Default login:** Username: `admin`, Password: `CHANGE_ME` (change before production)

## Configuration Checklist

All `CHANGE_ME` values must be replaced before running. Use this to find every one:

```bash
make check-config
```

### 1. `docker-compose.yml`

| Variable | Description |
|---|---|
| `LDAP_DOMAIN: "CHANGE_ME.local"` | Your LDAP domain (e.g., `example.com`) |
| `LDAP_ADMIN_PASSWORD: "CHANGE_ME"` | LDAP admin password |
| `API_SECRET_KEY: "CHANGE_ME"` | Secret key for API authentication |
| `LDAP_BASE_DN: "dc=CHANGE_ME,dc=local"` | Must match your LDAP domain |
| `LDAP_BIND_DN: "cn=admin,dc=CHANGE_ME,dc=local"` | LDAP bind user DN |
| `LDAP_BIND_PASSWORD: "CHANGE_ME"` | LDAP bind user password |
| `SMTP_USERNAME: "CHANGE_ME"` | SMTP login (for email OTP) |
| `SMTP_PASSWORD: "CHANGE_ME"` | SMTP password |
| `SMTP_FROM: "CHANGE_ME@CHANGE_ME.local"` | Sender email address |
| `ADMIN_EMAIL: "CHANGE_ME@CHANGE_ME.local"` | Admin email for notifications |

### 2. `ldap/seed.ldif`

Replace all `CHANGE_ME` passwords and `CHANGE_ME.local` email addresses with your own values for each seed user (`jay`, `luffy`, `zoro`, `ace`).

### 3. `server.py`

| Line | What to set |
|---|---|
| `APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")` | Set env var `APP_SECRET_KEY` to a random secret |
| `API_SECRET_KEY` fallback at bottom | Set env var `API_SECRET_KEY` (must match `docker-compose.yml`) |
| `SMTP_FROM` fallback | Set env var `SMTP_FROM` or update the default |

### 4. HTML files (`login.html`, `employee.html`, `admin.html`, `email-verification.html`)

Replace every `'X-API-Key': 'CHANGE_ME'` with your actual API secret key.

Alternatively, remove the hardcoded key from the frontend and fetch it from a server-side config endpoint instead.

### 5. `models.py`

| Line | What to set |
|---|---|
| `b"CHANGE_ME"` (default admin password) | Change the default admin password |
| `"admin@CHANGE_ME.local"` | Default admin email |

### 6. `generate_docs.py`

Replace `CHANGE_ME` with actual credentials if you regenerate the documentation PDF.

---

## Run

```bash
# Start all services
docker compose up -d

# Open the app
open http://localhost:8443
```

## Environment Variables (Alternative)

Instead of editing files, you can create a `.env` file:

```env
APP_SECRET_KEY=your-random-secret
API_SECRET_KEY=your-api-secret
LDAP_SERVER=ldap://openldap:389
LDAP_BASE_DN=dc=example,dc=com
LDAP_DOMAIN=EXAMPLE
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_PASSWORD=your-ldap-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
ADMIN_EMAIL=admin@example.com
```

## Default Users

| Username | Role | Access |
|----------|------|--------|
| `admin` | admin | Full access (MFA required) |
| `jay` | IT Security | 5 resources |
| `luffy` | IT Security | 2 resources |
| `zoro` | Operations | 2 resources |
| `ace` | Finance | 3 resources |

Passwords for all seed users are set in `ldap/seed.ldif` (default: `CHANGE_ME`).

## Useful Commands

| Command | What it does |
|---------|-------------|
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | View gateway logs |
| `make db` | List users in the database |
| `make lock` | Lock DB for production safety |
| `make check-config` | Find remaining `CHANGE_ME` placeholders |
| `make cli` | Run user management CLI (reset MFA, change passwords) |

## Ports

| Port | Service |
|------|---------|
| `8443` | Gateway (FastAPI app) |
| `389` | OpenLDAP |
| `636` | LDAPS |
| `51820` | WireGuard VPN |
| `8001` | Example accounting API |

## Troubleshooting

- **"No database found"** — Normal on first run. The DB is created automatically when the gateway starts.
- **Login fails** — Make sure LDAP is healthy (`docker compose ps`). Check logs with `make logs`.
- **Emails not sending** — Verify SMTP credentials. Gmail users need an [App Password](https://support.google.com/accounts/answer/185833).
- **WireGuard not connecting** — Ensure port `51820/udp` is open on your firewall.
