# Deployment Guide

## Prerequisites

- Docker & Docker Compose
- Git

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/habrok-21/TriGuard.git
cd TriGuard

# 2. Configure environment
```

All `CHANGE_ME` values in the project must be replaced with your own configuration. Here is every location:

---

## Configuration Checklist

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
