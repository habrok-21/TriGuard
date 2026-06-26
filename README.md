# TriGuard — Zero Trust IAM Gateway

Multi-layer authentication (password → TOTP → email OTP), device posture checking, LDAP/AD integration, VPN (WireGuard), reverse proxy, and an admin SIEM dashboard in one Docker Compose stack.

---

## Overview

TriGuard is a complete identity and access management system that sits in front of your internal applications and enforces strict security policies before allowing access. It combines a reverse proxy, authentication server, and policy engine into a single deployable unit powered by Docker.

| Component | Role |
|-----------|------|
| FastAPI Gateway | Authentication, authorization, session management |
| OpenLDAP | User directory and group sync |
| WireGuard | Secure network layer between services |
| SQLite | Persistent store for users, sessions, MFA keys, logs |

---

## The Problem

Traditional network security relies on a castle-and-moat model — once inside the corporate network, users have broad access to internal resources. This approach has critical flaws:

- **Stolen passwords** grant access to everything
- **No per-request verification** after login
- **No device health checks** before access
- **No centralized audit trail** of who accessed what
- **Single-factor authentication** is easily compromised

---

## Our Solution

TriGuard - The Zero Trust IAM Gateway implements a **never trust, always verify** architecture :

### Three-Layer Authentication
1. **Username & Password** — verified against LDAP or local database
2. **Time-based One-Time Password (TOTP)** — 6-digit code from authenticator app, valid for 30 seconds
3. **Email OTP** — 6-digit code sent to registered email (admin only)

### Policy-Based Access Control
- Role-based resource assignment (Finance, IT Security, Operations, etc.)
- Per-user resource overrides for fine-grained control
- Device posture evaluation with firewall compliance tracking

### Comprehensive Session Management
- 24-hour session lifetime with sliding expiry
- In-memory active session tracking for real-time visibility
- Immediate session invalidation on logout, password change, or MFA reset

### Enterprise-Ready Features
- LDAP synchronization for user creation, deletion, and password changes
- Backup recovery codes (3 per user, bcrypt-hashed, single-use)
- Emergency CLI tool for MFA/password/backup code resets
- Full SIEM event log with filtering and export
- Device posture profiles per user (OS, firewall status, compliance)

---

## Architecture

```
User ──► Login (password + TOTP + email OTP) ──► Gateway ──► Protected Apps
                                                    │
                                              ┌─────┴────-─┐
                                              │  LDAP/AD   │
                                              │  WireGuard │
                                              │  SIEM Logs │
                                              └────────────┘
```

## Authentication Flow

```
User → Login Page → POST /api/auth/login
                        ↓
               Password verified (LDAP or local)
                        ↓
               MFA required?
                ├── No  → Session created immediately
                └── Yes → Return preauth_token
                            ↓
                    POST /api/auth/verify-mfa (TOTP)
                     or POST /api/auth/verify-backup-code
                            ↓
                    Is admin?
                    ├── No  → Session created
                    └── Yes → Email OTP sent
                               ↓
                         POST /api/auth/verify-email-otp
                               ↓
                         Session created
```

---

## Tech Stack

- **Python 3.11** with **FastAPI** — high-performance async web framework
- **SQLite** with WAL mode — transactional, crash-safe persistence
- **Docker & Docker Compose** — containerized deployment
- **OpenLDAP** — user directory service
- **WireGuard** — secure network tunneling
- **pyotp** — TOTP (RFC 6238) implementation
- **bcrypt** — password and backup code hashing
- **ldap3** — LDAP protocol client

---

## Key Features

- **3-layer authentication** (Password + TOTP + Email OTP)
- **Backup recovery codes** (3 per user, one-time use)
- **LDAP synchronization** (read/write — create, delete, password sync)
- **Device posture evaluation** (OS detection, firewall compliance)
- **Real-time active session tracking** with auto-refresh dashboard
- **SIEM event log** with keyword filtering
- **Emergency CLI** for MFA and password resets
- **Database protection** — lock/unlock mechanism prevents accidental deletion
- **Session persistence** — survives container restarts via Docker bind mount

---

## Security

- Passwords stored as bcrypt hashes
- MFA secrets stored in SQLite (not in memory)
- Backup codes bcrypt-hashed before storage
- HTTP-only session cookies with 24-hour TTL
- API key authentication for all endpoints
- Preauth tokens expire after 10 minutes
- Password strength validation (min 8 chars, uppercase + digit required)

---

## Project Structure

```
├── server.py              # Main FastAPI application
├── models.py              # SQLite PeerStore and data models
├── proxy.py               # Reverse proxy router
├── ad_auth.py             # Active Directory / LDAP authentication
├── manage_users.py        # Emergency CLI tool
├── login.html             # Login page with MFA + backup code UI
├── admin.html             # Admin dashboard
├── employee.html          # Employee dashboard
├── email-verification.html# Email OTP verification page
├── Dockerfile             # Container build instructions
├── docker-compose.yml     # Multi-container orchestration
├── requirements.txt       # Python dependencies
├── protect_db.sh          # Database lock/unlock script
├── Makefile               # Common command shortcuts
├── ldap/seed.ldif         # LDAP seed data
├── store.db               # SQLite database (persistent)
└── .db-lock               # Database protection marker
```

---

## Quick Start

```bash
# 1. Configure all CHANGE_ME values first (see below)
# 2. Start the stack
docker compose up -d

# 3. Open the app
open http://localhost:8443
```

## Configuration

**Before running, you must replace every `CHANGE_ME` placeholder with your own values.**

Run this to find every location:

```bash
make check-config
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full configuration checklist covering :

- `docker-compose.yml` — LDAP domain, admin password, API secret, SMTP credentials
- `ldap/seed.ldif` — seed user passwords and emails
- HTML files — hardcoded `X-API-Key` in login/employee/admin pages
- `server.py` and `models.py` — default admin credentials
- `generate_docs.py` — documentation credentials

## Commands

| Command | Description |
|---|---|
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | Tail gateway logs |
| `make db` | Inspect users in the database |
| `make cli` | Run user management (reset MFA, etc.) |
| `make lock` | Lock the database (production safety) |
| `make check-config` | Find all remaining CHANGE_ME placeholders |
| `make destroy` | Wipe the database completely |

## Services

- **Gateway** (port `8443`) — FastAPI app: authentication, authorization, reverse proxy
- **OpenLDAP** (port `389`) — User directory
- **WireGuard** (port `51820`) — VPN access
- **Accounting API** (port `8001`) — Example backend (replace with your own)

## Security

- MFA enrollment required for admin users
- Database is locked in production (`make lock`)
- All credentials are `CHANGE_ME` placeholders — see [DEPLOYMENT.md](DEPLOYMENT.md)
- API keys should be set via environment variables, not hardcoded in HTML

## License

MIT — see [LICENSE](LICENSE)
