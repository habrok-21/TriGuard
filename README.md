# TriGuard — Zero Trust IAM Gateway

Multi-layer authentication (password → TOTP → email OTP), device posture checking, LDAP/AD integration, VPN (WireGuard), reverse proxy, and an admin SIEM dashboard in one Docker Compose stack.

## Architecture

```
User ──► Login (password + TOTP + email OTP) ──► Gateway ──► Protected Apps
                                                    │
                                              ┌─────┴─────┐
                                              │  LDAP/AD   │
                                              │  WireGuard │
                                              │  SIEM Logs │
                                              └────────────┘
```

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

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full configuration checklist covering:
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

## Architecture Notes

- **Password** — validated against LDAP or local SQLite fallback
- **TOTP** — time-based one-time password (authenticator app)
- **Email OTP** — one-time code sent via SMTP
- **Device Posture** — browser fingerprinting and geolocation checks
- **SIEM Dashboard** — real-time authentication logs with filtering
- **Reverse Proxy** — route requests to internal services based on resource permissions
- **WireGuard** — on-the-fly peer provisioning with MFA requirement

## Security

- MFA enrollment required for admin users
- Database is locked in production (`make lock`)
- All credentials are `CHANGE_ME` placeholders — see [DEPLOYMENT.md](DEPLOYMENT.md)
- API keys should be set via environment variables, not hardcoded in HTML

## License

MIT — see [LICENSE](LICENSE)
