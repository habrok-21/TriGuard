SHELL := /bin/bash
.ONESHELL:

# ─── Protection ───────────────────────────────────────────────────
# store.db is IMMUTABLE — it contains MFA keys, backup codes, and
# authentication data. Never delete it. Never edit it. Never reset it.
# To RESET everything, you must explicitly run: make destroy
DB_LOCK := .db-lock

guard:
	@if [ ! -f "$(DB_LOCK)" ]; then \
		echo "ERROR: store.db is UNLOCKED — run 'make lock' first"; \
		exit 1; \
	fi

lock:
	@./protect_db.sh lock

unlock:
	@./protect_db.sh unlock

# ─── Safe Commands ────────────────────────────────────────────────
up:
	@docker compose up -d

down:
	@docker compose down

restart: down up

logs:
	@docker compose logs -f gateway

# ─── Inspection (safe, read-only) ─────────────────────────────────
db:
	@if [ -f store.db ]; then sqlite3 -header -column store.db "SELECT username,role,vpn_ip,email,CASE WHEN mfa_secret!='' THEN 'YES' ELSE 'NO' END AS mfa FROM users;"; else echo "No database found."; fi

db-full:
	@sqlite3 -header -column store.db \
		"SELECT '── USERS ──' AS tbl;" \
		"SELECT username,role,vpn_ip,email FROM users;" \
		"SELECT '── SESSIONS ──' AS tbl;" \
		"SELECT token,username,mfa_verified FROM sessions;" \
		"SELECT '── BACKUP CODES ──' AS tbl;" \
		"SELECT username,used FROM backup_codes;" 2>/dev/null || true

# ─── Destructive (requires explicit guard removal) ────────────────
destroy:
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║   WARNING: This will DELETE store.db (MFA keys, etc.)  ║"
	@echo "║   Remove $(DB_LOCK) first to proceed.               ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@exit 1

# ─── CLI Tool ──────────────────────────────────────────────────────
cli:
	@read -p "Username: " u; \
	 read -p "Action (reset-mfa / reset-backup-codes / change-password): " a; \
	 docker exec -it wireguardproject-gateway-1 python /app/manage_users.py --$${a} $${u}

# ─── Configuration Check ───────────────────────────────────────────
check-config:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║           Remaining CHANGE_ME placeholders                  ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@grep -rn "CHANGE_ME" --include='*.py' --include='*.html' --include='*.yml' --include='*.yaml' --include='*.ldif' --include='*.conf' --include='*.sh' --include='*.md' . 2>/dev/null | grep -v 'node_modules/' | grep -v '.git/' | grep -v '__pycache__/' || echo "None found — all configured!"
	@echo ""
	@echo "Docs: see DEPLOYMENT.md for details on each setting."

.PHONY: lock unlock up down restart logs db db-full destroy cli guard check-config
