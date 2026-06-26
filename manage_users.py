"""
Emergency administration CLI for the Zero Trust IAM Gateway.

Run inside the Docker container:
    docker exec wireguardproject-gateway-1 python /app/manage_users.py --help

Or locally (with store.db in CWD):
    python manage_users.py --reset-mfa admin

Commands:
    --reset-mfa <username>
        Clear the user's mfa_secret so they can re-enroll.
    --change-password <username> <new_password>
        Hash and update the user's password.
    --list-backup-codes <username>
        Show remaining (unused) backup code hashes for a user.
    --reset-backup-codes <username>
        Delete all unused backup codes for a user (new ones
        will be generated on next MFA provisioning).
"""

import argparse
import sqlite3
import sys
from pathlib import Path

import bcrypt


DB_FILE = Path(__file__).parent / "store.db"


def get_conn() -> sqlite3.Connection:
    if not DB_FILE.exists():
        print(f"ERROR: Database not found at {DB_FILE}", file=sys.stderr)
        print("Are you in the project root or running inside the Docker container?", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def cmd_reset_mfa(username: str):
    conn = get_conn()
    cur = conn.execute("SELECT username FROM users WHERE username=?", (username,))
    if not cur.fetchone():
        print(f"ERROR: User '{username}' not found.")
        conn.close()
        sys.exit(1)
    conn.execute("UPDATE users SET mfa_secret='' WHERE username=?", (username,))
    conn.execute("DELETE FROM backup_codes WHERE username=? AND used=0", (username,))
    conn.commit()
    print(f"MFA secret and unused backup codes cleared for '{username}'.")
    print(f"They can now log in and re-enroll MFA.")
    conn.close()


def cmd_change_password(username: str, new_password: str):
    conn = get_conn()
    cur = conn.execute("SELECT username FROM users WHERE username=?", (username,))
    if not cur.fetchone():
        print(f"ERROR: User '{username}' not found.")
        conn.close()
        sys.exit(1)
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn.execute("UPDATE users SET password=? WHERE username=?", (hashed, username))
    # Invalidate all active sessions so user must re-login
    conn.execute("DELETE FROM sessions WHERE username=?", (username,))
    conn.commit()
    print(f"Password updated for '{username}'. All active sessions invalidated.")
    conn.close()


def cmd_list_backup_codes(username: str):
    conn = get_conn()
    cur = conn.execute("SELECT username FROM users WHERE username=?", (username,))
    if not cur.fetchone():
        print(f"ERROR: User '{username}' not found.")
        conn.close()
        sys.exit(1)
    rows = conn.execute(
        "SELECT id, code_hash FROM backup_codes WHERE username=? AND used=0",
        (username,),
    ).fetchall()
    if not rows:
        print(f"No unused backup codes for '{username}'.")
    else:
        print(f"Unused backup codes for '{username}':")
        for r in rows:
            print(f"  [{r['id']}] hash={r['code_hash'][:24]}...")
        print(f"\nTotal remaining: {len(rows)}")
    conn.close()


def cmd_reset_backup_codes(username: str):
    conn = get_conn()
    cur = conn.execute("SELECT username FROM users WHERE username=?", (username,))
    if not cur.fetchone():
        print(f"ERROR: User '{username}' not found.")
        conn.close()
        sys.exit(1)
    conn.execute("DELETE FROM backup_codes WHERE username=?", (username,))
    conn.commit()
    print(f"All backup codes cleared for '{username}'.")
    print("New codes will be generated the next time MFA is provisioned or reset.")
    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Emergency admin CLI for Zero Trust IAM Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--reset-mfa", metavar="USERNAME", help="Clear MFA secret and backup codes for a user")
    parser.add_argument("--change-password", nargs=2, metavar=("USERNAME", "PASSWORD"),
                        help="Change a user's password directly")
    parser.add_argument("--list-backup-codes", metavar="USERNAME", help="Show unused backup codes for a user")
    parser.add_argument("--reset-backup-codes", metavar="USERNAME", help="Delete all backup codes for a user")

    args = parser.parse_args()

    if args.reset_mfa:
        cmd_reset_mfa(args.reset_mfa)
    elif args.change_password:
        cmd_change_password(args.change_password[0], args.change_password[1])
    elif args.list_backup_codes:
        cmd_list_backup_codes(args.list_backup_codes)
    elif args.reset_backup_codes:
        cmd_reset_backup_codes(args.reset_backup_codes)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
