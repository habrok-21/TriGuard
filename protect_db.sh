#!/bin/bash
# Database Protection Script
# Usage: ./protect_db.sh [status|lock|unlock]
# 
# When LOCKED, the script will warn before allowing store.db deletion.

LOCK_FILE=".db-lock"

case "${1:-status}" in
  lock)
    touch "$LOCK_FILE"
    echo "🔒 DATABASE LOCKED — store.db is protected from accidental deletion."
    ;;
  unlock)
    rm -f "$LOCK_FILE"
    echo "🔓 DATABASE UNLOCKED — store.db can be deleted."
    ;;
  status)
    if [ -f "$LOCK_FILE" ]; then
      echo "🔒 DATABASE IS LOCKED"
      echo "   Run './protect_db.sh unlock' to allow deletion."
    else
      echo "🔓 DATABASE IS UNLOCKED"
      echo "   Run './protect_db.sh lock' to protect from accidental deletion."
    fi
    ;;
  *)
    echo "Usage: ./protect_db.sh [status|lock|unlock]"
    ;;
esac
