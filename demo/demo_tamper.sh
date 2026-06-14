#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DB_PATH="${1:-results/tamper_demo.db}"
FUIN_PASSWORD_VALUE="${FUIN_PASSWORD:-tamper-demo-pass}"
SQLITE_BIN="${SQLITE3:-sqlite3}"
R='\033[0m' B='\033[1;34m' G='\033[1;32m' RED='\033[1;31m' Y='\033[1;33m' D='\033[2m' BD='\033[1m' C='\033[0;36m'

if [[ ! -x ./fuin ]]; then
    make fuin
fi

command -v "$SQLITE_BIN" >/dev/null 2>&1 || {
    echo "sqlite3 not found" >&2
    exit 127
}

mkdir -p "$(dirname "$DB_PATH")"
rm -f "$DB_PATH" "$DB_PATH-shm" "$DB_PATH-wal"

export FUIN_PASSWORD="$FUIN_PASSWORD_VALUE"

wait_enter() {
    local completed="$1"
    local next="$2"
    echo
    echo -e "  ${G}Completed:${R} ${completed}"
    echo -e "  ${Y}Next:${R} ${next}"
    read -rp "  Press Enter to continue..." </dev/tty
    echo
}

finish_enter() {
    local completed="$1"
    echo
    echo -e "  ${G}Completed:${R} ${completed}"
    read -rp "  Press Enter to finish..." </dev/tty
    echo
}

section() {
    echo
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
    echo -e "${B}  $1${R}"
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
    echo
}

show_sql() {
    echo -e "  ${D}SQL>${R} $1"
}

section "STEP 1: Setup clean vault"
echo -e "  ${C}Create a fresh vault, store two secrets, read one, and delete one.${R}"
echo -e "  ${C}Those user actions will append signed audit rows.${R}"
echo
./fuin init -d "$DB_PATH"
printf 'primary-db-password' | ./fuin put -d "$DB_PATH" -n database/prod/password --stdin
printf 'stripe-live-key' | ./fuin put -d "$DB_PATH" -n api/stripe/key --stdin
./fuin get -d "$DB_PATH" -n database/prod/password >/dev/null
./fuin delete -d "$DB_PATH" -n api/stripe/key
echo
echo -e "  ${G}✓ Demo vault populated at ${DB_PATH}${R}"

wait_enter \
    "Created a clean vault and generated an audit trail for CREATE, READ, and DELETE operations." \
    "Query the audit_log table directly to see what evidence is stored."

section "STEP 2: Read audit log with SQL"
echo -e "  ${C}This SQL query does not verify anything yet; it only shows the audit rows stored in SQLite.${R}"
echo -e "  ${C}entry_id gives order, action says what happened, target is the keyed secret lookup, and result is success/failure.${R}"
echo
show_sql "SELECT entry_id, action, SUBSTR(target,1,16)||'...' AS target_lookup, target_version, result FROM audit_log ORDER BY entry_id;"
"$SQLITE_BIN" "$DB_PATH" \
    "SELECT entry_id, action, SUBSTR(target,1,16)||'...' AS target_lookup, target_version, result FROM audit_log ORDER BY entry_id;"

wait_enter \
    "Displayed the audit trail exactly as SQLite stores it before any tampering." \
    "Run audit verification so Fuin recomputes the hash chain and HMAC signatures."

section "STEP 3: Verify clean audit log"
echo -e "  ${C}audit-verify recomputes every entry hash, checks each prev_hash link, and verifies the HMAC signatures.${R}"
echo -e "  ${C}A clean log should pass because the stored rows match their cryptographic evidence.${R}"
echo
echo -e "  ${D}$ ./fuin audit-verify -d \"$DB_PATH\"${R}"
./fuin audit-verify -d "$DB_PATH"

wait_enter \
    "Confirmed the original audit log is internally consistent and cryptographically signed." \
    "Act as an attacker with direct SQLite access and change one audit action without the audit key."

section "STEP 4: Tamper with SQLite data"
echo -e "  ${RED}The attacker edits entry #2 from its original action to READ.${R}"
echo -e "  ${RED}They can change the database row, but they cannot recompute a valid HMAC without the ratcheted audit key.${R}"
echo
show_sql "UPDATE audit_log SET action = 'READ' WHERE entry_id = 2;"
"$SQLITE_BIN" "$DB_PATH" "UPDATE audit_log SET action = 'READ' WHERE entry_id = 2;"
echo
show_sql "SELECT entry_id, action, SUBSTR(target,1,16)||'...' AS target_lookup, target_version, result FROM audit_log ORDER BY entry_id;"
"$SQLITE_BIN" "$DB_PATH" \
    "SELECT entry_id, action, SUBSTR(target,1,16)||'...' AS target_lookup, target_version, result FROM audit_log ORDER BY entry_id;"

wait_enter \
    "Modified one audit row through SQLite while leaving the old hash and HMAC evidence behind." \
    "Run audit verification again; the recomputed evidence should no longer match."

section "STEP 5: Verify tampered audit log"
echo -e "  ${C}Now audit-verify recomputes the evidence from the edited row.${R}"
echo -e "  ${C}The changed action breaks the stored entry hash and HMAC, so verification must fail.${R}"
echo
echo -e "  ${D}$ ./fuin audit-verify -d \"$DB_PATH\"${R}"
set +e
VERIFY_OUTPUT="$(./fuin audit-verify -d "$DB_PATH" 2>&1)"
VERIFY_STATUS=$?
set -e

printf '%s\n' "$VERIFY_OUTPUT"
if [[ "$VERIFY_STATUS" -eq 0 ]]; then
    echo "tamper demo failed: verification unexpectedly succeeded" >&2
    finish_enter "Finished tamper demo with an unexpected verification success."
    exit 1
fi

echo
echo -e "${RED}${BD}TAMPERING DETECTED:${R} audit verification rejected the modified log."
finish_enter "Finished tamper demo; audit verification rejected the modified log."
