#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DB="results/demo.db"
mkdir -p "$(dirname "$DB")"
SQ="${SQLITE3:-sqlite3}"
[[ -x ./fuin ]] || make fuin
command -v "$SQ" >/dev/null 2>&1 || { echo "sqlite3 not found" >&2; exit 127; }
rm -f "$DB" "$DB-shm" "$DB-wal"

R='\033[0m' B='\033[1;34m' G='\033[1;32m' RED='\033[1;31m' Y='\033[1;33m' D='\033[2m' BD='\033[1m' C='\033[0;36m'

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

# ═════════════════════════════════════════════════════════
echo
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo -e "${B}  STEP 1: Password → Master Key → 3 Subkeys${R}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo
echo -e "  ${D}(example: MySecretPass123)${R}"
echo -ne "  ${BD}Password:${R}"
read -r PW </dev/tty
echo -e "  ${C}Please wait: deriving keys with Argon2id...${R}"
export FUIN_PASSWORD="$PW"
./fuin init -d "$DB" > /dev/null

# Use Python to derive and display actual keys
KDF_OUTPUT="$(python3 demo/demo_kdf.py "$PW" "$DB")"
SALT_HEX="$(echo "$KDF_OUTPUT" | sed -n '1p')"
MK_HEX="$(echo "$KDF_OUTPUT"   | sed -n '2p')"
KE_HEX="$(echo "$KDF_OUTPUT"   | sed -n '3p')"
KA_HEX="$(echo "$KDF_OUTPUT"   | sed -n '4p')"
KT_HEX="$(echo "$KDF_OUTPUT"   | sed -n '5p')"

echo
echo -e "  ${BD}Password${R}   ${D}\"$PW\"${R}"
echo -e "      +"
echo -e "  ${BD}Salt${R}       ${D}${SALT_HEX}${R}  ${C}(128-bit random, stored in DB)${R}"
echo -e "      │"
echo -e "      ▼  ${C}Argon2id (64 MB memory, 3 iterations)${R}"
echo -e "      │"
echo -e "  ${BD}Master Key${R} ${G}${MK_HEX}${R}"
echo -e "      │"
echo -e "      ▼  ${C}HKDF (BLAKE2B, context=\"FuinSeal\")${R}"
echo -e "      ├──────────────────────────────────────"
echo -e "      │"
echo -e "  ${BD}KEK_enc${R}    ${G}${KE_HEX}${R}"
echo -e "             ${C}← wraps the per-secret DEKs${R}"
echo -e "  ${BD}KEK_audit${R}  ${G}${KA_HEX}${R}"
echo -e "             ${C}← signs the audit log${R}"
echo -e "  ${BD}KEK_token${R}  ${G}${KT_HEX}${R}"
echo -e "             ${C}← signs access tokens${R}"
echo
echo -e "  ${BD}Stored in DB:${R}  salt"
echo -e "  ${RED}Never stored:${R}  password, master key, KEK_enc, KEK_audit, KEK_token"
echo -e "              ${C}(master key zeroized right after the split; subkeys live only in memory)${R}"

wait_enter \
    "Initialized a fresh vault and derived the password into separate encryption, audit, and token subkeys." \
    "Store a secret with envelope encryption and inspect what SQLite stores instead of the plaintext."

# ═════════════════════════════════════════════════════════
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo -e "${B}  STEP 2: Envelope Encryption — Encrypt${R}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo
echo -e "  ${D}(example name: database/prod/password)${R}"
echo -ne "  ${BD}Secret name: ${R}"
read -r SNAME </dev/tty
echo -e "  ${D}(example value: P@ssw0rd-2026)${R}"
echo -ne "  ${BD}Secret value: ${R}"
read -r SVAL </dev/tty
printf '%s' "$SVAL" | ./fuin put -d "$DB" -n "$SNAME" --stdin > /dev/null

CT_HEX="$("$SQ" "$DB" "SELECT HEX(ciphertext) FROM secrets ORDER BY rowid DESC LIMIT 1;")"
EDEK_HEX="$("$SQ" "$DB" "SELECT HEX(encrypted_dek) FROM secrets ORDER BY rowid DESC LIMIT 1;")"
EDEK_BYTES=$(( ${#EDEK_HEX} / 2 ))
NONCE_HEX="$("$SQ" "$DB" "SELECT HEX(nonce) FROM secrets ORDER BY rowid DESC LIMIT 1;")"
ALGO="$("$SQ" "$DB" "SELECT algorithm FROM secrets ORDER BY rowid DESC LIMIT 1;")"
NAME_LOOKUP="$("$SQ" "$DB" "SELECT name FROM secrets ORDER BY rowid DESC LIMIT 1;")"

echo
echo -e "  ${BD}Your plaintext${R}      ${G}${SVAL}${R}"
echo -e "      │"
echo -e "      │  ${C}① generate a random DEK (256-bit)${R}"
echo -e "      ▼"
echo -e "  ${BD}DEK encrypts secret${R} ${C}${ALGO}${R}"
echo -e "      │               AAD = H(row_id, name):1"
echo -e "      ▼"
echo -e "  ${BD}ciphertext${R}          ${D}${CT_HEX}${R}"
echo
echo -e "  ${BD}The DEK itself${R}"
echo -e "      │"
echo -e "      │  ${C}② KEK_enc wraps the DEK${R}"
echo -e "      ▼"
echo -e "  ${BD}encrypted_dek${R}       ${D}${EDEK_HEX}${R}"
echo -e "                       ${C}(32-byte DEK + AEAD tag = ${EDEK_BYTES} bytes here)${R}"
echo
echo -e "  ${BD}nonce${R}               ${D}${NONCE_HEX}${R}"
echo
echo -e "  ${BD}Stored in DB:${R}  ciphertext, encrypted_dek, nonce, algorithm"
echo -e "                 name lookup key ${D}${NAME_LOOKUP}${R}"
echo -e "  ${RED}Never stored:${R}  plaintext, DEK, plaintext secret name"
echo -e "              ${C}(DEK zeroized right after use; plaintext never touches disk)${R}"

wait_enter \
    "Encrypted your secret with a random DEK, wrapped that DEK with KEK_enc, and stored only ciphertext metadata." \
    "Walk the reverse path: unwrap the DEK, verify AAD and tags, then recover the plaintext."

# ═════════════════════════════════════════════════════════
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo -e "${B}  STEP 3: Decrypt — the reverse path${R}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo
echo -e "  ${BD}encrypted_dek${R}       ${D}${EDEK_HEX}${R}"
echo -e "      │"
echo -e "      │  ${C}① KEK_enc unwraps → recover the DEK${R}"
echo -e "      ▼"
echo -e "  ${BD}ciphertext${R}          ${D}${CT_HEX}${R}"
echo -e "      │"
echo -e "      │  ${C}② DEK decrypts → recover the plaintext${R}"
echo -e "      │  ${C}   verify AAD (H(row_id, name):1) + tag${R}"
echo -e "      ▼"
DECRYPTED="$(./fuin get -d "$DB" -n "$SNAME")"
echo -e "  ${BD}Decrypted${R}           ${G}${BD}${DECRYPTED}${R}"

wait_enter \
    "Decrypted the stored ciphertext back to the original secret after both AEAD checks passed." \
    "Inspect the audit log entries that were appended while the vault was used."

# ═════════════════════════════════════════════════════════
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo -e "${B}  STEP 4: Audit Log — Hash Chain + HMAC${R}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo

# Read chain data from DB
E1_ACTION="$("$SQ" "$DB" "SELECT action FROM audit_log WHERE entry_id=1;")"
E1_TARGET="$("$SQ" "$DB" "SELECT SUBSTR(target,1,16) || '...' FROM audit_log WHERE entry_id=1;")"
E1_HASH="$("$SQ" "$DB" "SELECT HEX(entry_hash) FROM audit_log WHERE entry_id=1;")"
E1_PREV="$("$SQ" "$DB" "SELECT HEX(prev_hash) FROM audit_log WHERE entry_id=1;")"
E1_HMAC="$("$SQ" "$DB" "SELECT HEX(SUBSTR(hmac_signature,1,8)) FROM audit_log WHERE entry_id=1;")"

E2_ACTION="$("$SQ" "$DB" "SELECT action FROM audit_log WHERE entry_id=2;")"
E2_TARGET="$("$SQ" "$DB" "SELECT SUBSTR(target,1,16) || '...' FROM audit_log WHERE entry_id=2;")"
E2_HASH="$("$SQ" "$DB" "SELECT HEX(entry_hash) FROM audit_log WHERE entry_id=2;")"
E2_PREV="$("$SQ" "$DB" "SELECT HEX(prev_hash) FROM audit_log WHERE entry_id=2;")"
E2_HMAC="$("$SQ" "$DB" "SELECT HEX(SUBSTR(hmac_signature,1,8)) FROM audit_log WHERE entry_id=2;")"

echo -e "  ${BD}Every operation appends an audit entry; entries are linked in a hash chain:${R}"
echo
echo -e "  ┌─ Entry #1 ──────────────────────────────┐"
echo -e "  │  action:     ${G}${E1_ACTION}${R}"
echo -e "  │  target:     ${E1_TARGET}"
echo -e "  │  prev_hash:  ${D}${E1_PREV}${R}  ${C}(init = 0)${R}"
echo -e "  │  entry_hash: ${D}${E1_HASH}${R}"
echo -e "  │  hmac:       ${D}${E1_HMAC}...${R}  ${C}← HMAC(ratcheted audit key, entry)${R}"
echo -e "  └─────────────────────────────────────────┘"
echo -e "       │ entry_hash feeds the next entry's prev_hash"
echo -e "       ▼"
echo -e "  ┌─ Entry #2 ──────────────────────────────┐"
echo -e "  │  action:     ${G}${E2_ACTION}${R}"
echo -e "  │  target:     ${E2_TARGET}"
echo -e "  │  prev_hash:  ${D}${E2_PREV}${R}"
echo -e "  │  entry_hash: ${D}${E2_HASH}${R}"
echo -e "  │  hmac:       ${D}${E2_HMAC}...${R}  ${C}← HMAC(ratcheted audit key, entry)${R}"
echo -e "  └─────────────────────────────────────────┘"
echo
echo -e "  ${BD}Stored in DB:${R}  action, target lookup key, prev_hash, entry_hash, hmac_signature"
echo -e "  ${C}verify = recompute every hash + check the chain links + verify HMAC signatures${R}"
echo
./fuin audit-verify -d "$DB" > /dev/null 2>&1
echo -e "  ${G}✓ Hash chain intact; all HMAC signatures verify${R}"

wait_enter \
    "Verified the clean audit log by recomputing each hash-chain link and HMAC signature." \
    "Simulate a database attacker changing an audit row directly with SQLite."

# ═════════════════════════════════════════════════════════
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo -e "${B}  STEP 5: Attacker tampers → detected${R}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}"
echo
echo -e "  ${RED}${BD}Attack: with direct DB access, flip entry #1's CREATE to DELETE via SQLite${R}"
"$SQ" "$DB" "UPDATE audit_log SET action = 'DELETE' WHERE entry_id = 1;"

# Read tampered data
E1T_ACTION="$("$SQ" "$DB" "SELECT action FROM audit_log WHERE entry_id=1;")"
E1T_HASH="$("$SQ" "$DB" "SELECT HEX(entry_hash) FROM audit_log WHERE entry_id=1;")"

echo
echo -e "  ┌─ Entry #1 (tampered) ───────────────────┐"
echo -e "  │  action:     ${RED}${E1T_ACTION}${R}  ${RED}← was CREATE${R}"
echo -e "  │  target:     ${E1_TARGET}"
echo -e "  │  entry_hash: ${D}${E1T_HASH}${R}  ${RED}← still the old hash!${R}"
echo -e "  │  hmac:       ${D}${E1_HMAC}...${R}  ${RED}← still the old signature!${R}"
echo -e "  └─────────────────────────────────────────┘"
echo -e "       │"
echo -e "       ▼  ${RED}hash = SHA-256(\"DELETE\"...) ≠ stored entry_hash${R}"
echo -e "          ${RED}recomputed HMAC fails too → even a fixed-up hash cannot be re-signed without the audit key${R}"

wait_enter \
    "Changed an audit action in SQLite without updating the stored hash or HMAC signature." \
    "Run audit verification again and confirm the tamper evidence trips."

set +e
./fuin audit-verify -d "$DB" > /dev/null 2>&1
VERIFY_STATUS=$?
set -e

echo -e "  ┌──────────────────────────────────────────────────────────┐"
if [[ "$VERIFY_STATUS" -ne 0 ]]; then
echo -e "  │              ${RED}${BD}✗  TAMPERING DETECTED${R}                       │"
else
echo -e "  │  demo failed: verification unexpectedly succeeded       │"
fi
echo -e "  └──────────────────────────────────────────────────────────┘"

if [[ "$VERIFY_STATUS" -ne 0 ]]; then
    finish_enter "Finished the guided demo; audit verification rejected the tampered log."
else
    finish_enter "Finished the guided demo; verification unexpectedly succeeded."
    exit 1
fi
