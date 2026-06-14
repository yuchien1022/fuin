#!/bin/sh
# End-to-end CLI smoke for the Linux/glibc runtime path. Run via
# `make ci-linux-smoke`, which executes it inside the Ubuntu container.
#
# It focuses on the features whose RUNTIME behaviour differs from a native
# macOS build (compile-level coverage is already in `make ci-linux`):
#   - default AEAD = XChaCha20-Poly1305 (macOS defaults to AEGIS-256)
#   - --algorithm AES-256-GCM / AEGIS-256 must degrade gracefully, never crash
#   - PQC (ML-KEM-768) / ML-DSA-65 availability depends on the OpenSSL version;
#     graceful fallback (clean non-zero, no crash) is acceptable and expected
#     on the OpenSSL-3.0 CI runner
#   - realpath / O_NOFOLLOW / owner-only file-security semantics
#
# Non-interactive via FUIN_PASSWORD / FUIN_NEW_PASSWORD / --key-passphrase-file.
# Exit non-zero only on a hard failure or a crash (signal); availability gaps
# are reported, not failed.

FUIN=./fuin
WORK="$(mktemp -d)"
DB="$WORK/vault.db"
KP="$WORK/keypass.txt"
KEEPVAL="keep-this-value-42"
PASS=0
FAIL=0

export FUIN_PASSWORD="correct horse battery staple"
printf 'k3y-passphrase-xyz\n' > "$KP"
chmod 600 "$KP"

ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }
note() { printf '  [info] %s\n' "$1"; }

echo "== A. init + default AEAD (XChaCha20 on Linux) round-trip =="
"$FUIN" init -d "$DB" >/dev/null 2>"$WORK/e" && ok "init" || bad "init: $(head -1 "$WORK/e")"
printf '%s' "$KEEPVAL" | "$FUIN" put -d "$DB" -n keep/secret --stdin >/dev/null 2>"$WORK/e" \
    && ok "put (default AEAD)" || bad "put: $(head -1 "$WORK/e")"
GOT="$("$FUIN" get -d "$DB" -n keep/secret 2>/dev/null)"
[ "$GOT" = "$KEEPVAL" ] && ok "get round-trip value matches" || bad "get mismatch: '$GOT'"
if "$FUIN" status-report -d "$DB" 2>/dev/null | grep -iqE 'xchacha|chacha'; then
    ok "default cipher reported as XChaCha20"
else
    note "could not confirm cipher name from status-report (informational)"
fi
"$FUIN" list -d "$DB" >/dev/null 2>&1 && ok "list" || bad "list"

echo "== B. versioning + rollback =="
printf 'v2-value' | "$FUIN" put -d "$DB" -n keep/secret --stdin >/dev/null 2>&1 \
    && ok "put v2" || bad "put v2"
V2="$("$FUIN" get -d "$DB" -n keep/secret 2>/dev/null)"
[ "$V2" = "v2-value" ] && ok "latest = v2" || bad "latest != v2: '$V2'"
"$FUIN" rollback keep/secret --version 1 -d "$DB" >/dev/null 2>"$WORK/e" \
    && ok "rollback v1" || bad "rollback: $(head -1 "$WORK/e")"
VR="$("$FUIN" get -d "$DB" -n keep/secret 2>/dev/null)"
[ "$VR" = "$KEEPVAL" ] && ok "value after rollback = v1" || bad "rollback value: '$VR'"

echo "== C. generate / delete / list --all =="
"$FUIN" generate gen/pw -d "$DB" >/dev/null 2>"$WORK/e" && ok "generate" || bad "generate: $(head -1 "$WORK/e")"
printf 'tmp' | "$FUIN" put -d "$DB" -n tmp/del --stdin >/dev/null 2>&1
"$FUIN" delete tmp/del -d "$DB" >/dev/null 2>"$WORK/e" && ok "delete (soft)" || bad "delete: $(head -1 "$WORK/e")"
"$FUIN" list --all -d "$DB" >/dev/null 2>&1 && ok "list --all" || bad "list --all"

echo "== D. --algorithm graceful handling (no crash on unavailable) =="
for ALG in XChaCha20-Poly1305 AES-256-GCM AEGIS-256; do
    printf 'x' | "$FUIN" put -d "$DB" -n "alg/$ALG" --algorithm "$ALG" --stdin >/dev/null 2>"$WORK/e"; rc=$?
    if [ "$rc" -ge 128 ]; then bad "--algorithm $ALG CRASHED (rc=$rc)"
    elif [ "$rc" -eq 0 ]; then ok "--algorithm $ALG available and worked"
    else ok "--algorithm $ALG unavailable, rejected cleanly (rc=$rc: $(head -1 "$WORK/e"))"
    fi
done

echo "== E. file-security: O_NOFOLLOW rejects a symlinked DB path =="
ln -s "$WORK/sl_target.db" "$WORK/sl_link.db"
( FUIN_PASSWORD="pw" "$FUIN" init -d "$WORK/sl_link.db" ) >/dev/null 2>"$WORK/e"; rc=$?
if [ "$rc" -ge 128 ]; then bad "init via symlink CRASHED (rc=$rc)"
elif [ "$rc" -ne 0 ]; then ok "init via symlinked DB path rejected (rc=$rc)"
else bad "init via symlinked DB path was ALLOWED (expected O_NOFOLLOW rejection)"
fi

echo "== F. PQC hybrid backup round-trip (OpenSSL-version dependent) =="
"$FUIN" pqc-keygen --public-out "$WORK/backup.pub" --private-out "$WORK/backup.key" \
    --key-passphrase-file "$KP" >/dev/null 2>"$WORK/e"; rc=$?
if [ "$rc" -ge 128 ]; then bad "pqc-keygen CRASHED (rc=$rc)"; pqc=0
elif [ "$rc" -eq 0 ]; then ok "pqc-keygen (X25519+ML-KEM-768) available"; pqc=1
else ok "pqc-keygen unavailable, clean fallback (rc=$rc: $(head -1 "$WORK/e")) — expected on OpenSSL 3.0"; pqc=0
fi
if [ "$pqc" -eq 1 ]; then
    "$FUIN" backup-export -d "$DB" --recipient "$WORK/backup.pub" --out "$WORK/vault.fuincap" \
        >/dev/null 2>"$WORK/e" && ok "backup-export" || bad "backup-export: $(head -1 "$WORK/e")"
    "$FUIN" backup-import --private-key "$WORK/backup.key" --input "$WORK/vault.fuincap" \
        --out "$WORK/restored.db" --key-passphrase-file "$KP" >/dev/null 2>"$WORK/e" \
        && ok "backup-import" || bad "backup-import: $(head -1 "$WORK/e")"
    RV="$("$FUIN" get -d "$WORK/restored.db" -n keep/secret 2>/dev/null)"
    [ "$RV" = "$KEEPVAL" ] && ok "restored capsule round-trips secret" || bad "restored value: '$RV'"
else
    note "skipping backup round-trip (PQC unavailable — expected on OpenSSL 3.0 CI runner)"
fi

echo "== G. ML-DSA-65 audit signing availability =="
"$FUIN" audit-keygen --public-out "$WORK/audit.pub" --private-out "$WORK/audit.key" \
    --key-passphrase-file "$KP" >/dev/null 2>"$WORK/e"; rc=$?
if [ "$rc" -ge 128 ]; then bad "audit-keygen CRASHED (rc=$rc)"
elif [ "$rc" -eq 0 ]; then ok "audit-keygen (ML-DSA-65) available"
else ok "audit-keygen (ML-DSA-65) unavailable, clean fallback (rc=$rc) — expected on OpenSSL 3.0"
fi

echo "== H. lifecycle: rotate-kek, tokens, TTL, audit chain =="
NEWPW="rotated-master-pw-456"
FUIN_NEW_PASSWORD="$NEWPW" "$FUIN" rotate-kek -d "$DB" >/dev/null 2>"$WORK/e"; rc=$?
if [ "$rc" -eq 0 ]; then ok "rotate-kek"; export FUIN_PASSWORD="$NEWPW"; else bad "rotate-kek: $(head -1 "$WORK/e")"; fi
RK="$("$FUIN" get -d "$DB" -n keep/secret 2>/dev/null)"
[ "$RK" = "$KEEPVAL" ] && ok "secret readable after rotate-kek (new password)" || bad "post-rotate get: '$RK'"
TOKEN="$("$FUIN" issue-token --scope 'read:keep/*' --subject svc:test --ttl 1h -d "$DB" 2>/dev/null | tail -1)"
[ -n "$TOKEN" ] && ok "issue-token" || bad "issue-token"
FUIN_TOKEN="$TOKEN" "$FUIN" check-token --scope 'read:keep/secret' -d "$DB" >/dev/null 2>"$WORK/e" \
    && ok "check-token (valid scope)" || bad "check-token: $(head -1 "$WORK/e")"
"$FUIN" revoke-tokens -d "$DB" >/dev/null 2>&1 && ok "revoke-tokens" || bad "revoke-tokens"
printf 'ttlv' | "$FUIN" put -d "$DB" -n ttl/short --ttl 1s --stdin >/dev/null 2>&1 \
    && ok "put with --ttl" || bad "put --ttl"
"$FUIN" check-expiry --within 365d -d "$DB" >/dev/null 2>&1 && ok "check-expiry" || bad "check-expiry"
"$FUIN" auto-rotate -d "$DB" >/dev/null 2>"$WORK/e" && ok "auto-rotate" || bad "auto-rotate: $(head -1 "$WORK/e")"
"$FUIN" audit-verify -d "$DB" >/dev/null 2>"$WORK/e" && ok "audit-verify (hash chain + HMAC)" || bad "audit-verify: $(head -1 "$WORK/e")"
"$FUIN" audit-root -d "$DB" >/dev/null 2>&1 && ok "audit-root (Merkle)" || bad "audit-root"

echo
echo "==== SMOKE SUMMARY: $PASS passed, $FAIL failed ===="
rm -rf "$WORK"
[ "$FAIL" -eq 0 ]
