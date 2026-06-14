# Development and Verification Notes

Internals, demos, and verification workflows for contributors. End users
should start with the top-level [README](../README.md) instead.

## Table of contents

- [Demos](#demos)
- [Cryptographic internals](#cryptographic-internals)
  - [Forward-secure audit log](#forward-secure-audit-log)
  - [Merkle root and inclusion proofs](#merkle-root-and-inclusion-proofs)
  - [Algorithm selection](#algorithm-selection)
- [Feature reference](#feature-reference)
  - [Secret expiration and auto-rotation](#secret-expiration-and-auto-rotation)
  - [Status report](#status-report)
  - [Hybrid PQC backup capsule](#hybrid-pqc-backup-capsule)
  - [HMAC access tokens](#hmac-access-tokens)
- [Testing](#testing)
  - [Fuzzing](#fuzzing)
  - [Valgrind](#valgrind)

---

## Demos

### Interactive tour

```bash
make demo
```

Walks through key derivation, envelope encryption, and tamper detection.
The KDF visualization uses PyNaCl when available, otherwise the local
libsodium library. Install PyNaCl only if your Python cannot load
libsodium directly:

```bash
python3 -m pip install PyNaCl
```

Use a custom database path:

```bash
./demo/demo.sh results/report_demo.db
```

### Live tamper detection

```bash
make demo-tamper
```

Creates a fresh vault, writes audit events, verifies the clean log,
mutates `audit_log.action` directly via SQLite, then re-verifies. The
second verification must fail — demonstrating that the hash chain and
HMAC signature reject database-layer tampering.

---

## Cryptographic internals

### Forward-secure audit log

Audit HMAC signatures use per-entry key ratcheting:

```text
K_0  = KEK_audit
sig_i = HMAC(K_i, canonical_entry_i)
K_{i+1} = SHA-256(K_i)
```

| Function | Role |
|---|---|
| `audit_log_event()` | Derives the signing key from current log length, signs, zeroes the key |
| `audit_verify_chain()` | Ratchets from `KEK_audit`, checks row id + hash chain + signature per entry |
| `audit_resign_chain()` | Re-signs when `rotate-kek` changes `KEK_audit` |

The canonical bytes include the stable `entry_id`, so renumbering rows
changes the HMAC input. This protects older entries if a later ratchet
key is exposed. It does **not** protect against full compromise of
`KEK_audit` or the master password.

### Merkle root and inclusion proofs

**Root.** After verifying the hash chain + HMAC ratchet, `audit-root`
prints:

```text
audit_merkle_root=<64 hex> entries=<count>
```

Save the root **outside** the vault. Any deleted, reordered, or modified
entry changes the root. The tree uses domain-separated hashing:

```text
leaf     = SHA-256(0x00 || entry_hash)
internal = SHA-256(0x01 || left || right)
```

Odd levels duplicate the final node.

**Inclusion proof.** Generate a proof for one entry:

```bash
fuin audit-proof --entry-id 3
```

Verify against a previously saved root:

```bash
fuin audit-verify-proof --entry-id 3 \
  --root "$ROOT" --proof "$PROOF" \
  --leaf-index "$IDX" --entries "$N"
```

Full-chain verification checks the live database; inclusion proofs make
selected audit events portable for reports or external review.

### Algorithm selection

| Algorithm | Nonce | Notes |
|---|---|---|
| `AES-256-GCM` | `SHA-256(identity)[0..3] ‖ counter64` | Hardware-accelerated; compatibility/benchmark option |
| `XChaCha20-Poly1305` | 192-bit random | Default fallback when AEGIS unavailable |
| `AEGIS-256` | 256-bit random | Default when libsodium >= 1.0.19 |
| `ChaCha20-Poly1305` | — | Alias for XChaCha20-Poly1305 |

Choose per `put`:

```bash
printf '%s' 'secret' | fuin put api/key --stdin --algorithm XChaCha20-Poly1305
```

The algorithm is stored per row — historical versions decrypt even after
later writes use a different algorithm. Rollback preserves the source
version's algorithm.

---

## Feature reference

### Secret expiration and auto-rotation

Set a TTL when storing:

```bash
printf '%s' 'secret' | fuin put db/prod --stdin --ttl 90d
```

Supported suffixes: `s`, `m`, `h`, `d`; bare number = seconds.

| Command | Action |
|---|---|
| `fuin check-expiry --within 7d` | List expired or soon-expiring active secrets |
| `fuin auto-rotate` | Re-key all expired secrets (fresh DEK, preserves value + algorithm) |

Auto-rotation archives the expired version, generates a new DEK, and
records a `ROTATE_DEK` audit event. The new version gets a fresh
`expires_at` from the original TTL interval.

### Status report

```bash
fuin status-report
```

Prints active/archived/deleted counts, TTL posture, algorithm
distribution, verified audit Merkle root, and PQC readiness. Designed
for demos and governance — shows the vault is observable and auditable
without revealing any secret plaintext.

### Hybrid PQC backup capsule

The vault's regular storage is symmetric and local. PQC protects
encrypted backups that leave the machine.

```bash
fuin pqc-keygen  --public-out backup.pub --private-out backup.key
fuin backup-export --recipient backup.pub --out vault.fuincap
fuin backup-import --private-key backup.key --input vault.fuincap --out restored.db
```

**Export pipeline:**

1. Verify audit chain → compute Merkle root
2. Encapsulate ML-KEM-768 shared secret + ephemeral X25519 shared secret
3. Derive capsule key (Merkle root + both shared secrets bound into KDF)
4. Encrypt SQLite online-backup snapshot with XChaCha20-Poly1305

The restored DB still requires the original master password — two layers
of protection (hybrid KEM for transport, Argon2id envelope for contents).

### HMAC access tokens

Self-contained tokens in the format `fu1.<payload_b64>.<hmac_b64>`.
The HMAC uses `KEK_token` (HKDF subkey id 3 from the master key).

```bash
fuin issue-token --scope 'read:database/*' --ttl 1h --subject svc:reader
FUIN_TOKEN="$TOKEN" fuin check-token --scope 'read:database/prod'
FUIN_TOKEN="$TOKEN" fuin get db/prod
```

| Scope pattern | Meaning |
|---|---|
| `read:path` | Read a specific secret |
| `write:path` | Write a specific secret |
| `delete:path` | Delete a specific secret |
| `read:database/*` | Read any secret under `database/` |
| `*:database/*` | Any operation under `database/` |
| `read:a/*,write:b/*` | Comma-separated multi-scope |

A token narrows what an unlocked session may do. It is not a replacement
for the master password — `FUIN_PASSWORD` is still needed to derive
`KEK_token`. Token issuance is recorded as a `TOKEN_ISSUE` audit event.

---

## Testing

### Fuzzing

Requires Homebrew LLVM on macOS (Apple clang lacks the libFuzzer
runtime):

```bash
brew install llvm
```

| Target | Command | Coverage |
|---|---|---|
| Audit parser | `make fuzz-audit` | `audit_verify_chain()`, Merkle root/proof paths |
| CLI parser | `make fuzz-cli-parse` | `getopt_long` parser in `main.c` |
| Vault input | `make fuzz-vault-input` | Name/value bytes through vault API + SQLite |
| All three | `make fuzz` | — |

Default: 60 s, `-max_len=512`. Override for quick checks:

```bash
make fuzz-cli-parse FUZZ_MAX_TOTAL_TIME=1
```

Fuzz binaries, `.dSYM` bundles, and `results/fuzz/` artifacts are
generated files — `make clean` removes them.

### Valgrind

**Linux** (native):

```bash
make test-valgrind
```

**macOS via Docker** (Colima or Docker Desktop):

```bash
brew install colima docker
colima start --cpu 2 --memory 3 --disk 20
make test-valgrind-docker
colima stop
```

**macOS native fallback** (Apple `leaks` tool):

```bash
make test-leaks
```

Checks for `0 leaks for 0 total leaked bytes`.

### Reproduce CI locally (Linux)

The GitHub Actions `build-and-test` job also runs on Ubuntu (glibc), which
is stricter than macOS clang: feature-test-macro gaps (e.g. `realpath()`
needing `_DEFAULT_SOURCE`) surface only there, never in a native macOS
build, because the macOS build compiles the `__APPLE__` branch. Reproduce
that exact environment before pushing:

```bash
brew install colima docker   # once
colima start                 # if not already running
make ci-linux                # build + test + test-asan + coverage on Ubuntu
```

`make ci-linux` builds `Dockerfile.ci` (Ubuntu + the same apt deps as CI)
and runs the full `make / test / test-asan / coverage` sequence inside the
container, so glibc-only `-Werror` failures are caught locally.

For an end-to-end check of the features whose *runtime* behaviour differs on
Linux — default XChaCha20-Poly1305 AEAD, `--algorithm` fallback, PQC/ML-DSA
availability, and O_NOFOLLOW file-security:

```bash
make ci-linux-smoke
```

It runs `tests/cli_smoke.sh` inside the same container. Availability gaps
versus the x86_64 / OpenSSL-3.0 CI runner (e.g. AES-256-GCM or ML-DSA being
absent) are reported, not failed.
