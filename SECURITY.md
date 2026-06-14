# Security Policy

## Project status

| | |
|---|---|
| **Maturity** | Research-grade — cryptography course project |
| **Primitives** | libsodium + OpenSSL standard APIs only; no custom cryptography |
| **Testing** | ASan, Valgrind, libFuzzer, 120+ unit tests, gcov 85–91 % |
| **Audit** | **Not independently audited** |

Do not use as the sole protection for high-value production secrets.

## Reporting a vulnerability

Open a **private** report (GitHub security advisory or email the
maintainer) rather than a public issue.

| Required info | |
|---|---|
| **Location** | Affected file, function, and commit hash |
| **Reproduction** | Proof-of-concept input or command sequence |
| **Impact** | Assessment against the documented threat model |

Reports targeting documented, deliberate boundaries (see "Honest
limitations" in README.md) are welcome as design discussions but are
not treated as vulnerabilities.

## Scope

| In scope | Out of scope |
|---|---|
| Memory-safety findings (ASan / Valgrind / fuzzer reproducers) | Documented limitations listed in README.md |
| Breaks to the audit hash chain, HMAC ratchet, or Merkle proofs | Same-database Merkle root storage (root must be external) |
| Key-material leaks via side channels or error paths | Attacks requiring the correct master password |
| Bypass of AAD binding, key-commitment, or name-encryption checks | Brute-force against Argon2id (by design) |

Attacker levels 1–7 and the defenses claimed against each are defined
in the project threat model (see "Security Assumptions and Trust
Boundaries" in README.md).
