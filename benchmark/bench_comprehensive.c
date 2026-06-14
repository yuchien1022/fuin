#define _POSIX_C_SOURCE 200809L

#include "audit.h"
#include "backup.h"
#include "crypto_engine.h"
#include "kdf.h"
#include "storage.h"
#include "utils.h"
#include "vault.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_DB_PATH "results/bench_comprehensive.db"

static double now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/* ================================================================
 * Benchmark 1: AES-256-GCM vs XChaCha20-Poly1305 vs AEGIS-256
 * ================================================================ */

static void bench_aead_throughput(void)
{
    static const size_t sizes[] = {32, 256, 1024, 4096, 16384, 65536, 262144, 1048576};
    static const int iterations = 200;
    size_t si;

    printf("# AEAD Throughput\n");
    printf("algorithm,secret_size_bytes,iterations,total_ms,throughput_mbs\n");

    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t sz = sizes[si];
        unsigned char kek[crypto_aead_aes256gcm_KEYBYTES];
        unsigned char *plaintext = NULL;
        int iter;

        randombytes_buf(kek, sizeof(kek));
        plaintext = malloc(sz);
        if (plaintext == NULL) {
            continue;
        }
        randombytes_buf(plaintext, sz);

        /* AES-256-GCM (if available) */
        if (crypto_aead_aes256gcm_is_available() == 1) {
            double start = now_ms();

            for (iter = 0; iter < iterations; iter++) {
                encrypted_secret_t enc;
                char id[UTILS_UUID_V4_BUFFER_LEN];

                memset(&enc, 0, sizeof(enc));
                (void)utils_generate_uuid_v4(id, sizeof(id));
                if (crypto_engine_encrypt_with_algorithm(
                        plaintext, sz, kek, id,
                        (uint32_t)(iter + 1), (uint64_t)(iter + 1),
                        "AES-256-GCM", &enc) == SM_OK) {
                    crypto_engine_free_encrypted_secret(&enc);
                }
            }

            {
                double elapsed = now_ms() - start;
                double total_bytes = (double)sz * (double)iterations;
                double throughput = total_bytes / (elapsed / 1000.0) / (1024.0 * 1024.0);
                printf("AES-256-GCM,%zu,%d,%.3f,%.2f\n",
                       sz, iterations, elapsed, throughput);
            }
        }

        /* XChaCha20-Poly1305 */
        {
            double start = now_ms();

            for (iter = 0; iter < iterations; iter++) {
                encrypted_secret_t enc;
                char id[UTILS_UUID_V4_BUFFER_LEN];

                memset(&enc, 0, sizeof(enc));
                (void)utils_generate_uuid_v4(id, sizeof(id));
                if (crypto_engine_encrypt_with_algorithm(
                        plaintext, sz, kek, id,
                        (uint32_t)(iter + 1), (uint64_t)(iter + 1),
                        "XChaCha20-Poly1305", &enc) == SM_OK) {
                    crypto_engine_free_encrypted_secret(&enc);
                }
            }

            {
                double elapsed = now_ms() - start;
                double total_bytes = (double)sz * (double)iterations;
                double throughput = total_bytes / (elapsed / 1000.0) / (1024.0 * 1024.0);
                printf("XChaCha20-Poly1305,%zu,%d,%.3f,%.2f\n",
                       sz, iterations, elapsed, throughput);
            }
        }

        /* AEGIS-256 (libsodium >= 1.0.19) */
        if (crypto_engine_algorithm_available("AEGIS-256") == SM_OK) {
            double start = now_ms();

            for (iter = 0; iter < iterations; iter++) {
                encrypted_secret_t enc;
                char id[UTILS_UUID_V4_BUFFER_LEN];

                memset(&enc, 0, sizeof(enc));
                (void)utils_generate_uuid_v4(id, sizeof(id));
                if (crypto_engine_encrypt_with_algorithm(
                        plaintext, sz, kek, id,
                        (uint32_t)(iter + 1), (uint64_t)(iter + 1),
                        "AEGIS-256", &enc) == SM_OK) {
                    crypto_engine_free_encrypted_secret(&enc);
                }
            }

            {
                double elapsed = now_ms() - start;
                double total_bytes = (double)sz * (double)iterations;
                double throughput = total_bytes / (elapsed / 1000.0) / (1024.0 * 1024.0);
                printf("AEGIS-256,%zu,%d,%.3f,%.2f\n",
                       sz, iterations, elapsed, throughput);
            }
        }

        sodium_memzero(kek, sizeof(kek));
        free(plaintext);
    }
    printf("\n");
}

/* ================================================================
 * Benchmark 2: Argon2id parameter sweep
 * ================================================================ */

static void bench_kdf_params(void)
{
    static const unsigned long long mem_limits[] = {
        16ULL * 1024ULL * 1024ULL,
        67108864ULL,
        268435456ULL
    };
    static const char *mem_labels[] = {"16MB", "64MB", "256MB"};
    static const unsigned long long ops_limits[] = {1, 3, 5};
    size_t mi, oi;

    printf("# KDF Parameter Sweep (Argon2id)\n");
    printf("memory,iterations,time_ms\n");

    for (mi = 0; mi < 3; mi++) {
        for (oi = 0; oi < 3; oi++) {
            unsigned char salt[crypto_pwhash_SALTBYTES];
            unsigned char key[32];
            const char *password = "benchmark-test-password-2026";
            double start, elapsed;
            int runs = 3;
            double total = 0.0;
            int r;

            randombytes_buf(salt, sizeof(salt));

            for (r = 0; r < runs; r++) {
                start = now_ms();
                if (crypto_pwhash(key, sizeof(key),
                                  password, strlen(password),
                                  salt,
                                  ops_limits[oi],
                                  mem_limits[mi],
                                  crypto_pwhash_ALG_ARGON2ID13) != 0) {
                    fprintf(stderr, "pwhash failed: mem=%s ops=%llu\n",
                            mem_labels[mi], ops_limits[oi]);
                    break;
                }
                elapsed = now_ms() - start;
                total += elapsed;
                sodium_memzero(key, sizeof(key));
            }

            printf("%s,%llu,%.1f\n", mem_labels[mi], ops_limits[oi], total / (double)runs);
        }
    }
    printf("\n");
}

/* ================================================================
 * Benchmark 3: Audit log verify time scaling
 * ================================================================ */

static void cleanup_bench_db(void)
{
    (void)vault_close();
    (void)remove(BENCH_DB_PATH);
    (void)remove(BENCH_DB_PATH "-shm");
    (void)remove(BENCH_DB_PATH "-wal");
}

static void bench_audit_verify(void)
{
    static const int counts[] = {100, 500, 1000, 5000, 10000, 50000};
    size_t ci;

    printf("# Audit Verify Scaling\n");
    printf("entry_count,verify_chain_ms,merkle_root_ms\n");

    for (ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
        int target = counts[ci];
        unsigned char audit_key[crypto_auth_KEYBYTES];
        double start, verify_ms, merkle_ms;
        int status;
        int i;

        cleanup_bench_db();
        status = storage_init(BENCH_DB_PATH);
        if (status != SM_OK) {
            fprintf(stderr, "storage_init failed for count=%d\n", target);
            continue;
        }

        randombytes_buf(audit_key, sizeof(audit_key));

        for (i = 0; i < target; i++) {
            char name[32];
            (void)snprintf(name, sizeof(name), "secret/%d", i);
            status = audit_log_event("user:bench", "CREATE", name, 1,
                                     "SUCCESS", audit_key, sizeof(audit_key));
            if (status != SM_OK) {
                fprintf(stderr, "audit_log_event failed at i=%d\n", i);
                break;
            }
        }

        if (status != SM_OK) {
            cleanup_bench_db();
            continue;
        }

        /* Verify chain */
        start = now_ms();
        (void)audit_verify_chain(audit_key, sizeof(audit_key));
        verify_ms = now_ms() - start;

        /* Merkle root */
        {
            unsigned char root[32];
            size_t leaf_count = 0;

            start = now_ms();
            (void)audit_compute_merkle_root(root, sizeof(root), &leaf_count);
            merkle_ms = now_ms() - start;
        }

        printf("%d,%.3f,%.3f\n", target, verify_ms, merkle_ms);
        cleanup_bench_db();
    }
    printf("\n");
}

/* ================================================================
 * Benchmark 4: End-to-end CRUD latency breakdown
 * ================================================================ */

static void bench_e2e_crud(void)
{
    static const size_t sizes[] = {32, 1024, 65536};
    static const char *size_labels[] = {"32B", "1KB", "64KB"};
    size_t si;

    printf("# E2E CRUD Latency (includes KDF on first unlock)\n");
    printf("secret_size,operation,time_ms\n");

    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t sz = sizes[si];
        unsigned char *plaintext = NULL;
        unsigned char *output = NULL;
        size_t written = 0;
        double start;

        cleanup_bench_db();
        plaintext = malloc(sz);
        output = malloc(sz);
        if ((plaintext == NULL) || (output == NULL)) {
            free(plaintext);
            free(output);
            continue;
        }
        randombytes_buf(plaintext, sz);

        /* INIT + UNLOCK (includes Argon2id) */
        start = now_ms();
        (void)vault_init(BENCH_DB_PATH);
        (void)vault_unlock("bench-password-2026");
        printf("%s,init+unlock,%.3f\n", size_labels[si], now_ms() - start);

        /* PUT (encrypt + SQLite write + audit) */
        start = now_ms();
        (void)vault_put("bench/secret", plaintext, sz);
        printf("%s,put,%.3f\n", size_labels[si], now_ms() - start);

        /* GET (SQLite read + decrypt + audit) */
        written = sz;
        start = now_ms();
        (void)vault_get("bench/secret", output, sz, &written);
        printf("%s,get,%.3f\n", size_labels[si], now_ms() - start);

        /* UPDATE (archive old + encrypt new + SQLite write + audit) */
        randombytes_buf(plaintext, sz);
        start = now_ms();
        (void)vault_put("bench/secret", plaintext, sz);
        printf("%s,update,%.3f\n", size_labels[si], now_ms() - start);

        /* DELETE (archive + audit) */
        start = now_ms();
        (void)vault_delete("bench/secret");
        printf("%s,delete,%.3f\n", size_labels[si], now_ms() - start);

        /* AUDIT VERIFY */
        start = now_ms();
        (void)vault_audit_verify();
        printf("%s,audit-verify,%.3f\n", size_labels[si], now_ms() - start);

        free(plaintext);
        free(output);
        cleanup_bench_db();
    }
    printf("\n");
}

/* ================================================================
 * Benchmark 5: Final rotate-kek end-to-end overhead
 * ================================================================ */

static int bench_seed_rotation_vault(size_t num_secrets,
                                     size_t secret_size,
                                     const char *algorithm)
{
    unsigned char *plaintext = NULL;
    int status = SM_OK;

    cleanup_bench_db();
    plaintext = malloc(secret_size);
    if ((plaintext == NULL) || (algorithm == NULL)) {
        free(plaintext);
        return SM_ERR_STORAGE;
    }

    status = vault_init(BENCH_DB_PATH);
    if (status == SM_OK) {
        status = vault_unlock("bench-old-password-2026");
    }

    for (size_t i = 0U; (status == SM_OK) && (i < num_secrets); i++) {
        char name[64];

        randombytes_buf(plaintext, secret_size);
        (void)snprintf(name, sizeof(name), "rotate/%zu", i);
        status = vault_put_with_options(name, plaintext, secret_size,
                                        algorithm, 0U);
    }

    sodium_memzero(plaintext, secret_size);
    free(plaintext);
    return status;
}

static void bench_final_rotate_kek(void)
{
    static const size_t counts[] = {100U, 1000U, 5000U};
    static const size_t secret_size = 1024U;
    static const int runs = 3;
    const char *algorithm = CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305;

    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) ==
        SM_OK) {
        algorithm = CRYPTO_ENGINE_ALGORITHM_AES_256_GCM;
    }

    printf("# Final Rotate-KEK E2E\n");
    printf("num_secrets,secret_size_bytes,runs,algorithm,total_ms,per_secret_us\n");

    for (size_t ci = 0U; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
        double total_ms = 0.0;
        int completed = 0;

        for (int run = 0; run < runs; run++) {
            double start = 0.0;
            double elapsed = 0.0;
            int status = bench_seed_rotation_vault(counts[ci],
                                                   secret_size,
                                                   algorithm);
            if (status != SM_OK) {
                fprintf(stderr, "seed rotation vault failed: count=%zu status=%d\n",
                        counts[ci], status);
                cleanup_bench_db();
                continue;
            }

            start = now_ms();
            status = vault_rotate_kek("bench-new-password-2026");
            elapsed = now_ms() - start;
            if (status != SM_OK) {
                fprintf(stderr, "vault_rotate_kek failed: count=%zu status=%d\n",
                        counts[ci], status);
                cleanup_bench_db();
                continue;
            }

            total_ms += elapsed;
            completed++;
            cleanup_bench_db();
        }

        if (completed > 0) {
            double avg_ms = total_ms / (double)completed;
            double per_secret_us = (avg_ms * 1000.0) / (double)counts[ci];

            printf("%zu,%zu,%d,%s,%.3f,%.3f\n",
                   counts[ci],
                   secret_size,
                   completed,
                   algorithm,
                   avg_ms,
                   per_secret_us);
        }
    }
    cleanup_bench_db();
    printf("\n");
}

/* ================================================================
 * Benchmark 6: Key-commitment microbenchmark
 * ================================================================ */

static void bench_key_commitment(void)
{
    typedef struct {
        const char *label;
        const char *algorithm;
        size_t nonce_len;
    } commitment_case_t;

    static const commitment_case_t cases[] = {
        {"AES-256-GCM", CRYPTO_ENGINE_ALGORITHM_AES_256_GCM, 12U},
        {"XChaCha20-Poly1305", CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305, 24U},
        {"AEGIS-256", CRYPTO_ENGINE_ALGORITHM_AEGIS_256, 32U},
    };
    static const int iterations = 200000;
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char dek[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char nonce[CRYPTO_ENGINE_MAX_NONCE_BYTES];
    unsigned char out[CRYPTO_ENGINE_COMMITMENT_HALF_BYTES];

    printf("# Key Commitment Microbenchmark\n");
    printf("algorithm,nonce_len,iterations,half_commit_us,full_commit_us\n");

    randombytes_buf(kek, sizeof(kek));
    randombytes_buf(dek, sizeof(dek));
    randombytes_buf(nonce, sizeof(nonce));

    for (size_t ci = 0U; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
        double start = 0.0;
        double half_ms = 0.0;
        double full_ms = 0.0;
        int status = SM_OK;

        if (crypto_engine_algorithm_available(cases[ci].algorithm) != SM_OK) {
            continue;
        }

        start = now_ms();
        for (int i = 0; (status == SM_OK) && (i < iterations); i++) {
            status = crypto_engine_compute_key_commitment(
                kek,
                sizeof(kek),
                CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
                nonce,
                cases[ci].nonce_len,
                out,
                sizeof(out));
        }
        half_ms = now_ms() - start;

        start = now_ms();
        for (int i = 0; (status == SM_OK) && (i < iterations); i++) {
            status = crypto_engine_compute_key_commitment(
                kek,
                sizeof(kek),
                CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
                nonce,
                cases[ci].nonce_len,
                out,
                sizeof(out));
            if (status == SM_OK) {
                status = crypto_engine_compute_key_commitment(
                    dek,
                    sizeof(dek),
                    CRYPTO_ENGINE_COMMIT_DOMAIN_DEK,
                    nonce,
                    cases[ci].nonce_len,
                    out,
                    sizeof(out));
            }
        }
        full_ms = now_ms() - start;

        if (status == SM_OK) {
            printf("%s,%zu,%d,%.4f,%.4f\n",
                   cases[ci].label,
                   cases[ci].nonce_len,
                   iterations,
                   (half_ms * 1000.0) / (double)iterations,
                   (full_ms * 1000.0) / (double)iterations);
        }
    }

    sodium_memzero(kek, sizeof(kek));
    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(out, sizeof(out));
    printf("\n");
}

/* ================================================================
 * Benchmark 7: Hybrid PQ backup (keygen + export + import)
 * ================================================================ */

#define BENCH_BACKUP_PUB   "results/bench_backup.pub"
#define BENCH_BACKUP_PRIV  "results/bench_backup.key"
#define BENCH_BACKUP_CAP   "results/bench_backup.capsule"
#define BENCH_BACKUP_OUT   "results/bench_backup_import.db"

static void cleanup_backup_files(void)
{
    (void)remove(BENCH_BACKUP_PUB);
    (void)remove(BENCH_BACKUP_PRIV);
    (void)remove(BENCH_BACKUP_CAP);
    (void)remove(BENCH_BACKUP_OUT);
}

static void bench_backup(void)
{
    static const size_t counts[] = {10U, 100U, 500U};
    static const size_t secret_size = 1024U;
    const char *algorithm = CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305;
    double keygen_ms = 0.0;

    if (!backup_pqc_available()) {
        printf("# Hybrid PQ Backup (SKIPPED: PQC not available)\n\n");
        return;
    }

    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) ==
        SM_OK) {
        algorithm = CRYPTO_ENGINE_ALGORITHM_AES_256_GCM;
    }

    printf("# Hybrid PQ Backup (X25519+ML-KEM-768)\n");
    printf("operation,num_secrets,secret_size_bytes,time_ms\n");

    /* Keygen (one-shot, measure 3 runs) */
    {
        double total = 0.0;
        int runs = 3;
        int r;

        for (r = 0; r < runs; r++) {
            double start;

            cleanup_backup_files();
            start = now_ms();
            if (backup_pqc_keygen(BENCH_BACKUP_PUB,
                                  BENCH_BACKUP_PRIV,
                                  "bench-passphrase") != SM_OK) {
                fprintf(stderr, "backup keygen failed\n");
                cleanup_backup_files();
                return;
            }
            total += now_ms() - start;
            cleanup_backup_files();
        }
        keygen_ms = total / (double)runs;
        printf("keygen,0,0,%.3f\n", keygen_ms);
    }

    /* Export + Import for each vault size */
    for (size_t ci = 0U; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
        double export_total = 0.0;
        double import_total = 0.0;
        int runs = 3;
        int completed = 0;
        int r;

        for (r = 0; r < runs; r++) {
            int status;
            double start;

            cleanup_backup_files();
            cleanup_bench_db();

            /* Generate keypair */
            if (backup_pqc_keygen(BENCH_BACKUP_PUB,
                                  BENCH_BACKUP_PRIV,
                                  "bench-passphrase") != SM_OK) {
                continue;
            }

            /* Seed vault */
            status = bench_seed_rotation_vault(counts[ci],
                                                secret_size,
                                                algorithm);
            if (status != SM_OK) {
                fprintf(stderr, "seed vault failed for backup bench: count=%zu\n",
                        counts[ci]);
                cleanup_backup_files();
                cleanup_bench_db();
                continue;
            }

            /* Export */
            start = now_ms();
            status = vault_backup_export(BENCH_BACKUP_PUB,
                                         BENCH_BACKUP_CAP);
            if (status != SM_OK) {
                fprintf(stderr, "backup export failed: count=%zu status=%d\n",
                        counts[ci], status);
                cleanup_backup_files();
                cleanup_bench_db();
                continue;
            }
            export_total += now_ms() - start;

            /* Close vault before import */
            (void)vault_close();

            /* Import */
            start = now_ms();
            status = vault_backup_import(BENCH_BACKUP_PRIV,
                                         "bench-passphrase",
                                         BENCH_BACKUP_CAP,
                                         BENCH_BACKUP_OUT);
            if (status != SM_OK) {
                fprintf(stderr, "backup import failed: count=%zu status=%d\n",
                        counts[ci], status);
                cleanup_backup_files();
                cleanup_bench_db();
                (void)remove(BENCH_BACKUP_OUT);
                continue;
            }
            import_total += now_ms() - start;
            completed++;

            cleanup_backup_files();
            cleanup_bench_db();
            (void)remove(BENCH_BACKUP_OUT);
        }

        if (completed > 0) {
            printf("export,%zu,%zu,%.3f\n",
                   counts[ci], secret_size,
                   export_total / (double)completed);
            printf("import,%zu,%zu,%.3f\n",
                   counts[ci], secret_size,
                   import_total / (double)completed);
        }
    }

    cleanup_backup_files();
    cleanup_bench_db();
    printf("\n");
}

/* ================================================================ */

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    if (crypto_engine_init() != SM_OK) {
        fprintf(stderr, "crypto_engine_init failed\n");
        return 1;
    }

    bench_aead_throughput();
    bench_kdf_params();
    bench_audit_verify();
    bench_e2e_crud();
    bench_final_rotate_kek();
    bench_key_commitment();
    bench_backup();

    return 0;
}
