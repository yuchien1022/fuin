#include "crypto_engine.h"
#include "key_manager.h"
#include "storage.h"
#include "utils.h"
#include "vault.h"

#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static const char *const TEST_DB = "results/test_rotation.db";

static void cleanup_rotation_db(void)
{
    (void)vault_close();
    (void)remove(TEST_DB);
    (void)remove("results/test_rotation.db-shm");
    (void)remove("results/test_rotation.db-wal");
}

static int open_unlocked_vault(const char *password)
{
    int status = vault_init(TEST_DB);

    if (status != SM_OK) {
        printf("open_unlocked_vault(rotation): init failed: %s\n",
               utils_status_message(status));
        return status;
    }
    status = vault_unlock(password);
    if (status != SM_OK) {
        printf("open_unlocked_vault(rotation): unlock failed: %s\n",
               utils_status_message(status));
    }
    return status;
}

static int query_rotate_count(int *count)
{
    static const char *const sql =
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ROTATE_KEK';";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *count = 0;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int(stmt, 0);
    } else {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int zero_first_audit_signature(void)
{
    static const char *const sql =
        "UPDATE audit_log SET hmac_signature = ? WHERE entry_id = 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    unsigned char zero[crypto_auth_BYTES];
    int rc = SQLITE_OK;
    int status = SM_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(zero, sizeof(zero));
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt,
                               1,
                               zero,
                               (int)sizeof(zero),
                               SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if ((rc != SQLITE_DONE) || (sqlite3_changes(db) != 1)) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    sodium_memzero(zero, sizeof(zero));
    return status;
}

static int test_key_manager_wrap_unwrap_roundtrip(void)
{
    unsigned char dek[KEY_MANAGER_DEK_BYTES];
    unsigned char kek[KEY_MANAGER_DEK_BYTES];
    unsigned char wrapped[KEY_MANAGER_WRAPPED_DEK_BYTES];
    unsigned char nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    unsigned char recovered[KEY_MANAGER_DEK_BYTES];
    size_t wrapped_len = 0U;
    size_t nonce_len = 0U;
    size_t recovered_len = 0U;
    int ok = 0;

    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(kek, sizeof(kek));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(recovered, sizeof(recovered));

    randombytes_buf(kek, sizeof(kek));
    ok = (key_manager_generate_dek(dek, sizeof(dek)) == SM_OK) &&
         (key_manager_wrap_dek("XChaCha20-Poly1305",
                               "rotation-secret-id",
                               1U,
                               dek,
                               sizeof(dek),
                               kek,
                               sizeof(kek),
                               nonce,
                               sizeof(nonce),
                               &nonce_len,
                               wrapped,
                               sizeof(wrapped),
                               &wrapped_len) == SM_OK) &&
         (key_manager_unwrap_dek("XChaCha20-Poly1305",
                                 "rotation-secret-id",
                                 1U,
                                 wrapped,
                                 wrapped_len,
                                 nonce,
                                 nonce_len,
                                 kek,
                                 sizeof(kek),
                                 recovered,
                                 sizeof(recovered),
                                 &recovered_len) == SM_OK) &&
         (recovered_len == sizeof(dek)) &&
         (sodium_memcmp(dek, recovered, sizeof(dek)) == 0);
    if (!ok) {
        printf("test_key_manager_wrap_unwrap_roundtrip: mismatch\n");
    }

    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(kek, sizeof(kek));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(recovered, sizeof(recovered));
    return ok ? 0 : 1;
}

static int test_key_manager_wrap_unwrap_aegis(void)
{
    unsigned char dek[KEY_MANAGER_DEK_BYTES];
    unsigned char kek[KEY_MANAGER_DEK_BYTES];
    unsigned char wrapped[KEY_MANAGER_WRAPPED_DEK_BYTES];
    unsigned char nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    unsigned char recovered[KEY_MANAGER_DEK_BYTES];
    size_t wrapped_len = 0U;
    size_t nonce_len = 0U;
    size_t recovered_len = 0U;
    int ok = 0;

    if (crypto_engine_algorithm_available("AEGIS-256") != SM_OK) {
        printf("test_key_manager_wrap_unwrap_aegis: AEGIS-256 unavailable; skipped\n");
        return 0;
    }

    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(kek, sizeof(kek));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(recovered, sizeof(recovered));

    randombytes_buf(kek, sizeof(kek));
    ok = (key_manager_generate_dek(dek, sizeof(dek)) == SM_OK) &&
         (key_manager_wrap_dek("AEGIS-256",
                               "rotation-aegis-id",
                               1U,
                               dek,
                               sizeof(dek),
                               kek,
                               sizeof(kek),
                               nonce,
                               sizeof(nonce),
                               &nonce_len,
                               wrapped,
                               sizeof(wrapped),
                               &wrapped_len) == SM_OK) &&
         (nonce_len == 32U) &&
         (wrapped_len == (KEY_MANAGER_DEK_BYTES + 32U)) &&
         (key_manager_unwrap_dek("AEGIS-256",
                                 "rotation-aegis-id",
                                 1U,
                                 wrapped,
                                 wrapped_len,
                                 nonce,
                                 nonce_len,
                                 kek,
                                 sizeof(kek),
                                 recovered,
                                 sizeof(recovered),
                                 &recovered_len) == SM_OK) &&
         (recovered_len == sizeof(dek)) &&
         (sodium_memcmp(dek, recovered, sizeof(dek)) == 0);
    if (!ok) {
        printf("test_key_manager_wrap_unwrap_aegis: mismatch\n");
    }

    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(kek, sizeof(kek));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(recovered, sizeof(recovered));
    return ok ? 0 : 1;
}

static int test_vault_rotate_kek_preserves_aegis_secret(void)
{
    const unsigned char secret[] = "aegis-rotation-secret";
    unsigned char recovered[sizeof(secret) - 1U];
    size_t recovered_len = sizeof(recovered);
    int ok = 0;

    if (crypto_engine_algorithm_available("AEGIS-256") != SM_OK) {
        printf("test_vault_rotate_kek_preserves_aegis_secret: "
               "AEGIS-256 unavailable; skipped\n");
        return 0;
    }

    cleanup_rotation_db();
    if (open_unlocked_vault("aegis rotation password") != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }

    ok = (vault_put_with_algorithm("rotation/aegis",
                                   secret,
                                   sizeof(secret) - 1U,
                                   "AEGIS-256") == SM_OK) &&
         (vault_rotate_kek("aegis rotation password 2") == SM_OK) &&
         (vault_get("rotation/aegis",
                    recovered,
                    sizeof(recovered),
                    &recovered_len) == SM_OK) &&
         (recovered_len == (sizeof(secret) - 1U)) &&
         (sodium_memcmp(secret, recovered, recovered_len) == 0);
    if (!ok) {
        printf("test_vault_rotate_kek_preserves_aegis_secret: "
               "AEGIS secret lost across rotation\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_rotation_db();
    return ok ? 0 : 1;
}

static int test_vault_rotate_kek_changes_password_and_preserves_secrets(void)
{
    const unsigned char first[] = "alpha-secret";
    const unsigned char second[] = "beta-secret";
    unsigned char recovered_first[sizeof(first) - 1U];
    unsigned char recovered_second[sizeof(second) - 1U];
    size_t first_len = sizeof(recovered_first);
    size_t second_len = sizeof(recovered_second);
    int rotate_count = 0;
    int ok = 0;

    cleanup_rotation_db();
    if (open_unlocked_vault("old rotation password") != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }

    ok = (vault_put("rotation/alpha", first, sizeof(first) - 1U) == SM_OK) &&
         (vault_put("rotation/beta", second, sizeof(second) - 1U) == SM_OK) &&
         (vault_rotate_kek("new rotation password") == SM_OK) &&
         (query_rotate_count(&rotate_count) == SM_OK) &&
         (rotate_count == 1) &&
         (vault_get("rotation/alpha",
                    recovered_first,
                    sizeof(recovered_first),
                    &first_len) == SM_OK) &&
         (vault_get("rotation/beta",
                    recovered_second,
                    sizeof(recovered_second),
                    &second_len) == SM_OK) &&
         (vault_audit_verify() == SM_OK) &&
         (first_len == (sizeof(first) - 1U)) &&
         (second_len == (sizeof(second) - 1U)) &&
         (sodium_memcmp(first, recovered_first, sizeof(recovered_first)) == 0) &&
         (sodium_memcmp(second, recovered_second, sizeof(recovered_second)) == 0);
    if (!ok) {
        printf("test_vault_rotate_kek_changes_password_and_preserves_secrets: "
               "rotation/session check failed\n");
        sodium_memzero(recovered_first, sizeof(recovered_first));
        sodium_memzero(recovered_second, sizeof(recovered_second));
        cleanup_rotation_db();
        return 1;
    }

    if (vault_close() != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }
    if ((vault_init(TEST_DB) != SM_OK) ||
        (vault_unlock("old rotation password") != SM_ERR_AUTH)) {
        printf("test_vault_rotate_kek_changes_password_and_preserves_secrets: "
               "old password was accepted\n");
        cleanup_rotation_db();
        return 1;
    }
    if (vault_close() != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }
    if ((vault_init(TEST_DB) != SM_OK) ||
        (vault_unlock("new rotation password") != SM_OK)) {
        printf("test_vault_rotate_kek_changes_password_and_preserves_secrets: "
               "new password rejected\n");
        cleanup_rotation_db();
        return 1;
    }

    sodium_memzero(recovered_first, sizeof(recovered_first));
    sodium_memzero(recovered_second, sizeof(recovered_second));
    cleanup_rotation_db();
    return 0;
}

static int test_vault_rotate_kek_rejects_tampered_audit(void)
{
    const unsigned char secret[] = "tamper-block";
    int old_ok = 0;
    int new_rejected = 0;

    cleanup_rotation_db();
    if (open_unlocked_vault("old tamper password") != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }

    if ((vault_put("rotation/tamper", secret, sizeof(secret) - 1U) != SM_OK) ||
        (zero_first_audit_signature() != SM_OK) ||
        (vault_rotate_kek("new tamper password") != SM_ERR_CRYPTO)) {
        printf("test_vault_rotate_kek_rejects_tampered_audit: expected rotate failure\n");
        cleanup_rotation_db();
        return 1;
    }
    if (vault_close() != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }

    old_ok = (vault_init(TEST_DB) == SM_OK) &&
             (vault_unlock("old tamper password") == SM_OK);
    (void)vault_close();
    new_rejected = (vault_init(TEST_DB) == SM_OK) &&
                   (vault_unlock("new tamper password") == SM_ERR_AUTH);

    if (!old_ok || !new_rejected) {
        printf("test_vault_rotate_kek_rejects_tampered_audit: metadata rollback failed\n");
        cleanup_rotation_db();
        return 1;
    }

    cleanup_rotation_db();
    return 0;
}

static int test_vault_rotate_kek_invalid_args(void)
{
    int ok = 1;

    cleanup_rotation_db();
    ok = ok && (vault_rotate_kek("new") == SM_ERR_AUTH);
    if (open_unlocked_vault("arg rotation password") != SM_OK) {
        cleanup_rotation_db();
        return 1;
    }
    ok = ok && (vault_rotate_kek(NULL) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_rotate_kek("") == SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_vault_rotate_kek_invalid_args: expected auth/argument failures\n");
    }
    cleanup_rotation_db();
    return ok ? 0 : 1;
}

int test_rotation_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_rotation_run: sodium_init failed\n");
        return 1;
    }

    failed += test_key_manager_wrap_unwrap_roundtrip();
    failed += test_key_manager_wrap_unwrap_aegis();
    failed += test_vault_rotate_kek_preserves_aegis_secret();
    failed += test_vault_rotate_kek_changes_password_and_preserves_secrets();
    failed += test_vault_rotate_kek_rejects_tampered_audit();
    failed += test_vault_rotate_kek_invalid_args();

    if (failed != 0) {
        printf("test_rotation_run: %d failures\n", failed);
    }

    cleanup_rotation_db();
    return failed == 0 ? 0 : 1;
}
