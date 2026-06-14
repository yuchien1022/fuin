#include "access.h"
#include "crypto_engine.h"
#include "storage.h"
#include "utils.h"
#include "vault.h"

#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static const char *const TEST_DB = "results/test_vault.db";

static void cleanup_vault_db(void)
{
    (void)vault_close();
    (void)remove(TEST_DB);
    (void)remove("results/test_vault.db-shm");
    (void)remove("results/test_vault.db-wal");
}

static int open_unlocked_vault(const char *password)
{
    int status = vault_init(TEST_DB);

    if (status != SM_OK) {
        printf("open_unlocked_vault: init failed: %s\n", utils_status_message(status));
        return status;
    }

    status = vault_unlock(password);
    if (status != SM_OK) {
        printf("open_unlocked_vault: unlock failed: %s\n", utils_status_message(status));
    }
    return status;
}

static int stored_name_for_test(const char *name,
                                char *stored_name,
                                size_t stored_name_len)
{
    if ((name == NULL) || (stored_name == NULL) ||
        (stored_name_len < VAULT_NAME_LOOKUP_HEX_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return vault_debug_name_lookup(name, stored_name, stored_name_len);
}

static int query_secret_state(const char *name,
                              int *version,
                              sqlite3_int64 *nonce_counter,
                              int *is_archived)
{
    static const char *const sql =
        "SELECT version, nonce_counter, is_archived "
        "FROM secrets WHERE name = ? AND is_archived = 0 "
        "ORDER BY version DESC LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL) || (version == NULL) ||
        (nonce_counter == NULL) || (is_archived == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
        *nonce_counter = sqlite3_column_int64(stmt, 1);
        *is_archived = sqlite3_column_int(stmt, 2);
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int query_secret_counts(const char *name,
                               int *row_count,
                               int *active_count,
                               int *archived_count)
{
    static const char *const sql =
        "SELECT COUNT(*), "
        "COALESCE(SUM(CASE WHEN is_archived = 0 THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_archived = 1 THEN 1 ELSE 0 END), 0) "
        "FROM secrets WHERE name = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL) || (row_count == NULL) ||
        (active_count == NULL) || (archived_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *row_count = sqlite3_column_int(stmt, 0);
        *active_count = sqlite3_column_int(stmt, 1);
        *archived_count = sqlite3_column_int(stmt, 2);
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int query_active_secret_algorithm(const char *name,
                                         char *algorithm,
                                         size_t algorithm_len,
                                         int *nonce_len)
{
    static const char *const sql =
        "SELECT algorithm, nonce FROM secrets "
        "WHERE name = ? AND is_archived = 0 "
        "ORDER BY version DESC LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;
    int written = 0;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL) || (algorithm == NULL) ||
        (algorithm_len == 0U) || (nonce_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);

        if (text == NULL) {
            status = SM_ERR_STORAGE;
        } else {
            written = snprintf(algorithm,
                               algorithm_len,
                               "%s",
                               (const char *)text);
            if ((written < 0) || ((size_t)written >= algorithm_len)) {
                status = SM_ERR_STORAGE;
            } else {
                *nonce_len = sqlite3_column_bytes(stmt, 1);
            }
        }
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int query_active_secret_expiration(const char *name,
                                          int *version,
                                          char *expires_at,
                                          size_t expires_at_len,
                                          sqlite3_int64 *rotation_interval)
{
    static const char *const sql =
        "SELECT version, expires_at, rotation_interval_seconds "
        "FROM secrets WHERE name = ? AND is_archived = 0 "
        "ORDER BY version DESC LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL) || (version == NULL) ||
        (expires_at == NULL) || (expires_at_len == 0U) ||
        (rotation_interval == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    expires_at[0] = '\0';
    *rotation_interval = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
        if (sqlite3_column_type(stmt, 1) == SQLITE_NULL) {
            status = SM_ERR_STORAGE;
        } else {
            const unsigned char *text = sqlite3_column_text(stmt, 1);
            int written = 0;

            if (text == NULL) {
                status = SM_ERR_STORAGE;
            } else {
                written = snprintf(expires_at,
                                   expires_at_len,
                                   "%s",
                                   (const char *)text);
                if ((written < 0) || ((size_t)written >= expires_at_len)) {
                    status = SM_ERR_STORAGE;
                }
            }
        }
        if (status == SM_OK) {
            *rotation_interval = sqlite3_column_int64(stmt, 2);
        }
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int force_active_secret_expired(const char *name)
{
    static const char *const sql =
        "UPDATE secrets SET expires_at = '1970-01-01T00:00:00Z' "
        "WHERE name = ? AND is_archived = 0;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
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
    return status;
}

static int tamper_secret_name(const char *old_name,
                              int version,
                              const char *new_name)
{
    static const char *const sql =
        "UPDATE secrets SET name = ? WHERE name = ? AND version = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char old_stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    char new_stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(old_stored_name, sizeof(old_stored_name));
    sodium_memzero(new_stored_name, sizeof(new_stored_name));
    if ((db == NULL) || (old_name == NULL) || (new_name == NULL) ||
        (version < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(old_name, old_stored_name, sizeof(old_stored_name));
    if (status == SM_OK) {
        status = stored_name_for_test(new_name,
                                      new_stored_name,
                                      sizeof(new_stored_name));
    }
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, new_stored_name, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, old_stored_name, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 3, version);
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
    return status;
}

static int tamper_active_version(const char *name, int active_version)
{
    static const char *const archive_sql =
        "UPDATE secrets SET is_archived = 1 WHERE name = ?;";
    static const char *const activate_sql =
        "UPDATE secrets SET is_archived = 0 WHERE name = ? AND version = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(stored_name, sizeof(stored_name));
    if ((db == NULL) || (name == NULL) || (active_version < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = stored_name_for_test(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, archive_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_step(stmt);
    if ((rc != SQLITE_DONE) || (sqlite3_changes(db) <= 0)) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    if (status != SM_OK) {
        return status;
    }

    stmt = NULL;
    rc = sqlite3_prepare_v2(db, activate_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 2, active_version);
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
    return status;
}

static int query_audit_action_count(const char *action,
                                    const char *target,
                                    int target_version,
                                    int *count)
{
    static const char *const version_sql =
        "SELECT COUNT(*) FROM audit_log "
        "WHERE action = ? AND target = ? AND target_version = ?;";
    static const char *const null_version_sql =
        "SELECT COUNT(*) FROM audit_log "
        "WHERE action = ? AND target = ? AND target_version IS NULL;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char stored_target[VAULT_NAME_LOOKUP_HEX_LEN];
    const char *sql = target_version > 0 ? version_sql : null_version_sql;
    int rc = SQLITE_OK;
    int status = SM_OK;
    int tried_stored_target = 0;

    sodium_memzero(stored_target, sizeof(stored_target));
    if ((db == NULL) || (action == NULL) || (target == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

retry:
    *count = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, action, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, target, -1, SQLITE_TRANSIENT);
    }
    if ((rc == SQLITE_OK) && (target_version > 0)) {
        rc = sqlite3_bind_int(stmt, 3, target_version);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
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
    stmt = NULL;
    if ((status == SM_OK) && (*count == 0) && !tried_stored_target &&
        (stored_name_for_test(target,
                              stored_target,
                              sizeof(stored_target)) == SM_OK)) {
        target = stored_target;
        tried_stored_target = 1;
        goto retry;
    }
    return status;
}

static int query_raw_secret_name_count(const char *raw_name, int *count)
{
    static const char *const sql =
        "SELECT COUNT(*) FROM secrets WHERE name = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (raw_name == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *count = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, raw_name, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
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

static int query_auth_failure_count(int *count)
{
    static const char *const sql =
        "SELECT COUNT(*) FROM auth_failures WHERE result = 'FAILURE';";
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

static int query_metadata_key_count(const char *key, int *count)
{
    static const char *const sql =
        "SELECT COUNT(*) FROM metadata WHERE key = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (key == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *count = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
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

static int delete_metadata_keys_for_test(void)
{
    sqlite3 *db = storage_get_db();
    char *error = NULL;
    int rc = SQLITE_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_exec(db,
                      "DELETE FROM metadata "
                      "WHERE key IN ('meta_key_nonce', 'meta_key_wrapped');",
                      NULL,
                      NULL,
                      &error);
    sqlite3_free(error);
    return rc == SQLITE_OK ? SM_OK : SM_ERR_STORAGE;
}

typedef struct {
    int seen;
    int version;
    int is_expired;
    char name[64];
    char expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
} expiry_capture_t;

static int capture_expiry(const char *name,
                          int version,
                          const char *expires_at,
                          int is_expired,
                          void *user_data)
{
    expiry_capture_t *capture = (expiry_capture_t *)user_data;
    int written = 0;

    if ((name == NULL) || (expires_at == NULL) || (capture == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    written = snprintf(capture->name, sizeof(capture->name), "%s", name);
    if ((written < 0) || ((size_t)written >= sizeof(capture->name))) {
        return SM_ERR_STORAGE;
    }
    written = snprintf(capture->expires_at,
                       sizeof(capture->expires_at),
                       "%s",
                       expires_at);
    if ((written < 0) || ((size_t)written >= sizeof(capture->expires_at))) {
        return SM_ERR_STORAGE;
    }
    capture->seen++;
    capture->version = version;
    capture->is_expired = is_expired;
    return SM_OK;
}

static int count_list_item(const vault_list_item_t *item, void *user_data)
{
    size_t *count = (size_t *)user_data;

    if ((item == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    (*count)++;
    return SM_OK;
}

typedef struct {
    size_t count;
    char first_name[64];
} name_capture_t;

static int capture_list_name(const vault_list_item_t *item, void *user_data)
{
    name_capture_t *capture = (name_capture_t *)user_data;
    int written = 0;

    if ((item == NULL) || (item->name == NULL) || (capture == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (capture->count == 0U) {
        written = snprintf(capture->first_name,
                           sizeof(capture->first_name),
                           "%s",
                           item->name);
        if ((written < 0) || ((size_t)written >= sizeof(capture->first_name))) {
            return SM_ERR_STORAGE;
        }
    }
    capture->count++;
    return SM_OK;
}

static int test_put_get_roundtrip(void)
{
    const unsigned char secret[] = "db-password";
    unsigned char recovered[sizeof(secret) - 1U];
    size_t written = sizeof(recovered);
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("correct horse battery staple") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if (vault_put("database/prod/password", secret, sizeof(secret) - 1U) != SM_OK) {
        printf("test_put_get_roundtrip: put failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get("database/prod/password", recovered, sizeof(recovered), &written) != SM_OK) {
        printf("test_put_get_roundtrip: get failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (written == (sizeof(secret) - 1U)) &&
         (sodium_memcmp(secret, recovered, sizeof(recovered)) == 0);
    if (!ok) {
        printf("test_put_get_roundtrip: secret mismatch\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_secret_name_metadata_not_plaintext(void)
{
    const unsigned char secret[] = "metadata-secret";
    name_capture_t capture;
    size_t matched = 0U;
    int plaintext_rows = 1;
    int ok = 0;

    sodium_memzero(&capture, sizeof(capture));
    cleanup_vault_db();
    if (open_unlocked_vault("metadata-private-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("metadata/private-name",
                   secret,
                   sizeof(secret) - 1U) != SM_OK) ||
        (query_raw_secret_name_count("metadata/private-name",
                                     &plaintext_rows) != SM_OK) ||
        (vault_list_secrets(0,
                            capture_list_name,
                            &capture,
                            &matched) != SM_OK)) {
        printf("test_secret_name_metadata_not_plaintext: setup/query failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (plaintext_rows == 0) &&
         (matched == 1U) &&
         (capture.count == 1U) &&
         (strcmp(capture.first_name, "metadata/private-name") == 0);
    if (!ok) {
        printf("test_secret_name_metadata_not_plaintext: plaintext name leaked\n");
    }

    sodium_memzero(&capture, sizeof(capture));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_put_with_xchacha_and_rollback_preserves_algorithm(void)
{
    const unsigned char first[] = "first-xchacha-value";
    const unsigned char second[] = "second-default-value";
    unsigned char recovered[sizeof(first) - 1U];
    char algorithm[CRYPTO_ENGINE_ALGORITHM_MAX];
    size_t written = sizeof(recovered);
    int nonce_len = 0;
    int ok = 0;

    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(algorithm, sizeof(algorithm));
    cleanup_vault_db();
    if (open_unlocked_vault("algorithm-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if (vault_put_with_algorithm("algorithm/selected",
                                 first,
                                 sizeof(first) - 1U,
                                 CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) !=
        SM_OK) {
        printf("test_put_with_xchacha_and_rollback_preserves_algorithm: xchacha put failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_active_secret_algorithm("algorithm/selected",
                                      algorithm,
                                      sizeof(algorithm),
                                      &nonce_len) != SM_OK) {
        printf("test_put_with_xchacha_and_rollback_preserves_algorithm: query v1 failed\n");
        cleanup_vault_db();
        return 1;
    }
    ok = (strcmp(algorithm, CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) == 0) &&
         (nonce_len == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    if (!ok) {
        printf("test_put_with_xchacha_and_rollback_preserves_algorithm: xchacha metadata mismatch\n");
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("algorithm/selected", second, sizeof(second) - 1U) != SM_OK) ||
        (vault_rollback("algorithm/selected", 1) != SM_OK) ||
        (vault_get("algorithm/selected",
                   recovered,
                   sizeof(recovered),
                   &written) != SM_OK) ||
        (query_active_secret_algorithm("algorithm/selected",
                                       algorithm,
                                       sizeof(algorithm),
                                       &nonce_len) != SM_OK)) {
        printf("test_put_with_xchacha_and_rollback_preserves_algorithm: update/rollback failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (written == (sizeof(first) - 1U)) &&
         (sodium_memcmp(first, recovered, sizeof(recovered)) == 0) &&
         (strcmp(algorithm, CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) == 0) &&
         (nonce_len == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    if (!ok) {
        printf("test_put_with_xchacha_and_rollback_preserves_algorithm: rollback mismatch\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(algorithm, sizeof(algorithm));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_expiry_check_and_auto_rotate(void)
{
    const unsigned char secret[] = "expiring-secret-value";
    unsigned char recovered[sizeof(secret) - 1U];
    char expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    expiry_capture_t capture;
    size_t matched = 0U;
    size_t rotated = 0U;
    size_t written = sizeof(recovered);
    sqlite3_int64 rotation_interval = 0;
    int version = 0;
    int row_count = 0;
    int active_count = 0;
    int archived_count = 0;
    int audit_count = 0;
    int ok = 0;

    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(&capture, sizeof(capture));
    cleanup_vault_db();
    if (open_unlocked_vault("expiry-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if (vault_put_with_options("expiry/rotating",
                               secret,
                               sizeof(secret) - 1U,
                               CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305,
                               3600U) != SM_OK) {
        printf("test_expiry_check_and_auto_rotate: put with ttl failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_active_secret_expiration("expiry/rotating",
                                       &version,
                                       expires_at,
                                       sizeof(expires_at),
                                       &rotation_interval) != SM_OK) {
        printf("test_expiry_check_and_auto_rotate: expiration query failed\n");
        cleanup_vault_db();
        return 1;
    }
    ok = (version == 1) &&
         (strlen(expires_at) == UTILS_ISO8601_UTC_LEN) &&
         (rotation_interval == 3600);
    if (!ok) {
        printf("test_expiry_check_and_auto_rotate: ttl metadata mismatch\n");
        cleanup_vault_db();
        return 1;
    }

    if ((vault_check_expiry(0U, NULL, NULL, &matched) != SM_OK) ||
        (matched != 0U)) {
        printf("test_expiry_check_and_auto_rotate: unexpected immediate expiry\n");
        cleanup_vault_db();
        return 1;
    }
    if ((vault_check_expiry(7200U, capture_expiry, &capture, &matched) !=
         SM_OK) ||
        (matched != 1U) ||
        (capture.seen != 1) ||
        (capture.version != 1) ||
        capture.is_expired ||
        (strcmp(capture.name, "expiry/rotating") != 0)) {
        printf("test_expiry_check_and_auto_rotate: lookahead mismatch\n");
        cleanup_vault_db();
        return 1;
    }

    sodium_memzero(&capture, sizeof(capture));
    if ((force_active_secret_expired("expiry/rotating") != SM_OK) ||
        (vault_check_expiry(0U, capture_expiry, &capture, &matched) != SM_OK) ||
        (matched != 1U) ||
        (capture.seen != 1) ||
        !capture.is_expired) {
        printf("test_expiry_check_and_auto_rotate: expired check mismatch\n");
        cleanup_vault_db();
        return 1;
    }

    if ((vault_auto_rotate_expired(&rotated) != SM_OK) ||
        (rotated != 1U) ||
        (vault_get("expiry/rotating",
                   recovered,
                   sizeof(recovered),
                   &written) != SM_OK) ||
        (query_secret_counts("expiry/rotating",
                             &row_count,
                             &active_count,
                             &archived_count) != SM_OK) ||
        (query_active_secret_expiration("expiry/rotating",
                                        &version,
                                        expires_at,
                                        sizeof(expires_at),
                                        &rotation_interval) != SM_OK) ||
        (query_audit_action_count("ROTATE_DEK",
                                  "expiry/rotating",
                                  2,
                                  &audit_count) != SM_OK)) {
        printf("test_expiry_check_and_auto_rotate: auto-rotate failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (written == (sizeof(secret) - 1U)) &&
         (sodium_memcmp(secret, recovered, sizeof(recovered)) == 0) &&
         (row_count == 2) &&
         (active_count == 1) &&
         (archived_count == 1) &&
         (version == 2) &&
         (rotation_interval == 3600) &&
         (audit_count == 1);
    if (ok) {
        matched = 99U;
        ok = (vault_check_expiry(0U, NULL, NULL, &matched) == SM_OK) &&
             (matched == 0U) &&
             (vault_auto_rotate_expired(&rotated) == SM_OK) &&
             (rotated == 0U);
    }
    if (!ok) {
        printf("test_expiry_check_and_auto_rotate: rotated metadata mismatch\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(&capture, sizeof(capture));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_token_issue_and_scope_authorization(void)
{
    char token[ACCESS_TOKEN_BUFFER_LEN];
    int audit_count = 0;
    int ok = 0;

    sodium_memzero(token, sizeof(token));
    cleanup_vault_db();
    if (open_unlocked_vault("token-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_issue_token("svc:reader",
                           "read:token/*",
                           3600U,
                           token,
                           sizeof(token)) != SM_OK) ||
        (vault_check_token(token, "read:token/demo") != SM_OK) ||
        (query_audit_action_count("TOKEN_ISSUE",
                                  "svc:reader",
                                  0,
                                  &audit_count) != SM_OK)) {
        printf("test_token_issue_and_scope_authorization: token issue/check failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (audit_count == 1) &&
         (vault_check_token(token, "write:token/demo") == SM_ERR_AUTH);
    if (!ok) {
        printf("test_token_issue_and_scope_authorization: token scope mismatch\n");
    }

    sodium_memzero(token, sizeof(token));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_token_revoke_invalidates_existing_token(void)
{
    char token[ACCESS_TOKEN_BUFFER_LEN];
    int audit_count = 0;
    int ok = 0;

    sodium_memzero(token, sizeof(token));
    cleanup_vault_db();
    if (open_unlocked_vault("token-revoke-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_issue_token("svc:writer",
                           "write:token/*",
                           3600U,
                           token,
                           sizeof(token)) != SM_OK) ||
        (vault_check_token(token, "write:token/demo") != SM_OK) ||
        (vault_revoke_tokens() != SM_OK) ||
        (query_audit_action_count("TOKEN_REVOKE",
                                  "tokens",
                                  0,
                                  &audit_count) != SM_OK)) {
        printf("test_token_revoke_invalidates_existing_token: setup failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (audit_count == 1) &&
         (vault_check_token(token, "write:token/demo") == SM_ERR_AUTH);
    if (!ok) {
        printf("test_token_revoke_invalidates_existing_token: revoked token accepted\n");
    }

    sodium_memzero(token, sizeof(token));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_update_increments_version_and_counter(void)
{
    const unsigned char first[] = "first-value";
    const unsigned char second[] = "second-value";
    unsigned char recovered[sizeof(second) - 1U];
    size_t written = sizeof(recovered);
    sqlite3_int64 nonce_counter = 0;
    int version = 0;
    int is_archived = 1;
    int row_count = 0;
    int active_count = 0;
    int archived_count = 0;
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("update-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("service/api/key", first, sizeof(first) - 1U) != SM_OK) ||
        (vault_put("service/api/key", second, sizeof(second) - 1U) != SM_OK)) {
        printf("test_update_increments_version_and_counter: put failed\n");
        cleanup_vault_db();
        return 1;
    }

    if (query_secret_state("service/api/key", &version, &nonce_counter, &is_archived) != SM_OK) {
        printf("test_update_increments_version_and_counter: query failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_secret_counts("service/api/key",
                            &row_count,
                            &active_count,
                            &archived_count) != SM_OK) {
        printf("test_update_increments_version_and_counter: count query failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get("service/api/key", recovered, sizeof(recovered), &written) != SM_OK) {
        printf("test_update_increments_version_and_counter: get failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (version == 2) &&
         (nonce_counter == 2) &&
         (is_archived == 0) &&
         (row_count == 2) &&
         (active_count == 1) &&
         (archived_count == 1) &&
         (written == (sizeof(second) - 1U)) &&
         (sodium_memcmp(second, recovered, sizeof(recovered)) == 0);
    if (!ok) {
        printf("test_update_increments_version_and_counter: state mismatch\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_get_specific_version_preserves_history(void)
{
    const unsigned char first[] = "first-version";
    const unsigned char second[] = "second-version";
    unsigned char recovered_first[sizeof(first) - 1U];
    unsigned char recovered_latest[sizeof(second) - 1U];
    size_t first_written = sizeof(recovered_first);
    size_t latest_written = sizeof(recovered_latest);
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("version-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("service/history/key", first, sizeof(first) - 1U) != SM_OK) ||
        (vault_put("service/history/key", second, sizeof(second) - 1U) != SM_OK)) {
        printf("test_get_specific_version_preserves_history: put failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get_version("service/history/key",
                          1,
                          recovered_first,
                          sizeof(recovered_first),
                          &first_written) != SM_OK) {
        printf("test_get_specific_version_preserves_history: get version failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get("service/history/key",
                  recovered_latest,
                  sizeof(recovered_latest),
                  &latest_written) != SM_OK) {
        printf("test_get_specific_version_preserves_history: get latest failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (first_written == (sizeof(first) - 1U)) &&
         (latest_written == (sizeof(second) - 1U)) &&
         (sodium_memcmp(first, recovered_first, sizeof(recovered_first)) == 0) &&
         (sodium_memcmp(second, recovered_latest, sizeof(recovered_latest)) == 0);
    if (!ok) {
        printf("test_get_specific_version_preserves_history: value mismatch\n");
    }

    sodium_memzero(recovered_first, sizeof(recovered_first));
    sodium_memzero(recovered_latest, sizeof(recovered_latest));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_metadata_name_tamper_rejected(void)
{
    const unsigned char secret[] = "name-bound-secret";
    unsigned char recovered[sizeof(secret) - 1U];
    size_t written = sizeof(recovered);
    int status = SM_OK;
    int ok = 0;

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    if (open_unlocked_vault("metadata-name-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("metadata/original", secret, sizeof(secret) - 1U) != SM_OK) ||
        (tamper_secret_name("metadata/original", 1, "metadata/renamed") != SM_OK)) {
        printf("test_metadata_name_tamper_rejected: setup failed\n");
        cleanup_vault_db();
        return 1;
    }

    status = vault_get("metadata/renamed",
                       recovered,
                       sizeof(recovered),
                       &written);
    ok = status != SM_OK;
    if (!ok) {
        printf("test_metadata_name_tamper_rejected: tampered name decrypted\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_active_version_tamper_rejected(void)
{
    const unsigned char first[] = "first-active";
    const unsigned char second[] = "second-active";
    unsigned char recovered[sizeof(first) - 1U];
    vault_security_report_t report;
    size_t matched = 0U;
    size_t listed = 0U;
    size_t written = sizeof(recovered);
    int status = SM_OK;
    int ok = 0;

    sodium_memzero(&report, sizeof(report));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    if (open_unlocked_vault("active-tamper-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("metadata/active", first, sizeof(first) - 1U) != SM_OK) ||
        (vault_put("metadata/active", second, sizeof(second) - 1U) != SM_OK) ||
        (tamper_active_version("metadata/active", 1) != SM_OK)) {
        printf("test_active_version_tamper_rejected: setup failed\n");
        cleanup_vault_db();
        return 1;
    }

    status = vault_get("metadata/active",
                       recovered,
                       sizeof(recovered),
                       &written);
    ok = (status != SM_OK) &&
         (vault_get_version("metadata/active",
                            1,
                            recovered,
                            sizeof(recovered),
                            &written) == SM_OK) &&
         (written == (sizeof(first) - 1U)) &&
         (sodium_memcmp(first, recovered, sizeof(recovered)) == 0) &&
         (vault_list_secrets(0, count_list_item, &listed, &matched) == SM_OK) &&
         (matched == 0U) &&
         (listed == 0U) &&
         (vault_security_report(&report) == SM_OK) &&
         (report.distinct_names == 1U) &&
         (report.active_secrets == 0U) &&
         (report.archived_versions == 2U) &&
         (report.total_versions == 2U) &&
         (report.deleted_names == 1U);
    if (!ok) {
        printf("test_active_version_tamper_rejected: active tamper accepted\n");
    }

    sodium_memzero(&report, sizeof(report));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

/* Regression for FIXED-055: the expiry scan (vault_check_expiry) and
   vault_auto_rotate_expired must share the same "current active version"
   definition as get/list/report. With an old, non-max version left
   is_archived=0 (tamper) and forced expired, the expiry path must NOT treat it
   as an active expiring secret, and auto-rotate must return OK with zero
   rotated rather than aborting trying to rotate a row the active lookup no
   longer resolves. */
static int test_expiry_ignores_tampered_active_version(void)
{
    static const char *const expire_sql =
        "UPDATE secrets SET expires_at = '2000-01-01T00:00:00Z' "
        "WHERE name = ? AND is_archived = 0;";
    const unsigned char first[] = "first-active";
    const unsigned char second[] = "second-active";
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    size_t matched = 0U;
    size_t rotated = 0U;
    int ok = 0;

    sodium_memzero(stored_name, sizeof(stored_name));
    cleanup_vault_db();
    if (open_unlocked_vault("expiry-tamper-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    /* v1 then v2 (v2 becomes the active max version), then tamper so the OLD
       non-max v1 is the only is_archived=0 row, and force that row expired. */
    db = storage_get_db();
    if ((vault_put_with_options("exp/tamper", first, sizeof(first) - 1U,
                                CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305,
                                3600U) != SM_OK) ||
        (vault_put_with_options("exp/tamper", second, sizeof(second) - 1U,
                                CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305,
                                3600U) != SM_OK) ||
        (tamper_active_version("exp/tamper", 1) != SM_OK) ||
        (stored_name_for_test("exp/tamper",
                              stored_name,
                              sizeof(stored_name)) != SM_OK) ||
        (db == NULL) ||
        (sqlite3_prepare_v2(db, expire_sql, -1, &stmt, NULL) != SQLITE_OK) ||
        (sqlite3_bind_text(stmt, 1, stored_name, -1, SQLITE_TRANSIENT)
             != SQLITE_OK) ||
        (sqlite3_step(stmt) != SQLITE_DONE)) {
        printf("test_expiry_ignores_tampered_active_version: setup failed\n");
        (void)sqlite3_finalize(stmt);
        cleanup_vault_db();
        return 1;
    }
    (void)sqlite3_finalize(stmt);

    ok = (vault_check_expiry(0U, NULL, NULL, &matched) == SM_OK) &&
         (matched == 0U) &&
         (vault_auto_rotate_expired(&rotated) == SM_OK) &&
         (rotated == 0U);
    if (!ok) {
        printf("test_expiry_ignores_tampered_active_version: tampered row "
               "treated as active by expiry path\n");
    }

    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_rollback_creates_new_active_version(void)
{
    const unsigned char first[] = "rollback-first";
    const unsigned char second[] = "rollback-second";
    unsigned char recovered_latest[sizeof(first) - 1U];
    unsigned char recovered_second[sizeof(second) - 1U];
    size_t latest_written = sizeof(recovered_latest);
    size_t second_written = sizeof(recovered_second);
    sqlite3_int64 nonce_counter = 0;
    int version = 0;
    int is_archived = 1;
    int row_count = 0;
    int active_count = 0;
    int archived_count = 0;
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("rollback-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("service/rollback/key", first, sizeof(first) - 1U) != SM_OK) ||
        (vault_put("service/rollback/key", second, sizeof(second) - 1U) != SM_OK) ||
        (vault_rollback("service/rollback/key", 1) != SM_OK)) {
        printf("test_rollback_creates_new_active_version: put/rollback failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_secret_state("service/rollback/key",
                           &version,
                           &nonce_counter,
                           &is_archived) != SM_OK) {
        printf("test_rollback_creates_new_active_version: state query failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_secret_counts("service/rollback/key",
                            &row_count,
                            &active_count,
                            &archived_count) != SM_OK) {
        printf("test_rollback_creates_new_active_version: count query failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get("service/rollback/key",
                  recovered_latest,
                  sizeof(recovered_latest),
                  &latest_written) != SM_OK) {
        printf("test_rollback_creates_new_active_version: latest get failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (vault_get_version("service/rollback/key",
                          2,
                          recovered_second,
                          sizeof(recovered_second),
                          &second_written) != SM_OK) {
        printf("test_rollback_creates_new_active_version: version get failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (version == 3) &&
         (nonce_counter == 3) &&
         (is_archived == 0) &&
         (row_count == 3) &&
         (active_count == 1) &&
         (archived_count == 2) &&
         (latest_written == (sizeof(first) - 1U)) &&
         (second_written == (sizeof(second) - 1U)) &&
         (sodium_memcmp(first, recovered_latest, sizeof(recovered_latest)) == 0) &&
         (sodium_memcmp(second, recovered_second, sizeof(recovered_second)) == 0);
    if (!ok) {
        printf("test_rollback_creates_new_active_version: state/value mismatch\n");
    }

    sodium_memzero(recovered_latest, sizeof(recovered_latest));
    sodium_memzero(recovered_second, sizeof(recovered_second));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_delete_archives_secret(void)
{
    const unsigned char secret[] = "delete-me";
    unsigned char recovered[sizeof(secret)];
    size_t written = sizeof(recovered);
    int row_count = 0;
    int active_count = 0;
    int archived_count = 0;
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("delete-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if ((vault_put("cache/token", secret, sizeof(secret) - 1U) != SM_OK) ||
        (vault_delete("cache/token") != SM_OK)) {
        printf("test_delete_archives_secret: put/delete failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (query_secret_counts("cache/token",
                            &row_count,
                            &active_count,
                            &archived_count) != SM_OK) {
        printf("test_delete_archives_secret: query failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = (row_count == 1) &&
         (active_count == 0) &&
         (archived_count == 1) &&
         (vault_get("cache/token", recovered, sizeof(recovered), &written) == SM_ERR_NOT_FOUND);
    if (!ok) {
        printf("test_delete_archives_secret: archive/get state mismatch\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_delete_missing_returns_not_found(void)
{
    const unsigned char secret[] = "delete-once";
    int ok = 1;

    cleanup_vault_db();
    if (open_unlocked_vault("delete-missing-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    ok = ok && (vault_delete("missing/secret") == SM_ERR_NOT_FOUND);
    ok = ok && (vault_put("cache/delete-once",
                          secret,
                          sizeof(secret) - 1U) == SM_OK);
    ok = ok && (vault_delete("cache/delete-once") == SM_OK);
    ok = ok && (vault_delete("cache/delete-once") == SM_ERR_NOT_FOUND);

    if (!ok) {
        printf("test_delete_missing_returns_not_found: expected not found\n");
    }

    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_wrong_password_rejected(void)
{
    int failure_count = 0;
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("right-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }
    if (vault_close() != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if (vault_init(TEST_DB) != SM_OK) {
        printf("test_wrong_password_rejected: reopen failed\n");
        cleanup_vault_db();
        return 1;
    }
    ok = (vault_unlock("wrong-password") == SM_ERR_AUTH) &&
         (query_auth_failure_count(&failure_count) == SM_OK) &&
         (failure_count == 1);
    if (!ok) {
        printf("test_wrong_password_rejected: expected auth failure event\n");
    }

    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_open_existing_requires_initialized_vault(void)
{
    FILE *file = NULL;
    int ok = 1;

    cleanup_vault_db();
    file = fopen(TEST_DB, "wb");
    if (file == NULL) {
        printf("test_open_existing_requires_initialized_vault: empty file setup failed\n");
        cleanup_vault_db();
        return 1;
    }
    if (fclose(file) != 0) {
        printf("test_open_existing_requires_initialized_vault: empty file close failed\n");
        cleanup_vault_db();
        return 1;
    }
    ok = ok && (vault_open(TEST_DB) == SM_ERR_STORAGE);

    cleanup_vault_db();
    ok = ok && (vault_init(TEST_DB) == SM_OK);
    ok = ok && (vault_close() == SM_OK);
    ok = ok && (vault_open(TEST_DB) == SM_OK);
    ok = ok && (vault_unlock_existing("schema-only-password") == SM_ERR_NOT_FOUND);

    if (!ok) {
        printf("test_open_existing_requires_initialized_vault: existing open accepted uninitialized DB\n");
    }

    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_missing_metadata_key_rejected_after_rotation(void)
{
    const unsigned char secret[] = "stable-metadata-secret";
    int nonce_count = -1;
    int wrapped_count = -1;
    int ok = 1;

    cleanup_vault_db();
    ok = ok && (open_unlocked_vault("old metadata password") == SM_OK);
    ok = ok && (vault_put("metadata/stable",
                          secret,
                          sizeof(secret) - 1U) == SM_OK);
    ok = ok && (vault_rotate_kek("new metadata password") == SM_OK);
    ok = ok && (delete_metadata_keys_for_test() == SM_OK);
    ok = ok && (vault_close() == SM_OK);
    ok = ok && (vault_open(TEST_DB) == SM_OK);
    ok = ok && (vault_unlock_existing("new metadata password") == SM_ERR_STORAGE);
    ok = ok && (query_metadata_key_count("meta_key_nonce", &nonce_count) == SM_OK);
    ok = ok && (query_metadata_key_count("meta_key_wrapped", &wrapped_count) == SM_OK);
    ok = ok && (nonce_count == 0) && (wrapped_count == 0);

    if (!ok) {
        printf("test_missing_metadata_key_rejected_after_rotation: "
               "unlock should fail closed without recreating metadata key\n");
    }

    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_get_output_too_small(void)
{
    const unsigned char secret[] = "long-secret";
    unsigned char recovered[4];
    size_t written = sizeof(recovered);
    int ok = 0;

    cleanup_vault_db();
    if (open_unlocked_vault("small-output-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    if (vault_put("small/output", secret, sizeof(secret) - 1U) != SM_OK) {
        printf("test_get_output_too_small: put failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = vault_get("small/output", recovered, sizeof(recovered), &written) ==
         SM_ERR_INVALID_ARGUMENT;
    if (!ok) {
        printf("test_get_output_too_small: expected invalid argument\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

typedef struct {
    size_t count;
    size_t archived_count;
    int saw_alpha_v2;
    int saw_gamma_ttl;
} list_probe_t;

static int collect_list_item(const vault_list_item_t *item, void *user_data)
{
    list_probe_t *probe = user_data;

    if ((item == NULL) || (probe == NULL) ||
        (item->name == NULL) || (item->algorithm == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    probe->count++;
    if (item->is_archived) {
        probe->archived_count++;
    }
    if ((strcmp(item->name, "alpha") == 0) &&
        (item->version == 2) &&
        !item->is_archived &&
        (strcmp(item->algorithm, "XChaCha20-Poly1305") == 0)) {
        probe->saw_alpha_v2 = 1;
    }
    if ((strcmp(item->name, "gamma") == 0) &&
        !item->is_archived &&
        (item->expires_at != NULL) &&
        (item->rotation_interval_seconds == 7U * 24U * 60U * 60U)) {
        probe->saw_gamma_ttl = 1;
    }

    return SM_OK;
}

static int test_list_and_security_report(void)
{
    const unsigned char first[] = "first";
    const unsigned char second[] = "second";
    const unsigned char beta[] = "beta";
    const unsigned char gamma[] = "gamma";
    vault_security_report_t report;
    list_probe_t active_probe = {0U, 0U, 0, 0};
    list_probe_t all_probe = {0U, 0U, 0, 0};
    size_t matched = 0U;
    int root_nonzero = 0;
    int ok = 1;

    sodium_memzero(&report, sizeof(report));
    cleanup_vault_db();
    if (open_unlocked_vault("report-password") != SM_OK) {
        cleanup_vault_db();
        return 1;
    }

    ok = ok && (vault_put_with_algorithm("alpha",
                                         first,
                                         sizeof(first) - 1U,
                                         "XChaCha20-Poly1305") == SM_OK);
    ok = ok && (vault_put_with_algorithm("alpha",
                                         second,
                                         sizeof(second) - 1U,
                                         "XChaCha20-Poly1305") == SM_OK);
    ok = ok && (vault_put_with_algorithm("beta",
                                         beta,
                                         sizeof(beta) - 1U,
                                         "XChaCha20-Poly1305") == SM_OK);
    ok = ok && (vault_delete("beta") == SM_OK);
    ok = ok && (vault_put_with_options("gamma",
                                       gamma,
                                       sizeof(gamma) - 1U,
                                       "XChaCha20-Poly1305",
                                       7U * 24U * 60U * 60U) == SM_OK);

    ok = ok && (vault_list_secrets(0,
                                   collect_list_item,
                                   &active_probe,
                                   &matched) == SM_OK) &&
         (matched == 2U) &&
         (active_probe.count == 2U) &&
         (active_probe.archived_count == 0U) &&
         active_probe.saw_alpha_v2 &&
         active_probe.saw_gamma_ttl;
    ok = ok && (vault_list_secrets(1,
                                   collect_list_item,
                                   &all_probe,
                                   &matched) == SM_OK) &&
         (matched == 4U) &&
         (all_probe.count == 4U) &&
         (all_probe.archived_count == 2U);
    ok = ok && (vault_security_report(&report) == SM_OK) &&
         (report.distinct_names == 3U) &&
         (report.active_secrets == 2U) &&
         (report.archived_versions == 2U) &&
         (report.total_versions == 4U) &&
         (report.deleted_names == 1U) &&
         (report.ttl_active == 1U) &&
         (report.expired_active == 0U) &&
         (report.expiring_7d == 1U) &&
         (report.active_xchacha20poly1305 == 2U) &&
         (report.active_aes256gcm == 0U) &&
         (report.audit_entries == 5U) &&
         (report.audit_leaf_count == 5U);

    if (ok) {
        for (size_t i = 0U; i < sizeof(report.audit_root); i++) {
            root_nonzero = root_nonzero || (report.audit_root[i] != 0U);
        }
        ok = root_nonzero;
    }
    if (!ok) {
        printf("test_list_and_security_report: expected governance report counts\n");
    }

    sodium_memzero(&report, sizeof(report));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

static int test_invalid_args_and_locked_state(void)
{
    const unsigned char secret[] = "secret";
    unsigned char recovered[16];
    size_t written = sizeof(recovered);
    int version = 0;
    int ok = 1;

    cleanup_vault_db();
    ok = ok && (vault_put("locked", secret, sizeof(secret) - 1U) == SM_ERR_AUTH);
    ok = ok && (vault_get("locked", recovered, sizeof(recovered), &written) == SM_ERR_AUTH);
    ok = ok && (vault_get_version("locked",
                                  1,
                                  recovered,
                                  sizeof(recovered),
                                  &written) == SM_ERR_AUTH);
    ok = ok && (vault_delete("locked") == SM_ERR_AUTH);
    ok = ok && (vault_rollback("locked", 1) == SM_ERR_AUTH);
    ok = ok && (vault_get_active_version("locked", &version) == SM_ERR_AUTH);
    ok = ok && (vault_check_expiry(0U, NULL, NULL, &written) == SM_ERR_AUTH);
    ok = ok && (vault_auto_rotate_expired(&written) == SM_ERR_AUTH);
    ok = ok && (vault_list_secrets(0, collect_list_item, NULL, &written) ==
                SM_ERR_AUTH);
    ok = ok && (vault_security_report((vault_security_report_t *)recovered) ==
                SM_ERR_AUTH);
    ok = ok && (vault_issue_token("locked",
                                  "read:*",
                                  60U,
                                  (char *)recovered,
                                  sizeof(recovered)) == SM_ERR_AUTH);
    ok = ok && (vault_check_token("token", "read:*") == SM_ERR_AUTH);

    if (vault_init(TEST_DB) != SM_OK || vault_unlock("arg-password") != SM_OK) {
        printf("test_invalid_args_and_locked_state: setup failed\n");
        cleanup_vault_db();
        return 1;
    }

    ok = ok && (vault_put(NULL, secret, sizeof(secret) - 1U) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_put("", secret, sizeof(secret) - 1U) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_put("bad-null-secret", NULL, 1U) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_put_with_algorithm("bad-algorithm",
                                         secret,
                                         sizeof(secret) - 1U,
                                         "Not-A-Real-Algorithm") ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_put_with_options("bad-ttl",
                                       secret,
                                       sizeof(secret) - 1U,
                                       NULL,
                                       UINT64_MAX) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_check_expiry(0U, NULL, NULL, NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_auto_rotate_expired(NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_list_secrets(0, NULL, NULL, &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_list_secrets(0, collect_list_item, NULL, NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_security_report(NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_issue_token(NULL,
                                  "read:*",
                                  60U,
                                  (char *)recovered,
                                  sizeof(recovered)) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_issue_token("subject",
                                  NULL,
                                  60U,
                                  (char *)recovered,
                                  sizeof(recovered)) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_issue_token("subject",
                                  "read:*",
                                  0U,
                                  (char *)recovered,
                                  sizeof(recovered)) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_check_token(NULL, "read:*") ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get(NULL, recovered, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get("", recovered, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get("name", NULL, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get("name", recovered, sizeof(recovered), NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_version(NULL, 1, recovered, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_version("", 1, recovered, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_version("name", 0, recovered, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_version("name", 1, NULL, sizeof(recovered), &written) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_version("name", 1, recovered, sizeof(recovered), NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_delete(NULL) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_delete("") == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_rollback(NULL, 1) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_rollback("", 1) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_rollback("name", 0) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_active_version(NULL, &version) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_active_version("", &version) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_get_active_version("name", NULL) ==
                SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_invalid_args_and_locked_state: expected argument/auth failures\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_vault_db();
    return ok ? 0 : 1;
}

int test_vault_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_vault_run: sodium_init failed\n");
        return 1;
    }

    failed += test_put_get_roundtrip();
    failed += test_secret_name_metadata_not_plaintext();
    failed += test_put_with_xchacha_and_rollback_preserves_algorithm();
    failed += test_expiry_check_and_auto_rotate();
    failed += test_token_issue_and_scope_authorization();
    failed += test_token_revoke_invalidates_existing_token();
    failed += test_update_increments_version_and_counter();
    failed += test_get_specific_version_preserves_history();
    failed += test_metadata_name_tamper_rejected();
    failed += test_active_version_tamper_rejected();
    failed += test_expiry_ignores_tampered_active_version();
    failed += test_rollback_creates_new_active_version();
    failed += test_delete_archives_secret();
    failed += test_delete_missing_returns_not_found();
    failed += test_wrong_password_rejected();
    failed += test_open_existing_requires_initialized_vault();
    failed += test_missing_metadata_key_rejected_after_rotation();
    failed += test_get_output_too_small();
    failed += test_list_and_security_report();
    failed += test_invalid_args_and_locked_state();

    if (failed != 0) {
        printf("test_vault_run: %d failures\n", failed);
    }

    cleanup_vault_db();
    return failed == 0 ? 0 : 1;
}
