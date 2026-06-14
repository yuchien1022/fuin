#include "audit.h"
#include "storage.h"
#include "utils.h"
#include "vault.h"

#include <sodium.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *const TEST_DB = "results/test_audit.db";

typedef struct {
    unsigned char *data;
    size_t len;
} test_audit_bytes_t;

static void test_audit_write_u32_le(unsigned char *output, uint32_t value)
{
    size_t i = 0U;

    for (i = 0U; i < 4U; i++) {
        output[i] = (unsigned char)(value >> (i * 8U));
    }
}

static void test_audit_write_i64_le(unsigned char *output, int64_t value)
{
    uint64_t encoded = (uint64_t)value;
    size_t i = 0U;

    for (i = 0U; i < 8U; i++) {
        output[i] = (unsigned char)(encoded >> (i * 8U));
    }
}

static void test_audit_free_bytes(test_audit_bytes_t *bytes)
{
    if ((bytes == NULL) || (bytes->data == NULL)) {
        return;
    }

    sodium_memzero(bytes->data, bytes->len);
    free(bytes->data);
    bytes->data = NULL;
    bytes->len = 0U;
}

static int test_audit_append_field(unsigned char **cursor,
                                   const unsigned char *data,
                                   size_t data_len)
{
    if ((cursor == NULL) || (*cursor == NULL) ||
        ((data == NULL) && (data_len > 0U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    test_audit_write_u32_le(*cursor, (uint32_t)data_len);
    *cursor += 4U;
    if (data_len > 0U) {
        memcpy(*cursor, data, data_len);
        *cursor += data_len;
    }

    return SM_OK;
}

static void cleanup_audit_db(void)
{
    (void)vault_close();
    (void)storage_close();
    (void)remove(TEST_DB);
    (void)remove("results/test_audit.db-shm");
    (void)remove("results/test_audit.db-wal");
}

static int open_audit_storage(void)
{
    int status = storage_init(TEST_DB);

    if (status != SM_OK) {
        printf("open_audit_storage: init failed: %s\n", utils_status_message(status));
    }
    return status;
}

static int query_audit_count(int *count)
{
    static const char *const sql = "SELECT COUNT(*) FROM audit_log;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

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

static int query_audit_event(int entry_id,
                             char *action,
                             size_t action_len,
                             int *target_version)
{
    static const char *const sql =
        "SELECT action, target_version FROM audit_log WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    const unsigned char *text = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;
    int written = 0;

    if ((db == NULL) || (entry_id < 1) || (action == NULL) ||
        (action_len == 0U) || (target_version == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 1, entry_id);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        text = sqlite3_column_text(stmt, 0);
        if (text == NULL) {
            status = SM_ERR_STORAGE;
        } else {
            written = snprintf(action, action_len, "%s", (const char *)text);
            if ((written < 0) || ((size_t)written >= action_len)) {
                status = SM_ERR_STORAGE;
            }
        }
        if (status == SM_OK) {
            *target_version = sqlite3_column_int(stmt, 1);
        }
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int query_audit_signature_material(int entry_id,
                                          char *timestamp,
                                          size_t timestamp_len,
                                          char *action,
                                          size_t action_len,
                                          char *actor,
                                          size_t actor_len,
                                          char *target,
                                          size_t target_len,
                                          int *target_version,
                                          char *result,
                                          size_t result_len,
                                          unsigned char *prev_hash,
                                          unsigned char *entry_hash,
                                          unsigned char *signature)
{
    static const char *const sql =
        "SELECT timestamp, action, actor, target, target_version, result, "
        "prev_hash, entry_hash, hmac_signature FROM audit_log WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char *text_outputs[] = {timestamp, action, actor, target, result};
    size_t text_lengths[] = {timestamp_len, action_len, actor_len, target_len, result_len};
    int text_columns[] = {0, 1, 2, 3, 5};
    unsigned char *blob_outputs[] = {prev_hash, entry_hash, signature};
    size_t blob_lengths[] = {crypto_hash_sha256_BYTES,
                             crypto_hash_sha256_BYTES,
                             crypto_auth_BYTES};
    int blob_columns[] = {6, 7, 8};
    int rc = SQLITE_OK;
    int status = SM_OK;
    size_t i = 0U;

    if ((db == NULL) || (entry_id < 1) || (timestamp == NULL) ||
        (action == NULL) || (actor == NULL) || (target == NULL) ||
        (target_version == NULL) || (result == NULL) ||
        (prev_hash == NULL) || (entry_hash == NULL) || (signature == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 1, entry_id);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    for (i = 0U; i < (sizeof(text_outputs) / sizeof(text_outputs[0])); i++) {
        const unsigned char *column_text = sqlite3_column_text(stmt, text_columns[i]);
        int written = 0;

        if ((column_text == NULL) || (text_lengths[i] == 0U)) {
            status = SM_ERR_STORAGE;
            goto cleanup;
        }
        written = snprintf(text_outputs[i],
                           text_lengths[i],
                           "%s",
                           (const char *)column_text);
        if ((written < 0) || ((size_t)written >= text_lengths[i])) {
            status = SM_ERR_STORAGE;
            goto cleanup;
        }
    }

    if (sqlite3_column_type(stmt, 4) == SQLITE_NULL) {
        *target_version = 0;
    } else {
        *target_version = sqlite3_column_int(stmt, 4);
        if (*target_version < 1) {
            status = SM_ERR_STORAGE;
            goto cleanup;
        }
    }

    for (i = 0U; i < (sizeof(blob_outputs) / sizeof(blob_outputs[0])); i++) {
        const void *blob = sqlite3_column_blob(stmt, blob_columns[i]);
        int blob_len = sqlite3_column_bytes(stmt, blob_columns[i]);

        if ((blob == NULL) || (blob_len != (int)blob_lengths[i])) {
            status = SM_ERR_STORAGE;
            goto cleanup;
        }
        memcpy(blob_outputs[i], blob, blob_lengths[i]);
    }

cleanup:
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int build_test_audit_signed_bytes(const char *timestamp,
                                         sqlite3_int64 entry_id,
                                         const char *action,
                                         const char *actor,
                                         const char *target,
                                         int target_version,
                                         const char *result,
                                         const unsigned char *prev_hash,
                                         const unsigned char *entry_hash,
                                         test_audit_bytes_t *bytes)
{
    static const unsigned char domain[] = "SM-AUDIT-v1";
    unsigned char entry_id_bytes[8];
    unsigned char version_bytes[8];
    const unsigned char *version_data = NULL;
    size_t version_len = 0U;
    size_t total = 0U;
    unsigned char *cursor = NULL;
    int status = SM_OK;

    if ((timestamp == NULL) || (action == NULL) || (actor == NULL) ||
        (entry_id < 1) || (target == NULL) || (result == NULL) ||
        (prev_hash == NULL) || (entry_hash == NULL) || (bytes == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    bytes->data = NULL;
    bytes->len = 0U;
    test_audit_write_i64_le(entry_id_bytes, (int64_t)entry_id);
    sodium_memzero(version_bytes, sizeof(version_bytes));
    if (target_version > 0) {
        test_audit_write_i64_le(version_bytes, (int64_t)target_version);
        version_data = version_bytes;
        version_len = sizeof(version_bytes);
    }

    total = (4U + (sizeof(domain) - 1U)) +
            (4U + sizeof(entry_id_bytes)) +
            (4U + strlen(timestamp)) +
            (4U + strlen(action)) +
            (4U + strlen(actor)) +
            (4U + strlen(target)) +
            (4U + version_len) +
            (4U + strlen(result)) +
            (4U + crypto_hash_sha256_BYTES) +
            (4U + crypto_hash_sha256_BYTES);
    bytes->data = malloc(total);
    if (bytes->data == NULL) {
        sodium_memzero(entry_id_bytes, sizeof(entry_id_bytes));
        sodium_memzero(version_bytes, sizeof(version_bytes));
        return SM_ERR_STORAGE;
    }
    bytes->len = total;
    cursor = bytes->data;

    status = test_audit_append_field(&cursor, domain, sizeof(domain) - 1U);
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         entry_id_bytes,
                                         sizeof(entry_id_bytes));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         (const unsigned char *)timestamp,
                                         strlen(timestamp));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         (const unsigned char *)action,
                                         strlen(action));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         (const unsigned char *)actor,
                                         strlen(actor));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         (const unsigned char *)target,
                                         strlen(target));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor, version_data, version_len);
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         (const unsigned char *)result,
                                         strlen(result));
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         prev_hash,
                                         crypto_hash_sha256_BYTES);
    }
    if (status == SM_OK) {
        status = test_audit_append_field(&cursor,
                                         entry_hash,
                                         crypto_hash_sha256_BYTES);
    }
    if ((status != SM_OK) || ((size_t)(cursor - bytes->data) != total)) {
        test_audit_free_bytes(bytes);
        status = status == SM_OK ? SM_ERR_STORAGE : status;
    }

    sodium_memzero(entry_id_bytes, sizeof(entry_id_bytes));
    sodium_memzero(version_bytes, sizeof(version_bytes));
    return status;
}

static int tamper_action(int entry_id, const char *action)
{
    static const char *const sql =
        "UPDATE audit_log SET action = ? WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (entry_id < 1) || (action == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, action, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 2, entry_id);
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

static int tamper_prev_hash(int entry_id)
{
    static const char *const sql =
        "UPDATE audit_log SET prev_hash = ? WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    unsigned char zero_hash[crypto_hash_sha256_BYTES];
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (entry_id < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(zero_hash, sizeof(zero_hash));
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt,
                               1,
                               zero_hash,
                               (int)sizeof(zero_hash),
                               SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 2, entry_id);
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
    sodium_memzero(zero_hash, sizeof(zero_hash));
    return status;
}

static int tamper_entry_ids_by_offset(int offset)
{
    static const char *const sql =
        "UPDATE audit_log SET entry_id = entry_id + ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (offset <= 0)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 1, offset);
    }
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
    return status;
}

static int test_log_and_verify_chain(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char last_hash[crypto_hash_sha256_BYTES];
    int count = 0;
    int nonzero = 0;
    size_t i = 0U;
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    if ((audit_get_last_hash(last_hash, sizeof(last_hash)) != SM_OK) ||
        (audit_log_event(NULL, "CREATE", "database/prod/password", 1, "SUCCESS",
                         key, sizeof(key)) != SM_OK) ||
        (audit_log_event("user:default", "READ", "database/prod/password", 1,
                         "SUCCESS", key, sizeof(key)) != SM_OK) ||
        (audit_verify_chain(key, sizeof(key)) != SM_OK) ||
        (query_audit_count(&count) != SM_OK) ||
        (audit_get_last_hash(last_hash, sizeof(last_hash)) != SM_OK)) {
        printf("test_log_and_verify_chain: audit operation failed\n");
        cleanup_audit_db();
        sodium_memzero(key, sizeof(key));
        return 1;
    }

    for (i = 0U; i < sizeof(last_hash); i++) {
        nonzero = nonzero || (last_hash[i] != 0U);
    }
    ok = (count == 2) && nonzero;
    if (!ok) {
        printf("test_log_and_verify_chain: expected 2 entries and nonzero last hash\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(last_hash, sizeof(last_hash));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_renumbered_entry_id_detected(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    ok = (audit_log_event("user:default", "CREATE", "renumber/key", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_log_event("user:default", "READ", "renumber/key", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
         (tamper_entry_ids_by_offset(100) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_ERR_CRYPTO);
    if (!ok) {
        printf("test_renumbered_entry_id_detected: expected rowid tamper failure\n");
    }

    sodium_memzero(key, sizeof(key));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_tampered_action_detected(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    ok = (audit_log_event("user:default", "CREATE", "api/key", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
         (tamper_action(1, "READ") == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_ERR_CRYPTO);
    if (!ok) {
        printf("test_tampered_action_detected: expected tamper failure\n");
    }

    sodium_memzero(key, sizeof(key));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_tampered_prev_hash_detected(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    ok = (audit_log_event("user:default", "CREATE", "api/key", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_log_event("user:default", "UPDATE", "api/key", 2, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
         (tamper_prev_hash(2) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_ERR_CRYPTO);
    if (!ok) {
        printf("test_tampered_prev_hash_detected: expected chain failure\n");
    }

    sodium_memzero(key, sizeof(key));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_wrong_key_detected(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char wrong_key[crypto_auth_KEYBYTES];
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    randombytes_buf(wrong_key, sizeof(wrong_key));
    ok = (audit_log_event("user:default", "DELETE", "cache/token", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(wrong_key, sizeof(wrong_key)) == SM_ERR_CRYPTO);
    if (!ok) {
        printf("test_wrong_key_detected: expected wrong-key failure\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(wrong_key, sizeof(wrong_key));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_forward_secure_ratchet_signatures(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char ratchet_key[crypto_auth_KEYBYTES];
    char timestamp[UTILS_ISO8601_UTC_BUFFER_LEN];
    char action[16];
    char actor[32];
    char target[64];
    char result[16];
    int target_version = 0;
    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    unsigned char entry_hash[crypto_hash_sha256_BYTES];
    unsigned char signature[crypto_auth_BYTES];
    test_audit_bytes_t signed_bytes = {NULL, 0U};
    int root_verifies = 0;
    int ratchet_verifies = 0;
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(signature, sizeof(signature));

    if ((audit_log_event("user:default", "CREATE", "ratchet/key", 1, "SUCCESS",
                         key, sizeof(key)) != SM_OK) ||
        (audit_log_event("user:default", "READ", "ratchet/key", 1, "SUCCESS",
                         key, sizeof(key)) != SM_OK) ||
        (audit_verify_chain(key, sizeof(key)) != SM_OK) ||
        (query_audit_signature_material(2,
                                        timestamp,
                                        sizeof(timestamp),
                                        action,
                                        sizeof(action),
                                        actor,
                                        sizeof(actor),
                                        target,
                                        sizeof(target),
                                        &target_version,
                                        result,
                                        sizeof(result),
                                        prev_hash,
                                        entry_hash,
                                        signature) != SM_OK) ||
        (build_test_audit_signed_bytes(timestamp,
                                       2,
                                       action,
                                       actor,
                                       target,
                                       target_version,
                                       result,
                                       prev_hash,
                                       entry_hash,
                                       &signed_bytes) != SM_OK)) {
        printf("test_forward_secure_ratchet_signatures: setup failed\n");
        goto cleanup;
    }

    memcpy(ratchet_key, key, sizeof(ratchet_key));
    if (crypto_hash_sha256(ratchet_key, key, sizeof(key)) != 0) {
        printf("test_forward_secure_ratchet_signatures: ratchet failed\n");
        goto cleanup;
    }

    root_verifies = crypto_auth_verify(signature,
                                       signed_bytes.data,
                                       (unsigned long long)signed_bytes.len,
                                       key) == 0;
    ratchet_verifies = crypto_auth_verify(signature,
                                          signed_bytes.data,
                                          (unsigned long long)signed_bytes.len,
                                          ratchet_key) == 0;
    ok = (!root_verifies) && ratchet_verifies;
    if (!ok) {
        printf("test_forward_secure_ratchet_signatures: expected second entry "
               "to require the ratcheted key\n");
    }

cleanup:
    test_audit_free_bytes(&signed_bytes);
    sodium_memzero(key, sizeof(key));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(signature, sizeof(signature));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_merkle_root_and_proof(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char new_root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    unsigned char entry_hash[crypto_hash_sha256_BYTES];
    unsigned char tampered[AUDIT_MERKLE_ROOT_BYTES];
    char timestamp[UTILS_ISO8601_UTC_BUFFER_LEN];
    char action[16];
    char actor[32];
    char target[64];
    char result[16];
    int target_version = 0;
    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    unsigned char signature[crypto_auth_BYTES];
    size_t proof_len = 0U;
    size_t leaf_index = 0U;
    size_t leaf_count = 0U;
    size_t new_leaf_count = 0U;
    int root_nonzero = 0;
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(new_root, sizeof(new_root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(tampered, sizeof(tampered));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(signature, sizeof(signature));

    ok = (audit_log_event("user:default", "CREATE", "merkle/a", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_log_event("user:default", "READ", "merkle/a", 1, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_log_event("user:default", "UPDATE", "merkle/a", 2, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_log_event("user:default", "DELETE", "merkle/a", 2, "SUCCESS",
                          key, sizeof(key)) == SM_OK) &&
         (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
         (audit_compute_merkle_root(root, sizeof(root), &leaf_count) == SM_OK) &&
         (leaf_count == 4U) &&
         (audit_build_merkle_proof(3,
                                   proof,
                                   sizeof(proof),
                                   &proof_len,
                                   &leaf_index,
                                   &leaf_count) == SM_OK) &&
         (leaf_count == 4U) &&
         (leaf_index == 2U) &&
         (proof_len == (2U * AUDIT_MERKLE_ROOT_BYTES)) &&
         (query_audit_signature_material(3,
                                         timestamp,
                                         sizeof(timestamp),
                                         action,
                                         sizeof(action),
                                         actor,
                                         sizeof(actor),
                                         target,
                                         sizeof(target),
                                         &target_version,
                                         result,
                                         sizeof(result),
                                         prev_hash,
                                         entry_hash,
                                         signature) == SM_OK) &&
         (audit_get_entry_hash(3, tampered, sizeof(tampered)) == SM_OK) &&
         (sodium_memcmp(tampered, entry_hash, sizeof(tampered)) == 0) &&
         (audit_verify_merkle_proof(entry_hash,
                                    sizeof(entry_hash),
                                    leaf_index,
                                    leaf_count,
                                    proof,
                                    proof_len,
                                    root,
                                    sizeof(root)) == SM_OK);
    if (ok) {
        for (size_t i = 0U; i < sizeof(root); i++) {
            root_nonzero = root_nonzero || (root[i] != 0U);
        }
        ok = root_nonzero;
    }
    if (ok) {
        memcpy(tampered, entry_hash, sizeof(tampered));
        tampered[0] ^= 0x01U;
        ok = audit_verify_merkle_proof(tampered,
                                       sizeof(tampered),
                                       leaf_index,
                                       leaf_count,
                                       proof,
                                       proof_len,
                                       root,
                                       sizeof(root)) == SM_ERR_CRYPTO;
    }
    if (ok) {
        memcpy(tampered, root, sizeof(tampered));
        tampered[0] ^= 0x01U;
        ok = audit_verify_merkle_proof(entry_hash,
                                       sizeof(entry_hash),
                                       leaf_index,
                                       leaf_count,
                                       proof,
                                       proof_len,
                                       tampered,
                                       sizeof(tampered)) == SM_ERR_CRYPTO;
    }
    if (ok) {
        ok = (audit_log_event("user:default", "READ", "merkle/a", 2, "SUCCESS",
                              key, sizeof(key)) == SM_OK) &&
             (audit_compute_merkle_root(new_root,
                                        sizeof(new_root),
                                        &new_leaf_count) == SM_OK) &&
             (new_leaf_count == 5U) &&
             (sodium_memcmp(root, new_root, sizeof(root)) != 0);
    }
    if (!ok) {
        printf("test_merkle_root_and_proof: expected valid root/proof and "
               "tamper failures\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(new_root, sizeof(new_root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(tampered, sizeof(tampered));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(signature, sizeof(signature));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_merkle_edge_cases(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    unsigned char short_proof[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char entry_hash[crypto_hash_sha256_BYTES];
    char timestamp[UTILS_ISO8601_UTC_BUFFER_LEN];
    char action[16];
    char actor[32];
    char target[64];
    char result[16];
    int target_version = 0;
    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    unsigned char signature[crypto_auth_BYTES];
    size_t proof_len = 0U;
    size_t short_proof_len = 0U;
    size_t leaf_index = 0U;
    size_t leaf_count = 0U;
    int root_zero = 1;
    int short_proof_zero = 1;
    int ok = 0;

    cleanup_audit_db();
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    randombytes_buf(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(short_proof, sizeof(short_proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(signature, sizeof(signature));

    ok = (audit_compute_merkle_root(root, sizeof(root), &leaf_count) == SM_OK) &&
         (leaf_count == 0U) &&
         (audit_build_merkle_proof(1,
                                   proof,
                                   sizeof(proof),
                                   &proof_len,
                                   &leaf_index,
                                   &leaf_count) == SM_ERR_NOT_FOUND);
    if (ok) {
        for (size_t i = 0U; i < sizeof(root); i++) {
            root_zero = root_zero && (root[i] == 0U);
        }
        ok = root_zero;
    }
    if (ok) {
        ok = (audit_compute_merkle_root(NULL, sizeof(root), &leaf_count) ==
              SM_ERR_INVALID_ARGUMENT) &&
             (audit_compute_merkle_root(root, 1U, &leaf_count) ==
              SM_ERR_INVALID_ARGUMENT) &&
             (audit_build_merkle_proof(0,
                                       proof,
                                       sizeof(proof),
                                       &proof_len,
                                       &leaf_index,
                                       &leaf_count) ==
              SM_ERR_INVALID_ARGUMENT) &&
             (audit_verify_merkle_proof(entry_hash,
                                        sizeof(entry_hash),
                                        1U,
                                        1U,
                                        proof,
                                        0U,
                                        root,
                                        sizeof(root)) ==
              SM_ERR_INVALID_ARGUMENT);
    }
    if (ok) {
        ok = (audit_log_event("user:default", "CREATE", "edge/a", 1, "SUCCESS",
                              key, sizeof(key)) == SM_OK) &&
             (audit_log_event("user:default", "READ", "edge/a", 1, "SUCCESS",
                              key, sizeof(key)) == SM_OK) &&
             (audit_log_event("user:default", "DELETE", "edge/a", 1, "SUCCESS",
                              key, sizeof(key)) == SM_OK) &&
             (audit_verify_chain(key, sizeof(key)) == SM_OK) &&
             (audit_compute_merkle_root(root, sizeof(root), &leaf_count) == SM_OK) &&
             (leaf_count == 3U) &&
             (audit_build_merkle_proof(3,
                                       proof,
                                       sizeof(proof),
                                       &proof_len,
                                       &leaf_index,
                                       &leaf_count) == SM_OK) &&
             (leaf_index == 2U) &&
             (leaf_count == 3U) &&
             (proof_len == (2U * AUDIT_MERKLE_ROOT_BYTES)) &&
             (query_audit_signature_material(3,
                                             timestamp,
                                             sizeof(timestamp),
                                             action,
                                             sizeof(action),
                                             actor,
                                             sizeof(actor),
                                             target,
                                             sizeof(target),
                                             &target_version,
                                             result,
                                             sizeof(result),
                                             prev_hash,
                                             entry_hash,
                                             signature) == SM_OK) &&
             (audit_verify_merkle_proof(entry_hash,
                                        sizeof(entry_hash),
                                        leaf_index,
                                        leaf_count,
                                        proof,
                                        proof_len,
                                        root,
                                        sizeof(root)) == SM_OK);
    }
    if (ok) {
        ok = (audit_verify_merkle_proof(entry_hash,
                                        sizeof(entry_hash),
                                        leaf_index,
                                        leaf_count,
                                        proof,
                                        proof_len - AUDIT_MERKLE_ROOT_BYTES,
                                        root,
                                        sizeof(root)) ==
              SM_ERR_INVALID_ARGUMENT) &&
             (audit_verify_merkle_proof(entry_hash,
                                        sizeof(entry_hash),
                                        leaf_index,
                                        leaf_count,
                                        proof,
                                        proof_len + AUDIT_MERKLE_ROOT_BYTES,
                                        root,
                                        sizeof(root)) ==
              SM_ERR_INVALID_ARGUMENT);
    }
    if (ok) {
        ok = audit_build_merkle_proof(3,
                                      short_proof,
                                      sizeof(short_proof),
                                      &short_proof_len,
                                      &leaf_index,
                                      &leaf_count) == SM_ERR_INVALID_ARGUMENT;
    }
    if (ok) {
        for (size_t i = 0U; i < sizeof(short_proof); i++) {
            short_proof_zero = short_proof_zero && (short_proof[i] == 0U);
        }
        ok = short_proof_zero &&
             (short_proof_len == 0U) &&
             (leaf_index == 0U) &&
             (leaf_count == 0U);
    }
    if (!ok) {
        printf("test_merkle_edge_cases: expected edge cases to validate\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(short_proof, sizeof(short_proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(action, sizeof(action));
    sodium_memzero(actor, sizeof(actor));
    sodium_memzero(target, sizeof(target));
    sodium_memzero(result, sizeof(result));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(signature, sizeof(signature));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_invalid_args(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char hash[crypto_hash_sha256_BYTES];
    int ok = 1;

    cleanup_audit_db();
    randombytes_buf(key, sizeof(key));

    ok = ok && (audit_get_last_hash(hash, sizeof(hash)) ==
                SM_ERR_INVALID_ARGUMENT);
    if (open_audit_storage() != SM_OK) {
        cleanup_audit_db();
        return 1;
    }

    ok = ok && (audit_log_event("user:default", NULL, "target", 1, "SUCCESS",
                                key, sizeof(key)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_log_event("user:default", "CREATE", NULL, 1, "SUCCESS",
                                key, sizeof(key)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_log_event("user:default", "CREATE", "target", 1, "BAD",
                                key, sizeof(key)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_log_event("user:default", "CREATE", "target", 1,
                                "SUCCESS", key, sizeof(key) - 1U) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_verify_chain(NULL, sizeof(key)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_verify_chain(key, sizeof(key) - 1U) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_get_entry_hash(0, hash, sizeof(hash)) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (audit_get_entry_hash(99, hash, sizeof(hash)) ==
                SM_ERR_NOT_FOUND);

    if (!ok) {
        printf("test_invalid_args: expected invalid argument failures\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(hash, sizeof(hash));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

static int test_vault_writes_audit_events(void)
{
    const unsigned char first[] = "first";
    const unsigned char second[] = "second";
    unsigned char recovered[sizeof(second) - 1U];
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    unsigned char entry_hash[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char tampered_root[AUDIT_MERKLE_ROOT_BYTES];
    char action[16];
    size_t written = sizeof(recovered);
    size_t leaf_count = 0U;
    size_t proof_len = 0U;
    size_t leaf_index = 0U;
    int version = 0;
    int count = 0;
    int ok = 1;

    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(tampered_root, sizeof(tampered_root));
    cleanup_audit_db();
    if ((vault_init(TEST_DB) != SM_OK) ||
        (vault_unlock("audit-vault-password") != SM_OK)) {
        printf("test_vault_writes_audit_events: setup failed\n");
        cleanup_audit_db();
        return 1;
    }

    ok = ok && (vault_put("service/api/key", first, sizeof(first) - 1U) == SM_OK);
    ok = ok && (vault_put("service/api/key", second, sizeof(second) - 1U) == SM_OK);
    ok = ok && (vault_rollback("service/api/key", 1) == SM_OK);
    ok = ok && (vault_get("service/api/key", recovered, sizeof(recovered), &written) == SM_OK);
    ok = ok && (vault_delete("service/api/key") == SM_OK);
    ok = ok && (query_audit_count(&count) == SM_OK) && (count == 5);
    ok = ok && (query_audit_event(1, action, sizeof(action), &version) == SM_OK) &&
         (strcmp(action, "CREATE") == 0) && (version == 1);
    ok = ok && (query_audit_event(2, action, sizeof(action), &version) == SM_OK) &&
         (strcmp(action, "UPDATE") == 0) && (version == 2);
    ok = ok && (query_audit_event(3, action, sizeof(action), &version) == SM_OK) &&
         (strcmp(action, "ROLLBACK") == 0) && (version == 3);
    ok = ok && (query_audit_event(4, action, sizeof(action), &version) == SM_OK) &&
         (strcmp(action, "READ") == 0) && (version == 3);
    ok = ok && (query_audit_event(5, action, sizeof(action), &version) == SM_OK) &&
         (strcmp(action, "DELETE") == 0) && (version == 3);
    ok = ok && (vault_audit_verify() == SM_OK);
    ok = ok && (vault_audit_merkle_root(root, sizeof(root), &leaf_count) == SM_OK) &&
         (leaf_count == 5U);
    ok = ok && (vault_audit_merkle_proof(3,
                                         entry_hash,
                                         sizeof(entry_hash),
                                         root,
                                         sizeof(root),
                                         proof,
                                         sizeof(proof),
                                         &proof_len,
                                         &leaf_index,
                                         &leaf_count) == SM_OK) &&
         (leaf_index == 2U) &&
         (leaf_count == 5U) &&
         (proof_len == (3U * AUDIT_MERKLE_ROOT_BYTES));
    ok = ok && (vault_audit_verify_merkle_proof(3,
                                                root,
                                                sizeof(root),
                                                proof,
                                                proof_len,
                                                leaf_index,
                                                leaf_count) == SM_OK);
    ok = ok && (vault_audit_merkle_proof(99,
                                         entry_hash,
                                         sizeof(entry_hash),
                                         root,
                                         sizeof(root),
                                         proof,
                                         sizeof(proof),
                                         &proof_len,
                                         &leaf_index,
                                         &leaf_count) == SM_ERR_NOT_FOUND);
    ok = ok && (vault_audit_verify_merkle_proof(99,
                                                root,
                                                sizeof(root),
                                                proof,
                                                proof_len,
                                                leaf_index,
                                                leaf_count) == SM_ERR_NOT_FOUND);
    if (ok) {
        memcpy(tampered_root, root, sizeof(tampered_root));
        tampered_root[0] ^= 0x01U;
        ok = vault_audit_verify_merkle_proof(3,
                                             tampered_root,
                                             sizeof(tampered_root),
                                             proof,
                                             proof_len,
                                             leaf_index,
                                             leaf_count) == SM_ERR_CRYPTO;
    }

    if (!ok) {
        printf("test_vault_writes_audit_events: audit event mismatch\n");
    }

    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(tampered_root, sizeof(tampered_root));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_audit_db();
    return ok ? 0 : 1;
}

int test_audit_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_audit_run: sodium_init failed\n");
        return 1;
    }

    failed += test_log_and_verify_chain();
    failed += test_renumbered_entry_id_detected();
    failed += test_tampered_action_detected();
    failed += test_tampered_prev_hash_detected();
    failed += test_wrong_key_detected();
    failed += test_forward_secure_ratchet_signatures();
    failed += test_merkle_root_and_proof();
    failed += test_merkle_edge_cases();
    failed += test_invalid_args();
    failed += test_vault_writes_audit_events();

    if (failed != 0) {
        printf("test_audit_run: %d failures\n", failed);
    }

    cleanup_audit_db();
    return failed == 0 ? 0 : 1;
}
