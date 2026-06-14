#include "audit.h"

#include "storage.h"
#include "utils.h"

#include <limits.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AUDIT_ACTOR_DEFAULT "user:default"
#define AUDIT_RESULT_SUCCESS "SUCCESS"
#define AUDIT_RESULT_FAILURE "FAILURE"
#define AUDIT_MERKLE_LEAF_DOMAIN 0x00U
#define AUDIT_MERKLE_INTERNAL_DOMAIN 0x01U

typedef struct {
    unsigned char *data;
    size_t len;
} audit_bytes_t;

typedef struct {
    sqlite3_int64 entry_id;
    unsigned char signature[crypto_auth_BYTES];
} audit_resign_item_t;

typedef struct {
    unsigned char *hashes;
    size_t count;
} audit_merkle_level_t;

static int audit_checked_add(size_t *total, size_t value)
{
    if (total == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (*total > (SIZE_MAX - value)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *total += value;
    return SM_OK;
}

static void audit_write_u32_le(unsigned char *output, uint32_t value)
{
    size_t i = 0U;

    for (i = 0U; i < 4U; i++) {
        output[i] = (unsigned char)(value >> (i * 8U));
    }
}

static int audit_field_size(size_t field_len, size_t *encoded_len)
{
    if (encoded_len == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (field_len > (size_t)UINT32_MAX) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *encoded_len = 4U + field_len;
    return SM_OK;
}

static int audit_append_field(unsigned char **cursor,
                              const unsigned char *data,
                              size_t data_len)
{
    if ((cursor == NULL) || (*cursor == NULL) ||
        ((data == NULL) && (data_len > 0U)) ||
        (data_len > (size_t)UINT32_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    audit_write_u32_le(*cursor, (uint32_t)data_len);
    *cursor += 4U;
    if (data_len > 0U) {
        memcpy(*cursor, data, data_len);
        *cursor += data_len;
    }

    return SM_OK;
}

static void audit_free_bytes(audit_bytes_t *bytes)
{
    if ((bytes == NULL) || (bytes->data == NULL)) {
        return;
    }

    sodium_memzero(bytes->data, bytes->len);
    free(bytes->data);
    bytes->data = NULL;
    bytes->len = 0U;
}

static void audit_free_resign_items(audit_resign_item_t *items, size_t count)
{
    size_t i = 0U;

    if (items == NULL) {
        return;
    }

    for (i = 0U; i < count; i++) {
        sodium_memzero(items[i].signature, sizeof(items[i].signature));
    }
    free(items);
}

static void audit_free_merkle_level(audit_merkle_level_t *level)
{
    if ((level == NULL) || (level->hashes == NULL)) {
        return;
    }

    sodium_memzero(level->hashes, level->count * AUDIT_MERKLE_ROOT_BYTES);
    free(level->hashes);
    level->hashes = NULL;
    level->count = 0U;
}

static int audit_valid_action(const char *action)
{
    static const char *const actions[] = {
        "CREATE",
        "READ",
        "UPDATE",
        "DELETE",
        "ROLLBACK",
        "ROTATE_KEK",
        "ROTATE_DEK",
        "TOKEN_ISSUE",
        "TOKEN_REVOKE",
    };
    size_t i = 0U;

    if ((action == NULL) || (action[0] == '\0')) {
        return 0;
    }

    for (i = 0U; i < (sizeof(actions) / sizeof(actions[0])); i++) {
        if (strcmp(action, actions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int audit_valid_result(const char *result)
{
    if ((result == NULL) || (result[0] == '\0')) {
        return 0;
    }
    return (strcmp(result, AUDIT_RESULT_SUCCESS) == 0) ||
           (strcmp(result, AUDIT_RESULT_FAILURE) == 0);
}

static int audit_validate_key(const unsigned char *audit_key, size_t audit_key_len)
{
    if ((audit_key == NULL) || (audit_key_len != crypto_auth_KEYBYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return sodium_init() < 0 ? SM_ERR_CRYPTO : SM_OK;
}

static int audit_advance_ratchet_key(unsigned char *ratchet_key,
                                     size_t ratchet_key_len)
{
    unsigned char next_key[crypto_hash_sha256_BYTES];
    int status = SM_OK;

    if ((ratchet_key == NULL) || (ratchet_key_len != crypto_auth_KEYBYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(next_key, sizeof(next_key));
    if (crypto_hash_sha256(next_key, ratchet_key, ratchet_key_len) != 0) {
        status = SM_ERR_CRYPTO;
    } else {
        memcpy(ratchet_key, next_key, crypto_auth_KEYBYTES);
    }

    sodium_memzero(next_key, sizeof(next_key));
    return status;
}

/* Entry 0 uses K0; entry i uses SHA-256 ratcheted i times from K0. */
static int audit_derive_ratchet_key(const unsigned char *audit_key,
                                    size_t audit_key_len,
                                    size_t entry_index,
                                    unsigned char *ratchet_key)
{
    size_t i = 0U;
    int status = SM_OK;

    if (ratchet_key == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = audit_validate_key(audit_key, audit_key_len);
    if (status != SM_OK) {
        return status;
    }

    memcpy(ratchet_key, audit_key, crypto_auth_KEYBYTES);
    for (i = 0U; i < entry_index; i++) {
        status = audit_advance_ratchet_key(ratchet_key, crypto_auth_KEYBYTES);
        if (status != SM_OK) {
            sodium_memzero(ratchet_key, crypto_auth_KEYBYTES);
            return status;
        }
    }

    return SM_OK;
}

static int audit_build_entry_bytes(const char *timestamp,
                                   sqlite3_int64 entry_id,
                                   const char *action,
                                   const char *actor,
                                   const char *target,
                                   int target_version,
                                   const char *result,
                                   const unsigned char *prev_hash,
                                   const unsigned char *entry_hash,
                                   audit_bytes_t *bytes)
{
    static const unsigned char domain[] = "SM-AUDIT-v1";
    unsigned char entry_id_bytes[8];
    unsigned char version_bytes[8];
    const unsigned char *version_data = NULL;
    size_t version_len = 0U;
    const char *actor_value = actor;
    size_t total = 0U;
    size_t field_len = 0U;
    unsigned char *cursor = NULL;
    int status = SM_OK;

    if ((timestamp == NULL) || (timestamp[0] == '\0') ||
        (entry_id < 1) ||
        !audit_valid_action(action) ||
        (target == NULL) || (target[0] == '\0') ||
        !audit_valid_result(result) ||
        (prev_hash == NULL) ||
        (bytes == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((actor_value == NULL) || (actor_value[0] == '\0')) {
        actor_value = AUDIT_ACTOR_DEFAULT;
    }
    utils_write_u64_le(entry_id_bytes, (uint64_t)entry_id);
    if (target_version > 0) {
        utils_write_u64_le(version_bytes, (uint64_t)target_version);
        version_data = version_bytes;
        version_len = sizeof(version_bytes);
    }

    bytes->data = NULL;
    bytes->len = 0U;

#define ADD_FIELD_SIZE(length_expr)                                     \
    do {                                                                \
        status = audit_field_size((length_expr), &field_len);           \
        if (status == SM_OK) {                                          \
            status = audit_checked_add(&total, field_len);              \
        }                                                               \
        if (status != SM_OK) {                                          \
            sodium_memzero(entry_id_bytes, sizeof(entry_id_bytes));     \
            sodium_memzero(version_bytes, sizeof(version_bytes));       \
            return status;                                              \
        }                                                               \
    } while (0)

    ADD_FIELD_SIZE(sizeof(domain) - 1U);
    ADD_FIELD_SIZE(sizeof(entry_id_bytes));
    ADD_FIELD_SIZE(strlen(timestamp));
    ADD_FIELD_SIZE(strlen(action));
    ADD_FIELD_SIZE(strlen(actor_value));
    ADD_FIELD_SIZE(strlen(target));
    ADD_FIELD_SIZE(version_len);
    ADD_FIELD_SIZE(strlen(result));
    ADD_FIELD_SIZE(crypto_hash_sha256_BYTES);
    if (entry_hash != NULL) {
        ADD_FIELD_SIZE(crypto_hash_sha256_BYTES);
    }

#undef ADD_FIELD_SIZE

    bytes->data = malloc(total);
    if (bytes->data == NULL) {
        sodium_memzero(entry_id_bytes, sizeof(entry_id_bytes));
        sodium_memzero(version_bytes, sizeof(version_bytes));
        return SM_ERR_STORAGE;
    }
    bytes->len = total;
    cursor = bytes->data;

    status = audit_append_field(&cursor, domain, sizeof(domain) - 1U);
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    entry_id_bytes,
                                    sizeof(entry_id_bytes));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    (const unsigned char *)timestamp,
                                    strlen(timestamp));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    (const unsigned char *)action,
                                    strlen(action));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    (const unsigned char *)actor_value,
                                    strlen(actor_value));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    (const unsigned char *)target,
                                    strlen(target));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor, version_data, version_len);
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    (const unsigned char *)result,
                                    strlen(result));
    }
    if (status == SM_OK) {
        status = audit_append_field(&cursor,
                                    prev_hash,
                                    crypto_hash_sha256_BYTES);
    }
    if ((status == SM_OK) && (entry_hash != NULL)) {
        status = audit_append_field(&cursor,
                                    entry_hash,
                                    crypto_hash_sha256_BYTES);
    }

    sodium_memzero(entry_id_bytes, sizeof(entry_id_bytes));
    sodium_memzero(version_bytes, sizeof(version_bytes));
    if ((status != SM_OK) || ((size_t)(cursor - bytes->data) != total)) {
        audit_free_bytes(bytes);
        return status == SM_OK ? SM_ERR_STORAGE : status;
    }

    return SM_OK;
}

static int audit_compute_entry_hash(const char *timestamp,
                                    sqlite3_int64 entry_id,
                                    const char *action,
                                    const char *actor,
                                    const char *target,
                                    int target_version,
                                    const char *result,
                                    const unsigned char *prev_hash,
                                    unsigned char *entry_hash)
{
    audit_bytes_t bytes = {NULL, 0U};
    int status = SM_OK;

    if (entry_hash == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = audit_build_entry_bytes(timestamp,
                                     entry_id,
                                     action,
                                     actor,
                                     target,
                                     target_version,
                                     result,
                                     prev_hash,
                                     NULL,
                                     &bytes);
    if (status == SM_OK) {
        if (crypto_hash_sha256(entry_hash,
                               bytes.data,
                               (unsigned long long)bytes.len) != 0) {
            status = SM_ERR_CRYPTO;
        }
    }

    audit_free_bytes(&bytes);
    return status;
}

static int audit_compute_signature(const char *timestamp,
                                   sqlite3_int64 entry_id,
                                   const char *action,
                                   const char *actor,
                                   const char *target,
                                   int target_version,
                                   const char *result,
                                   const unsigned char *prev_hash,
                                   const unsigned char *entry_hash,
                                   const unsigned char *audit_key,
                                   unsigned char *signature)
{
    audit_bytes_t bytes = {NULL, 0U};
    int status = SM_OK;

    if ((entry_hash == NULL) || (audit_key == NULL) || (signature == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = audit_build_entry_bytes(timestamp,
                                     entry_id,
                                     action,
                                     actor,
                                     target,
                                     target_version,
                                     result,
                                     prev_hash,
                                     entry_hash,
                                     &bytes);
    if (status == SM_OK) {
        if (crypto_auth(signature,
                        bytes.data,
                        (unsigned long long)bytes.len,
                        audit_key) != 0) {
            status = SM_ERR_CRYPTO;
        }
    }

    audit_free_bytes(&bytes);
    return status;
}

static int audit_bind_blob(sqlite3_stmt *stmt,
                           int index,
                           const unsigned char *data,
                           size_t data_len)
{
    if ((stmt == NULL) || (data == NULL) || (data_len == 0U) ||
        (data_len > (size_t)INT_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return sqlite3_bind_blob(stmt,
                             index,
                             data,
                             (int)data_len,
                             SQLITE_TRANSIENT) == SQLITE_OK
               ? SM_OK
               : SM_ERR_STORAGE;
}

static int audit_column_text(sqlite3_stmt *stmt,
                             int column,
                             const char **text)
{
    const unsigned char *column_text = NULL;

    if ((stmt == NULL) || (text == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    column_text = sqlite3_column_text(stmt, column);
    if (column_text == NULL) {
        return SM_ERR_STORAGE;
    }

    *text = (const char *)column_text;
    return SM_OK;
}

static int audit_column_hash(sqlite3_stmt *stmt,
                             int column,
                             unsigned char *hash)
{
    const void *blob = NULL;
    int blob_len = 0;

    if ((stmt == NULL) || (hash == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    blob = sqlite3_column_blob(stmt, column);
    blob_len = sqlite3_column_bytes(stmt, column);
    if ((blob == NULL) || (blob_len != crypto_hash_sha256_BYTES)) {
        return SM_ERR_STORAGE;
    }

    memcpy(hash, blob, crypto_hash_sha256_BYTES);
    return SM_OK;
}

static int audit_column_signature(sqlite3_stmt *stmt,
                                  int column,
                                  unsigned char *signature)
{
    const void *blob = NULL;
    int blob_len = 0;

    if ((stmt == NULL) || (signature == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    blob = sqlite3_column_blob(stmt, column);
    blob_len = sqlite3_column_bytes(stmt, column);
    if ((blob == NULL) || (blob_len != crypto_auth_BYTES)) {
        return SM_ERR_STORAGE;
    }

    memcpy(signature, blob, crypto_auth_BYTES);
    return SM_OK;
}

static int audit_hash_merkle_leaf(const unsigned char *entry_hash,
                                  size_t entry_hash_len,
                                  unsigned char *leaf_hash)
{
    crypto_hash_sha256_state state;
    const unsigned char domain = AUDIT_MERKLE_LEAF_DOMAIN;

    if ((entry_hash == NULL) ||
        (entry_hash_len != AUDIT_MERKLE_ROOT_BYTES) ||
        (leaf_hash == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((crypto_hash_sha256_init(&state) != 0) ||
        (crypto_hash_sha256_update(&state, &domain, sizeof(domain)) != 0) ||
        (crypto_hash_sha256_update(&state, entry_hash, entry_hash_len) != 0) ||
        (crypto_hash_sha256_final(&state, leaf_hash) != 0)) {
        sodium_memzero(&state, sizeof(state));
        return SM_ERR_CRYPTO;
    }

    sodium_memzero(&state, sizeof(state));
    return SM_OK;
}

static int audit_hash_merkle_internal(const unsigned char *left_hash,
                                      const unsigned char *right_hash,
                                      unsigned char *parent_hash)
{
    crypto_hash_sha256_state state;
    const unsigned char domain = AUDIT_MERKLE_INTERNAL_DOMAIN;

    if ((left_hash == NULL) || (right_hash == NULL) || (parent_hash == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((crypto_hash_sha256_init(&state) != 0) ||
        (crypto_hash_sha256_update(&state, &domain, sizeof(domain)) != 0) ||
        (crypto_hash_sha256_update(&state,
                                   left_hash,
                                   AUDIT_MERKLE_ROOT_BYTES) != 0) ||
        (crypto_hash_sha256_update(&state,
                                   right_hash,
                                   AUDIT_MERKLE_ROOT_BYTES) != 0) ||
        (crypto_hash_sha256_final(&state, parent_hash) != 0)) {
        sodium_memzero(&state, sizeof(state));
        return SM_ERR_CRYPTO;
    }

    sodium_memzero(&state, sizeof(state));
    return SM_OK;
}

static int audit_count_entries(size_t *entry_count)
{
    static const char *const sql = "SELECT COUNT(*) FROM audit_log;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    sqlite3_int64 raw_count = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (entry_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *entry_count = 0U;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        raw_count = sqlite3_column_int64(stmt, 0);
        if ((raw_count < 0) || ((uint64_t)raw_count > (uint64_t)SIZE_MAX)) {
            status = SM_ERR_STORAGE;
        } else {
            *entry_count = (size_t)raw_count;
        }
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int audit_next_entry_id(sqlite3_int64 *entry_id)
{
    static const char *const sql =
        "SELECT COALESCE(MAX(entry_id), 0) + 1 FROM audit_log;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    sqlite3_int64 next_id = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (entry_id == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *entry_id = 0;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        next_id = sqlite3_column_int64(stmt, 0);
        if (next_id < 1) {
            status = SM_ERR_STORAGE;
        } else {
            *entry_id = next_id;
        }
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int audit_load_merkle_leaves(audit_merkle_level_t *level,
                                    int target_entry_id,
                                    size_t *target_index)
{
    static const char *const sql =
        "SELECT entry_id, entry_hash FROM audit_log ORDER BY entry_id ASC;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    size_t count = 0U;
    size_t index = 0U;
    int found = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (level == NULL) ||
        ((target_entry_id > 0) && (target_index == NULL))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    level->hashes = NULL;
    level->count = 0U;
    if (target_index != NULL) {
        *target_index = 0U;
    }

    status = audit_count_entries(&count);
    if (status != SM_OK) {
        return status;
    }
    if (count == 0U) {
        return target_entry_id > 0 ? SM_ERR_NOT_FOUND : SM_OK;
    }
    if (count > (SIZE_MAX / AUDIT_MERKLE_ROOT_BYTES)) {
        return SM_ERR_STORAGE;
    }

    level->hashes = malloc(count * AUDIT_MERKLE_ROOT_BYTES);
    if (level->hashes == NULL) {
        return SM_ERR_STORAGE;
    }
    level->count = count;
    sodium_memzero(level->hashes, count * AUDIT_MERKLE_ROOT_BYTES);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 entry_id = sqlite3_column_int64(stmt, 0);
        unsigned char entry_hash[AUDIT_MERKLE_ROOT_BYTES];

        if (index >= count) {
            status = SM_ERR_STORAGE;
            break;
        }
        sodium_memzero(entry_hash, sizeof(entry_hash));
        status = audit_column_hash(stmt, 1, entry_hash);
        if (status == SM_OK) {
            status = audit_hash_merkle_leaf(entry_hash,
                                            sizeof(entry_hash),
                                            level->hashes +
                                                (index * AUDIT_MERKLE_ROOT_BYTES));
        }
        sodium_memzero(entry_hash, sizeof(entry_hash));
        if (status != SM_OK) {
            break;
        }
        if ((target_entry_id > 0) && (entry_id == target_entry_id)) {
            *target_index = index;
            found = 1;
        }
        index++;
    }
    if ((rc != SQLITE_DONE) && (status == SM_OK)) {
        status = SM_ERR_STORAGE;
    }
    if (index != count) {
        status = SM_ERR_STORAGE;
    }

cleanup:
    if (stmt != NULL) {
        if (sqlite3_finalize(stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
    }
    if ((status == SM_OK) && (target_entry_id > 0) && !found) {
        status = SM_ERR_NOT_FOUND;
    }
    if (status != SM_OK) {
        audit_free_merkle_level(level);
    }
    return status;
}

static int audit_reduce_merkle_level(const audit_merkle_level_t *current,
                                     audit_merkle_level_t *next)
{
    size_t i = 0U;
    size_t next_count = 0U;
    int status = SM_OK;

    if ((current == NULL) || (current->hashes == NULL) ||
        (current->count < 2U) || (next == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    next->hashes = NULL;
    next->count = 0U;
    next_count = (current->count + 1U) / 2U;
    if (next_count > (SIZE_MAX / AUDIT_MERKLE_ROOT_BYTES)) {
        return SM_ERR_STORAGE;
    }
    next->hashes = malloc(next_count * AUDIT_MERKLE_ROOT_BYTES);
    if (next->hashes == NULL) {
        return SM_ERR_STORAGE;
    }
    next->count = next_count;
    sodium_memzero(next->hashes, next_count * AUDIT_MERKLE_ROOT_BYTES);

    for (i = 0U; i < next_count; i++) {
        const size_t left_index = i * 2U;
        size_t right_index = left_index + 1U;
        const unsigned char *left = current->hashes +
                                    (left_index * AUDIT_MERKLE_ROOT_BYTES);
        const unsigned char *right = NULL;

        if (right_index >= current->count) {
            right_index = left_index;
        }
        right = current->hashes + (right_index * AUDIT_MERKLE_ROOT_BYTES);
        status = audit_hash_merkle_internal(left,
                                            right,
                                            next->hashes +
                                                (i * AUDIT_MERKLE_ROOT_BYTES));
        if (status != SM_OK) {
            audit_free_merkle_level(next);
            return status;
        }
    }

    return SM_OK;
}

int audit_get_last_hash(unsigned char *hash, size_t hash_len)
{
    static const char *const sql =
        "SELECT entry_hash FROM audit_log ORDER BY entry_id DESC LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    const void *blob = NULL;
    int blob_len = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (hash == NULL) ||
        (hash_len < crypto_hash_sha256_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(hash, hash_len);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        blob = sqlite3_column_blob(stmt, 0);
        blob_len = sqlite3_column_bytes(stmt, 0);
        if ((blob == NULL) || (blob_len != crypto_hash_sha256_BYTES)) {
            status = SM_ERR_STORAGE;
        } else {
            memcpy(hash, blob, crypto_hash_sha256_BYTES);
        }
    } else if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

int audit_get_entry_hash(int entry_id, unsigned char *hash, size_t hash_len)
{
    static const char *const sql =
        "SELECT entry_hash FROM audit_log WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (entry_id < 1) || (hash == NULL) ||
        (hash_len < crypto_hash_sha256_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(hash, hash_len);
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
        status = audit_column_hash(stmt, 0, hash);
    } else if (rc == SQLITE_DONE) {
        status = SM_ERR_NOT_FOUND;
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

int audit_compute_merkle_root(unsigned char *root,
                              size_t root_len,
                              size_t *leaf_count)
{
    audit_merkle_level_t current = {NULL, 0U};
    int status = SM_OK;

    if ((root == NULL) || (root_len < AUDIT_MERKLE_ROOT_BYTES) ||
        (leaf_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(root, root_len);
    *leaf_count = 0U;
    status = audit_load_merkle_leaves(&current, 0, NULL);
    if (status != SM_OK) {
        return status;
    }
    *leaf_count = current.count;
    if (current.count == 0U) {
        return SM_OK;
    }

    while ((status == SM_OK) && (current.count > 1U)) {
        audit_merkle_level_t next = {NULL, 0U};

        status = audit_reduce_merkle_level(&current, &next);
        audit_free_merkle_level(&current);
        current = next;
    }
    if (status == SM_OK) {
        memcpy(root, current.hashes, AUDIT_MERKLE_ROOT_BYTES);
    }

    audit_free_merkle_level(&current);
    return status;
}

int audit_build_merkle_proof(int entry_id,
                             unsigned char *proof,
                             size_t proof_capacity,
                             size_t *proof_len,
                             size_t *leaf_index,
                             size_t *leaf_count)
{
    audit_merkle_level_t current = {NULL, 0U};
    size_t index = 0U;
    int status = SM_OK;

    if ((entry_id < 1) || (proof == NULL) || (proof_len == NULL) ||
        (leaf_index == NULL) || (leaf_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *proof_len = 0U;
    *leaf_index = 0U;
    *leaf_count = 0U;
    status = audit_load_merkle_leaves(&current, entry_id, &index);
    if (status != SM_OK) {
        return status;
    }
    *leaf_index = index;
    *leaf_count = current.count;

    while ((status == SM_OK) && (current.count > 1U)) {
        audit_merkle_level_t next = {NULL, 0U};
        size_t sibling_index = (index % 2U) == 0U ? index + 1U : index - 1U;
        const unsigned char *sibling = NULL;

        if (sibling_index >= current.count) {
            sibling_index = index;
        }
        if (*proof_len > (SIZE_MAX - AUDIT_MERKLE_ROOT_BYTES)) {
            status = SM_ERR_STORAGE;
            break;
        }
        if ((*proof_len + AUDIT_MERKLE_ROOT_BYTES) > proof_capacity) {
            status = SM_ERR_INVALID_ARGUMENT;
            break;
        }
        sibling = current.hashes + (sibling_index * AUDIT_MERKLE_ROOT_BYTES);
        memcpy(proof + *proof_len, sibling, AUDIT_MERKLE_ROOT_BYTES);
        *proof_len += AUDIT_MERKLE_ROOT_BYTES;

        status = audit_reduce_merkle_level(&current, &next);
        audit_free_merkle_level(&current);
        current = next;
        index /= 2U;
    }

    audit_free_merkle_level(&current);
    if (status != SM_OK) {
        sodium_memzero(proof, proof_capacity);
        *proof_len = 0U;
        *leaf_index = 0U;
        *leaf_count = 0U;
    }
    return status;
}

int audit_verify_merkle_proof(const unsigned char *entry_hash,
                              size_t entry_hash_len,
                              size_t leaf_index,
                              size_t leaf_count,
                              const unsigned char *proof,
                              size_t proof_len,
                              const unsigned char *root,
                              size_t root_len)
{
    unsigned char current[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char parent[AUDIT_MERKLE_ROOT_BYTES];
    size_t index = leaf_index;
    size_t count = leaf_count;
    size_t offset = 0U;
    int status = SM_OK;

    if ((entry_hash == NULL) ||
        (entry_hash_len != AUDIT_MERKLE_ROOT_BYTES) ||
        (leaf_count == 0U) ||
        (leaf_index >= leaf_count) ||
        ((proof == NULL) && (proof_len > 0U)) ||
        ((proof_len % AUDIT_MERKLE_ROOT_BYTES) != 0U) ||
        (root == NULL) ||
        (root_len != AUDIT_MERKLE_ROOT_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(current, sizeof(current));
    sodium_memzero(parent, sizeof(parent));
    status = audit_hash_merkle_leaf(entry_hash, entry_hash_len, current);
    if (status != SM_OK) {
        goto cleanup;
    }

    while (count > 1U) {
        const unsigned char *sibling = NULL;

        if ((proof_len - offset) < AUDIT_MERKLE_ROOT_BYTES) {
            status = SM_ERR_INVALID_ARGUMENT;
            goto cleanup;
        }
        sibling = proof + offset;
        if ((index % 2U) == 0U) {
            status = audit_hash_merkle_internal(current, sibling, parent);
        } else {
            status = audit_hash_merkle_internal(sibling, current, parent);
        }
        if (status != SM_OK) {
            goto cleanup;
        }

        memcpy(current, parent, sizeof(current));
        sodium_memzero(parent, sizeof(parent));
        offset += AUDIT_MERKLE_ROOT_BYTES;
        index /= 2U;
        count = (count + 1U) / 2U;
    }
    if (offset != proof_len) {
        status = SM_ERR_INVALID_ARGUMENT;
    } else if (sodium_memcmp(current, root, AUDIT_MERKLE_ROOT_BYTES) != 0) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    sodium_memzero(current, sizeof(current));
    sodium_memzero(parent, sizeof(parent));
    return status;
}

int audit_log_event(const char *actor,
                    const char *action,
                    const char *target,
                    int target_version,
                    const char *result,
                    const unsigned char *audit_key,
                    size_t audit_key_len)
{
    static const char *const sql =
        "INSERT INTO audit_log "
        "(entry_id, timestamp, action, actor, target, target_version, result, "
        "prev_hash, entry_hash, hmac_signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char timestamp[UTILS_ISO8601_UTC_BUFFER_LEN];
    const char *actor_value = actor;
    sqlite3_int64 entry_id = 0;
    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    unsigned char entry_hash[crypto_hash_sha256_BYTES];
    unsigned char signature[crypto_auth_BYTES];
    unsigned char ratchet_key[crypto_auth_KEYBYTES];
    size_t entry_count = 0U;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = audit_validate_key(audit_key, audit_key_len);
    if (status != SM_OK) {
        return status;
    }
    if ((actor_value == NULL) || (actor_value[0] == '\0')) {
        actor_value = AUDIT_ACTOR_DEFAULT;
    }

    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));

    status = utils_now_iso8601(timestamp, sizeof(timestamp));
    if (status == SM_OK) {
        status = audit_get_last_hash(prev_hash, sizeof(prev_hash));
    }
    if (status == SM_OK) {
        status = audit_next_entry_id(&entry_id);
    }
    if (status == SM_OK) {
        status = audit_count_entries(&entry_count);
    }
    if (status == SM_OK) {
        status = audit_compute_entry_hash(timestamp,
                                          entry_id,
                                          action,
                                          actor_value,
                                          target,
                                          target_version,
                                          result,
                                          prev_hash,
                                          entry_hash);
    }
    if (status == SM_OK) {
        status = audit_derive_ratchet_key(audit_key,
                                          audit_key_len,
                                          entry_count,
                                          ratchet_key);
    }
    if (status == SM_OK) {
        status = audit_compute_signature(timestamp,
                                         entry_id,
                                         action,
                                         actor_value,
                                         target,
                                         target_version,
                                         result,
                                         prev_hash,
                                         entry_hash,
                                         ratchet_key,
                                         signature);
    }
    if (status != SM_OK) {
        goto cleanup;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    rc = sqlite3_bind_int64(stmt, 1, entry_id);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 3, action, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 4, actor_value, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 5, target, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = target_version > 0
                 ? sqlite3_bind_int(stmt, 6, target_version)
                 : sqlite3_bind_null(stmt, 6);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 7, result, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        status = audit_bind_blob(stmt, 8, prev_hash, sizeof(prev_hash));
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = audit_bind_blob(stmt, 9, entry_hash, sizeof(entry_hash));
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = audit_bind_blob(stmt, 10, signature, sizeof(signature));
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc != SQLITE_OK) {
        status = status == SM_OK ? SM_ERR_STORAGE : status;
        goto cleanup;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

cleanup:
    if (stmt != NULL) {
        if (sqlite3_finalize(stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
    }
    sodium_memzero(timestamp, sizeof(timestamp));
    sodium_memzero(prev_hash, sizeof(prev_hash));
    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    return status;
}

int audit_resign_chain(const unsigned char *audit_key, size_t audit_key_len)
{
    static const char *const select_sql =
        "SELECT entry_id, timestamp, action, actor, target, target_version, result, "
        "prev_hash, entry_hash FROM audit_log ORDER BY entry_id ASC;";
    static const char *const update_sql =
        "UPDATE audit_log SET hmac_signature = ? WHERE entry_id = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *select_stmt = NULL;
    sqlite3_stmt *update_stmt = NULL;
    audit_resign_item_t *items = NULL;
    size_t item_count = 0U;
    size_t item_capacity = 0U;
    unsigned char expected_prev[crypto_hash_sha256_BYTES];
    unsigned char stored_prev[crypto_hash_sha256_BYTES];
    unsigned char stored_entry_hash[crypto_hash_sha256_BYTES];
    unsigned char computed_entry_hash[crypto_hash_sha256_BYTES];
    unsigned char ratchet_key[crypto_auth_KEYBYTES];
    int rc = SQLITE_OK;
    int status = SM_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = audit_validate_key(audit_key, audit_key_len);
    if (status != SM_OK) {
        return status;
    }

    sodium_memzero(expected_prev, sizeof(expected_prev));
    sodium_memzero(stored_prev, sizeof(stored_prev));
    sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
    sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    memcpy(ratchet_key, audit_key, sizeof(ratchet_key));

    rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    while ((rc = sqlite3_step(select_stmt)) == SQLITE_ROW) {
        const char *timestamp = NULL;
        const char *action = NULL;
        const char *actor = NULL;
        const char *target = NULL;
        const char *result = NULL;
        int target_version = 0;
        audit_resign_item_t *grown = NULL;

        if (item_count == item_capacity) {
            size_t new_capacity = item_capacity == 0U ? 8U : item_capacity * 2U;

            if (new_capacity < item_capacity) {
                status = SM_ERR_STORAGE;
                break;
            }
            if (new_capacity > (SIZE_MAX / sizeof(*items))) {
                status = SM_ERR_STORAGE;
                break;
            }
            grown = realloc(items, new_capacity * sizeof(*items));
            if (grown == NULL) {
                status = SM_ERR_STORAGE;
                break;
            }
            items = grown;
            sodium_memzero(items + item_capacity,
                           (new_capacity - item_capacity) * sizeof(*items));
            item_capacity = new_capacity;
        }

        items[item_count].entry_id = sqlite3_column_int64(select_stmt, 0);
        if (items[item_count].entry_id < 1) {
            status = SM_ERR_STORAGE;
        }
        if (status == SM_OK) {
            status = audit_column_text(select_stmt, 1, &timestamp);
        }
        if (status == SM_OK) {
            status = audit_column_text(select_stmt, 2, &action);
        }
        if (status == SM_OK) {
            status = audit_column_text(select_stmt, 3, &actor);
        }
        if (status == SM_OK) {
            status = audit_column_text(select_stmt, 4, &target);
        }
        if (status == SM_OK) {
            if (sqlite3_column_type(select_stmt, 5) == SQLITE_NULL) {
                target_version = 0;
            } else {
                target_version = sqlite3_column_int(select_stmt, 5);
                if (target_version < 1) {
                    status = SM_ERR_STORAGE;
                }
            }
        }
        if (status == SM_OK) {
            status = audit_column_text(select_stmt, 6, &result);
        }
        if (status == SM_OK) {
            status = audit_column_hash(select_stmt, 7, stored_prev);
        }
        if (status == SM_OK) {
            status = audit_column_hash(select_stmt, 8, stored_entry_hash);
        }
        if (status != SM_OK) {
            break;
        }

        if (sodium_memcmp(stored_prev,
                          expected_prev,
                          sizeof(stored_prev)) != 0) {
            status = SM_ERR_CRYPTO;
            break;
        }

        status = audit_compute_entry_hash(timestamp,
                                          items[item_count].entry_id,
                                          action,
                                          actor,
                                          target,
                                          target_version,
                                          result,
                                          stored_prev,
                                          computed_entry_hash);
        if (status != SM_OK) {
            break;
        }
        if (sodium_memcmp(stored_entry_hash,
                          computed_entry_hash,
                          sizeof(stored_entry_hash)) != 0) {
            status = SM_ERR_CRYPTO;
            break;
        }

        status = audit_compute_signature(timestamp,
                                         items[item_count].entry_id,
                                         action,
                                         actor,
                                         target,
                                         target_version,
                                         result,
                                         stored_prev,
                                         stored_entry_hash,
                                         ratchet_key,
                                         items[item_count].signature);
        if (status != SM_OK) {
            break;
        }

        status = audit_advance_ratchet_key(ratchet_key, sizeof(ratchet_key));
        if (status != SM_OK) {
            break;
        }

        memcpy(expected_prev, stored_entry_hash, sizeof(expected_prev));
        sodium_memzero(stored_prev, sizeof(stored_prev));
        sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
        sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
        item_count++;
    }

    if ((rc != SQLITE_DONE) && (status == SM_OK)) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(select_stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    select_stmt = NULL;
    if (status != SM_OK) {
        goto cleanup;
    }

    rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    for (size_t i = 0U; i < item_count; i++) {
        rc = sqlite3_bind_blob(update_stmt,
                               1,
                               items[i].signature,
                               (int)sizeof(items[i].signature),
                               SQLITE_TRANSIENT);
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_int(update_stmt, 2, items[i].entry_id);
        }
        if (rc != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
        if (status == SM_OK) {
            rc = sqlite3_step(update_stmt);
            if ((rc != SQLITE_DONE) || (sqlite3_changes(db) != 1)) {
                status = SM_ERR_STORAGE;
            }
        }
        if (sqlite3_reset(update_stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
        if (sqlite3_clear_bindings(update_stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
        if (status != SM_OK) {
            break;
        }
    }

cleanup:
    if (select_stmt != NULL) {
        if (sqlite3_finalize(select_stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
    }
    if (update_stmt != NULL) {
        if (sqlite3_finalize(update_stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
    }
    audit_free_resign_items(items, item_count);
    sodium_memzero(expected_prev, sizeof(expected_prev));
    sodium_memzero(stored_prev, sizeof(stored_prev));
    sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
    sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    return status;
}

int audit_verify_chain(const unsigned char *audit_key, size_t audit_key_len)
{
    static const char *const sql =
        "SELECT entry_id, timestamp, action, actor, target, target_version, result, "
        "prev_hash, entry_hash, hmac_signature "
        "FROM audit_log ORDER BY entry_id ASC;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    unsigned char expected_prev[crypto_hash_sha256_BYTES];
    unsigned char stored_prev[crypto_hash_sha256_BYTES];
    unsigned char stored_entry_hash[crypto_hash_sha256_BYTES];
    unsigned char computed_entry_hash[crypto_hash_sha256_BYTES];
    unsigned char signature[crypto_auth_BYTES];
    unsigned char ratchet_key[crypto_auth_KEYBYTES];
    const char *timestamp = NULL;
    const char *action = NULL;
    const char *actor = NULL;
    const char *target = NULL;
    const char *result = NULL;
    sqlite3_int64 entry_id = 0;
    int target_version = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = audit_validate_key(audit_key, audit_key_len);
    if (status != SM_OK) {
        return status;
    }

    sodium_memzero(expected_prev, sizeof(expected_prev));
    sodium_memzero(stored_prev, sizeof(stored_prev));
    sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
    sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    memcpy(ratchet_key, audit_key, sizeof(ratchet_key));

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        entry_id = sqlite3_column_int64(stmt, 0);
        if (entry_id < 1) {
            status = SM_ERR_STORAGE;
        }
        if (status == SM_OK) {
            status = audit_column_text(stmt, 1, &timestamp);
        }
        if (status == SM_OK) {
            status = audit_column_text(stmt, 2, &action);
        }
        if (status == SM_OK) {
            status = audit_column_text(stmt, 3, &actor);
        }
        if (status == SM_OK) {
            status = audit_column_text(stmt, 4, &target);
        }
        if (status == SM_OK) {
            if (sqlite3_column_type(stmt, 5) == SQLITE_NULL) {
                target_version = 0;
            } else {
                target_version = sqlite3_column_int(stmt, 5);
                if (target_version < 1) {
                    status = SM_ERR_STORAGE;
                }
            }
        }
        if (status == SM_OK) {
            status = audit_column_text(stmt, 6, &result);
        }
        if (status == SM_OK) {
            status = audit_column_hash(stmt, 7, stored_prev);
        }
        if (status == SM_OK) {
            status = audit_column_hash(stmt, 8, stored_entry_hash);
        }
        if (status == SM_OK) {
            status = audit_column_signature(stmt, 9, signature);
        }
        if (status != SM_OK) {
            break;
        }

        if (sodium_memcmp(stored_prev,
                          expected_prev,
                          sizeof(stored_prev)) != 0) {
            status = SM_ERR_CRYPTO;
            break;
        }

        status = audit_compute_entry_hash(timestamp,
                                          entry_id,
                                          action,
                                          actor,
                                          target,
                                          target_version,
                                          result,
                                          stored_prev,
                                          computed_entry_hash);
        if (status != SM_OK) {
            break;
        }
        if (sodium_memcmp(stored_entry_hash,
                          computed_entry_hash,
                          sizeof(stored_entry_hash)) != 0) {
            status = SM_ERR_CRYPTO;
            break;
        }

        {
            audit_bytes_t signed_bytes = {NULL, 0U};

            status = audit_build_entry_bytes(timestamp,
                                             entry_id,
                                             action,
                                             actor,
                                             target,
                                             target_version,
                                             result,
                                             stored_prev,
                                             stored_entry_hash,
                                             &signed_bytes);
            if (status == SM_OK) {
                if (crypto_auth_verify(signature,
                                       signed_bytes.data,
                                       (unsigned long long)signed_bytes.len,
                                       ratchet_key) != 0) {
                    status = SM_ERR_CRYPTO;
                }
            }
            audit_free_bytes(&signed_bytes);
        }
        if (status != SM_OK) {
            break;
        }
        status = audit_advance_ratchet_key(ratchet_key, sizeof(ratchet_key));
        if (status != SM_OK) {
            break;
        }

        memcpy(expected_prev, stored_entry_hash, sizeof(expected_prev));
        sodium_memzero(stored_prev, sizeof(stored_prev));
        sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
        sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
        sodium_memzero(signature, sizeof(signature));
    }

    if ((rc != SQLITE_DONE) && (status == SM_OK)) {
        status = SM_ERR_STORAGE;
    }
cleanup:
    if ((stmt != NULL) && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        status = SM_ERR_STORAGE;
    }

    sodium_memzero(expected_prev, sizeof(expected_prev));
    sodium_memzero(stored_prev, sizeof(stored_prev));
    sodium_memzero(stored_entry_hash, sizeof(stored_entry_hash));
    sodium_memzero(computed_entry_hash, sizeof(computed_entry_hash));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(ratchet_key, sizeof(ratchet_key));
    return status;
}
