#include "vault.h"

#include "access.h"
#include "audit.h"
#include "backup.h"
#include "crypto_engine.h"
#include "key_manager.h"
#include "kdf.h"
#include "storage.h"
#include "utils.h"

#include <limits.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VAULT_METADATA_SALT "salt"
#define VAULT_METADATA_VERIFIER "password_verifier"
#define VAULT_METADATA_TOKEN_NOT_BEFORE "token_not_before"
#define VAULT_METADATA_META_KEY_NONCE "meta_key_nonce"
#define VAULT_METADATA_META_KEY_WRAPPED "meta_key_wrapped"
#define VAULT_META_KEY_WRAP_AAD "vault:kek_meta:v1"
#define VAULT_META_KEY_WRAP_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define VAULT_META_KEY_WRAP_BYTES \
    (crypto_aead_xchacha20poly1305_ietf_KEYBYTES + \
     crypto_aead_xchacha20poly1305_ietf_ABYTES)
#define VAULT_SECRET_NAME_MAX 256U
#define VAULT_NAME_LOOKUP_BYTES crypto_generichash_BYTES
#define VAULT_NAME_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define VAULT_ENCRYPTED_NAME_MAX \
    (VAULT_SECRET_NAME_MAX + crypto_aead_xchacha20poly1305_ietf_ABYTES)

/* Single source of truth for "this row is the current active version of its
   secret": not archived AND the highest version among rows sharing its name.
   Every active-row query (point lookup, list, expiry scan, security report)
   references this macro so the definition cannot drift between call sites. The
   <t> argument is the outer table alias and MUST differ from the inner
   "secrets" so the correlated subquery binds to the outer row, not itself. */
#define VAULT_SQL_ACTIVE_ROW(t) \
    t ".is_archived = 0 AND " t ".version = " \
    "(SELECT MAX(version) FROM secrets WHERE name = " t ".name)"

typedef struct {
    int exists;
    char id[UTILS_UUID_V4_BUFFER_LEN];
    int version;
    sqlite3_int64 nonce_counter;
    unsigned char name_nonce[VAULT_NAME_NONCE_BYTES];
    size_t name_nonce_len;
    unsigned char encrypted_name[VAULT_ENCRYPTED_NAME_MAX];
    size_t encrypted_name_len;
    char created_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    char expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    sqlite3_int64 rotation_interval_seconds;
    int has_expiration;
} vault_secret_metadata_t;

typedef struct {
    char id[UTILS_UUID_V4_BUFFER_LEN];
    int version;
    encrypted_secret_t encrypted;
} vault_secret_row_t;

static kdf_subkeys_t *g_subkeys;
static int g_unlocked;

static kdf_subkeys_t *vault_alloc_subkeys(void)
{
    kdf_subkeys_t *subkeys = sodium_malloc(sizeof(*subkeys));

    if (subkeys == NULL) {
        return NULL;
    }
    if (sodium_mlock(subkeys, sizeof(*subkeys)) != 0) {
        sodium_free(subkeys);
        return NULL;
    }

    sodium_memzero(subkeys, sizeof(*subkeys));
    return subkeys;
}

static void vault_free_subkeys(kdf_subkeys_t **subkeys)
{
    if ((subkeys == NULL) || (*subkeys == NULL)) {
        return;
    }

    sodium_memzero(*subkeys, sizeof(**subkeys));
    (void)sodium_munlock(*subkeys, sizeof(**subkeys));
    sodium_free(*subkeys);
    *subkeys = NULL;
}

static void vault_lock_state(void)
{
    vault_free_subkeys(&g_subkeys);
    g_unlocked = 0;
}

static int vault_require_unlocked(void)
{
    return (g_unlocked && (g_subkeys != NULL)) ? SM_OK : SM_ERR_AUTH;
}

static int vault_log_success(const char *action,
                             const char *target,
                             int target_version)
{
    if ((g_subkeys == NULL) || (action == NULL) || (target == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return audit_log_event("user:default",
                           action,
                           target,
                           target_version,
                           "SUCCESS",
                           g_subkeys->kek_audit,
                           sizeof(g_subkeys->kek_audit));
}

static int vault_bind_blob(sqlite3_stmt *stmt,
                           int index,
                           const unsigned char *data,
                           size_t data_len)
{
    if ((stmt == NULL) || ((data == NULL) && (data_len > 0U)) ||
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

static int vault_build_name_lookup(const char *name,
                                   char *lookup_hex,
                                   size_t lookup_hex_len)
{
    unsigned char lookup[VAULT_NAME_LOOKUP_BYTES];
    int status = SM_OK;

    sodium_memzero(lookup, sizeof(lookup));
    if ((g_subkeys == NULL) || (name == NULL) || (name[0] == '\0') ||
        (lookup_hex == NULL) || (lookup_hex_len < VAULT_NAME_LOOKUP_HEX_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (crypto_generichash(lookup,
                           sizeof(lookup),
                           (const unsigned char *)name,
                           strlen(name),
                           g_subkeys->kek_meta,
                           sizeof(g_subkeys->kek_meta)) != 0) {
        status = SM_ERR_CRYPTO;
    }
    if (status == SM_OK) {
        if (sodium_bin2hex(lookup_hex,
                           lookup_hex_len,
                           lookup,
                           sizeof(lookup)) == NULL) {
            status = SM_ERR_CRYPTO;
        }
    }

    sodium_memzero(lookup, sizeof(lookup));
    return status;
}

static int vault_encrypt_display_name(const char *name,
                                      const char *stored_name,
                                      unsigned char *nonce,
                                      size_t nonce_len,
                                      unsigned char *encrypted_name,
                                      size_t encrypted_name_capacity,
                                      size_t *encrypted_name_len)
{
    unsigned long long written = 0U;
    size_t name_len = name == NULL ? 0U : strlen(name);

    if ((g_subkeys == NULL) || (name == NULL) || (stored_name == NULL) ||
        (stored_name[0] == '\0') || (name_len == 0U) ||
        (name_len > VAULT_SECRET_NAME_MAX) ||
        (nonce == NULL) || (nonce_len != VAULT_NAME_NONCE_BYTES) ||
        (encrypted_name == NULL) ||
        (encrypted_name_capacity < (name_len + crypto_aead_xchacha20poly1305_ietf_ABYTES)) ||
        (encrypted_name_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    randombytes_buf(nonce, nonce_len);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted_name,
            &written,
            (const unsigned char *)name,
            (unsigned long long)name_len,
            (const unsigned char *)stored_name,
            (unsigned long long)strlen(stored_name),
            NULL,
            nonce,
            g_subkeys->kek_meta) != 0) {
        sodium_memzero(nonce, nonce_len);
        sodium_memzero(encrypted_name, encrypted_name_capacity);
        return SM_ERR_CRYPTO;
    }

    *encrypted_name_len = (size_t)written;
    return SM_OK;
}

static int vault_decrypt_display_name(const char *stored_name,
                                      const unsigned char *nonce,
                                      size_t nonce_len,
                                      const unsigned char *encrypted_name,
                                      size_t encrypted_name_len,
                                      char *name,
                                      size_t name_len)
{
    unsigned long long written = 0U;

    if ((g_subkeys == NULL) || (stored_name == NULL) ||
        (stored_name[0] == '\0') ||
        (nonce == NULL) || (nonce_len != VAULT_NAME_NONCE_BYTES) ||
        (encrypted_name == NULL) ||
        (encrypted_name_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
        (encrypted_name_len > VAULT_ENCRYPTED_NAME_MAX) ||
        (name == NULL) || (name_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char *)name,
            &written,
            NULL,
            encrypted_name,
            (unsigned long long)encrypted_name_len,
            (const unsigned char *)stored_name,
            (unsigned long long)strlen(stored_name),
            nonce,
            g_subkeys->kek_meta) != 0) {
        sodium_memzero(name, name_len);
        return SM_ERR_CRYPTO;
    }
    if (written >= name_len) {
        sodium_memzero(name, name_len);
        return SM_ERR_STORAGE;
    }

    name[written] = '\0';
    return SM_OK;
}

static int vault_copy_name_metadata(sqlite3_stmt *stmt,
                                    int nonce_column,
                                    int encrypted_name_column,
                                    vault_secret_metadata_t *metadata)
{
    const void *nonce = NULL;
    const void *encrypted_name = NULL;
    int nonce_len = 0;
    int encrypted_name_len = 0;
    int status = SM_OK;

    if ((stmt == NULL) || (metadata == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    nonce = sqlite3_column_blob(stmt, nonce_column);
    nonce_len = sqlite3_column_bytes(stmt, nonce_column);
    encrypted_name = sqlite3_column_blob(stmt, encrypted_name_column);
    encrypted_name_len = sqlite3_column_bytes(stmt, encrypted_name_column);
    if ((nonce == NULL) || (nonce_len != (int)sizeof(metadata->name_nonce)) ||
        (encrypted_name == NULL) ||
        (encrypted_name_len <= (int)crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
        (encrypted_name_len > (int)sizeof(metadata->encrypted_name))) {
        return SM_ERR_STORAGE;
    }

    metadata->name_nonce_len = (size_t)nonce_len;
    metadata->encrypted_name_len = (size_t)encrypted_name_len;
    memcpy(metadata->name_nonce, nonce, metadata->name_nonce_len);
    memcpy(metadata->encrypted_name,
           encrypted_name,
           metadata->encrypted_name_len);
    return status;
}

static int vault_copy_text_column(sqlite3_stmt *stmt,
                                  int column,
                                  char *output,
                                  size_t output_len)
{
    const unsigned char *text = NULL;
    int written = 0;

    if ((stmt == NULL) || (output == NULL) || (output_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    text = sqlite3_column_text(stmt, column);
    if (text == NULL) {
        output[0] = '\0';
        return SM_ERR_STORAGE;
    }

    written = snprintf(output, output_len, "%s", (const char *)text);
    if ((written < 0) || ((size_t)written >= output_len)) {
        output[0] = '\0';
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

static int vault_column_blob_size(sqlite3_stmt *stmt, int column, size_t *blob_len)
{
    int column_bytes = 0;

    if ((stmt == NULL) || (blob_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    column_bytes = sqlite3_column_bytes(stmt, column);
    if (column_bytes <= 0) {
        return SM_ERR_STORAGE;
    }

    *blob_len = (size_t)column_bytes;
    return SM_OK;
}

static int vault_copy_blob_column(sqlite3_stmt *stmt,
                                  int column,
                                  unsigned char *output,
                                  size_t output_len)
{
    const void *blob = NULL;
    int column_bytes = 0;

    if ((stmt == NULL) || (output == NULL) || (output_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    column_bytes = sqlite3_column_bytes(stmt, column);
    if ((column_bytes <= 0) || ((size_t)column_bytes != output_len)) {
        return SM_ERR_STORAGE;
    }

    blob = sqlite3_column_blob(stmt, column);
    if (blob == NULL) {
        return SM_ERR_STORAGE;
    }

    memcpy(output, blob, output_len);
    return SM_OK;
}

static int vault_put_metadata_blob(const char *key,
                                   const unsigned char *value,
                                   size_t value_len);

static int vault_get_metadata_blob(const char *key,
                                   unsigned char *output,
                                   size_t output_len,
                                   size_t *written,
                                   int *found)
{
    static const char *const sql =
        "SELECT value FROM metadata WHERE key = ? LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    const void *blob = NULL;
    int blob_len = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (key == NULL) || (output == NULL) ||
        (written == NULL) || (found == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = 0U;
    *found = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        blob = sqlite3_column_blob(stmt, 0);
        blob_len = sqlite3_column_bytes(stmt, 0);
        if ((blob_len < 0) || ((size_t)blob_len > output_len) ||
            ((blob == NULL) && (blob_len > 0))) {
            status = SM_ERR_STORAGE;
        } else {
            if (blob_len > 0) {
                memcpy(output, blob, (size_t)blob_len);
            }
            *written = (size_t)blob_len;
            *found = 1;
        }
    } else if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int vault_get_token_not_before(uint64_t *not_before)
{
    unsigned char encoded[8];
    size_t written = 0U;
    int found = 0;
    int status = SM_OK;

    if (not_before == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *not_before = 0U;
    sodium_memzero(encoded, sizeof(encoded));

    status = vault_get_metadata_blob(VAULT_METADATA_TOKEN_NOT_BEFORE,
                                     encoded,
                                     sizeof(encoded),
                                     &written,
                                     &found);
    if (status == SM_OK) {
        if (!found) {
            *not_before = 0U;
        } else if (written != sizeof(encoded)) {
            status = SM_ERR_STORAGE;
        } else {
            for (size_t i = 0U; i < sizeof(encoded); i++) {
                *not_before |= ((uint64_t)encoded[i]) << (8U * i);
            }
        }
    }

    sodium_memzero(encoded, sizeof(encoded));
    return status;
}

static int vault_put_token_not_before(uint64_t not_before)
{
    unsigned char encoded[8];
    int status = SM_OK;

    utils_write_u64_le(encoded, not_before);
    status = vault_put_metadata_blob(VAULT_METADATA_TOKEN_NOT_BEFORE,
                                     encoded,
                                     sizeof(encoded));
    sodium_memzero(encoded, sizeof(encoded));
    return status;
}

static int vault_put_wrapped_meta_key(const unsigned char *meta_key,
                                      const unsigned char *wrapping_key)
{
    unsigned char nonce[VAULT_META_KEY_WRAP_NONCE_BYTES];
    unsigned char wrapped[VAULT_META_KEY_WRAP_BYTES];
    unsigned long long wrapped_len = 0ULL;
    int status = SM_OK;

    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(wrapped, sizeof(wrapped));
    if ((meta_key == NULL) || (wrapping_key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            wrapped,
            &wrapped_len,
            meta_key,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            (const unsigned char *)VAULT_META_KEY_WRAP_AAD,
            (unsigned long long)(sizeof(VAULT_META_KEY_WRAP_AAD) - 1U),
            NULL,
            nonce,
            wrapping_key) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (wrapped_len != sizeof(wrapped)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }

    status = vault_put_metadata_blob(VAULT_METADATA_META_KEY_NONCE,
                                     nonce,
                                     sizeof(nonce));
    if (status == SM_OK) {
        status = vault_put_metadata_blob(VAULT_METADATA_META_KEY_WRAPPED,
                                         wrapped,
                                         sizeof(wrapped));
    }

cleanup:
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(wrapped, sizeof(wrapped));
    wrapped_len = 0ULL;
    return status;
}

static int vault_load_meta_key(kdf_subkeys_t *subkeys)
{
    unsigned char nonce[VAULT_META_KEY_WRAP_NONCE_BYTES];
    unsigned char wrapped[VAULT_META_KEY_WRAP_BYTES];
    unsigned char meta_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned long long meta_key_len = 0ULL;
    size_t nonce_len = 0U;
    size_t wrapped_len = 0U;
    int nonce_found = 0;
    int wrapped_found = 0;
    int status = SM_OK;

    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(meta_key, sizeof(meta_key));
    if (subkeys == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_get_metadata_blob(VAULT_METADATA_META_KEY_NONCE,
                                     nonce,
                                     sizeof(nonce),
                                     &nonce_len,
                                     &nonce_found);
    if (status == SM_OK) {
        status = vault_get_metadata_blob(VAULT_METADATA_META_KEY_WRAPPED,
                                         wrapped,
                                         sizeof(wrapped),
                                         &wrapped_len,
                                         &wrapped_found);
    }
    if (status != SM_OK) {
        goto cleanup;
    }

    if (!nonce_found || !wrapped_found ||
        (nonce_len != sizeof(nonce)) ||
        (wrapped_len != sizeof(wrapped))) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            meta_key,
            &meta_key_len,
            NULL,
            wrapped,
            (unsigned long long)wrapped_len,
            (const unsigned char *)VAULT_META_KEY_WRAP_AAD,
            (unsigned long long)(sizeof(VAULT_META_KEY_WRAP_AAD) - 1U),
            nonce,
            subkeys->kek_enc) != 0) {
        status = SM_ERR_AUTH;
        goto cleanup;
    }
    if (meta_key_len != sizeof(meta_key)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    memcpy(subkeys->kek_meta, meta_key, sizeof(meta_key));

cleanup:
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(wrapped, sizeof(wrapped));
    sodium_memzero(meta_key, sizeof(meta_key));
    meta_key_len = 0ULL;
    return status;
}

static int vault_put_metadata_blob(const char *key,
                                   const unsigned char *value,
                                   size_t value_len)
{
    static const char *const sql =
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?);";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (key == NULL) || ((value == NULL) && (value_len > 0U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt, 2, value, value_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return status == SM_OK ? SM_ERR_STORAGE : status;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int vault_log_auth_failure_untrusted(void)
{
    static const char *const sql =
        "INSERT INTO auth_failures (timestamp, result) VALUES (?1, 'FAILURE');";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(now, sizeof(now));
    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        return status;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    rc = sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
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
    sodium_memzero(now, sizeof(now));
    return status;
}

static int vault_copy_password(const char *master_password,
                               char **password_copy,
                               size_t *password_len)
{
    size_t len = 0U;
    char *copy = NULL;

    if ((master_password == NULL) || (password_copy == NULL) || (password_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    len = strlen(master_password);
    if (len == 0U) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    copy = sodium_malloc(len + 1U);
    if (copy == NULL) {
        return SM_ERR_STORAGE;
    }
    if (sodium_mlock(copy, len + 1U) != 0) {
        sodium_free(copy);
        return SM_ERR_STORAGE;
    }

    memcpy(copy, master_password, len + 1U);
    *password_copy = copy;
    *password_len = len + 1U;
    return SM_OK;
}

static void vault_free_password(char **password, size_t password_len)
{
    if ((password == NULL) || (*password == NULL)) {
        return;
    }

    sodium_memzero(*password, password_len);
    (void)sodium_munlock(*password, password_len);
    sodium_free(*password);
    *password = NULL;
}

static int vault_load_auth_metadata(unsigned char *salt,
                                    unsigned char *verifier,
                                    int *metadata_exists)
{
    size_t salt_len = 0U;
    size_t verifier_len = 0U;
    int salt_found = 0;
    int verifier_found = 0;
    int status = SM_OK;

    status = vault_get_metadata_blob(VAULT_METADATA_SALT,
                                     salt,
                                     KDF_SALT_BYTES,
                                     &salt_len,
                                     &salt_found);
    if (status == SM_OK) {
        status = vault_get_metadata_blob(VAULT_METADATA_VERIFIER,
                                         verifier,
                                         crypto_hash_sha256_BYTES,
                                         &verifier_len,
                                         &verifier_found);
    }
    if (status != SM_OK) {
        return status;
    }

    if (!salt_found && !verifier_found) {
        *metadata_exists = 0;
        return SM_OK;
    }

    if (!salt_found || !verifier_found ||
        (salt_len != KDF_SALT_BYTES) ||
        (verifier_len != crypto_hash_sha256_BYTES)) {
        return SM_ERR_STORAGE;
    }

    *metadata_exists = 1;
    return SM_OK;
}

static int vault_store_auth_metadata(const unsigned char *salt,
                                     const unsigned char *verifier,
                                     const kdf_subkeys_t *subkeys)
{
    int status = SM_OK;

    if ((salt == NULL) || (verifier == NULL) || (subkeys == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = storage_begin_transaction();
    if (status != SM_OK) {
        return status;
    }

    status = vault_put_metadata_blob(VAULT_METADATA_SALT, salt, KDF_SALT_BYTES);
    if (status == SM_OK) {
        status = vault_put_metadata_blob(VAULT_METADATA_VERIFIER,
                                         verifier,
                                         crypto_hash_sha256_BYTES);
    }
    if (status == SM_OK) {
        status = vault_put_wrapped_meta_key(subkeys->kek_meta,
                                            subkeys->kek_enc);
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }

    return status;
}

static int vault_derive_credentials(const char *master_password,
                                    unsigned char *salt,
                                    unsigned char *verifier,
                                    kdf_subkeys_t **subkeys_out)
{
    unsigned char *master_key = NULL;
    kdf_subkeys_t *subkeys = NULL;
    char *password_copy = NULL;
    size_t password_copy_len = 0U;
    int master_key_locked = 0;
    int status = SM_OK;

    if ((master_password == NULL) || (master_password[0] == '\0') ||
        (salt == NULL) || (verifier == NULL) || (subkeys_out == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *subkeys_out = NULL;
    sodium_memzero(verifier, crypto_hash_sha256_BYTES);

    status = kdf_generate_salt(salt);
    if (status != SM_OK) {
        return status;
    }

    master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    if (master_key == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (sodium_mlock(master_key, KDF_MASTER_KEY_BYTES) != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    master_key_locked = 1;

    status = vault_copy_password(master_password, &password_copy, &password_copy_len);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = kdf_derive_master_key(password_copy, salt, master_key);
    vault_free_password(&password_copy, password_copy_len);
    if (status != SM_OK) {
        goto cleanup;
    }

    if (crypto_hash_sha256(verifier, master_key, KDF_MASTER_KEY_BYTES) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }

    subkeys = vault_alloc_subkeys();
    if (subkeys == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    status = kdf_derive_subkeys(master_key, subkeys);
    if (status != SM_OK) {
        goto cleanup;
    }
    *subkeys_out = subkeys;
    subkeys = NULL;

cleanup:
    vault_free_subkeys(&subkeys);
    vault_free_password(&password_copy, password_copy_len);
    if (master_key != NULL) {
        sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
        if (master_key_locked) {
            (void)sodium_munlock(master_key, KDF_MASTER_KEY_BYTES);
        }
        sodium_free(master_key);
    }
    if (status != SM_OK) {
        sodium_memzero(salt, KDF_SALT_BYTES);
        sodium_memzero(verifier, crypto_hash_sha256_BYTES);
    }
    return status;
}

static int vault_find_secret_metadata(const char *name, vault_secret_metadata_t *metadata)
{
    static const char *const sql =
        "SELECT id, version, nonce_counter, name_nonce, encrypted_name, "
        "created_at, expires_at, "
        "rotation_interval_seconds "
        "FROM secrets AS s "
        "WHERE s.name = ?1 AND " VAULT_SQL_ACTIVE_ROW("s") " "
        "LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (name == NULL) || (metadata == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(metadata, sizeof(*metadata));
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        metadata->exists = 1;
        status = vault_copy_text_column(stmt,
                                        0,
                                        metadata->id,
                                        sizeof(metadata->id));
        if (status == SM_OK) {
            metadata->version = sqlite3_column_int(stmt, 1);
            metadata->nonce_counter = sqlite3_column_int64(stmt, 2);
            status = vault_copy_name_metadata(stmt, 3, 4, metadata);
        }
        if (status == SM_OK) {
            status = vault_copy_text_column(stmt,
                                            5,
                                            metadata->created_at,
                                            sizeof(metadata->created_at));
        }
        if ((status == SM_OK) &&
            (sqlite3_column_type(stmt, 6) != SQLITE_NULL)) {
            metadata->has_expiration = 1;
            status = vault_copy_text_column(stmt,
                                            6,
                                            metadata->expires_at,
                                            sizeof(metadata->expires_at));
        }
        if (status == SM_OK) {
            if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
                metadata->rotation_interval_seconds = sqlite3_column_int64(stmt, 7);
            }
            if (metadata->rotation_interval_seconds < 0) {
                status = SM_ERR_STORAGE;
            }
        }
        if ((status == SM_OK) &&
            ((metadata->version < 1) || (metadata->nonce_counter < 0))) {
            status = SM_ERR_STORAGE;
        }
    } else if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int vault_get_version_ttl(const char *name,
                                int version,
                                sqlite3_int64 *rotation_interval)
{
    static const char *const sql =
        "SELECT rotation_interval_seconds "
        "FROM secrets WHERE name = ? AND version = ? LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (name == NULL) || (version < 1) ||
        (rotation_interval == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *rotation_interval = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 2, version);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            *rotation_interval = sqlite3_column_int64(stmt, 0);
            if (*rotation_interval < 0) {
                status = SM_ERR_STORAGE;
            }
        }
    } else if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int vault_find_secret_history_bounds(const char *name,
                                            int *has_history,
                                            int *max_version,
                                            sqlite3_int64 *max_nonce_counter)
{
    static const char *const sql =
        "SELECT COUNT(*), MAX(version), MAX(nonce_counter) "
        "FROM secrets WHERE name = ?;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;
    int count = 0;

    if ((db == NULL) || (name == NULL) || (has_history == NULL) ||
        (max_version == NULL) || (max_nonce_counter == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *has_history = 0;
    *max_version = 0;
    *max_nonce_counter = 0;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            *has_history = 1;
            *max_version = sqlite3_column_int(stmt, 1);
            *max_nonce_counter = sqlite3_column_int64(stmt, 2);
            if ((*max_version < 1) || (*max_nonce_counter < 0)) {
                status = SM_ERR_STORAGE;
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

static int vault_bind_encrypted_secret(sqlite3_stmt *stmt,
                                       int first_index,
                                       const encrypted_secret_t *encrypted)
{
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((stmt == NULL) || (encrypted == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_text(stmt,
                           first_index,
                           encrypted->algorithm,
                           -1,
                           SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt,
                                 first_index + 1,
                                 encrypted->ciphertext,
                                 encrypted->ciphertext_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt,
                                 first_index + 2,
                                 encrypted->encrypted_dek,
                                 encrypted->encrypted_dek_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt,
                                 first_index + 3,
                                 encrypted->nonce,
                                 encrypted->nonce_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt,
                                 first_index + 4,
                                 encrypted->dek_nonce,
                                 encrypted->dek_nonce_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt,
                                 first_index + 5,
                                 encrypted->key_commitment,
                                 encrypted->key_commitment_len);
    }

    return status;
}

static int vault_insert_secret(const char *id,
                               const char *name,
                               const unsigned char *name_nonce,
                               size_t name_nonce_len,
                               const unsigned char *encrypted_name,
                               size_t encrypted_name_len,
                               int version,
                               sqlite3_int64 nonce_counter,
                               const char *created_at,
                               const char *updated_at,
                               const char *expires_at,
                               sqlite3_int64 rotation_interval_seconds,
                               const encrypted_secret_t *encrypted)
{
    static const char *const sql =
        "INSERT INTO secrets "
        "(id, name, name_nonce, encrypted_name, version, algorithm, ciphertext, "
        "encrypted_dek, nonce, dek_nonce, "
        "key_commitment, nonce_counter, created_at, updated_at, expires_at, "
        "rotation_interval_seconds, tags, is_archived) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0);";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt, 3, name_nonce, name_nonce_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_blob(stmt, 4, encrypted_name, encrypted_name_len);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 5, version);
    }
    if (rc == SQLITE_OK) {
        status = vault_bind_encrypted_secret(stmt, 6, encrypted);
        rc = status == SM_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(stmt, 12, nonce_counter);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 13, created_at, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 14, updated_at, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        if (expires_at != NULL) {
            rc = sqlite3_bind_text(stmt, 15, expires_at, -1, SQLITE_TRANSIENT);
        } else {
            rc = sqlite3_bind_null(stmt, 15);
        }
    }
    if (rc == SQLITE_OK) {
        if (rotation_interval_seconds > 0) {
            rc = sqlite3_bind_int64(stmt, 16, rotation_interval_seconds);
        } else {
            rc = sqlite3_bind_null(stmt, 16);
        }
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return status == SM_OK ? SM_ERR_STORAGE : status;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int vault_archive_active_secret(const char *name,
                                       const char *updated_at,
                                       int require_existing)
{
    static const char *const sql =
        "UPDATE secrets SET is_archived = 1, updated_at = ? "
        "WHERE name = ? AND is_archived = 0;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;
    int changes = 0;

    if ((db == NULL) || (name == NULL) || (updated_at == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_bind_text(stmt, 1, updated_at, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    changes = sqlite3_changes(db);
    if ((rc != SQLITE_DONE) || (changes < 0) || (changes > 1)) {
        status = SM_ERR_STORAGE;
    } else if (require_existing && (changes == 0)) {
        status = SM_ERR_NOT_FOUND;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static void vault_free_secret_row(vault_secret_row_t *row)
{
    if (row == NULL) {
        return;
    }

    crypto_engine_free_encrypted_secret(&row->encrypted);
    sodium_memzero(row, sizeof(*row));
}

static int vault_copy_secret_row(sqlite3_stmt *stmt, vault_secret_row_t *row)
{
    int status = SM_OK;

    if ((stmt == NULL) || (row == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(row, sizeof(*row));
    status = vault_copy_text_column(stmt, 0, row->id, sizeof(row->id));
    if (status == SM_OK) {
        row->version = sqlite3_column_int(stmt, 1);
        if (row->version < 1) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        status = vault_copy_text_column(stmt,
                                        2,
                                        row->encrypted.algorithm,
                                        sizeof(row->encrypted.algorithm));
    }
    if (status == SM_OK) {
        status = vault_column_blob_size(stmt, 3, &row->encrypted.ciphertext_len);
    }
    if (status == SM_OK) {
        status = vault_column_blob_size(stmt, 4, &row->encrypted.encrypted_dek_len);
    }
    if (status == SM_OK) {
        status = vault_column_blob_size(stmt, 5, &row->encrypted.nonce_len);
    }
    if (status == SM_OK) {
        status = vault_column_blob_size(stmt, 6, &row->encrypted.dek_nonce_len);
    }
    if ((status == SM_OK) &&
        ((row->encrypted.nonce_len > sizeof(row->encrypted.nonce)) ||
         (row->encrypted.dek_nonce_len > sizeof(row->encrypted.dek_nonce)))) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        row->encrypted.ciphertext = sodium_malloc(row->encrypted.ciphertext_len);
        row->encrypted.encrypted_dek =
            sodium_malloc(row->encrypted.encrypted_dek_len);
        if ((row->encrypted.ciphertext == NULL) ||
            (row->encrypted.encrypted_dek == NULL)) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        status = vault_copy_blob_column(stmt,
                                        3,
                                        row->encrypted.ciphertext,
                                        row->encrypted.ciphertext_len);
    }
    if (status == SM_OK) {
        status = vault_copy_blob_column(stmt,
                                        4,
                                        row->encrypted.encrypted_dek,
                                        row->encrypted.encrypted_dek_len);
    }
    if (status == SM_OK) {
        status = vault_copy_blob_column(stmt,
                                        5,
                                        row->encrypted.nonce,
                                        row->encrypted.nonce_len);
    }
    if (status == SM_OK) {
        status = vault_copy_blob_column(stmt,
                                        6,
                                        row->encrypted.dek_nonce,
                                        row->encrypted.dek_nonce_len);
    }
    if (status == SM_OK) {
        status = vault_column_blob_size(stmt,
                                        7,
                                        &row->encrypted.key_commitment_len);
    }
    if ((status == SM_OK) &&
        (row->encrypted.key_commitment_len !=
         sizeof(row->encrypted.key_commitment))) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        status = vault_copy_blob_column(stmt,
                                        7,
                                        row->encrypted.key_commitment,
                                        row->encrypted.key_commitment_len);
    }
    if (status != SM_OK) {
        vault_free_secret_row(row);
    }
    return status;
}

static int vault_load_secret_row(const char *name,
                                 int version,
                                 int active_only,
                                 vault_secret_row_t *row)
{
    static const char *const active_sql =
        "SELECT id, version, algorithm, ciphertext, encrypted_dek, nonce, dek_nonce, "
        "key_commitment "
        "FROM secrets AS s "
        "WHERE s.name = ?1 AND " VAULT_SQL_ACTIVE_ROW("s") " "
        "LIMIT 1;";
    static const char *const version_sql =
        "SELECT id, version, algorithm, ciphertext, encrypted_dek, nonce, dek_nonce, "
        "key_commitment "
        "FROM secrets WHERE name = ? AND version = ? LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;
    const char *sql = active_only ? active_sql : version_sql;

    if ((db == NULL) || (name == NULL) || (name[0] == '\0') ||
        (row == NULL) || (!active_only && (version < 1))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(row, sizeof(*row));
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    if ((rc == SQLITE_OK) && !active_only) {
        rc = sqlite3_bind_int(stmt, 2, version);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        status = vault_copy_secret_row(stmt, row);
    } else if (rc == SQLITE_DONE) {
        status = SM_ERR_NOT_FOUND;
    } else {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    if (status != SM_OK) {
        vault_free_secret_row(row);
    }
    return status;
}

static int vault_decrypt_secret_row(const vault_secret_row_t *row,
                                    const char *name,
                                    unsigned char *output,
                                    size_t output_len,
                                    size_t *written)
{
    char identity[CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN];
    size_t plaintext_len = output_len;
    int status = SM_OK;

    sodium_memzero(identity, sizeof(identity));
    if ((row == NULL) || (name == NULL) || (name[0] == '\0') ||
        (output == NULL) || (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = 0U;
    status = crypto_engine_build_row_identity(row->id,
                                         name,
                                         identity,
                                         sizeof(identity));
    if (status == SM_OK) {
        status = crypto_engine_decrypt(&row->encrypted,
                                       g_subkeys->kek_enc,
                                       identity,
                                       (uint32_t)row->version,
                                       output,
                                       &plaintext_len);
    }
    if (status == SM_OK) {
        *written = plaintext_len;
    }
    sodium_memzero(identity, sizeof(identity));
    return status;
}

static int vault_read_secret(const char *name,
                             int version,
                             int active_only,
                             unsigned char *output,
                             size_t output_len,
                             size_t *written,
                             int log_read)
{
    vault_secret_row_t row;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int status = SM_OK;

    sodium_memzero(&row, sizeof(row));
    sodium_memzero(stored_name, sizeof(stored_name));
    if ((name == NULL) || (name[0] == '\0') || (output == NULL) ||
        (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *written = 0U;

    status = vault_build_name_lookup(name, stored_name, sizeof(stored_name));
    if (status == SM_OK) {
        status = vault_load_secret_row(stored_name, version, active_only, &row);
    }
    if (status == SM_OK) {
        status = vault_decrypt_secret_row(&row,
                                          stored_name,
                                          output,
                                          output_len,
                                          written);
    }
    if ((status == SM_OK) && log_read) {
        status = vault_log_success("READ", stored_name, row.version);
        if (status != SM_OK) {
            sodium_memzero(output, *written);
            *written = 0U;
        }
    }

    vault_free_secret_row(&row);
    sodium_memzero(stored_name, sizeof(stored_name));
    return status;
}

static int vault_decrypt_secret_alloc(const char *name,
                                      int version,
                                      unsigned char **plaintext,
                                      size_t *plaintext_len,
                                      size_t *plaintext_capacity,
                                      char *algorithm,
                                      size_t algorithm_len)
{
    vault_secret_row_t row;
    unsigned char *buffer = NULL;
    size_t buffer_len = 0U;
    int written = 0;
    int status = SM_OK;

    sodium_memzero(&row, sizeof(row));
    if ((name == NULL) || (name[0] == '\0') || (version < 1) ||
        (plaintext == NULL) || (plaintext_len == NULL) ||
        (plaintext_capacity == NULL) ||
        ((algorithm != NULL) && (algorithm_len == 0U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *plaintext = NULL;
    *plaintext_len = 0U;
    *plaintext_capacity = 0U;

    status = vault_load_secret_row(name, version, 0, &row);
    if (status != SM_OK) {
        return status;
    }

    buffer_len = row.encrypted.ciphertext_len;
    buffer = sodium_malloc(buffer_len);
    if (buffer == NULL) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        sodium_memzero(buffer, buffer_len);
        status = vault_decrypt_secret_row(&row, name, buffer, buffer_len, plaintext_len);
    }
    if ((status == SM_OK) && (algorithm != NULL)) {
        written = snprintf(algorithm,
                           algorithm_len,
                           "%s",
                           row.encrypted.algorithm);
        if ((written < 0) || ((size_t)written >= algorithm_len)) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        *plaintext = buffer;
        *plaintext_capacity = buffer_len;
        buffer = NULL;
    }

    if (buffer != NULL) {
        sodium_memzero(buffer, buffer_len);
        sodium_free(buffer);
    }
    vault_free_secret_row(&row);
    return status;
}

static int vault_expiry_is_due(const char *expires_at, const char *now)
{
    if ((expires_at == NULL) || (now == NULL) ||
        (expires_at[0] == '\0') || (now[0] == '\0')) {
        return 0;
    }

    return strcmp(expires_at, now) <= 0;
}

static int vault_find_next_expired_secret(const char *now, char **name)
{
    static const char *const sql =
        "SELECT name FROM secrets AS s "
        "WHERE " VAULT_SQL_ACTIVE_ROW("s") " "
        "AND s.expires_at IS NOT NULL AND s.expires_at <= ? "
        "ORDER BY s.expires_at ASC, s.name ASC LIMIT 1;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char *name_copy = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;
    int name_bytes = 0;

    if ((db == NULL) || (now == NULL) || (name == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *name = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);

        name_bytes = sqlite3_column_bytes(stmt, 0);
        if ((text == NULL) || (name_bytes <= 0)) {
            status = SM_ERR_STORAGE;
        } else {
            name_copy = malloc((size_t)name_bytes + 1U);
            if (name_copy == NULL) {
                status = SM_ERR_STORAGE;
            } else {
                memcpy(name_copy, text, (size_t)name_bytes);
                name_copy[name_bytes] = '\0';
                *name = name_copy;
                name_copy = NULL;
            }
        }
    } else if (rc != SQLITE_DONE) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    free(name_copy);
    return status;
}

static int vault_rotate_expired_secret(const char *name)
{
    vault_secret_metadata_t metadata;
    encrypted_secret_t encrypted;
    char id[UTILS_UUID_V4_BUFFER_LEN];
    char identity[CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN];
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    char algorithm[CRYPTO_ENGINE_ALGORITHM_MAX];
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0U;
    size_t plaintext_capacity = 0U;
    int has_history = 0;
    int max_version = 0;
    int new_version = 0;
    sqlite3_int64 max_nonce_counter = 0;
    sqlite3_int64 new_nonce_counter = 0;
    int status = SM_OK;

    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(&encrypted, sizeof(encrypted));
    sodium_memzero(id, sizeof(id));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(algorithm, sizeof(algorithm));

    if ((name == NULL) || (name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_find_secret_metadata(name, &metadata);
    if (status != SM_OK) {
        goto cleanup;
    }
    if (!metadata.exists) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (!metadata.has_expiration ||
        !vault_expiry_is_due(metadata.expires_at, now)) {
        goto cleanup;
    }

    status = vault_decrypt_secret_alloc(name,
                                        metadata.version,
                                        &plaintext,
                                        &plaintext_len,
                                        &plaintext_capacity,
                                        algorithm,
                                        sizeof(algorithm));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_find_secret_history_bounds(name,
                                              &has_history,
                                              &max_version,
                                              &max_nonce_counter);
    if (status != SM_OK) {
        goto cleanup;
    }
    if (!has_history ||
        (max_version == INT_MAX) ||
        (max_nonce_counter == INT64_MAX)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    new_version = max_version + 1;
    new_nonce_counter = max_nonce_counter + 1;
    status = utils_generate_uuid_v4(id, sizeof(id));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = crypto_engine_build_row_identity(id, name, identity, sizeof(identity));
    if (status != SM_OK) {
        goto cleanup;
    }
    if (metadata.rotation_interval_seconds > 0) {
        status = utils_now_plus_seconds_iso8601(
            (uint64_t)metadata.rotation_interval_seconds,
            expires_at,
            sizeof(expires_at));
        if (status != SM_OK) {
            goto cleanup;
        }
    }

    status = crypto_engine_encrypt_with_algorithm(plaintext,
                                                  plaintext_len,
                                                  g_subkeys->kek_enc,
                                                  identity,
                                                  (uint32_t)new_version,
                                                  (uint64_t)new_nonce_counter,
                                                  algorithm,
                                                  &encrypted);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = storage_begin_transaction();
    if (status == SM_OK) {
        status = vault_archive_active_secret(name, now, 1);
    }
    if (status == SM_OK) {
        status = vault_insert_secret(id,
                                     name,
                                     metadata.name_nonce,
                                     metadata.name_nonce_len,
                                     metadata.encrypted_name,
                                     metadata.encrypted_name_len,
                                     new_version,
                                     new_nonce_counter,
                                     now,
                                     now,
                                     metadata.rotation_interval_seconds > 0
                                         ? expires_at
                                         : NULL,
                                     metadata.rotation_interval_seconds,
                                     &encrypted);
    }
    if (status == SM_OK) {
        status = vault_log_success("ROTATE_DEK", name, new_version);
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }

cleanup:
    crypto_engine_free_encrypted_secret(&encrypted);
    if (plaintext != NULL) {
        sodium_memzero(plaintext, plaintext_capacity);
        sodium_free(plaintext);
    }
    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(id, sizeof(id));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(algorithm, sizeof(algorithm));
    plaintext_len = 0U;
    plaintext_capacity = 0U;
    return status;
}

int vault_init(const char *db_path)
{
    vault_lock_state();
    return storage_init(db_path);
}

int vault_open(const char *db_path)
{
    vault_lock_state();
    return storage_open(db_path);
}

static int vault_unlock_internal(const char *master_password,
                                 int allow_metadata_initialize)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char verifier[crypto_hash_sha256_BYTES];
    unsigned char computed_verifier[crypto_hash_sha256_BYTES];
    unsigned char *master_key = NULL;
    kdf_subkeys_t *subkeys = NULL;
    char *password_copy = NULL;
    size_t password_copy_len = 0U;
    int metadata_exists = 0;
    int master_key_locked = 0;
    int status = SM_OK;

    if ((master_password == NULL) || (master_password[0] == '\0') ||
        (storage_get_db() == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    vault_lock_state();
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(verifier, sizeof(verifier));
    sodium_memzero(computed_verifier, sizeof(computed_verifier));

    status = vault_load_auth_metadata(salt, verifier, &metadata_exists);
    if ((status == SM_OK) && !metadata_exists && !allow_metadata_initialize) {
        status = SM_ERR_NOT_FOUND;
    }
    if ((status == SM_OK) && !metadata_exists) {
        status = kdf_generate_salt(salt);
    }
    if (status != SM_OK) {
        goto cleanup;
    }

    master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    if (master_key == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (sodium_mlock(master_key, KDF_MASTER_KEY_BYTES) != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    master_key_locked = 1;

    status = vault_copy_password(master_password, &password_copy, &password_copy_len);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = kdf_derive_master_key(password_copy, salt, master_key);
    vault_free_password(&password_copy, password_copy_len);
    if (status != SM_OK) {
        goto cleanup;
    }

    if (crypto_hash_sha256(computed_verifier,
                           master_key,
                           KDF_MASTER_KEY_BYTES) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (metadata_exists &&
        (sodium_memcmp(computed_verifier,
                       verifier,
                       sizeof(computed_verifier)) != 0)) {
        status = vault_log_auth_failure_untrusted();
        if (status == SM_OK) {
            status = SM_ERR_AUTH;
        }
        goto cleanup;
    }

    subkeys = vault_alloc_subkeys();
    if (subkeys == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    status = kdf_derive_subkeys(master_key, subkeys);
    if (master_key_locked) {
        (void)sodium_munlock(master_key, KDF_MASTER_KEY_BYTES);
        master_key_locked = 0;
    }
    sodium_free(master_key);
    master_key = NULL;
    if (status != SM_OK) {
        goto cleanup;
    }

    if (!metadata_exists) {
        status = vault_store_auth_metadata(salt, computed_verifier, subkeys);
        if (status != SM_OK) {
            vault_lock_state();
            goto cleanup;
        }
    } else {
        status = vault_load_meta_key(subkeys);
        if (status != SM_OK) {
            vault_lock_state();
            goto cleanup;
        }
    }
    g_subkeys = subkeys;
    subkeys = NULL;
    g_unlocked = 1;

cleanup:
    vault_free_subkeys(&subkeys);
    vault_free_password(&password_copy, password_copy_len);
    if (master_key != NULL) {
        sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
        if (master_key_locked) {
            (void)sodium_munlock(master_key, KDF_MASTER_KEY_BYTES);
        }
        sodium_free(master_key);
    }
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(verifier, sizeof(verifier));
    sodium_memzero(computed_verifier, sizeof(computed_verifier));
    if (status != SM_OK) {
        vault_lock_state();
    }
    return status;
}

int vault_unlock(const char *master_password)
{
    return vault_unlock_internal(master_password, 1);
}

int vault_unlock_existing(const char *master_password)
{
    return vault_unlock_internal(master_password, 0);
}

int vault_put(const char *name,
              const unsigned char *secret,
              size_t secret_len)
{
    return vault_put_with_options(name, secret, secret_len, NULL, 0U);
}

int vault_put_with_algorithm(const char *name,
                             const unsigned char *secret,
                             size_t secret_len,
                             const char *algorithm)
{
    return vault_put_with_options(name, secret, secret_len, algorithm, 0U);
}

/* Secret names are echoed to the terminal (list, status-report, and the
   put/delete/rollback confirmations), so reject C0 control bytes and DEL to
   stop a stored name from injecting terminal escape sequences. Printable
   ASCII and UTF-8 (bytes >= 0x80) are allowed. */
static int vault_name_is_clean(const char *name)
{
    size_t i = 0U;

    if ((name == NULL) || (name[0] == '\0') ||
        (strlen(name) > VAULT_SECRET_NAME_MAX)) {
        return 0;
    }
    for (i = 0U; name[i] != '\0'; i++) {
        unsigned char c = (unsigned char)name[i];

        if ((c < 0x20U) || (c == 0x7FU)) {
            return 0;
        }
    }
    return 1;
}

int vault_put_with_options(const char *name,
                           const unsigned char *secret,
                           size_t secret_len,
                           const char *algorithm,
                           uint64_t ttl_seconds)
{
    vault_secret_metadata_t metadata;
    encrypted_secret_t encrypted;
    char id[UTILS_UUID_V4_BUFFER_LEN];
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    char identity[CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN];
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    unsigned char name_nonce[VAULT_NAME_NONCE_BYTES];
    unsigned char encrypted_name[VAULT_ENCRYPTED_NAME_MAX];
    size_t encrypted_name_len = 0U;
    const unsigned char empty_secret = 0U;
    const unsigned char *plaintext = secret;
    int version = 1;
    sqlite3_int64 nonce_counter = 1;
    int has_history = 0;
    int max_version = 0;
    sqlite3_int64 max_nonce_counter = 0;
    const char *audit_action = "CREATE";
    int status = SM_OK;

    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(&encrypted, sizeof(encrypted));
    sodium_memzero(id, sizeof(id));
    sodium_memzero(stored_name, sizeof(stored_name));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(name_nonce, sizeof(name_nonce));
    sodium_memzero(encrypted_name, sizeof(encrypted_name));

    status = vault_require_unlocked();
    if (status != SM_OK) {
        goto cleanup;
    }
    if (!vault_name_is_clean(name) ||
        ((secret == NULL) && (secret_len > 0U))) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }
    if (plaintext == NULL) {
        plaintext = &empty_secret;
    }

    status = vault_build_name_lookup(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_encrypt_display_name(name,
                                        stored_name,
                                        name_nonce,
                                        sizeof(name_nonce),
                                        encrypted_name,
                                        sizeof(encrypted_name),
                                        &encrypted_name_len);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_find_secret_metadata(stored_name, &metadata);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_find_secret_history_bounds(stored_name,
                                              &has_history,
                                              &max_version,
                                              &max_nonce_counter);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        goto cleanup;
    }
    if (ttl_seconds > 0U) {
        if (ttl_seconds > (uint64_t)INT64_MAX) {
            status = SM_ERR_INVALID_ARGUMENT;
            goto cleanup;
        }
        status = utils_now_plus_seconds_iso8601(ttl_seconds,
                                                expires_at,
                                                sizeof(expires_at));
        if (status != SM_OK) {
            goto cleanup;
        }
    }

    if (has_history) {
        if ((max_version == INT_MAX) || (max_nonce_counter == INT64_MAX)) {
            status = SM_ERR_STORAGE;
            goto cleanup;
        }
        version = max_version + 1;
        nonce_counter = max_nonce_counter + 1;
    }
    if (metadata.exists) {
        audit_action = "UPDATE";
    }
    status = utils_generate_uuid_v4(id, sizeof(id));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = crypto_engine_build_row_identity(id,
                                              stored_name,
                                              identity,
                                              sizeof(identity));
    if (status != SM_OK) {
        goto cleanup;
    }

    status = crypto_engine_encrypt_with_algorithm(plaintext,
                                                  secret_len,
                                                  g_subkeys->kek_enc,
                                                  identity,
                                                  (uint32_t)version,
                                                  (uint64_t)nonce_counter,
                                                  algorithm,
                                                  &encrypted);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = storage_begin_transaction();
    if (status == SM_OK) {
        if (metadata.exists) {
            status = vault_archive_active_secret(stored_name, now, 1);
        }
        if (status == SM_OK) {
            status = vault_insert_secret(id,
                                         stored_name,
                                         name_nonce,
                                         sizeof(name_nonce),
                                         encrypted_name,
                                         encrypted_name_len,
                                         version,
                                         nonce_counter,
                                         now,
                                         now,
                                         ttl_seconds > 0U ? expires_at : NULL,
                                         (sqlite3_int64)ttl_seconds,
                                         &encrypted);
        }
    }
    if (status == SM_OK) {
        status = vault_log_success(audit_action, stored_name, version);
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }

cleanup:
    crypto_engine_free_encrypted_secret(&encrypted);
    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(id, sizeof(id));
    sodium_memzero(stored_name, sizeof(stored_name));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(expires_at, sizeof(expires_at));
    sodium_memzero(name_nonce, sizeof(name_nonce));
    sodium_memzero(encrypted_name, sizeof(encrypted_name));
    encrypted_name_len = 0U;
    return status;
}

int vault_get(const char *name,
              unsigned char *output,
              size_t output_len,
              size_t *written)
{
    int status = SM_OK;

    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    return vault_read_secret(name, 0, 1, output, output_len, written, 1);
}

int vault_get_version(const char *name,
                      int version,
                      unsigned char *output,
                      size_t output_len,
                      size_t *written)
{
    int status = SM_OK;

    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if (version < 1) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return vault_read_secret(name, version, 0, output, output_len, written, 1);
}

int vault_delete(const char *name)
{
    vault_secret_metadata_t metadata;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    int status = SM_OK;

    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(stored_name, sizeof(stored_name));
    sodium_memzero(now, sizeof(now));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((storage_get_db() == NULL) || (name == NULL) || (name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_build_name_lookup(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(&metadata, sizeof(metadata));
        sodium_memzero(stored_name, sizeof(stored_name));
        return status;
    }
    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        sodium_memzero(stored_name, sizeof(stored_name));
        return status;
    }
    status = vault_find_secret_metadata(stored_name, &metadata);
    if (status != SM_OK) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(&metadata, sizeof(metadata));
        sodium_memzero(stored_name, sizeof(stored_name));
        return status;
    }
    if (!metadata.exists) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(&metadata, sizeof(metadata));
        sodium_memzero(stored_name, sizeof(stored_name));
        return SM_ERR_NOT_FOUND;
    }

    status = storage_begin_transaction();
    if (status != SM_OK) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(&metadata, sizeof(metadata));
        sodium_memzero(stored_name, sizeof(stored_name));
        return status;
    }

    status = vault_archive_active_secret(stored_name, now, 1);
    if (status == SM_OK) {
        status = vault_log_success("DELETE", stored_name, metadata.version);
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }

    sodium_memzero(now, sizeof(now));
    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(stored_name, sizeof(stored_name));
    return status;
}

int vault_list_secrets(int include_archived,
                       vault_list_callback_t callback,
                       void *user_data,
                       size_t *matched_count)
{
    static const char *const sql =
        "SELECT name, name_nonce, encrypted_name, version, algorithm, created_at, "
        "updated_at, expires_at, "
        "rotation_interval_seconds, is_archived "
        "FROM secrets AS s "
        "WHERE (?1 != 0 OR (" VAULT_SQL_ACTIVE_ROW("s") ")) "
        "ORDER BY name ASC, version ASC;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    size_t count = 0U;
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(now, sizeof(now));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((db == NULL) || (callback == NULL) || (matched_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *matched_count = 0U;
    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        return status;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 1, include_archived ? 1 : 0);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        sodium_memzero(now, sizeof(now));
        return SM_ERR_STORAGE;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        vault_list_item_t item;
        const unsigned char *stored_name = sqlite3_column_text(stmt, 0);
        const unsigned char *name_nonce = sqlite3_column_blob(stmt, 1);
        const unsigned char *encrypted_name = sqlite3_column_blob(stmt, 2);
        const unsigned char *algorithm = sqlite3_column_text(stmt, 4);
        const unsigned char *created_at = sqlite3_column_text(stmt, 5);
        const unsigned char *updated_at = sqlite3_column_text(stmt, 6);
        const unsigned char *expires_at = sqlite3_column_text(stmt, 7);
        char display_name[VAULT_SECRET_NAME_MAX + 1U];
        sqlite3_int64 rotation_interval = 0;
        int stored_name_len = sqlite3_column_bytes(stmt, 0);
        int name_nonce_len = sqlite3_column_bytes(stmt, 1);
        int encrypted_name_len = sqlite3_column_bytes(stmt, 2);

        sodium_memzero(&item, sizeof(item));
        sodium_memzero(display_name, sizeof(display_name));
        if ((stored_name == NULL) || (stored_name_len <= 0) ||
            (name_nonce == NULL) || (encrypted_name == NULL) ||
            (algorithm == NULL) ||
            (created_at == NULL) || (updated_at == NULL)) {
            status = SM_ERR_STORAGE;
            break;
        }

        status = vault_decrypt_display_name((const char *)stored_name,
                                            name_nonce,
                                            (size_t)name_nonce_len,
                                            encrypted_name,
                                            (size_t)encrypted_name_len,
                                            display_name,
                                            sizeof(display_name));
        if (status != SM_OK) {
            break;
        }

        rotation_interval = sqlite3_column_type(stmt, 8) == SQLITE_NULL
                                ? 0
                                : sqlite3_column_int64(stmt, 8);
        if (rotation_interval < 0) {
            status = SM_ERR_STORAGE;
            sodium_memzero(display_name, sizeof(display_name));
            break;
        }

        item.name = display_name;
        item.version = sqlite3_column_int(stmt, 3);
        item.algorithm = (const char *)algorithm;
        item.created_at = (const char *)created_at;
        item.updated_at = (const char *)updated_at;
        item.expires_at = expires_at == NULL ? NULL : (const char *)expires_at;
        item.rotation_interval_seconds = (uint64_t)rotation_interval;
        item.is_archived = sqlite3_column_int(stmt, 9);
        item.is_expired = (!item.is_archived && (item.expires_at != NULL))
                              ? vault_expiry_is_due(item.expires_at, now)
                              : 0;

        if ((item.version < 1) ||
            ((item.is_archived != 0) && (item.is_archived != 1))) {
            status = SM_ERR_STORAGE;
            sodium_memzero(display_name, sizeof(display_name));
            break;
        }

        status = callback(&item, user_data);
        sodium_memzero(display_name, sizeof(display_name));
        if (status != SM_OK) {
            break;
        }
        count++;
    }
    if ((rc != SQLITE_DONE) && (status == SM_OK)) {
        status = SM_ERR_STORAGE;
    }

    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        *matched_count = count;
    }
    sodium_memzero(now, sizeof(now));
    return status;
}

int vault_security_report(vault_security_report_t *report)
{
    static const char *const report_sql =
        "WITH classified AS ("
        "SELECT s.*, CASE WHEN " VAULT_SQL_ACTIVE_ROW("s") " "
        "THEN 1 ELSE 0 END AS is_current_active "
        "FROM secrets AS s"
        ") "
        "SELECT "
        "COUNT(DISTINCT name), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 0 THEN 1 ELSE 0 END), 0), "
        "COUNT(*), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND "
        "rotation_interval_seconds IS NOT NULL AND "
        "rotation_interval_seconds > 0 THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND expires_at IS NOT NULL "
        "AND expires_at <= ?1 THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND expires_at IS NOT NULL "
        "AND expires_at > ?1 AND expires_at <= ?2 THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND algorithm = 'AES-256-GCM' "
        "THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND "
        "algorithm = 'XChaCha20-Poly1305' THEN 1 ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN is_current_active = 1 AND "
        "algorithm = 'AEGIS-256' THEN 1 ELSE 0 END), 0) "
        "FROM classified;";
    static const char *const deleted_sql =
        "SELECT COUNT(*) FROM ("
        "SELECT s.name FROM secrets AS s GROUP BY s.name "
        "HAVING COALESCE(SUM(CASE WHEN " VAULT_SQL_ACTIVE_ROW("s") " "
        "THEN 1 ELSE 0 END), 0) = 0"
        ");";
    static const char *const audit_sql = "SELECT COUNT(*) FROM audit_log;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char soon[UTILS_ISO8601_UTC_BUFFER_LEN];
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(now, sizeof(now));
    sodium_memzero(soon, sizeof(soon));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((db == NULL) || (report == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(report, sizeof(*report));
    status = utils_now_iso8601(now, sizeof(now));
    if (status == SM_OK) {
        status = utils_now_plus_seconds_iso8601(7ULL * 24ULL * 60ULL * 60ULL,
                                                soon,
                                                sizeof(soon));
    }
    if (status != SM_OK) {
        goto cleanup;
    }

    rc = sqlite3_prepare_v2(db, report_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, soon, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        report->distinct_names = (size_t)sqlite3_column_int64(stmt, 0);
        report->active_secrets = (size_t)sqlite3_column_int64(stmt, 1);
        report->archived_versions = (size_t)sqlite3_column_int64(stmt, 2);
        report->total_versions = (size_t)sqlite3_column_int64(stmt, 3);
        report->ttl_active = (size_t)sqlite3_column_int64(stmt, 4);
        report->expired_active = (size_t)sqlite3_column_int64(stmt, 5);
        report->expiring_7d = (size_t)sqlite3_column_int64(stmt, 6);
        report->active_aes256gcm = (size_t)sqlite3_column_int64(stmt, 7);
        report->active_xchacha20poly1305 = (size_t)sqlite3_column_int64(stmt, 8);
        report->active_aegis256 = (size_t)sqlite3_column_int64(stmt, 9);
    } else {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    stmt = NULL;
    if (status != SM_OK) {
        goto cleanup;
    }

    rc = sqlite3_prepare_v2(db, deleted_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        report->deleted_names = (size_t)sqlite3_column_int64(stmt, 0);
    } else {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    stmt = NULL;
    if (status != SM_OK) {
        goto cleanup;
    }

    rc = sqlite3_prepare_v2(db, audit_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        report->audit_entries = (size_t)sqlite3_column_int64(stmt, 0);
    } else {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    stmt = NULL;
    if (status != SM_OK) {
        goto cleanup;
    }

    status = audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
    if (status == SM_OK) {
        status = audit_compute_merkle_root(report->audit_root,
                                           sizeof(report->audit_root),
                                           &report->audit_leaf_count);
    }

cleanup:
    if (stmt != NULL) {
        if (sqlite3_finalize(stmt) != SQLITE_OK) {
            status = SM_ERR_STORAGE;
        }
    }
    sodium_memzero(now, sizeof(now));
    sodium_memzero(soon, sizeof(soon));
    if (status != SM_OK) {
        sodium_memzero(report, sizeof(*report));
    }
    return status;
}

int vault_backup_keygen(const char *public_key_path,
                        const char *private_key_path,
                        const char *private_key_passphrase)
{
    return backup_pqc_keygen(public_key_path,
                             private_key_path,
                             private_key_passphrase);
}

int vault_backup_export(const char *recipient_public_key_path,
                        const char *capsule_path)
{
    unsigned char audit_root[AUDIT_MERKLE_ROOT_BYTES];
    size_t leaf_count = 0U;
    int status = vault_require_unlocked();

    sodium_memzero(audit_root, sizeof(audit_root));
    if (status != SM_OK) {
        return status;
    }
    if ((recipient_public_key_path == NULL) ||
        (recipient_public_key_path[0] == '\0') ||
        (capsule_path == NULL) ||
        (capsule_path[0] == '\0') ||
        (storage_get_db() == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_audit_merkle_root(audit_root, sizeof(audit_root), &leaf_count);
    if (status == SM_OK) {
        status = backup_pqc_export(storage_get_db(),
                                   recipient_public_key_path,
                                   capsule_path,
                                   audit_root,
                                   sizeof(audit_root));
    }

    (void)leaf_count;
    sodium_memzero(audit_root, sizeof(audit_root));
    return status;
}

int vault_backup_import(const char *private_key_path,
                        const char *private_key_passphrase,
                        const char *capsule_path,
                        const char *output_db_path)
{
    return backup_pqc_import(private_key_path,
                             private_key_passphrase,
                             capsule_path,
                             output_db_path);
}

int vault_audit_signing_keygen(const char *public_key_path,
                               const char *private_key_path,
                               const char *private_key_passphrase)
{
    return backup_mldsa_keygen(public_key_path,
                               private_key_path,
                               private_key_passphrase);
}

int vault_audit_sign_root(const char *private_key_path,
                          const char *private_key_passphrase,
                          unsigned char *root,
                          size_t root_len,
                          size_t *leaf_count,
                          unsigned char *signature,
                          size_t signature_len,
                          size_t *signature_written)
{
    unsigned char message[AUDIT_MERKLE_ROOT_BYTES + 8U];
    int status = SM_OK;

    sodium_memzero(message, sizeof(message));
    if ((root == NULL) || (root_len != AUDIT_MERKLE_ROOT_BYTES) ||
        (leaf_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_audit_merkle_root(root, root_len, leaf_count);
    if (status == SM_OK) {
        memcpy(message, root, AUDIT_MERKLE_ROOT_BYTES);
        utils_write_u64_le(message + AUDIT_MERKLE_ROOT_BYTES,
                           (uint64_t)*leaf_count);
        status = backup_mldsa_sign(private_key_path,
                                   private_key_passphrase,
                                   message,
                                   sizeof(message),
                                   signature,
                                   signature_len,
                                   signature_written);
    }
    sodium_memzero(message, sizeof(message));
    return status;
}

int vault_rollback(const char *name, int version)
{
    encrypted_secret_t encrypted;
    char id[UTILS_UUID_V4_BUFFER_LEN];
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    char identity[CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN];
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char algorithm[CRYPTO_ENGINE_ALGORITHM_MAX];
    char new_expires_at[UTILS_ISO8601_UTC_BUFFER_LEN];
    unsigned char name_nonce[VAULT_NAME_NONCE_BYTES];
    unsigned char encrypted_name[VAULT_ENCRYPTED_NAME_MAX];
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0U;
    size_t plaintext_capacity = 0U;
    size_t encrypted_name_len = 0U;
    int has_history = 0;
    int max_version = 0;
    int new_version = 0;
    sqlite3_int64 max_nonce_counter = 0;
    sqlite3_int64 new_nonce_counter = 0;
    sqlite3_int64 src_ttl = 0;
    int status = SM_OK;

    sodium_memzero(&encrypted, sizeof(encrypted));
    sodium_memzero(id, sizeof(id));
    sodium_memzero(stored_name, sizeof(stored_name));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(algorithm, sizeof(algorithm));
    sodium_memzero(new_expires_at, sizeof(new_expires_at));
    sodium_memzero(name_nonce, sizeof(name_nonce));
    sodium_memzero(encrypted_name, sizeof(encrypted_name));

    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((name == NULL) || (name[0] == '\0') || (version < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_build_name_lookup(name, stored_name, sizeof(stored_name));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_encrypt_display_name(name,
                                        stored_name,
                                        name_nonce,
                                        sizeof(name_nonce),
                                        encrypted_name,
                                        sizeof(encrypted_name),
                                        &encrypted_name_len);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = vault_decrypt_secret_alloc(stored_name,
                                        version,
                                        &plaintext,
                                        &plaintext_len,
                                        &plaintext_capacity,
                                        algorithm,
                                        sizeof(algorithm));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_get_version_ttl(stored_name, version, &src_ttl);
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_find_secret_history_bounds(stored_name,
                                              &has_history,
                                              &max_version,
                                              &max_nonce_counter);
    if (status != SM_OK) {
        goto cleanup;
    }
    if (!has_history ||
        (max_version == INT_MAX) ||
        (max_nonce_counter == INT64_MAX)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    new_version = max_version + 1;
    new_nonce_counter = max_nonce_counter + 1;
    status = utils_now_iso8601(now, sizeof(now));
    if (status != SM_OK) {
        goto cleanup;
    }
    if (src_ttl > 0) {
        status = utils_now_plus_seconds_iso8601((uint64_t)src_ttl,
                                                new_expires_at,
                                                sizeof(new_expires_at));
        if (status != SM_OK) {
            goto cleanup;
        }
    }
    status = utils_generate_uuid_v4(id, sizeof(id));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = crypto_engine_build_row_identity(id,
                                              stored_name,
                                              identity,
                                              sizeof(identity));
    if (status != SM_OK) {
        goto cleanup;
    }

    status = crypto_engine_encrypt_with_algorithm(plaintext,
                                                  plaintext_len,
                                                  g_subkeys->kek_enc,
                                                  identity,
                                                  (uint32_t)new_version,
                                                  (uint64_t)new_nonce_counter,
                                                  algorithm,
                                                  &encrypted);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = storage_begin_transaction();
    if (status == SM_OK) {
        status = vault_archive_active_secret(stored_name, now, 0);
    }
    if (status == SM_OK) {
        status = vault_insert_secret(id,
                                     stored_name,
                                     name_nonce,
                                     sizeof(name_nonce),
                                     encrypted_name,
                                     encrypted_name_len,
                                     new_version,
                                     new_nonce_counter,
                                     now,
                                     now,
                                     src_ttl > 0 ? new_expires_at : NULL,
                                     src_ttl,
                                     &encrypted);
    }
    if (status == SM_OK) {
        status = vault_log_success("ROLLBACK", stored_name, new_version);
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }

cleanup:
    crypto_engine_free_encrypted_secret(&encrypted);
    if (plaintext != NULL) {
        sodium_memzero(plaintext, plaintext_capacity);
        sodium_free(plaintext);
    }
    sodium_memzero(id, sizeof(id));
    sodium_memzero(stored_name, sizeof(stored_name));
    sodium_memzero(identity, sizeof(identity));
    sodium_memzero(now, sizeof(now));
    sodium_memzero(algorithm, sizeof(algorithm));
    sodium_memzero(new_expires_at, sizeof(new_expires_at));
    sodium_memzero(name_nonce, sizeof(name_nonce));
    sodium_memzero(encrypted_name, sizeof(encrypted_name));
    plaintext_len = 0U;
    plaintext_capacity = 0U;
    encrypted_name_len = 0U;
    return status;
}

int vault_get_active_version(const char *name, int *version)
{
    vault_secret_metadata_t metadata;
    char stored_name[VAULT_NAME_LOOKUP_HEX_LEN];
    int status = SM_OK;

    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(stored_name, sizeof(stored_name));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((name == NULL) || (name[0] == '\0') || (version == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *version = 0;
    status = vault_build_name_lookup(name, stored_name, sizeof(stored_name));
    if (status == SM_OK) {
        status = vault_find_secret_metadata(stored_name, &metadata);
    }
    if (status == SM_OK) {
        if (!metadata.exists) {
            status = SM_ERR_NOT_FOUND;
        } else {
            *version = metadata.version;
        }
    }

    sodium_memzero(&metadata, sizeof(metadata));
    sodium_memzero(stored_name, sizeof(stored_name));
    return status;
}

int vault_audit_verify(void)
{
    int status = vault_require_unlocked();

    if (status != SM_OK) {
        return status;
    }

    return audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
}

int vault_audit_merkle_root(unsigned char *root,
                            size_t root_len,
                            size_t *leaf_count)
{
    int status = vault_require_unlocked();

    if (status != SM_OK) {
        return status;
    }
    if ((root == NULL) || (leaf_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
    if (status == SM_OK) {
        status = audit_compute_merkle_root(root, root_len, leaf_count);
    }
    return status;
}

int vault_audit_merkle_proof(int entry_id,
                             unsigned char *entry_hash,
                             size_t entry_hash_len,
                             unsigned char *root,
                             size_t root_len,
                             unsigned char *proof,
                             size_t proof_capacity,
                             size_t *proof_len,
                             size_t *leaf_index,
                             size_t *leaf_count)
{
    size_t root_leaf_count = 0U;
    int status = vault_require_unlocked();

    if (status != SM_OK) {
        return status;
    }
    if ((entry_id < 1) || (entry_hash == NULL) || (root == NULL) ||
        (proof == NULL) || (proof_len == NULL) || (leaf_index == NULL) ||
        (leaf_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
    if (status == SM_OK) {
        status = audit_get_entry_hash(entry_id, entry_hash, entry_hash_len);
    }
    if (status == SM_OK) {
        status = audit_compute_merkle_root(root, root_len, &root_leaf_count);
    }
    if (status == SM_OK) {
        status = audit_build_merkle_proof(entry_id,
                                          proof,
                                          proof_capacity,
                                          proof_len,
                                          leaf_index,
                                          leaf_count);
    }
    if ((status == SM_OK) && (root_leaf_count != *leaf_count)) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

int vault_audit_verify_merkle_proof(int entry_id,
                                    const unsigned char *root,
                                    size_t root_len,
                                    const unsigned char *proof,
                                    size_t proof_len,
                                    size_t leaf_index,
                                    size_t leaf_count)
{
    unsigned char entry_hash[AUDIT_MERKLE_ROOT_BYTES];
    int status = vault_require_unlocked();

    sodium_memzero(entry_hash, sizeof(entry_hash));
    if (status != SM_OK) {
        return status;
    }
    if ((entry_id < 1) || (root == NULL) || ((proof == NULL) && (proof_len > 0U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
    if (status == SM_OK) {
        status = audit_get_entry_hash(entry_id, entry_hash, sizeof(entry_hash));
    }
    if (status == SM_OK) {
        status = audit_verify_merkle_proof(entry_hash,
                                           sizeof(entry_hash),
                                           leaf_index,
                                           leaf_count,
                                           proof,
                                           proof_len,
                                           root,
                                           root_len);
    }

    sodium_memzero(entry_hash, sizeof(entry_hash));
    return status;
}

int vault_rotate_kek(const char *new_master_password)
{
    unsigned char new_salt[KDF_SALT_BYTES];
    unsigned char new_verifier[crypto_hash_sha256_BYTES];
    kdf_subkeys_t *new_subkeys = NULL;
    int status = SM_OK;

    sodium_memzero(new_salt, sizeof(new_salt));
    sodium_memzero(new_verifier, sizeof(new_verifier));

    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((new_master_password == NULL) || (new_master_password[0] == '\0') ||
        (storage_get_db() == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = vault_derive_credentials(new_master_password,
                                      new_salt,
                                      new_verifier,
                                      &new_subkeys);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = storage_begin_transaction();
    if (status != SM_OK) {
        goto cleanup;
    }

    status = audit_verify_chain(g_subkeys->kek_audit, sizeof(g_subkeys->kek_audit));
    if (status == SM_OK) {
        status = key_manager_rotate_kek(storage_get_db(),
                                        g_subkeys->kek_enc,
                                        sizeof(g_subkeys->kek_enc),
                                        new_subkeys->kek_enc,
                                        sizeof(new_subkeys->kek_enc));
    }
    if (status == SM_OK) {
        status = vault_put_wrapped_meta_key(g_subkeys->kek_meta,
                                            new_subkeys->kek_enc);
    }
    if (status == SM_OK) {
        status = vault_put_metadata_blob(VAULT_METADATA_SALT,
                                         new_salt,
                                         sizeof(new_salt));
    }
    if (status == SM_OK) {
        status = vault_put_metadata_blob(VAULT_METADATA_VERIFIER,
                                         new_verifier,
                                         sizeof(new_verifier));
    }
    if (status == SM_OK) {
        status = audit_resign_chain(new_subkeys->kek_audit,
                                    sizeof(new_subkeys->kek_audit));
    }
    if (status == SM_OK) {
        status = audit_log_event("user:default",
                                 "ROTATE_KEK",
                                 "vault",
                                 0,
                                 "SUCCESS",
                                 new_subkeys->kek_audit,
                                 sizeof(new_subkeys->kek_audit));
    }

    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }
    if (status == SM_OK) {
        memcpy(new_subkeys->kek_meta,
               g_subkeys->kek_meta,
               sizeof(new_subkeys->kek_meta));
        vault_free_subkeys(&g_subkeys);
        g_subkeys = new_subkeys;
        new_subkeys = NULL;
        g_unlocked = 1;
    }

cleanup:
    vault_free_subkeys(&new_subkeys);
    sodium_memzero(new_salt, sizeof(new_salt));
    sodium_memzero(new_verifier, sizeof(new_verifier));
    return status;
}

int vault_check_expiry(uint64_t within_seconds,
                       vault_expiry_callback_t callback,
                       void *user_data,
                       size_t *matched_count)
{
    static const char *const sql =
        "SELECT s.name, name_nonce, encrypted_name, version, expires_at "
        "FROM secrets AS s "
        "WHERE " VAULT_SQL_ACTIVE_ROW("s") " "
        "AND s.expires_at IS NOT NULL AND s.expires_at <= ? "
        "ORDER BY s.expires_at ASC, s.name ASC;";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char threshold[UTILS_ISO8601_UTC_BUFFER_LEN];
    size_t matched = 0U;
    int copied = 0;
    int rc = SQLITE_OK;
    int status = SM_OK;

    sodium_memzero(now, sizeof(now));
    sodium_memzero(threshold, sizeof(threshold));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if ((db == NULL) || (matched_count == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *matched_count = 0U;

    status = utils_now_iso8601(now, sizeof(now));
    if (status == SM_OK) {
        if (within_seconds > 0U) {
            status = utils_now_plus_seconds_iso8601(within_seconds,
                                                    threshold,
                                                    sizeof(threshold));
        } else {
            copied = snprintf(threshold, sizeof(threshold), "%s", now);
            if ((copied < 0) || ((size_t)copied >= sizeof(threshold))) {
                status = SM_ERR_INVALID_ARGUMENT;
            }
        }
    }
    if (status != SM_OK) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(threshold, sizeof(threshold));
        return status;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sodium_memzero(now, sizeof(now));
        sodium_memzero(threshold, sizeof(threshold));
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_bind_text(stmt, 1, threshold, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        sodium_memzero(now, sizeof(now));
        sodium_memzero(threshold, sizeof(threshold));
        return SM_ERR_STORAGE;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *stored_name = sqlite3_column_text(stmt, 0);
        const unsigned char *name_nonce = sqlite3_column_blob(stmt, 1);
        const unsigned char *encrypted_name = sqlite3_column_blob(stmt, 2);
        const unsigned char *expires_at = sqlite3_column_text(stmt, 4);
        char display_name[VAULT_SECRET_NAME_MAX + 1U];
        int stored_name_len = sqlite3_column_bytes(stmt, 0);
        int name_nonce_len = sqlite3_column_bytes(stmt, 1);
        int encrypted_name_len = sqlite3_column_bytes(stmt, 2);
        int version = sqlite3_column_int(stmt, 3);

        sodium_memzero(display_name, sizeof(display_name));
        if ((stored_name == NULL) || (stored_name_len <= 0) ||
            (name_nonce == NULL) || (encrypted_name == NULL) ||
            (expires_at == NULL) || (version < 1)) {
            status = SM_ERR_STORAGE;
            break;
        }
        status = vault_decrypt_display_name((const char *)stored_name,
                                            name_nonce,
                                            (size_t)name_nonce_len,
                                            encrypted_name,
                                            (size_t)encrypted_name_len,
                                            display_name,
                                            sizeof(display_name));
        if (status != SM_OK) {
            break;
        }
        if (callback != NULL) {
            status = callback(display_name,
                              version,
                              (const char *)expires_at,
                              vault_expiry_is_due((const char *)expires_at, now),
                              user_data);
            sodium_memzero(display_name, sizeof(display_name));
            if (status != SM_OK) {
                break;
            }
        } else {
            sodium_memzero(display_name, sizeof(display_name));
        }
        matched++;
    }
    if ((status == SM_OK) && (rc != SQLITE_DONE)) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        *matched_count = matched;
    }

    sodium_memzero(now, sizeof(now));
    sodium_memzero(threshold, sizeof(threshold));
    return status;
}

int vault_auto_rotate_expired(size_t *rotated_count)
{
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char *name = NULL;
    size_t rotated = 0U;
    int status = SM_OK;

    sodium_memzero(now, sizeof(now));
    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    if (rotated_count == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *rotated_count = 0U;

    status = utils_now_iso8601(now, sizeof(now));
    while (status == SM_OK) {
        status = vault_find_next_expired_secret(now, &name);
        if ((status != SM_OK) || (name == NULL)) {
            break;
        }
        status = vault_rotate_expired_secret(name);
        if (status == SM_OK) {
            rotated++;
        }
        free(name);
        name = NULL;
    }
    if (status == SM_OK) {
        *rotated_count = rotated;
    }

    free(name);
    sodium_memzero(now, sizeof(now));
    return status;
}

int vault_issue_token(const char *subject,
                      const char *scope,
                      uint64_t ttl_seconds,
                      char *token,
                      size_t token_len)
{
    char issued_token[ACCESS_TOKEN_BUFFER_LEN];
    int copied = 0;
    int status = SM_OK;

    sodium_memzero(issued_token, sizeof(issued_token));
    if ((token == NULL) || (token_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    token[0] = '\0';

    status = vault_require_unlocked();
    if (status != SM_OK) {
        return status;
    }
    status = access_issue_token(subject,
                                scope,
                                ttl_seconds,
                                g_subkeys->kek_token,
                                sizeof(g_subkeys->kek_token),
                                issued_token,
                                sizeof(issued_token));
    if (status == SM_OK) {
        copied = snprintf(token, token_len, "%s", issued_token);
        if ((copied < 0) || ((size_t)copied >= token_len)) {
            status = SM_ERR_INVALID_ARGUMENT;
        }
    }
    if (status == SM_OK) {
        status = vault_log_success("TOKEN_ISSUE", subject, 0);
    }
    if (status != SM_OK) {
        token[0] = '\0';
    }

    sodium_memzero(issued_token, sizeof(issued_token));
    return status;
}

int vault_check_token(const char *token, const char *required_scope)
{
    access_token_claims_t claims;
    uint64_t not_before = 0U;
    int status = vault_require_unlocked();

    sodium_memzero(&claims, sizeof(claims));
    if (status != SM_OK) {
        return status;
    }

    status = access_verify_token(token,
                                 required_scope,
                                 g_subkeys->kek_token,
                                 sizeof(g_subkeys->kek_token),
                                 &claims);
    if (status == SM_OK) {
        status = vault_get_token_not_before(&not_before);
    }
    if ((status == SM_OK) && (not_before > 0U) &&
        (claims.issued_at <= not_before)) {
        status = SM_ERR_AUTH;
    }

    sodium_memzero(&claims, sizeof(claims));
    return status;
}

int vault_revoke_tokens(void)
{
    time_t now = 0;
    int status = vault_require_unlocked();

    if (status != SM_OK) {
        return status;
    }
    now = time(NULL);
    if (now <= (time_t)0) {
        return SM_ERR_STORAGE;
    }

    status = storage_begin_transaction();
    if (status == SM_OK) {
        status = vault_put_token_not_before((uint64_t)now);
    }
    if (status == SM_OK) {
        status = vault_log_success("TOKEN_REVOKE", "tokens", 0);
    }
    if (status == SM_OK) {
        status = storage_commit_transaction();
        if (status != SM_OK) {
            (void)storage_rollback_transaction();
        }
    } else {
        (void)storage_rollback_transaction();
    }
    return status;
}

int vault_debug_name_lookup(const char *name, char *lookup_hex, size_t lookup_hex_len)
{
    int status = vault_require_unlocked();

    if (status != SM_OK) {
        return status;
    }
    return vault_build_name_lookup(name, lookup_hex, lookup_hex_len);
}

int vault_close(void)
{
    int status = SM_OK;

    vault_lock_state();
    status = storage_close();
    return status;
}
