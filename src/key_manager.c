#include "key_manager.h"

#include "crypto_engine.h"
#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define KEY_MANAGER_AAD_MAX 256U
#define KEY_MANAGER_ALGORITHM_MAX 32U
#define KEY_MANAGER_AES_ALGORITHM "AES-256-GCM"
#define KEY_MANAGER_XCHACHA_ALGORITHM "XChaCha20-Poly1305"
#define KEY_MANAGER_AEGIS_ALGORITHM "AEGIS-256"

#if defined(crypto_aead_aegis256_KEYBYTES) && !defined(SM_DISABLE_AEGIS)
#define KEY_MANAGER_HAS_AEGIS 1
#endif

typedef enum {
    KEY_MANAGER_ALG_AES_256_GCM = 1,
    KEY_MANAGER_ALG_XCHACHA20_POLY1305 = 2,
    KEY_MANAGER_ALG_AEGIS_256 = 3
} key_manager_algorithm_t;

static int key_manager_init_sodium(void)
{
    return sodium_init() < 0 ? SM_ERR_CRYPTO : SM_OK;
}

static int key_manager_algorithm_equals_literal(const char *left,
                                                const char *right,
                                                size_t right_len)
{
    size_t i = 0U;

    if ((left == NULL) || (right == NULL) || (right_len >= KEY_MANAGER_ALGORITHM_MAX)) {
        return 0;
    }

    for (i = 0U; i < KEY_MANAGER_ALGORITHM_MAX; i++) {
        unsigned char left_ch = (unsigned char)left[i];

        if (i == right_len) {
            return left_ch == '\0';
        }

        if ((left_ch == '\0') || (left_ch != (unsigned char)right[i])) {
            return 0;
        }
    }

    return 0;
}

static int key_manager_algorithm_from_name(const char *name,
                                           key_manager_algorithm_t *algorithm)
{
    if ((name == NULL) || (algorithm == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (key_manager_algorithm_equals_literal(name,
                                             KEY_MANAGER_AES_ALGORITHM,
                                             sizeof(KEY_MANAGER_AES_ALGORITHM) - 1U)) {
        if (crypto_aead_aes256gcm_is_available() != 1) {
            return SM_ERR_CRYPTO;
        }
        *algorithm = KEY_MANAGER_ALG_AES_256_GCM;
        return SM_OK;
    }

    if (key_manager_algorithm_equals_literal(name,
                                             KEY_MANAGER_XCHACHA_ALGORITHM,
                                             sizeof(KEY_MANAGER_XCHACHA_ALGORITHM) - 1U)) {
        *algorithm = KEY_MANAGER_ALG_XCHACHA20_POLY1305;
        return SM_OK;
    }

#ifdef KEY_MANAGER_HAS_AEGIS
    if (key_manager_algorithm_equals_literal(name,
                                             KEY_MANAGER_AEGIS_ALGORITHM,
                                             sizeof(KEY_MANAGER_AEGIS_ALGORITHM) - 1U)) {
        *algorithm = KEY_MANAGER_ALG_AEGIS_256;
        return SM_OK;
    }
#endif

    return SM_ERR_INVALID_ARGUMENT;
}

static size_t key_manager_nonce_bytes(key_manager_algorithm_t algorithm)
{
    switch (algorithm) {
    case KEY_MANAGER_ALG_AES_256_GCM:
        return crypto_aead_aes256gcm_NPUBBYTES;
#ifdef KEY_MANAGER_HAS_AEGIS
    case KEY_MANAGER_ALG_AEGIS_256:
        return crypto_aead_aegis256_NPUBBYTES;
#endif
    default:
        return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    }
}

static size_t key_manager_tag_bytes(key_manager_algorithm_t algorithm)
{
    switch (algorithm) {
    case KEY_MANAGER_ALG_AES_256_GCM:
        return crypto_aead_aes256gcm_ABYTES;
#ifdef KEY_MANAGER_HAS_AEGIS
    case KEY_MANAGER_ALG_AEGIS_256:
        return crypto_aead_aegis256_ABYTES;
#endif
    default:
        return crypto_aead_xchacha20poly1305_ietf_ABYTES;
    }
}

static int key_manager_build_aad(char *aad,
                                 size_t aad_len,
                                 const char *secret_id,
                                 uint32_t version,
                                 size_t *written)
{
    int result = 0;

    if ((aad == NULL) || (secret_id == NULL) || (secret_id[0] == '\0') ||
        (version == 0U) || (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    result = snprintf(aad, aad_len, "%s:%u", secret_id, (unsigned int)version);
    if ((result < 0) || ((size_t)result >= aad_len)) {
        sodium_memzero(aad, aad_len);
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = (size_t)result;
    return SM_OK;
}

static int key_manager_encrypt_dek(key_manager_algorithm_t algorithm,
                                   unsigned char *wrapped_dek,
                                   unsigned long long *written,
                                   const unsigned char *dek,
                                   const unsigned char *aad,
                                   size_t aad_len,
                                   const unsigned char *dek_nonce,
                                   const unsigned char *kek)
{
    if (algorithm == KEY_MANAGER_ALG_AES_256_GCM) {
        return crypto_aead_aes256gcm_encrypt(wrapped_dek,
                                             written,
                                             dek,
                                             KEY_MANAGER_DEK_BYTES,
                                             aad,
                                             (unsigned long long)aad_len,
                                             NULL,
                                             dek_nonce,
                                             kek) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }

#ifdef KEY_MANAGER_HAS_AEGIS
    if (algorithm == KEY_MANAGER_ALG_AEGIS_256) {
        return crypto_aead_aegis256_encrypt(wrapped_dek,
                                            written,
                                            dek,
                                            KEY_MANAGER_DEK_BYTES,
                                            aad,
                                            (unsigned long long)aad_len,
                                            NULL,
                                            dek_nonce,
                                            kek) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }
#endif

    return crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_dek,
                                                      written,
                                                      dek,
                                                      KEY_MANAGER_DEK_BYTES,
                                                      aad,
                                                      (unsigned long long)aad_len,
                                                      NULL,
                                                      dek_nonce,
                                                      kek) == 0
               ? SM_OK
               : SM_ERR_CRYPTO;
}

static int key_manager_decrypt_dek(key_manager_algorithm_t algorithm,
                                   unsigned char *dek,
                                   unsigned long long *written,
                                   const unsigned char *wrapped_dek,
                                   size_t wrapped_dek_len,
                                   const unsigned char *aad,
                                   size_t aad_len,
                                   const unsigned char *dek_nonce,
                                   const unsigned char *kek)
{
    if (algorithm == KEY_MANAGER_ALG_AES_256_GCM) {
        return crypto_aead_aes256gcm_decrypt(dek,
                                             written,
                                             NULL,
                                             wrapped_dek,
                                             (unsigned long long)wrapped_dek_len,
                                             aad,
                                             (unsigned long long)aad_len,
                                             dek_nonce,
                                             kek) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }

#ifdef KEY_MANAGER_HAS_AEGIS
    if (algorithm == KEY_MANAGER_ALG_AEGIS_256) {
        return crypto_aead_aegis256_decrypt(dek,
                                            written,
                                            NULL,
                                            wrapped_dek,
                                            (unsigned long long)wrapped_dek_len,
                                            aad,
                                            (unsigned long long)aad_len,
                                            dek_nonce,
                                            kek) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }
#endif

    return crypto_aead_xchacha20poly1305_ietf_decrypt(dek,
                                                      written,
                                                      NULL,
                                                      wrapped_dek,
                                                      (unsigned long long)wrapped_dek_len,
                                                      aad,
                                                      (unsigned long long)aad_len,
                                                      dek_nonce,
                                                      kek) == 0
               ? SM_OK
               : SM_ERR_CRYPTO;
}

static int key_manager_validate_kek(const unsigned char *kek, size_t kek_len)
{
    if ((kek == NULL) || (kek_len != KEY_MANAGER_DEK_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return SM_OK;
}

static int key_manager_copy_text_column(sqlite3_stmt *stmt,
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

static int key_manager_update_wrapped_dek(sqlite3 *db,
                                          sqlite3_stmt *stmt,
                                          const char *id,
                                          const unsigned char *wrapped_dek,
                                          size_t wrapped_dek_len,
                                          const unsigned char *dek_nonce,
                                          size_t dek_nonce_len,
                                          const unsigned char *key_commitment,
                                          size_t key_commitment_len)
{
    int rc = SQLITE_OK;
    int status = SM_OK;

    if ((db == NULL) || (stmt == NULL) || (id == NULL) ||
        (wrapped_dek == NULL) || (wrapped_dek_len > (size_t)INT_MAX) ||
        (dek_nonce == NULL) || (dek_nonce_len > (size_t)INT_MAX) ||
        (key_commitment == NULL) ||
        (key_commitment_len != CRYPTO_ENGINE_COMMITMENT_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_blob(stmt,
                           1,
                           wrapped_dek,
                           (int)wrapped_dek_len,
                           SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt,
                               2,
                               dek_nonce,
                               (int)dek_nonce_len,
                               SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt,
                               3,
                               key_commitment,
                               (int)key_commitment_len,
                               SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 4, id, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }

    if (status == SM_OK) {
        rc = sqlite3_step(stmt);
        if ((rc != SQLITE_DONE) || (sqlite3_changes(db) != 1)) {
            status = SM_ERR_STORAGE;
        }
    }
    if (sqlite3_reset(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_clear_bindings(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }

    return status;
}

int key_manager_generate_dek(unsigned char *dek, size_t dek_len)
{
    int status = SM_OK;

    if ((dek == NULL) || (dek_len != KEY_MANAGER_DEK_BYTES)) {
        if (dek != NULL) {
            sodium_memzero(dek, dek_len);
        }
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = key_manager_init_sodium();
    if (status != SM_OK) {
        sodium_memzero(dek, dek_len);
        return status;
    }

    randombytes_buf(dek, dek_len);
    return SM_OK;
}

int key_manager_wrap_dek(const char *algorithm,
                         const char *secret_id,
                         uint32_t version,
                         const unsigned char *dek,
                         size_t dek_len,
                         const unsigned char *kek,
                         size_t kek_len,
                         unsigned char *dek_nonce,
                         size_t dek_nonce_len,
                         size_t *dek_nonce_written,
                         unsigned char *wrapped_dek,
                         size_t wrapped_dek_len,
                         size_t *written)
{
    key_manager_algorithm_t alg = KEY_MANAGER_ALG_XCHACHA20_POLY1305;
    char aad[KEY_MANAGER_AAD_MAX];
    size_t aad_len = 0U;
    size_t nonce_len = 0U;
    size_t expected_wrapped_len = 0U;
    unsigned long long actual_written = 0U;
    int status = SM_OK;

    sodium_memzero(aad, sizeof(aad));
    if ((dek == NULL) || (dek_len != KEY_MANAGER_DEK_BYTES) ||
        (dek_nonce == NULL) || (dek_nonce_written == NULL) ||
        (wrapped_dek == NULL) || (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *dek_nonce_written = 0U;
    *written = 0U;

    status = key_manager_validate_kek(kek, kek_len);
    if (status == SM_OK) {
        status = key_manager_init_sodium();
    }
    if (status == SM_OK) {
        status = key_manager_algorithm_from_name(algorithm, &alg);
    }
    if (status == SM_OK) {
        status = key_manager_build_aad(aad, sizeof(aad), secret_id, version, &aad_len);
    }
    if (status != SM_OK) {
        sodium_memzero(aad, sizeof(aad));
        return status;
    }

    nonce_len = key_manager_nonce_bytes(alg);
    expected_wrapped_len = KEY_MANAGER_DEK_BYTES + key_manager_tag_bytes(alg);
    if ((dek_nonce_len < nonce_len) || (wrapped_dek_len < expected_wrapped_len)) {
        sodium_memzero(aad, sizeof(aad));
        return SM_ERR_INVALID_ARGUMENT;
    }

    randombytes_buf(dek_nonce, nonce_len);
    status = key_manager_encrypt_dek(alg,
                                     wrapped_dek,
                                     &actual_written,
                                     dek,
                                     (const unsigned char *)aad,
                                     aad_len,
                                     dek_nonce,
                                     kek);
    sodium_memzero(aad, sizeof(aad));
    if ((status != SM_OK) || ((size_t)actual_written != expected_wrapped_len)) {
        sodium_memzero(dek_nonce, dek_nonce_len);
        sodium_memzero(wrapped_dek, wrapped_dek_len);
        return status == SM_OK ? SM_ERR_CRYPTO : status;
    }

    *dek_nonce_written = nonce_len;
    *written = (size_t)actual_written;
    return SM_OK;
}

int key_manager_unwrap_dek(const char *algorithm,
                           const char *secret_id,
                           uint32_t version,
                           const unsigned char *wrapped_dek,
                           size_t wrapped_dek_len,
                           const unsigned char *dek_nonce,
                           size_t dek_nonce_len,
                           const unsigned char *kek,
                           size_t kek_len,
                           unsigned char *dek,
                           size_t dek_len,
                           size_t *written)
{
    key_manager_algorithm_t alg = KEY_MANAGER_ALG_XCHACHA20_POLY1305;
    char aad[KEY_MANAGER_AAD_MAX];
    size_t aad_len = 0U;
    size_t nonce_len = 0U;
    size_t expected_wrapped_len = 0U;
    unsigned long long actual_written = 0U;
    int status = SM_OK;

    sodium_memzero(aad, sizeof(aad));
    if ((wrapped_dek == NULL) || (dek_nonce == NULL) || (dek == NULL) ||
        (dek_len < KEY_MANAGER_DEK_BYTES) || (written == NULL)) {
        if (dek != NULL) {
            sodium_memzero(dek, dek_len);
        }
        return SM_ERR_INVALID_ARGUMENT;
    }
    *written = 0U;

    status = key_manager_validate_kek(kek, kek_len);
    if (status == SM_OK) {
        status = key_manager_init_sodium();
    }
    if (status == SM_OK) {
        status = key_manager_algorithm_from_name(algorithm, &alg);
    }
    if (status == SM_OK) {
        status = key_manager_build_aad(aad, sizeof(aad), secret_id, version, &aad_len);
    }
    if (status != SM_OK) {
        sodium_memzero(aad, sizeof(aad));
        sodium_memzero(dek, dek_len);
        return status;
    }

    nonce_len = key_manager_nonce_bytes(alg);
    expected_wrapped_len = KEY_MANAGER_DEK_BYTES + key_manager_tag_bytes(alg);
    if ((dek_nonce_len != nonce_len) || (wrapped_dek_len != expected_wrapped_len)) {
        sodium_memzero(aad, sizeof(aad));
        sodium_memzero(dek, dek_len);
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = key_manager_decrypt_dek(alg,
                                     dek,
                                     &actual_written,
                                     wrapped_dek,
                                     wrapped_dek_len,
                                     (const unsigned char *)aad,
                                     aad_len,
                                     dek_nonce,
                                     kek);
    sodium_memzero(aad, sizeof(aad));
    if ((status != SM_OK) || (actual_written != KEY_MANAGER_DEK_BYTES)) {
        sodium_memzero(dek, dek_len);
        return status == SM_OK ? SM_ERR_CRYPTO : status;
    }

    *written = (size_t)actual_written;
    return SM_OK;
}

static int key_manager_rewrap_dek(const char *algorithm,
                                  const char *secret_id,
                                  uint32_t version,
                                  const unsigned char *old_wrapped_dek,
                                  size_t old_wrapped_dek_len,
                                  const unsigned char *old_dek_nonce,
                                  size_t old_dek_nonce_len,
                                  const unsigned char *old_kek,
                                  size_t old_kek_len,
                                  const unsigned char *new_kek,
                                  size_t new_kek_len,
                                  unsigned char *new_wrapped_dek,
                                  size_t new_wrapped_dek_len,
                                  size_t *new_wrapped_written,
                                  unsigned char *new_dek_nonce,
                                  size_t new_dek_nonce_len,
                                  size_t *new_dek_nonce_written)
{
    unsigned char *dek = NULL;
    size_t dek_written = 0U;
    int status = SM_OK;

    if ((new_wrapped_written == NULL) || (new_dek_nonce_written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *new_wrapped_written = 0U;
    *new_dek_nonce_written = 0U;

    dek = sodium_malloc(KEY_MANAGER_DEK_BYTES);
    if (dek == NULL) {
        return SM_ERR_STORAGE;
    }
    if (sodium_mlock(dek, KEY_MANAGER_DEK_BYTES) != 0) {
        sodium_memzero(dek, KEY_MANAGER_DEK_BYTES);
        sodium_free(dek);
        return SM_ERR_STORAGE;
    }

    status = key_manager_unwrap_dek(algorithm,
                                    secret_id,
                                    version,
                                    old_wrapped_dek,
                                    old_wrapped_dek_len,
                                    old_dek_nonce,
                                    old_dek_nonce_len,
                                    old_kek,
                                    old_kek_len,
                                    dek,
                                    KEY_MANAGER_DEK_BYTES,
                                    &dek_written);
    if (status == SM_OK) {
        status = key_manager_wrap_dek(algorithm,
                                      secret_id,
                                      version,
                                      dek,
                                      dek_written,
                                      new_kek,
                                      new_kek_len,
                                      new_dek_nonce,
                                      new_dek_nonce_len,
                                      new_dek_nonce_written,
                                      new_wrapped_dek,
                                      new_wrapped_dek_len,
                                      new_wrapped_written);
    }

    sodium_memzero(dek, KEY_MANAGER_DEK_BYTES);
    (void)sodium_munlock(dek, KEY_MANAGER_DEK_BYTES);
    sodium_free(dek);
    return status;
}

int key_manager_rotate_kek(sqlite3 *db,
                           const unsigned char *old_kek,
                           size_t old_kek_len,
                           const unsigned char *new_kek,
                           size_t new_kek_len)
{
    static const char *const select_sql =
        "SELECT id, name, version, algorithm, encrypted_dek, dek_nonce, key_commitment "
        "FROM secrets ORDER BY id ASC;";
    static const char *const update_sql =
        "UPDATE secrets SET encrypted_dek = ?, dek_nonce = ?, key_commitment = ? "
        "WHERE id = ?;";
    sqlite3_stmt *select_stmt = NULL;
    sqlite3_stmt *update_stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_OK;

    if (db == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = key_manager_validate_kek(old_kek, old_kek_len);
    if (status == SM_OK) {
        status = key_manager_validate_kek(new_kek, new_kek_len);
    }
    if (status == SM_OK) {
        status = key_manager_init_sodium();
    }
    if (status != SM_OK) {
        return status;
    }

    rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL);
    }
    if (rc != SQLITE_OK) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    while ((rc = sqlite3_step(select_stmt)) == SQLITE_ROW) {
        char id[UTILS_UUID_V4_BUFFER_LEN];
        char identity[CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN];
        char algorithm[KEY_MANAGER_ALGORITHM_MAX];
        const unsigned char *name_text = NULL;
        const void *old_wrapped_dek = NULL;
        const void *old_dek_nonce = NULL;
        const void *old_commitment = NULL;
        int name_len = 0;
        int old_wrapped_dek_len = 0;
        int old_dek_nonce_len = 0;
        int old_commitment_len = 0;
        int version = 0;
        unsigned char new_wrapped_dek[KEY_MANAGER_WRAPPED_DEK_BYTES];
        unsigned char new_dek_nonce[KEY_MANAGER_MAX_NONCE_BYTES];
        unsigned char new_commitment[CRYPTO_ENGINE_COMMITMENT_BYTES];
        size_t new_wrapped_written = 0U;
        size_t new_dek_nonce_written = 0U;

        sodium_memzero(id, sizeof(id));
        sodium_memzero(identity, sizeof(identity));
        sodium_memzero(algorithm, sizeof(algorithm));
        sodium_memzero(new_wrapped_dek, sizeof(new_wrapped_dek));
        sodium_memzero(new_dek_nonce, sizeof(new_dek_nonce));
        sodium_memzero(new_commitment, sizeof(new_commitment));

        status = key_manager_copy_text_column(select_stmt, 0, id, sizeof(id));
        if (status == SM_OK) {
            name_text = sqlite3_column_text(select_stmt, 1);
            name_len = sqlite3_column_bytes(select_stmt, 1);
            if ((name_text == NULL) || (name_len <= 0) ||
                (strlen((const char *)name_text) != (size_t)name_len)) {
                status = SM_ERR_STORAGE;
            }
        }
        if (status == SM_OK) {
            version = sqlite3_column_int(select_stmt, 2);
            if (version < 1) {
                status = SM_ERR_STORAGE;
            }
        }
        if (status == SM_OK) {
            status = key_manager_copy_text_column(select_stmt,
                                                  3,
                                                  algorithm,
                                                  sizeof(algorithm));
        }
        if (status == SM_OK) {
            old_wrapped_dek = sqlite3_column_blob(select_stmt, 4);
            old_wrapped_dek_len = sqlite3_column_bytes(select_stmt, 4);
            old_dek_nonce = sqlite3_column_blob(select_stmt, 5);
            old_dek_nonce_len = sqlite3_column_bytes(select_stmt, 5);
            old_commitment = sqlite3_column_blob(select_stmt, 6);
            old_commitment_len = sqlite3_column_bytes(select_stmt, 6);
            if ((old_wrapped_dek == NULL) || (old_dek_nonce == NULL) ||
                (old_wrapped_dek_len <= 0) || (old_dek_nonce_len <= 0) ||
                (old_commitment == NULL) ||
                (old_commitment_len != (int)CRYPTO_ENGINE_COMMITMENT_BYTES)) {
                status = SM_ERR_STORAGE;
            }
        }
        if (status == SM_OK) {
            status = crypto_engine_build_row_identity(id,
                                                       (const char *)name_text,
                                                       identity,
                                                       sizeof(identity));
        }
        if (status == SM_OK) {
            status = key_manager_rewrap_dek(algorithm,
                                            identity,
                                            (uint32_t)version,
                                            old_wrapped_dek,
                                            (size_t)old_wrapped_dek_len,
                                            old_dek_nonce,
                                            (size_t)old_dek_nonce_len,
                                            old_kek,
                                            old_kek_len,
                                            new_kek,
                                            new_kek_len,
                                            new_wrapped_dek,
                                            sizeof(new_wrapped_dek),
                                            &new_wrapped_written,
                                            new_dek_nonce,
                                            sizeof(new_dek_nonce),
                                            &new_dek_nonce_written);
        }
        if (status == SM_OK) {
            /* Rewrap changes the KEK and dek_nonce, so the KEK half of
               the commitment must be recomputed; the DEK and payload
               nonce are untouched, so the DEK half carries over. */
            status = crypto_engine_compute_key_commitment(
                new_kek,
                new_kek_len,
                CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
                new_dek_nonce,
                new_dek_nonce_written,
                new_commitment,
                CRYPTO_ENGINE_COMMITMENT_HALF_BYTES);
        }
        if (status == SM_OK) {
            memcpy(new_commitment + CRYPTO_ENGINE_COMMITMENT_HALF_BYTES,
                   (const unsigned char *)old_commitment +
                       CRYPTO_ENGINE_COMMITMENT_HALF_BYTES,
                   CRYPTO_ENGINE_COMMITMENT_HALF_BYTES);
            status = key_manager_update_wrapped_dek(db,
                                                    update_stmt,
                                                    id,
                                                    new_wrapped_dek,
                                                    new_wrapped_written,
                                                    new_dek_nonce,
                                                    new_dek_nonce_written,
                                                    new_commitment,
                                                    sizeof(new_commitment));
        }

        sodium_memzero(id, sizeof(id));
        sodium_memzero(identity, sizeof(identity));
        sodium_memzero(algorithm, sizeof(algorithm));
        sodium_memzero(new_wrapped_dek, sizeof(new_wrapped_dek));
        sodium_memzero(new_dek_nonce, sizeof(new_dek_nonce));
        sodium_memzero(new_commitment, sizeof(new_commitment));
        if (status != SM_OK) {
            break;
        }
    }

    if ((rc != SQLITE_DONE) && (status == SM_OK)) {
        status = SM_ERR_STORAGE;
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

    return status;
}
