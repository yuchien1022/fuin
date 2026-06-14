#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
/* Expose realpath() on glibc, which gates it behind _DEFAULT_SOURCE under
   -std=c11; macOS provides it via _DARWIN_C_SOURCE above. */
#define _DEFAULT_SOURCE
#endif

#include "backup.h"

#include "audit.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BACKUP_MAGIC_LEN 8U
#define BACKUP_VERSION 1U
#define BACKUP_FIXED_HEADER_LEN 44U
#define BACKUP_MAX_DB_BYTES (128ULL * 1024ULL * 1024ULL)
#define BACKUP_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define BACKUP_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define BACKUP_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define BACKUP_ENCAP_PREFIX_LEN 4U
#define BACKUP_X25519_PUBLIC_BYTES 32U

static const unsigned char BACKUP_MAGIC[BACKUP_MAGIC_LEN] = {
    'S', 'M', 'B', 'K', 'P', 'Q', '1', '\n'
};

typedef struct {
    unsigned char *data;
    size_t len;
} backup_bytes_t;

static void backup_free_bytes(backup_bytes_t *bytes)
{
    if ((bytes == NULL) || (bytes->data == NULL)) {
        return;
    }

    sodium_memzero(bytes->data, bytes->len);
    free(bytes->data);
    bytes->data = NULL;
    bytes->len = 0U;
}

static void backup_openssl_clear_free(unsigned char **data, size_t len)
{
    if ((data == NULL) || (*data == NULL)) {
        return;
    }

    OPENSSL_clear_free(*data, len);
    *data = NULL;
}

static void backup_write_u32_le(unsigned char *out, uint32_t value)
{
    size_t i = 0U;

    for (i = 0U; i < 4U; i++) {
        out[i] = (unsigned char)(value >> (i * 8U));
    }
}

static uint32_t backup_read_u32_le(const unsigned char *in)
{
    uint32_t value = 0U;
    size_t i = 0U;

    for (i = 0U; i < 4U; i++) {
        value |= ((uint32_t)in[i]) << (i * 8U);
    }
    return value;
}

static uint64_t backup_read_u64_le(const unsigned char *in)
{
    uint64_t value = 0U;
    size_t i = 0U;

    for (i = 0U; i < 8U; i++) {
        value |= ((uint64_t)in[i]) << (i * 8U);
    }
    return value;
}

static int backup_checked_add(size_t *total, size_t value)
{
    if (total == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (*total > (SIZE_MAX - value)) {
        return SM_ERR_STORAGE;
    }
    *total += value;
    return SM_OK;
}

static int backup_resolve_parent_path(const char *path, char **resolved_path)
{
    const char *slash = NULL;
    const char *basename = NULL;
    char *parent = NULL;
    char *resolved_parent = NULL;
    char *combined = NULL;
    const char *separator = "/";
    size_t parent_len = 0U;
    size_t parent_path_len = 0U;
    size_t basename_len = 0U;
    size_t separator_len = 1U;
    size_t combined_len = 0U;
    int written = 0;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') || (resolved_path == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *resolved_path = NULL;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        basename = path;
        parent_len = 1U;
        parent = malloc(parent_len + 1U);
        if (parent == NULL) {
            return SM_ERR_STORAGE;
        }
        memcpy(parent, ".", parent_len + 1U);
    } else {
        basename = slash + 1;
        if (basename[0] == '\0') {
            return SM_ERR_INVALID_ARGUMENT;
        }
        parent_len = (slash == path) ? 1U : (size_t)(slash - path);
        parent = malloc(parent_len + 1U);
        if (parent == NULL) {
            return SM_ERR_STORAGE;
        }
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    }

    if ((strcmp(basename, ".") == 0) || (strcmp(basename, "..") == 0)) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }

    resolved_parent = realpath(parent, NULL);
    if (resolved_parent == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    parent_path_len = strlen(resolved_parent);
    basename_len = strlen(basename);
    if (strcmp(resolved_parent, "/") == 0) {
        separator = "";
        separator_len = 0U;
    }
    if ((parent_path_len > (SIZE_MAX - separator_len)) ||
        ((parent_path_len + separator_len) > (SIZE_MAX - basename_len)) ||
        ((parent_path_len + separator_len + basename_len) >
         (SIZE_MAX - 1U))) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    combined_len = parent_path_len + separator_len + basename_len + 1U;
    combined = malloc(combined_len);
    if (combined == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    written = snprintf(combined,
                       combined_len,
                       "%s%s%s",
                       resolved_parent,
                       separator,
                       basename);
    if ((written < 0) || ((size_t)written >= combined_len)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    *resolved_path = combined;
    combined = NULL;

cleanup:
    free(combined);
    free(resolved_parent);
    free(parent);
    return status;
}

static int backup_private_key_passphrase_is_valid(const char *passphrase)
{
    return (passphrase != NULL) && (passphrase[0] != '\0');
}

static int backup_private_key_file_header_is_encrypted(FILE *fp)
{
    static const char begin_prefix[] = "-----BEGIN ";
    static const char encrypted_header[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    char line[256];
    size_t begin_len = sizeof(begin_prefix) - 1U;
    size_t header_len = sizeof(encrypted_header) - 1U;
    int saw_private_key = 0;
    int status = SM_OK;

    if (fp == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, begin_prefix, begin_len) == 0) {
            saw_private_key = 1;
            if (strncmp(line, encrypted_header, header_len) != 0) {
                status = SM_ERR_CRYPTO;
                break;
            }
        }
    }
    if (ferror(fp)) {
        status = SM_ERR_STORAGE;
    } else if ((status == SM_OK) && !saw_private_key) {
        status = SM_ERR_STORAGE;
    }
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int backup_fopen_owner_only_read(const char *path, FILE **out)
{
    struct stat st;
    char *resolved_path = NULL;
    FILE *fp = NULL;
    int status = SM_OK;
    int fd = -1;

    if ((path == NULL) || (path[0] == '\0') || (out == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    status = backup_resolve_parent_path(path, &resolved_path);
    if (status != SM_OK) {
        return status;
    }

    fd = open(resolved_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        free(resolved_path);
        return SM_ERR_STORAGE;
    }
    if ((fstat(fd, &st) != 0) ||
        !S_ISREG(st.st_mode) ||
        (st.st_uid != getuid()) ||
        ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)) {
        (void)close(fd);
        free(resolved_path);
        return SM_ERR_STORAGE;
    }

    fp = fdopen(fd, "rb");
    if (fp == NULL) {
        (void)close(fd);
        free(resolved_path);
        return SM_ERR_STORAGE;
    }
    *out = fp;
    free(resolved_path);
    return SM_OK;
}

static int backup_write_encrypted_private_key(FILE *fp,
                                              EVP_PKEY *key,
                                              const char *passphrase)
{
    size_t passphrase_len = 0U;

    if ((fp == NULL) || (key == NULL) ||
        !backup_private_key_passphrase_is_valid(passphrase)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    passphrase_len = strlen(passphrase);
    if (passphrase_len > (size_t)INT_MAX) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return PEM_write_PrivateKey(fp,
                                key,
                                EVP_aes_256_cbc(),
                                (unsigned char *)passphrase,
                                (int)passphrase_len,
                                NULL,
                                NULL) == 1
               ? SM_OK
               : SM_ERR_CRYPTO;
}

/* Atomically create a new file with the given permissions; fails if the
   path already exists (O_EXCL), so no separate existence pre-check is
   needed and the file is never visible with umask-default permissions. */
static FILE *backup_fopen_exclusive(const char *path, mode_t mode)
{
    char *resolved_path = NULL;
    FILE *fp = NULL;
    int fd = -1;

    if (backup_resolve_parent_path(path, &resolved_path) != SM_OK) {
        return NULL;
    }

    fd = open(resolved_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (fd < 0) {
        free(resolved_path);
        return NULL;
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        (void)close(fd);
        (void)remove(resolved_path);
    }
    free(resolved_path);
    return fp;
}

static int backup_write_all(const char *path,
                            const unsigned char *data,
                            size_t data_len)
{
    FILE *fp = NULL;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') ||
        ((data == NULL) && (data_len > 0U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    fp = backup_fopen_exclusive(path, S_IRUSR | S_IWUSR);
    if (fp == NULL) {
        return SM_ERR_STORAGE;
    }
    if ((data_len > 0U) && (fwrite(data, 1U, data_len, fp) != data_len)) {
        status = SM_ERR_STORAGE;
    }
    if (fclose(fp) != 0) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int backup_read_all(const char *path,
                           backup_bytes_t *bytes,
                           uint64_t max_bytes)
{
    FILE *fp = NULL;
    long size = 0L;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') || (bytes == NULL) ||
        (max_bytes > (uint64_t)SIZE_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    bytes->data = NULL;
    bytes->len = 0U;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return SM_ERR_STORAGE;
    }
    if ((fseek(fp, 0L, SEEK_END) != 0) || ((size = ftell(fp)) < 0L) ||
        (fseek(fp, 0L, SEEK_SET) != 0)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if ((uint64_t)size > max_bytes) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }
    if (size == 0L) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    bytes->data = malloc((size_t)size);
    if (bytes->data == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    bytes->len = (size_t)size;
    if (fread(bytes->data, 1U, bytes->len, fp) != bytes->len) {
        backup_free_bytes(bytes);
        status = SM_ERR_STORAGE;
    }

cleanup:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            status = SM_ERR_STORAGE;
        }
    }
    return status;
}

static int backup_sqlite_snapshot(sqlite3 *source_db, backup_bytes_t *snapshot)
{
    unsigned char *serialized = NULL;
    sqlite3_int64 serialized_len = 0;
    int status = SM_OK;

    if ((source_db == NULL) || (snapshot == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    snapshot->data = NULL;
    snapshot->len = 0U;

    /* In-memory serialization (SQLite >= 3.36 ships it by default): the
       DB image carries plaintext metadata, so it must never be written to
       a temp file that could outlive a crash or be recovered after
       deletion. */
    serialized = sqlite3_serialize(source_db, "main", &serialized_len, 0U);
    if ((serialized == NULL) || (serialized_len <= 0)) {
        sqlite3_free(serialized);
        return SM_ERR_STORAGE;
    }
    if ((uint64_t)serialized_len > BACKUP_MAX_DB_BYTES) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }

    snapshot->data = malloc((size_t)serialized_len);
    if (snapshot->data == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    snapshot->len = (size_t)serialized_len;
    memcpy(snapshot->data, serialized, snapshot->len);

cleanup:
    sodium_memzero(serialized, (size_t)serialized_len);
    sqlite3_free(serialized);
    return status;
}

static int backup_load_public_keypair(const char *path,
                                      EVP_PKEY **kem_key,
                                      EVP_PKEY **x25519_key)
{
    FILE *fp = NULL;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') ||
        (kem_key == NULL) || (x25519_key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *kem_key = NULL;
    *x25519_key = NULL;
    fp = fopen(path, "rb");
    if (fp == NULL) {
        return SM_ERR_STORAGE;
    }
    *kem_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (*kem_key == NULL) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *x25519_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (*x25519_key == NULL) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    if (fclose(fp) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (status != SM_OK) {
        EVP_PKEY_free(*kem_key);
        EVP_PKEY_free(*x25519_key);
        *kem_key = NULL;
        *x25519_key = NULL;
    }
    return status;
}

static int backup_load_private_keypair(const char *path,
                                       const char *passphrase,
                                       EVP_PKEY **kem_key,
                                       EVP_PKEY **x25519_key)
{
    FILE *fp = NULL;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') ||
        !backup_private_key_passphrase_is_valid(passphrase) ||
        (kem_key == NULL) || (x25519_key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *kem_key = NULL;
    *x25519_key = NULL;
    status = backup_fopen_owner_only_read(path, &fp);
    if (status != SM_OK) {
        return status;
    }
    status = backup_private_key_file_header_is_encrypted(fp);
    if (status != SM_OK) {
        goto cleanup;
    }
    *kem_key = PEM_read_PrivateKey(fp, NULL, NULL, (void *)passphrase);
    if (*kem_key == NULL) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *x25519_key = PEM_read_PrivateKey(fp, NULL, NULL, (void *)passphrase);
    if (*x25519_key == NULL) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    if (fclose(fp) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (status != SM_OK) {
        EVP_PKEY_free(*kem_key);
        EVP_PKEY_free(*x25519_key);
        *kem_key = NULL;
        *x25519_key = NULL;
    }
    return status;
}

static int backup_encapsulate(EVP_PKEY *public_key,
                              unsigned char **kem_ct,
                              size_t *kem_ct_len,
                              unsigned char **shared_secret,
                              size_t *shared_secret_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    int status = SM_OK;

    if ((public_key == NULL) || (kem_ct == NULL) || (kem_ct_len == NULL) ||
        (shared_secret == NULL) || (shared_secret_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *kem_ct = NULL;
    *kem_ct_len = 0U;
    *shared_secret = NULL;
    *shared_secret_len = 0U;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
    if ((ctx == NULL) || (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) ||
        (EVP_PKEY_encapsulate(ctx,
                              NULL,
                              kem_ct_len,
                              NULL,
                              shared_secret_len) <= 0)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *kem_ct = OPENSSL_malloc(*kem_ct_len);
    *shared_secret = OPENSSL_malloc(*shared_secret_len);
    if ((*kem_ct == NULL) || (*shared_secret == NULL)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (EVP_PKEY_encapsulate(ctx,
                             *kem_ct,
                             kem_ct_len,
                             *shared_secret,
                             shared_secret_len) <= 0) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (status != SM_OK) {
        backup_openssl_clear_free(kem_ct, *kem_ct_len);
        backup_openssl_clear_free(shared_secret, *shared_secret_len);
        *kem_ct_len = 0U;
        *shared_secret_len = 0U;
    }
    return status;
}

static int backup_decapsulate(EVP_PKEY *private_key,
                              const unsigned char *kem_ct,
                              size_t kem_ct_len,
                              unsigned char **shared_secret,
                              size_t *shared_secret_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    int status = SM_OK;

    if ((private_key == NULL) || (kem_ct == NULL) || (kem_ct_len == 0U) ||
        (shared_secret == NULL) || (shared_secret_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *shared_secret = NULL;
    *shared_secret_len = 0U;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    if ((ctx == NULL) || (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) ||
        (EVP_PKEY_decapsulate(ctx,
                              NULL,
                              shared_secret_len,
                              kem_ct,
                              kem_ct_len) <= 0)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *shared_secret = OPENSSL_malloc(*shared_secret_len);
    if (*shared_secret == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (EVP_PKEY_decapsulate(ctx,
                             *shared_secret,
                             shared_secret_len,
                             kem_ct,
                             kem_ct_len) <= 0) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (status != SM_OK) {
        backup_openssl_clear_free(shared_secret, *shared_secret_len);
        *shared_secret_len = 0U;
    }
    return status;
}

static int backup_x25519_derive(EVP_PKEY *private_key,
                                EVP_PKEY *peer_public_key,
                                unsigned char **shared_secret,
                                size_t *shared_secret_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    int status = SM_OK;

    if ((private_key == NULL) || (peer_public_key == NULL) ||
        (shared_secret == NULL) || (shared_secret_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *shared_secret = NULL;
    *shared_secret_len = 0U;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    if ((ctx == NULL) || (EVP_PKEY_derive_init(ctx) <= 0) ||
        (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0) ||
        (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *shared_secret = OPENSSL_malloc(*shared_secret_len);
    if (*shared_secret == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, *shared_secret, shared_secret_len) <= 0) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (status != SM_OK) {
        backup_openssl_clear_free(shared_secret, *shared_secret_len);
        *shared_secret_len = 0U;
    }
    return status;
}

static int backup_get_raw_public_key(EVP_PKEY *key,
                                     unsigned char **public_key,
                                     size_t *public_key_len)
{
    int status = SM_OK;

    if ((key == NULL) || (public_key == NULL) || (public_key_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *public_key = NULL;
    *public_key_len = 0U;
    if (EVP_PKEY_get_raw_public_key(key, NULL, public_key_len) <= 0) {
        return SM_ERR_CRYPTO;
    }
    *public_key = OPENSSL_malloc(*public_key_len);
    if (*public_key == NULL) {
        return SM_ERR_STORAGE;
    }
    if (EVP_PKEY_get_raw_public_key(key, *public_key, public_key_len) <= 0) {
        status = SM_ERR_CRYPTO;
    }
    if (status != SM_OK) {
        backup_openssl_clear_free(public_key, *public_key_len);
        *public_key_len = 0U;
    }
    return status;
}

static int backup_x25519_public_from_raw(const unsigned char *public_key,
                                         size_t public_key_len,
                                         EVP_PKEY **key)
{
    if ((public_key == NULL) ||
        (public_key_len != BACKUP_X25519_PUBLIC_BYTES) ||
        (key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *key = EVP_PKEY_new_raw_public_key_ex(NULL,
                                          BACKUP_CLASSICAL_KEX_ALGORITHM,
                                          NULL,
                                          public_key,
                                          public_key_len);
    return *key == NULL ? SM_ERR_CRYPTO : SM_OK;
}

static int backup_build_hybrid_encap(unsigned char **encap,
                                     size_t *encap_len,
                                     const unsigned char *ephemeral_public,
                                     size_t ephemeral_public_len,
                                     const unsigned char *kem_ct,
                                     size_t kem_ct_len)
{
    unsigned char *cursor = NULL;
    size_t total = BACKUP_ENCAP_PREFIX_LEN;
    int status = SM_OK;

    if ((encap == NULL) || (encap_len == NULL) ||
        (ephemeral_public == NULL) ||
        (ephemeral_public_len != BACKUP_X25519_PUBLIC_BYTES) ||
        (kem_ct == NULL) || (kem_ct_len == 0U) ||
        (ephemeral_public_len > UINT32_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *encap = NULL;
    *encap_len = 0U;
    status = backup_checked_add(&total, ephemeral_public_len);
    if (status == SM_OK) {
        status = backup_checked_add(&total, kem_ct_len);
    }
    if (status != SM_OK) {
        return status;
    }

    *encap = malloc(total);
    if (*encap == NULL) {
        return SM_ERR_STORAGE;
    }
    *encap_len = total;
    cursor = *encap;
    backup_write_u32_le(cursor, (uint32_t)ephemeral_public_len);
    cursor += BACKUP_ENCAP_PREFIX_LEN;
    memcpy(cursor, ephemeral_public, ephemeral_public_len);
    cursor += ephemeral_public_len;
    memcpy(cursor, kem_ct, kem_ct_len);
    cursor += kem_ct_len;

    if ((size_t)(cursor - *encap) != total) {
        sodium_memzero(*encap, total);
        free(*encap);
        *encap = NULL;
        *encap_len = 0U;
        return SM_ERR_STORAGE;
    }
    return SM_OK;
}

static int backup_parse_hybrid_encap(const unsigned char *encap,
                                     size_t encap_len,
                                     const unsigned char **ephemeral_public,
                                     size_t *ephemeral_public_len,
                                     const unsigned char **kem_ct,
                                     size_t *kem_ct_len)
{
    uint32_t encoded_ephemeral_len = 0U;
    size_t offset = BACKUP_ENCAP_PREFIX_LEN;

    if ((encap == NULL) || (encap_len <= BACKUP_ENCAP_PREFIX_LEN) ||
        (ephemeral_public == NULL) || (ephemeral_public_len == NULL) ||
        (kem_ct == NULL) || (kem_ct_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *ephemeral_public = NULL;
    *ephemeral_public_len = 0U;
    *kem_ct = NULL;
    *kem_ct_len = 0U;
    encoded_ephemeral_len = backup_read_u32_le(encap);
    if ((encoded_ephemeral_len != BACKUP_X25519_PUBLIC_BYTES) ||
        ((size_t)encoded_ephemeral_len > (encap_len - offset))) {
        return SM_ERR_CRYPTO;
    }

    *ephemeral_public = encap + offset;
    *ephemeral_public_len = (size_t)encoded_ephemeral_len;
    offset += *ephemeral_public_len;
    if (offset >= encap_len) {
        return SM_ERR_CRYPTO;
    }
    *kem_ct = encap + offset;
    *kem_ct_len = encap_len - offset;
    return SM_OK;
}

static int backup_derive_capsule_key(const unsigned char *kem_shared_secret,
                                     size_t kem_shared_secret_len,
                                     const unsigned char *x25519_shared_secret,
                                     size_t x25519_shared_secret_len,
                                     const unsigned char *encap,
                                     size_t encap_len,
                                     const unsigned char *audit_root,
                                     size_t audit_root_len,
                                     unsigned char *key)
{
    crypto_generichash_state state;
    static const unsigned char context[] =
        "Fuin-PQC-Backup-v1|X25519+ML-KEM-768|XChaCha20-Poly1305";
    int status = SM_OK;

    if ((kem_shared_secret == NULL) || (kem_shared_secret_len == 0U) ||
        (x25519_shared_secret == NULL) || (x25519_shared_secret_len == 0U) ||
        (encap == NULL) || (encap_len == 0U) ||
        (audit_root == NULL) || (audit_root_len != AUDIT_MERKLE_ROOT_BYTES) ||
        (key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((crypto_generichash_init(&state,
                                 NULL,
                                 0U,
                                 BACKUP_KEY_BYTES) != 0) ||
        (crypto_generichash_update(&state, context, sizeof(context) - 1U) != 0) ||
        (crypto_generichash_update(&state,
                                   kem_shared_secret,
                                   kem_shared_secret_len) != 0) ||
        (crypto_generichash_update(&state,
                                   x25519_shared_secret,
                                   x25519_shared_secret_len) != 0) ||
        (crypto_generichash_update(&state, encap, encap_len) != 0) ||
        (crypto_generichash_update(&state, audit_root, audit_root_len) != 0) ||
        (crypto_generichash_final(&state, key, BACKUP_KEY_BYTES) != 0)) {
        status = SM_ERR_CRYPTO;
    }

    sodium_memzero(&state, sizeof(state));
    return status;
}

static int backup_build_aad(unsigned char **aad,
                            size_t *aad_len,
                            const unsigned char *fixed_header,
                            const char *algorithm,
                            size_t algorithm_len,
                            const unsigned char *kem_ct,
                            size_t kem_ct_len,
                            const unsigned char *nonce,
                            size_t nonce_len,
                            const unsigned char *audit_root,
                            size_t audit_root_len)
{
    unsigned char *cursor = NULL;
    size_t total = BACKUP_FIXED_HEADER_LEN;
    int status = SM_OK;

    if ((aad == NULL) || (aad_len == NULL) || (fixed_header == NULL) ||
        (algorithm == NULL) || (kem_ct == NULL) || (nonce == NULL) ||
        (audit_root == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *aad = NULL;
    *aad_len = 0U;
    status = backup_checked_add(&total, algorithm_len);
    if (status == SM_OK) {
        status = backup_checked_add(&total, kem_ct_len);
    }
    if (status == SM_OK) {
        status = backup_checked_add(&total, nonce_len);
    }
    if (status == SM_OK) {
        status = backup_checked_add(&total, audit_root_len);
    }
    if (status != SM_OK) {
        return status;
    }

    *aad = malloc(total);
    if (*aad == NULL) {
        return SM_ERR_STORAGE;
    }
    *aad_len = total;
    cursor = *aad;
    memcpy(cursor, fixed_header, BACKUP_FIXED_HEADER_LEN);
    cursor += BACKUP_FIXED_HEADER_LEN;
    memcpy(cursor, algorithm, algorithm_len);
    cursor += algorithm_len;
    memcpy(cursor, kem_ct, kem_ct_len);
    cursor += kem_ct_len;
    memcpy(cursor, nonce, nonce_len);
    cursor += nonce_len;
    memcpy(cursor, audit_root, audit_root_len);
    cursor += audit_root_len;
    if ((size_t)(cursor - *aad) != total) {
        sodium_memzero(*aad, total);
        free(*aad);
        *aad = NULL;
        *aad_len = 0U;
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

static int backup_build_fixed_header(unsigned char *header,
                                     size_t header_len,
                                     size_t algorithm_len,
                                     size_t kem_ct_len,
                                     size_t nonce_len,
                                     size_t audit_root_len,
                                     size_t ciphertext_len,
                                     size_t plaintext_len)
{
    unsigned char *cursor = header;

    if ((header == NULL) || (header_len != BACKUP_FIXED_HEADER_LEN) ||
        (algorithm_len > UINT32_MAX) || (kem_ct_len > UINT32_MAX) ||
        (nonce_len > UINT32_MAX) || (audit_root_len > UINT32_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    memcpy(cursor, BACKUP_MAGIC, BACKUP_MAGIC_LEN);
    cursor += BACKUP_MAGIC_LEN;
    backup_write_u32_le(cursor, BACKUP_VERSION);
    cursor += 4U;
    backup_write_u32_le(cursor, (uint32_t)algorithm_len);
    cursor += 4U;
    backup_write_u32_le(cursor, (uint32_t)kem_ct_len);
    cursor += 4U;
    backup_write_u32_le(cursor, (uint32_t)nonce_len);
    cursor += 4U;
    backup_write_u32_le(cursor, (uint32_t)audit_root_len);
    cursor += 4U;
    utils_write_u64_le(cursor, (uint64_t)ciphertext_len);
    cursor += 8U;
    utils_write_u64_le(cursor, (uint64_t)plaintext_len);
    cursor += 8U;

    return (size_t)(cursor - header) == header_len ? SM_OK : SM_ERR_STORAGE;
}

int backup_pqc_available(void)
{
    EVP_PKEY *kem_key = EVP_PKEY_Q_keygen(NULL, NULL, BACKUP_PQC_KEM_ALGORITHM);
    EVP_PKEY *x25519_key = EVP_PKEY_Q_keygen(NULL,
                                             NULL,
                                             BACKUP_CLASSICAL_KEX_ALGORITHM);
    int available = (kem_key != NULL) && (x25519_key != NULL);

    EVP_PKEY_free(kem_key);
    EVP_PKEY_free(x25519_key);
    return available;
}

int backup_pqc_keygen(const char *public_key_path,
                      const char *private_key_path,
                      const char *private_key_passphrase)
{
    EVP_PKEY *kem_key = NULL;
    EVP_PKEY *x25519_key = NULL;
    FILE *public_fp = NULL;
    FILE *private_fp = NULL;
    int status = SM_OK;

    if ((public_key_path == NULL) || (public_key_path[0] == '\0') ||
        (private_key_path == NULL) || (private_key_path[0] == '\0') ||
        !backup_private_key_passphrase_is_valid(private_key_passphrase)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    kem_key = EVP_PKEY_Q_keygen(NULL, NULL, BACKUP_PQC_KEM_ALGORITHM);
    x25519_key = EVP_PKEY_Q_keygen(NULL, NULL, BACKUP_CLASSICAL_KEX_ALGORITHM);
    if ((kem_key == NULL) || (x25519_key == NULL)) {
        EVP_PKEY_free(kem_key);
        EVP_PKEY_free(x25519_key);
        return SM_ERR_CRYPTO;
    }

    private_fp = backup_fopen_exclusive(private_key_path, S_IRUSR | S_IWUSR);
    if (private_fp == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    status = backup_write_encrypted_private_key(private_fp,
                                                kem_key,
                                                private_key_passphrase);
    if (status == SM_OK) {
        status = backup_write_encrypted_private_key(private_fp,
                                                    x25519_key,
                                                    private_key_passphrase);
    }
    if (status != SM_OK) {
        goto cleanup;
    }
    if (fclose(private_fp) != 0) {
        private_fp = NULL;
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    private_fp = NULL;

    public_fp = backup_fopen_exclusive(public_key_path,
                                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (public_fp == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if ((PEM_write_PUBKEY(public_fp, kem_key) != 1) ||
        (PEM_write_PUBKEY(public_fp, x25519_key) != 1)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (fclose(public_fp) != 0) {
        public_fp = NULL;
        status = SM_ERR_STORAGE;
    }
    public_fp = NULL;

cleanup:
    if (public_fp != NULL) {
        (void)fclose(public_fp);
    }
    if (private_fp != NULL) {
        (void)fclose(private_fp);
    }
    EVP_PKEY_free(kem_key);
    EVP_PKEY_free(x25519_key);
    if (status != SM_OK) {
        (void)remove(public_key_path);
        (void)remove(private_key_path);
    }
    return status;
}

int backup_pqc_export(sqlite3 *source_db,
                      const char *recipient_public_key_path,
                      const char *capsule_path,
                      const unsigned char *audit_root,
                      size_t audit_root_len)
{
    EVP_PKEY *kem_public_key = NULL;
    EVP_PKEY *x25519_public_key = NULL;
    EVP_PKEY *ephemeral_key = NULL;
    backup_bytes_t snapshot = {NULL, 0U};
    unsigned char *kem_ct = NULL;
    unsigned char *kem_shared_secret = NULL;
    unsigned char *x25519_shared_secret = NULL;
    unsigned char *ephemeral_public = NULL;
    unsigned char *encap = NULL;
    unsigned char *aad = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *capsule = NULL;
    unsigned char fixed_header[BACKUP_FIXED_HEADER_LEN];
    unsigned char nonce[BACKUP_NONCE_BYTES];
    unsigned char capsule_key[BACKUP_KEY_BYTES];
    unsigned long long ciphertext_len = 0ULL;
    size_t ciphertext_capacity = 0U;
    size_t kem_ct_len = 0U;
    size_t kem_shared_secret_len = 0U;
    size_t x25519_shared_secret_len = 0U;
    size_t ephemeral_public_len = 0U;
    size_t encap_len = 0U;
    size_t aad_len = 0U;
    size_t capsule_len = 0U;
    size_t offset = 0U;
    const char *algorithm = BACKUP_CAPSULE_ALGORITHM;
    const size_t algorithm_len = strlen(BACKUP_CAPSULE_ALGORITHM);
    int status = SM_OK;

    sodium_memzero(fixed_header, sizeof(fixed_header));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(capsule_key, sizeof(capsule_key));
    if ((source_db == NULL) ||
        (recipient_public_key_path == NULL) ||
        (capsule_path == NULL) ||
        (audit_root == NULL) ||
        (audit_root_len != AUDIT_MERKLE_ROOT_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = backup_sqlite_snapshot(source_db, &snapshot);
    if (status == SM_OK) {
        status = backup_load_public_keypair(recipient_public_key_path,
                                            &kem_public_key,
                                            &x25519_public_key);
    }
    if (status == SM_OK) {
        status = backup_encapsulate(kem_public_key,
                                    &kem_ct,
                                    &kem_ct_len,
                                    &kem_shared_secret,
                                    &kem_shared_secret_len);
    }
    if (status == SM_OK) {
        ephemeral_key = EVP_PKEY_Q_keygen(NULL,
                                          NULL,
                                          BACKUP_CLASSICAL_KEX_ALGORITHM);
        if (ephemeral_key == NULL) {
            status = SM_ERR_CRYPTO;
        }
    }
    if (status == SM_OK) {
        status = backup_x25519_derive(ephemeral_key,
                                      x25519_public_key,
                                      &x25519_shared_secret,
                                      &x25519_shared_secret_len);
    }
    if (status == SM_OK) {
        status = backup_get_raw_public_key(ephemeral_key,
                                           &ephemeral_public,
                                           &ephemeral_public_len);
    }
    if (status == SM_OK) {
        status = backup_build_hybrid_encap(&encap,
                                           &encap_len,
                                           ephemeral_public,
                                           ephemeral_public_len,
                                           kem_ct,
                                           kem_ct_len);
    }
    if (status == SM_OK) {
        status = backup_derive_capsule_key(kem_shared_secret,
                                           kem_shared_secret_len,
                                           x25519_shared_secret,
                                           x25519_shared_secret_len,
                                           encap,
                                           encap_len,
                                           audit_root,
                                           audit_root_len,
                                           capsule_key);
    }
    if (status == SM_OK) {
        if (snapshot.len > (SIZE_MAX - BACKUP_TAG_BYTES)) {
            status = SM_ERR_STORAGE;
        } else {
            ciphertext_capacity = snapshot.len + BACKUP_TAG_BYTES;
            ciphertext = malloc(ciphertext_capacity);
            if (ciphertext == NULL) {
                status = SM_ERR_STORAGE;
            }
        }
    }
    if (status == SM_OK) {
        randombytes_buf(nonce, sizeof(nonce));
        status = backup_build_fixed_header(fixed_header,
                                           sizeof(fixed_header),
                                           algorithm_len,
                                           encap_len,
                                           sizeof(nonce),
                                           audit_root_len,
                                           snapshot.len + BACKUP_TAG_BYTES,
                                           snapshot.len);
    }
    if (status == SM_OK) {
        status = backup_build_aad(&aad,
                                  &aad_len,
                                  fixed_header,
                                  algorithm,
                                  algorithm_len,
                                  encap,
                                  encap_len,
                                  nonce,
                                  sizeof(nonce),
                                  audit_root,
                                  audit_root_len);
    }
    if (status == SM_OK) {
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext,
                &ciphertext_len,
                snapshot.data,
                (unsigned long long)snapshot.len,
                aad,
                (unsigned long long)aad_len,
                NULL,
                nonce,
                capsule_key) != 0) {
            status = SM_ERR_CRYPTO;
        }
    }
    if (status == SM_OK) {
        capsule_len = aad_len;
        status = backup_checked_add(&capsule_len, (size_t)ciphertext_len);
    }
    if (status == SM_OK) {
        capsule = malloc(capsule_len);
        if (capsule == NULL) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        memcpy(capsule, aad, aad_len);
        offset = aad_len;
        memcpy(capsule + offset, ciphertext, (size_t)ciphertext_len);
        status = backup_write_all(capsule_path, capsule, capsule_len);
    }

    EVP_PKEY_free(kem_public_key);
    EVP_PKEY_free(x25519_public_key);
    EVP_PKEY_free(ephemeral_key);
    backup_free_bytes(&snapshot);
    backup_openssl_clear_free(&kem_ct, kem_ct_len);
    backup_openssl_clear_free(&kem_shared_secret, kem_shared_secret_len);
    backup_openssl_clear_free(&x25519_shared_secret, x25519_shared_secret_len);
    backup_openssl_clear_free(&ephemeral_public, ephemeral_public_len);
    if (encap != NULL) {
        sodium_memzero(encap, encap_len);
        free(encap);
    }
    if (aad != NULL) {
        sodium_memzero(aad, aad_len);
        free(aad);
    }
    if (ciphertext != NULL) {
        sodium_memzero(ciphertext, ciphertext_capacity);
        free(ciphertext);
    }
    if (capsule != NULL) {
        sodium_memzero(capsule, capsule_len);
        free(capsule);
    }
    sodium_memzero(fixed_header, sizeof(fixed_header));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(capsule_key, sizeof(capsule_key));
    return status;
}

int backup_pqc_import(const char *private_key_path,
                      const char *private_key_passphrase,
                      const char *capsule_path,
                      const char *output_db_path)
{
    EVP_PKEY *kem_private_key = NULL;
    EVP_PKEY *x25519_private_key = NULL;
    EVP_PKEY *ephemeral_public_key = NULL;
    backup_bytes_t capsule = {NULL, 0U};
    unsigned char *kem_shared_secret = NULL;
    unsigned char *x25519_shared_secret = NULL;
    unsigned char *plaintext = NULL;
    unsigned char capsule_key[BACKUP_KEY_BYTES];
    unsigned char audit_root[AUDIT_MERKLE_ROOT_BYTES];
    const unsigned char *fixed_header = NULL;
    const unsigned char *algorithm = NULL;
    const unsigned char *encap = NULL;
    const unsigned char *ephemeral_public = NULL;
    const unsigned char *kem_ct = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *ciphertext = NULL;
    unsigned long long plaintext_len = 0ULL;
    size_t kem_shared_secret_len = 0U;
    size_t x25519_shared_secret_len = 0U;
    size_t algorithm_len = 0U;
    size_t encap_len = 0U;
    size_t ephemeral_public_len = 0U;
    size_t kem_ct_len = 0U;
    size_t nonce_len = 0U;
    size_t audit_root_len = 0U;
    size_t ciphertext_len = 0U;
    size_t expected_plaintext_len = 0U;
    size_t offset = 0U;
    int status = SM_OK;

    sodium_memzero(capsule_key, sizeof(capsule_key));
    sodium_memzero(audit_root, sizeof(audit_root));
    if ((private_key_path == NULL) ||
        !backup_private_key_passphrase_is_valid(private_key_passphrase) ||
        (capsule_path == NULL) ||
        (output_db_path == NULL) || (output_db_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = backup_read_all(capsule_path, &capsule, BACKUP_MAX_DB_BYTES + 8192ULL);
    if (status != SM_OK) {
        goto cleanup;
    }
    if (capsule.len < BACKUP_FIXED_HEADER_LEN) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    fixed_header = capsule.data;
    if (sodium_memcmp(fixed_header, BACKUP_MAGIC, BACKUP_MAGIC_LEN) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (backup_read_u32_le(fixed_header + 8U) != BACKUP_VERSION) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    algorithm_len = backup_read_u32_le(fixed_header + 12U);
    encap_len = backup_read_u32_le(fixed_header + 16U);
    nonce_len = backup_read_u32_le(fixed_header + 20U);
    audit_root_len = backup_read_u32_le(fixed_header + 24U);
    ciphertext_len = (size_t)backup_read_u64_le(fixed_header + 28U);
    expected_plaintext_len = (size_t)backup_read_u64_le(fixed_header + 36U);
    if ((algorithm_len != strlen(BACKUP_CAPSULE_ALGORITHM)) ||
        (nonce_len != BACKUP_NONCE_BYTES) ||
        (audit_root_len != AUDIT_MERKLE_ROOT_BYTES) ||
        (ciphertext_len < BACKUP_TAG_BYTES) ||
        (expected_plaintext_len != (ciphertext_len - BACKUP_TAG_BYTES))) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }

    offset = BACKUP_FIXED_HEADER_LEN;
    if ((offset > capsule.len) ||
        (algorithm_len > (capsule.len - offset))) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    algorithm = capsule.data + offset;
    offset += algorithm_len;
    if ((algorithm_len != strlen(BACKUP_CAPSULE_ALGORITHM)) ||
        (memcmp(algorithm, BACKUP_CAPSULE_ALGORITHM, algorithm_len) != 0) ||
        (encap_len > (capsule.len - offset))) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    encap = capsule.data + offset;
    offset += encap_len;
    if (nonce_len > (capsule.len - offset)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    nonce = capsule.data + offset;
    offset += nonce_len;
    if (audit_root_len > (capsule.len - offset)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    memcpy(audit_root, capsule.data + offset, sizeof(audit_root));
    offset += audit_root_len;
    if (ciphertext_len != (capsule.len - offset)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    ciphertext = capsule.data + offset;

    status = backup_parse_hybrid_encap(encap,
                                       encap_len,
                                       &ephemeral_public,
                                       &ephemeral_public_len,
                                       &kem_ct,
                                       &kem_ct_len);
    if (status == SM_OK) {
        status = backup_load_private_keypair(private_key_path,
                                             private_key_passphrase,
                                             &kem_private_key,
                                             &x25519_private_key);
    }
    if (status == SM_OK) {
        status = backup_decapsulate(kem_private_key,
                                    kem_ct,
                                    kem_ct_len,
                                    &kem_shared_secret,
                                    &kem_shared_secret_len);
    }
    if (status == SM_OK) {
        status = backup_x25519_public_from_raw(ephemeral_public,
                                               ephemeral_public_len,
                                               &ephemeral_public_key);
    }
    if (status == SM_OK) {
        status = backup_x25519_derive(x25519_private_key,
                                      ephemeral_public_key,
                                      &x25519_shared_secret,
                                      &x25519_shared_secret_len);
    }
    if (status == SM_OK) {
        status = backup_derive_capsule_key(kem_shared_secret,
                                           kem_shared_secret_len,
                                           x25519_shared_secret,
                                           x25519_shared_secret_len,
                                           encap,
                                           encap_len,
                                           audit_root,
                                           sizeof(audit_root),
                                           capsule_key);
    }
    if (status == SM_OK) {
        plaintext = malloc(expected_plaintext_len);
        if (plaintext == NULL) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext,
                &plaintext_len,
                NULL,
                ciphertext,
                (unsigned long long)ciphertext_len,
                capsule.data,
                (unsigned long long)offset,
                nonce,
                capsule_key) != 0) {
            status = SM_ERR_CRYPTO;
        }
    }
    if ((status == SM_OK) && (plaintext_len != expected_plaintext_len)) {
        status = SM_ERR_CRYPTO;
    }
    if (status == SM_OK) {
        status = backup_write_all(output_db_path, plaintext, (size_t)plaintext_len);
    }

cleanup:
    EVP_PKEY_free(kem_private_key);
    EVP_PKEY_free(x25519_private_key);
    EVP_PKEY_free(ephemeral_public_key);
    backup_free_bytes(&capsule);
    backup_openssl_clear_free(&kem_shared_secret, kem_shared_secret_len);
    backup_openssl_clear_free(&x25519_shared_secret, x25519_shared_secret_len);
    if (plaintext != NULL) {
        sodium_memzero(plaintext, expected_plaintext_len);
        free(plaintext);
    }
    sodium_memzero(capsule_key, sizeof(capsule_key));
    sodium_memzero(audit_root, sizeof(audit_root));
    return status;
}

static int backup_load_single_public_key(const char *path, EVP_PKEY **key)
{
    FILE *fp = NULL;

    if ((path == NULL) || (path[0] == '\0') || (key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *key = NULL;
    fp = fopen(path, "rb");
    if (fp == NULL) {
        return SM_ERR_STORAGE;
    }
    *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    (void)fclose(fp);
    return *key == NULL ? SM_ERR_CRYPTO : SM_OK;
}

static int backup_load_single_private_key(const char *path,
                                          const char *passphrase,
                                          EVP_PKEY **key)
{
    FILE *fp = NULL;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') ||
        !backup_private_key_passphrase_is_valid(passphrase) ||
        (key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *key = NULL;
    status = backup_fopen_owner_only_read(path, &fp);
    if (status != SM_OK) {
        return status;
    }
    status = backup_private_key_file_header_is_encrypted(fp);
    if (status != SM_OK) {
        (void)fclose(fp);
        return status;
    }
    *key = PEM_read_PrivateKey(fp, NULL, NULL, (void *)passphrase);
    (void)fclose(fp);
    return *key == NULL ? SM_ERR_CRYPTO : SM_OK;
}

int backup_mldsa_available(void)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, BACKUP_MLDSA_ALGORITHM);
    int available = key != NULL;

    EVP_PKEY_free(key);
    return available;
}

int backup_mldsa_keygen(const char *public_key_path,
                        const char *private_key_path,
                        const char *private_key_passphrase)
{
    EVP_PKEY *key = NULL;
    FILE *public_fp = NULL;
    FILE *private_fp = NULL;
    int status = SM_OK;

    if ((public_key_path == NULL) || (public_key_path[0] == '\0') ||
        (private_key_path == NULL) || (private_key_path[0] == '\0') ||
        !backup_private_key_passphrase_is_valid(private_key_passphrase)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    key = EVP_PKEY_Q_keygen(NULL, NULL, BACKUP_MLDSA_ALGORITHM);
    if (key == NULL) {
        return SM_ERR_CRYPTO;
    }

    private_fp = backup_fopen_exclusive(private_key_path, S_IRUSR | S_IWUSR);
    if (private_fp == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    status = backup_write_encrypted_private_key(private_fp,
                                                key,
                                                private_key_passphrase);
    if (status != SM_OK) {
        goto cleanup;
    }
    if (fclose(private_fp) != 0) {
        private_fp = NULL;
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    private_fp = NULL;

    public_fp = backup_fopen_exclusive(public_key_path,
                                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (public_fp == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (PEM_write_PUBKEY(public_fp, key) != 1) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (fclose(public_fp) != 0) {
        public_fp = NULL;
        status = SM_ERR_STORAGE;
    }
    public_fp = NULL;

cleanup:
    if (public_fp != NULL) {
        (void)fclose(public_fp);
    }
    if (private_fp != NULL) {
        (void)fclose(private_fp);
    }
    EVP_PKEY_free(key);
    if (status != SM_OK) {
        (void)remove(public_key_path);
        (void)remove(private_key_path);
    }
    return status;
}

int backup_mldsa_sign(const char *private_key_path,
                      const char *private_key_passphrase,
                      const unsigned char *message,
                      size_t message_len,
                      unsigned char *signature,
                      size_t signature_len,
                      size_t *written)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t sig_len = signature_len;
    int status = SM_OK;

    if ((message == NULL) || (message_len == 0U) || (signature == NULL) ||
        (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *written = 0U;

    status = backup_load_single_private_key(private_key_path,
                                            private_key_passphrase,
                                            &key);
    if (status != SM_OK) {
        return status;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    /* ML-DSA is a one-shot message signature: no digest is selected. */
    if ((EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1) ||
        (EVP_DigestSign(ctx, signature, &sig_len, message, message_len) != 1)) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    *written = sig_len;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (status != SM_OK) {
        sodium_memzero(signature, signature_len);
    }
    return status;
}

int backup_mldsa_verify(const char *public_key_path,
                        const unsigned char *message,
                        size_t message_len,
                        const unsigned char *signature,
                        size_t signature_len)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    int status = SM_OK;

    if ((message == NULL) || (message_len == 0U) || (signature == NULL) ||
        (signature_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = backup_load_single_public_key(public_key_path, &key);
    if (status != SM_OK) {
        return status;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if ((EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1) ||
        (EVP_DigestVerify(ctx, signature, signature_len, message, message_len) != 1)) {
        status = SM_ERR_CRYPTO;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return status;
}
