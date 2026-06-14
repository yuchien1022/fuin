#include "crypto_engine.h"

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRYPTO_ENGINE_AAD_MAX 256U

/* AEGIS-256 ships with libsodium >= 1.0.19; older builds (e.g. Debian
   bookworm's 1.0.18) simply do not offer the algorithm. SM_DISABLE_AEGIS
   lets CI compile-check the fallback path on a new libsodium. */
#if defined(crypto_aead_aegis256_KEYBYTES) && !defined(SM_DISABLE_AEGIS)
#define CRYPTO_ENGINE_HAS_AEGIS 1
#endif

typedef enum {
    CRYPTO_ENGINE_ALG_AES_256_GCM = 1,
    CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305 = 2,
    CRYPTO_ENGINE_ALG_AEGIS_256 = 3
} crypto_engine_algorithm_t;

static int crypto_engine_build_aad(char *aad,
                                   size_t aad_len,
                                   const char *secret_id,
                                   uint32_t version,
                                   size_t *written)
{
    int result = 0;

    if ((aad == NULL) || (secret_id == NULL) || (written == NULL)) {
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

static int crypto_engine_init_sodium(void)
{
    if (sodium_init() < 0) {
        return SM_ERR_CRYPTO;
    }

    return SM_OK;
}

static crypto_engine_algorithm_t crypto_engine_select_default_algorithm(void)
{
#ifdef CRYPTO_ENGINE_HAS_AEGIS
    return CRYPTO_ENGINE_ALG_AEGIS_256;
#else
    return CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305;
#endif
}

static int crypto_engine_algorithm_equals_literal(const char *left,
                                                  const char *right,
                                                  size_t right_len)
{
    size_t i = 0;

    if ((left == NULL) || (right == NULL) || (right_len >= CRYPTO_ENGINE_ALGORITHM_MAX)) {
        return 0;
    }

    for (i = 0; i < CRYPTO_ENGINE_ALGORITHM_MAX; i++) {
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

static int crypto_engine_algorithm_from_name(const char *name,
                                             crypto_engine_algorithm_t *algorithm)
{
    if ((name == NULL) || (algorithm == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (crypto_engine_algorithm_equals_literal(name,
                                               CRYPTO_ENGINE_ALGORITHM_AES_256_GCM,
                                               sizeof(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) - 1U)) {
        *algorithm = CRYPTO_ENGINE_ALG_AES_256_GCM;
        return SM_OK;
    }

    if (crypto_engine_algorithm_equals_literal(name,
                                               CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305,
                                               sizeof(CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) - 1U) ||
        crypto_engine_algorithm_equals_literal(name,
                                               CRYPTO_ENGINE_ALGORITHM_CHACHA20_POLY1305,
                                               sizeof(CRYPTO_ENGINE_ALGORITHM_CHACHA20_POLY1305) - 1U)) {
        *algorithm = CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305;
        return SM_OK;
    }

#ifdef CRYPTO_ENGINE_HAS_AEGIS
    if (crypto_engine_algorithm_equals_literal(name,
                                               CRYPTO_ENGINE_ALGORITHM_AEGIS_256,
                                               sizeof(CRYPTO_ENGINE_ALGORITHM_AEGIS_256) - 1U)) {
        *algorithm = CRYPTO_ENGINE_ALG_AEGIS_256;
        return SM_OK;
    }
#endif

    return SM_ERR_INVALID_ARGUMENT;
}

static int crypto_engine_algorithm_is_available(crypto_engine_algorithm_t algorithm)
{
    if ((algorithm == CRYPTO_ENGINE_ALG_AES_256_GCM) &&
        (crypto_aead_aes256gcm_is_available() != 1)) {
        return SM_ERR_CRYPTO;
    }

    return SM_OK;
}

static int crypto_engine_select_algorithm(const char *name,
                                          crypto_engine_algorithm_t *algorithm)
{
    int status = SM_OK;

    if (algorithm == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (name == NULL) {
        *algorithm = crypto_engine_select_default_algorithm();
        return SM_OK;
    }
    if (name[0] == '\0') {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = crypto_engine_algorithm_from_name(name, algorithm);
    if (status == SM_OK) {
        status = crypto_engine_algorithm_is_available(*algorithm);
    }
    return status;
}

static int crypto_engine_set_algorithm_name(encrypted_secret_t *output,
                                            crypto_engine_algorithm_t algorithm)
{
    const char *name = NULL;
    int result = 0;

    switch (algorithm) {
    case CRYPTO_ENGINE_ALG_AES_256_GCM:
        name = CRYPTO_ENGINE_ALGORITHM_AES_256_GCM;
        break;
#ifdef CRYPTO_ENGINE_HAS_AEGIS
    case CRYPTO_ENGINE_ALG_AEGIS_256:
        name = CRYPTO_ENGINE_ALGORITHM_AEGIS_256;
        break;
#endif
    default:
        name = CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305;
        break;
    }
    result = snprintf(output->algorithm, sizeof(output->algorithm), "%s", name);

    return (result < 0) || ((size_t)result >= sizeof(output->algorithm))
               ? SM_ERR_INVALID_ARGUMENT
               : SM_OK;
}

int crypto_engine_build_row_identity(const char *id,
                                     const char *name,
                                     char *identity,
                                     size_t identity_len)
{
    static const unsigned char domain[] = "Fuin secret row identity v1";
    crypto_hash_sha256_state state;
    unsigned char digest[crypto_hash_sha256_BYTES];
    unsigned char length[8];
    size_t id_len = 0U;
    size_t name_len = 0U;
    int status = SM_OK;

    if ((id == NULL) || (id[0] == '\0') ||
        (name == NULL) || (name[0] == '\0') ||
        (identity == NULL) ||
        (identity_len < CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    id_len = strlen(id);
    name_len = strlen(name);
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(length, sizeof(length));

    if (crypto_hash_sha256_init(&state) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_hash_sha256_update(&state, domain, sizeof(domain) - 1U) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    utils_write_u64_le(length, (uint64_t)id_len);
    if (crypto_hash_sha256_update(&state, length, sizeof(length)) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_hash_sha256_update(&state,
                                  (const unsigned char *)id,
                                  id_len) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    utils_write_u64_le(length, (uint64_t)name_len);
    if (crypto_hash_sha256_update(&state, length, sizeof(length)) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_hash_sha256_update(&state,
                                  (const unsigned char *)name,
                                  name_len) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_hash_sha256_final(&state, digest) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (sodium_bin2hex(identity, identity_len, digest, sizeof(digest)) == NULL) {
        status = SM_ERR_STORAGE;
    }

cleanup:
    if (status != SM_OK) {
        sodium_memzero(identity, identity_len);
    }
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(length, sizeof(length));
    return status;
}

static size_t crypto_engine_nonce_bytes(crypto_engine_algorithm_t algorithm)
{
    switch (algorithm) {
    case CRYPTO_ENGINE_ALG_AES_256_GCM:
        return crypto_aead_aes256gcm_NPUBBYTES;
#ifdef CRYPTO_ENGINE_HAS_AEGIS
    case CRYPTO_ENGINE_ALG_AEGIS_256:
        return crypto_aead_aegis256_NPUBBYTES;
#endif
    default:
        return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    }
}

static int crypto_engine_build_nonce(crypto_engine_algorithm_t algorithm,
                                     const char *secret_id,
                                     uint64_t nonce_counter,
                                     unsigned char *nonce,
                                     size_t *nonce_len)
{
    unsigned char hash[crypto_hash_sha256_BYTES];

    if ((secret_id == NULL) || (nonce == NULL) || (nonce_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (algorithm == CRYPTO_ENGINE_ALG_AES_256_GCM) {
        if (crypto_hash_sha256(hash,
                               (const unsigned char *)secret_id,
                               (unsigned long long)strlen(secret_id)) != 0) {
            sodium_memzero(hash, sizeof(hash));
            return SM_ERR_CRYPTO;
        }
        memcpy(nonce, hash, 4U);
        utils_write_u64_le(nonce + 4U, nonce_counter);
        *nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
    } else {
        /* XChaCha (192-bit) and AEGIS-256 (256-bit) nonces are large
           enough that random generation cannot realistically collide. */
        (void)nonce_counter;
        *nonce_len = crypto_engine_nonce_bytes(algorithm);
        randombytes_buf(nonce, *nonce_len);
    }

    sodium_memzero(hash, sizeof(hash));
    return SM_OK;
}

static size_t crypto_engine_tag_bytes(crypto_engine_algorithm_t algorithm)
{
    switch (algorithm) {
    case CRYPTO_ENGINE_ALG_AES_256_GCM:
        return crypto_aead_aes256gcm_ABYTES;
#ifdef CRYPTO_ENGINE_HAS_AEGIS
    case CRYPTO_ENGINE_ALG_AEGIS_256:
        return crypto_aead_aegis256_ABYTES;
#endif
    default:
        return crypto_aead_xchacha20poly1305_ietf_ABYTES;
    }
}

/* Keyed BLAKE2b over (domain || nonce): a binding commitment to the key
   used at one envelope layer. Verified before the key is trusted, which
   upgrades the non-committing AEADs to key-committing behavior (CMT-1). */
static int crypto_engine_commitment(const unsigned char *key,
                                    size_t key_len,
                                    const char *domain,
                                    const unsigned char *nonce,
                                    size_t nonce_len,
                                    unsigned char *out)
{
    crypto_generichash_state state;
    int status = SM_OK;

    if ((key == NULL) || (domain == NULL) || (nonce == NULL) || (out == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((crypto_generichash_init(&state,
                                 key,
                                 key_len,
                                 CRYPTO_ENGINE_COMMITMENT_HALF_BYTES) != 0) ||
        (crypto_generichash_update(&state,
                                   (const unsigned char *)domain,
                                   (unsigned long long)strlen(domain)) != 0) ||
        (crypto_generichash_update(&state,
                                   nonce,
                                   (unsigned long long)nonce_len) != 0) ||
        (crypto_generichash_final(&state,
                                  out,
                                  CRYPTO_ENGINE_COMMITMENT_HALF_BYTES) != 0)) {
        status = SM_ERR_CRYPTO;
    }

    sodium_memzero(&state, sizeof(state));
    return status;
}

static unsigned char *crypto_engine_alloc_key(void)
{
    unsigned char *key = sodium_malloc(CRYPTO_ENGINE_DEK_BYTES);

    if (key == NULL) {
        return NULL;
    }

    if (sodium_mlock(key, CRYPTO_ENGINE_DEK_BYTES) != 0) {
        sodium_memzero(key, CRYPTO_ENGINE_DEK_BYTES);
        sodium_free(key);
        return NULL;
    }

    return key;
}

static void crypto_engine_free_key(unsigned char **key)
{
    if ((key == NULL) || (*key == NULL)) {
        return;
    }

    sodium_memzero(*key, CRYPTO_ENGINE_DEK_BYTES);
    (void)sodium_munlock(*key, CRYPTO_ENGINE_DEK_BYTES);
    sodium_free(*key);
    *key = NULL;
}

static int crypto_engine_encrypt_payload(crypto_engine_algorithm_t algorithm,
                                         unsigned char *ciphertext,
                                         unsigned long long *ciphertext_len,
                                         const unsigned char *plaintext,
                                         size_t plaintext_len,
                                         const unsigned char *aad,
                                         size_t aad_len,
                                         const unsigned char *nonce,
                                         const unsigned char *key)
{
    if (algorithm == CRYPTO_ENGINE_ALG_AES_256_GCM) {
        return crypto_aead_aes256gcm_encrypt(ciphertext,
                                             ciphertext_len,
                                             plaintext,
                                             (unsigned long long)plaintext_len,
                                             aad,
                                             (unsigned long long)aad_len,
                                             NULL,
                                             nonce,
                                             key) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }

#ifdef CRYPTO_ENGINE_HAS_AEGIS
    if (algorithm == CRYPTO_ENGINE_ALG_AEGIS_256) {
        return crypto_aead_aegis256_encrypt(ciphertext,
                                            ciphertext_len,
                                            plaintext,
                                            (unsigned long long)plaintext_len,
                                            aad,
                                            (unsigned long long)aad_len,
                                            NULL,
                                            nonce,
                                            key) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }
#endif

    return crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext,
                                                      ciphertext_len,
                                                      plaintext,
                                                      (unsigned long long)plaintext_len,
                                                      aad,
                                                      (unsigned long long)aad_len,
                                                      NULL,
                                                      nonce,
                                                      key) == 0
               ? SM_OK
               : SM_ERR_CRYPTO;
}

static int crypto_engine_decrypt_payload(crypto_engine_algorithm_t algorithm,
                                         unsigned char *plaintext,
                                         unsigned long long *plaintext_len,
                                         const unsigned char *ciphertext,
                                         size_t ciphertext_len,
                                         const unsigned char *aad,
                                         size_t aad_len,
                                         const unsigned char *nonce,
                                         const unsigned char *key)
{
    if (algorithm == CRYPTO_ENGINE_ALG_AES_256_GCM) {
        return crypto_aead_aes256gcm_decrypt(plaintext,
                                             plaintext_len,
                                             NULL,
                                             ciphertext,
                                             (unsigned long long)ciphertext_len,
                                             aad,
                                             (unsigned long long)aad_len,
                                             nonce,
                                             key) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }

#ifdef CRYPTO_ENGINE_HAS_AEGIS
    if (algorithm == CRYPTO_ENGINE_ALG_AEGIS_256) {
        return crypto_aead_aegis256_decrypt(plaintext,
                                            plaintext_len,
                                            NULL,
                                            ciphertext,
                                            (unsigned long long)ciphertext_len,
                                            aad,
                                            (unsigned long long)aad_len,
                                            nonce,
                                            key) == 0
                   ? SM_OK
                   : SM_ERR_CRYPTO;
    }
#endif

    return crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext,
                                                      plaintext_len,
                                                      NULL,
                                                      ciphertext,
                                                      (unsigned long long)ciphertext_len,
                                                      aad,
                                                      (unsigned long long)aad_len,
                                                      nonce,
                                                      key) == 0
               ? SM_OK
               : SM_ERR_CRYPTO;
}

int crypto_engine_init(void)
{
    return crypto_engine_init_sodium();
}

int crypto_engine_algorithm_available(const char *algorithm)
{
    crypto_engine_algorithm_t selected = CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305;
    int status = crypto_engine_init_sodium();

    if (status == SM_OK) {
        status = crypto_engine_select_algorithm(algorithm, &selected);
    }
    return status;
}

int crypto_engine_encrypt(const unsigned char *plaintext,
                          size_t plaintext_len,
                          const unsigned char *kek_enc,
                          const char *secret_id,
                          uint32_t version,
                          uint64_t nonce_counter,
                          encrypted_secret_t *output)
{
    return crypto_engine_encrypt_with_algorithm(plaintext,
                                                plaintext_len,
                                                kek_enc,
                                                secret_id,
                                                version,
                                                nonce_counter,
                                                NULL,
                                                output);
}

int crypto_engine_encrypt_with_algorithm(const unsigned char *plaintext,
                                         size_t plaintext_len,
                                         const unsigned char *kek_enc,
                                         const char *secret_id,
                                         uint32_t version,
                                         uint64_t nonce_counter,
                                         const char *algorithm_name,
                                         encrypted_secret_t *output)
{
    encrypted_secret_t temp;
    crypto_engine_algorithm_t algorithm = CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305;
    unsigned char *dek = NULL;
    char aad[CRYPTO_ENGINE_AAD_MAX];
    size_t aad_len = 0U;
    size_t tag_len = 0U;
    unsigned long long written = 0U;
    int status = SM_OK;

    memset(&temp, 0, sizeof(temp));
    sodium_memzero(aad, sizeof(aad));

    if (((plaintext == NULL) && (plaintext_len > 0U)) ||
        (kek_enc == NULL) ||
        (secret_id == NULL) ||
        (secret_id[0] == '\0') ||
        (output == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = crypto_engine_init_sodium();
    if (status != SM_OK) {
        return status;
    }

    status = crypto_engine_build_aad(aad, sizeof(aad), secret_id, version, &aad_len);
    if (status != SM_OK) {
        return status;
    }

    status = crypto_engine_select_algorithm(algorithm_name, &algorithm);
    if (status != SM_OK) {
        sodium_memzero(aad, sizeof(aad));
        return status;
    }
    tag_len = crypto_engine_tag_bytes(algorithm);
    if (plaintext_len > (SIZE_MAX - tag_len)) {
        sodium_memzero(aad, sizeof(aad));
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = crypto_engine_set_algorithm_name(&temp, algorithm);
    if (status == SM_OK) {
        status = crypto_engine_build_nonce(algorithm,
                                           secret_id,
                                           nonce_counter,
                                           temp.nonce,
                                           &temp.nonce_len);
    }
    if (status != SM_OK) {
        sodium_memzero(aad, sizeof(aad));
        return status;
    }

    temp.ciphertext_len = plaintext_len + tag_len;
    temp.encrypted_dek_len = CRYPTO_ENGINE_DEK_BYTES + tag_len;
    temp.ciphertext = sodium_malloc(temp.ciphertext_len);
    temp.encrypted_dek = sodium_malloc(temp.encrypted_dek_len);
    dek = crypto_engine_alloc_key();
    if ((temp.ciphertext == NULL) || (temp.encrypted_dek == NULL) || (dek == NULL)) {
        crypto_engine_free_encrypted_secret(&temp);
        crypto_engine_free_key(&dek);
        sodium_memzero(aad, sizeof(aad));
        return SM_ERR_STORAGE;
    }

    randombytes_buf(dek, CRYPTO_ENGINE_DEK_BYTES);
    status = crypto_engine_encrypt_payload(algorithm,
                                           temp.ciphertext,
                                           &written,
                                           plaintext,
                                           plaintext_len,
                                           (const unsigned char *)aad,
                                           aad_len,
                                           temp.nonce,
                                           dek);
    if (status == SM_OK) {
        temp.ciphertext_len = (size_t)written;
        temp.dek_nonce_len = crypto_engine_nonce_bytes(algorithm);
        randombytes_buf(temp.dek_nonce, temp.dek_nonce_len);
        status = crypto_engine_encrypt_payload(algorithm,
                                               temp.encrypted_dek,
                                               &written,
                                               dek,
                                               CRYPTO_ENGINE_DEK_BYTES,
                                               (const unsigned char *)aad,
                                               aad_len,
                                               temp.dek_nonce,
                                               kek_enc);
    }
    if (status == SM_OK) {
        status = crypto_engine_commitment(kek_enc,
                                          CRYPTO_ENGINE_DEK_BYTES,
                                          CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
                                          temp.dek_nonce,
                                          temp.dek_nonce_len,
                                          temp.key_commitment);
    }
    if (status == SM_OK) {
        status = crypto_engine_commitment(
            dek,
            CRYPTO_ENGINE_DEK_BYTES,
            CRYPTO_ENGINE_COMMIT_DOMAIN_DEK,
            temp.nonce,
            temp.nonce_len,
            temp.key_commitment + CRYPTO_ENGINE_COMMITMENT_HALF_BYTES);
        temp.key_commitment_len = CRYPTO_ENGINE_COMMITMENT_BYTES;
    }

    crypto_engine_free_key(&dek);
    sodium_memzero(aad, sizeof(aad));

    if (status != SM_OK) {
        crypto_engine_free_encrypted_secret(&temp);
        return status;
    }

    temp.encrypted_dek_len = (size_t)written;
    *output = temp;
    return SM_OK;
}

int crypto_engine_decrypt(const encrypted_secret_t *input,
                          const unsigned char *kek_enc,
                          const char *secret_id,
                          uint32_t version,
                          unsigned char *plaintext,
                          size_t *plaintext_len)
{
    crypto_engine_algorithm_t algorithm = CRYPTO_ENGINE_ALG_XCHACHA20_POLY1305;
    unsigned char *dek = NULL;
    unsigned char commitment[CRYPTO_ENGINE_COMMITMENT_HALF_BYTES];
    char aad[CRYPTO_ENGINE_AAD_MAX];
    size_t aad_len = 0U;
    size_t tag_len = 0U;
    size_t plaintext_capacity = 0U;
    unsigned long long written = 0U;
    int status = SM_OK;

    sodium_memzero(aad, sizeof(aad));
    sodium_memzero(commitment, sizeof(commitment));

    if ((input == NULL) ||
        (input->ciphertext == NULL) ||
        (input->encrypted_dek == NULL) ||
        (kek_enc == NULL) ||
        (secret_id == NULL) ||
        (secret_id[0] == '\0') ||
        (plaintext == NULL) ||
        (plaintext_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    plaintext_capacity = *plaintext_len;
    status = crypto_engine_init_sodium();
    if (status == SM_OK) {
        status = crypto_engine_algorithm_from_name(input->algorithm, &algorithm);
    }
    if (status == SM_OK) {
        status = crypto_engine_algorithm_is_available(algorithm);
    }
    if (status == SM_OK) {
        status = crypto_engine_build_aad(aad, sizeof(aad), secret_id, version, &aad_len);
    }
    if (status != SM_OK) {
        sodium_memzero(aad, sizeof(aad));
        return status;
    }

    tag_len = crypto_engine_tag_bytes(algorithm);
    if ((input->ciphertext_len < tag_len) ||
        (input->encrypted_dek_len != (CRYPTO_ENGINE_DEK_BYTES + tag_len)) ||
        (input->nonce_len != crypto_engine_nonce_bytes(algorithm)) ||
        (input->dek_nonce_len != input->nonce_len) ||
        (input->key_commitment_len != CRYPTO_ENGINE_COMMITMENT_BYTES) ||
        (plaintext_capacity < (input->ciphertext_len - tag_len))) {
        sodium_memzero(aad, sizeof(aad));
        return SM_ERR_INVALID_ARGUMENT;
    }

    /* Verify the KEK commitment before trusting the unwrap result. */
    status = crypto_engine_commitment(kek_enc,
                                      CRYPTO_ENGINE_DEK_BYTES,
                                      CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
                                      input->dek_nonce,
                                      input->dek_nonce_len,
                                      commitment);
    if ((status == SM_OK) &&
        (sodium_memcmp(commitment,
                       input->key_commitment,
                       CRYPTO_ENGINE_COMMITMENT_HALF_BYTES) != 0)) {
        status = SM_ERR_CRYPTO;
    }
    if (status != SM_OK) {
        sodium_memzero(commitment, sizeof(commitment));
        sodium_memzero(aad, sizeof(aad));
        sodium_memzero(plaintext, plaintext_capacity);
        return status;
    }

    dek = crypto_engine_alloc_key();
    if (dek == NULL) {
        sodium_memzero(commitment, sizeof(commitment));
        sodium_memzero(aad, sizeof(aad));
        return SM_ERR_STORAGE;
    }

    status = crypto_engine_decrypt_payload(algorithm,
                                           dek,
                                           &written,
                                           input->encrypted_dek,
                                           input->encrypted_dek_len,
                                           (const unsigned char *)aad,
                                           aad_len,
                                           input->dek_nonce,
                                           kek_enc);
    if ((status != SM_OK) || (written != CRYPTO_ENGINE_DEK_BYTES)) {
        crypto_engine_free_key(&dek);
        sodium_memzero(commitment, sizeof(commitment));
        sodium_memzero(aad, sizeof(aad));
        sodium_memzero(plaintext, plaintext_capacity);
        return status == SM_OK ? SM_ERR_CRYPTO : status;
    }

    /* Verify the DEK commitment before decrypting the payload with it. */
    status = crypto_engine_commitment(dek,
                                      CRYPTO_ENGINE_DEK_BYTES,
                                      CRYPTO_ENGINE_COMMIT_DOMAIN_DEK,
                                      input->nonce,
                                      input->nonce_len,
                                      commitment);
    if ((status == SM_OK) &&
        (sodium_memcmp(commitment,
                       input->key_commitment +
                           CRYPTO_ENGINE_COMMITMENT_HALF_BYTES,
                       CRYPTO_ENGINE_COMMITMENT_HALF_BYTES) != 0)) {
        status = SM_ERR_CRYPTO;
    }
    if (status != SM_OK) {
        crypto_engine_free_key(&dek);
        sodium_memzero(commitment, sizeof(commitment));
        sodium_memzero(aad, sizeof(aad));
        sodium_memzero(plaintext, plaintext_capacity);
        return status;
    }

    status = crypto_engine_decrypt_payload(algorithm,
                                           plaintext,
                                           &written,
                                           input->ciphertext,
                                           input->ciphertext_len,
                                           (const unsigned char *)aad,
                                           aad_len,
                                           input->nonce,
                                           dek);
    crypto_engine_free_key(&dek);
    sodium_memzero(commitment, sizeof(commitment));
    sodium_memzero(aad, sizeof(aad));
    if (status != SM_OK) {
        sodium_memzero(plaintext, plaintext_capacity);
        return status;
    }

    *plaintext_len = (size_t)written;
    return SM_OK;
}

int crypto_engine_compute_key_commitment(const unsigned char *key,
                                         size_t key_len,
                                         const char *domain,
                                         const unsigned char *nonce,
                                         size_t nonce_len,
                                         unsigned char *out,
                                         size_t out_len)
{
    int status = crypto_engine_init_sodium();

    if (status != SM_OK) {
        return status;
    }
    if ((out == NULL) || (out_len != CRYPTO_ENGINE_COMMITMENT_HALF_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return crypto_engine_commitment(key, key_len, domain, nonce, nonce_len, out);
}

void crypto_engine_free_encrypted_secret(encrypted_secret_t *secret)
{
    if (secret == NULL) {
        return;
    }

    if (secret->ciphertext != NULL) {
        sodium_memzero(secret->ciphertext, secret->ciphertext_len);
        sodium_free(secret->ciphertext);
    }
    if (secret->encrypted_dek != NULL) {
        sodium_memzero(secret->encrypted_dek, secret->encrypted_dek_len);
        sodium_free(secret->encrypted_dek);
    }

    sodium_memzero(secret, sizeof(*secret));
}

int crypto_engine_shutdown(void)
{
    return SM_OK;
}
