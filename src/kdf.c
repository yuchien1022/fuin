#include "kdf.h"

#include "utils.h"

#include <stdint.h>
#include <string.h>

#define KDF_OPSLIMIT 3U
#define KDF_MEMLIMIT 67108864U

static const char kdf_context[crypto_kdf_CONTEXTBYTES] = {
    'F', 'u', 'i', 'n', 'S', 'e', 'a', 'l'
};

static int kdf_init_sodium(void)
{
    return sodium_init() < 0 ? SM_ERR_CRYPTO : SM_OK;
}

static void kdf_clear_password(char *password, size_t password_len)
{
    if (password != NULL) {
        sodium_memzero(password, password_len);
    }
}

static int kdf_fail_master_key(char *password,
                               size_t password_len,
                               unsigned char *master_key,
                               int status)
{
    kdf_clear_password(password, password_len);
    if (master_key != NULL) {
        sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    }
    return status;
}

static int kdf_fail_subkeys(unsigned char *master_key,
                            kdf_subkeys_t *subkeys,
                            int status)
{
    if (master_key != NULL) {
        sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    }
    if (subkeys != NULL) {
        sodium_memzero(subkeys, sizeof(*subkeys));
    }
    return status;
}

static int kdf_derive_subkey(unsigned char *subkey,
                             size_t subkey_len,
                             uint64_t subkey_id,
                             const unsigned char *master_key)
{
    return crypto_kdf_derive_from_key(subkey,
                                      subkey_len,
                                      subkey_id,
                                      kdf_context,
                                      master_key) == 0
               ? SM_OK
               : SM_ERR_CRYPTO;
}

int kdf_generate_salt(unsigned char *salt)
{
    int status = SM_OK;

    if (salt == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = kdf_init_sodium();
    if (status != SM_OK) {
        return status;
    }

    randombytes_buf(salt, KDF_SALT_BYTES);
    return SM_OK;
}

int kdf_derive_master_key(char *password,
                          const unsigned char *salt,
                          unsigned char *master_key)
{
    size_t password_len = password == NULL ? 0U : strlen(password);
    int status = SM_OK;

    if ((password == NULL) || (salt == NULL) || (master_key == NULL)) {
        return kdf_fail_master_key(password,
                                   password_len,
                                   master_key,
                                   SM_ERR_INVALID_ARGUMENT);
    }

    status = kdf_init_sodium();
    if (status != SM_OK) {
        return kdf_fail_master_key(password, password_len, master_key, status);
    }

    if (crypto_pwhash(master_key,
                      KDF_MASTER_KEY_BYTES,
                      password,
                      (unsigned long long)password_len,
                      salt,
                      KDF_OPSLIMIT,
                      KDF_MEMLIMIT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return kdf_fail_master_key(password,
                                   password_len,
                                   master_key,
                                   SM_ERR_CRYPTO);
    }

    kdf_clear_password(password, password_len);
    return SM_OK;
}

int kdf_derive_subkeys(unsigned char *master_key, kdf_subkeys_t *subkeys)
{
    int status = SM_OK;

    if ((master_key == NULL) || (subkeys == NULL)) {
        return kdf_fail_subkeys(master_key, subkeys, SM_ERR_INVALID_ARGUMENT);
    }

    sodium_memzero(subkeys, sizeof(*subkeys));

    status = kdf_init_sodium();
    if (status != SM_OK) {
        return kdf_fail_subkeys(master_key, subkeys, status);
    }

    status = kdf_derive_subkey(subkeys->kek_enc,
                               sizeof(subkeys->kek_enc),
                               1U,
                               master_key);
    if (status == SM_OK) {
        status = kdf_derive_subkey(subkeys->kek_audit,
                                   sizeof(subkeys->kek_audit),
                                   2U,
                                   master_key);
    }
    if (status == SM_OK) {
        status = kdf_derive_subkey(subkeys->kek_token,
                                   sizeof(subkeys->kek_token),
                                   3U,
                                   master_key);
    }
    if (status == SM_OK) {
        status = kdf_derive_subkey(subkeys->kek_meta,
                                   sizeof(subkeys->kek_meta),
                                   4U,
                                   master_key);
    }

    sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    if (status != SM_OK) {
        sodium_memzero(subkeys, sizeof(*subkeys));
    }

    return status;
}
