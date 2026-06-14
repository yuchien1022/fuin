#ifndef SECRETS_MANAGER_KDF_H
#define SECRETS_MANAGER_KDF_H

#include <sodium.h>

#define KDF_MASTER_KEY_BYTES crypto_kdf_KEYBYTES
#define KDF_SALT_BYTES crypto_pwhash_SALTBYTES

typedef struct {
    unsigned char kek_enc[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char kek_audit[crypto_auth_KEYBYTES];
    unsigned char kek_token[crypto_auth_KEYBYTES];
    unsigned char kek_meta[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
} kdf_subkeys_t;

int kdf_generate_salt(unsigned char *salt);
/* Caller must allocate master_key with sodium_malloc(KDF_MASTER_KEY_BYTES). */
int kdf_derive_master_key(char *password,
                          const unsigned char *salt,
                          unsigned char *master_key);
/* master_key is consumed and securely cleared by this call. */
int kdf_derive_subkeys(unsigned char *master_key, kdf_subkeys_t *subkeys);

#endif
