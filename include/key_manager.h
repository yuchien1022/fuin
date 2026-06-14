#ifndef SECRETS_MANAGER_KEY_MANAGER_H
#define SECRETS_MANAGER_KEY_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>
#include <sqlite3.h>

#define KEY_MANAGER_DEK_BYTES crypto_aead_aes256gcm_KEYBYTES
/* Sized for AEGIS-256: 256-bit nonce and 256-bit tag. */
#define KEY_MANAGER_MAX_NONCE_BYTES 32U
#define KEY_MANAGER_MAX_TAG_BYTES 32U
#define KEY_MANAGER_WRAPPED_DEK_BYTES \
    (KEY_MANAGER_DEK_BYTES + KEY_MANAGER_MAX_TAG_BYTES)

int key_manager_generate_dek(unsigned char *dek, size_t dek_len);
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
                         size_t *written);
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
                           size_t *written);
/* Caller owns the surrounding SQLite transaction for atomic metadata/audit updates. */
int key_manager_rotate_kek(sqlite3 *db,
                           const unsigned char *old_kek,
                           size_t old_kek_len,
                           const unsigned char *new_kek,
                           size_t new_kek_len);

#endif
