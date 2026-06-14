#ifndef SECRETS_MANAGER_CRYPTO_ENGINE_H
#define SECRETS_MANAGER_CRYPTO_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#define CRYPTO_ENGINE_ALGORITHM_MAX 32U
#define CRYPTO_ENGINE_ALGORITHM_AES_256_GCM "AES-256-GCM"
#define CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305 "XChaCha20-Poly1305"
#define CRYPTO_ENGINE_ALGORITHM_CHACHA20_POLY1305 "ChaCha20-Poly1305"
#define CRYPTO_ENGINE_ALGORITHM_AEGIS_256 "AEGIS-256"
#define CRYPTO_ENGINE_DEK_BYTES crypto_aead_aes256gcm_KEYBYTES
/* Large enough for the AEGIS-256 256-bit nonce; XChaCha uses 24, AES-GCM 12. */
#define CRYPTO_ENGINE_MAX_NONCE_BYTES 32U

/* Hex length (with NUL) of the per-row identity hash that binds a secret's
   (row id, logical name) into the AEAD AAD. SHA-256 -> 64 hex chars + NUL. */
#define CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN (crypto_hash_sha256_BYTES * 2U + 1U)

/* Key commitment (CMT-1): none of AES-GCM / (X)ChaCha20-Poly1305 / AEGIS
   are key-committing AEADs, so a ciphertext could otherwise decrypt
   validly under more than one key. Each layer stores a keyed BLAKE2b
   commitment binding (key, nonce); decrypt verifies it in constant time
   before using that layer's key. */
#define CRYPTO_ENGINE_COMMITMENT_HALF_BYTES 32U
#define CRYPTO_ENGINE_COMMITMENT_BYTES (2U * CRYPTO_ENGINE_COMMITMENT_HALF_BYTES)
#define CRYPTO_ENGINE_COMMIT_DOMAIN_KEK "Fuin-kek-commit-v1"
#define CRYPTO_ENGINE_COMMIT_DOMAIN_DEK "Fuin-dek-commit-v1"

typedef struct {
    char algorithm[CRYPTO_ENGINE_ALGORITHM_MAX];
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *encrypted_dek;
    size_t encrypted_dek_len;
    unsigned char nonce[CRYPTO_ENGINE_MAX_NONCE_BYTES];
    size_t nonce_len;
    unsigned char dek_nonce[CRYPTO_ENGINE_MAX_NONCE_BYTES];
    size_t dek_nonce_len;
    /* [0..32) commits the KEK over dek_nonce; [32..64) commits the DEK
       over the payload nonce. */
    unsigned char key_commitment[CRYPTO_ENGINE_COMMITMENT_BYTES];
    size_t key_commitment_len;
} encrypted_secret_t;

int crypto_engine_init(void);
int crypto_engine_algorithm_available(const char *algorithm);
/* Builds the per-row AAD identity = hex(SHA-256(domain || len(id)||id ||
   len(name)||name)) into identity (capacity >= CRYPTO_ENGINE_ROW_IDENTITY_HEX_LEN).
   This is the secret_id passed to encrypt/decrypt; vault reads/writes and
   key_manager KEK-rotation MUST derive it identically, so it lives in one
   place here rather than being recomputed per caller. */
int crypto_engine_build_row_identity(const char *id,
                                     const char *name,
                                     char *identity,
                                     size_t identity_len);
/* output receives owned buffers; release them with crypto_engine_free_encrypted_secret(). */
int crypto_engine_encrypt(const unsigned char *plaintext,
                          size_t plaintext_len,
                          const unsigned char *kek_enc,
                          const char *secret_id,
                          uint32_t version,
                          uint64_t nonce_counter,
                          encrypted_secret_t *output);
int crypto_engine_encrypt_with_algorithm(const unsigned char *plaintext,
                                         size_t plaintext_len,
                                         const unsigned char *kek_enc,
                                         const char *secret_id,
                                         uint32_t version,
                                         uint64_t nonce_counter,
                                         const char *algorithm,
                                         encrypted_secret_t *output);
/* *plaintext_len is input capacity on call and actual plaintext length on success. */
int crypto_engine_decrypt(const encrypted_secret_t *input,
                          const unsigned char *kek_enc,
                          const char *secret_id,
                          uint32_t version,
                          unsigned char *plaintext,
                          size_t *plaintext_len);
int crypto_engine_compute_key_commitment(const unsigned char *key,
                                         size_t key_len,
                                         const char *domain,
                                         const unsigned char *nonce,
                                         size_t nonce_len,
                                         unsigned char *out,
                                         size_t out_len);
void crypto_engine_free_encrypted_secret(encrypted_secret_t *secret);
int crypto_engine_shutdown(void);

#endif
