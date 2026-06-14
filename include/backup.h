#ifndef SECRETS_MANAGER_BACKUP_H
#define SECRETS_MANAGER_BACKUP_H

#include <stddef.h>

#include <sqlite3.h>

#define BACKUP_PQC_KEM_ALGORITHM "ML-KEM-768"
#define BACKUP_CLASSICAL_KEX_ALGORITHM "X25519"
#define BACKUP_CAPSULE_ALGORITHM "X25519+ML-KEM-768"
#define BACKUP_MLDSA_ALGORITHM "ML-DSA-65"
/* ML-DSA-65 signatures are 3309 bytes; leave headroom. */
#define BACKUP_MLDSA_SIGNATURE_MAX_BYTES 4096U

int backup_pqc_available(void);
int backup_mldsa_available(void);
int backup_mldsa_keygen(const char *public_key_path,
                        const char *private_key_path,
                        const char *private_key_passphrase);
int backup_mldsa_sign(const char *private_key_path,
                      const char *private_key_passphrase,
                      const unsigned char *message,
                      size_t message_len,
                      unsigned char *signature,
                      size_t signature_len,
                      size_t *written);
int backup_mldsa_verify(const char *public_key_path,
                        const unsigned char *message,
                        size_t message_len,
                        const unsigned char *signature,
                        size_t signature_len);
int backup_pqc_keygen(const char *public_key_path,
                      const char *private_key_path,
                      const char *private_key_passphrase);
int backup_pqc_export(sqlite3 *source_db,
                      const char *recipient_public_key_path,
                      const char *capsule_path,
                      const unsigned char *audit_root,
                      size_t audit_root_len);
int backup_pqc_import(const char *private_key_path,
                      const char *private_key_passphrase,
                      const char *capsule_path,
                      const char *output_db_path);

#endif
