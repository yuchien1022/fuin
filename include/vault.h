#ifndef SECRETS_MANAGER_VAULT_H
#define SECRETS_MANAGER_VAULT_H

#include <stdint.h>
#include <stddef.h>

#define VAULT_NAME_LOOKUP_HEX_LEN 65U

typedef int (*vault_expiry_callback_t)(const char *name,
                                       int version,
                                       const char *expires_at,
                                       int is_expired,
                                       void *user_data);

typedef struct {
    const char *name;
    int version;
    const char *algorithm;
    const char *created_at;
    const char *updated_at;
    const char *expires_at;
    uint64_t rotation_interval_seconds;
    int is_archived;
    int is_expired;
} vault_list_item_t;

typedef int (*vault_list_callback_t)(const vault_list_item_t *item,
                                     void *user_data);

typedef struct {
    size_t distinct_names;
    size_t active_secrets;
    size_t archived_versions;
    size_t total_versions;
    size_t deleted_names;
    size_t ttl_active;
    size_t expired_active;
    size_t expiring_7d;
    size_t active_aes256gcm;
    size_t active_xchacha20poly1305;
    size_t active_aegis256;
    size_t audit_entries;
    size_t audit_leaf_count;
    unsigned char audit_root[32];
} vault_security_report_t;

int vault_init(const char *db_path);
int vault_open(const char *db_path);
int vault_unlock(const char *master_password);
int vault_unlock_existing(const char *master_password);
int vault_put(const char *name,
              const unsigned char *secret,
              size_t secret_len);
int vault_put_with_algorithm(const char *name,
                             const unsigned char *secret,
                             size_t secret_len,
                             const char *algorithm);
int vault_put_with_options(const char *name,
                           const unsigned char *secret,
                           size_t secret_len,
                           const char *algorithm,
                           uint64_t ttl_seconds);
int vault_get(const char *name,
              unsigned char *output,
              size_t output_len,
              size_t *written);
int vault_get_version(const char *name,
                      int version,
                      unsigned char *output,
                      size_t output_len,
                      size_t *written);
int vault_delete(const char *name);
int vault_list_secrets(int include_archived,
                       vault_list_callback_t callback,
                       void *user_data,
                       size_t *matched_count);
int vault_security_report(vault_security_report_t *report);
int vault_backup_keygen(const char *public_key_path,
                        const char *private_key_path,
                        const char *private_key_passphrase);
int vault_backup_export(const char *recipient_public_key_path,
                        const char *capsule_path);
int vault_backup_import(const char *private_key_path,
                        const char *private_key_passphrase,
                        const char *capsule_path,
                        const char *output_db_path);
int vault_audit_signing_keygen(const char *public_key_path,
                               const char *private_key_path,
                               const char *private_key_passphrase);
int vault_audit_sign_root(const char *private_key_path,
                          const char *private_key_passphrase,
                          unsigned char *root,
                          size_t root_len,
                          size_t *leaf_count,
                          unsigned char *signature,
                          size_t signature_len,
                          size_t *signature_written);
int vault_audit_verify(void);
int vault_audit_merkle_root(unsigned char *root,
                            size_t root_len,
                            size_t *leaf_count);
int vault_audit_merkle_proof(int entry_id,
                             unsigned char *entry_hash,
                             size_t entry_hash_len,
                             unsigned char *root,
                             size_t root_len,
                             unsigned char *proof,
                             size_t proof_capacity,
                             size_t *proof_len,
                             size_t *leaf_index,
                             size_t *leaf_count);
int vault_audit_verify_merkle_proof(int entry_id,
                                    const unsigned char *root,
                                    size_t root_len,
                                    const unsigned char *proof,
                                    size_t proof_len,
                                    size_t leaf_index,
                                    size_t leaf_count);
int vault_rollback(const char *name, int version);
int vault_get_active_version(const char *name, int *version);
int vault_rotate_kek(const char *new_master_password);
int vault_check_expiry(uint64_t within_seconds,
                       vault_expiry_callback_t callback,
                       void *user_data,
                       size_t *matched_count);
int vault_auto_rotate_expired(size_t *rotated_count);
int vault_issue_token(const char *subject,
                      const char *scope,
                      uint64_t ttl_seconds,
                      char *token,
                      size_t token_len);
int vault_check_token(const char *token, const char *required_scope);
int vault_revoke_tokens(void);
int vault_debug_name_lookup(const char *name, char *lookup_hex, size_t lookup_hex_len);
int vault_close(void);

#endif
