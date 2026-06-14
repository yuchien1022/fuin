#ifndef SECRETS_MANAGER_AUDIT_H
#define SECRETS_MANAGER_AUDIT_H

#include <stddef.h>

#define AUDIT_MERKLE_ROOT_BYTES 32U
#define AUDIT_MERKLE_PROOF_MAX_HASHES 64U
#define AUDIT_MERKLE_PROOF_MAX_BYTES \
    (AUDIT_MERKLE_ROOT_BYTES * AUDIT_MERKLE_PROOF_MAX_HASHES)

int audit_log_event(const char *actor,
                    const char *action,
                    const char *target,
                    int target_version,
                    const char *result,
                    const unsigned char *audit_key,
                    size_t audit_key_len);
int audit_verify_chain(const unsigned char *audit_key, size_t audit_key_len);
int audit_resign_chain(const unsigned char *audit_key, size_t audit_key_len);
int audit_get_last_hash(unsigned char *hash, size_t hash_len);
int audit_get_entry_hash(int entry_id, unsigned char *hash, size_t hash_len);
int audit_compute_merkle_root(unsigned char *root,
                              size_t root_len,
                              size_t *leaf_count);
int audit_build_merkle_proof(int entry_id,
                             unsigned char *proof,
                             size_t proof_capacity,
                             size_t *proof_len,
                             size_t *leaf_index,
                             size_t *leaf_count);
int audit_verify_merkle_proof(const unsigned char *entry_hash,
                              size_t entry_hash_len,
                              size_t leaf_index,
                              size_t leaf_count,
                              const unsigned char *proof,
                              size_t proof_len,
                              const unsigned char *root,
                              size_t root_len);

#endif
