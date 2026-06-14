#ifndef SECRETS_MANAGER_ACCESS_H
#define SECRETS_MANAGER_ACCESS_H

#include <stdint.h>
#include <stddef.h>

#define ACCESS_SUBJECT_MAX 128U
#define ACCESS_SCOPE_MAX 256U
#define ACCESS_TOKEN_BUFFER_LEN 2048U

typedef struct {
    char subject[ACCESS_SUBJECT_MAX];
    char scope[ACCESS_SCOPE_MAX];
    uint64_t issued_at;
    uint64_t expires_at;
} access_token_claims_t;

int access_issue_token(const char *subject,
                       const char *scope,
                       uint64_t ttl_seconds,
                       const unsigned char *kek_token,
                       size_t kek_token_len,
                       char *token,
                       size_t token_len);
int access_verify_token(const char *token,
                        const char *required_scope,
                        const unsigned char *kek_token,
                        size_t kek_token_len,
                        access_token_claims_t *claims);
int access_scope_allows(const char *token_scope, const char *required_scope);

#endif
