#include "access.h"
#include "utils.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int test_issue_and_verify_token(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    char token[ACCESS_TOKEN_BUFFER_LEN];
    access_token_claims_t claims;
    int ok = 0;

    randombytes_buf(key, sizeof(key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(&claims, sizeof(claims));

    if (access_issue_token("user:default",
                           "read:database/*",
                           3600U,
                           key,
                           sizeof(key),
                           token,
                           sizeof(token)) != SM_OK) {
        printf("test_issue_and_verify_token: issue failed\n");
        sodium_memzero(key, sizeof(key));
        return 1;
    }
    if (access_verify_token(token,
                            "read:database/prod",
                            key,
                            sizeof(key),
                            &claims) != SM_OK) {
        printf("test_issue_and_verify_token: verify failed\n");
        sodium_memzero(key, sizeof(key));
        sodium_memzero(token, sizeof(token));
        return 1;
    }

    ok = (strcmp(claims.subject, "user:default") == 0) &&
         (strcmp(claims.scope, "read:database/*") == 0) &&
         (claims.expires_at > claims.issued_at);
    if (!ok) {
        printf("test_issue_and_verify_token: claims mismatch\n");
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(&claims, sizeof(claims));
    return ok ? 0 : 1;
}

static int test_scope_matching(void)
{
    int ok = 1;

    ok = ok && access_scope_allows("read:database/*",
                                   "read:database/prod");
    ok = ok && access_scope_allows("read:database/prod,write:cache/*",
                                   "write:cache/redis");
    ok = ok && access_scope_allows("*:service/*",
                                   "delete:service/api/key");
    ok = ok && access_scope_allows("*", "read:anything");
    ok = ok && !access_scope_allows("read:database/*",
                                    "write:database/prod");
    ok = ok && !access_scope_allows("read:database/prod",
                                    "read:database/prod/child");
    ok = ok && !access_scope_allows("read:database/*",
                                    "read:cache/prod");
    ok = ok && !access_scope_allows("read:db*", "read:db-secret");
    ok = ok && access_scope_allows("read:db*", "read:db/prod");
    ok = ok && access_scope_allows("read:db*", "read:db");
    ok = ok && !access_scope_allows(NULL, "read:database/prod");
    ok = ok && !access_scope_allows("read:database/*", NULL);

    if (!ok) {
        printf("test_scope_matching: scope mismatch\n");
    }
    return ok ? 0 : 1;
}

static int test_verify_rejects_tamper_and_wrong_scope(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char other_key[crypto_auth_KEYBYTES];
    char token[ACCESS_TOKEN_BUFFER_LEN];
    char tampered[ACCESS_TOKEN_BUFFER_LEN];
    size_t token_len = 0U;
    int ok = 1;

    randombytes_buf(key, sizeof(key));
    randombytes_buf(other_key, sizeof(other_key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(tampered, sizeof(tampered));

    if (access_issue_token("svc",
                           "read:database/prod",
                           3600U,
                           key,
                           sizeof(key),
                           token,
                           sizeof(token)) != SM_OK) {
        printf("test_verify_rejects_tamper_and_wrong_scope: issue failed\n");
        sodium_memzero(key, sizeof(key));
        sodium_memzero(other_key, sizeof(other_key));
        return 1;
    }

    ok = ok && (access_verify_token(token,
                                    "write:database/prod",
                                    key,
                                    sizeof(key),
                                    NULL) == SM_ERR_AUTH);
    ok = ok && (access_verify_token(token,
                                    "read:database/prod",
                                    other_key,
                                    sizeof(other_key),
                                    NULL) == SM_ERR_AUTH);

    token_len = strlen(token);
    if (token_len >= sizeof(tampered)) {
        ok = 0;
    } else {
        memcpy(tampered, token, token_len + 1U);
        tampered[token_len - 1U] =
            tampered[token_len - 1U] == 'A' ? 'B' : 'A';
        ok = ok && (access_verify_token(tampered,
                                        "read:database/prod",
                                        key,
                                        sizeof(key),
                                        NULL) == SM_ERR_AUTH);
    }

    if (!ok) {
        printf("test_verify_rejects_tamper_and_wrong_scope: expected auth failures\n");
    }
    sodium_memzero(key, sizeof(key));
    sodium_memzero(other_key, sizeof(other_key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(tampered, sizeof(tampered));
    return ok ? 0 : 1;
}

static int test_invalid_args(void)
{
    unsigned char key[crypto_auth_KEYBYTES];
    char token[ACCESS_TOKEN_BUFFER_LEN];
    char small_token[16];
    int ok = 1;

    randombytes_buf(key, sizeof(key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(small_token, sizeof(small_token));

    ok = ok && (access_issue_token(NULL,
                                   "read:*",
                                   1U,
                                   key,
                                   sizeof(key),
                                   token,
                                   sizeof(token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_issue_token("subject",
                                   NULL,
                                   1U,
                                   key,
                                   sizeof(key),
                                   token,
                                   sizeof(token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_issue_token("subject",
                                   "read:*",
                                   0U,
                                   key,
                                   sizeof(key),
                                   token,
                                   sizeof(token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_issue_token("subject",
                                   "read:*",
                                   1U,
                                   NULL,
                                   sizeof(key),
                                   token,
                                   sizeof(token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_issue_token("subject",
                                   "read:*",
                                   1U,
                                   key,
                                   sizeof(key) - 1U,
                                   token,
                                   sizeof(token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_issue_token("subject",
                                   "read:*",
                                   1U,
                                   key,
                                   sizeof(key),
                                   small_token,
                                   sizeof(small_token)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_verify_token(NULL,
                                    "read:*",
                                    key,
                                    sizeof(key),
                                    NULL) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (access_verify_token("not-a-token",
                                    "read:*",
                                    key,
                                    sizeof(key),
                                    NULL) == SM_ERR_AUTH);

    if (!ok) {
        printf("test_invalid_args: expected invalid argument/auth failures\n");
    }
    sodium_memzero(key, sizeof(key));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(small_token, sizeof(small_token));
    return ok ? 0 : 1;
}

int test_access_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_access_run: sodium_init failed\n");
        return 1;
    }

    failed += test_issue_and_verify_token();
    failed += test_scope_matching();
    failed += test_verify_rejects_tamper_and_wrong_scope();
    failed += test_invalid_args();

    if (failed != 0) {
        printf("test_access_run: %d failures\n", failed);
    }
    return failed == 0 ? 0 : 1;
}
