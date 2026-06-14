#define _POSIX_C_SOURCE 200809L

#include "access.h"

#include "cJSON.h"
#include "utils.h"

#include <limits.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ACCESS_TOKEN_PREFIX "fu1."
#define ACCESS_TOKEN_PREFIX_LEN 4U
#define ACCESS_NONCE_BYTES 16U
#define ACCESS_MAX_JSON_SECONDS 9007199254740991.0

static int access_init_sodium(void)
{
    return sodium_init() < 0 ? SM_ERR_CRYPTO : SM_OK;
}

static int access_copy_claim(char *output,
                             size_t output_len,
                             const char *input)
{
    int written = 0;

    if ((output == NULL) || (output_len == 0U) ||
        (input == NULL) || (input[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    written = snprintf(output, output_len, "%s", input);
    return (written < 0) || ((size_t)written >= output_len)
               ? SM_ERR_INVALID_ARGUMENT
               : SM_OK;
}

static int access_now(uint64_t *now)
{
    time_t current = (time_t)0;

    if (now == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    current = time(NULL);
    if ((current == (time_t)-1) || (current < (time_t)0)) {
        return SM_ERR_STORAGE;
    }

    *now = (uint64_t)current;
    return SM_OK;
}

static int access_make_nonce_b64(char *nonce_b64, size_t nonce_b64_len)
{
    unsigned char nonce[ACCESS_NONCE_BYTES];
    size_t written = 0U;
    int status = SM_OK;

    if ((nonce_b64 == NULL) || (nonce_b64_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    randombytes_buf(nonce, sizeof(nonce));
    status = utils_base64_encode(nonce,
                                 sizeof(nonce),
                                 nonce_b64,
                                 nonce_b64_len,
                                 &written);
    sodium_memzero(nonce, sizeof(nonce));
    return status;
}

static int access_validate_key(const unsigned char *kek_token, size_t kek_token_len)
{
    if ((kek_token == NULL) || (kek_token_len != crypto_auth_KEYBYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return SM_OK;
}

static int access_build_payload(const char *subject,
                                const char *scope,
                                uint64_t issued_at,
                                uint64_t expires_at,
                                char **payload,
                                size_t *payload_len)
{
    char nonce_b64[sodium_base64_ENCODED_LEN(ACCESS_NONCE_BYTES,
                                             sodium_base64_VARIANT_ORIGINAL)];
    cJSON *root = NULL;
    char *printed = NULL;
    int status = SM_OK;

    if ((subject == NULL) || (scope == NULL) || (payload == NULL) ||
        (payload_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *payload = NULL;
    *payload_len = 0U;
    sodium_memzero(nonce_b64, sizeof(nonce_b64));

    status = access_make_nonce_b64(nonce_b64, sizeof(nonce_b64));
    if (status != SM_OK) {
        return status;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        sodium_memzero(nonce_b64, sizeof(nonce_b64));
        return SM_ERR_STORAGE;
    }
    if ((cJSON_AddNumberToObject(root, "v", 1.0) == NULL) ||
        (cJSON_AddStringToObject(root, "sub", subject) == NULL) ||
        (cJSON_AddStringToObject(root, "scope", scope) == NULL) ||
        (cJSON_AddNumberToObject(root, "iat", (double)issued_at) == NULL) ||
        (cJSON_AddNumberToObject(root, "exp", (double)expires_at) == NULL) ||
        (cJSON_AddStringToObject(root, "nonce", nonce_b64) == NULL)) {
        status = SM_ERR_STORAGE;
    }
    if (status == SM_OK) {
        printed = cJSON_PrintUnformatted(root);
        if (printed == NULL) {
            status = SM_ERR_STORAGE;
        }
    }

    cJSON_Delete(root);
    sodium_memzero(nonce_b64, sizeof(nonce_b64));
    if (status != SM_OK) {
        cJSON_free(printed);
        return status;
    }

    *payload = printed;
    *payload_len = strlen(printed);
    return SM_OK;
}

static int access_b64_encode_alloc(const unsigned char *input,
                                   size_t input_len,
                                   char **encoded)
{
    size_t encoded_len = 0U;
    size_t written = 0U;
    int status = SM_OK;

    if (((input == NULL) && (input_len > 0U)) || (encoded == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *encoded = NULL;

    encoded_len = sodium_base64_ENCODED_LEN(input_len,
                                            sodium_base64_VARIANT_ORIGINAL);
    *encoded = malloc(encoded_len);
    if (*encoded == NULL) {
        return SM_ERR_STORAGE;
    }

    status = utils_base64_encode(input,
                                 input_len,
                                 *encoded,
                                 encoded_len,
                                 &written);
    if (status != SM_OK) {
        sodium_memzero(*encoded, encoded_len);
        free(*encoded);
        *encoded = NULL;
    }
    return status;
}

static int access_compose_token(const char *payload_b64,
                                const char *signature_b64,
                                char *token,
                                size_t token_len)
{
    int written = 0;

    if ((payload_b64 == NULL) || (signature_b64 == NULL) ||
        (token == NULL) || (token_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    written = snprintf(token,
                       token_len,
                       "%s%s.%s",
                       ACCESS_TOKEN_PREFIX,
                       payload_b64,
                       signature_b64);
    return (written < 0) || ((size_t)written >= token_len)
               ? SM_ERR_INVALID_ARGUMENT
               : SM_OK;
}

static int access_extract_token_parts(const char *token,
                                      char **payload_b64,
                                      char **signature_b64)
{
    const char *payload_start = NULL;
    const char *payload_end = NULL;
    const char *signature_start = NULL;
    size_t token_len = 0U;
    size_t payload_len = 0U;
    size_t signature_len = 0U;

    if ((token == NULL) || (payload_b64 == NULL) || (signature_b64 == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *payload_b64 = NULL;
    *signature_b64 = NULL;
    token_len = strlen(token);
    if ((token_len <= ACCESS_TOKEN_PREFIX_LEN) ||
        (token_len > ACCESS_TOKEN_BUFFER_LEN) ||
        (strncmp(token, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_PREFIX_LEN) != 0)) {
        return SM_ERR_AUTH;
    }

    payload_start = token + ACCESS_TOKEN_PREFIX_LEN;
    payload_end = strchr(payload_start, '.');
    if ((payload_end == NULL) || (payload_end == payload_start)) {
        return SM_ERR_AUTH;
    }
    signature_start = payload_end + 1;
    if ((signature_start[0] == '\0') || (strchr(signature_start, '.') != NULL)) {
        return SM_ERR_AUTH;
    }

    payload_len = (size_t)(payload_end - payload_start);
    signature_len = strlen(signature_start);
    *payload_b64 = malloc(payload_len + 1U);
    *signature_b64 = malloc(signature_len + 1U);
    if ((*payload_b64 == NULL) || (*signature_b64 == NULL)) {
        free(*payload_b64);
        free(*signature_b64);
        *payload_b64 = NULL;
        *signature_b64 = NULL;
        return SM_ERR_STORAGE;
    }

    memcpy(*payload_b64, payload_start, payload_len);
    (*payload_b64)[payload_len] = '\0';
    memcpy(*signature_b64, signature_start, signature_len + 1U);
    return SM_OK;
}

static int access_decode_payload(const char *payload_b64,
                                 unsigned char **payload,
                                 size_t *payload_len)
{
    size_t input_len = 0U;
    size_t written = 0U;
    int status = SM_OK;

    if ((payload_b64 == NULL) || (payload == NULL) || (payload_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *payload = NULL;
    *payload_len = 0U;

    input_len = strlen(payload_b64);
    if ((input_len == 0U) || (input_len > ACCESS_TOKEN_BUFFER_LEN)) {
        return SM_ERR_AUTH;
    }
    *payload = malloc(input_len + 1U);
    if (*payload == NULL) {
        return SM_ERR_STORAGE;
    }

    status = utils_base64_decode(payload_b64, *payload, input_len, &written);
    if (status != SM_OK) {
        sodium_memzero(*payload, input_len + 1U);
        free(*payload);
        *payload = NULL;
        return SM_ERR_AUTH;
    }
    (*payload)[written] = '\0';
    *payload_len = written;
    return SM_OK;
}

static int access_decode_signature(const char *signature_b64,
                                   unsigned char *signature,
                                   size_t signature_len)
{
    unsigned char decoded[crypto_auth_BYTES];
    size_t written = 0U;
    int status = SM_OK;

    if ((signature_b64 == NULL) || (signature == NULL) ||
        (signature_len != crypto_auth_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(decoded, sizeof(decoded));
    status = utils_base64_decode(signature_b64,
                                 decoded,
                                 sizeof(decoded),
                                 &written);
    if ((status != SM_OK) || (written != crypto_auth_BYTES)) {
        sodium_memzero(decoded, sizeof(decoded));
        return SM_ERR_AUTH;
    }

    memcpy(signature, decoded, sizeof(decoded));
    sodium_memzero(decoded, sizeof(decoded));
    return SM_OK;
}

static int access_json_uint64(cJSON *root, const char *name, uint64_t *value)
{
    cJSON *item = NULL;
    double number = 0.0;

    if ((root == NULL) || (name == NULL) || (value == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(item)) {
        return SM_ERR_AUTH;
    }
    number = item->valuedouble;
    if ((number < 0.0) || (number > ACCESS_MAX_JSON_SECONDS)) {
        return SM_ERR_AUTH;
    }

    *value = (uint64_t)number;
    return SM_OK;
}

static int access_json_string(cJSON *root,
                              const char *name,
                              char *output,
                              size_t output_len)
{
    cJSON *item = NULL;

    if ((root == NULL) || (name == NULL) || (output == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(item) || (item->valuestring == NULL)) {
        return SM_ERR_AUTH;
    }
    return access_copy_claim(output, output_len, item->valuestring);
}

static int access_parse_claims(const unsigned char *payload,
                               size_t payload_len,
                               access_token_claims_t *claims)
{
    cJSON *root = NULL;
    cJSON *version = NULL;
    cJSON *nonce = NULL;
    unsigned char nonce_bytes[ACCESS_NONCE_BYTES];
    size_t nonce_len = 0U;
    int status = SM_OK;

    if ((payload == NULL) || (payload_len == 0U) || (claims == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(claims, sizeof(*claims));
    sodium_memzero(nonce_bytes, sizeof(nonce_bytes));
    root = cJSON_ParseWithLength((const char *)payload, payload_len);
    if (root == NULL) {
        return SM_ERR_AUTH;
    }

    version = cJSON_GetObjectItemCaseSensitive(root, "v");
    if (!cJSON_IsNumber(version) || (version->valueint != 1)) {
        status = SM_ERR_AUTH;
    }
    if (status == SM_OK) {
        status = access_json_string(root,
                                    "sub",
                                    claims->subject,
                                    sizeof(claims->subject));
    }
    if (status == SM_OK) {
        status = access_json_string(root,
                                    "scope",
                                    claims->scope,
                                    sizeof(claims->scope));
    }
    if (status == SM_OK) {
        status = access_json_uint64(root, "iat", &claims->issued_at);
    }
    if (status == SM_OK) {
        status = access_json_uint64(root, "exp", &claims->expires_at);
    }
    if ((status == SM_OK) && (claims->expires_at <= claims->issued_at)) {
        status = SM_ERR_AUTH;
    }
    if (status == SM_OK) {
        nonce = cJSON_GetObjectItemCaseSensitive(root, "nonce");
        if (!cJSON_IsString(nonce) || (nonce->valuestring == NULL)) {
            status = SM_ERR_AUTH;
        } else {
            status = utils_base64_decode(nonce->valuestring,
                                         nonce_bytes,
                                         sizeof(nonce_bytes),
                                         &nonce_len);
            if ((status != SM_OK) || (nonce_len != ACCESS_NONCE_BYTES)) {
                status = SM_ERR_AUTH;
            }
        }
    }

    cJSON_Delete(root);
    sodium_memzero(nonce_bytes, sizeof(nonce_bytes));
    if (status != SM_OK) {
        sodium_memzero(claims, sizeof(*claims));
    }
    return status;
}

static int access_resource_matches(const char *allowed,
                                   size_t allowed_len,
                                   const char *required)
{
    size_t required_len = 0U;

    if ((allowed == NULL) || (required == NULL)) {
        return 0;
    }
    if ((allowed_len == 1U) && (allowed[0] == '*')) {
        return 1;
    }
    required_len = strlen(required);
    if ((allowed_len > 0U) && (allowed[allowed_len - 1U] == '*')) {
        size_t prefix_len = allowed_len - 1U;

        if (strncmp(allowed, required, prefix_len) != 0) {
            return 0;
        }
        /* A trailing star spans at most one path segment: unless the literal
           prefix already ends with a slash, the next required character must
           be a slash or end-of-string. So a "db/" pattern matches "db/prod",
           but a bare "db" pattern does NOT match "db-secret" (it matches only
           "db" or a "db/" child). */
        if ((prefix_len > 0U) && (allowed[prefix_len - 1U] != '/')) {
            char next = required[prefix_len];

            if ((next != '\0') && (next != '/')) {
                return 0;
            }
        }
        return 1;
    }

    return (allowed_len == required_len) &&
           (strncmp(allowed, required, required_len) == 0);
}

static int access_one_scope_allows(const char *token_scope,
                                   size_t token_scope_len,
                                   const char *required_scope)
{
    const char *token_colon = NULL;
    const char *required_colon = NULL;
    const char *token_resource = NULL;
    const char *required_resource = NULL;
    size_t token_action_len = 0U;
    size_t required_action_len = 0U;
    size_t token_resource_len = 0U;

    if ((token_scope == NULL) || (token_scope_len == 0U) ||
        (required_scope == NULL)) {
        return 0;
    }
    if ((token_scope_len == 1U) && (token_scope[0] == '*')) {
        return 1;
    }

    token_colon = memchr(token_scope, ':', token_scope_len);
    required_colon = strchr(required_scope, ':');
    if ((token_colon == NULL) || (required_colon == NULL)) {
        return 0;
    }
    token_action_len = (size_t)(token_colon - token_scope);
    required_action_len = (size_t)(required_colon - required_scope);
    if ((token_action_len == 0U) || (required_action_len == 0U)) {
        return 0;
    }

    if (!((token_action_len == 1U && token_scope[0] == '*') ||
          ((token_action_len == required_action_len) &&
           (strncmp(token_scope, required_scope, required_action_len) == 0)))) {
        return 0;
    }

    token_resource = token_colon + 1;
    required_resource = required_colon + 1;
    token_resource_len = token_scope_len - token_action_len - 1U;
    return access_resource_matches(token_resource,
                                   token_resource_len,
                                   required_resource);
}

int access_scope_allows(const char *token_scope, const char *required_scope)
{
    const char *cursor = token_scope;
    const char *comma = NULL;
    size_t scope_len = 0U;

    if ((token_scope == NULL) || (token_scope[0] == '\0') ||
        (required_scope == NULL) || (required_scope[0] == '\0')) {
        return 0;
    }

    while (*cursor != '\0') {
        comma = strchr(cursor, ',');
        scope_len = comma == NULL ? strlen(cursor) : (size_t)(comma - cursor);
        if (access_one_scope_allows(cursor, scope_len, required_scope)) {
            return 1;
        }
        if (comma == NULL) {
            break;
        }
        cursor = comma + 1;
    }

    return 0;
}

int access_issue_token(const char *subject,
                       const char *scope,
                       uint64_t ttl_seconds,
                       const unsigned char *kek_token,
                       size_t kek_token_len,
                       char *token,
                       size_t token_len)
{
    char subject_copy[ACCESS_SUBJECT_MAX];
    char scope_copy[ACCESS_SCOPE_MAX];
    char *payload = NULL;
    char *payload_b64 = NULL;
    char *signature_b64 = NULL;
    unsigned char signature[crypto_auth_BYTES];
    uint64_t issued_at = 0U;
    uint64_t expires_at = 0U;
    size_t payload_len = 0U;
    int status = SM_OK;

    sodium_memzero(subject_copy, sizeof(subject_copy));
    sodium_memzero(scope_copy, sizeof(scope_copy));
    sodium_memzero(signature, sizeof(signature));
    if (token != NULL && token_len > 0U) {
        token[0] = '\0';
    }

    if ((subject == NULL) || (scope == NULL) || (ttl_seconds == 0U) ||
        (token == NULL) || (token_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = access_validate_key(kek_token, kek_token_len);
    if (status != SM_OK) {
        return status;
    }
    status = access_init_sodium();
    if (status != SM_OK) {
        return status;
    }
    status = access_copy_claim(subject_copy, sizeof(subject_copy), subject);
    if (status == SM_OK) {
        status = access_copy_claim(scope_copy, sizeof(scope_copy), scope);
    }
    if (status == SM_OK) {
        status = access_now(&issued_at);
    }
    if ((status == SM_OK) && (ttl_seconds > (UINT64_MAX - issued_at))) {
        status = SM_ERR_INVALID_ARGUMENT;
    }
    if (status == SM_OK) {
        expires_at = issued_at + ttl_seconds;
        if ((double)expires_at > ACCESS_MAX_JSON_SECONDS) {
            status = SM_ERR_INVALID_ARGUMENT;
        }
    }
    if (status == SM_OK) {
        status = access_build_payload(subject_copy,
                                      scope_copy,
                                      issued_at,
                                      expires_at,
                                      &payload,
                                      &payload_len);
    }
    if (status == SM_OK) {
        if (crypto_auth(signature,
                        (const unsigned char *)payload,
                        (unsigned long long)payload_len,
                        kek_token) != 0) {
            status = SM_ERR_CRYPTO;
        }
    }
    if (status == SM_OK) {
        status = access_b64_encode_alloc((const unsigned char *)payload,
                                         payload_len,
                                         &payload_b64);
    }
    if (status == SM_OK) {
        status = access_b64_encode_alloc(signature,
                                         sizeof(signature),
                                         &signature_b64);
    }
    if (status == SM_OK) {
        status = access_compose_token(payload_b64,
                                      signature_b64,
                                      token,
                                      token_len);
    }

    if (payload != NULL) {
        sodium_memzero(payload, payload_len);
        cJSON_free(payload);
    }
    if (payload_b64 != NULL) {
        sodium_memzero(payload_b64, strlen(payload_b64));
        free(payload_b64);
    }
    if (signature_b64 != NULL) {
        sodium_memzero(signature_b64, strlen(signature_b64));
        free(signature_b64);
    }
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(subject_copy, sizeof(subject_copy));
    sodium_memzero(scope_copy, sizeof(scope_copy));
    if ((status != SM_OK) && (token != NULL) && (token_len > 0U)) {
        token[0] = '\0';
    }
    return status;
}

int access_verify_token(const char *token,
                        const char *required_scope,
                        const unsigned char *kek_token,
                        size_t kek_token_len,
                        access_token_claims_t *claims)
{
    access_token_claims_t parsed;
    char *payload_b64 = NULL;
    char *signature_b64 = NULL;
    unsigned char *payload = NULL;
    unsigned char signature[crypto_auth_BYTES];
    size_t payload_len = 0U;
    uint64_t now = 0U;
    int status = SM_OK;

    sodium_memzero(&parsed, sizeof(parsed));
    sodium_memzero(signature, sizeof(signature));
    if (claims != NULL) {
        sodium_memzero(claims, sizeof(*claims));
    }

    if ((token == NULL) || (token[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = access_validate_key(kek_token, kek_token_len);
    if (status != SM_OK) {
        return status;
    }
    status = access_init_sodium();
    if (status == SM_OK) {
        status = access_extract_token_parts(token, &payload_b64, &signature_b64);
    }
    if (status == SM_OK) {
        status = access_decode_payload(payload_b64, &payload, &payload_len);
    }
    if (status == SM_OK) {
        status = access_decode_signature(signature_b64,
                                         signature,
                                         sizeof(signature));
    }
    if (status == SM_OK) {
        if (crypto_auth_verify(signature,
                               payload,
                               (unsigned long long)payload_len,
                               kek_token) != 0) {
            status = SM_ERR_AUTH;
        }
    }
    if (status == SM_OK) {
        status = access_parse_claims(payload, payload_len, &parsed);
    }
    if (status == SM_OK) {
        status = access_now(&now);
    }
    if ((status == SM_OK) && (now >= parsed.expires_at)) {
        status = SM_ERR_AUTH;
    }
    if ((status == SM_OK) && (required_scope != NULL) &&
        (required_scope[0] != '\0') &&
        !access_scope_allows(parsed.scope, required_scope)) {
        status = SM_ERR_AUTH;
    }
    if ((status == SM_OK) && (claims != NULL)) {
        *claims = parsed;
    }

    free(payload_b64);
    free(signature_b64);
    if (payload != NULL) {
        sodium_memzero(payload, payload_len + 1U);
        free(payload);
    }
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(&parsed, sizeof(parsed));
    return status;
}
