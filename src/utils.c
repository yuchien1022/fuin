#define _POSIX_C_SOURCE 200809L

#include "utils.h"

#include <limits.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int utils_init_sodium(void)
{
    if (sodium_init() < 0) {
        return SM_ERR_CRYPTO;
    }

    return SM_OK;
}

void utils_write_u64_le(unsigned char out[8], uint64_t value)
{
    size_t i = 0U;

    for (i = 0U; i < 8U; i++) {
        out[i] = (unsigned char)(value >> (i * 8U));
    }
}

static int utils_format_iso8601(time_t timestamp, char *buffer, size_t buffer_len)
{
    struct tm utc_time;
    int written = 0;

    if ((buffer == NULL) || (buffer_len < UTILS_ISO8601_UTC_BUFFER_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    memset(&utc_time, 0, sizeof(utc_time));
    if (gmtime_r(&timestamp, &utc_time) == NULL) {
        buffer[0] = '\0';
        return SM_ERR_STORAGE;
    }

    written = snprintf(buffer,
                       buffer_len,
                       "%04d-%02d-%02dT%02d:%02d:%02dZ",
                       utc_time.tm_year + 1900,
                       utc_time.tm_mon + 1,
                       utc_time.tm_mday,
                       utc_time.tm_hour,
                       utc_time.tm_min,
                       utc_time.tm_sec);
    if ((written < 0) || ((size_t)written >= buffer_len)) {
        buffer[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }

    return SM_OK;
}

const char *utils_status_message(int status)
{
    switch (status) {
    case SM_OK:
        return "ok";
    case SM_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case SM_ERR_NOT_IMPLEMENTED:
        return "not implemented";
    case SM_ERR_CRYPTO:
        return "crypto error";
    case SM_ERR_STORAGE:
        return "storage error";
    case SM_ERR_AUTH:
        return "authentication error";
    case SM_ERR_NOT_FOUND:
        return "not found";
    case SM_ERR_INPUT_TOO_LARGE:
        return "input too large";
    default:
        return "unknown error";
    }
}

int utils_now_iso8601(char *buffer, size_t buffer_len)
{
    time_t now = (time_t)0;

    if ((buffer == NULL) || (buffer_len < UTILS_ISO8601_UTC_BUFFER_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        buffer[0] = '\0';
        return SM_ERR_STORAGE;
    }

    return utils_format_iso8601(now, buffer, buffer_len);
}

int utils_now_plus_seconds_iso8601(uint64_t seconds,
                                   char *buffer,
                                   size_t buffer_len)
{
    time_t now = (time_t)0;
    time_t offset = (time_t)0;
    time_t expires = (time_t)0;

    if ((buffer == NULL) || (buffer_len < UTILS_ISO8601_UTC_BUFFER_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (seconds > (uint64_t)LONG_MAX) {
        buffer[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        buffer[0] = '\0';
        return SM_ERR_STORAGE;
    }
    offset = (time_t)seconds;
    if (offset < (time_t)0) {
        buffer[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }
    expires = now + offset;
    if (expires < now) {
        buffer[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }

    return utils_format_iso8601(expires, buffer, buffer_len);
}

int utils_base64_encode(const unsigned char *input,
                        size_t input_len,
                        char *output,
                        size_t output_len,
                        size_t *written)
{
    const unsigned char empty = 0U;
    const unsigned char *source = input;
    size_t encoded_len = 0U;
    int status = SM_OK;

    if (((input == NULL) && (input_len > 0U)) ||
        (output == NULL) ||
        (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = 0U;
    status = utils_init_sodium();
    if (status != SM_OK) {
        return status;
    }

    encoded_len = sodium_base64_ENCODED_LEN(input_len, sodium_base64_VARIANT_ORIGINAL);
    if (output_len < encoded_len) {
        if (output_len > 0U) {
            output[0] = '\0';
        }
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (source == NULL) {
        source = &empty;
    }
    if (sodium_bin2base64(output,
                          output_len,
                          source,
                          input_len,
                          sodium_base64_VARIANT_ORIGINAL) == NULL) {
        output[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = strlen(output);
    return SM_OK;
}

int utils_base64_decode(const char *input,
                        unsigned char *output,
                        size_t output_len,
                        size_t *written)
{
    size_t decoded_len = 0U;
    int status = SM_OK;

    if ((input == NULL) || (output == NULL) || (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = 0U;
    status = utils_init_sodium();
    if (status != SM_OK) {
        return status;
    }

    if (sodium_base642bin(output,
                          output_len,
                          input,
                          strlen(input),
                          NULL,
                          &decoded_len,
                          NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        sodium_memzero(output, output_len);
        return SM_ERR_INVALID_ARGUMENT;
    }

    *written = decoded_len;
    return SM_OK;
}

int utils_generate_uuid_v4(char *buffer, size_t buffer_len)
{
    unsigned char uuid[16];
    int status = SM_OK;
    int written = 0;

    if ((buffer == NULL) || (buffer_len < UTILS_UUID_V4_BUFFER_LEN)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = utils_init_sodium();
    if (status != SM_OK) {
        buffer[0] = '\0';
        return status;
    }

    randombytes_buf(uuid, sizeof(uuid));
    uuid[6] = (unsigned char)((uuid[6] & 0x0FU) | 0x40U);
    uuid[8] = (unsigned char)((uuid[8] & 0x3FU) | 0x80U);

    written = snprintf(buffer,
                       buffer_len,
                       "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                       (unsigned int)uuid[0],
                       (unsigned int)uuid[1],
                       (unsigned int)uuid[2],
                       (unsigned int)uuid[3],
                       (unsigned int)uuid[4],
                       (unsigned int)uuid[5],
                       (unsigned int)uuid[6],
                       (unsigned int)uuid[7],
                       (unsigned int)uuid[8],
                       (unsigned int)uuid[9],
                       (unsigned int)uuid[10],
                       (unsigned int)uuid[11],
                       (unsigned int)uuid[12],
                       (unsigned int)uuid[13],
                       (unsigned int)uuid[14],
                       (unsigned int)uuid[15]);
    sodium_memzero(uuid, sizeof(uuid));
    if ((written < 0) || ((size_t)written >= buffer_len)) {
        buffer[0] = '\0';
        return SM_ERR_INVALID_ARGUMENT;
    }

    return SM_OK;
}

int utils_generate_password(char *buffer,
                            size_t buffer_len,
                            size_t password_len,
                            int include_symbols)
{
    /* Symbols avoid quotes, backslash, backtick, and space so generated
       values stay safe to paste into shells and config files. */
    static const char alnum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";
    static const char symbols[] = "!@#$%^&*()-_=+[]{}:;,.?";
    char charset[(sizeof(alnum) - 1U) + (sizeof(symbols) - 1U)];
    size_t charset_len = sizeof(alnum) - 1U;
    size_t i = 0U;
    int status = SM_OK;

    if ((buffer == NULL) || (password_len == 0U) ||
        (buffer_len <= password_len)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = utils_init_sodium();
    if (status != SM_OK) {
        buffer[0] = '\0';
        return status;
    }

    memcpy(charset, alnum, charset_len);
    if (include_symbols) {
        memcpy(charset + charset_len, symbols, sizeof(symbols) - 1U);
        charset_len += sizeof(symbols) - 1U;
    }

    for (i = 0U; i < password_len; i++) {
        /* randombytes_uniform avoids modulo bias over the charset. */
        buffer[i] = charset[randombytes_uniform((uint32_t)charset_len)];
    }
    buffer[password_len] = '\0';
    return SM_OK;
}

int utils_base32_decode(const char *input,
                        size_t input_len,
                        unsigned char *output,
                        size_t output_len,
                        size_t *written)
{
    uint32_t accumulator = 0U;
    size_t bits = 0U;
    size_t out_pos = 0U;
    size_t i = 0U;
    int padding_seen = 0;

    if ((input == NULL) || (output == NULL) || (written == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *written = 0U;

    for (i = 0U; i < input_len; i++) {
        unsigned char c = (unsigned char)input[i];
        uint32_t value = 0U;

        /* Authenticator apps commonly display seeds in spaced groups. */
        if ((c == ' ') || (c == '\n') || (c == '\r') || (c == '\t')) {
            continue;
        }
        if (c == '=') {
            padding_seen = 1;
            continue;
        }
        if (padding_seen) {
            return SM_ERR_INVALID_ARGUMENT;
        }
        if ((c >= 'A') && (c <= 'Z')) {
            value = (uint32_t)(c - 'A');
        } else if ((c >= 'a') && (c <= 'z')) {
            value = (uint32_t)(c - 'a');
        } else if ((c >= '2') && (c <= '7')) {
            value = (uint32_t)(c - '2') + 26U;
        } else {
            return SM_ERR_INVALID_ARGUMENT;
        }

        accumulator = (accumulator << 5U) | value;
        bits += 5U;
        if (bits >= 8U) {
            if (out_pos >= output_len) {
                sodium_memzero(output, output_len);
                return SM_ERR_INVALID_ARGUMENT;
            }
            output[out_pos++] =
                (unsigned char)((accumulator >> (bits - 8U)) & 0xFFU);
            bits -= 8U;
        }
    }

    if (out_pos == 0U) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *written = out_pos;
    return SM_OK;
}

int utils_totp_code(const unsigned char *seed,
                    size_t seed_len,
                    uint64_t unix_time,
                    uint32_t period_seconds,
                    int digits,
                    char *output,
                    size_t output_len)
{
    unsigned char counter_bytes[8];
    unsigned char mac[64];
    size_t mac_len = 0U;
    uint64_t counter = 0U;
    uint32_t binary_code = 0U;
    uint32_t modulus = 1U;
    size_t offset = 0U;
    int i = 0;
    int result = 0;

    if ((seed == NULL) || (seed_len == 0U) || (period_seconds == 0U) ||
        (digits < 6) || (digits > 8) || (output == NULL) ||
        (output_len <= (size_t)digits)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    counter = unix_time / period_seconds;
    for (i = 7; i >= 0; i--) {
        counter_bytes[i] = (unsigned char)(counter & 0xFFU);
        counter >>= 8U;
    }

    /* RFC 6238 defaults to HMAC-SHA1; that is what authenticator apps
       and provisioning URIs assume, so SHA-1's collision weakness is not
       a concern here (HMAC does not rely on collision resistance). */
    if (EVP_Q_mac(NULL,
                  "HMAC",
                  NULL,
                  "SHA1",
                  NULL,
                  seed,
                  seed_len,
                  counter_bytes,
                  sizeof(counter_bytes),
                  mac,
                  sizeof(mac),
                  &mac_len) == NULL ||
        (mac_len < 20U)) {
        sodium_memzero(mac, sizeof(mac));
        sodium_memzero(counter_bytes, sizeof(counter_bytes));
        return SM_ERR_CRYPTO;
    }

    offset = (size_t)(mac[mac_len - 1U] & 0x0FU);
    binary_code = (((uint32_t)mac[offset] & 0x7FU) << 24U) |
                  (((uint32_t)mac[offset + 1U]) << 16U) |
                  (((uint32_t)mac[offset + 2U]) << 8U) |
                  ((uint32_t)mac[offset + 3U]);
    for (i = 0; i < digits; i++) {
        modulus *= 10U;
    }

    result = snprintf(output,
                      output_len,
                      "%0*u",
                      digits,
                      (unsigned int)(binary_code % modulus));
    sodium_memzero(mac, sizeof(mac));
    sodium_memzero(counter_bytes, sizeof(counter_bytes));
    if ((result < 0) || ((size_t)result >= output_len)) {
        sodium_memzero(output, output_len);
        return SM_ERR_INVALID_ARGUMENT;
    }
    return SM_OK;
}
