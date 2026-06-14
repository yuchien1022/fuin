#include "utils.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int is_digit_char(char value)
{
    return (value >= '0') && (value <= '9');
}

static int is_lower_hex_char(char value)
{
    return ((value >= '0') && (value <= '9')) ||
           ((value >= 'a') && (value <= 'f'));
}

static int is_uuid_variant_char(char value)
{
    return (value == '8') || (value == '9') || (value == 'a') || (value == 'b');
}

static int test_now_iso8601_format(void)
{
    char timestamp[UTILS_ISO8601_UTC_BUFFER_LEN];
    int ok = 1;
    size_t i = 0U;

    if (utils_now_iso8601(timestamp, sizeof(timestamp)) != SM_OK) {
        printf("test_now_iso8601_format: timestamp failed\n");
        return 1;
    }

    ok = strlen(timestamp) == UTILS_ISO8601_UTC_LEN;
    ok = ok && (timestamp[4] == '-') && (timestamp[7] == '-');
    ok = ok && (timestamp[10] == 'T') && (timestamp[13] == ':');
    ok = ok && (timestamp[16] == ':') && (timestamp[19] == 'Z');
    for (i = 0U; i < UTILS_ISO8601_UTC_LEN; i++) {
        if ((i == 4U) || (i == 7U) || (i == 10U) ||
            (i == 13U) || (i == 16U) || (i == 19U)) {
            continue;
        }
        ok = ok && is_digit_char(timestamp[i]);
    }

    if (!ok) {
        printf("test_now_iso8601_format: invalid format %s\n", timestamp);
    }
    return ok ? 0 : 1;
}

static int test_now_iso8601_invalid_args(void)
{
    char timestamp[UTILS_ISO8601_UTC_LEN];
    int ok = 1;

    ok = ok && (utils_now_iso8601(NULL, UTILS_ISO8601_UTC_BUFFER_LEN) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_now_iso8601(timestamp, sizeof(timestamp)) ==
                SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_now_iso8601_invalid_args: expected invalid argument\n");
    }
    return ok ? 0 : 1;
}

static int test_now_plus_seconds_iso8601(void)
{
    char now[UTILS_ISO8601_UTC_BUFFER_LEN];
    char future[UTILS_ISO8601_UTC_BUFFER_LEN];
    int ok = 1;

    if ((utils_now_iso8601(now, sizeof(now)) != SM_OK) ||
        (utils_now_plus_seconds_iso8601(3600U, future, sizeof(future)) != SM_OK)) {
        printf("test_now_plus_seconds_iso8601: timestamp failed\n");
        return 1;
    }

    ok = ok && (strlen(future) == UTILS_ISO8601_UTC_LEN);
    ok = ok && (future[4] == '-') && (future[7] == '-') &&
         (future[10] == 'T') && (future[13] == ':') &&
         (future[16] == ':') && (future[19] == 'Z');
    ok = ok && (strcmp(future, now) >= 0);
    if (!ok) {
        printf("test_now_plus_seconds_iso8601: invalid future timestamp\n");
    }
    return ok ? 0 : 1;
}

static int test_now_plus_seconds_invalid_args(void)
{
    char timestamp[UTILS_ISO8601_UTC_LEN];
    int ok = 1;

    ok = ok && (utils_now_plus_seconds_iso8601(1U,
                                               NULL,
                                               UTILS_ISO8601_UTC_BUFFER_LEN) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_now_plus_seconds_iso8601(1U,
                                               timestamp,
                                               sizeof(timestamp)) ==
                SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_now_plus_seconds_invalid_args: expected invalid argument\n");
    }
    return ok ? 0 : 1;
}

static int test_base64_known_value(void)
{
    const unsigned char input[] = "hello";
    char encoded[16];
    size_t written = 0U;
    int ok = 0;

    if (utils_base64_encode(input, sizeof(input) - 1U,
                            encoded, sizeof(encoded), &written) != SM_OK) {
        printf("test_base64_known_value: encode failed\n");
        return 1;
    }

    ok = (written == strlen("aGVsbG8=")) && (strcmp(encoded, "aGVsbG8=") == 0);
    if (!ok) {
        printf("test_base64_known_value: unexpected encoded value\n");
    }
    return ok ? 0 : 1;
}

static int test_base64_roundtrip_binary(void)
{
    const unsigned char input[] = {
        0x00U, 0x01U, 0x02U, 0x41U, 0x42U, 0xffU
    };
    char encoded[32];
    unsigned char decoded[sizeof(input)];
    size_t encoded_len = 0U;
    size_t decoded_len = 0U;
    int ok = 0;

    if (utils_base64_encode(input, sizeof(input),
                            encoded, sizeof(encoded), &encoded_len) != SM_OK) {
        printf("test_base64_roundtrip_binary: encode failed\n");
        return 1;
    }
    if (utils_base64_decode(encoded, decoded, sizeof(decoded), &decoded_len) != SM_OK) {
        printf("test_base64_roundtrip_binary: decode failed\n");
        return 1;
    }

    ok = (decoded_len == sizeof(input)) &&
         (sodium_memcmp(input, decoded, sizeof(input)) == 0);
    if (!ok) {
        printf("test_base64_roundtrip_binary: roundtrip mismatch\n");
    }

    sodium_memzero(decoded, sizeof(decoded));
    return ok ? 0 : 1;
}

static int test_base64_empty_input(void)
{
    char encoded[4];
    unsigned char decoded[1] = {0xAAU};
    size_t written = 99U;
    int ok = 1;

    ok = ok && (utils_base64_encode(NULL, 0U, encoded, sizeof(encoded), &written) == SM_OK);
    ok = ok && (written == 0U) && (encoded[0] == '\0');
    written = 99U;
    ok = ok && (utils_base64_decode(encoded, decoded, sizeof(decoded), &written) == SM_OK);
    ok = ok && (written == 0U);

    if (!ok) {
        printf("test_base64_empty_input: unexpected empty handling\n");
    }
    return ok ? 0 : 1;
}

static int test_base64_invalid_args(void)
{
    const unsigned char input[] = "abc";
    char encoded[4];
    unsigned char decoded[3];
    size_t written = 0U;
    int ok = 1;

    ok = ok && (utils_base64_encode(NULL, sizeof(input), encoded,
                                    sizeof(encoded), &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_encode(input, sizeof(input), NULL,
                                    sizeof(encoded), &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_encode(input, sizeof(input), encoded,
                                    sizeof(encoded), NULL) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_encode(input, sizeof(input), encoded,
                                    2U, &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_decode(NULL, decoded,
                                    sizeof(decoded), &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_decode("###", decoded,
                                    sizeof(decoded), &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base64_decode("YWJj", decoded,
                                    1U, &written) == SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_base64_invalid_args: expected invalid argument\n");
    }
    sodium_memzero(decoded, sizeof(decoded));
    return ok ? 0 : 1;
}

static int test_uuid_v4_format(void)
{
    char uuid[UTILS_UUID_V4_BUFFER_LEN];
    int ok = 1;
    size_t i = 0U;

    if (utils_generate_uuid_v4(uuid, sizeof(uuid)) != SM_OK) {
        printf("test_uuid_v4_format: uuid generation failed\n");
        return 1;
    }

    ok = ok && (strlen(uuid) == UTILS_UUID_V4_LEN);
    ok = ok && (uuid[8] == '-') && (uuid[13] == '-') &&
         (uuid[18] == '-') && (uuid[23] == '-');
    ok = ok && (uuid[14] == '4') && is_uuid_variant_char(uuid[19]);
    for (i = 0U; i < UTILS_UUID_V4_LEN; i++) {
        if ((i == 8U) || (i == 13U) || (i == 18U) || (i == 23U)) {
            continue;
        }
        ok = ok && is_lower_hex_char(uuid[i]);
    }

    if (!ok) {
        printf("test_uuid_v4_format: invalid uuid %s\n", uuid);
    }
    return ok ? 0 : 1;
}

static int test_uuid_v4_unique(void)
{
    char first[UTILS_UUID_V4_BUFFER_LEN];
    char second[UTILS_UUID_V4_BUFFER_LEN];
    int ok = 0;

    if ((utils_generate_uuid_v4(first, sizeof(first)) != SM_OK) ||
        (utils_generate_uuid_v4(second, sizeof(second)) != SM_OK)) {
        printf("test_uuid_v4_unique: uuid generation failed\n");
        return 1;
    }

    ok = strcmp(first, second) != 0;
    if (!ok) {
        printf("test_uuid_v4_unique: duplicate uuid generated\n");
    }
    return ok ? 0 : 1;
}

static int test_uuid_v4_invalid_args(void)
{
    char uuid[UTILS_UUID_V4_LEN];
    int ok = 1;

    ok = ok && (utils_generate_uuid_v4(NULL, UTILS_UUID_V4_BUFFER_LEN) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_generate_uuid_v4(uuid, sizeof(uuid)) ==
                SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_uuid_v4_invalid_args: expected invalid argument\n");
    }
    return ok ? 0 : 1;
}

static int test_generate_password_length_and_charset(void)
{
    static const char allowed[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}:;,.?";
    char password[65];
    size_t i = 0U;
    int ok = 1;

    if (utils_generate_password(password, sizeof(password), 64U, 1) != SM_OK) {
        printf("test_generate_password_length_and_charset: generation failed\n");
        return 1;
    }

    ok = ok && (strlen(password) == 64U);
    for (i = 0U; ok && (i < 64U); i++) {
        ok = strchr(allowed, password[i]) != NULL;
    }
    if (!ok) {
        printf("test_generate_password_length_and_charset: "
               "unexpected length or character\n");
    }
    sodium_memzero(password, sizeof(password));
    return ok ? 0 : 1;
}

static int test_generate_password_no_symbols(void)
{
    char password[129];
    size_t i = 0U;
    int ok = 1;

    if (utils_generate_password(password, sizeof(password), 128U, 0) != SM_OK) {
        printf("test_generate_password_no_symbols: generation failed\n");
        return 1;
    }

    for (i = 0U; ok && (i < 128U); i++) {
        unsigned char c = (unsigned char)password[i];

        ok = ((c >= 'A') && (c <= 'Z')) ||
             ((c >= 'a') && (c <= 'z')) ||
             ((c >= '0') && (c <= '9'));
    }
    if (!ok) {
        printf("test_generate_password_no_symbols: non-alnum character\n");
    }
    sodium_memzero(password, sizeof(password));
    return ok ? 0 : 1;
}

static int test_generate_password_unique(void)
{
    char first[33];
    char second[33];
    int ok = 0;

    if ((utils_generate_password(first, sizeof(first), 32U, 1) != SM_OK) ||
        (utils_generate_password(second, sizeof(second), 32U, 1) != SM_OK)) {
        printf("test_generate_password_unique: generation failed\n");
        return 1;
    }

    ok = strcmp(first, second) != 0;
    if (!ok) {
        printf("test_generate_password_unique: duplicate password generated\n");
    }
    sodium_memzero(first, sizeof(first));
    sodium_memzero(second, sizeof(second));
    return ok ? 0 : 1;
}

static int test_generate_password_invalid_args(void)
{
    char password[16];
    int ok = 1;

    ok = ok && (utils_generate_password(NULL, 16U, 8U, 1) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_generate_password(password, sizeof(password), 0U, 1) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_generate_password(password,
                                        sizeof(password),
                                        sizeof(password),
                                        1) == SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_generate_password_invalid_args: expected invalid argument\n");
    }
    return ok ? 0 : 1;
}

static int test_base32_decode_vectors(void)
{
    unsigned char output[32];
    size_t written = 0U;
    int ok = 1;

    /* RFC 4648 test vector. */
    ok = ok && (utils_base32_decode("MZXW6YTBOI======",
                                    16U,
                                    output,
                                    sizeof(output),
                                    &written) == SM_OK) &&
         (written == 6U) && (memcmp(output, "foobar", 6U) == 0);

    /* Lowercase and grouped-with-spaces forms are accepted. */
    ok = ok && (utils_base32_decode("mzxw 6ytb oi",
                                    12U,
                                    output,
                                    sizeof(output),
                                    &written) == SM_OK) &&
         (written == 6U) && (memcmp(output, "foobar", 6U) == 0);

    /* Invalid characters are rejected ('1' and '8' are not in base32). */
    ok = ok && (utils_base32_decode("MZXW18",
                                    6U,
                                    output,
                                    sizeof(output),
                                    &written) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_base32_decode(NULL,
                                    0U,
                                    output,
                                    sizeof(output),
                                    &written) == SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_base32_decode_vectors: mismatch\n");
    }
    sodium_memzero(output, sizeof(output));
    return ok ? 0 : 1;
}

static int test_totp_rfc6238_vectors(void)
{
    /* RFC 6238 Appendix B SHA-1 vectors: ASCII seed, 8 digits, 30 s. */
    const unsigned char seed[] = "12345678901234567890";
    char code[16];
    int ok = 1;

    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                59U,
                                30U,
                                8,
                                code,
                                sizeof(code)) == SM_OK) &&
         (strcmp(code, "94287082") == 0);
    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                1111111109U,
                                30U,
                                8,
                                code,
                                sizeof(code)) == SM_OK) &&
         (strcmp(code, "07081804") == 0);
    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                20000000000U,
                                30U,
                                8,
                                code,
                                sizeof(code)) == SM_OK) &&
         (strcmp(code, "65353130") == 0);

    /* 6-digit code is the low-order truncation of the same value. */
    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                59U,
                                30U,
                                6,
                                code,
                                sizeof(code)) == SM_OK) &&
         (strcmp(code, "287082") == 0);

    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                59U,
                                0U,
                                6,
                                code,
                                sizeof(code)) == SM_ERR_INVALID_ARGUMENT);
    ok = ok && (utils_totp_code(seed,
                                sizeof(seed) - 1U,
                                59U,
                                30U,
                                9,
                                code,
                                sizeof(code)) == SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_totp_rfc6238_vectors: mismatch\n");
    }
    sodium_memzero(code, sizeof(code));
    return ok ? 0 : 1;
}

int test_utils_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_utils_run: sodium_init failed\n");
        return 1;
    }

    failed += test_now_iso8601_format();
    failed += test_now_iso8601_invalid_args();
    failed += test_now_plus_seconds_iso8601();
    failed += test_now_plus_seconds_invalid_args();
    failed += test_base64_known_value();
    failed += test_base64_roundtrip_binary();
    failed += test_base64_empty_input();
    failed += test_base64_invalid_args();
    failed += test_uuid_v4_format();
    failed += test_uuid_v4_unique();
    failed += test_uuid_v4_invalid_args();
    failed += test_generate_password_length_and_charset();
    failed += test_generate_password_no_symbols();
    failed += test_generate_password_unique();
    failed += test_generate_password_invalid_args();
    failed += test_base32_decode_vectors();
    failed += test_totp_rfc6238_vectors();

    if (failed != 0) {
        printf("test_utils_run: %d failures\n", failed);
    }

    return failed == 0 ? 0 : 1;
}
