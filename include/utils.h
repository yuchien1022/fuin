#ifndef SECRETS_MANAGER_UTILS_H
#define SECRETS_MANAGER_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define UTILS_UUID_V4_LEN 36U
#define UTILS_UUID_V4_BUFFER_LEN (UTILS_UUID_V4_LEN + 1U)
#define UTILS_ISO8601_UTC_LEN 20U
#define UTILS_ISO8601_UTC_BUFFER_LEN (UTILS_ISO8601_UTC_LEN + 1U)

enum sm_status {
    SM_OK = 0,
    SM_ERR_INVALID_ARGUMENT = -1,
    SM_ERR_NOT_IMPLEMENTED = -2,
    SM_ERR_CRYPTO = -3,
    SM_ERR_STORAGE = -4,
    SM_ERR_AUTH = -5,
    SM_ERR_NOT_FOUND = -6,
    SM_ERR_INPUT_TOO_LARGE = -7
};

const char *utils_status_message(int status);
int utils_now_iso8601(char *buffer, size_t buffer_len);
int utils_now_plus_seconds_iso8601(uint64_t seconds,
                                   char *buffer,
                                   size_t buffer_len);
int utils_base64_encode(const unsigned char *input,
                        size_t input_len,
                        char *output,
                        size_t output_len,
                        size_t *written);
int utils_base64_decode(const char *input,
                        unsigned char *output,
                        size_t output_len,
                        size_t *written);
int utils_generate_uuid_v4(char *buffer, size_t buffer_len);
int utils_generate_password(char *buffer,
                            size_t buffer_len,
                            size_t password_len,
                            int include_symbols);
int utils_base32_decode(const char *input,
                        size_t input_len,
                        unsigned char *output,
                        size_t output_len,
                        size_t *written);
int utils_totp_code(const unsigned char *seed,
                    size_t seed_len,
                    uint64_t unix_time,
                    uint32_t period_seconds,
                    int digits,
                    char *output,
                    size_t output_len);

/* Writes the 8 little-endian bytes of value into out. Shared by the modules
   that serialize length/counter/id fields into hashes and AEAD inputs so the
   byte layout cannot drift between a producer and its verifier. */
void utils_write_u64_le(unsigned char out[8], uint64_t value);

#endif
