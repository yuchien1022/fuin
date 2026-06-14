#include "crypto_engine.h"
#include "utils.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void cleanup_secret(encrypted_secret_t *secret)
{
    crypto_engine_free_encrypted_secret(secret);
}

static int encrypt_for_test(const unsigned char *plaintext,
                            size_t plaintext_len,
                            const unsigned char *kek_enc,
                            const char *secret_id,
                            uint32_t version,
                            uint64_t nonce_counter,
                            encrypted_secret_t *output)
{
    int status = crypto_engine_encrypt(plaintext,
                                       plaintext_len,
                                       kek_enc,
                                       secret_id,
                                       version,
                                       nonce_counter,
                                       output);
    if (status != SM_OK) {
        printf("crypto_engine_encrypt failed: %s\n", utils_status_message(status));
        return 1;
    }

    return 0;
}

static int encrypt_for_test_with_algorithm(const unsigned char *plaintext,
                                           size_t plaintext_len,
                                           const unsigned char *kek_enc,
                                           const char *secret_id,
                                           uint32_t version,
                                           uint64_t nonce_counter,
                                           const char *algorithm,
                                           encrypted_secret_t *output)
{
    int status = crypto_engine_encrypt_with_algorithm(plaintext,
                                                      plaintext_len,
                                                      kek_enc,
                                                      secret_id,
                                                      version,
                                                      nonce_counter,
                                                      algorithm,
                                                      output);
    if (status != SM_OK) {
        printf("crypto_engine_encrypt_with_algorithm failed: %s\n",
               utils_status_message(status));
        return 1;
    }

    return 0;
}

static int decrypt_expect_success(const encrypted_secret_t *input,
                                  const unsigned char *kek_enc,
                                  const char *secret_id,
                                  uint32_t version,
                                  unsigned char *plaintext,
                                  size_t *plaintext_len)
{
    int status = crypto_engine_decrypt(input,
                                       kek_enc,
                                       secret_id,
                                       version,
                                       plaintext,
                                       plaintext_len);
    if (status != SM_OK) {
        printf("crypto_engine_decrypt failed: %s\n", utils_status_message(status));
        return 1;
    }

    return 0;
}

static int decrypt_expect_crypto_failure(const encrypted_secret_t *input,
                                         const unsigned char *kek_enc,
                                         const char *secret_id,
                                         uint32_t version,
                                         unsigned char *plaintext,
                                         size_t *plaintext_len)
{
    int status = crypto_engine_decrypt(input,
                                       kek_enc,
                                       secret_id,
                                       version,
                                       plaintext,
                                       plaintext_len);
    if (status != SM_ERR_CRYPTO) {
        printf("crypto_engine_decrypt returned %s, expected crypto failure\n",
               utils_status_message(status));
        return 1;
    }

    return 0;
}

static int test_encrypt_decrypt_roundtrip(void)
{
    const unsigned char plaintext[] = "hello world";
    const char *secret_id = "test1";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               1U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, sizeof(recovered)) != 0);
    if (failed) {
        printf("test_encrypt_decrypt_roundtrip: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_encrypt_different_ciphertext(void)
{
    const unsigned char plaintext[] = "repeatable secret";
    const char *secret_id = "test-different-ciphertext";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t first;
    encrypted_secret_t second;
    int failed = 1;

    sodium_memzero(&first, sizeof(first));
    sodium_memzero(&second, sizeof(second));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         secret_id,
                         1U,
                         100U,
                         &first) != 0 ||
        encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         secret_id,
                         1U,
                         101U,
                         &second) != 0) {
        goto cleanup;
    }

    failed = (first.ciphertext_len == second.ciphertext_len) &&
             (sodium_memcmp(first.ciphertext,
                            second.ciphertext,
                            first.ciphertext_len) == 0);
    if (failed) {
        printf("test_encrypt_different_ciphertext: ciphertext matched\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&first);
    cleanup_secret(&second);
    return failed;
}

static int test_decrypt_wrong_kek(void)
{
    const unsigned char plaintext[] = "kek-protected";
    const char *secret_id = "wrong-kek";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char wrong_kek[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext)];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    for (size_t i = 0U; i < sizeof(wrong_kek); i++) {
        wrong_kek[i] = kek_enc[i];
    }
    wrong_kek[0] ^= 0x01U;

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext),
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    failed = decrypt_expect_crypto_failure(&encrypted,
                                           wrong_kek,
                                           secret_id,
                                           1U,
                                           recovered,
                                           &recovered_len);

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(wrong_kek, sizeof(wrong_kek));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_tampered_ciphertext(void)
{
    const unsigned char plaintext[] = "tamper ciphertext";
    const char *secret_id = "tampered-ciphertext";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext)];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext),
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    encrypted.ciphertext[0] ^= 0x01U;
    failed = decrypt_expect_crypto_failure(&encrypted,
                                           kek_enc,
                                           secret_id,
                                           1U,
                                           recovered,
                                           &recovered_len);

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_tampered_encrypted_dek(void)
{
    const unsigned char plaintext[] = "tamper dek";
    const char *secret_id = "tampered-dek";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext)];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext),
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    encrypted.encrypted_dek[0] ^= 0x01U;
    failed = decrypt_expect_crypto_failure(&encrypted,
                                           kek_enc,
                                           secret_id,
                                           1U,
                                           recovered,
                                           &recovered_len);

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_large_plaintext(void)
{
    const size_t plaintext_len = 1024U * 1024U;
    const char *secret_id = "large-plaintext";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char *plaintext = sodium_malloc(plaintext_len);
    unsigned char *recovered = sodium_malloc(plaintext_len);
    encrypted_secret_t encrypted;
    size_t recovered_len = plaintext_len;
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    if ((plaintext == NULL) || (recovered == NULL)) {
        printf("test_large_plaintext: sodium_malloc failed\n");
        goto cleanup;
    }

    randombytes_buf(plaintext, plaintext_len);
    if (encrypt_for_test(plaintext,
                         plaintext_len,
                         kek_enc,
                         secret_id,
                         1U,
                         42U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               1U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != plaintext_len) ||
             (sodium_memcmp(plaintext, recovered, plaintext_len) != 0);
    if (failed) {
        printf("test_large_plaintext: plaintext mismatch\n");
    }

cleanup:
    if (plaintext != NULL) {
        sodium_memzero(plaintext, plaintext_len);
        sodium_free(plaintext);
    }
    if (recovered != NULL) {
        sodium_memzero(recovered, plaintext_len);
        sodium_free(recovered);
    }
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_empty_plaintext(void)
{
    const unsigned char empty = 0U;
    const char *secret_id = "empty-plaintext";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered = 0xAAU;
    encrypted_secret_t encrypted;
    size_t recovered_len = 0U;
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(&empty,
                         0U,
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               1U,
                               &recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = recovered_len != 0U;
    if (failed) {
        printf("test_empty_plaintext: non-empty output\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_nonce_structure(void)
{
    const unsigned char plaintext[] = "nonce";
    const char *secret_id = "nonce-structure";
    const uint64_t nonce_counter = 0x0102030405060708ULL;
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char expected_hash[crypto_hash_sha256_BYTES];
    encrypted_secret_t encrypted;
    size_t counter_offset = 0U;
    size_t i = 0U;
    int failed = 1;

    /* The deterministic prefix||counter nonce layout is specific to the
       AES-256-GCM path; without it the default algorithm uses random
       nonces and there is nothing to check. */
    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) !=
        SM_OK) {
        printf("test_nonce_structure: AES-GCM unavailable; skipped\n");
        return 0;
    }

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext),
                                        kek_enc,
                                        secret_id,
                                        1U,
                                        nonce_counter,
                                        CRYPTO_ENGINE_ALGORITHM_AES_256_GCM,
                                        &encrypted) != 0) {
        goto cleanup;
    }

    if (crypto_hash_sha256(expected_hash,
                           (const unsigned char *)secret_id,
                           (unsigned long long)sizeof("nonce-structure") - 1U) != 0) {
        printf("test_nonce_structure: hash failed\n");
        goto cleanup;
    }

    if (sodium_memcmp(encrypted.nonce, expected_hash, 4U) != 0) {
        printf("test_nonce_structure: prefix mismatch\n");
        goto cleanup;
    }

    counter_offset = encrypted.nonce_len - 8U;
    for (i = 0U; i < 8U; i++) {
        unsigned char expected = (unsigned char)(nonce_counter >> (i * 8U));
        if (encrypted.nonce[counter_offset + i] != expected) {
            printf("test_nonce_structure: counter mismatch\n");
            goto cleanup;
        }
    }

    failed = 0;

cleanup:
    sodium_memzero(expected_hash, sizeof(expected_hash));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_aad_prevents_swapping(void)
{
    const unsigned char secret_a[] = "secret_A_value";
    const unsigned char secret_b[] = "secret_B_value";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(secret_a)];
    encrypted_secret_t encrypted_a;
    encrypted_secret_t encrypted_b;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted_a, sizeof(encrypted_a));
    sodium_memzero(&encrypted_b, sizeof(encrypted_b));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(secret_a,
                         sizeof(secret_a),
                         kek_enc,
                         "AAAA",
                         1U,
                         1U,
                         &encrypted_a) != 0 ||
        encrypt_for_test(secret_b,
                         sizeof(secret_b),
                         kek_enc,
                         "BBBB",
                         1U,
                         2U,
                         &encrypted_b) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_crypto_failure(&encrypted_a,
                                      kek_enc,
                                      "BBBB",
                                      1U,
                                      recovered,
                                      &recovered_len) != 0) {
        goto cleanup;
    }

    recovered_len = sizeof(recovered);
    if (decrypt_expect_success(&encrypted_a,
                               kek_enc,
                               "AAAA",
                               1U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != sizeof(secret_a)) ||
             (sodium_memcmp(secret_a, recovered, sizeof(secret_a)) != 0);
    if (failed) {
        printf("test_aad_prevents_swapping: control decrypt mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted_a);
    cleanup_secret(&encrypted_b);
    return failed;
}

static int test_aad_version_binding(void)
{
    const unsigned char plaintext[] = "version-bound";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext)];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext),
                         kek_enc,
                         "AAAA",
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    failed = decrypt_expect_crypto_failure(&encrypted,
                                           kek_enc,
                                           "AAAA",
                                           2U,
                                           recovered,
                                           &recovered_len);

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_nist_aes256_gcm_case16(void)
{
    static const unsigned char key[crypto_aead_aes256gcm_KEYBYTES] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    };
    static const unsigned char iv[crypto_aead_aes256gcm_NPUBBYTES] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    };
    static const unsigned char aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2,
    };
    static const unsigned char plaintext[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39,
    };
    static const unsigned char expected_ciphertext[] = {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62,
    };
    static const unsigned char expected_tag[crypto_aead_aes256gcm_ABYTES] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
    };
    unsigned char ciphertext[sizeof(expected_ciphertext)];
    unsigned char tag[crypto_aead_aes256gcm_ABYTES];
    unsigned long long tag_len = 0U;
    int failed = 1;

    if (crypto_aead_aes256gcm_is_available() == 0) {
        printf("WARNING: skipping NIST AES-256-GCM KAT; AES-GCM unavailable\n");
        return 0;
    }

    if (crypto_aead_aes256gcm_encrypt_detached(ciphertext,
                                               tag,
                                               &tag_len,
                                               plaintext,
                                               (unsigned long long)sizeof(plaintext),
                                               aad,
                                               (unsigned long long)sizeof(aad),
                                               NULL,
                                               iv,
                                               key) != 0) {
        printf("test_nist_aes256_gcm_case16: encrypt_detached failed\n");
        goto cleanup;
    }

    failed = (tag_len != sizeof(expected_tag)) ||
             (sodium_memcmp(ciphertext,
                            expected_ciphertext,
                            sizeof(expected_ciphertext)) != 0) ||
             (sodium_memcmp(tag, expected_tag, sizeof(expected_tag)) != 0);
    if (failed) {
        printf("test_nist_aes256_gcm_case16: vector mismatch\n");
    }

cleanup:
    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(tag, sizeof(tag));
    return failed;
}

static int test_encrypt_null_kek(void)
{
    const unsigned char plaintext[] = "test";
    encrypted_secret_t encrypted;
    int failed;

    sodium_memzero(&encrypted, sizeof(encrypted));
    failed = crypto_engine_encrypt(plaintext, sizeof(plaintext) - 1U,
                                   NULL, "test-null-kek", 1U, 1U,
                                   &encrypted) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_encrypt_null_kek: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    return failed;
}

static int test_encrypt_null_secret_id(void)
{
    const unsigned char plaintext[] = "test";
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t encrypted;
    int failed;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek, sizeof(kek));
    failed = crypto_engine_encrypt(plaintext, sizeof(plaintext) - 1U,
                                   kek, NULL, 1U, 1U,
                                   &encrypted) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_encrypt_null_secret_id: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    sodium_memzero(kek, sizeof(kek));
    return failed;
}

static int test_encrypt_empty_secret_id(void)
{
    const unsigned char plaintext[] = "test";
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t encrypted;
    int failed;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek, sizeof(kek));
    failed = crypto_engine_encrypt(plaintext, sizeof(plaintext) - 1U,
                                   kek, "", 1U, 1U,
                                   &encrypted) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_encrypt_empty_secret_id: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    sodium_memzero(kek, sizeof(kek));
    return failed;
}

static int test_encrypt_null_output(void)
{
    const unsigned char plaintext[] = "test";
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    int failed;

    randombytes_buf(kek, sizeof(kek));
    failed = crypto_engine_encrypt(plaintext, sizeof(plaintext) - 1U,
                                   kek, "test", 1U, 1U,
                                   NULL) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_encrypt_null_output: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    sodium_memzero(kek, sizeof(kek));
    return failed;
}

static int test_decrypt_null_input(void)
{
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char buf[64];
    size_t buf_len = sizeof(buf);
    int failed;

    randombytes_buf(kek, sizeof(kek));
    failed = crypto_engine_decrypt(NULL, kek, "test", 1U,
                                   buf, &buf_len) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_decrypt_null_input: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    sodium_memzero(kek, sizeof(kek));
    return failed;
}

static int test_aad_overflow(void)
{
    char long_id[300];
    unsigned char kek[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char plaintext[] = "test";
    encrypted_secret_t encrypted;
    size_t i;
    int failed;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek, sizeof(kek));
    for (i = 0U; i < 299U; i++) {
        long_id[i] = 'A';
    }
    long_id[299] = '\0';

    failed = crypto_engine_encrypt(plaintext, sizeof(plaintext) - 1U,
                                   kek, long_id, 1U, 1U,
                                   &encrypted) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_aad_overflow: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    sodium_memzero(kek, sizeof(kek));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_nonce_counter_zero(void)
{
    const unsigned char plaintext[] = "counter-zero";
    const char *secret_id = "counter-zero-id";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext, sizeof(plaintext) - 1U,
                         kek_enc, secret_id, 1U, 0U, &encrypted) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted, kek_enc, secret_id, 1U,
                               recovered, &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_nonce_counter_zero: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_nonce_counter_max(void)
{
    const unsigned char plaintext[] = "counter-max";
    const char *secret_id = "counter-max-id";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext, sizeof(plaintext) - 1U,
                         kek_enc, secret_id, 1U, UINT64_MAX, &encrypted) != 0) {
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted, kek_enc, secret_id, 1U,
                               recovered, &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_nonce_counter_max: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_nonce_deterministic(void)
{
    const unsigned char plaintext[] = "nonce-det";
    const char *secret_id = "nonce-deterministic";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t first;
    encrypted_secret_t second;
    int failed = 1;

    sodium_memzero(&first, sizeof(first));
    sodium_memzero(&second, sizeof(second));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) !=
        SM_OK) {
        printf("WARNING: skipping AES nonce determinism; AES-GCM unavailable\n");
        failed = 0;
        goto cleanup;
    }

    if (encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext) - 1U,
                                        kek_enc,
                                        secret_id,
                                        1U,
                                        42U,
                                        CRYPTO_ENGINE_ALGORITHM_AES_256_GCM,
                                        &first) != 0 ||
        encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext) - 1U,
                                        kek_enc,
                                        secret_id,
                                        1U,
                                        42U,
                                        CRYPTO_ENGINE_ALGORITHM_AES_256_GCM,
                                        &second) != 0) {
        goto cleanup;
    }

    failed = (first.nonce_len != second.nonce_len) ||
             (sodium_memcmp(first.nonce, second.nonce, first.nonce_len) != 0);
    if (failed) {
        printf("test_nonce_deterministic: nonces differ\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&first);
    cleanup_secret(&second);
    return failed;
}

static int test_aes256_gcm_requested_algorithm(void)
{
    const unsigned char plaintext[] = "requested-aes";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) !=
        SM_OK) {
        printf("WARNING: skipping requested AES-GCM; AES-GCM unavailable\n");
        failed = 0;
        goto cleanup;
    }

    if (encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext) - 1U,
                                        kek_enc,
                                        "requested-aes-id",
                                        3U,
                                        9U,
                                        CRYPTO_ENGINE_ALGORITHM_AES_256_GCM,
                                        &encrypted) != 0) {
        goto cleanup;
    }
    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               "requested-aes-id",
                               3U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (strcmp(encrypted.algorithm,
                     CRYPTO_ENGINE_ALGORITHM_AES_256_GCM) != 0) ||
             (encrypted.nonce_len != crypto_aead_aes256gcm_NPUBBYTES) ||
             (encrypted.dek_nonce_len != crypto_aead_aes256gcm_NPUBBYTES) ||
             (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_aes256_gcm_requested_algorithm: mismatch\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_xchacha20_requested_algorithm(void)
{
    const unsigned char plaintext[] = "requested-xchacha";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t first;
    encrypted_secret_t second;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&first, sizeof(first));
    sodium_memzero(&second, sizeof(second));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext) - 1U,
                                        kek_enc,
                                        "requested-xchacha-id",
                                        4U,
                                        11U,
                                        CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305,
                                        &first) != 0 ||
        encrypt_for_test_with_algorithm(plaintext,
                                        sizeof(plaintext) - 1U,
                                        kek_enc,
                                        "requested-xchacha-id",
                                        4U,
                                        11U,
                                        CRYPTO_ENGINE_ALGORITHM_CHACHA20_POLY1305,
                                        &second) != 0) {
        goto cleanup;
    }
    if (decrypt_expect_success(&first,
                               kek_enc,
                               "requested-xchacha-id",
                               4U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (strcmp(first.algorithm,
                     CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) != 0) ||
             (strcmp(second.algorithm,
                     CRYPTO_ENGINE_ALGORITHM_XCHACHA20_POLY1305) != 0) ||
             (first.nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) ||
             (first.dek_nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) ||
             (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0) ||
             ((first.nonce_len == second.nonce_len) &&
              (sodium_memcmp(first.nonce, second.nonce, first.nonce_len) == 0));
    if (failed) {
        printf("test_xchacha20_requested_algorithm: mismatch\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_secret(&first);
    cleanup_secret(&second);
    return failed;
}

static int test_dek_nonce_random(void)
{
    const unsigned char plaintext[] = "dek-nonce";
    const char *secret_id = "dek-nonce-test";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t first;
    encrypted_secret_t second;
    int failed = 1;

    sodium_memzero(&first, sizeof(first));
    sodium_memzero(&second, sizeof(second));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext, sizeof(plaintext) - 1U,
                         kek_enc, secret_id, 1U, 1U, &first) != 0 ||
        encrypt_for_test(plaintext, sizeof(plaintext) - 1U,
                         kek_enc, secret_id, 1U, 1U, &second) != 0) {
        goto cleanup;
    }

    failed = (first.dek_nonce_len == second.dek_nonce_len) &&
             (sodium_memcmp(first.dek_nonce, second.dek_nonce,
                            first.dek_nonce_len) == 0);
    if (failed) {
        printf("test_dek_nonce_random: dek_nonces matched (should be random)\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&first);
    cleanup_secret(&second);
    return failed;
}

static int build_xchacha_secret(const unsigned char *plaintext,
                                size_t plaintext_len,
                                const unsigned char *kek_enc,
                                const char *secret_id,
                                uint32_t version,
                                encrypted_secret_t *output)
{
    unsigned char dek[CRYPTO_ENGINE_DEK_BYTES];
    char aad[64];
    int written = 0;
    unsigned long long cipher_len = 0U;
    unsigned long long wrapped_len = 0U;
    int status = SM_OK;

    if ((plaintext == NULL) || (kek_enc == NULL) || (secret_id == NULL) ||
        (output == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(output, sizeof(*output));
    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(aad, sizeof(aad));
    randombytes_buf(dek, sizeof(dek));
    written = snprintf(aad, sizeof(aad), "%s:%u", secret_id, (unsigned int)version);
    if ((written < 0) || ((size_t)written >= sizeof(aad))) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }
    written = snprintf(output->algorithm,
                       sizeof(output->algorithm),
                       "%s",
                       "XChaCha20-Poly1305");
    if ((written < 0) || ((size_t)written >= sizeof(output->algorithm))) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }

    output->nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    output->dek_nonce_len = output->nonce_len;
    output->ciphertext_len = plaintext_len +
                             crypto_aead_xchacha20poly1305_ietf_ABYTES;
    output->encrypted_dek_len = CRYPTO_ENGINE_DEK_BYTES +
                                crypto_aead_xchacha20poly1305_ietf_ABYTES;
    output->ciphertext = sodium_malloc(output->ciphertext_len);
    output->encrypted_dek = sodium_malloc(output->encrypted_dek_len);
    if ((output->ciphertext == NULL) || (output->encrypted_dek == NULL)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    randombytes_buf(output->nonce, output->nonce_len);
    randombytes_buf(output->dek_nonce, output->dek_nonce_len);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(output->ciphertext,
                                                   &cipher_len,
                                                   plaintext,
                                                   (unsigned long long)plaintext_len,
                                                   (const unsigned char *)aad,
                                                   (unsigned long long)strlen(aad),
                                                   NULL,
                                                   output->nonce,
                                                   dek) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(output->encrypted_dek,
                                                   &wrapped_len,
                                                   dek,
                                                   sizeof(dek),
                                                   (const unsigned char *)aad,
                                                   (unsigned long long)strlen(aad),
                                                   NULL,
                                                   output->dek_nonce,
                                                   kek_enc) != 0) {
        status = SM_ERR_CRYPTO;
        goto cleanup;
    }
    output->ciphertext_len = (size_t)cipher_len;
    output->encrypted_dek_len = (size_t)wrapped_len;

    status = crypto_engine_compute_key_commitment(
        kek_enc,
        CRYPTO_ENGINE_DEK_BYTES,
        CRYPTO_ENGINE_COMMIT_DOMAIN_KEK,
        output->dek_nonce,
        output->dek_nonce_len,
        output->key_commitment,
        CRYPTO_ENGINE_COMMITMENT_HALF_BYTES);
    if (status == SM_OK) {
        status = crypto_engine_compute_key_commitment(
            dek,
            sizeof(dek),
            CRYPTO_ENGINE_COMMIT_DOMAIN_DEK,
            output->nonce,
            output->nonce_len,
            output->key_commitment + CRYPTO_ENGINE_COMMITMENT_HALF_BYTES,
            CRYPTO_ENGINE_COMMITMENT_HALF_BYTES);
    }
    if (status != SM_OK) {
        goto cleanup;
    }
    output->key_commitment_len = CRYPTO_ENGINE_COMMITMENT_BYTES;

cleanup:
    if (status != SM_OK) {
        cleanup_secret(output);
    }
    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(aad, sizeof(aad));
    return status;
}

static int test_xchacha20_decrypt_compatibility(void)
{
    const unsigned char plaintext[] = "xchacha-direct";
    const char *secret_id = "xchacha-direct-id";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    if (build_xchacha_secret(plaintext,
                             sizeof(plaintext) - 1U,
                             kek_enc,
                             secret_id,
                             7U,
                             &encrypted) != SM_OK) {
        printf("test_xchacha20_decrypt_compatibility: setup failed\n");
        goto cleanup;
    }
    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               7U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_xchacha20_decrypt_compatibility: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_decrypt_rejects_unknown_algorithm(void)
{
    const unsigned char plaintext[] = "unknown-algorithm";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext)];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    if (encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         "unknown-algorithm-id",
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }
    if (snprintf(encrypted.algorithm,
                 sizeof(encrypted.algorithm),
                 "%s",
                 "Not-A-Real-Algorithm") < 0) {
        goto cleanup;
    }

    failed = crypto_engine_decrypt(&encrypted,
                                   kek_enc,
                                   "unknown-algorithm-id",
                                   1U,
                                   recovered,
                                   &recovered_len) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_decrypt_rejects_unknown_algorithm: expected invalid argument\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_encrypt_rejects_unknown_algorithm(void)
{
    const unsigned char plaintext[] = "bad-algorithm";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    encrypted_secret_t encrypted;
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    failed = crypto_engine_encrypt_with_algorithm(plaintext,
                                                  sizeof(plaintext) - 1U,
                                                  kek_enc,
                                                  "bad-algorithm-id",
                                                  1U,
                                                  1U,
                                                  "Not-A-Real-Algorithm",
                                                  &encrypted) !=
             SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_encrypt_rejects_unknown_algorithm: expected invalid argument\n");
    }

    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_decrypt_rejects_small_output_buffer(void)
{
    const unsigned char plaintext[] = "small-buffer";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 2U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));
    if (encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         "small-buffer-id",
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }

    failed = crypto_engine_decrypt(&encrypted,
                                   kek_enc,
                                   "small-buffer-id",
                                   1U,
                                   recovered,
                                   &recovered_len) != SM_ERR_INVALID_ARGUMENT;
    if (failed) {
        printf("test_decrypt_rejects_small_output_buffer: expected invalid argument\n");
    }

cleanup:
    sodium_memzero(kek_enc, sizeof(kek_enc));
    sodium_memzero(recovered, sizeof(recovered));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_crypto_engine_lifecycle_helpers(void)
{
    int failed = 0;

    failed = failed || (crypto_engine_init() != SM_OK);
    crypto_engine_free_encrypted_secret(NULL);
    failed = failed || (crypto_engine_shutdown() != SM_OK);
    if (failed) {
        printf("test_crypto_engine_lifecycle_helpers: lifecycle helper failed\n");
    }
    return failed;
}

static int test_aegis256_roundtrip(void)
{
    const unsigned char plaintext[] = "aegis quantum of solace";
    const char *secret_id = "test-aegis";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    if (crypto_engine_algorithm_available(CRYPTO_ENGINE_ALGORITHM_AEGIS_256) !=
        SM_OK) {
        printf("test_aegis256_roundtrip: AEGIS-256 unavailable; skipped\n");
        return 0;
    }

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (crypto_engine_encrypt_with_algorithm(plaintext,
                                             sizeof(plaintext) - 1U,
                                             kek_enc,
                                             secret_id,
                                             1U,
                                             1U,
                                             CRYPTO_ENGINE_ALGORITHM_AEGIS_256,
                                             &encrypted) != SM_OK) {
        printf("test_aegis256_roundtrip: encrypt failed\n");
        goto cleanup;
    }

    /* 256-bit random nonce on both layers is the DESIGN-001 escape hatch. */
    if ((strcmp(encrypted.algorithm, CRYPTO_ENGINE_ALGORITHM_AEGIS_256) != 0) ||
        (encrypted.nonce_len != 32U) || (encrypted.dek_nonce_len != 32U)) {
        printf("test_aegis256_roundtrip: unexpected metadata\n");
        goto cleanup;
    }

    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               1U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_aegis256_roundtrip: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

static int test_key_commitment_tamper_detected(void)
{
    const unsigned char plaintext[] = "committed";
    const char *secret_id = "test-commitment";
    unsigned char kek_enc[CRYPTO_ENGINE_DEK_BYTES];
    unsigned char recovered[sizeof(plaintext) - 1U];
    encrypted_secret_t encrypted;
    size_t recovered_len = sizeof(recovered);
    int failed = 1;

    sodium_memzero(&encrypted, sizeof(encrypted));
    randombytes_buf(kek_enc, sizeof(kek_enc));

    if (encrypt_for_test(plaintext,
                         sizeof(plaintext) - 1U,
                         kek_enc,
                         secret_id,
                         1U,
                         1U,
                         &encrypted) != 0) {
        goto cleanup;
    }
    if (encrypted.key_commitment_len != CRYPTO_ENGINE_COMMITMENT_BYTES) {
        printf("test_key_commitment_tamper_detected: commitment missing\n");
        goto cleanup;
    }

    /* Tampered KEK half must fail before the DEK is even unwrapped. */
    encrypted.key_commitment[0] ^= 0x01U;
    recovered_len = sizeof(recovered);
    if (decrypt_expect_crypto_failure(&encrypted,
                                      kek_enc,
                                      secret_id,
                                      1U,
                                      recovered,
                                      &recovered_len) != 0) {
        goto cleanup;
    }
    encrypted.key_commitment[0] ^= 0x01U;

    /* Tampered DEK half must fail before the payload is decrypted. */
    encrypted.key_commitment[CRYPTO_ENGINE_COMMITMENT_HALF_BYTES] ^= 0x01U;
    recovered_len = sizeof(recovered);
    if (decrypt_expect_crypto_failure(&encrypted,
                                      kek_enc,
                                      secret_id,
                                      1U,
                                      recovered,
                                      &recovered_len) != 0) {
        goto cleanup;
    }
    encrypted.key_commitment[CRYPTO_ENGINE_COMMITMENT_HALF_BYTES] ^= 0x01U;

    /* Missing commitment is rejected as malformed input. */
    encrypted.key_commitment_len = 0U;
    recovered_len = sizeof(recovered);
    if (crypto_engine_decrypt(&encrypted,
                              kek_enc,
                              secret_id,
                              1U,
                              recovered,
                              &recovered_len) != SM_ERR_INVALID_ARGUMENT) {
        printf("test_key_commitment_tamper_detected: "
               "expected invalid argument for missing commitment\n");
        goto cleanup;
    }
    encrypted.key_commitment_len = CRYPTO_ENGINE_COMMITMENT_BYTES;

    /* Restored commitment decrypts again. */
    recovered_len = sizeof(recovered);
    if (decrypt_expect_success(&encrypted,
                               kek_enc,
                               secret_id,
                               1U,
                               recovered,
                               &recovered_len) != 0) {
        goto cleanup;
    }

    failed = (recovered_len != (sizeof(plaintext) - 1U)) ||
             (sodium_memcmp(plaintext, recovered, recovered_len) != 0);
    if (failed) {
        printf("test_key_commitment_tamper_detected: plaintext mismatch\n");
    }

cleanup:
    sodium_memzero(recovered, sizeof(recovered));
    sodium_memzero(kek_enc, sizeof(kek_enc));
    cleanup_secret(&encrypted);
    return failed;
}

int test_crypto_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_crypto_run: sodium_init failed\n");
        return 1;
    }

    failed += test_encrypt_decrypt_roundtrip();
    failed += test_encrypt_different_ciphertext();
    failed += test_decrypt_wrong_kek();
    failed += test_tampered_ciphertext();
    failed += test_tampered_encrypted_dek();
    failed += test_large_plaintext();
    failed += test_empty_plaintext();
    failed += test_nonce_structure();
    failed += test_aad_prevents_swapping();
    failed += test_aad_version_binding();
    failed += test_nist_aes256_gcm_case16();
    failed += test_encrypt_null_kek();
    failed += test_encrypt_null_secret_id();
    failed += test_encrypt_empty_secret_id();
    failed += test_encrypt_null_output();
    failed += test_decrypt_null_input();
    failed += test_aad_overflow();
    failed += test_nonce_counter_zero();
    failed += test_nonce_counter_max();
    failed += test_nonce_deterministic();
    failed += test_dek_nonce_random();
    failed += test_aes256_gcm_requested_algorithm();
    failed += test_xchacha20_requested_algorithm();
    failed += test_xchacha20_decrypt_compatibility();
    failed += test_decrypt_rejects_unknown_algorithm();
    failed += test_encrypt_rejects_unknown_algorithm();
    failed += test_decrypt_rejects_small_output_buffer();
    failed += test_crypto_engine_lifecycle_helpers();
    failed += test_aegis256_roundtrip();
    failed += test_key_commitment_tamper_detected();

    if (failed != 0) {
        printf("test_crypto_run: %d failures\n", failed);
    }

    return failed == 0 ? 0 : 1;
}
