#define _POSIX_C_SOURCE 200809L

#include "key_manager.h"
#include "utils.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_ROTATION_AAD "bench-rotation:1"
#define BENCH_ROTATION_ENVELOPE_ID "bench-envelope-secret"
#define BENCH_ROTATION_VERSION 1U

typedef struct {
    const char *key_manager_name;
    int use_aes_gcm;
    size_t nonce_len;
    size_t tag_len;
} bench_rotation_algorithm_t;

typedef struct {
    unsigned char *data;
    size_t len;
} bench_buffer_t;

static const size_t default_counts[] = {100U, 500U, 1000U, 5000U};
static const size_t default_sizes[] = {32U, 1024U, 65536U, 1048576U};
static const size_t quick_counts[] = {10U, 50U};
static const size_t quick_sizes[] = {32U, 1024U};

static void bench_write_u64_le(unsigned char *output, uint64_t value)
{
    size_t i = 0U;

    for (i = 0U; i < 8U; i++) {
        output[i] = (unsigned char)(value >> (i * 8U));
    }
}

static int bench_select_algorithm(bench_rotation_algorithm_t *algorithm)
{
    if (algorithm == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (crypto_aead_aes256gcm_is_available() == 1) {
        algorithm->key_manager_name = "AES-256-GCM";
        algorithm->use_aes_gcm = 1;
        algorithm->nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
        algorithm->tag_len = crypto_aead_aes256gcm_ABYTES;
    } else {
        algorithm->key_manager_name = "XChaCha20-Poly1305";
        algorithm->use_aes_gcm = 0;
        algorithm->nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        algorithm->tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    }

    return SM_OK;
}

static void bench_build_nonce(const bench_rotation_algorithm_t *algorithm,
                              uint64_t counter,
                              unsigned char *nonce,
                              size_t nonce_len)
{
    static const unsigned char aes_prefix[4] = {0x42U, 0x45U, 0x4eU, 0x43U};
    static const unsigned char xchacha_prefix[16] = {
        0x42U, 0x45U, 0x4eU, 0x43U, 0x48U, 0x2dU, 0x52U, 0x4fU,
        0x54U, 0x41U, 0x54U, 0x45U, 0x2dU, 0x4eU, 0x4fU, 0x4eU,
    };

    if ((algorithm == NULL) || (nonce == NULL)) {
        return;
    }

    sodium_memzero(nonce, nonce_len);
    if (algorithm->use_aes_gcm) {
        if (nonce_len >= crypto_aead_aes256gcm_NPUBBYTES) {
            memcpy(nonce, aes_prefix, sizeof(aes_prefix));
            bench_write_u64_le(nonce + sizeof(aes_prefix), counter);
        }
    } else if (nonce_len >= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        memcpy(nonce, xchacha_prefix, sizeof(xchacha_prefix));
        bench_write_u64_le(nonce + sizeof(xchacha_prefix), counter);
    }
}

static int bench_now(struct timespec *ts)
{
    if (ts == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        return SM_ERR_STORAGE;
    }
    return SM_OK;
#else
    return timespec_get(ts, TIME_UTC) == TIME_UTC ? SM_OK : SM_ERR_STORAGE;
#endif
}

static double bench_elapsed_ms(const struct timespec *start,
                               const struct timespec *end)
{
    double seconds = 0.0;
    double nanoseconds = 0.0;

    seconds = (double)(end->tv_sec - start->tv_sec);
    nanoseconds = (double)(end->tv_nsec - start->tv_nsec);
    return (seconds * 1000.0) + (nanoseconds / 1000000.0);
}

static int bench_alloc_buffer(bench_buffer_t *buffer, size_t len)
{
    if ((buffer == NULL) || (len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    buffer->data = sodium_malloc(len);
    if (buffer->data == NULL) {
        buffer->len = 0U;
        return SM_ERR_STORAGE;
    }
    buffer->len = len;
    sodium_memzero(buffer->data, buffer->len);
    return SM_OK;
}

static void bench_free_buffer(bench_buffer_t *buffer)
{
    if ((buffer == NULL) || (buffer->data == NULL)) {
        return;
    }

    sodium_memzero(buffer->data, buffer->len);
    sodium_free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0U;
}

static int bench_encrypt_payload(const bench_rotation_algorithm_t *algorithm,
                                 unsigned char *ciphertext,
                                 size_t ciphertext_capacity,
                                 size_t *ciphertext_len,
                                 const unsigned char *plaintext,
                                 size_t plaintext_len,
                                 const unsigned char *aad,
                                 size_t aad_len,
                                 const unsigned char *nonce,
                                 const unsigned char *key)
{
    unsigned long long written = 0U;
    int rc = 0;

    if ((algorithm == NULL) || (ciphertext == NULL) || (ciphertext_len == NULL) ||
        ((plaintext == NULL) && (plaintext_len > 0U)) || (aad == NULL) ||
        (nonce == NULL) || (key == NULL) ||
        (plaintext_len > (SIZE_MAX - algorithm->tag_len)) ||
        (ciphertext_capacity < (plaintext_len + algorithm->tag_len))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (algorithm->use_aes_gcm) {
        rc = crypto_aead_aes256gcm_encrypt(ciphertext,
                                           &written,
                                           plaintext,
                                           (unsigned long long)plaintext_len,
                                           aad,
                                           (unsigned long long)aad_len,
                                           NULL,
                                           nonce,
                                           key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext,
                                                        &written,
                                                        plaintext,
                                                        (unsigned long long)plaintext_len,
                                                        aad,
                                                        (unsigned long long)aad_len,
                                                        NULL,
                                                        nonce,
                                                        key);
    }
    if (rc != 0) {
        sodium_memzero(ciphertext, ciphertext_capacity);
        return SM_ERR_CRYPTO;
    }

    *ciphertext_len = (size_t)written;
    return SM_OK;
}

static int bench_decrypt_payload(const bench_rotation_algorithm_t *algorithm,
                                 unsigned char *plaintext,
                                 size_t plaintext_capacity,
                                 size_t *plaintext_len,
                                 const unsigned char *ciphertext,
                                 size_t ciphertext_len,
                                 const unsigned char *aad,
                                 size_t aad_len,
                                 const unsigned char *nonce,
                                 const unsigned char *key)
{
    unsigned long long written = 0U;
    int rc = 0;

    if ((algorithm == NULL) || (plaintext == NULL) || (plaintext_len == NULL) ||
        (ciphertext == NULL) || (aad == NULL) || (nonce == NULL) || (key == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (algorithm->use_aes_gcm) {
        rc = crypto_aead_aes256gcm_decrypt(plaintext,
                                           &written,
                                           NULL,
                                           ciphertext,
                                           (unsigned long long)ciphertext_len,
                                           aad,
                                           (unsigned long long)aad_len,
                                           nonce,
                                           key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext,
                                                        &written,
                                                        NULL,
                                                        ciphertext,
                                                        (unsigned long long)ciphertext_len,
                                                        aad,
                                                        (unsigned long long)aad_len,
                                                        nonce,
                                                        key);
    }
    if ((rc != 0) || ((size_t)written > plaintext_capacity)) {
        sodium_memzero(plaintext, plaintext_capacity);
        return SM_ERR_CRYPTO;
    }

    *plaintext_len = (size_t)written;
    return SM_OK;
}

static int bench_envelope_rotation(const bench_rotation_algorithm_t *algorithm,
                                   size_t num_secrets,
                                   double *elapsed_ms)
{
    unsigned char old_kek[KEY_MANAGER_DEK_BYTES];
    unsigned char new_kek[KEY_MANAGER_DEK_BYTES];
    unsigned char dek[KEY_MANAGER_DEK_BYTES];
    unsigned char old_wrapped[KEY_MANAGER_WRAPPED_DEK_BYTES];
    unsigned char new_wrapped[KEY_MANAGER_WRAPPED_DEK_BYTES];
    unsigned char old_dek_nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    unsigned char new_dek_nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    size_t old_wrapped_len = 0U;
    size_t new_wrapped_len = 0U;
    size_t old_dek_nonce_len = 0U;
    size_t new_dek_nonce_len = 0U;
    size_t dek_written = 0U;
    struct timespec start;
    struct timespec end;
    int status = SM_OK;

    if ((algorithm == NULL) || (elapsed_ms == NULL) || (num_secrets == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(old_kek, sizeof(old_kek));
    sodium_memzero(new_kek, sizeof(new_kek));
    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(old_wrapped, sizeof(old_wrapped));
    sodium_memzero(new_wrapped, sizeof(new_wrapped));
    sodium_memzero(old_dek_nonce, sizeof(old_dek_nonce));
    sodium_memzero(new_dek_nonce, sizeof(new_dek_nonce));

    randombytes_buf(old_kek, sizeof(old_kek));
    randombytes_buf(new_kek, sizeof(new_kek));
    status = key_manager_generate_dek(dek, sizeof(dek));
    if (status == SM_OK) {
        status = key_manager_wrap_dek(algorithm->key_manager_name,
                                      BENCH_ROTATION_ENVELOPE_ID,
                                      BENCH_ROTATION_VERSION,
                                      dek,
                                      sizeof(dek),
                                      old_kek,
                                      sizeof(old_kek),
                                      old_dek_nonce,
                                      sizeof(old_dek_nonce),
                                      &old_dek_nonce_len,
                                      old_wrapped,
                                      sizeof(old_wrapped),
                                      &old_wrapped_len);
    }
    sodium_memzero(dek, sizeof(dek));
    if (status != SM_OK) {
        goto cleanup;
    }

    status = bench_now(&start);
    for (size_t i = 0U; (status == SM_OK) && (i < num_secrets); i++) {
        status = key_manager_unwrap_dek(algorithm->key_manager_name,
                                        BENCH_ROTATION_ENVELOPE_ID,
                                        BENCH_ROTATION_VERSION,
                                        old_wrapped,
                                        old_wrapped_len,
                                        old_dek_nonce,
                                        old_dek_nonce_len,
                                        old_kek,
                                        sizeof(old_kek),
                                        dek,
                                        sizeof(dek),
                                        &dek_written);
        if (status == SM_OK) {
            status = key_manager_wrap_dek(algorithm->key_manager_name,
                                          BENCH_ROTATION_ENVELOPE_ID,
                                          BENCH_ROTATION_VERSION,
                                          dek,
                                          dek_written,
                                          new_kek,
                                          sizeof(new_kek),
                                          new_dek_nonce,
                                          sizeof(new_dek_nonce),
                                          &new_dek_nonce_len,
                                          new_wrapped,
                                          sizeof(new_wrapped),
                                          &new_wrapped_len);
        }
        sodium_memzero(dek, sizeof(dek));
    }
    if (status == SM_OK) {
        status = bench_now(&end);
    }
    if (status == SM_OK) {
        *elapsed_ms = bench_elapsed_ms(&start, &end);
    }

cleanup:
    sodium_memzero(old_kek, sizeof(old_kek));
    sodium_memzero(new_kek, sizeof(new_kek));
    sodium_memzero(dek, sizeof(dek));
    sodium_memzero(old_wrapped, sizeof(old_wrapped));
    sodium_memzero(new_wrapped, sizeof(new_wrapped));
    sodium_memzero(old_dek_nonce, sizeof(old_dek_nonce));
    sodium_memzero(new_dek_nonce, sizeof(new_dek_nonce));
    return status;
}

static int bench_naive_rotation(const bench_rotation_algorithm_t *algorithm,
                                size_t num_secrets,
                                size_t secret_size,
                                double *elapsed_ms)
{
    static const unsigned char aad[] = BENCH_ROTATION_AAD;
    bench_buffer_t plaintext = {NULL, 0U};
    bench_buffer_t recovered = {NULL, 0U};
    bench_buffer_t old_ciphertext = {NULL, 0U};
    bench_buffer_t new_ciphertext = {NULL, 0U};
    unsigned char old_key[KEY_MANAGER_DEK_BYTES];
    unsigned char new_key[KEY_MANAGER_DEK_BYTES];
    unsigned char old_nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    unsigned char new_nonce[KEY_MANAGER_MAX_NONCE_BYTES];
    size_t old_ciphertext_len = 0U;
    size_t new_ciphertext_len = 0U;
    size_t recovered_len = 0U;
    struct timespec start;
    struct timespec end;
    int status = SM_OK;

    if ((algorithm == NULL) || (num_secrets == 0U) || (secret_size == 0U) ||
        (elapsed_ms == NULL) || (secret_size > (SIZE_MAX - algorithm->tag_len))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(old_key, sizeof(old_key));
    sodium_memzero(new_key, sizeof(new_key));
    sodium_memzero(old_nonce, sizeof(old_nonce));
    sodium_memzero(new_nonce, sizeof(new_nonce));

    randombytes_buf(old_key, sizeof(old_key));
    randombytes_buf(new_key, sizeof(new_key));
    status = bench_alloc_buffer(&plaintext, secret_size);
    if (status == SM_OK) {
        status = bench_alloc_buffer(&recovered, secret_size);
    }
    if (status == SM_OK) {
        status = bench_alloc_buffer(&old_ciphertext, secret_size + algorithm->tag_len);
    }
    if (status == SM_OK) {
        status = bench_alloc_buffer(&new_ciphertext, secret_size + algorithm->tag_len);
    }
    if (status != SM_OK) {
        goto cleanup;
    }

    randombytes_buf(plaintext.data, plaintext.len);
    bench_build_nonce(algorithm, 1U, old_nonce, sizeof(old_nonce));
    status = bench_encrypt_payload(algorithm,
                                   old_ciphertext.data,
                                   old_ciphertext.len,
                                   &old_ciphertext_len,
                                   plaintext.data,
                                   plaintext.len,
                                   aad,
                                   sizeof(aad) - 1U,
                                   old_nonce,
                                   old_key);
    if (status != SM_OK) {
        goto cleanup;
    }

    status = bench_now(&start);
    for (size_t i = 0U; (status == SM_OK) && (i < num_secrets); i++) {
        status = bench_decrypt_payload(algorithm,
                                       recovered.data,
                                       recovered.len,
                                       &recovered_len,
                                       old_ciphertext.data,
                                       old_ciphertext_len,
                                       aad,
                                       sizeof(aad) - 1U,
                                       old_nonce,
                                       old_key);
        if ((status == SM_OK) && (recovered_len != plaintext.len)) {
            status = SM_ERR_CRYPTO;
        }
        if (status == SM_OK) {
            bench_build_nonce(algorithm,
                              (uint64_t)i + 2U,
                              new_nonce,
                              sizeof(new_nonce));
            status = bench_encrypt_payload(algorithm,
                                           new_ciphertext.data,
                                           new_ciphertext.len,
                                           &new_ciphertext_len,
                                           recovered.data,
                                           recovered_len,
                                           aad,
                                           sizeof(aad) - 1U,
                                           new_nonce,
                                           new_key);
        }
    }
    if (status == SM_OK) {
        status = bench_now(&end);
    }
    if (status == SM_OK) {
        *elapsed_ms = bench_elapsed_ms(&start, &end);
    }

cleanup:
    sodium_memzero(old_key, sizeof(old_key));
    sodium_memzero(new_key, sizeof(new_key));
    sodium_memzero(old_nonce, sizeof(old_nonce));
    sodium_memzero(new_nonce, sizeof(new_nonce));
    bench_free_buffer(&plaintext);
    bench_free_buffer(&recovered);
    bench_free_buffer(&old_ciphertext);
    bench_free_buffer(&new_ciphertext);
    return status;
}

static int bench_run_matrix(const bench_rotation_algorithm_t *algorithm,
                            const size_t *counts,
                            size_t count_len,
                            const size_t *sizes,
                            size_t size_len)
{
    int status = SM_OK;

    if ((algorithm == NULL) || (counts == NULL) || (count_len == 0U) ||
        (sizes == NULL) || (size_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    puts("num_secrets,secret_size_bytes,envelope_ms,naive_ms,speedup");
    for (size_t i = 0U; (status == SM_OK) && (i < count_len); i++) {
        double envelope_ms = 0.0;

        status = bench_envelope_rotation(algorithm, counts[i], &envelope_ms);
        for (size_t j = 0U; (status == SM_OK) && (j < size_len); j++) {
            double naive_ms = 0.0;
            double speedup = 0.0;

            status = bench_naive_rotation(algorithm, counts[i], sizes[j], &naive_ms);
            if (status == SM_OK) {
                speedup = envelope_ms > 0.0 ? naive_ms / envelope_ms : 0.0;
                printf("%zu,%zu,%.6f,%.6f,%.6f\n",
                       counts[i],
                       sizes[j],
                       envelope_ms,
                       naive_ms,
                       speedup);
                if (fflush(stdout) != 0) {
                    status = SM_ERR_STORAGE;
                }
            }
        }
    }

    return status;
}

static void bench_print_usage(FILE *stream)
{
    fprintf(stream,
            "Usage: bench_rotation [--quick]\n"
            "\n"
            "Outputs CSV columns:\n"
            "  num_secrets,secret_size_bytes,envelope_ms,naive_ms,speedup\n"
            "\n"
            "Default matrix: counts {100,500,1000,5000} x sizes {32B,1KB,64KB,1MB}.\n"
            "--quick uses a small compile/smoke matrix for local sanity checks.\n");
}

int main(int argc, char **argv)
{
    bench_rotation_algorithm_t algorithm;
    const size_t *counts = default_counts;
    const size_t *sizes = default_sizes;
    size_t count_len = sizeof(default_counts) / sizeof(default_counts[0]);
    size_t size_len = sizeof(default_sizes) / sizeof(default_sizes[0]);
    int status = SM_OK;

    if (sodium_init() < 0) {
        fputs("bench_rotation: libsodium initialization failed\n", stderr);
        return 1;
    }

    sodium_memzero(&algorithm, sizeof(algorithm));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quick") == 0) {
            counts = quick_counts;
            sizes = quick_sizes;
            count_len = sizeof(quick_counts) / sizeof(quick_counts[0]);
            size_len = sizeof(quick_sizes) / sizeof(quick_sizes[0]);
        } else if ((strcmp(argv[i], "--help") == 0) ||
                   (strcmp(argv[i], "-h") == 0)) {
            bench_print_usage(stdout);
            return 0;
        } else {
            bench_print_usage(stderr);
            return 2;
        }
    }

    status = bench_select_algorithm(&algorithm);
    if (status == SM_OK) {
        fprintf(stderr,
                "bench_rotation: algorithm=%s\n",
                algorithm.key_manager_name);
        status = bench_run_matrix(&algorithm, counts, count_len, sizes, size_len);
    }
    if (status != SM_OK) {
        fprintf(stderr, "bench_rotation: %s\n", utils_status_message(status));
        return 1;
    }

    return 0;
}
