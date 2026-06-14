#include "kdf.h"
#include "utils.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int buffer_is_zero(const unsigned char *buffer, size_t len)
{
    size_t i = 0;

    for (i = 0; i < len; i++) {
        if (buffer[i] != 0x00U) {
            return 0;
        }
    }

    return 1;
}

static void fill_salt(unsigned char *salt, unsigned char value)
{
    size_t i = 0;

    for (i = 0; i < KDF_SALT_BYTES; i++) {
        salt[i] = value;
    }
}

static int derive_test_key(const char *password_text,
                           const unsigned char *salt,
                           unsigned char *master_key)
{
    char password[64];
    int written = snprintf(password, sizeof(password), "%s", password_text);

    if ((written < 0) || ((size_t)written >= sizeof(password))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return kdf_derive_master_key(password, salt, master_key);
}

static int test_derive_deterministic(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key_a = sodium_malloc(KDF_MASTER_KEY_BYTES);
    unsigned char *master_key_b = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if ((master_key_a == NULL) || (master_key_b == NULL)) {
        printf("test_derive_deterministic: sodium_malloc failed\n");
        goto cleanup;
    }

    fill_salt(salt, 0xA5U);
    if (derive_test_key("same-password", salt, master_key_a) != SM_OK ||
        derive_test_key("same-password", salt, master_key_b) != SM_OK) {
        printf("test_derive_deterministic: derive failed\n");
        goto cleanup;
    }

    ok = sodium_memcmp(master_key_a, master_key_b, KDF_MASTER_KEY_BYTES) == 0;
    if (!ok) {
        printf("test_derive_deterministic: keys differ\n");
    }

cleanup:
    if (master_key_a != NULL) {
        sodium_memzero(master_key_a, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_a);
    }
    if (master_key_b != NULL) {
        sodium_memzero(master_key_b, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_b);
    }
    return ok ? 0 : 1;
}

static int test_derive_different_salt(void)
{
    unsigned char salt_a[KDF_SALT_BYTES];
    unsigned char salt_b[KDF_SALT_BYTES];
    unsigned char *master_key_a = sodium_malloc(KDF_MASTER_KEY_BYTES);
    unsigned char *master_key_b = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if ((master_key_a == NULL) || (master_key_b == NULL)) {
        printf("test_derive_different_salt: sodium_malloc failed\n");
        goto cleanup;
    }

    fill_salt(salt_a, 0x11U);
    fill_salt(salt_b, 0x22U);
    if (derive_test_key("same-password", salt_a, master_key_a) != SM_OK ||
        derive_test_key("same-password", salt_b, master_key_b) != SM_OK) {
        printf("test_derive_different_salt: derive failed\n");
        goto cleanup;
    }

    ok = sodium_memcmp(master_key_a, master_key_b, KDF_MASTER_KEY_BYTES) != 0;
    if (!ok) {
        printf("test_derive_different_salt: keys match\n");
    }

cleanup:
    if (master_key_a != NULL) {
        sodium_memzero(master_key_a, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_a);
    }
    if (master_key_b != NULL) {
        sodium_memzero(master_key_b, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_b);
    }
    return ok ? 0 : 1;
}

static int test_derive_different_password(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key_a = sodium_malloc(KDF_MASTER_KEY_BYTES);
    unsigned char *master_key_b = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if ((master_key_a == NULL) || (master_key_b == NULL)) {
        printf("test_derive_different_password: sodium_malloc failed\n");
        goto cleanup;
    }

    fill_salt(salt, 0x33U);
    if (derive_test_key("password-one", salt, master_key_a) != SM_OK ||
        derive_test_key("password-two", salt, master_key_b) != SM_OK) {
        printf("test_derive_different_password: derive failed\n");
        goto cleanup;
    }

    ok = sodium_memcmp(master_key_a, master_key_b, KDF_MASTER_KEY_BYTES) != 0;
    if (!ok) {
        printf("test_derive_different_password: keys match\n");
    }

cleanup:
    if (master_key_a != NULL) {
        sodium_memzero(master_key_a, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_a);
    }
    if (master_key_b != NULL) {
        sodium_memzero(master_key_b, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_b);
    }
    return ok ? 0 : 1;
}

static int test_subkeys_independent(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    kdf_subkeys_t subkeys;
    int ok = 0;

    if (master_key == NULL) {
        printf("test_subkeys_independent: sodium_malloc failed\n");
        return 1;
    }

    fill_salt(salt, 0x44U);
    if (derive_test_key("subkey-password", salt, master_key) != SM_OK) {
        printf("test_subkeys_independent: derive failed\n");
        goto cleanup;
    }

    if (kdf_derive_subkeys(master_key, &subkeys) != SM_OK) {
        printf("test_subkeys_independent: subkey derive failed\n");
        goto cleanup;
    }

    ok = (sodium_memcmp(subkeys.kek_enc,
                        subkeys.kek_audit,
                        sizeof(subkeys.kek_enc)) != 0) &&
         (sodium_memcmp(subkeys.kek_enc,
                        subkeys.kek_token,
                        sizeof(subkeys.kek_enc)) != 0) &&
         (sodium_memcmp(subkeys.kek_audit,
                        subkeys.kek_token,
                        sizeof(subkeys.kek_audit)) != 0);
    if (!ok) {
        printf("test_subkeys_independent: subkeys match\n");
    }

    sodium_memzero(&subkeys, sizeof(subkeys));

cleanup:
    sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_master_key_zeroed(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    kdf_subkeys_t subkeys;
    int ok = 0;

    if (master_key == NULL) {
        printf("test_master_key_zeroed: sodium_malloc failed\n");
        return 1;
    }

    fill_salt(salt, 0x55U);
    if (derive_test_key("zero-master-key", salt, master_key) != SM_OK) {
        printf("test_master_key_zeroed: derive failed\n");
        goto cleanup;
    }

    if (kdf_derive_subkeys(master_key, &subkeys) != SM_OK) {
        printf("test_master_key_zeroed: subkey derive failed\n");
        goto cleanup;
    }

    ok = buffer_is_zero(master_key, KDF_MASTER_KEY_BYTES);
    if (!ok) {
        printf("test_master_key_zeroed: master key was not cleared\n");
    }

    sodium_memzero(&subkeys, sizeof(subkeys));

cleanup:
    sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_generate_salt_null(void)
{
    int ok = kdf_generate_salt(NULL) == SM_ERR_INVALID_ARGUMENT;

    if (!ok) {
        printf("test_generate_salt_null: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    return ok ? 0 : 1;
}

static int test_derive_null_password(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if (master_key == NULL) {
        printf("test_derive_null_password: sodium_malloc failed\n");
        return 1;
    }

    fill_salt(salt, 0x66U);
    ok = kdf_derive_master_key(NULL, salt, master_key) == SM_ERR_INVALID_ARGUMENT;
    if (!ok) {
        printf("test_derive_null_password: expected SM_ERR_INVALID_ARGUMENT\n");
    }

    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_derive_null_salt(void)
{
    char password[] = "test-password";
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if (master_key == NULL) {
        printf("test_derive_null_salt: sodium_malloc failed\n");
        return 1;
    }

    ok = kdf_derive_master_key(password, NULL, master_key) == SM_ERR_INVALID_ARGUMENT;
    if (!ok) {
        printf("test_derive_null_salt: expected SM_ERR_INVALID_ARGUMENT\n");
    }

    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_derive_null_master_key(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    char password[] = "test-password";
    int ok = 0;

    fill_salt(salt, 0x77U);
    ok = kdf_derive_master_key(password, salt, NULL) == SM_ERR_INVALID_ARGUMENT;
    if (!ok) {
        printf("test_derive_null_master_key: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    return ok ? 0 : 1;
}

static int test_derive_empty_password(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    char password[] = "";
    int ok = 0;

    if (master_key == NULL) {
        printf("test_derive_empty_password: sodium_malloc failed\n");
        return 1;
    }

    fill_salt(salt, 0xAAU);
    if (kdf_derive_master_key(password, salt, master_key) != SM_OK) {
        printf("test_derive_empty_password: derive failed\n");
        sodium_free(master_key);
        return 1;
    }

    ok = !buffer_is_zero(master_key, KDF_MASTER_KEY_BYTES);
    if (!ok) {
        printf("test_derive_empty_password: key is all zero\n");
    }

    sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_derive_password_zeroed(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    char password[64];
    int written = 0;
    int ok = 0;

    if (master_key == NULL) {
        printf("test_derive_password_zeroed: sodium_malloc failed\n");
        return 1;
    }

    fill_salt(salt, 0x88U);
    written = snprintf(password, sizeof(password), "clear-me-password");
    if ((written < 0) || ((size_t)written >= sizeof(password))) {
        printf("test_derive_password_zeroed: snprintf failed\n");
        sodium_free(master_key);
        return 1;
    }

    if (kdf_derive_master_key(password, salt, master_key) != SM_OK) {
        printf("test_derive_password_zeroed: derive failed\n");
        sodium_free(master_key);
        return 1;
    }

    ok = buffer_is_zero((const unsigned char *)password, (size_t)written);
    if (!ok) {
        printf("test_derive_password_zeroed: password not cleared\n");
    }

    sodium_memzero(master_key, KDF_MASTER_KEY_BYTES);
    sodium_free(master_key);
    return ok ? 0 : 1;
}

static int test_subkeys_deterministic(void)
{
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char *master_key_a = sodium_malloc(KDF_MASTER_KEY_BYTES);
    unsigned char *master_key_b = sodium_malloc(KDF_MASTER_KEY_BYTES);
    kdf_subkeys_t subkeys_a;
    kdf_subkeys_t subkeys_b;
    int ok = 0;

    if ((master_key_a == NULL) || (master_key_b == NULL)) {
        printf("test_subkeys_deterministic: sodium_malloc failed\n");
        goto cleanup;
    }

    fill_salt(salt, 0x99U);
    if (derive_test_key("deterministic-subkeys", salt, master_key_a) != SM_OK ||
        derive_test_key("deterministic-subkeys", salt, master_key_b) != SM_OK) {
        printf("test_subkeys_deterministic: derive failed\n");
        goto cleanup;
    }

    if (kdf_derive_subkeys(master_key_a, &subkeys_a) != SM_OK ||
        kdf_derive_subkeys(master_key_b, &subkeys_b) != SM_OK) {
        printf("test_subkeys_deterministic: subkey derive failed\n");
        goto cleanup;
    }

    ok = (sodium_memcmp(subkeys_a.kek_enc, subkeys_b.kek_enc,
                        sizeof(subkeys_a.kek_enc)) == 0) &&
         (sodium_memcmp(subkeys_a.kek_audit, subkeys_b.kek_audit,
                        sizeof(subkeys_a.kek_audit)) == 0) &&
         (sodium_memcmp(subkeys_a.kek_token, subkeys_b.kek_token,
                        sizeof(subkeys_a.kek_token)) == 0);
    if (!ok) {
        printf("test_subkeys_deterministic: subkeys differ\n");
    }

    sodium_memzero(&subkeys_a, sizeof(subkeys_a));
    sodium_memzero(&subkeys_b, sizeof(subkeys_b));

cleanup:
    if (master_key_a != NULL) {
        sodium_memzero(master_key_a, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_a);
    }
    if (master_key_b != NULL) {
        sodium_memzero(master_key_b, KDF_MASTER_KEY_BYTES);
        sodium_free(master_key_b);
    }
    return ok ? 0 : 1;
}

static int test_subkeys_null_master_key(void)
{
    kdf_subkeys_t subkeys;
    int ok = kdf_derive_subkeys(NULL, &subkeys) == SM_ERR_INVALID_ARGUMENT;

    if (!ok) {
        printf("test_subkeys_null_master_key: expected SM_ERR_INVALID_ARGUMENT\n");
    }
    return ok ? 0 : 1;
}

static int test_subkeys_null_subkeys(void)
{
    unsigned char *master_key = sodium_malloc(KDF_MASTER_KEY_BYTES);
    int ok = 0;

    if (master_key == NULL) {
        printf("test_subkeys_null_subkeys: sodium_malloc failed\n");
        return 1;
    }

    randombytes_buf(master_key, KDF_MASTER_KEY_BYTES);
    ok = kdf_derive_subkeys(master_key, NULL) == SM_ERR_INVALID_ARGUMENT;
    if (!ok) {
        printf("test_subkeys_null_subkeys: expected SM_ERR_INVALID_ARGUMENT\n");
    }

    sodium_free(master_key);
    return ok ? 0 : 1;
}

int test_kdf_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_kdf_run: sodium_init failed\n");
        return 1;
    }

    failed += test_derive_deterministic();
    failed += test_derive_different_salt();
    failed += test_derive_different_password();
    failed += test_subkeys_independent();
    failed += test_master_key_zeroed();
    failed += test_generate_salt_null();
    failed += test_derive_null_password();
    failed += test_derive_null_salt();
    failed += test_derive_null_master_key();
    failed += test_derive_empty_password();
    failed += test_derive_password_zeroed();
    failed += test_subkeys_deterministic();
    failed += test_subkeys_null_master_key();
    failed += test_subkeys_null_subkeys();

    if (failed != 0) {
        printf("test_kdf_run: %d failures\n", failed);
    }

    return failed == 0 ? 0 : 1;
}
