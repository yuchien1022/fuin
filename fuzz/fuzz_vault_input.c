#include "vault.h"

#include "utils.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_VAULT_DB "results/fuzz/vault_input_fuzz.db"
#define FUZZ_VAULT_PASSWORD "fuzz-password"
#define FUZZ_VAULT_RESET_INTERVAL 128U
#define FUZZ_VAULT_MAX_NAME 128U
#define FUZZ_VAULT_MAX_VALUE 256U

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t offset;
} fuzz_cursor_t;

static uint8_t fuzz_take_byte(fuzz_cursor_t *cursor)
{
    if ((cursor == NULL) || (cursor->offset >= cursor->len)) {
        return 0U;
    }
    return cursor->data[cursor->offset++];
}

static size_t fuzz_remaining(const fuzz_cursor_t *cursor)
{
    if ((cursor == NULL) || (cursor->offset >= cursor->len)) {
        return 0U;
    }
    return cursor->len - cursor->offset;
}

static void fuzz_take_c_string(fuzz_cursor_t *cursor,
                               char *output,
                               size_t output_len)
{
    size_t requested = 0U;
    size_t available = 0U;

    if ((cursor == NULL) || (output == NULL) || (output_len == 0U)) {
        return;
    }

    requested = (size_t)(fuzz_take_byte(cursor) % (uint8_t)output_len);
    available = fuzz_remaining(cursor);
    if (requested > (output_len - 1U)) {
        requested = output_len - 1U;
    }
    if (requested > available) {
        requested = available;
    }
    if (requested > 0U) {
        memcpy(output, cursor->data + cursor->offset, requested);
    }
    cursor->offset += requested;
    output[requested] = '\0';
}

static size_t fuzz_take_value(fuzz_cursor_t *cursor,
                              unsigned char *output,
                              size_t output_len)
{
    size_t requested = 0U;
    size_t available = 0U;

    if ((cursor == NULL) || (output == NULL) || (output_len == 0U)) {
        return 0U;
    }

    requested = (size_t)fuzz_take_byte(cursor);
    if (requested > output_len) {
        requested %= (output_len + 1U);
    }
    available = fuzz_remaining(cursor);
    if (requested > output_len) {
        requested = output_len;
    }
    if (requested > available) {
        requested = available;
    }
    if (requested > 0U) {
        memcpy(output, cursor->data + cursor->offset, requested);
    }
    cursor->offset += requested;
    return requested;
}

static void fuzz_remove_db_files(void)
{
    (void)remove(FUZZ_VAULT_DB);
    (void)remove("results/fuzz/vault_input_fuzz.db-shm");
    (void)remove("results/fuzz/vault_input_fuzz.db-wal");
}

static int fuzz_reset_vault(void)
{
    (void)vault_close();
    fuzz_remove_db_files();
    if (vault_init(FUZZ_VAULT_DB) != SM_OK) {
        return 0;
    }
    return vault_unlock(FUZZ_VAULT_PASSWORD) == SM_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized;
    static size_t iteration_count;
    char name[FUZZ_VAULT_MAX_NAME + 1U];
    unsigned char value[FUZZ_VAULT_MAX_VALUE];
    unsigned char output[FUZZ_VAULT_MAX_VALUE];
    size_t value_len = 0U;
    size_t output_len = 0U;
    int version = 0;
    fuzz_cursor_t cursor = {data, size, 0U};

    if ((data == NULL) || (size > 4096U)) {
        return 0;
    }
    if (!initialized || ((iteration_count % FUZZ_VAULT_RESET_INTERVAL) == 0U)) {
        initialized = fuzz_reset_vault();
        if (!initialized) {
            return 0;
        }
    }
    iteration_count++;

    sodium_memzero(name, sizeof(name));
    sodium_memzero(value, sizeof(value));
    sodium_memzero(output, sizeof(output));
    fuzz_take_c_string(&cursor, name, sizeof(name));
    value_len = fuzz_take_value(&cursor, value, sizeof(value));
    output_len = sizeof(output);
    version = 1 + (int)(fuzz_take_byte(&cursor) % 4U);

    switch (fuzz_take_byte(&cursor) % 6U) {
    case 0:
        (void)vault_put(name, value, value_len);
        break;
    case 1:
        (void)vault_put(name, value, value_len);
        output_len = sizeof(output);
        (void)vault_get(name, output, output_len, &output_len);
        break;
    case 2:
        (void)vault_put(name, value, value_len);
        output_len = sizeof(output);
        (void)vault_get_version(name, version, output, output_len, &output_len);
        break;
    case 3:
        (void)vault_delete(name);
        break;
    case 4:
        (void)vault_put(name, value, value_len);
        (void)vault_rollback(name, version);
        break;
    default:
        (void)vault_audit_verify();
        break;
    }

    sodium_memzero(name, sizeof(name));
    sodium_memzero(value, sizeof(value));
    sodium_memzero(output, sizeof(output));
    return 0;
}
