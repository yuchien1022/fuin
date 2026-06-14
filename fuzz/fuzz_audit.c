#include "audit.h"
#include "storage.h"
#include "utils.h"

#include <sodium.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_AUDIT_DB "results/fuzz/audit_fuzz.db"
#define FUZZ_AUDIT_MAX_ROWS 4U
#define FUZZ_AUDIT_MAX_TEXT 32U
#define FUZZ_AUDIT_MAX_BLOB 64U

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

static void fuzz_take_text(fuzz_cursor_t *cursor, char *output, size_t output_len)
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
    for (size_t i = 0U; i < requested; i++) {
        uint8_t value = fuzz_take_byte(cursor);
        output[i] = (char)(0x20U + (value % 0x5FU));
    }
    if (requested == 0U) {
        output[0] = 'x';
        requested = 1U;
    }
    output[requested] = '\0';
}

static size_t fuzz_blob_len(fuzz_cursor_t *cursor)
{
    size_t len = (size_t)(fuzz_take_byte(cursor) % (FUZZ_AUDIT_MAX_BLOB + 1U));
    size_t available = fuzz_remaining(cursor);

    return len > available ? available : len;
}

static const char *fuzz_action(uint8_t selector)
{
    static const char *const actions[] = {
        "CREATE",
        "READ",
        "UPDATE",
        "DELETE",
        "ROLLBACK",
        "ROTATE_KEK",
        "ROTATE_DEK",
    };

    return actions[selector % (sizeof(actions) / sizeof(actions[0]))];
}

static const char *fuzz_result(uint8_t selector)
{
    return (selector & 1U) == 0U ? "SUCCESS" : "FAILURE";
}

static int fuzz_bind_blob(sqlite3_stmt *stmt, int index, fuzz_cursor_t *cursor)
{
    size_t len = fuzz_blob_len(cursor);
    const void *blob = NULL;

    if ((stmt == NULL) || (cursor == NULL)) {
        return SQLITE_MISUSE;
    }
    if (len > 0U) {
        blob = cursor->data + cursor->offset;
    }
    cursor->offset += len;
    return sqlite3_bind_blob(stmt, index, blob, (int)len, SQLITE_TRANSIENT);
}

static void fuzz_reset_audit_log(void)
{
    sqlite3 *db = storage_get_db();

    if (db == NULL) {
        return;
    }
    (void)sqlite3_exec(db, "DELETE FROM audit_log;", NULL, NULL, NULL);
    (void)sqlite3_exec(db,
                       "DELETE FROM sqlite_sequence WHERE name = 'audit_log';",
                       NULL,
                       NULL,
                       NULL);
}

static void fuzz_insert_audit_rows(fuzz_cursor_t *cursor)
{
    static const char *const sql =
        "INSERT INTO audit_log "
        "(timestamp, action, actor, target, target_version, result, "
        "prev_hash, entry_hash, hmac_signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3 *db = storage_get_db();
    sqlite3_stmt *stmt = NULL;
    size_t row_count = 0U;

    if ((db == NULL) || (cursor == NULL)) {
        return;
    }

    row_count = (size_t)(fuzz_take_byte(cursor) % (FUZZ_AUDIT_MAX_ROWS + 1U));
    for (size_t row = 0U; row < row_count; row++) {
        char timestamp[FUZZ_AUDIT_MAX_TEXT + 1U];
        char actor[FUZZ_AUDIT_MAX_TEXT + 1U];
        char target[FUZZ_AUDIT_MAX_TEXT + 1U];
        int target_version = (int)fuzz_take_byte(cursor);
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

        if (rc != SQLITE_OK) {
            return;
        }
        fuzz_take_text(cursor, timestamp, sizeof(timestamp));
        fuzz_take_text(cursor, actor, sizeof(actor));
        fuzz_take_text(cursor, target, sizeof(target));

        rc = sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_TRANSIENT);
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(stmt,
                                   2,
                                   fuzz_action(fuzz_take_byte(cursor)),
                                   -1,
                                   SQLITE_STATIC);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(stmt, 3, actor, -1, SQLITE_TRANSIENT);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(stmt, 4, target, -1, SQLITE_TRANSIENT);
        }
        if (rc == SQLITE_OK) {
            if ((fuzz_take_byte(cursor) & 1U) == 0U) {
                rc = sqlite3_bind_null(stmt, 5);
            } else {
                rc = sqlite3_bind_int(stmt, 5, target_version);
            }
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(stmt,
                                   6,
                                   fuzz_result(fuzz_take_byte(cursor)),
                                   -1,
                                   SQLITE_STATIC);
        }
        if (rc == SQLITE_OK) {
            rc = fuzz_bind_blob(stmt, 7, cursor);
        }
        if (rc == SQLITE_OK) {
            rc = fuzz_bind_blob(stmt, 8, cursor);
        }
        if (rc == SQLITE_OK) {
            rc = fuzz_bind_blob(stmt, 9, cursor);
        }
        if (rc == SQLITE_OK) {
            (void)sqlite3_step(stmt);
        }
        (void)sqlite3_finalize(stmt);
        stmt = NULL;
    }
}

static void fuzz_exercise_audit_apis(const uint8_t *data, size_t size)
{
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    size_t leaf_count = 0U;
    size_t proof_len = 0U;
    size_t leaf_index = 0U;
    fuzz_cursor_t cursor = {data, size, 0U};

    sodium_memzero(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    (void)crypto_hash_sha256(key, data, (unsigned long long)size);

    fuzz_reset_audit_log();
    fuzz_insert_audit_rows(&cursor);

    (void)audit_verify_chain(key, sizeof(key));
    if (audit_compute_merkle_root(root, sizeof(root), &leaf_count) == SM_OK) {
        if (leaf_count > 0U) {
            int entry_id = 1 + (int)(fuzz_take_byte(&cursor) % (uint8_t)leaf_count);

            (void)audit_build_merkle_proof(entry_id,
                                           proof,
                                           sizeof(proof),
                                           &proof_len,
                                           &leaf_index,
                                           &leaf_count);
        }
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized;

    if ((data == NULL) || (size > 4096U)) {
        return 0;
    }
    if (!initialized) {
        (void)sodium_init();
        (void)remove(FUZZ_AUDIT_DB);
        if (storage_init(FUZZ_AUDIT_DB) != SM_OK) {
            return 0;
        }
        initialized = 1;
    }

    fuzz_exercise_audit_apis(data, size);
    return 0;
}
