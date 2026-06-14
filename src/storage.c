#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
/* Expose O_NOFOLLOW on macOS, which gates it behind _DARWIN_C_SOURCE;
   glibc already provides it under _POSIX_C_SOURCE >= 200809L. */
#define _DARWIN_C_SOURCE
#else
/* Expose realpath() on glibc, which gates it behind _DEFAULT_SOURCE under
   -std=c11. */
#define _DEFAULT_SOURCE
#endif

#include "storage.h"

#include "schema_embedded.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef SQLITE_OPEN_NOFOLLOW
#define SQLITE_OPEN_NOFOLLOW 0
#endif

static sqlite3 *g_db;

static int storage_step_statement(sqlite3_stmt *stmt)
{
    int rc = sqlite3_step(stmt);
    if ((rc != SQLITE_DONE) && (rc != SQLITE_ROW)) {
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

static int storage_execute_sql(const char *sql)
{
    const char *tail = sql;

    if ((g_db == NULL) || (sql == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    while (*tail != '\0') {
        sqlite3_stmt *stmt = NULL;
        const char *next = NULL;
        int status = SM_OK;
        int rc = SQLITE_OK;

        while ((*tail != '\0') && isspace((unsigned char)*tail)) {
            tail++;
        }
        if (*tail == '\0') {
            break;
        }

        rc = sqlite3_prepare_v2(g_db, tail, -1, &stmt, &next);
        if (rc != SQLITE_OK) {
            return SM_ERR_STORAGE;
        }
        if (stmt == NULL) {
            tail = next;
            continue;
        }

        status = storage_step_statement(stmt);
        rc = sqlite3_finalize(stmt);
        if ((status != SM_OK) || (rc != SQLITE_OK)) {
            return SM_ERR_STORAGE;
        }

        tail = next;
    }

    return SM_OK;
}

static int storage_read_file(const char *path, char **content)
{
    FILE *file = NULL;
    long file_size = 0;
    size_t bytes_read = 0;
    char *buffer = NULL;

    if ((path == NULL) || (content == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *content = NULL;
    file = fopen(path, "rb");
    if (file == NULL) {
        return SM_ERR_STORAGE;
    }

    if (fseek(file, 0L, SEEK_END) != 0) {
        fclose(file);
        return SM_ERR_STORAGE;
    }

    file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return SM_ERR_STORAGE;
    }

    if (fseek(file, 0L, SEEK_SET) != 0) {
        fclose(file);
        return SM_ERR_STORAGE;
    }

    buffer = malloc((size_t)file_size + 1U);
    if (buffer == NULL) {
        fclose(file);
        return SM_ERR_STORAGE;
    }

    bytes_read = fread(buffer, 1U, (size_t)file_size, file);
    if (bytes_read != (size_t)file_size) {
        free(buffer);
        fclose(file);
        return SM_ERR_STORAGE;
    }

    buffer[bytes_read] = '\0';
    if (fclose(file) != 0) {
        free(buffer);
        return SM_ERR_STORAGE;
    }

    *content = buffer;
    return SM_OK;
}

static int storage_require_table(const char *table_name)
{
    static const char *const sql =
        "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int status = SM_ERR_STORAGE;

    if ((g_db == NULL) || (table_name == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_bind_text(stmt, 1, "table", -1, SQLITE_STATIC);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, table_name, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return SM_ERR_STORAGE;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        status = SM_OK;
    }

    rc = sqlite3_finalize(stmt);
    if ((status != SM_OK) || (rc != SQLITE_OK)) {
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

typedef struct {
    const char *name;
    const char *type;
    int not_null;
    int primary_key;
} storage_required_column_t;

static int storage_require_column(const char *table_name,
                                  const storage_required_column_t *required)
{
    sqlite3_stmt *stmt = NULL;
    char *sql = NULL;
    int rc = SQLITE_OK;
    int found = 0;
    int status = SM_ERR_STORAGE;

    if ((g_db == NULL) || (table_name == NULL) || (required == NULL) ||
        (required->name == NULL) || (required->type == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sql = sqlite3_mprintf("PRAGMA table_info(%Q);", table_name);
    if (sql == NULL) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        const unsigned char *type = sqlite3_column_text(stmt, 2);
        int not_null = sqlite3_column_int(stmt, 3) != 0;
        int primary_key = sqlite3_column_int(stmt, 5) != 0;

        if ((name != NULL) &&
            (strcmp((const char *)name, required->name) == 0)) {
            found = 1;
            if ((type == NULL) ||
                (sqlite3_stricmp((const char *)type, required->type) != 0) ||
                (required->not_null && !not_null) ||
                (required->primary_key && !primary_key)) {
                status = SM_ERR_STORAGE;
            } else {
                status = SM_OK;
            }
            break;
        }
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        status = SM_ERR_STORAGE;
    }
    if (!found) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int storage_require_columns(const char *table_name,
                                   const storage_required_column_t *columns,
                                   size_t column_count)
{
    size_t i = 0U;

    if ((table_name == NULL) || (columns == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    for (i = 0U; i < column_count; i++) {
        int status = storage_require_column(table_name, &columns[i]);
        if (status != SM_OK) {
            return status;
        }
    }
    return SM_OK;
}

static int storage_require_index(const char *table_name,
                                 const char *index_name,
                                 int unique,
                                 int partial)
{
    sqlite3_stmt *stmt = NULL;
    char *sql = NULL;
    int rc = SQLITE_OK;
    int found = 0;
    int status = SM_ERR_STORAGE;

    if ((g_db == NULL) || (table_name == NULL) || (index_name == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sql = sqlite3_mprintf("PRAGMA index_list(%Q);", table_name);
    if (sql == NULL) {
        return SM_ERR_STORAGE;
    }
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        return SM_ERR_STORAGE;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        int is_unique = sqlite3_column_int(stmt, 2) != 0;
        int is_partial = sqlite3_column_count(stmt) > 4
                             ? (sqlite3_column_int(stmt, 4) != 0)
                             : 0;

        if ((name != NULL) && (strcmp((const char *)name, index_name) == 0)) {
            found = 1;
            status = ((is_unique == unique) && (is_partial == partial))
                         ? SM_OK
                         : SM_ERR_STORAGE;
            break;
        }
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        status = SM_ERR_STORAGE;
    }
    if (!found) {
        status = SM_ERR_STORAGE;
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int storage_verify_schema(void)
{
    static const char *const required_tables[] = {
        "secrets",
        "audit_log",
        "metadata",
        "auth_failures",
    };
    static const storage_required_column_t secrets_columns[] = {
        {"id", "TEXT", 0, 1},
        {"name", "TEXT", 1, 0},
        {"name_nonce", "BLOB", 1, 0},
        {"encrypted_name", "BLOB", 1, 0},
        {"version", "INTEGER", 1, 0},
        {"algorithm", "TEXT", 1, 0},
        {"ciphertext", "BLOB", 1, 0},
        {"encrypted_dek", "BLOB", 1, 0},
        {"nonce", "BLOB", 1, 0},
        {"dek_nonce", "BLOB", 1, 0},
        {"key_commitment", "BLOB", 1, 0},
        {"nonce_counter", "INTEGER", 1, 0},
        {"created_at", "TEXT", 1, 0},
        {"updated_at", "TEXT", 1, 0},
        {"expires_at", "TEXT", 0, 0},
        {"rotation_interval_seconds", "INTEGER", 0, 0},
        {"tags", "TEXT", 0, 0},
        {"is_archived", "INTEGER", 1, 0},
    };
    static const storage_required_column_t audit_columns[] = {
        {"entry_id", "INTEGER", 0, 1},
        {"timestamp", "TEXT", 1, 0},
        {"action", "TEXT", 1, 0},
        {"actor", "TEXT", 1, 0},
        {"target", "TEXT", 1, 0},
        {"target_version", "INTEGER", 0, 0},
        {"result", "TEXT", 1, 0},
        {"prev_hash", "BLOB", 1, 0},
        {"entry_hash", "BLOB", 1, 0},
        {"hmac_signature", "BLOB", 1, 0},
    };
    static const storage_required_column_t metadata_columns[] = {
        {"key", "TEXT", 0, 1},
        {"value", "BLOB", 1, 0},
    };
    static const storage_required_column_t auth_failure_columns[] = {
        {"event_id", "INTEGER", 0, 1},
        {"timestamp", "TEXT", 1, 0},
        {"result", "TEXT", 1, 0},
    };
    size_t i = 0;

    for (i = 0; i < (sizeof(required_tables) / sizeof(required_tables[0])); i++) {
        int status = storage_require_table(required_tables[i]);
        if (status != SM_OK) {
            return status;
        }
    }

    if (storage_require_columns("secrets",
                                secrets_columns,
                                sizeof(secrets_columns) /
                                    sizeof(secrets_columns[0])) != SM_OK) {
        return SM_ERR_STORAGE;
    }
    if (storage_require_columns("audit_log",
                                audit_columns,
                                sizeof(audit_columns) /
                                    sizeof(audit_columns[0])) != SM_OK) {
        return SM_ERR_STORAGE;
    }
    if (storage_require_columns("metadata",
                                metadata_columns,
                                sizeof(metadata_columns) /
                                    sizeof(metadata_columns[0])) != SM_OK) {
        return SM_ERR_STORAGE;
    }
    if (storage_require_columns("auth_failures",
                                auth_failure_columns,
                                sizeof(auth_failure_columns) /
                                    sizeof(auth_failure_columns[0])) != SM_OK) {
        return SM_ERR_STORAGE;
    }
    if (storage_require_index("secrets", "idx_secrets_name_active", 1, 1) != SM_OK) {
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

/* Tighten a sidecar (WAL/SHM) to owner-only (0600) via an O_NOFOLLOW fd +
   fchmod rather than path-based chmod(), which follows symlinks. A pre-planted
   symlink at the "-wal"/"-shm" path would otherwise redirect the chmod onto
   another file the user owns (the same vector FIXED-044 closed for the main DB
   open). O_NOFOLLOW makes the open fail instead, so we never tighten an
   attacker-chosen target. A missing sidecar is not an error when allow_missing
   is set (the file may not have been created yet). */
static int storage_chmod_owner_only(const char *path, int allow_missing)
{
    int fd = -1;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (allow_missing && (errno == ENOENT)) {
            return SM_OK;
        }
        return SM_ERR_STORAGE;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (close(fd) != 0) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int storage_chmod_sidecar(const char *db_path, const char *suffix)
{
    char *sidecar_path = NULL;
    size_t db_len = 0U;
    size_t suffix_len = 0U;
    int status = SM_OK;

    if ((db_path == NULL) || (suffix == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    db_len = strlen(db_path);
    suffix_len = strlen(suffix);
    if (db_len > (SIZE_MAX - suffix_len - 1U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sidecar_path = malloc(db_len + suffix_len + 1U);
    if (sidecar_path == NULL) {
        return SM_ERR_STORAGE;
    }
    memcpy(sidecar_path, db_path, db_len);
    memcpy(sidecar_path + db_len, suffix, suffix_len + 1U);

    status = storage_chmod_owner_only(sidecar_path, 1);
    free(sidecar_path);
    return status;
}

static int storage_chmod_wal_sidecars(const char *db_path)
{
    int status = storage_chmod_sidecar(db_path, "-wal");

    if (status == SM_OK) {
        status = storage_chmod_sidecar(db_path, "-shm");
    }
    return status;
}

static int storage_open_owner_only_fd(const char *db_path, int create)
{
    int flags = O_RDWR | O_NOFOLLOW;
    int fd = -1;
    int status = SM_OK;

    if ((db_path == NULL) || (db_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (create) {
        flags |= O_CREAT;
    }
    fd = open(db_path, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return SM_ERR_STORAGE;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (close(fd) != 0) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int storage_resolve_db_path(const char *db_path, char **resolved_path)
{
    char *resolved = NULL;

    if ((db_path == NULL) || (db_path[0] == '\0') ||
        (resolved_path == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *resolved_path = NULL;
    resolved = realpath(db_path, NULL);
    if (resolved == NULL) {
        return SM_ERR_STORAGE;
    }

    *resolved_path = resolved;
    return SM_OK;
}

int storage_init(const char *db_path)
{
    int status = SM_OK;
    char *resolved_path = NULL;

    if ((db_path == NULL) || (db_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (g_db != NULL) {
        return SM_ERR_STORAGE;
    }

    /* Pre-create or tighten the vault file owner-only (0600):
       sqlite3_open_v2 would create it with the process umask, and an
       already-existing permissive file would otherwise keep that mode.
       O_NOFOLLOW refuses the open if the vault path is a symlink, so a
       pre-planted symlink in a writable directory cannot redirect the
       create/fchmod onto another file the user owns. */
    status = storage_open_owner_only_fd(db_path, 1);
    if (status != SM_OK) {
        return status;
    }

    status = storage_resolve_db_path(db_path, &resolved_path);
    if (status != SM_OK) {
        return status;
    }

    if (sqlite3_open_v2(resolved_path,
                        &g_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW,
                        NULL) != SQLITE_OK) {
        storage_close();
        free(resolved_path);
        return SM_ERR_STORAGE;
    }

    status = storage_execute_sql("PRAGMA journal_mode = WAL;");
    if (status == SM_OK) {
        status = storage_chmod_wal_sidecars(resolved_path);
    }
    if (status == SM_OK) {
        /* The schema is compiled in (generated from sql/schema.sql), so
           init works regardless of the process working directory. */
        status = storage_execute_sql(STORAGE_EMBEDDED_SCHEMA);
    }
    if (status == SM_OK) {
        status = storage_chmod_wal_sidecars(resolved_path);
    }
    if (status == SM_OK) {
        status = storage_execute_sql(STORAGE_EMBEDDED_SCHEMA);
    }
    if (status == SM_OK) {
        status = storage_verify_schema();
    }

    if (status != SM_OK) {
        storage_close();
    }

    free(resolved_path);
    return status;
}

int storage_open(const char *db_path)
{
    int status = SM_OK;
    char *resolved_path = NULL;

    if ((db_path == NULL) || (db_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (g_db != NULL) {
        return SM_ERR_STORAGE;
    }

    status = storage_open_owner_only_fd(db_path, 0);
    if (status != SM_OK) {
        return status;
    }

    status = storage_resolve_db_path(db_path, &resolved_path);
    if (status != SM_OK) {
        return status;
    }

    if (sqlite3_open_v2(resolved_path,
                        &g_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                            SQLITE_OPEN_NOFOLLOW,
                        NULL) != SQLITE_OK) {
        storage_close();
        free(resolved_path);
        return SM_ERR_STORAGE;
    }

    status = storage_execute_sql("PRAGMA journal_mode = WAL;");
    if (status == SM_OK) {
        status = storage_chmod_wal_sidecars(resolved_path);
    }
    if (status == SM_OK) {
        status = storage_verify_schema();
    }

    if (status != SM_OK) {
        storage_close();
    }

    free(resolved_path);
    return status;
}

int storage_init_schema(const char *schema_path)
{
    int status = SM_OK;
    char *schema = NULL;

    status = storage_read_file(schema_path, &schema);
    if (status != SM_OK) {
        return status;
    }

    status = storage_execute_sql(schema);
    free(schema);
    return status;
}

int storage_begin_transaction(void)
{
    return storage_execute_sql("BEGIN IMMEDIATE;");
}

int storage_commit_transaction(void)
{
    return storage_execute_sql("COMMIT;");
}

int storage_rollback_transaction(void)
{
    return storage_execute_sql("ROLLBACK;");
}

sqlite3 *storage_get_db(void)
{
    return g_db;
}

int storage_close(void)
{
    int rc = SQLITE_OK;

    if (g_db == NULL) {
        return SM_OK;
    }

    rc = sqlite3_close(g_db);
    if (rc != SQLITE_OK) {
        /*
         * SQLITE_BUSY means SQLite kept the handle open, usually because a
         * statement is still alive. Keep g_db set so callers can finalize the
         * outstanding work and retry storage_close().
         */
        return SM_ERR_STORAGE;
    }

    g_db = NULL;
    return SM_OK;
}
