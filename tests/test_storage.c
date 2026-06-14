#define _POSIX_C_SOURCE 200809L

#include "storage.h"
#include "utils.h"

#include <sqlite3.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const TEST_DB = "results/test_storage.db";
static const char *const EMPTY_DB = "results/test_empty.db";
static const char *const PERMISSIVE_DB = "results/test_permissive.db";
static const char *const SYMLINK_DB = "results/test_storage_link.db";
static const char *const SYMLINK_TARGET_DB = "results/test_storage_target.db";
static const char *const SYMLINK_PARENT_REAL_DIR = "results/test_storage_real_parent";
static const char *const SYMLINK_PARENT_LINK_DIR = "results/test_storage_link_parent";
static const char *const SYMLINK_PARENT_DB =
    "results/test_storage_link_parent/parent.db";
static const char *const SYMLINK_PARENT_REAL_DB =
    "results/test_storage_real_parent/parent.db";
static const char *const SIDECAR_DB = "results/test_storage_sidecar.db";
static const char *const SIDECAR_VICTIM = "results/test_storage_victim.txt";
static const char *const PARTIAL_SCHEMA_DB = "results/test_partial_schema.db";

static void cleanup_db(void)
{
    (void)remove(TEST_DB);
    (void)remove("results/test_storage.db-shm");
    (void)remove("results/test_storage.db-wal");
}

static void cleanup_empty_db(void)
{
    (void)remove(EMPTY_DB);
    (void)remove("results/test_empty.db-shm");
    (void)remove("results/test_empty.db-wal");
}

static void cleanup_permissive_db(void)
{
    (void)remove(PERMISSIVE_DB);
    (void)remove("results/test_permissive.db-shm");
    (void)remove("results/test_permissive.db-wal");
}

static void cleanup_symlink_db(void)
{
    (void)remove(SYMLINK_DB);
    (void)remove("results/test_storage_link.db-shm");
    (void)remove("results/test_storage_link.db-wal");
    (void)remove(SYMLINK_TARGET_DB);
    (void)remove("results/test_storage_target.db-shm");
    (void)remove("results/test_storage_target.db-wal");
}

static void cleanup_symlink_parent_db(void)
{
    (void)remove("results/test_storage_link_parent/parent.db-shm");
    (void)remove("results/test_storage_link_parent/parent.db-wal");
    (void)remove(SYMLINK_PARENT_DB);
    (void)remove("results/test_storage_real_parent/parent.db-shm");
    (void)remove("results/test_storage_real_parent/parent.db-wal");
    (void)remove(SYMLINK_PARENT_REAL_DB);
    (void)remove(SYMLINK_PARENT_LINK_DIR);
    (void)rmdir(SYMLINK_PARENT_REAL_DIR);
}

static void cleanup_sidecar_db(void)
{
    (void)remove("results/test_storage_sidecar.db-shm");
    (void)remove("results/test_storage_sidecar.db-wal");
    (void)remove(SIDECAR_DB);
    (void)remove(SIDECAR_VICTIM);
}

static void cleanup_partial_schema_db(void)
{
    (void)remove(PARTIAL_SCHEMA_DB);
    (void)remove("results/test_partial_schema.db-shm");
    (void)remove("results/test_partial_schema.db-wal");
}

static int path_mode_is_owner_only(const char *path)
{
    struct stat st;

    return (stat(path, &st) == 0) &&
           ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) ==
            (S_IRUSR | S_IWUSR));
}

static int path_mode_ok_or_absent(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return 1;
    return (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) ==
           (S_IRUSR | S_IWUSR);
}

static int chmod_if_exists(const char *path, mode_t mode)
{
    if (access(path, F_OK) != 0)
        return 0;
    return chmod(path, mode);
}

static int test_init_close(void)
{
    int status;

    cleanup_db();
    status = storage_init(TEST_DB);
    if (status != SM_OK) {
        printf("test_init_close: init failed: %s\n", utils_status_message(status));
        (void)storage_close();
        cleanup_db();
        return 1;
    }

    status = storage_close();
    if (status != SM_OK) {
        printf("test_init_close: close failed: %s\n", utils_status_message(status));
        cleanup_db();
        return 1;
    }

    cleanup_db();
    return 0;
}

static int test_null_path(void)
{
    int ok = storage_init(NULL) == SM_ERR_INVALID_ARGUMENT;

    if (!ok) {
        printf("test_null_path: expected SM_ERR_INVALID_ARGUMENT\n");
        (void)storage_close();
    }
    return ok ? 0 : 1;
}

static int test_empty_path(void)
{
    int ok = storage_init("") == SM_ERR_INVALID_ARGUMENT;

    if (!ok) {
        printf("test_empty_path: expected SM_ERR_INVALID_ARGUMENT\n");
        (void)storage_close();
    }
    return ok ? 0 : 1;
}

static int test_double_init(void)
{
    int status;
    int ok;

    cleanup_db();
    status = storage_init(TEST_DB);
    if (status != SM_OK) {
        printf("test_double_init: first init failed\n");
        cleanup_db();
        return 1;
    }

    ok = storage_init(TEST_DB) == SM_ERR_STORAGE;
    if (!ok) {
        printf("test_double_init: expected SM_ERR_STORAGE for double init\n");
    }

    (void)storage_close();
    cleanup_db();
    return ok ? 0 : 1;
}

static int test_close_idempotent(void)
{
    int status;

    cleanup_db();
    status = storage_init(TEST_DB);
    if (status != SM_OK) {
        printf("test_close_idempotent: init failed\n");
        cleanup_db();
        return 1;
    }

    status = storage_close();
    if (status != SM_OK) {
        printf("test_close_idempotent: first close failed\n");
        cleanup_db();
        return 1;
    }

    status = storage_close();
    if (status != SM_OK) {
        printf("test_close_idempotent: second close not idempotent\n");
        cleanup_db();
        return 1;
    }

    cleanup_db();
    return 0;
}

static int test_init_owner_only_permissions(void)
{
    int ok;

    cleanup_db();
    if (storage_init(TEST_DB) != SM_OK) {
        printf("test_init_owner_only_permissions: init failed\n");
        cleanup_db();
        return 1;
    }

    ok = path_mode_is_owner_only(TEST_DB);
    if (!ok) {
        printf("test_init_owner_only_permissions: expected vault DB mode 0600\n");
    }

    (void)storage_close();
    cleanup_db();
    return ok ? 0 : 1;
}

static int test_init_tightens_existing_permissions(void)
{
    FILE *fp = NULL;
    int ok = 0;

    cleanup_permissive_db();
    fp = fopen(PERMISSIVE_DB, "wb");
    if (fp == NULL) {
        printf("test_init_tightens_existing_permissions: setup fopen failed\n");
        cleanup_permissive_db();
        return 1;
    }
    if (fclose(fp) != 0) {
        printf("test_init_tightens_existing_permissions: setup fclose failed\n");
        cleanup_permissive_db();
        return 1;
    }
    if (chmod(PERMISSIVE_DB, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        printf("test_init_tightens_existing_permissions: setup chmod failed\n");
        cleanup_permissive_db();
        return 1;
    }

    if (storage_init(PERMISSIVE_DB) != SM_OK) {
        printf("test_init_tightens_existing_permissions: init failed\n");
        (void)storage_close();
        cleanup_permissive_db();
        return 1;
    }

    ok = path_mode_is_owner_only(PERMISSIVE_DB) &&
         path_mode_ok_or_absent("results/test_permissive.db-wal") &&
         path_mode_ok_or_absent("results/test_permissive.db-shm");
    if (!ok) {
        printf("test_init_tightens_existing_permissions: expected DB/WAL/SHM mode 0600\n");
    }

    (void)storage_close();
    cleanup_permissive_db();
    return ok ? 0 : 1;
}

static int test_open_tightens_existing_permissions(void)
{
    int ok = 0;

    cleanup_permissive_db();
    if (storage_init(PERMISSIVE_DB) != SM_OK) {
        printf("test_open_tightens_existing_permissions: init failed\n");
        (void)storage_close();
        cleanup_permissive_db();
        return 1;
    }
    if (storage_close() != SM_OK) {
        printf("test_open_tightens_existing_permissions: close failed\n");
        cleanup_permissive_db();
        return 1;
    }
    if ((chmod(PERMISSIVE_DB, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) ||
        (chmod_if_exists("results/test_permissive.db-wal",
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) ||
        (chmod_if_exists("results/test_permissive.db-shm",
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)) {
        printf("test_open_tightens_existing_permissions: setup chmod failed\n");
        cleanup_permissive_db();
        return 1;
    }

    if (storage_open(PERMISSIVE_DB) != SM_OK) {
        printf("test_open_tightens_existing_permissions: open failed\n");
        (void)storage_close();
        cleanup_permissive_db();
        return 1;
    }

    ok = path_mode_is_owner_only(PERMISSIVE_DB) &&
         path_mode_ok_or_absent("results/test_permissive.db-wal") &&
         path_mode_ok_or_absent("results/test_permissive.db-shm");
    if (!ok) {
        printf("test_open_tightens_existing_permissions: expected DB/WAL/SHM mode 0600\n");
    }

    (void)storage_close();
    cleanup_permissive_db();
    return ok ? 0 : 1;
}

static int test_open_rejects_symlink(void)
{
    int ok = 0;

    cleanup_symlink_db();
    if (storage_init(SYMLINK_TARGET_DB) != SM_OK) {
        printf("test_open_rejects_symlink: target init failed\n");
        (void)storage_close();
        cleanup_symlink_db();
        return 1;
    }
    if (storage_close() != SM_OK) {
        printf("test_open_rejects_symlink: target close failed\n");
        cleanup_symlink_db();
        return 1;
    }
    if (symlink("test_storage_target.db", SYMLINK_DB) != 0) {
        printf("test_open_rejects_symlink: symlink setup failed\n");
        cleanup_symlink_db();
        return 1;
    }

    ok = storage_open(SYMLINK_DB) == SM_ERR_STORAGE;
    if (!ok) {
        printf("test_open_rejects_symlink: expected symlink open failure\n");
        (void)storage_close();
    }

    cleanup_symlink_db();
    return ok ? 0 : 1;
}

static int test_init_allows_symlink_parent(void)
{
    int ok = 0;

    cleanup_symlink_parent_db();
    if (mkdir(SYMLINK_PARENT_REAL_DIR, S_IRWXU) != 0) {
        printf("test_init_allows_symlink_parent: mkdir failed\n");
        cleanup_symlink_parent_db();
        return 1;
    }
    if (symlink("test_storage_real_parent", SYMLINK_PARENT_LINK_DIR) != 0) {
        printf("test_init_allows_symlink_parent: symlink setup failed\n");
        cleanup_symlink_parent_db();
        return 1;
    }

    if (storage_init(SYMLINK_PARENT_DB) != SM_OK) {
        printf("test_init_allows_symlink_parent: init through symlink parent failed\n");
        (void)storage_close();
        cleanup_symlink_parent_db();
        return 1;
    }

    ok = path_mode_is_owner_only(SYMLINK_PARENT_REAL_DB);
    if (!ok) {
        printf("test_init_allows_symlink_parent: expected real DB mode 0600\n");
    }

    (void)storage_close();
    cleanup_symlink_parent_db();
    return ok ? 0 : 1;
}

/* A pre-planted symlink at the WAL sidecar path must not let storage tighten
   (chmod) an attacker-chosen target: the O_NOFOLLOW sidecar open refuses the
   symlink, storage_open fails, and the victim file keeps its original
   group/other-readable mode (the chmod is never redirected onto it).
   Regression for the sidecar gap left open by FIXED-044/049. */
static int test_open_rejects_symlink_sidecar(void)
{
    FILE *victim = NULL;
    int open_rejected = 0;
    int victim_untouched = 0;

    cleanup_sidecar_db();
    if (storage_init(SIDECAR_DB) != SM_OK) {
        printf("test_open_rejects_symlink_sidecar: init failed\n");
        (void)storage_close();
        cleanup_sidecar_db();
        return 1;
    }
    if (storage_close() != SM_OK) {
        printf("test_open_rejects_symlink_sidecar: close failed\n");
        cleanup_sidecar_db();
        return 1;
    }

    /* Stand-in for a file the user owns elsewhere; left group/other-readable so
       a redirected chmod-to-0600 would be observable. */
    victim = fopen(SIDECAR_VICTIM, "w");
    if ((victim == NULL) || (fclose(victim) != 0) ||
        (chmod(SIDECAR_VICTIM, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)) {
        printf("test_open_rejects_symlink_sidecar: victim setup failed\n");
        cleanup_sidecar_db();
        return 1;
    }

    (void)remove("results/test_storage_sidecar.db-wal");
    if (symlink("test_storage_victim.txt",
                "results/test_storage_sidecar.db-wal") != 0) {
        printf("test_open_rejects_symlink_sidecar: symlink setup failed\n");
        cleanup_sidecar_db();
        return 1;
    }

    open_rejected = storage_open(SIDECAR_DB) != SM_OK;
    (void)storage_close();
    victim_untouched = !path_mode_is_owner_only(SIDECAR_VICTIM);

    if (!open_rejected) {
        printf("test_open_rejects_symlink_sidecar: expected open to fail on symlinked WAL\n");
    }
    if (!victim_untouched) {
        printf("test_open_rejects_symlink_sidecar: chmod redirected onto symlink target\n");
    }

    cleanup_sidecar_db();
    return (open_rejected && victim_untouched) ? 0 : 1;
}

static int test_transactions(void)
{
    int status;
    int failed = 0;

    cleanup_db();
    status = storage_init(TEST_DB);
    if (status != SM_OK) {
        printf("test_transactions: init failed\n");
        cleanup_db();
        return 1;
    }

    status = storage_begin_transaction();
    if (status != SM_OK) {
        printf("test_transactions: begin failed\n");
        failed = 1;
        goto cleanup;
    }

    status = storage_commit_transaction();
    if (status != SM_OK) {
        printf("test_transactions: commit failed\n");
        failed = 1;
        goto cleanup;
    }

    status = storage_begin_transaction();
    if (status != SM_OK) {
        printf("test_transactions: second begin failed\n");
        failed = 1;
        goto cleanup;
    }

    status = storage_rollback_transaction();
    if (status != SM_OK) {
        printf("test_transactions: rollback failed\n");
        failed = 1;
    }

cleanup:
    (void)storage_close();
    cleanup_db();
    return failed;
}

static int test_open_nonexistent(void)
{
    int ok;

    (void)remove("results/test_no_such.db");
    (void)remove("results/test_no_such.db-shm");
    (void)remove("results/test_no_such.db-wal");

    ok = storage_open("results/test_no_such.db") == SM_ERR_STORAGE;
    if (!ok) {
        printf("test_open_nonexistent: expected SM_ERR_STORAGE\n");
        (void)storage_close();
        (void)remove("results/test_no_such.db");
        (void)remove("results/test_no_such.db-shm");
        (void)remove("results/test_no_such.db-wal");
    }
    return ok ? 0 : 1;
}

static int test_open_empty_db_without_schema(void)
{
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;
    int ok = 0;

    cleanup_empty_db();
    rc = sqlite3_open_v2(EMPTY_DB,
                         &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                         NULL);
    if (rc != SQLITE_OK) {
        printf("test_open_empty_db_without_schema: failed to create empty db\n");
        if (db != NULL) {
            (void)sqlite3_close(db);
        }
        cleanup_empty_db();
        return 1;
    }
    if (sqlite3_close(db) != SQLITE_OK) {
        printf("test_open_empty_db_without_schema: failed to close setup db\n");
        cleanup_empty_db();
        return 1;
    }

    ok = storage_open(EMPTY_DB) == SM_ERR_STORAGE;
    if (!ok) {
        printf("test_open_empty_db_without_schema: expected SM_ERR_STORAGE\n");
        (void)storage_close();
    }

    cleanup_empty_db();
    return ok ? 0 : 1;
}

static int test_open_rejects_partial_schema(void)
{
    static const char *const partial_schema =
        "CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);"
        "CREATE TABLE audit_log ("
        "entry_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp TEXT NOT NULL,"
        "action TEXT NOT NULL,"
        "actor TEXT NOT NULL,"
        "target TEXT NOT NULL,"
        "target_version INTEGER,"
        "result TEXT NOT NULL,"
        "prev_hash BLOB NOT NULL,"
        "entry_hash BLOB NOT NULL,"
        "hmac_signature BLOB NOT NULL);"
        "CREATE TABLE metadata (key TEXT, value BLOB NOT NULL);"
        "CREATE TABLE auth_failures ("
        "event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp TEXT NOT NULL,"
        "result TEXT NOT NULL);";
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = SQLITE_OK;
    int ok = 0;

    cleanup_partial_schema_db();
    rc = sqlite3_open_v2(PARTIAL_SCHEMA_DB,
                         &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                         NULL);
    if (rc != SQLITE_OK) {
        printf("test_open_rejects_partial_schema: setup open failed\n");
        if (db != NULL) {
            (void)sqlite3_close(db);
        }
        cleanup_partial_schema_db();
        return 1;
    }
    rc = sqlite3_exec(db, partial_schema, NULL, NULL, &error);
    sqlite3_free(error);
    if (rc != SQLITE_OK) {
        printf("test_open_rejects_partial_schema: setup schema failed\n");
        (void)sqlite3_close(db);
        cleanup_partial_schema_db();
        return 1;
    }
    if (sqlite3_close(db) != SQLITE_OK) {
        printf("test_open_rejects_partial_schema: setup close failed\n");
        cleanup_partial_schema_db();
        return 1;
    }

    ok = storage_open(PARTIAL_SCHEMA_DB) == SM_ERR_STORAGE;
    if (!ok) {
        printf("test_open_rejects_partial_schema: expected SM_ERR_STORAGE\n");
        (void)storage_close();
    }

    cleanup_partial_schema_db();
    return ok ? 0 : 1;
}

int test_storage_run(void)
{
    int failed = 0;

    failed += test_init_close();
    failed += test_null_path();
    failed += test_empty_path();
    failed += test_double_init();
    failed += test_close_idempotent();
    failed += test_init_owner_only_permissions();
    failed += test_init_tightens_existing_permissions();
    failed += test_open_tightens_existing_permissions();
    failed += test_init_allows_symlink_parent();
    failed += test_open_rejects_symlink();
    failed += test_open_rejects_symlink_sidecar();
    failed += test_transactions();
    failed += test_open_nonexistent();
    failed += test_open_empty_db_without_schema();
    failed += test_open_rejects_partial_schema();

    if (failed != 0) {
        printf("test_storage_run: %d failures\n", failed);
    }

    return failed == 0 ? 0 : 1;
}
