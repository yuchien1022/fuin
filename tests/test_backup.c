#define _POSIX_C_SOURCE 200809L

#include "backup.h"
#include "utils.h"
#include "vault.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const TEST_DB = "results/test_backup.db";
static const char *const TEST_DB_SHM = "results/test_backup.db-shm";
static const char *const TEST_DB_WAL = "results/test_backup.db-wal";
static const char *const RESTORED_DB = "results/test_backup_restored.db";
static const char *const RESTORED_DB_SHM = "results/test_backup_restored.db-shm";
static const char *const RESTORED_DB_WAL = "results/test_backup_restored.db-wal";
static const char *const CAPSULE = "results/test_backup.fuincap";
static const char *const TAMPERED_CAPSULE = "results/test_backup_tampered.fuincap";
static const char *const PUBLIC_KEY = "results/test_backup_hybrid_pub.pem";
static const char *const PRIVATE_KEY = "results/test_backup_hybrid_priv.pem";
static const char *const PRIVATE_KEY_LINK = "results/test_backup_hybrid_priv_link.pem";
static const char *const SYMLINK_PARENT_REAL_DIR = "results/test_backup_real_parent";
static const char *const SYMLINK_PARENT_LINK_DIR = "results/test_backup_link_parent";
static const char *const SYMLINK_PARENT_PUBLIC_KEY =
    "results/test_backup_link_parent/hybrid_pub.pem";
static const char *const SYMLINK_PARENT_PRIVATE_KEY =
    "results/test_backup_link_parent/hybrid_priv.pem";
static const char *const SYMLINK_PARENT_AUDIT_PUBLIC_KEY =
    "results/test_backup_link_parent/audit_pub.pem";
static const char *const SYMLINK_PARENT_AUDIT_PRIVATE_KEY =
    "results/test_backup_link_parent/audit_priv.pem";
static const char *const SYMLINK_PARENT_CAPSULE =
    "results/test_backup_link_parent/backup.fuincap";
static const char *const SYMLINK_PARENT_RESTORED_DB =
    "results/test_backup_link_parent/restored.db";
static const char *const SYMLINK_PARENT_SYMLINK_KEY =
    "results/test_backup_link_parent/final_symlink_priv.pem";
static const char *const KEY_PASSPHRASE = "test-key-passphrase";
static const char *const WRONG_KEY_PASSPHRASE = "wrong-test-key-passphrase";

static void cleanup_symlink_parent_files(void)
{
    (void)vault_close();
    (void)remove(SYMLINK_PARENT_PUBLIC_KEY);
    (void)remove(SYMLINK_PARENT_PRIVATE_KEY);
    (void)remove(SYMLINK_PARENT_AUDIT_PUBLIC_KEY);
    (void)remove(SYMLINK_PARENT_AUDIT_PRIVATE_KEY);
    (void)remove(SYMLINK_PARENT_CAPSULE);
    (void)remove(SYMLINK_PARENT_RESTORED_DB);
    (void)remove("results/test_backup_link_parent/restored.db-shm");
    (void)remove("results/test_backup_link_parent/restored.db-wal");
    (void)remove(SYMLINK_PARENT_SYMLINK_KEY);
    (void)remove(SYMLINK_PARENT_LINK_DIR);
    (void)remove("results/test_backup_real_parent/restored.db-shm");
    (void)remove("results/test_backup_real_parent/restored.db-wal");
    (void)rmdir(SYMLINK_PARENT_REAL_DIR);
}

static void cleanup_backup_files(void)
{
    (void)vault_close();
    (void)remove(TEST_DB);
    (void)remove(TEST_DB_SHM);
    (void)remove(TEST_DB_WAL);
    (void)remove(RESTORED_DB);
    (void)remove(RESTORED_DB_SHM);
    (void)remove(RESTORED_DB_WAL);
    (void)remove(CAPSULE);
    (void)remove(TAMPERED_CAPSULE);
    (void)remove(PUBLIC_KEY);
    (void)remove(PRIVATE_KEY);
    (void)remove(PRIVATE_KEY_LINK);
    cleanup_symlink_parent_files();
}

static int copy_and_tamper_capsule(void)
{
    FILE *in = NULL;
    FILE *out = NULL;
    unsigned char buffer[4096];
    size_t nread = 0U;
    int status = SM_OK;
    int tampered = 0;

    in = fopen(CAPSULE, "rb");
    if (in == NULL) {
        return SM_ERR_STORAGE;
    }
    out = fopen(TAMPERED_CAPSULE, "wb");
    if (out == NULL) {
        (void)fclose(in);
        return SM_ERR_STORAGE;
    }

    while ((nread = fread(buffer, 1U, sizeof(buffer), in)) > 0U) {
        if (!tampered && (nread > 0U)) {
            buffer[nread - 1U] ^= 0x01U;
            tampered = 1;
        }
        if (fwrite(buffer, 1U, nread, out) != nread) {
            status = SM_ERR_STORAGE;
            break;
        }
    }
    if (ferror(in)) {
        status = SM_ERR_STORAGE;
    }
    if (fclose(in) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (fclose(out) != 0) {
        status = SM_ERR_STORAGE;
    }
    sodium_memzero(buffer, sizeof(buffer));
    return (status == SM_OK) && tampered ? SM_OK : SM_ERR_STORAGE;
}

static int file_mode_is_owner_only(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return 0;
    }
    return (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) ==
           (S_IRUSR | S_IWUSR);
}

static int test_hybrid_backup_roundtrip(void)
{
    const unsigned char secret[] = "backup-secret";
    unsigned char recovered[sizeof(secret)];
    size_t written = 0U;
    int ok = 1;

    cleanup_backup_files();
    if (!backup_pqc_available()) {
        printf("test_hybrid_backup_roundtrip: X25519+ML-KEM-768 unavailable; skipped\n");
        return 0;
    }

    ok = ok && (vault_backup_keygen(PUBLIC_KEY,
                                    PRIVATE_KEY,
                                    KEY_PASSPHRASE) == SM_OK);
    ok = ok && file_mode_is_owner_only(PRIVATE_KEY);
    ok = ok && (vault_init(TEST_DB) == SM_OK);
    ok = ok && (vault_unlock("backup-password") == SM_OK);
    ok = ok && (vault_put_with_algorithm("backup/api",
                                         secret,
                                         sizeof(secret) - 1U,
                                         "XChaCha20-Poly1305") == SM_OK);
    ok = ok && (vault_backup_export(PUBLIC_KEY, CAPSULE) == SM_OK);
    ok = ok && file_mode_is_owner_only(CAPSULE);
    ok = ok && (copy_and_tamper_capsule() == SM_OK);
    ok = ok && (chmod(PRIVATE_KEY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    CAPSULE,
                                    "results/test_backup_weak_key.db") ==
                SM_ERR_STORAGE);
    (void)remove("results/test_backup_weak_key.db");
    ok = ok && (chmod(PRIVATE_KEY, S_IRUSR | S_IWUSR) == 0);
    (void)remove(PRIVATE_KEY_LINK);
    ok = ok && (symlink(PRIVATE_KEY, PRIVATE_KEY_LINK) == 0);
    ok = ok && (vault_backup_import(PRIVATE_KEY_LINK,
                                    KEY_PASSPHRASE,
                                    CAPSULE,
                                    "results/test_backup_symlink_key.db") ==
                SM_ERR_STORAGE);
    (void)remove("results/test_backup_symlink_key.db");
    (void)remove(PRIVATE_KEY_LINK);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    CAPSULE,
                                    RESTORED_DB) == SM_OK);
    ok = ok && file_mode_is_owner_only(RESTORED_DB);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    WRONG_KEY_PASSPHRASE,
                                    CAPSULE,
                                    "results/test_backup_wrong_pass.db") ==
                SM_ERR_CRYPTO);
    (void)remove("results/test_backup_wrong_pass.db");
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    TAMPERED_CAPSULE,
                                    "results/test_backup_bad.db") == SM_ERR_CRYPTO);
    (void)remove("results/test_backup_bad.db");

    ok = ok && (vault_close() == SM_OK);
    ok = ok && (vault_init(RESTORED_DB) == SM_OK);
    ok = ok && (vault_unlock("backup-password") == SM_OK);
    written = sizeof(recovered);
    ok = ok && (vault_get("backup/api",
                          recovered,
                          sizeof(recovered),
                          &written) == SM_OK) &&
         (written == (sizeof(secret) - 1U)) &&
         (memcmp(recovered, secret, written) == 0);

    if (!ok) {
        printf("test_hybrid_backup_roundtrip: expected backup export/import roundtrip\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_backup_files();
    return ok ? 0 : 1;
}

static int test_mldsa_sign_verify_roundtrip(void)
{
    static const char *const PUB = "results/test_mldsa_pub.pem";
    static const char *const PRIV = "results/test_mldsa_priv.pem";
    unsigned char message[32];
    unsigned char signature[BACKUP_MLDSA_SIGNATURE_MAX_BYTES];
    size_t signature_len = 0U;
    size_t wrong_pass_signature_len = 0U;
    int ok = 1;

    (void)remove(PUB);
    (void)remove(PRIV);
    if (!backup_mldsa_available()) {
        printf("test_mldsa_sign_verify_roundtrip: ML-DSA-65 unavailable; skipped\n");
        return 0;
    }

    randombytes_buf(message, sizeof(message));
    ok = ok && (backup_mldsa_keygen(PUB, PRIV, KEY_PASSPHRASE) == SM_OK);
    ok = ok && file_mode_is_owner_only(PRIV);
    ok = ok && (chmod(PRIV, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0);
    ok = ok && (backup_mldsa_sign(PRIV,
                                  KEY_PASSPHRASE,
                                  message,
                                  sizeof(message),
                                  signature,
                                  sizeof(signature),
                                  &signature_len) == SM_ERR_STORAGE);
    ok = ok && (chmod(PRIV, S_IRUSR | S_IWUSR) == 0);
    ok = ok && (backup_mldsa_sign(PRIV,
                                  KEY_PASSPHRASE,
                                  message,
                                  sizeof(message),
                                  signature,
                                  sizeof(signature),
                                  &signature_len) == SM_OK) &&
         (signature_len > 0U);
    ok = ok && (backup_mldsa_sign(PRIV,
                                  WRONG_KEY_PASSPHRASE,
                                  message,
                                  sizeof(message),
                                  signature,
                                  sizeof(signature),
                                  &wrong_pass_signature_len) == SM_ERR_CRYPTO);
    ok = ok && (backup_mldsa_verify(PUB,
                                    message,
                                    sizeof(message),
                                    signature,
                                    signature_len) == SM_OK);

    /* A flipped message bit must fail verification. */
    message[0] ^= 0x01U;
    ok = ok && (backup_mldsa_verify(PUB,
                                    message,
                                    sizeof(message),
                                    signature,
                                    signature_len) == SM_ERR_CRYPTO);
    message[0] ^= 0x01U;

    /* A flipped signature bit must fail verification. */
    signature[0] ^= 0x01U;
    ok = ok && (backup_mldsa_verify(PUB,
                                    message,
                                    sizeof(message),
                                    signature,
                                    signature_len) == SM_ERR_CRYPTO);

    if (!ok) {
        printf("test_mldsa_sign_verify_roundtrip: failure\n");
    }
    sodium_memzero(signature, sizeof(signature));
    (void)remove(PUB);
    (void)remove(PRIV);
    return ok ? 0 : 1;
}

static int test_backup_allows_symlink_parent_outputs(void)
{
    const unsigned char secret[] = "symlink-parent-secret";
    unsigned char recovered[sizeof(secret)];
    size_t written = 0U;
    int ok = 1;

    cleanup_backup_files();
    if (!backup_pqc_available()) {
        printf("test_backup_allows_symlink_parent_outputs: X25519+ML-KEM-768 unavailable; skipped\n");
        return 0;
    }

    ok = ok && (mkdir(SYMLINK_PARENT_REAL_DIR, S_IRWXU) == 0);
    ok = ok && (symlink("test_backup_real_parent",
                        SYMLINK_PARENT_LINK_DIR) == 0);
    ok = ok && (vault_backup_keygen(SYMLINK_PARENT_PUBLIC_KEY,
                                    SYMLINK_PARENT_PRIVATE_KEY,
                                    KEY_PASSPHRASE) == SM_OK);
    ok = ok && file_mode_is_owner_only(SYMLINK_PARENT_PRIVATE_KEY);

    if (backup_mldsa_available()) {
        ok = ok && (backup_mldsa_keygen(SYMLINK_PARENT_AUDIT_PUBLIC_KEY,
                                        SYMLINK_PARENT_AUDIT_PRIVATE_KEY,
                                        KEY_PASSPHRASE) == SM_OK);
        ok = ok && file_mode_is_owner_only(SYMLINK_PARENT_AUDIT_PRIVATE_KEY);
    }

    ok = ok && (vault_init(TEST_DB) == SM_OK);
    ok = ok && (vault_unlock("backup-password") == SM_OK);
    ok = ok && (vault_put("backup/symlink-parent",
                          secret,
                          sizeof(secret) - 1U) == SM_OK);
    ok = ok && (vault_backup_export(SYMLINK_PARENT_PUBLIC_KEY,
                                    SYMLINK_PARENT_CAPSULE) == SM_OK);
    ok = ok && file_mode_is_owner_only(SYMLINK_PARENT_CAPSULE);
    ok = ok && (vault_backup_import(SYMLINK_PARENT_PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    SYMLINK_PARENT_CAPSULE,
                                    SYMLINK_PARENT_RESTORED_DB) == SM_OK);
    ok = ok && file_mode_is_owner_only(SYMLINK_PARENT_RESTORED_DB);

    ok = ok && (vault_close() == SM_OK);
    ok = ok && (vault_init(SYMLINK_PARENT_RESTORED_DB) == SM_OK);
    ok = ok && (vault_unlock("backup-password") == SM_OK);
    written = sizeof(recovered);
    ok = ok && (vault_get("backup/symlink-parent",
                          recovered,
                          sizeof(recovered),
                          &written) == SM_OK) &&
         (written == (sizeof(secret) - 1U)) &&
         (memcmp(recovered, secret, written) == 0);

    ok = ok && (symlink("target", SYMLINK_PARENT_SYMLINK_KEY) == 0);
    ok = ok && (vault_backup_keygen(SYMLINK_PARENT_PUBLIC_KEY,
                                    SYMLINK_PARENT_SYMLINK_KEY,
                                    KEY_PASSPHRASE) == SM_ERR_STORAGE);

    if (!ok) {
        printf("test_backup_allows_symlink_parent_outputs: expected symlink-parent output support and final symlink rejection\n");
    }

    sodium_memzero(recovered, sizeof(recovered));
    cleanup_backup_files();
    return ok ? 0 : 1;
}

static int test_backup_invalid_args(void)
{
    int ok = 1;

    cleanup_backup_files();
    ok = ok && (vault_backup_keygen(NULL,
                                    PRIVATE_KEY,
                                    KEY_PASSPHRASE) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_keygen(PUBLIC_KEY,
                                    NULL,
                                    KEY_PASSPHRASE) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_keygen(PUBLIC_KEY,
                                    PRIVATE_KEY,
                                    NULL) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_export(PUBLIC_KEY, CAPSULE) == SM_ERR_AUTH);
    ok = ok && (vault_backup_import(NULL,
                                    KEY_PASSPHRASE,
                                    CAPSULE,
                                    RESTORED_DB) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    NULL,
                                    CAPSULE,
                                    RESTORED_DB) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    NULL,
                                    RESTORED_DB) ==
                SM_ERR_INVALID_ARGUMENT);
    ok = ok && (vault_backup_import(PRIVATE_KEY,
                                    KEY_PASSPHRASE,
                                    CAPSULE,
                                    NULL) ==
                SM_ERR_INVALID_ARGUMENT);

    if (!ok) {
        printf("test_backup_invalid_args: expected argument/auth failures\n");
    }

    cleanup_backup_files();
    return ok ? 0 : 1;
}

int test_backup_run(void)
{
    int failed = 0;

    if (sodium_init() < 0) {
        printf("test_backup_run: sodium_init failed\n");
        return 1;
    }

    failed += test_backup_invalid_args();
    failed += test_hybrid_backup_roundtrip();
    failed += test_mldsa_sign_verify_roundtrip();
    failed += test_backup_allows_symlink_parent_outputs();

    if (failed != 0) {
        printf("test_backup_run: %d failures\n", failed);
    }

    cleanup_backup_files();
    return failed == 0 ? 0 : 1;
}
