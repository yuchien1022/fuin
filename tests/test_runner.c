#include "utils.h"

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_failed;

static void expect_true(int condition, const char *name)
{
    tests_run++;
    if (!condition) {
        tests_failed++;
        printf("FAIL: %s\n", name);
    }
}

int test_storage_run(void);
int test_kdf_run(void);
int test_crypto_run(void);
int test_utils_run(void);
int test_vault_run(void);
int test_audit_run(void);
int test_rotation_run(void);
int test_access_run(void);
int test_backup_run(void);
int test_cli_run(void);

static void test_status_messages(void)
{
    expect_true(strcmp(utils_status_message(SM_OK), "ok") == 0,
                "SM_OK message");
    expect_true(strcmp(utils_status_message(SM_ERR_NOT_IMPLEMENTED),
                       "not implemented") == 0,
                "SM_ERR_NOT_IMPLEMENTED message");
}

int main(void)
{
    test_status_messages();
    expect_true(test_utils_run() == 0, "utils suite");
    expect_true(test_storage_run() == 0, "storage suite");
    expect_true(test_kdf_run() == 0, "kdf suite");
    expect_true(test_crypto_run() == 0, "crypto suite");
    expect_true(test_vault_run() == 0, "vault suite");
    expect_true(test_audit_run() == 0, "audit suite");
    expect_true(test_rotation_run() == 0, "rotation suite");
    expect_true(test_access_run() == 0, "access suite");
    expect_true(test_backup_run() == 0, "backup suite");
    expect_true(test_cli_run() == 0, "cli suite");

    printf("tests: %d run, %d failed\n", tests_run, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
