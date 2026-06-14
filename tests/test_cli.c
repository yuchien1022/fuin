#define main fuin_cli_main_for_test
#include "../src/main.c"
#undef main

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const CLI_PASSPHRASE_FILE = "results/test_cli_passphrase.txt";
static const char *const CLI_PASSPHRASE_LINK = "results/test_cli_passphrase_link.txt";
static const char *const CLI_PASSPHRASE_REAL_DIR =
    "results/test_cli_real_parent";
static const char *const CLI_PASSPHRASE_PARENT_LINK =
    "results/test_cli_link_parent";
static const char *const CLI_PASSPHRASE_PARENT_FILE =
    "results/test_cli_link_parent/passphrase.txt";

static void cleanup_cli_files(void)
{
    (void)remove(CLI_PASSPHRASE_FILE);
    (void)remove(CLI_PASSPHRASE_LINK);
    (void)remove(CLI_PASSPHRASE_PARENT_FILE);
    (void)remove(CLI_PASSPHRASE_PARENT_LINK);
    (void)rmdir(CLI_PASSPHRASE_REAL_DIR);
}

static int write_passphrase_file(const char *path, mode_t mode)
{
    FILE *fp = fopen(path, "wb");

    if (fp == NULL) {
        return SM_ERR_STORAGE;
    }
    if (fputs("owner-only-passphrase\n", fp) < 0) {
        (void)fclose(fp);
        return SM_ERR_STORAGE;
    }
    if (fclose(fp) != 0) {
        return SM_ERR_STORAGE;
    }
    return chmod(path, mode) == 0 ? SM_OK : SM_ERR_STORAGE;
}

static int test_key_passphrase_file_owner_only(void)
{
    char passphrase[CLI_PASSWORD_MAX];
    int ok = 1;

    cleanup_cli_files();
    sodium_memzero(passphrase, sizeof(passphrase));

    ok = ok && (write_passphrase_file(CLI_PASSPHRASE_FILE,
                                      S_IRUSR | S_IWUSR) == SM_OK);
    ok = ok && (cli_read_key_passphrase_file(CLI_PASSPHRASE_FILE,
                                             passphrase,
                                             sizeof(passphrase)) == SM_OK);
    ok = ok && (strcmp(passphrase, "owner-only-passphrase") == 0);

    ok = ok && (chmod(CLI_PASSPHRASE_FILE,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0);
    ok = ok && (cli_read_key_passphrase_file(CLI_PASSPHRASE_FILE,
                                             passphrase,
                                             sizeof(passphrase)) ==
                SM_ERR_STORAGE);

    ok = ok && (chmod(CLI_PASSPHRASE_FILE, S_IRUSR | S_IWUSR) == 0);
    (void)remove(CLI_PASSPHRASE_LINK);
    ok = ok && (symlink(CLI_PASSPHRASE_FILE, CLI_PASSPHRASE_LINK) == 0);
    ok = ok && (cli_read_key_passphrase_file(CLI_PASSPHRASE_LINK,
                                             passphrase,
                                             sizeof(passphrase)) ==
                SM_ERR_STORAGE);

    ok = ok && (mkdir(CLI_PASSPHRASE_REAL_DIR, S_IRWXU) == 0);
    ok = ok && (symlink("test_cli_real_parent",
                        CLI_PASSPHRASE_PARENT_LINK) == 0);
    ok = ok && (write_passphrase_file(CLI_PASSPHRASE_PARENT_FILE,
                                      S_IRUSR | S_IWUSR) == SM_OK);
    ok = ok && (cli_read_key_passphrase_file(CLI_PASSPHRASE_PARENT_FILE,
                                             passphrase,
                                             sizeof(passphrase)) == SM_OK);
    ok = ok && (strcmp(passphrase, "owner-only-passphrase") == 0);

    if (!ok) {
        printf("test_key_passphrase_file_owner_only: expected secure file handling\n");
    }

    sodium_memzero(passphrase, sizeof(passphrase));
    cleanup_cli_files();
    return ok ? 0 : 1;
}

int test_cli_run(void)
{
    int failed = 0;

    failed += test_key_passphrase_file_owner_only();

    if (failed != 0) {
        printf("test_cli_run: %d failures\n", failed);
    }

    cleanup_cli_files();
    return failed == 0 ? 0 : 1;
}
