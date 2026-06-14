#define main fuzzed_vault_main
#include "../src/main.c"
#undef main

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_CLI_MAX_ARG 160U
#define FUZZ_CLI_MAX_ARGS 16U

#ifdef __APPLE__
extern int optreset;
#endif

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

static void fuzz_take_arg(fuzz_cursor_t *cursor, char *output, size_t output_len)
{
    size_t requested = 0U;
    size_t available = 0U;

    if ((cursor == NULL) || (output == NULL) || (output_len == 0U)) {
        return;
    }

    requested = (size_t)fuzz_take_byte(cursor);
    if (requested >= output_len) {
        requested %= output_len;
    }
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

static const char *fuzz_command(uint8_t selector, const char *generated)
{
    static const char *const commands[] = {
        "init",
        "put",
        "set",
        "get",
        "delete",
        "del",
        "rollback",
        "rotate-kek",
        "rotate",
        "audit-verify",
        "verify",
        "audit-root",
        "merkle-root",
    };

    if ((selector & 0x80U) != 0U) {
        return generated;
    }
    return commands[selector % (sizeof(commands) / sizeof(commands[0]))];
}

static void fuzz_version_arg(fuzz_cursor_t *cursor, char *output, size_t output_len)
{
    uint8_t selector = 0U;
    unsigned int value = 0U;

    if ((cursor == NULL) || (output == NULL) || (output_len == 0U)) {
        return;
    }

    selector = fuzz_take_byte(cursor);
    value = ((unsigned int)selector << 8U) | (unsigned int)fuzz_take_byte(cursor);
    if ((selector & 1U) == 0U) {
        (void)snprintf(output, output_len, "%u", value);
    } else if ((selector & 2U) == 0U) {
        (void)snprintf(output, output_len, "%ux", value);
    } else {
        fuzz_take_arg(cursor, output, output_len);
    }
}

static void fuzz_add_arg(char **argv, int *argc, char *arg)
{
    if ((argv == NULL) || (argc == NULL) || (*argc >= (int)FUZZ_CLI_MAX_ARGS)) {
        return;
    }
    argv[*argc] = arg;
    (*argc)++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_cursor_t cursor = {data, size, 0U};
    cli_options_t options;
    char generated_command[FUZZ_CLI_MAX_ARG];
    char db_path[FUZZ_CLI_MAX_ARG];
    char password[FUZZ_CLI_MAX_ARG];
    char new_password[FUZZ_CLI_MAX_ARG];
    char name[FUZZ_CLI_MAX_ARG];
    char value[FUZZ_CLI_MAX_ARG];
    char algorithm[FUZZ_CLI_MAX_ARG];
    char ttl[FUZZ_CLI_MAX_ARG];
    char within[FUZZ_CLI_MAX_ARG];
    char subject[FUZZ_CLI_MAX_ARG];
    char scope[FUZZ_CLI_MAX_ARG];
    char token[FUZZ_CLI_MAX_ARG];
    char version[FUZZ_CLI_MAX_ARG];
    char unknown_option[FUZZ_CLI_MAX_ARG];
    char *argv[FUZZ_CLI_MAX_ARGS + 1U];
    int argc = 0;
    uint8_t selector = 0U;

    if ((data == NULL) || (size > 4096U)) {
        return 0;
    }

    memset(&options, 0, sizeof(options));
    sodium_memzero(generated_command, sizeof(generated_command));
    sodium_memzero(db_path, sizeof(db_path));
    sodium_memzero(password, sizeof(password));
    sodium_memzero(new_password, sizeof(new_password));
    sodium_memzero(name, sizeof(name));
    sodium_memzero(value, sizeof(value));
    sodium_memzero(algorithm, sizeof(algorithm));
    sodium_memzero(ttl, sizeof(ttl));
    sodium_memzero(within, sizeof(within));
    sodium_memzero(subject, sizeof(subject));
    sodium_memzero(scope, sizeof(scope));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(version, sizeof(version));
    sodium_memzero(unknown_option, sizeof(unknown_option));
    memset(argv, 0, sizeof(argv));

    fuzz_take_arg(&cursor, generated_command, sizeof(generated_command));
    fuzz_take_arg(&cursor, db_path, sizeof(db_path));
    fuzz_take_arg(&cursor, password, sizeof(password));
    fuzz_take_arg(&cursor, new_password, sizeof(new_password));
    fuzz_take_arg(&cursor, name, sizeof(name));
    fuzz_take_arg(&cursor, value, sizeof(value));
    fuzz_take_arg(&cursor, algorithm, sizeof(algorithm));
    fuzz_take_arg(&cursor, ttl, sizeof(ttl));
    fuzz_take_arg(&cursor, within, sizeof(within));
    fuzz_take_arg(&cursor, subject, sizeof(subject));
    fuzz_take_arg(&cursor, scope, sizeof(scope));
    fuzz_take_arg(&cursor, token, sizeof(token));
    fuzz_version_arg(&cursor, version, sizeof(version));
    fuzz_take_arg(&cursor, unknown_option, sizeof(unknown_option));

    selector = fuzz_take_byte(&cursor);
    fuzz_add_arg(argv, &argc, "vault");
    if ((selector & 1U) == 0U) {
        fuzz_add_arg(argv,
                     &argc,
                     (char *)fuzz_command(fuzz_take_byte(&cursor),
                                          generated_command));
    }
    if ((selector & 2U) != 0U) {
        fuzz_add_arg(argv, &argc, "--help");
    }
    if ((selector & 4U) != 0U) {
        fuzz_add_arg(argv, &argc, "--db");
        fuzz_add_arg(argv, &argc, db_path);
    }
    if ((selector & 8U) != 0U) {
        fuzz_add_arg(argv, &argc, "--password");
        fuzz_add_arg(argv, &argc, password);
    }
    if ((selector & 16U) != 0U) {
        fuzz_add_arg(argv, &argc, "--new-password");
        fuzz_add_arg(argv, &argc, new_password);
    }
    if ((selector & 32U) != 0U) {
        fuzz_add_arg(argv, &argc, "--name");
        fuzz_add_arg(argv, &argc, name);
    }
    if ((selector & 64U) != 0U) {
        fuzz_add_arg(argv, &argc, "--value");
        fuzz_add_arg(argv, &argc, value);
    }
    if ((selector & 128U) != 0U) {
        fuzz_add_arg(argv, &argc, "--version");
        fuzz_add_arg(argv, &argc, version);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--algorithm");
        fuzz_add_arg(argv, &argc, algorithm);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--ttl");
        fuzz_add_arg(argv, &argc, ttl);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--within");
        fuzz_add_arg(argv, &argc, within);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--subject");
        fuzz_add_arg(argv, &argc, subject);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--scope");
        fuzz_add_arg(argv, &argc, scope);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--token");
        fuzz_add_arg(argv, &argc, token);
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, "--stdin");
    }
    if ((fuzz_take_byte(&cursor) & 1U) != 0U) {
        fuzz_add_arg(argv, &argc, unknown_option);
    }
    if ((selector & 1U) != 0U) {
        fuzz_add_arg(argv,
                     &argc,
                     (char *)fuzz_command(fuzz_take_byte(&cursor),
                                          generated_command));
    }
    argv[argc] = NULL;

#ifdef __APPLE__
    optreset = 1;
#endif
    (void)cli_parse_options(argc, argv, &options);

    sodium_memzero(generated_command, sizeof(generated_command));
    sodium_memzero(db_path, sizeof(db_path));
    sodium_memzero(password, sizeof(password));
    sodium_memzero(new_password, sizeof(new_password));
    sodium_memzero(name, sizeof(name));
    sodium_memzero(value, sizeof(value));
    sodium_memzero(algorithm, sizeof(algorithm));
    sodium_memzero(ttl, sizeof(ttl));
    sodium_memzero(within, sizeof(within));
    sodium_memzero(subject, sizeof(subject));
    sodium_memzero(scope, sizeof(scope));
    sodium_memzero(token, sizeof(token));
    sodium_memzero(version, sizeof(version));
    sodium_memzero(unknown_option, sizeof(unknown_option));
    return 0;
}
