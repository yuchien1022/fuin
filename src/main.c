#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
/* Expose realpath() on glibc, which gates it behind _DEFAULT_SOURCE under
   -std=c11; macOS provides it via _DARWIN_C_SOURCE above. */
#define _DEFAULT_SOURCE
#endif

#include "access.h"
#include "audit.h"
#include "backup.h"
#include "crypto_engine.h"
#include "utils.h"
#include "vault.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CLI_DEFAULT_DB_PATH "fuin.db"
#define CLI_MAX_SECRET_BYTES (1024U * 1024U)
#define CLI_SCOPE_BUFFER_LEN ACCESS_SCOPE_MAX
#define CLI_PASSWORD_MAX 512U
#define CLI_GENERATE_DEFAULT_LENGTH 24
#define CLI_GENERATE_MAX_LENGTH 256
#define CLI_CLIPBOARD_CLEAR_SECONDS 30U
#define CLI_CLIPBOARD_CLEAR_HELPER "__fuin_clipboard_clear_helper"
#define CLI_CLIPBOARD_ENV_MAX 12U

/* Absolute candidate paths for the platform clipboard helpers, tried in order.
   Exec-ing an absolute path (never a PATH search) keeps the no-injection
   hardening, while listing the common install locations lets `--copy` work on
   distros that ship xclip outside /usr/bin (/usr/local, /bin, Nix). */
#ifdef __APPLE__
static const char *const CLI_CLIPBOARD_COPY_CANDIDATES[] = {
    "/usr/bin/pbcopy", NULL,
};
static const char *const CLI_CLIPBOARD_PASTE_CANDIDATES[] = {
    "/usr/bin/pbpaste", NULL,
};
#else
static const char *const CLI_CLIPBOARD_COPY_CANDIDATES[] = {
    "/usr/bin/xclip", "/usr/local/bin/xclip", "/bin/xclip",
    "/run/current-system/sw/bin/xclip", NULL,
};
static const char *const CLI_CLIPBOARD_PASTE_CANDIDATES[] = {
    "/usr/bin/xclip", "/usr/local/bin/xclip", "/bin/xclip",
    "/run/current-system/sw/bin/xclip", NULL,
};
#endif

static const char *g_program_path = NULL;
static int g_cli_open_error_reported = 0;

/* ---- Terminal colour (TTY-gated, NO_COLOR-aware) -------------------------
   Colour and status glyphs are emitted only when the destination stream is
   an interactive terminal and the user has not opted out via NO_COLOR /
   TERM=dumb. When colour is disabled the output is byte-for-byte identical
   to the plain form, so redirected/piped output (and any scripts that parse
   it) is unaffected. Secret values and machine-readable data on stdout
   (get/generate/totp/tokens, audit hex/base64) are never decorated. */
#define CLI_SGR_RESET  "\033[0m"
#define CLI_SGR_BOLD   "\033[1m"
#define CLI_SGR_DIM    "\033[2m"
#define CLI_SGR_RED    "\033[31m"
#define CLI_SGR_GREEN  "\033[32m"
#define CLI_SGR_YELLOW "\033[33m"
#define CLI_SGR_CYAN   "\033[36m"
#define CLI_SYM_CHECK "\xE2\x9C\x93"  /* U+2713 check mark */
#define CLI_SYM_CROSS "\xE2\x9C\x97"  /* U+2717 ballot x */
#define CLI_SYM_DOT   "\xE2\x97\x8F"  /* U+25CF black circle */
#define CLI_SYM_ARROW "\xE2\x86\x92"  /* U+2192 rightwards arrow */
#define CLI_SYM_DASH  "\xE2\x80\x94"  /* U+2014 em dash */
#define CLI_SYM_SEP   "\xC2\xB7"      /* U+00B7 middle dot */

static int cli_color_probe(FILE *stream)
{
    const char *no_color = getenv("NO_COLOR");
    const char *term = getenv("TERM");
    int fd = (stream != NULL) ? fileno(stream) : -1;

    if ((no_color != NULL) && (no_color[0] != '\0')) {
        return 0;
    }
    if ((term != NULL) && (strcmp(term, "dumb") == 0)) {
        return 0;
    }
    return (fd >= 0) && (isatty(fd) == 1);
}

static int cli_color_enabled(FILE *stream)
{
    static int cached_out = -1;
    static int cached_err = -1;

    if (stream == stdout) {
        if (cached_out < 0) {
            cached_out = cli_color_probe(stdout);
        }
        return cached_out;
    }
    if (stream == stderr) {
        if (cached_err < 0) {
            cached_err = cli_color_probe(stderr);
        }
        return cached_err;
    }
    return cli_color_probe(stream);
}

/* Bold cyan section heading on a TTY; the plain text otherwise. */
static void cli_heading(FILE *stream, const char *text)
{
    if (cli_color_enabled(stream)) {
        fprintf(stream, CLI_SGR_BOLD CLI_SGR_CYAN "%s" CLI_SGR_RESET "\n", text);
    } else {
        fprintf(stream, "%s\n", text);
    }
}

/* Green "<check> <msg>" success line on a TTY; "<msg>" otherwise. */
static void cli_ok(FILE *stream, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void cli_ok(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    if (cli_color_enabled(stream)) {
        fputs(CLI_SGR_GREEN CLI_SYM_CHECK " " CLI_SGR_RESET, stream);
    }
    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
    va_end(ap);
    fputc('\n', stream);
}

/* Red "<cross> <msg>" error line on a TTY; "fuin: <msg>" otherwise. Always
   writes to stderr, matching the plain progname-prefixed convention. */
static void cli_error(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
static void cli_error(const char *fmt, ...)
{
    va_list ap;

    if (cli_color_enabled(stderr)) {
        fputs(CLI_SGR_RED CLI_SGR_BOLD CLI_SYM_CROSS " " CLI_SGR_RESET, stderr);
    } else {
        fputs("fuin: ", stderr);
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Dim "  <arrow> <msg>" follow-up hint on a TTY; "  <msg>" otherwise. */
static void cli_hint(FILE *stream, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void cli_hint(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    if (cli_color_enabled(stream)) {
        fputs(CLI_SGR_DIM "  " CLI_SYM_ARROW " ", stream);
    } else {
        fputs("  ", stream);
    }
    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
    va_end(ap);
    if (cli_color_enabled(stream)) {
        fputs(CLI_SGR_RESET, stream);
    }
    fputc('\n', stream);
}

/* Two-space-indented "command   description" reference line, as used by the
   intro and `init` next-steps. The command is cyan and the description dim on
   a TTY; plain (and byte-identical to the original literals) otherwise.
   desc_col is the column at which the description starts. */
static void cli_listing_line(FILE *stream,
                             int desc_col,
                             const char *cmd,
                             const char *desc)
{
    int pad = desc_col - 2 - (int)strlen(cmd);

    if (pad < 1) {
        pad = 1;
    }
    if (cli_color_enabled(stream)) {
        fprintf(stream,
                "  " CLI_SGR_CYAN "%s" CLI_SGR_RESET "%*s" CLI_SGR_DIM "%s"
                CLI_SGR_RESET "\n",
                cmd, pad, "", desc);
    } else {
        fprintf(stream, "  %s%*s%s\n", cmd, pad, "", desc);
    }
}

typedef struct {
    const char *command;
    const char *db_path;
    const char *password;
    const char *new_password;
    const char *name;
    const char *value;
    const char *algorithm;
    const char *subject;
    const char *scope;
    const char *token;
    const char *positional_name;
    const char *root_hex;
    const char *proof_hex;
    const char *signature_b64;
    const char *recipient_path;
    const char *private_key_path;
    const char *public_key_path;
    const char *key_passphrase_file;
    const char *public_out_path;
    const char *private_out_path;
    const char *input_path;
    const char *output_path;
    uint64_t ttl_seconds;
    uint64_t within_seconds;
    size_t leaf_index;
    size_t leaf_count;
    int version;
    int entry_id;
    int generate_length;
    int has_ttl;
    int has_within;
    int has_leaf_index;
    int has_leaf_count;
    int has_length;
    int no_symbols;
    int copy;
    int raw;
    int show_all;
    int read_stdin;
    int help;
} cli_options_t;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t capacity;
    int locked;
} cli_secret_buffer_t;

static void cli_print_intro(FILE *stream)
{
    if (cli_color_enabled(stream)) {
        fputs(CLI_SGR_BOLD "fuin - seal your secrets, prove your history"
              CLI_SGR_RESET "\n",
              stream);
    } else {
        fputs("fuin - seal your secrets, prove your history\n", stream);
    }
    fputs("\n"
          "Your secrets are encrypted on this machine (no server, no cloud),\n"
          "and every operation is recorded in a tamper-evident audit log you\n"
          "can verify yourself.\n"
          "\n",
          stream);
    cli_heading(stream, "Quick start:");
    cli_listing_line(stream, 29, "fuin init",
                     "create a vault (asks for a master password)");
    cli_listing_line(stream, 29, "fuin generate db/prod",
                     "generate and store a random secret");
    cli_listing_line(stream, 29, "fuin get db/prod --copy",
                     "copy it to the clipboard (auto-clears in 30 s)");
    cli_listing_line(stream, 29, "fuin list",
                     "see what is stored, without values");
    cli_listing_line(stream, 29, "fuin audit-verify",
                     "prove the history is untampered");
    fputs("\n", stream);
    if (cli_color_enabled(stream)) {
        fputs(CLI_SGR_DIM "Run 'fuin --help' for the full command reference."
              CLI_SGR_RESET "\n",
              stream);
    } else {
        fputs("Run 'fuin --help' for the full command reference.\n", stream);
    }
}

static void cli_print_usage(FILE *stream)
{
    fputs("Usage: fuin COMMAND [NAME] [OPTIONS]\n"
          "\n"
          "Commands that take a secret NAME accept it directly\n"
          "(e.g. 'fuin get db/prod') or via -n/--name.\n"
          "\n",
          stream);
    cli_heading(stream, "Everyday commands:");
    fputs("  init                 Create a new vault database\n"
          "  generate [NAME]      Generate, store, and print a random secret to\n"
          "                       stdout (or copy it to the clipboard)\n"
          "  put [NAME]           Store a secret (-v VALUE or --stdin)\n"
          "  get [NAME]           Print a secret value (--copy for clipboard,\n"
          "                       --raw for exact bytes without a newline)\n"
          "  totp [NAME]          Print an RFC 6238 code from a stored base32 seed\n"
          "  list                 List secret metadata without revealing values\n"
          "  delete [NAME]        Soft-delete a secret (history is kept)\n"
          "\n",
          stream);
    cli_heading(stream, "Lifecycle and access control:");
    fputs("  rollback [NAME]      Restore a historical version (--version N)\n"
          "  rotate-kek           Change the master password; rewraps all keys atomically\n"
          "  check-expiry         List expired or soon-expiring active secrets\n"
          "  auto-rotate          Re-encrypt expired active secrets with new keys\n"
          "  issue-token          Issue a scoped HMAC access token\n"
          "  check-token          Verify an HMAC access token and required scope\n"
          "  revoke-tokens        Revoke all previously issued HMAC access tokens\n"
          "  status-report        Print vault inventory and security posture\n"
          "\n",
          stream);
    cli_heading(stream, "Audit and proofs:");
    fputs("  audit-verify         Verify the audit hash chain and HMAC signatures\n"
          "  audit-root           Print the Merkle root (store it OUTSIDE the vault)\n"
          "  audit-proof          Print an inclusion proof for one audit entry\n"
          "  audit-verify-proof   Verify an entry proof against a saved root\n"
          "  audit-keygen         Generate an ML-DSA-65 audit signing keypair\n"
          "  audit-sign-root      Sign the audit Merkle root with ML-DSA-65\n"
          "  audit-verify-root-sig\n"
          "                       Verify a saved root signature offline (no password)\n"
          "\n",
          stream);
    cli_heading(stream, "Backup (post-quantum hybrid):");
    fputs("  pqc-keygen           Generate an X25519+ML-KEM-768 recipient keypair\n"
          "  backup-export        Export an encrypted backup capsule\n"
          "  backup-import        Restore a capsule (still needs the master password)\n"
          "\n",
          stream);
    cli_heading(stream, "Options:");
    fputs("  -d, --db PATH        SQLite vault path (default: fuin.db)\n"
          "  -p, --password PASS  Master password; disabled unless\n"
          "                       FUIN_ALLOW_INSECURE_ARGS=1\n"
          "      --new-password PASS\n"
          "                       New master password; disabled unless\n"
          "                       FUIN_ALLOW_INSECURE_ARGS=1\n"
          "  -n, --name NAME      Secret name\n"
          "  -v, --value VALUE    Secret value for put\n"
          "      --algorithm NAME AEAD for put/generate: AES-256-GCM,\n"
          "                       XChaCha20-Poly1305, or AEGIS-256\n"
          "      --ttl DURATION   Secret TTL for put: 90d, 24h, 60m, or 3600s\n"
          "      --within DURATION\n"
          "                       Lookahead for check-expiry; same units as --ttl\n"
          "      --subject NAME   Token subject for issue-token\n"
          "      --scope SCOPE    Token scope or required scope\n"
          "      --token TOKEN    HMAC token; disabled unless\n"
          "                       FUIN_ALLOW_INSECURE_ARGS=1\n"
          "      --version N      Historical version for get/rollback\n"
          "      --entry-id N     Audit entry id for audit-proof/verify-proof\n"
          "      --root HEX       Saved audit Merkle root for audit-verify-proof\n"
          "      --proof HEX      Concatenated sibling hashes for audit-verify-proof\n"
          "      --leaf-index N   Zero-based Merkle leaf index for audit-verify-proof\n"
          "      --entries N      Audit leaf count for proofs/root signatures\n"
          "      --recipient PATH hybrid public key for backup-export\n"
          "      --private-key PATH\n"
          "                       private key for backup-import/audit-sign-root\n"
          "      --public-key PATH\n"
          "                       ML-DSA public key for audit-verify-root-sig\n"
          "      --key-passphrase-file PATH\n"
          "                       First line supplies a backup/audit private key\n"
          "                       passphrase; otherwise a no-echo prompt is used\n"
          "      --signature B64  Root signature for audit-verify-root-sig\n"
          "      --public-out PATH\n"
          "                       Public key output for pqc-keygen\n"
          "      --private-out PATH\n"
          "                       Private key output for pqc-keygen\n"
          "      --input PATH     Capsule input for backup-import\n"
          "      --out PATH       Capsule or restored DB output path\n"
          "      --all            Include archived versions for list\n"
          "      --stdin          Read secret value for put from stdin\n"
          "      --length N       Generated secret length (default 24, max 256)\n"
          "      --no-symbols     Generate with letters and digits only\n"
          "      --copy           Copy secret to clipboard instead of printing;\n"
          "                       clipboard auto-clears after 30 seconds\n"
          "      --raw            For get: write exact secret bytes, no newline\n"
          "  -h, --help           Show this help\n"
          "\n",
          stream);
    cli_heading(stream, "Examples:");
    fputs("  fuin init\n"
          "  fuin generate db/prod --length 32\n"
          "  fuin put api/stripe --stdin < key.txt\n"
          "  fuin get db/prod --copy\n"
          "  fuin totp otp/github\n"
          "  fuin rotate-kek\n"
          "\n"
          "The master password is read from a no-echo prompt when the session\n"
          "is interactive, or from FUIN_PASSWORD otherwise. Direct password,\n"
          "token, and secret argv values require FUIN_ALLOW_INSECURE_ARGS=1.\n",
          stream);
}

static void cli_init_options(cli_options_t *options)
{
    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(*options));
    options->db_path = CLI_DEFAULT_DB_PATH;
}

static int cli_parse_positive_int(const char *value, int *parsed)
{
    char *end = NULL;
    long result = 0;

    if ((value == NULL) || (value[0] == '\0') || (parsed == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    errno = 0;
    result = strtol(value, &end, 10);
    if ((errno != 0) || (end == value) || (*end != '\0') ||
        (result < 1L) || (result > (long)INT_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *parsed = (int)result;
    return SM_OK;
}

static int cli_parse_size_value(const char *value,
                                size_t *parsed,
                                int allow_zero)
{
    char *end = NULL;
    unsigned long long result = 0ULL;

    if ((value == NULL) || (value[0] == '\0') || (parsed == NULL) ||
        (value[0] < '0') || (value[0] > '9')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    errno = 0;
    result = strtoull(value, &end, 10);
    if ((errno != 0) || (end == value) || (*end != '\0') ||
        ((!allow_zero) && (result == 0ULL)) ||
        (result > (unsigned long long)SIZE_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *parsed = (size_t)result;
    return SM_OK;
}

static int cli_parse_duration_seconds(const char *value, uint64_t *seconds)
{
    char *end = NULL;
    unsigned long long amount = 0ULL;
    uint64_t multiplier = 1U;

    if ((value == NULL) || (value[0] == '\0') ||
        (value[0] < '0') || (value[0] > '9') ||
        (seconds == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    errno = 0;
    amount = strtoull(value, &end, 10);
    if ((errno != 0) || (end == value) || (amount == 0ULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (*end != '\0') {
        if (end[1] != '\0') {
            return SM_ERR_INVALID_ARGUMENT;
        }
        switch (*end) {
        case 's':
            multiplier = 1U;
            break;
        case 'm':
            multiplier = 60U;
            break;
        case 'h':
            multiplier = 60U * 60U;
            break;
        case 'd':
            multiplier = 24U * 60U * 60U;
            break;
        default:
            return SM_ERR_INVALID_ARGUMENT;
        }
    }
    if (amount > (unsigned long long)(UINT64_MAX / multiplier)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *seconds = (uint64_t)amount * multiplier;
    return SM_OK;
}

static int cli_alloc_secret_buffer(cli_secret_buffer_t *buffer, size_t capacity)
{
    if ((buffer == NULL) || (capacity == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    memset(buffer, 0, sizeof(*buffer));
    buffer->data = sodium_malloc(capacity);
    if (buffer->data == NULL) {
        return SM_ERR_STORAGE;
    }

    buffer->capacity = capacity;
    sodium_memzero(buffer->data, buffer->capacity);
    if (sodium_mlock(buffer->data, buffer->capacity) == 0) {
        buffer->locked = 1;
    }

    return SM_OK;
}

static void cli_free_secret_buffer(cli_secret_buffer_t *buffer)
{
    if ((buffer == NULL) || (buffer->data == NULL)) {
        return;
    }

    sodium_memzero(buffer->data, buffer->capacity);
    if (buffer->locked) {
        (void)sodium_munlock(buffer->data, buffer->capacity);
    }
    sodium_free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int cli_read_stdin_secret(cli_secret_buffer_t *buffer)
{
    size_t total = 0U;
    unsigned char extra = 0U;

    if (buffer == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (cli_alloc_secret_buffer(buffer, CLI_MAX_SECRET_BYTES) != SM_OK) {
        return SM_ERR_STORAGE;
    }

    while (total < buffer->capacity) {
        size_t nread = fread(buffer->data + total,
                             1U,
                             buffer->capacity - total,
                             stdin);
        total += nread;
        if (nread == 0U) {
            break;
        }
    }
    if (ferror(stdin)) {
        cli_free_secret_buffer(buffer);
        return SM_ERR_STORAGE;
    }
    if ((total == buffer->capacity) &&
        (fread(&extra, 1U, 1U, stdin) == 1U)) {
        sodium_memzero(&extra, sizeof(extra));
        cli_free_secret_buffer(buffer);
        return SM_ERR_INPUT_TOO_LARGE;
    }
    sodium_memzero(&extra, sizeof(extra));
    if (ferror(stdin)) {
        cli_free_secret_buffer(buffer);
        return SM_ERR_STORAGE;
    }
    if ((total < buffer->capacity) && !feof(stdin)) {
        cli_free_secret_buffer(buffer);
        return SM_ERR_STORAGE;
    }

    buffer->len = total;
    return SM_OK;
}

static int cli_sensitive_argv_allowed(void)
{
    const char *allowed = getenv("FUIN_ALLOW_INSECURE_ARGS");

    return (allowed != NULL) && (strcmp(allowed, "1") == 0);
}

static int cli_parse_with_getopt(int argc, char **argv, cli_options_t *options)
{
    static const struct option long_options[] = {
        {"db", required_argument, NULL, 'd'},
        {"password", required_argument, NULL, 'p'},
        {"new-password", required_argument, NULL, 1000},
        {"version", required_argument, NULL, 1001},
        {"algorithm", required_argument, NULL, 1002},
        {"ttl", required_argument, NULL, 1003},
        {"within", required_argument, NULL, 1004},
        {"subject", required_argument, NULL, 1005},
        {"scope", required_argument, NULL, 1006},
        {"token", required_argument, NULL, 1007},
        {"entry-id", required_argument, NULL, 1008},
        {"root", required_argument, NULL, 1009},
        {"proof", required_argument, NULL, 1010},
        {"leaf-index", required_argument, NULL, 1011},
        {"entries", required_argument, NULL, 1012},
        {"all", no_argument, NULL, 1013},
        {"recipient", required_argument, NULL, 1014},
        {"private-key", required_argument, NULL, 1015},
        {"public-out", required_argument, NULL, 1016},
        {"private-out", required_argument, NULL, 1017},
        {"input", required_argument, NULL, 1018},
        {"out", required_argument, NULL, 1019},
        {"length", required_argument, NULL, 1020},
        {"no-symbols", no_argument, NULL, 1021},
        {"copy", no_argument, NULL, 1022},
        {"public-key", required_argument, NULL, 1023},
        {"signature", required_argument, NULL, 1024},
        {"raw", no_argument, NULL, 1025},
        {"key-passphrase-file", required_argument, NULL, 1026},
        {"name", required_argument, NULL, 'n'},
        {"value", required_argument, NULL, 'v'},
        {"stdin", no_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option = 0;

    if ((argc < 1) || (argv == NULL) || (options == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    optind = 1;
    opterr = 0;
    while ((option = getopt_long(argc,
                                 argv,
                                 "d:p:n:v:sh",
                                 long_options,
                                 NULL)) != -1) {
        switch (option) {
        case 'd':
            options->db_path = optarg;
            break;
        case 'p':
            if (!cli_sensitive_argv_allowed()) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->password = optarg;
            break;
        case 1000:
            if (!cli_sensitive_argv_allowed()) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->new_password = optarg;
            break;
        case 1001:
            if (cli_parse_positive_int(optarg, &options->version) != SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            break;
        case 1002:
            options->algorithm = optarg;
            break;
        case 1003:
            if (cli_parse_duration_seconds(optarg, &options->ttl_seconds) !=
                SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->has_ttl = 1;
            break;
        case 1004:
            if (cli_parse_duration_seconds(optarg, &options->within_seconds) !=
                SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->has_within = 1;
            break;
        case 1005:
            options->subject = optarg;
            break;
        case 1006:
            options->scope = optarg;
            break;
        case 1007:
            if (!cli_sensitive_argv_allowed()) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->token = optarg;
            break;
        case 1008:
            if (cli_parse_positive_int(optarg, &options->entry_id) != SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            break;
        case 1009:
            options->root_hex = optarg;
            break;
        case 1010:
            options->proof_hex = optarg;
            break;
        case 1011:
            if (cli_parse_size_value(optarg, &options->leaf_index, 1) !=
                SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->has_leaf_index = 1;
            break;
        case 1012:
            if (cli_parse_size_value(optarg, &options->leaf_count, 0) !=
                SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->has_leaf_count = 1;
            break;
        case 1013:
            options->show_all = 1;
            break;
        case 1014:
            options->recipient_path = optarg;
            break;
        case 1015:
            options->private_key_path = optarg;
            break;
        case 1016:
            options->public_out_path = optarg;
            break;
        case 1017:
            options->private_out_path = optarg;
            break;
        case 1018:
            options->input_path = optarg;
            break;
        case 1019:
            options->output_path = optarg;
            break;
        case 1020:
            if (cli_parse_positive_int(optarg, &options->generate_length) !=
                SM_OK) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->has_length = 1;
            break;
        case 1021:
            options->no_symbols = 1;
            break;
        case 1022:
            options->copy = 1;
            break;
        case 1023:
            options->public_key_path = optarg;
            break;
        case 1024:
            options->signature_b64 = optarg;
            break;
        case 1025:
            options->raw = 1;
            break;
        case 1026:
            options->key_passphrase_file = optarg;
            break;
        case 'n':
            options->name = optarg;
            break;
        case 'v':
            if (!cli_sensitive_argv_allowed()) {
                return SM_ERR_INVALID_ARGUMENT;
            }
            options->value = optarg;
            break;
        case 's':
            options->read_stdin = 1;
            break;
        case 'h':
            options->help = 1;
            break;
        default:
            return SM_ERR_INVALID_ARGUMENT;
        }
    }

    if (options->command == NULL) {
        if (optind < argc) {
            options->command = argv[optind];
            optind++;
        }
    }
    if ((optind < argc) && (options->positional_name == NULL)) {
        options->positional_name = argv[optind];
        optind++;
    }
    if (optind < argc) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    return SM_OK;
}

static int cli_command_accepts_name(const char *command)
{
    return (strcmp(command, "put") == 0) || (strcmp(command, "set") == 0) ||
           (strcmp(command, "generate") == 0) ||
           (strcmp(command, "gen") == 0) ||
           (strcmp(command, "get") == 0) || (strcmp(command, "totp") == 0) ||
           (strcmp(command, "delete") == 0) ||
           (strcmp(command, "del") == 0) ||
           (strcmp(command, "rollback") == 0);
}

static int cli_parse_options(int argc, char **argv, cli_options_t *options)
{
    char **parse_argv = NULL;
    int parse_argc = argc;
    int status = SM_OK;
    int i = 0;

    if ((argc < 1) || (argv == NULL) || (options == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    cli_init_options(options);
    if ((argc > 1) && (argv[1][0] != '-')) {
        options->command = argv[1];
        parse_argc = argc - 1;
        parse_argv = malloc(((size_t)parse_argc + 1U) * sizeof(*parse_argv));
        if (parse_argv == NULL) {
            return SM_ERR_STORAGE;
        }
        parse_argv[0] = argv[0];
        for (i = 2; i < argc; i++) {
            parse_argv[i - 1] = argv[i];
        }
        parse_argv[parse_argc] = NULL;
        status = cli_parse_with_getopt(parse_argc, parse_argv, options);
        free(parse_argv);
    } else {
        status = cli_parse_with_getopt(argc, argv, options);
    }

    if (status == SM_OK) {
        if (options->password == NULL) {
            options->password = getenv("FUIN_PASSWORD");
        }
        if (options->new_password == NULL) {
            options->new_password = getenv("FUIN_NEW_PASSWORD");
        }
        if (options->token == NULL) {
            options->token = getenv("FUIN_TOKEN");
        }
        if ((options->value != NULL) && options->read_stdin) {
            status = SM_ERR_INVALID_ARGUMENT;
        }
        if ((options->db_path == NULL) || (options->db_path[0] == '\0')) {
            status = SM_ERR_INVALID_ARGUMENT;
        }
        if (options->positional_name != NULL) {
            if ((options->command == NULL) ||
                !cli_command_accepts_name(options->command) ||
                (options->name != NULL)) {
                status = SM_ERR_INVALID_ARGUMENT;
            } else {
                options->name = options->positional_name;
            }
        }
        if (options->raw && !options->help) {
            if ((options->command == NULL) ||
                (strcmp(options->command, "get") != 0) ||
                options->copy) {
                status = SM_ERR_INVALID_ARGUMENT;
            }
        }
    }

    return status;
}

static int cli_require_password(const cli_options_t *options)
{
    if ((options == NULL) ||
        (options->password == NULL) ||
        (options->password[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    return SM_OK;
}

/* Print the standard "no [initialised] vault at PATH; create one first" error
   plus hint, and record that the open phase already produced a complete
   explanation so main() stays silent instead of printing a second, generic
   message for the same failure. The lead text varies (truly missing file vs
   schema-only DB without metadata); everything else is identical. */
static int cli_report_missing_vault(const char *db_path, const char *lead)
{
    cli_error("%s '%s'", lead, db_path);
    g_cli_open_error_reported = 1;
    if (cli_color_enabled(stderr)) {
        cli_hint(stderr, "create one first: fuin init --db %s", db_path);
    } else {
        fprintf(stderr,
                "       create one first: fuin init --db %s\n",
                db_path);
    }
    return SM_ERR_NOT_FOUND;
}

static int cli_open_unlocked_vault(const cli_options_t *options)
{
    int status = cli_require_password(options);

    if (status != SM_OK) {
        return status;
    }

    /* Only `init` may create the database file; everything else on a
       missing path should explain itself instead of silently creating
       an empty vault. */
    if ((strcmp(options->command, "init") != 0) &&
        (access(options->db_path, F_OK) != 0)) {
        return cli_report_missing_vault(options->db_path,
                                        "no vault database at");
    }

    if (strcmp(options->command, "init") == 0) {
        status = vault_init(options->db_path);
        if (status == SM_OK) {
            status = vault_unlock(options->password);
        }
        return status;
    }

    status = vault_open(options->db_path);
    if (status != SM_OK) {
        /* The path exists (checked above) but could not be opened as a vault:
           it may be uninitialised or corrupt, or its final path component may
           be a symlink refused by O_NOFOLLOW. Report accurately and preserve
           the real error instead of claiming the database is missing and
           offering "fuin init" advice that would also fail on a final symlink.
         */
        cli_error("cannot open vault database at '%s' "
                  "(not an initialised vault, or the path is not a regular file)",
                  options->db_path);
        g_cli_open_error_reported = 1;
        return status;
    }

    status = vault_unlock_existing(options->password);
    if (status == SM_ERR_NOT_FOUND) {
        return cli_report_missing_vault(options->db_path,
                                        "no initialized vault database at");
    }
    return status;
}

/* Reads a password from the controlling terminal with echo disabled.
   Returns SM_ERR_INVALID_ARGUMENT when no terminal is available so
   non-interactive callers fall back to the env/option error path. */
static int cli_prompt_password(const char *prompt, char *out, size_t out_len)
{
    FILE *tty = NULL;
    struct termios saved;
    struct termios noecho;
    size_t len = 0U;
    int status = SM_OK;

    if ((prompt == NULL) || (out == NULL) || (out_len < 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    tty = fopen("/dev/tty", "r+");
    if (tty == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (tcgetattr(fileno(tty), &saved) != 0) {
        (void)fclose(tty);
        return SM_ERR_STORAGE;
    }
    noecho = saved;
    noecho.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(fileno(tty), TCSAFLUSH, &noecho) != 0) {
        (void)fclose(tty);
        return SM_ERR_STORAGE;
    }

    fputs(prompt, tty);
    (void)fflush(tty);
    if (fgets(out, (int)out_len, tty) == NULL) {
        status = SM_ERR_INVALID_ARGUMENT;
    }
    (void)tcsetattr(fileno(tty), TCSAFLUSH, &saved);
    (void)fputc('\n', tty);
    (void)fclose(tty);

    if (status == SM_OK) {
        len = strlen(out);
        while ((len > 0U) &&
               ((out[len - 1U] == '\n') || (out[len - 1U] == '\r'))) {
            out[--len] = '\0';
        }
        if (len == 0U) {
            status = SM_ERR_INVALID_ARGUMENT;
        }
    }
    if (status != SM_OK) {
        sodium_memzero(out, out_len);
    }
    return status;
}

/* Prompts twice; SM_ERR_AUTH means the two entries did not match. */
static int cli_prompt_password_confirmed(const char *prompt,
                                         const char *confirm_prompt,
                                         char *out,
                                         size_t out_len)
{
    char confirm[CLI_PASSWORD_MAX];
    int status = cli_prompt_password(prompt, out, out_len);

    if (status != SM_OK) {
        return status;
    }
    status = cli_prompt_password(confirm_prompt, confirm, sizeof(confirm));
    if (status == SM_OK) {
        if ((strlen(out) != strlen(confirm)) ||
            (sodium_memcmp(out, confirm, strlen(out)) != 0)) {
            status = SM_ERR_AUTH;
        }
    }
    sodium_memzero(confirm, sizeof(confirm));
    if (status != SM_OK) {
        sodium_memzero(out, out_len);
    }
    return status;
}

static int cli_resolve_parent_path(const char *path, char **resolved_path)
{
    const char *slash = NULL;
    const char *basename = NULL;
    char *parent = NULL;
    char *resolved_parent = NULL;
    char *combined = NULL;
    const char *separator = "/";
    size_t parent_len = 0U;
    size_t parent_path_len = 0U;
    size_t basename_len = 0U;
    size_t separator_len = 1U;
    size_t combined_len = 0U;
    int written = 0;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') || (resolved_path == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *resolved_path = NULL;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        basename = path;
        parent_len = 1U;
        parent = malloc(parent_len + 1U);
        if (parent == NULL) {
            return SM_ERR_STORAGE;
        }
        memcpy(parent, ".", parent_len + 1U);
    } else {
        basename = slash + 1;
        if (basename[0] == '\0') {
            return SM_ERR_INVALID_ARGUMENT;
        }
        parent_len = (slash == path) ? 1U : (size_t)(slash - path);
        parent = malloc(parent_len + 1U);
        if (parent == NULL) {
            return SM_ERR_STORAGE;
        }
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    }

    if ((strcmp(basename, ".") == 0) || (strcmp(basename, "..") == 0)) {
        status = SM_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }

    resolved_parent = realpath(parent, NULL);
    if (resolved_parent == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    parent_path_len = strlen(resolved_parent);
    basename_len = strlen(basename);
    if (strcmp(resolved_parent, "/") == 0) {
        separator = "";
        separator_len = 0U;
    }
    if ((parent_path_len > (SIZE_MAX - separator_len)) ||
        ((parent_path_len + separator_len) > (SIZE_MAX - basename_len)) ||
        ((parent_path_len + separator_len + basename_len) >
         (SIZE_MAX - 1U))) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    combined_len = parent_path_len + separator_len + basename_len + 1U;
    combined = malloc(combined_len);
    if (combined == NULL) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    written = snprintf(combined,
                       combined_len,
                       "%s%s%s",
                       resolved_parent,
                       separator,
                       basename);
    if ((written < 0) || ((size_t)written >= combined_len)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    *resolved_path = combined;
    combined = NULL;

cleanup:
    free(combined);
    free(resolved_parent);
    free(parent);
    return status;
}

static int cli_fopen_owner_only_read(const char *path, FILE **out)
{
    struct stat st;
    char *resolved_path = NULL;
    FILE *fp = NULL;
    int status = SM_OK;
    int fd = -1;

    if ((path == NULL) || (path[0] == '\0') || (out == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    status = cli_resolve_parent_path(path, &resolved_path);
    if (status != SM_OK) {
        return status;
    }

    fd = open(resolved_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        free(resolved_path);
        return SM_ERR_STORAGE;
    }
    if ((fstat(fd, &st) != 0) ||
        !S_ISREG(st.st_mode) ||
        (st.st_uid != getuid()) ||
        ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)) {
        (void)close(fd);
        free(resolved_path);
        return SM_ERR_STORAGE;
    }

    fp = fdopen(fd, "rb");
    if (fp == NULL) {
        (void)close(fd);
        free(resolved_path);
        return SM_ERR_STORAGE;
    }
    *out = fp;
    free(resolved_path);
    return SM_OK;
}

static int cli_read_key_passphrase_file(const char *path,
                                        char *out,
                                        size_t out_len)
{
    FILE *fp = NULL;
    size_t nread = 0U;
    size_t len = 0U;
    unsigned char extra = 0U;
    int status = SM_OK;

    if ((path == NULL) || (path[0] == '\0') ||
        (out == NULL) || (out_len < 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    sodium_memzero(out, out_len);
    status = cli_fopen_owner_only_read(path, &fp);
    if (status != SM_OK) {
        return status;
    }
    nread = fread(out, 1U, out_len - 1U, fp);
    if (ferror(fp)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if ((nread == (out_len - 1U)) &&
        (fread(&extra, 1U, 1U, fp) == 1U)) {
        status = SM_ERR_INPUT_TOO_LARGE;
        goto cleanup;
    }
    out[nread] = '\0';
    len = strlen(out);
    while ((len > 0U) &&
           ((out[len - 1U] == '\n') || (out[len - 1U] == '\r'))) {
        out[--len] = '\0';
    }
    if (len == 0U) {
        status = SM_ERR_INVALID_ARGUMENT;
    }

cleanup:
    sodium_memzero(&extra, sizeof(extra));
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status != SM_OK) {
        sodium_memzero(out, out_len);
    }
    return status;
}

static int cli_load_key_passphrase(const cli_options_t *options,
                                   int confirmed,
                                   char *out,
                                   size_t out_len)
{
    if ((options == NULL) || (out == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (options->key_passphrase_file != NULL) {
        return cli_read_key_passphrase_file(options->key_passphrase_file,
                                            out,
                                            out_len);
    }
    if (confirmed) {
        return cli_prompt_password_confirmed("Private key passphrase: ",
                                             "Confirm private key passphrase: ",
                                             out,
                                             out_len);
    }
    return cli_prompt_password("Private key passphrase: ", out, out_len);
}

static int cli_command_needs_master_password(const char *command)
{
    return (strcmp(command, "pqc-keygen") != 0) &&
           (strcmp(command, "backup-import") != 0) &&
           (strcmp(command, "audit-keygen") != 0) &&
           (strcmp(command, "audit-verify-root-sig") != 0);
}

static int cli_write_all_ignore_sigpipe(int fd,
                                        const unsigned char *data,
                                        size_t data_len);
static int cli_clipboard_build_env(char **envp, size_t envp_len);
static void cli_clipboard_free_env(char **envp);

static int cli_wait_for_child(pid_t pid)
{
    int child_status = 0;
    pid_t waited = (pid_t)-1;

    do {
        waited = waitpid(pid, &child_status, 0);
    } while ((waited < 0) && (errno == EINTR));

    if ((waited < 0) ||
        !WIFEXITED(child_status) ||
        (WEXITSTATUS(child_status) != 0)) {
        return SM_ERR_STORAGE;
    }
    return SM_OK;
}

/* First candidate path that exists and is executable, or NULL. Keeps the
   "exec an absolute path, never a PATH search" hardening while tolerating
   clipboard helpers installed outside /usr/bin. */
static const char *cli_clipboard_resolve_program(const char *const *candidates)
{
    size_t i = 0U;

    if (candidates == NULL) {
        return NULL;
    }
    for (i = 0U; candidates[i] != NULL; i++) {
        if (access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

/* Spawns the clipboard helper with the controlled env and a single pipe wired
   to the child's child_std (STDIN to feed it for copy, STDOUT to read from it
   for paste); the child's other stdio go to /dev/null. On success *parent_fd
   receives the parent end of the pipe (caller closes it) and *pid the child
   (caller reaps with cli_wait_for_child). Shared by the copy and paste paths
   so the fork/exec/fd lifecycle exists in exactly one place. */
static int cli_clipboard_spawn(const char *program,
                               char *const argv[],
                               int child_std,
                               int *parent_fd,
                               pid_t *pid)
{
    posix_spawn_file_actions_t actions;
    char *helper_env[CLI_CLIPBOARD_ENV_MAX] = {0};
    int pipe_fds[2] = {-1, -1};
    int child_end = (child_std == STDIN_FILENO) ? 0 : 1;
    int parent_end = (child_std == STDIN_FILENO) ? 1 : 0;
    int actions_ready = 0;
    int status = SM_OK;

    *parent_fd = -1;
    *pid = (pid_t)0;

    status = cli_clipboard_build_env(helper_env,
                                     sizeof(helper_env) / sizeof(helper_env[0]));
    if (status != SM_OK) {
        cli_clipboard_free_env(helper_env);
        return status;
    }
    if (pipe(pipe_fds) != 0) {
        cli_clipboard_free_env(helper_env);
        return SM_ERR_STORAGE;
    }
    if (posix_spawn_file_actions_init(&actions) != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    actions_ready = 1;
    if ((posix_spawn_file_actions_adddup2(&actions,
                                          pipe_fds[child_end],
                                          child_std) != 0) ||
        (posix_spawn_file_actions_addclose(&actions, pipe_fds[0]) != 0) ||
        (posix_spawn_file_actions_addclose(&actions, pipe_fds[1]) != 0)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    /* Send every child stdio stream except the piped one to /dev/null. */
    if ((child_std != STDOUT_FILENO) &&
        (posix_spawn_file_actions_addopen(&actions,
                                          STDOUT_FILENO,
                                          "/dev/null",
                                          O_WRONLY,
                                          0) != 0)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (posix_spawn_file_actions_addopen(&actions,
                                         STDERR_FILENO,
                                         "/dev/null",
                                         O_WRONLY,
                                         0) != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (posix_spawn(pid, program, &actions, NULL, argv, helper_env) != 0) {
        *pid = (pid_t)0;
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    if (close(pipe_fds[child_end]) != 0) {
        status = SM_ERR_STORAGE;
    }
    pipe_fds[child_end] = -1;
    if (status == SM_OK) {
        *parent_fd = pipe_fds[parent_end];
        pipe_fds[parent_end] = -1;
    }

cleanup:
    if (pipe_fds[0] >= 0) {
        (void)close(pipe_fds[0]);
    }
    if (pipe_fds[1] >= 0) {
        (void)close(pipe_fds[1]);
    }
    if (actions_ready) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    cli_clipboard_free_env(helper_env);
    return status;
}

static int cli_clipboard_write(const unsigned char *data, size_t data_len)
{
    const char *program =
        cli_clipboard_resolve_program(CLI_CLIPBOARD_COPY_CANDIDATES);
#ifdef __APPLE__
    char *copy_argv[] = {(char *)program, NULL};
#else
    char *copy_argv[] = {
        (char *)program,
        (char *)"-selection",
        (char *)"clipboard",
        NULL,
    };
#endif
    int parent_fd = -1;
    int status = SM_OK;
    pid_t pid = (pid_t)0;

    if ((data == NULL) && (data_len > 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (program == NULL) {
        return SM_ERR_STORAGE;
    }

    status = cli_clipboard_spawn(program, copy_argv, STDIN_FILENO,
                                 &parent_fd, &pid);
    if (status != SM_OK) {
        return status;
    }
    if (cli_write_all_ignore_sigpipe(parent_fd, data, data_len) != SM_OK) {
        status = SM_ERR_STORAGE;
    }
    if (close(parent_fd) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (cli_wait_for_child(pid) != SM_OK) {
        status = SM_ERR_STORAGE;
    }
    return status;
}

static int cli_read_exact_fd(int fd, unsigned char *data, size_t data_len)
{
    size_t total = 0U;

    if (((data == NULL) && (data_len > 0U)) || (fd < 0)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    while (total < data_len) {
        ssize_t nread = read(fd, data + total, data_len - total);

        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SM_ERR_STORAGE;
        }
        if (nread == 0) {
            return SM_ERR_STORAGE;
        }
        total += (size_t)nread;
    }
    return SM_OK;
}

static int cli_write_all_fd(int fd, const unsigned char *data, size_t data_len)
{
    size_t total = 0U;

    if (((data == NULL) && (data_len > 0U)) || (fd < 0)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    while (total < data_len) {
        ssize_t nwritten = write(fd, data + total, data_len - total);

        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SM_ERR_STORAGE;
        }
        if (nwritten == 0) {
            return SM_ERR_STORAGE;
        }
        total += (size_t)nwritten;
    }
    return SM_OK;
}

static int cli_write_all_ignore_sigpipe(int fd,
                                        const unsigned char *data,
                                        size_t data_len)
{
    struct sigaction ignore_action;
    struct sigaction old_action;
    int restore_signal = 0;
    int status = SM_OK;

    memset(&ignore_action, 0, sizeof(ignore_action));
    memset(&old_action, 0, sizeof(old_action));
    ignore_action.sa_handler = SIG_IGN;
    if (sigemptyset(&ignore_action.sa_mask) != 0) {
        return SM_ERR_STORAGE;
    }
    if (sigaction(SIGPIPE, &ignore_action, &old_action) == 0) {
        restore_signal = 1;
    }

    status = cli_write_all_fd(fd, data, data_len);

    if (restore_signal) {
        (void)sigaction(SIGPIPE, &old_action, NULL);
    }
    return status;
}

static int cli_clipboard_read_current(unsigned char **current,
                                      size_t *current_len,
                                      size_t max_len)
{
    const char *program =
        cli_clipboard_resolve_program(CLI_CLIPBOARD_PASTE_CANDIDATES);
#ifdef __APPLE__
    char *paste_argv[] = {(char *)program, NULL};
#else
    char *paste_argv[] = {
        (char *)program,
        (char *)"-selection",
        (char *)"clipboard",
        (char *)"-o",
        NULL,
    };
#endif
    unsigned char *buffer = NULL;
    int parent_fd = -1;
    int status = SM_OK;
    pid_t pid = (pid_t)0;

    if ((current == NULL) || (current_len == NULL) ||
        (max_len > CLI_MAX_SECRET_BYTES)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    *current = NULL;
    *current_len = 0U;
    if (program == NULL) {
        return SM_ERR_STORAGE;
    }

    buffer = malloc(max_len + 1U);
    if (buffer == NULL) {
        return SM_ERR_STORAGE;
    }

    status = cli_clipboard_spawn(program, paste_argv, STDOUT_FILENO,
                                 &parent_fd, &pid);
    if (status != SM_OK) {
        sodium_memzero(buffer, max_len + 1U);
        free(buffer);
        return status;
    }

    while ((status == SM_OK) && (*current_len < (max_len + 1U))) {
        ssize_t nread = read(parent_fd,
                             buffer + *current_len,
                             (max_len + 1U) - *current_len);

        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            status = SM_ERR_STORAGE;
        } else if (nread == 0) {
            break;
        } else {
            *current_len += (size_t)nread;
        }
    }
    if (close(parent_fd) != 0) {
        status = SM_ERR_STORAGE;
    }
    if (cli_wait_for_child(pid) != SM_OK) {
        status = SM_ERR_STORAGE;
    }

    if (status != SM_OK) {
        sodium_memzero(buffer, max_len + 1U);
        free(buffer);
        *current_len = 0U;
        return status;
    }

    *current = buffer;
    return SM_OK;
}

static int cli_clipboard_clear_helper(int argc, char **argv)
{
    unsigned char *expected = NULL;
    unsigned char *current = NULL;
    size_t expected_len = 0U;
    size_t current_len = 0U;
    size_t delay_seconds = 0U;
    int expected_locked = 0;
    int matches = 0;
    int status = SM_OK;

    if ((argc != 4) || (argv == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    status = cli_parse_size_value(argv[2], &expected_len, 1);
    if (status == SM_OK) {
        status = cli_parse_size_value(argv[3], &delay_seconds, 1);
    }
    if ((status != SM_OK) ||
        (expected_len > CLI_MAX_SECRET_BYTES) ||
        (delay_seconds > (size_t)UINT_MAX)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (expected_len == 0U) {
        return SM_OK;
    }

    expected = sodium_malloc(expected_len);
    if (expected == NULL) {
        return SM_ERR_STORAGE;
    }
    if (sodium_mlock(expected, expected_len) == 0) {
        expected_locked = 1;
    }

    status = cli_read_exact_fd(STDIN_FILENO, expected, expected_len);
    if (status == SM_OK) {
        while (delay_seconds > 0U) {
            delay_seconds = sleep((unsigned int)delay_seconds);
        }
        if (cli_clipboard_read_current(&current,
                                       &current_len,
                                       expected_len) == SM_OK) {
            matches = (current_len == expected_len) &&
                      (sodium_memcmp(current, expected, expected_len) == 0);
            if (matches) {
                (void)cli_clipboard_write(NULL, 0U);
            }
        }
    }

    if (current != NULL) {
        sodium_memzero(current, expected_len + 1U);
        free(current);
    }
    sodium_memzero(expected, expected_len);
    if (expected_locked) {
        (void)sodium_munlock(expected, expected_len);
    }
    sodium_free(expected);
    return status;
}

static int cli_clipboard_add_env(char **envp,
                                 size_t envp_len,
                                 size_t *env_count,
                                 const char *name,
                                 const char *fallback_value)
{
    const char *value = NULL;
    size_t name_len = 0U;
    size_t value_len = 0U;
    char *entry = NULL;

    if ((envp == NULL) || (env_count == NULL) || (name == NULL) ||
        (*env_count + 1U >= envp_len)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if ((strcmp(name, "PATH") == 0) && (fallback_value != NULL)) {
        value = fallback_value;
    } else {
        value = getenv(name);
        if ((value == NULL) || (value[0] == '\0')) {
            value = fallback_value;
        }
    }
    if ((value == NULL) || (value[0] == '\0')) {
        return SM_OK;
    }

    name_len = strlen(name);
    value_len = strlen(value);
    if (name_len > (SIZE_MAX - value_len - 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    entry = malloc(name_len + value_len + 2U);
    if (entry == NULL) {
        return SM_ERR_STORAGE;
    }
    memcpy(entry, name, name_len);
    entry[name_len] = '=';
    memcpy(entry + name_len + 1U, value, value_len + 1U);

    envp[*env_count] = entry;
    (*env_count)++;
    envp[*env_count] = NULL;
    return SM_OK;
}

static void cli_clipboard_free_env(char **envp)
{
    size_t i = 0U;

    if (envp == NULL) {
        return;
    }
    for (i = 0U; envp[i] != NULL; i++) {
        free(envp[i]);
        envp[i] = NULL;
    }
}

static int cli_clipboard_build_env(char **envp, size_t envp_len)
{
    size_t env_count = 0U;
    int status = SM_OK;

    if ((envp == NULL) || (envp_len < 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    memset(envp, 0, envp_len * sizeof(*envp));

    status = cli_clipboard_add_env(
        envp,
        envp_len,
        &env_count,
        "PATH",
        "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin");
    if (status == SM_OK) {
        status = cli_clipboard_add_env(envp, envp_len, &env_count, "HOME", NULL);
    }
    if (status == SM_OK) {
        status = cli_clipboard_add_env(envp, envp_len, &env_count, "DISPLAY", NULL);
    }
    if (status == SM_OK) {
        status = cli_clipboard_add_env(
            envp, envp_len, &env_count, "WAYLAND_DISPLAY", NULL);
    }
    if (status == SM_OK) {
        status = cli_clipboard_add_env(
            envp, envp_len, &env_count, "XDG_RUNTIME_DIR", NULL);
    }
    if (status == SM_OK) {
        status = cli_clipboard_add_env(
            envp, envp_len, &env_count, "XAUTHORITY", NULL);
    }
    if (status == SM_OK) {
        status = cli_clipboard_add_env(
            envp, envp_len, &env_count, "DBUS_SESSION_BUS_ADDRESS", NULL);
    }

    return status;
}

/* Spawns a fresh helper process that clears the clipboard after the timeout,
   but only if it still holds the value we copied. The helper receives the
   expected value over stdin after exec, so it does not inherit the unlocked
   vault address space or FUIN_* password/token environment variables. */
static int cli_clipboard_schedule_clear(const unsigned char *data,
                                        size_t data_len)
{
    posix_spawn_file_actions_t actions;
    char *helper_argv[5];
    char *helper_env[CLI_CLIPBOARD_ENV_MAX];
    char len_arg[32];
    char delay_arg[32];
    int pipe_fds[2] = {-1, -1};
    int actions_ready = 0;
    int spawn_status = 0;
    int status = SM_OK;
    pid_t pid = (pid_t)0;

    if (((data == NULL) && (data_len > 0U)) ||
        (data_len > CLI_MAX_SECRET_BYTES) ||
        (g_program_path == NULL) ||
        (g_program_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (data_len == 0U) {
        return SM_OK;
    }

    if ((snprintf(len_arg, sizeof(len_arg), "%zu", data_len) < 0) ||
        (snprintf(delay_arg,
                  sizeof(delay_arg),
                  "%u",
                  (unsigned int)CLI_CLIPBOARD_CLEAR_SECONDS) < 0)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    helper_argv[0] = (char *)g_program_path;
    helper_argv[1] = (char *)CLI_CLIPBOARD_CLEAR_HELPER;
    helper_argv[2] = len_arg;
    helper_argv[3] = delay_arg;
    helper_argv[4] = NULL;

    status = cli_clipboard_build_env(helper_env,
                                     sizeof(helper_env) / sizeof(helper_env[0]));
    if (status != SM_OK) {
        cli_clipboard_free_env(helper_env);
        return status;
    }

    if (pipe(pipe_fds) != 0) {
        cli_clipboard_free_env(helper_env);
        return SM_ERR_STORAGE;
    }
    if (posix_spawn_file_actions_init(&actions) != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }
    actions_ready = 1;
    if ((posix_spawn_file_actions_adddup2(&actions,
                                          pipe_fds[0],
                                          STDIN_FILENO) != 0) ||
        (posix_spawn_file_actions_addclose(&actions, pipe_fds[0]) != 0) ||
        (posix_spawn_file_actions_addclose(&actions, pipe_fds[1]) != 0) ||
        (posix_spawn_file_actions_addopen(&actions,
                                          STDOUT_FILENO,
                                          "/dev/null",
                                          O_WRONLY,
                                          0) != 0) ||
        (posix_spawn_file_actions_addopen(&actions,
                                          STDERR_FILENO,
                                          "/dev/null",
                                          O_WRONLY,
                                          0) != 0)) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    spawn_status = posix_spawnp(&pid,
                                g_program_path,
                                &actions,
                                NULL,
                                helper_argv,
                                helper_env);
    if (spawn_status != 0) {
        status = SM_ERR_STORAGE;
        goto cleanup;
    }

    if (close(pipe_fds[0]) != 0) {
        status = SM_ERR_STORAGE;
    }
    pipe_fds[0] = -1;
    if ((status == SM_OK) &&
        (cli_write_all_ignore_sigpipe(pipe_fds[1], data, data_len) != SM_OK)) {
        status = SM_ERR_STORAGE;
    }

cleanup:
    if (pipe_fds[0] >= 0) {
        (void)close(pipe_fds[0]);
    }
    if (pipe_fds[1] >= 0) {
        (void)close(pipe_fds[1]);
    }
    if (actions_ready) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    cli_clipboard_free_env(helper_env);
    return status;
}

static int cli_copy_secret_to_clipboard(const unsigned char *data,
                                        size_t data_len)
{
    int status = vault_close();

    if (status == SM_OK) {
        status = cli_clipboard_write(data, data_len);
    }

    if (status != SM_OK) {
        return status;
    }
    if (cli_clipboard_schedule_clear(data, data_len) == SM_OK) {
        cli_ok(stderr,
               "copied to clipboard; clearing in %u seconds",
               (unsigned int)CLI_CLIPBOARD_CLEAR_SECONDS);
    } else {
        cli_ok(stderr, "copied to clipboard; auto-clear unavailable");
    }
    return SM_OK;
}

static int cli_print_hex(const unsigned char *data, size_t data_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0U;

    if (data == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    for (i = 0U; i < data_len; i++) {
        if ((fputc(hex[data[i] >> 4U], stdout) == EOF) ||
            (fputc(hex[data[i] & 0x0FU], stdout) == EOF)) {
            return SM_ERR_STORAGE;
        }
    }
    return SM_OK;
}

static int cli_decode_hex_exact(const char *hex,
                                unsigned char *output,
                                size_t output_len)
{
    size_t hex_len = 0U;
    size_t bin_len = 0U;
    const char *hex_end = NULL;

    if ((hex == NULL) || (output == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (output_len > (SIZE_MAX / 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    hex_len = strlen(hex);
    if (hex_len != (output_len * 2U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    sodium_memzero(output, output_len);
    if (sodium_hex2bin(output,
                       output_len,
                       hex,
                       hex_len,
                       NULL,
                       &bin_len,
                       &hex_end) != 0) {
        sodium_memzero(output, output_len);
        return SM_ERR_INVALID_ARGUMENT;
    }
    if ((bin_len != output_len) || (hex_end != (hex + hex_len))) {
        sodium_memzero(output, output_len);
        return SM_ERR_INVALID_ARGUMENT;
    }

    return SM_OK;
}

static int cli_decode_proof_hex(const char *hex,
                                unsigned char *proof,
                                size_t proof_capacity,
                                size_t *proof_len)
{
    size_t hex_len = 0U;
    size_t bin_len = 0U;
    const char *hex_end = NULL;

    if ((hex == NULL) || (proof == NULL) || (proof_len == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    hex_len = strlen(hex);
    if ((hex_len % (AUDIT_MERKLE_ROOT_BYTES * 2U)) != 0U ||
        (hex_len / 2U) > proof_capacity) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    *proof_len = 0U;
    sodium_memzero(proof, proof_capacity);
    if (hex_len == 0U) {
        return SM_OK;
    }
    if (sodium_hex2bin(proof,
                       proof_capacity,
                       hex,
                       hex_len,
                       NULL,
                       &bin_len,
                       &hex_end) != 0) {
        sodium_memzero(proof, proof_capacity);
        return SM_ERR_INVALID_ARGUMENT;
    }
    if ((hex_end != (hex + hex_len)) ||
        ((bin_len % AUDIT_MERKLE_ROOT_BYTES) != 0U)) {
        sodium_memzero(proof, proof_capacity);
        return SM_ERR_INVALID_ARGUMENT;
    }

    *proof_len = bin_len;
    return SM_OK;
}

static int cli_required_scope(char *scope,
                              size_t scope_len,
                              const char *operation,
                              const char *name)
{
    int written = 0;

    if ((scope == NULL) || (scope_len == 0U) ||
        (operation == NULL) || (name == NULL) || (name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    written = snprintf(scope, scope_len, "%s:%s", operation, name);
    return (written < 0) || ((size_t)written >= scope_len)
               ? SM_ERR_INVALID_ARGUMENT
               : SM_OK;
}

static int cli_authorize_token(const cli_options_t *options,
                               const char *operation,
                               const char *name)
{
    char required_scope[CLI_SCOPE_BUFFER_LEN];
    int status = SM_OK;

    sodium_memzero(required_scope, sizeof(required_scope));
    if ((options == NULL) || (options->token == NULL)) {
        return SM_OK;
    }
    if (options->token[0] == '\0') {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_required_scope(required_scope,
                                sizeof(required_scope),
                                operation,
                                name);
    if (status == SM_OK) {
        status = vault_check_token(options->token, required_scope);
    }
    sodium_memzero(required_scope, sizeof(required_scope));
    return status;
}

typedef struct {
    size_t printed;
    size_t active;
    size_t archived;
    size_t expired;
} cli_list_ctx_t;

#define CLI_LIST_NAME_WIDTH 28U
#define CLI_LIST_NAME_ELLIPSIS "..."
#define CLI_LIST_NAME_ELLIPSIS_LEN 3U
#define CLI_DISPLAY_NAME_MAX 512U

static int cli_sanitize_display_text(const char *input,
                                     char *output,
                                     size_t output_len)
{
    size_t in = 0U;
    size_t out = 0U;

    if ((input == NULL) || (output == NULL) || (output_len == 0U)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    while ((input[in] != '\0') && (out + 1U < output_len)) {
        unsigned char c = (unsigned char)input[in++];

        output[out++] = ((c < 0x20U) || (c == 0x7FU)) ? '?' : (char)c;
    }
    output[out] = '\0';
    return input[in] == '\0' ? SM_OK : SM_ERR_INPUT_TOO_LARGE;
}

static size_t cli_utf8_prefix_len(const char *text, size_t max_bytes)
{
    size_t offset = 0U;

    if (text == NULL) {
        return 0U;
    }
    while ((text[offset] != '\0') && (offset < max_bytes)) {
        unsigned char c = (unsigned char)text[offset];
        size_t char_len = 1U;

        if (c < 0x80U) {
            char_len = 1U;
        } else if ((c & 0xE0U) == 0xC0U) {
            char_len = 2U;
        } else if ((c & 0xF0U) == 0xE0U) {
            char_len = 3U;
        } else if ((c & 0xF8U) == 0xF0U) {
            char_len = 4U;
        }
        if (char_len > 1U) {
            for (size_t i = 1U; i < char_len; i++) {
                unsigned char cc = 0U;

                if ((offset + i) >= max_bytes) {
                    return offset;
                }
                cc = (unsigned char)text[offset + i];
                if ((cc == '\0') ||
                    ((cc & 0xC0U) != 0x80U)) {
                    return offset;
                }
            }
        }
        if (offset + char_len > max_bytes) {
            break;
        }
        offset += char_len;
    }
    return offset;
}

static int cli_format_list_name(const char *name, char *output, size_t output_len)
{
    char safe_name[CLI_DISPLAY_NAME_MAX];
    size_t name_len = 0U;
    size_t prefix_len = 0U;

    sodium_memzero(safe_name, sizeof(safe_name));
    if ((name == NULL) || (output == NULL) ||
        (output_len < (CLI_LIST_NAME_WIDTH + 1U))) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (cli_sanitize_display_text(name, safe_name, sizeof(safe_name)) != SM_OK) {
        return SM_ERR_STORAGE;
    }

    name_len = strlen(safe_name);
    if (name_len <= CLI_LIST_NAME_WIDTH) {
        int written = snprintf(output, output_len, "%s", safe_name);

        return ((written >= 0) && ((size_t)written < output_len))
                   ? SM_OK
                   : SM_ERR_STORAGE;
    }

    prefix_len = cli_utf8_prefix_len(
        safe_name, CLI_LIST_NAME_WIDTH - CLI_LIST_NAME_ELLIPSIS_LEN);
    if (prefix_len == 0U) {
        /* No clean UTF-8 boundary within the budget (a name whose leading
           bytes are not valid UTF-8). Fall back to a raw byte truncation so
           `list` still renders the row instead of aborting the whole listing
           on one odd name; the name was already non-UTF-8, so an imperfect
           glyph here is purely cosmetic. The name is >CLI_LIST_NAME_WIDTH
           bytes (checked above), so this many bytes are always available. */
        prefix_len = CLI_LIST_NAME_WIDTH - CLI_LIST_NAME_ELLIPSIS_LEN;
    }
    memcpy(output, safe_name, prefix_len);
    memcpy(output + prefix_len,
           CLI_LIST_NAME_ELLIPSIS,
           CLI_LIST_NAME_ELLIPSIS_LEN + 1U);
    return SM_OK;
}

static int cli_print_list_item(const vault_list_item_t *item, void *user_data)
{
    cli_list_ctx_t *ctx = user_data;
    char display_name[CLI_LIST_NAME_WIDTH + 1U];
    char expires[64];
    int color;

    if ((item == NULL) || (ctx == NULL) ||
        (item->name == NULL) || (item->algorithm == NULL) ||
        (item->created_at == NULL) || (item->updated_at == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (cli_format_list_name(item->name,
                             display_name,
                             sizeof(display_name)) != SM_OK) {
        return SM_ERR_STORAGE;
    }

    color = cli_color_enabled(stdout);

    if (ctx->printed == 0U) {
        int header_rc = color
            ? printf(CLI_SGR_DIM "%-28s %4s  %-10s  %-19s %s" CLI_SGR_RESET "\n",
                     "NAME", "VER", "STATE", "ALGORITHM", "EXPIRES")
            : printf("%-28s %4s  %-8s  %-19s %s\n",
                     "NAME", "VER", "STATE", "ALGORITHM", "EXPIRES");
        if (header_rc < 0) {
            return SM_ERR_STORAGE;
        }
    }

    if (item->is_archived) {
        ctx->archived++;
    } else {
        ctx->active++;
    }
    if (item->is_expired) {
        ctx->expired++;
    }

    if (color) {
        const char *state_word = item->is_archived ? "archived" : "active";
        const char *state_color = item->is_expired
                                      ? CLI_SGR_RED
                                      : (item->is_archived ? CLI_SGR_YELLOW
                                                           : CLI_SGR_GREEN);
        if (printf("%-28s %4d  %s" CLI_SYM_DOT CLI_SGR_RESET " %s%-8s"
                   CLI_SGR_RESET "  %-19s ",
                   display_name,
                   item->version,
                   state_color,
                   state_color,
                   state_word,
                   item->algorithm) < 0) {
            return SM_ERR_STORAGE;
        }
        if (item->expires_at == NULL) {
            if (fputs(CLI_SGR_DIM CLI_SYM_DASH CLI_SGR_RESET "\n", stdout) ==
                EOF) {
                return SM_ERR_STORAGE;
            }
        } else if (printf("%s%s\n",
                          item->expires_at,
                          item->is_expired
                              ? CLI_SGR_RED "  EXPIRED" CLI_SGR_RESET
                              : "") < 0) {
            return SM_ERR_STORAGE;
        }
        ctx->printed++;
        return SM_OK;
    }

    if (item->expires_at == NULL) {
        (void)snprintf(expires, sizeof(expires), "-");
    } else {
        (void)snprintf(expires,
                       sizeof(expires),
                       "%s%s",
                       item->expires_at,
                       item->is_expired ? "  EXPIRED" : "");
    }

    if (printf("%-28s %4d  %-8s  %-19s %s\n",
               display_name,
               item->version,
               item->is_archived ? "archived" : "active",
               item->algorithm,
               expires) < 0) {
        return SM_ERR_STORAGE;
    }

    ctx->printed++;
    return SM_OK;
}

static int cli_run_list(const cli_options_t *options)
{
    cli_list_ctx_t ctx;
    size_t matched = 0U;
    int status = SM_OK;

    if (options == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    memset(&ctx, 0, sizeof(ctx));

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_list_secrets(options->show_all,
                                    cli_print_list_item,
                                    &ctx,
                                    &matched);
    }
    if ((status == SM_OK) && (ctx.printed == 0U) && (matched == 0U)) {
        puts("no secrets");
    } else if ((status == SM_OK) && (ctx.printed > 0U) &&
               cli_color_enabled(stdout)) {
        printf(CLI_SGR_DIM "%zu shown " CLI_SYM_SEP " %zu active " CLI_SYM_SEP
               " %zu archived " CLI_SYM_SEP " %zu expired" CLI_SGR_RESET "\n",
               ctx.printed, ctx.active, ctx.archived, ctx.expired);
    }
    return status;
}

static int cli_run_init(const cli_options_t *options)
{
    int status = cli_open_unlocked_vault(options);

    if (status == SM_OK) {
        cli_ok(stdout, "vault initialized: %s", options->db_path);
        cli_heading(stdout, "next steps:");
        cli_listing_line(stdout, 32, "fuin generate <name>",
                         "store a random secret");
        cli_listing_line(stdout, 32, "fuin put <name> --stdin",
                         "store an existing value");
        cli_listing_line(stdout, 32, "fuin get <name> --copy",
                         "read it back");
    }
    return status;
}

static int cli_run_put(const cli_options_t *options)
{
    cli_secret_buffer_t stdin_secret;
    static char typed_value[4096];
    char typed_confirm[4096];
    const unsigned char *secret = NULL;
    size_t secret_len = 0U;
    int status = SM_OK;

    memset(&stdin_secret, 0, sizeof(stdin_secret));
    sodium_memzero(typed_value, sizeof(typed_value));
    sodium_memzero(typed_confirm, sizeof(typed_confirm));
    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (options->read_stdin) {
        status = cli_read_stdin_secret(&stdin_secret);
        if (status != SM_OK) {
            return status;
        }
        secret = stdin_secret.data;
        secret_len = stdin_secret.len;
    } else if (options->value != NULL) {
        secret = (const unsigned char *)options->value;
        secret_len = strlen(options->value);
    } else {
        /* Interactive: ask for the value with echo off, twice, the same
           way `pass insert` does. */
        char prompt[128];

        (void)snprintf(prompt,
                       sizeof(prompt),
                       "Value for '%s': ",
                       options->name);
        status = cli_prompt_password(prompt,
                                     typed_value,
                                     sizeof(typed_value));
        if (status == SM_OK) {
            status = cli_prompt_password("Retype to confirm: ",
                                         typed_confirm,
                                         sizeof(typed_confirm));
        }
        if ((status == SM_OK) &&
            ((strlen(typed_value) != strlen(typed_confirm)) ||
             (sodium_memcmp(typed_value,
                            typed_confirm,
                            strlen(typed_value)) != 0))) {
            status = SM_ERR_AUTH;
        }
        sodium_memzero(typed_confirm, sizeof(typed_confirm));
        if (status == SM_ERR_AUTH) {
            sodium_memzero(typed_value, sizeof(typed_value));
            cli_error("the two values do not match");
            return SM_ERR_INVALID_ARGUMENT;
        }
        if (status != SM_OK) {
            sodium_memzero(typed_value, sizeof(typed_value));
            cli_error("put needs a value: pass -v VALUE, pipe via --stdin, "
                      "or run from an interactive terminal");
            return SM_ERR_INVALID_ARGUMENT;
        }
        secret = (const unsigned char *)typed_value;
        secret_len = strlen(typed_value);
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = cli_authorize_token(options, "write", options->name);
    }
    if (status == SM_OK) {
        status = vault_put_with_options(options->name,
                                        secret,
                                        secret_len,
                                        options->algorithm,
                                        options->has_ttl
                                            ? options->ttl_seconds
                                            : 0U);
    }
    if (status == SM_OK) {
        cli_ok(stderr, "secret stored: %s", options->name);
    }

    sodium_memzero(typed_value, sizeof(typed_value));
    cli_free_secret_buffer(&stdin_secret);
    return status;
}

static int cli_run_generate(const cli_options_t *options)
{
    char password[CLI_GENERATE_MAX_LENGTH + 1U];
    size_t length = CLI_GENERATE_DEFAULT_LENGTH;
    int status = SM_OK;

    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (options->has_length) {
        if ((options->generate_length < 1) ||
            (options->generate_length > CLI_GENERATE_MAX_LENGTH)) {
            return SM_ERR_INVALID_ARGUMENT;
        }
        length = (size_t)options->generate_length;
    }

    status = utils_generate_password(password,
                                     sizeof(password),
                                     length,
                                     !options->no_symbols);
    if (status == SM_OK) {
        status = cli_open_unlocked_vault(options);
    }
    if (status == SM_OK) {
        status = cli_authorize_token(options, "write", options->name);
    }
    if (status == SM_OK) {
        status = vault_put_with_options(options->name,
                                        (const unsigned char *)password,
                                        length,
                                        options->algorithm,
                                        options->has_ttl
                                            ? options->ttl_seconds
                                            : 0U);
    }
    if (status == SM_OK) {
        if (options->copy) {
            status = cli_copy_secret_to_clipboard(
                (const unsigned char *)password, length);
        } else {
            printf("%s\n", password);
        }
    }
    if (status == SM_OK) {
        cli_ok(stderr, "secret generated and stored: %s", options->name);
    }

    sodium_memzero(password, sizeof(password));
    return status;
}

static int cli_run_get(const cli_options_t *options)
{
    cli_secret_buffer_t output;
    size_t written = 0U;
    int status = SM_OK;

    memset(&output, 0, sizeof(output));
    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_alloc_secret_buffer(&output, CLI_MAX_SECRET_BYTES);
    if (status != SM_OK) {
        return status;
    }
    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = cli_authorize_token(options, "read", options->name);
    }
    if (status == SM_OK) {
        if (options->version > 0) {
            status = vault_get_version(options->name,
                                       options->version,
                                       output.data,
                                       output.capacity,
                                       &written);
        } else {
            status = vault_get(options->name, output.data, output.capacity, &written);
        }
    }
    if (status == SM_OK) {
        if (options->copy) {
            status = cli_copy_secret_to_clipboard(output.data, written);
        } else if (fwrite(output.data, 1U, written, stdout) != written) {
            status = SM_ERR_STORAGE;
        } else if (!options->raw && (fputc('\n', stdout) == EOF)) {
            status = SM_ERR_STORAGE;
        }
    }

    cli_free_secret_buffer(&output);
    return status;
}

static int cli_run_totp(const cli_options_t *options)
{
    cli_secret_buffer_t seed_text;
    unsigned char seed[256];
    char code[16];
    size_t written = 0U;
    size_t seed_len = 0U;
    uint64_t now = 0U;
    int status = SM_OK;

    memset(&seed_text, 0, sizeof(seed_text));
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(code, sizeof(code));
    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_alloc_secret_buffer(&seed_text, CLI_MAX_SECRET_BYTES);
    if (status != SM_OK) {
        return status;
    }
    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = cli_authorize_token(options, "read", options->name);
    }
    if (status == SM_OK) {
        status = vault_get(options->name,
                           seed_text.data,
                           seed_text.capacity,
                           &written);
    }
    if (status == SM_OK) {
        status = utils_base32_decode((const char *)seed_text.data,
                                     written,
                                     seed,
                                     sizeof(seed),
                                     &seed_len);
    }
    if (status == SM_OK) {
        now = (uint64_t)time(NULL);
        status = utils_totp_code(seed,
                                 seed_len,
                                 now,
                                 30U,
                                 6,
                                 code,
                                 sizeof(code));
    }
    if (status == SM_OK) {
        if (options->copy) {
            status = cli_copy_secret_to_clipboard(
                (const unsigned char *)code, strlen(code));
        } else {
            printf("%s\n", code);
        }
    }
    if (status == SM_OK) {
        fprintf(stderr,
                "valid for %u more seconds\n",
                (unsigned int)(30U - (now % 30U)));
    }

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(code, sizeof(code));
    cli_free_secret_buffer(&seed_text);
    return status;
}

static int cli_run_delete(const cli_options_t *options)
{
    int status = SM_OK;

    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = cli_authorize_token(options, "delete", options->name);
    }
    if (status == SM_OK) {
        status = vault_delete(options->name);
    }
    if (status == SM_OK) {
        cli_ok(stderr, "secret deleted: %s", options->name);
    }
    return status;
}

static int cli_run_rollback(const cli_options_t *options)
{
    int active_version = 0;
    int status = SM_OK;

    if ((options == NULL) ||
        (options->name == NULL) ||
        (options->name[0] == '\0') ||
        (options->version < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = cli_authorize_token(options, "write", options->name);
    }
    if (status == SM_OK) {
        status = vault_rollback(options->name, options->version);
    }
    if (status == SM_OK) {
        if (vault_get_active_version(options->name, &active_version) == SM_OK) {
            cli_ok(stderr,
                   "secret rolled back: %s version %d -> %d",
                   options->name,
                   options->version,
                   active_version);
        } else {
            cli_ok(stderr,
                   "secret rolled back: %s",
                   options->name);
        }
    }
    return status;
}

static int cli_run_rotate_kek(const cli_options_t *options)
{
    int status = SM_OK;

    if ((options == NULL) ||
        (options->new_password == NULL) ||
        (options->new_password[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_rotate_kek(options->new_password);
    }
    if (status == SM_OK) {
        cli_ok(stderr, "kek rotated");
    }
    return status;
}

static int cli_print_expiry(const char *name,
                            int version,
                            const char *expires_at,
                            int is_expired,
                            void *user_data)
{
    char safe_name[CLI_DISPLAY_NAME_MAX];

    (void)user_data;

    sodium_memzero(safe_name, sizeof(safe_name));
    if ((name == NULL) || (expires_at == NULL) || (version < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if (cli_sanitize_display_text(name, safe_name, sizeof(safe_name)) != SM_OK) {
        return SM_ERR_STORAGE;
    }
    if (printf("%s name=%s version=%d expires_at=%s\n",
               is_expired ? "expired" : "expiring",
               safe_name,
               version,
               expires_at) < 0) {
        return SM_ERR_STORAGE;
    }

    return SM_OK;
}

static int cli_run_check_expiry(const cli_options_t *options)
{
    size_t matched = 0U;
    int status = SM_OK;

    if (options == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_check_expiry(options->has_within
                                        ? options->within_seconds
                                        : 0U,
                                    cli_print_expiry,
                                    NULL,
                                    &matched);
    }
    if ((status == SM_OK) && (matched == 0U)) {
        puts("no expiring secrets");
    }
    return status;
}

static int cli_run_auto_rotate(const cli_options_t *options)
{
    size_t rotated = 0U;
    int status = SM_OK;

    if (options == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_auto_rotate_expired(&rotated);
    }
    if (status == SM_OK) {
        cli_ok(stdout, "dek rotated: %zu expired secrets", rotated);
    }
    return status;
}

static int cli_run_issue_token(const cli_options_t *options)
{
    char token[ACCESS_TOKEN_BUFFER_LEN];
    const char *subject = "user:default";
    int status = SM_OK;

    sodium_memzero(token, sizeof(token));
    if ((options == NULL) ||
        (options->scope == NULL) ||
        (options->scope[0] == '\0') ||
        !options->has_ttl) {
        return SM_ERR_INVALID_ARGUMENT;
    }
    if ((options->subject != NULL) && (options->subject[0] != '\0')) {
        subject = options->subject;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_issue_token(subject,
                                   options->scope,
                                   options->ttl_seconds,
                                   token,
                                   sizeof(token));
    }
    if (status == SM_OK) {
        puts(token);
        fprintf(stderr,
                "scope: %s, expires in: %llus\n"
                "use it: FUIN_TOKEN=<token> fuin get <name> "
                "(treat the token like a password)\n",
                options->scope,
                (unsigned long long)options->ttl_seconds);
    }

    sodium_memzero(token, sizeof(token));
    return status;
}

static int cli_run_check_token(const cli_options_t *options)
{
    int status = SM_OK;

    if ((options == NULL) ||
        (options->token == NULL) ||
        (options->token[0] == '\0') ||
        (options->scope == NULL) ||
        (options->scope[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_check_token(options->token, options->scope);
    }
    if (status == SM_OK) {
        cli_ok(stdout, "token verified");
    }
    return status;
}

static int cli_run_revoke_tokens(const cli_options_t *options)
{
    int status = cli_open_unlocked_vault(options);

    if (status == SM_OK) {
        status = vault_revoke_tokens();
    }
    if (status == SM_OK) {
        cli_ok(stdout, "all previously issued tokens revoked");
    }
    return status;
}

static int cli_run_audit_verify(const cli_options_t *options)
{
    int status = cli_open_unlocked_vault(options);

    if (status == SM_OK) {
        status = vault_audit_verify();
    }
    if (status == SM_OK) {
        cli_ok(stdout, "audit log verified");
    }
    return status;
}

static int cli_run_audit_root(const cli_options_t *options)
{
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    size_t leaf_count = 0U;
    int status = SM_OK;

    sodium_memzero(root, sizeof(root));
    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_audit_merkle_root(root, sizeof(root), &leaf_count);
    }
    if (status == SM_OK) {
        printf("audit_merkle_root=");
        status = cli_print_hex(root, sizeof(root));
        if (status == SM_OK) {
            if (printf(" entries=%zu\n", leaf_count) < 0) {
                status = SM_ERR_STORAGE;
            }
        }
    }

    sodium_memzero(root, sizeof(root));
    return status;
}

static int cli_run_status_report(const cli_options_t *options)
{
    vault_security_report_t report;
    int status = SM_OK;
    int pqc_supported = 0;

    sodium_memzero(&report, sizeof(report));
    if (options == NULL) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_security_report(&report);
    }
    if (status == SM_OK) {
        cli_heading(stdout, "Secrets");
        if (cli_color_enabled(stdout)) {
            const char *exp_c =
                (report.expired_active > 0U) ? CLI_SGR_RED : CLI_SGR_BOLD;
            const char *soon_c =
                (report.expiring_7d > 0U) ? CLI_SGR_YELLOW : CLI_SGR_BOLD;
            printf("  active: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET " ("
                   CLI_SGR_BOLD "%zu" CLI_SGR_RESET " distinct names), archived "
                   "versions: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET ", deleted "
                   "names: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET "\n",
                   report.active_secrets,
                   report.distinct_names,
                   report.archived_versions,
                   report.deleted_names);
            printf("  expiry: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET " with TTL, "
                   "%s%zu" CLI_SGR_RESET " expired, %s%zu" CLI_SGR_RESET
                   " expiring within 7 days\n",
                   report.ttl_active,
                   exp_c, report.expired_active,
                   soon_c, report.expiring_7d);
            printf("  algorithms: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET
                   " AES-256-GCM, " CLI_SGR_BOLD "%zu" CLI_SGR_RESET
                   " XChaCha20-Poly1305, " CLI_SGR_BOLD "%zu" CLI_SGR_RESET
                   " AEGIS-256\n",
                   report.active_aes256gcm,
                   report.active_xchacha20poly1305,
                   report.active_aegis256);
        } else {
            printf("  active: %zu (%zu distinct names), archived versions: %zu, "
                   "deleted names: %zu\n",
                   report.active_secrets,
                   report.distinct_names,
                   report.archived_versions,
                   report.deleted_names);
            printf("  expiry: %zu with TTL, %zu expired, %zu expiring within 7 days\n",
                   report.ttl_active,
                   report.expired_active,
                   report.expiring_7d);
            printf("  algorithms: %zu AES-256-GCM, %zu XChaCha20-Poly1305, "
                   "%zu AEGIS-256\n",
                   report.active_aes256gcm,
                   report.active_xchacha20poly1305,
                   report.active_aegis256);
        }
        cli_heading(stdout, "Audit");
        if (cli_color_enabled(stdout)) {
            printf("  entries: " CLI_SGR_BOLD "%zu" CLI_SGR_RESET
                   ", chain verified: " CLI_SGR_GREEN "yes" CLI_SGR_RESET "\n",
                   report.audit_entries);
        } else {
            printf("  entries: %zu, chain verified: yes\n",
                   report.audit_entries);
        }
        printf("  merkle root: ");
        status = cli_print_hex(report.audit_root, sizeof(report.audit_root));
        if (status == SM_OK) {
            if (cli_color_enabled(stdout)) {
                printf(" (" CLI_SGR_BOLD "%zu" CLI_SGR_RESET
                       " leaves; store it outside the vault)\n",
                       report.audit_leaf_count);
            } else {
                printf(" (%zu leaves; store it outside the vault)\n",
                       report.audit_leaf_count);
            }
        }
        pqc_supported = backup_pqc_available();
        if (status == SM_OK) {
            cli_heading(stdout, "Post-quantum");
            printf("  %s\n",
                   pqc_supported
                       ? "X25519+ML-KEM-768 backup capsules supported; "
                         "symmetric-256 core encryption"
                       : "symmetric-256 crypto-agile; X25519+ML-KEM-768 "
                         "unavailable in the linked libcrypto");
        }
        if ((status == SM_OK) &&
            (((report.active_secrets > 1000U) &&
              (report.active_aes256gcm > 0U)) ||
             (report.expired_active > 0U))) {
            cli_heading(stdout, "Recommendations");
            if ((report.active_secrets > 1000U) &&
                (report.active_aes256gcm > 0U)) {
                printf("  - prefer XChaCha20-Poly1305 or AEGIS-256 for large "
                       "vaults (AES-GCM nonce prefix scale limit)\n");
            }
            if (report.expired_active > 0U) {
                if (cli_color_enabled(stdout)) {
                    printf("  - run auto-rotate: " CLI_SGR_RED "%zu"
                           CLI_SGR_RESET " active secrets have expired\n",
                           report.expired_active);
                } else {
                    printf("  - run auto-rotate: %zu active secrets have "
                           "expired\n",
                           report.expired_active);
                }
            }
        }
    }

    sodium_memzero(&report, sizeof(report));
    return status;
}

static int cli_run_pqc_keygen(const cli_options_t *options)
{
    char key_passphrase[CLI_PASSWORD_MAX];
    int status = SM_OK;

    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    if ((options == NULL) ||
        (options->public_out_path == NULL) ||
        (options->public_out_path[0] == '\0') ||
        (options->private_out_path == NULL) ||
        (options->private_out_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_load_key_passphrase(options,
                                     1,
                                     key_passphrase,
                                     sizeof(key_passphrase));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_backup_keygen(options->public_out_path,
                                 options->private_out_path,
                                 key_passphrase);
    if (status == SM_OK) {
        printf("hybrid backup keypair generated: public=%s private=%s\n",
               options->public_out_path,
               options->private_out_path);
    }

cleanup:
    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    return status;
}

static int cli_run_backup_export(const cli_options_t *options)
{
    int status = SM_OK;

    if ((options == NULL) ||
        (options->recipient_path == NULL) ||
        (options->recipient_path[0] == '\0') ||
        (options->output_path == NULL) ||
        (options->output_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_backup_export(options->recipient_path,
                                     options->output_path);
    }
    if (status == SM_OK) {
        printf("backup capsule exported: %s\n", options->output_path);
    }
    return status;
}

static int cli_run_backup_import(const cli_options_t *options)
{
    char key_passphrase[CLI_PASSWORD_MAX];
    int status = SM_OK;

    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    if ((options == NULL) ||
        (options->private_key_path == NULL) ||
        (options->private_key_path[0] == '\0') ||
        (options->input_path == NULL) ||
        (options->input_path[0] == '\0') ||
        (options->output_path == NULL) ||
        (options->output_path[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_load_key_passphrase(options,
                                     0,
                                     key_passphrase,
                                     sizeof(key_passphrase));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_backup_import(options->private_key_path,
                                 key_passphrase,
                                 options->input_path,
                                 options->output_path);
    if (status == SM_OK) {
        printf("backup capsule imported: %s\n", options->output_path);
    }

cleanup:
    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    return status;
}

static int cli_run_audit_proof(const cli_options_t *options)
{
    unsigned char entry_hash[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    size_t proof_len = 0U;
    size_t leaf_index = 0U;
    size_t leaf_count = 0U;
    int status = SM_OK;

    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    if ((options == NULL) || (options->entry_id < 1)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_audit_merkle_proof(options->entry_id,
                                          entry_hash,
                                          sizeof(entry_hash),
                                          root,
                                          sizeof(root),
                                          proof,
                                          sizeof(proof),
                                          &proof_len,
                                          &leaf_index,
                                          &leaf_count);
    }
    if (status == SM_OK) {
        if (printf("audit_entry_id=%d leaf_index=%zu entries=%zu\n",
                   options->entry_id,
                   leaf_index,
                   leaf_count) < 0) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        printf("entry_hash=");
        status = cli_print_hex(entry_hash, sizeof(entry_hash));
        if ((status == SM_OK) && (fputc('\n', stdout) == EOF)) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        printf("audit_merkle_root=");
        status = cli_print_hex(root, sizeof(root));
        if ((status == SM_OK) && (fputc('\n', stdout) == EOF)) {
            status = SM_ERR_STORAGE;
        }
    }
    if (status == SM_OK) {
        printf("proof=");
        status = cli_print_hex(proof, proof_len);
        if ((status == SM_OK) && (fputc('\n', stdout) == EOF)) {
            status = SM_ERR_STORAGE;
        }
    }

    sodium_memzero(entry_hash, sizeof(entry_hash));
    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    return status;
}

static int cli_run_audit_keygen(const cli_options_t *options)
{
    char key_passphrase[CLI_PASSWORD_MAX];
    int status = SM_OK;

    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    if ((options == NULL) ||
        (options->public_out_path == NULL) ||
        (options->private_out_path == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (!backup_mldsa_available()) {
        cli_error("ML-DSA-65 unavailable (OpenSSL >= 3.5 required)");
        return SM_ERR_CRYPTO;
    }

    status = cli_load_key_passphrase(options,
                                     1,
                                     key_passphrase,
                                     sizeof(key_passphrase));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = vault_audit_signing_keygen(options->public_out_path,
                                        options->private_out_path,
                                        key_passphrase);
    if (status == SM_OK) {
        printf("audit signing keypair written: %s %s\n",
               options->public_out_path,
               options->private_out_path);
    }

cleanup:
    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    return status;
}

static int cli_run_audit_sign_root(const cli_options_t *options)
{
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char signature[BACKUP_MLDSA_SIGNATURE_MAX_BYTES];
    char signature_b64[(BACKUP_MLDSA_SIGNATURE_MAX_BYTES * 2U)];
    char key_passphrase[CLI_PASSWORD_MAX];
    size_t leaf_count = 0U;
    size_t signature_len = 0U;
    size_t b64_len = 0U;
    int status = SM_OK;

    sodium_memzero(root, sizeof(root));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(signature_b64, sizeof(signature_b64));
    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    if ((options == NULL) || (options->private_key_path == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_load_key_passphrase(options,
                                     0,
                                     key_passphrase,
                                     sizeof(key_passphrase));
    if (status != SM_OK) {
        goto cleanup;
    }
    status = cli_open_unlocked_vault(options);
    if (status == SM_OK) {
        status = vault_audit_sign_root(options->private_key_path,
                                       key_passphrase,
                                       root,
                                       sizeof(root),
                                       &leaf_count,
                                       signature,
                                       sizeof(signature),
                                       &signature_len);
    }
    if (status == SM_OK) {
        status = utils_base64_encode(signature,
                                     signature_len,
                                     signature_b64,
                                     sizeof(signature_b64),
                                     &b64_len);
    }
    if (status == SM_OK) {
        fputs("audit merkle root: ", stdout);
        status = cli_print_hex(root, sizeof(root));
    }
    if (status == SM_OK) {
        printf("\nentries: %zu\n", leaf_count);
        printf("algorithm: %s\n", BACKUP_MLDSA_ALGORITHM);
        printf("signature: %s\n", signature_b64);
        puts("store the root and signature outside the vault");
    }

cleanup:
    sodium_memzero(root, sizeof(root));
    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(signature_b64, sizeof(signature_b64));
    sodium_memzero(key_passphrase, sizeof(key_passphrase));
    return status;
}

static int cli_run_audit_verify_root_sig(const cli_options_t *options)
{
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char message[AUDIT_MERKLE_ROOT_BYTES + 8U];
    unsigned char signature[BACKUP_MLDSA_SIGNATURE_MAX_BYTES];
    size_t signature_len = 0U;
    int status = SM_OK;

    sodium_memzero(root, sizeof(root));
    sodium_memzero(message, sizeof(message));
    sodium_memzero(signature, sizeof(signature));
    if ((options == NULL) ||
        (options->public_key_path == NULL) ||
        (options->root_hex == NULL) ||
        !options->has_leaf_count ||
        (options->signature_b64 == NULL)) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_decode_hex_exact(options->root_hex, root, sizeof(root));
    if (status == SM_OK) {
        status = utils_base64_decode(options->signature_b64,
                                     signature,
                                     sizeof(signature),
                                     &signature_len);
    }
    if (status == SM_OK) {
        memcpy(message, root, AUDIT_MERKLE_ROOT_BYTES);
        utils_write_u64_le(message + AUDIT_MERKLE_ROOT_BYTES,
                           (uint64_t)options->leaf_count);
        status = backup_mldsa_verify(options->public_key_path,
                                     message,
                                     sizeof(message),
                                     signature,
                                     signature_len);
    }
    if (status == SM_OK) {
        cli_ok(stdout, "audit root signature verified");
    }

    sodium_memzero(root, sizeof(root));
    sodium_memzero(message, sizeof(message));
    sodium_memzero(signature, sizeof(signature));
    return status;
}

static int cli_run_audit_verify_proof(const cli_options_t *options)
{
    unsigned char root[AUDIT_MERKLE_ROOT_BYTES];
    unsigned char proof[AUDIT_MERKLE_PROOF_MAX_BYTES];
    size_t proof_len = 0U;
    int status = SM_OK;

    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    if ((options == NULL) || (options->entry_id < 1) ||
        (options->root_hex == NULL) || (options->proof_hex == NULL) ||
        !options->has_leaf_index || !options->has_leaf_count) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    status = cli_decode_hex_exact(options->root_hex, root, sizeof(root));
    if (status == SM_OK) {
        status = cli_decode_proof_hex(options->proof_hex,
                                      proof,
                                      sizeof(proof),
                                      &proof_len);
    }
    if (status == SM_OK) {
        status = cli_open_unlocked_vault(options);
    }
    if (status == SM_OK) {
        status = vault_audit_verify_merkle_proof(options->entry_id,
                                                 root,
                                                 sizeof(root),
                                                 proof,
                                                 proof_len,
                                                 options->leaf_index,
                                                 options->leaf_count);
    }
    if (status == SM_OK) {
        cli_ok(stdout, "audit proof verified");
    }

    sodium_memzero(root, sizeof(root));
    sodium_memzero(proof, sizeof(proof));
    return status;
}

static int cli_dispatch(const cli_options_t *options)
{
    if ((options == NULL) ||
        (options->command == NULL) ||
        (options->command[0] == '\0')) {
        return SM_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(options->command, "init") == 0) {
        return cli_run_init(options);
    }
    if ((strcmp(options->command, "put") == 0) ||
        (strcmp(options->command, "set") == 0)) {
        return cli_run_put(options);
    }
    if ((strcmp(options->command, "generate") == 0) ||
        (strcmp(options->command, "gen") == 0)) {
        return cli_run_generate(options);
    }
    if (strcmp(options->command, "get") == 0) {
        return cli_run_get(options);
    }
    if (strcmp(options->command, "totp") == 0) {
        return cli_run_totp(options);
    }
    if ((strcmp(options->command, "list") == 0) ||
        (strcmp(options->command, "ls") == 0)) {
        return cli_run_list(options);
    }
    if ((strcmp(options->command, "delete") == 0) ||
        (strcmp(options->command, "del") == 0)) {
        return cli_run_delete(options);
    }
    if (strcmp(options->command, "rollback") == 0) {
        return cli_run_rollback(options);
    }
    if ((strcmp(options->command, "rotate-kek") == 0) ||
        (strcmp(options->command, "rotate") == 0)) {
        return cli_run_rotate_kek(options);
    }
    if (strcmp(options->command, "check-expiry") == 0) {
        return cli_run_check_expiry(options);
    }
    if ((strcmp(options->command, "auto-rotate") == 0) ||
        (strcmp(options->command, "rotate-dek") == 0)) {
        return cli_run_auto_rotate(options);
    }
    if (strcmp(options->command, "issue-token") == 0) {
        return cli_run_issue_token(options);
    }
    if (strcmp(options->command, "check-token") == 0) {
        return cli_run_check_token(options);
    }
    if (strcmp(options->command, "revoke-tokens") == 0) {
        return cli_run_revoke_tokens(options);
    }
    if ((strcmp(options->command, "audit-verify") == 0) ||
        (strcmp(options->command, "verify") == 0)) {
        return cli_run_audit_verify(options);
    }
    if ((strcmp(options->command, "audit-root") == 0) ||
        (strcmp(options->command, "merkle-root") == 0)) {
        return cli_run_audit_root(options);
    }
    if (strcmp(options->command, "audit-proof") == 0) {
        return cli_run_audit_proof(options);
    }
    if (strcmp(options->command, "audit-verify-proof") == 0) {
        return cli_run_audit_verify_proof(options);
    }
    if (strcmp(options->command, "audit-keygen") == 0) {
        return cli_run_audit_keygen(options);
    }
    if (strcmp(options->command, "audit-sign-root") == 0) {
        return cli_run_audit_sign_root(options);
    }
    if (strcmp(options->command, "audit-verify-root-sig") == 0) {
        return cli_run_audit_verify_root_sig(options);
    }
    if ((strcmp(options->command, "status-report") == 0) ||
        (strcmp(options->command, "security-report") == 0) ||
        (strcmp(options->command, "report") == 0)) {
        return cli_run_status_report(options);
    }
    if (strcmp(options->command, "pqc-keygen") == 0) {
        return cli_run_pqc_keygen(options);
    }
    if (strcmp(options->command, "backup-export") == 0) {
        return cli_run_backup_export(options);
    }
    if (strcmp(options->command, "backup-import") == 0) {
        return cli_run_backup_import(options);
    }

    return SM_ERR_INVALID_ARGUMENT;
}

static void cli_clear_sensitive(cli_options_t *options)
{
    if (options->password != NULL) {
        sodium_memzero((void *)options->password, strlen(options->password));
        options->password = NULL;
    }
    if (options->new_password != NULL) {
        sodium_memzero((void *)options->new_password,
                       strlen(options->new_password));
        options->new_password = NULL;
    }
    if (options->token != NULL) {
        sodium_memzero((void *)options->token, strlen(options->token));
        options->token = NULL;
    }
}

int main(int argc, char **argv)
{
    static char prompted_password[CLI_PASSWORD_MAX];
    static char prompted_new_password[CLI_PASSWORD_MAX];
    cli_options_t options;
    int status = SM_OK;
    int prompt_status = SM_OK;
    int close_status = SM_OK;

    if (sodium_init() < 0) {
        cli_error("libsodium initialization failed");
        return 1;
    }
    if ((argv != NULL) && (argv[0] != NULL)) {
        g_program_path = argv[0];
    }
    if ((argc > 1) && (argv != NULL) && (argv[1] != NULL) &&
        (strcmp(argv[1], CLI_CLIPBOARD_CLEAR_HELPER) == 0)) {
        status = cli_clipboard_clear_helper(argc, argv);
        return status == SM_OK ? 0 : 1;
    }

    status = cli_parse_options(argc, argv, &options);
    if (status != SM_OK) {
        cli_print_usage(stderr);
        cli_clear_sensitive(&options);
        return 2;
    }
    if (options.help) {
        cli_print_usage(stdout);
        cli_clear_sensitive(&options);
        return 0;
    }
    if (options.command == NULL) {
        cli_print_intro(stdout);
        cli_clear_sensitive(&options);
        return 0;
    }

    if ((options.password == NULL) &&
        cli_command_needs_master_password(options.command)) {
        if ((strcmp(options.command, "init") == 0) &&
            (access(options.db_path, F_OK) != 0)) {
            prompt_status = cli_prompt_password_confirmed(
                "Master password: ",
                "Confirm master password: ",
                prompted_password,
                sizeof(prompted_password));
        } else {
            prompt_status = cli_prompt_password("Master password: ",
                                                prompted_password,
                                                sizeof(prompted_password));
        }
        if (prompt_status == SM_OK) {
            options.password = prompted_password;
        } else if (prompt_status == SM_ERR_AUTH) {
            cli_error("passwords do not match");
            cli_clear_sensitive(&options);
            return 1;
        }
        /* Other prompt failures (no terminal) keep password NULL so the
           existing missing-password error path reports it. */
    }
    if ((options.new_password == NULL) &&
        ((strcmp(options.command, "rotate-kek") == 0) ||
         (strcmp(options.command, "rotate") == 0))) {
        prompt_status = cli_prompt_password_confirmed(
            "New master password: ",
            "Confirm new master password: ",
            prompted_new_password,
            sizeof(prompted_new_password));
        if (prompt_status == SM_OK) {
            options.new_password = prompted_new_password;
        } else if (prompt_status == SM_ERR_AUTH) {
            cli_error("passwords do not match");
            cli_clear_sensitive(&options);
            return 1;
        }
    }

    g_cli_open_error_reported = 0;
    status = cli_dispatch(&options);
    close_status = vault_close();
    if ((status == SM_OK) && (close_status != SM_OK)) {
        status = close_status;
    }

    cli_clear_sensitive(&options);

    if (status != SM_OK) {
        if (g_cli_open_error_reported) {
            /* cli_open_unlocked_vault already printed a complete explanation
               (missing / uninitialised / unopenable database); stay silent. */
        } else if (status == SM_ERR_NOT_FOUND) {
            if (((strcmp(options.command, "audit-proof") == 0) ||
                 (strcmp(options.command, "audit-verify-proof") == 0)) &&
                (options.entry_id > 0) &&
                (access(options.db_path, F_OK) == 0)) {
                cli_error("audit entry %d not found", options.entry_id);
            } else if ((options.name != NULL) &&
                (access(options.db_path, F_OK) == 0)) {
                if (options.version > 0) {
                    cli_error("version %d of '%s' not found",
                              options.version,
                              options.name);
                } else if (cli_color_enabled(stderr)) {
                    cli_error("secret '%s' not found", options.name);
                    cli_hint(stderr, "run 'fuin list' to see stored names");
                } else {
                    fprintf(stderr,
                            "fuin: secret '%s' not found "
                            "(see stored names with: fuin list)\n",
                            options.name);
                }
            }
        } else if (status == SM_ERR_AUTH) {
            cli_error("authentication failed (wrong master password, "
                      "or the token lacks the required scope)");
        } else if (status == SM_ERR_INPUT_TOO_LARGE) {
            cli_error("stdin secret is too large (max %u bytes)",
                      (unsigned int)CLI_MAX_SECRET_BYTES);
        } else {
            cli_error("%s", utils_status_message(status));
        }
        return 1;
    }

    return 0;
}
