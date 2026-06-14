CC := gcc
PKG_CONFIG ?= pkg-config
VALGRIND ?= valgrind
VALGRIND_IMAGE ?= secrets-manager-valgrind
CI_LINUX_IMAGE ?= secrets-manager-ci-linux
FUZZ_CC ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang) clang)
FUZZ_SYMBOLIZER ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/llvm-symbolizer /usr/local/opt/llvm/bin/llvm-symbolizer) llvm-symbolizer)
FUZZ_MAX_TOTAL_TIME ?= 60
FUZZ_MAX_LEN ?= 512
FUZZ_COMMON_ARGS ?= -max_total_time=$(FUZZ_MAX_TOTAL_TIME) -max_len=$(FUZZ_MAX_LEN) -print_final_stats=1 -verbosity=0
OPENSSL_MIN_VERSION ?= 3.6.3

BUILD_DIR ?= build
PREFIX ?= /usr/local
INSTALL_NAME ?= fuin
TARGET := fuin
SCHEMA_HEADER := include/schema_embedded.h
TEST_TARGET := test_runner
BENCH_ROTATION_TARGET := bench_rotation
BENCH_COMPREHENSIVE_TARGET := bench_comprehensive
BENCH_TARGETS := $(BENCH_ROTATION_TARGET) $(BENCH_COMPREHENSIVE_TARGET)
FUZZ_AUDIT_TARGET := fuzz_audit
FUZZ_CLI_PARSE_TARGET := fuzz_cli_parse
FUZZ_VAULT_INPUT_TARGET := fuzz_vault_input
FUZZ_TARGETS := $(FUZZ_AUDIT_TARGET) $(FUZZ_CLI_PARSE_TARGET) $(FUZZ_VAULT_INPUT_TARGET)

APP_SRC := $(wildcard src/*.c)
LIB_SRC := $(filter-out src/main.c,$(APP_SRC))
THIRD_PARTY_SRC := third_party/cJSON.c
TEST_SRC := $(wildcard tests/*.c)
BENCH_ROTATION_SRC := benchmark/bench_rotation.c
BENCH_COMPREHENSIVE_SRC := benchmark/bench_comprehensive.c
FUZZ_AUDIT_SRC := fuzz/fuzz_audit.c
FUZZ_CLI_PARSE_SRC := fuzz/fuzz_cli_parse.c
FUZZ_VAULT_INPUT_SRC := fuzz/fuzz_vault_input.c

APP_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(APP_SRC) $(THIRD_PARTY_SRC))
TEST_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(LIB_SRC) $(THIRD_PARTY_SRC) $(TEST_SRC))
BENCH_ROTATION_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(LIB_SRC) $(THIRD_PARTY_SRC) $(BENCH_ROTATION_SRC))
BENCH_COMPREHENSIVE_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(LIB_SRC) $(THIRD_PARTY_SRC) $(BENCH_COMPREHENSIVE_SRC))

HAVE_PKG_CONFIG := $(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(HAVE_PKG_CONFIG),yes)
DEP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libsodium sqlite3 libcrypto)
DEP_LDLIBS := $(shell $(PKG_CONFIG) --libs libsodium sqlite3 libcrypto)
else
SQLITE_PREFIX := $(firstword $(wildcard /opt/homebrew/opt/sqlite3 /usr/local/opt/sqlite3))
SODIUM_PREFIX := $(firstword $(wildcard /opt/homebrew/opt/libsodium /usr/local/opt/libsodium))
OPENSSL_PREFIX := $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3 /opt/homebrew/opt/openssl /usr/local/opt/openssl))
ifneq ($(SQLITE_PREFIX),)
DEP_CFLAGS += -I$(SQLITE_PREFIX)/include
DEP_LDLIBS += -L$(SQLITE_PREFIX)/lib -lsqlite3
else
DEP_LDLIBS += -lsqlite3
endif
ifneq ($(SODIUM_PREFIX),)
DEP_CFLAGS += -I$(SODIUM_PREFIX)/include
DEP_LDLIBS += -L$(SODIUM_PREFIX)/lib -lsodium
endif
ifneq ($(OPENSSL_PREFIX),)
DEP_CFLAGS += -I$(OPENSSL_PREFIX)/include
DEP_LDLIBS += -L$(OPENSSL_PREFIX)/lib -lcrypto
else
DEP_LDLIBS += -lcrypto
endif
endif

BASE_CFLAGS := -std=c11 -Wall -Wextra -Werror -Iinclude -Ithird_party $(DEP_CFLAGS)
OPT_CFLAGS ?= -O2
CFLAGS_ALL := $(BASE_CFLAGS) $(OPT_CFLAGS) $(CFLAGS_EXTRA)
LDLIBS_ALL := $(DEP_LDLIBS) $(LDLIBS_EXTRA)
FUZZ_CFLAGS := $(BASE_CFLAGS) -O1 -g -fsanitize=address,fuzzer -fno-omit-frame-pointer
FUZZ_LDLIBS := $(DEP_LDLIBS) -fsanitize=address,fuzzer

.PHONY: all check-deps test test-asan test-leaks test-valgrind test-valgrind-docker ci-linux ci-linux-smoke bench fuzz fuzz-audit fuzz-cli-parse fuzz-vault-input demo demo-tamper coverage clean install uninstall

all: check-deps $(TARGET)

check-deps:
ifeq ($(HAVE_PKG_CONFIG),yes)
	@$(PKG_CONFIG) --atleast-version=$(OPENSSL_MIN_VERSION) libcrypto || { \
	  echo "warning: libcrypto >= $(OPENSSL_MIN_VERSION) is recommended for supported OpenSSL security fixes" >&2; \
	  echo "         found $$($(PKG_CONFIG) --modversion libcrypto 2>/dev/null || echo unknown); building anyway (set OPENSSL_MIN_VERSION to change the threshold)" >&2; \
	}
else
	@echo "pkg-config is required to verify libcrypto >= $(OPENSSL_MIN_VERSION)"
	@exit 1
endif

# Embed sql/schema.sql at build time so the binary works from any
# working directory (single source of truth; no drift, no file lookup).
$(SCHEMA_HEADER): sql/schema.sql
	{ printf 'static const char STORAGE_EMBEDDED_SCHEMA[] =\n'; \
	  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$$/\\n"/' sql/schema.sql; \
	  printf ';\n'; } > $@

$(BUILD_DIR)/src/storage.o: $(SCHEMA_HEADER)

$(TARGET): $(APP_OBJ) | check-deps
	$(CC) -o $@ $^ $(LDLIBS_ALL)

$(TEST_TARGET): $(TEST_OBJ) | check-deps
	$(CC) -o $@ $^ $(LDLIBS_ALL)

$(BENCH_ROTATION_TARGET): $(BENCH_ROTATION_OBJ) | check-deps
	$(CC) -o $@ $^ $(LDLIBS_ALL)

$(BENCH_COMPREHENSIVE_TARGET): $(BENCH_COMPREHENSIVE_OBJ) | check-deps
	$(CC) -o $@ $^ $(LDLIBS_ALL)

$(FUZZ_AUDIT_TARGET): $(LIB_SRC) $(THIRD_PARTY_SRC) $(FUZZ_AUDIT_SRC) | $(SCHEMA_HEADER) check-deps
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDLIBS)

$(FUZZ_CLI_PARSE_TARGET): $(LIB_SRC) $(THIRD_PARTY_SRC) $(FUZZ_CLI_PARSE_SRC) src/main.c | $(SCHEMA_HEADER) check-deps
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(LIB_SRC) $(THIRD_PARTY_SRC) $(FUZZ_CLI_PARSE_SRC) -o $@ $(FUZZ_LDLIBS)

$(FUZZ_VAULT_INPUT_TARGET): $(LIB_SRC) $(THIRD_PARTY_SRC) $(FUZZ_VAULT_INPUT_SRC) | $(SCHEMA_HEADER) check-deps
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDLIBS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_ALL) -MMD -MP -c $< -o $@

test: check-deps $(TEST_TARGET)
	@mkdir -p results
	./$(TEST_TARGET)

test-asan:
	$(MAKE) BUILD_DIR=build/asan OPT_CFLAGS=-O1 CFLAGS_EXTRA="-fsanitize=address -fno-omit-frame-pointer -g" LDLIBS_EXTRA="-fsanitize=address" test

test-valgrind: $(TEST_TARGET)
	@mkdir -p results
	@command -v $(VALGRIND) >/dev/null 2>&1 || { echo "$(VALGRIND) not found"; exit 127; }
	$(VALGRIND) --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 --track-origins=yes --log-file=results/valgrind.log ./$(TEST_TARGET)

test-valgrind-docker:
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 127; }
	docker build -f Dockerfile.valgrind -t $(VALGRIND_IMAGE) .
	docker run --rm $(VALGRIND_IMAGE)

# Reproduce the GitHub Actions ubuntu-latest job locally (see Dockerfile.ci).
# Catches glibc-only build errors (feature-test macros, stricter -Werror)
# that the macOS __APPLE__ build path cannot surface.
ci-linux:
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 127; }
	docker build -f Dockerfile.ci -t $(CI_LINUX_IMAGE) .
	docker run --rm --cap-add=SYS_PTRACE $(CI_LINUX_IMAGE) sh -c 'make clean && make && make test && make test-asan && make coverage'

# End-to-end CLI smoke on Linux/glibc (tests/cli_smoke.sh): the default
# XChaCha20 path, --algorithm fallback, PQC/ML-DSA availability, and
# O_NOFOLLOW file-security. Availability gaps vs the x86_64/OpenSSL-3.0 CI
# runner are reported, not failed.
ci-linux-smoke:
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 127; }
	docker build -f Dockerfile.ci -t $(CI_LINUX_IMAGE) .
	docker run --rm $(CI_LINUX_IMAGE) sh -c 'make >/dev/null && sh tests/cli_smoke.sh'

test-leaks: $(TEST_TARGET)
	@mkdir -p results
	@command -v leaks >/dev/null 2>&1 || { echo "leaks not found"; exit 127; }
	leaks --atExit -- ./$(TEST_TARGET) > results/leaks.log 2>&1
	@grep -q "0 leaks for 0 total leaked bytes" results/leaks.log

bench: check-deps $(BENCH_TARGETS)

fuzz: check-deps fuzz-audit fuzz-cli-parse fuzz-vault-input

fuzz-audit: $(FUZZ_AUDIT_TARGET)
	@mkdir -p results/fuzz
	ASAN_SYMBOLIZER_PATH=$(FUZZ_SYMBOLIZER) ./$(FUZZ_AUDIT_TARGET) $(FUZZ_COMMON_ARGS) -artifact_prefix=results/fuzz/audit-

fuzz-cli-parse: $(FUZZ_CLI_PARSE_TARGET)
	@mkdir -p results/fuzz
	ASAN_SYMBOLIZER_PATH=$(FUZZ_SYMBOLIZER) ./$(FUZZ_CLI_PARSE_TARGET) $(FUZZ_COMMON_ARGS) -artifact_prefix=results/fuzz/cli-parse-

fuzz-vault-input: $(FUZZ_VAULT_INPUT_TARGET)
	@mkdir -p results/fuzz
	ASAN_SYMBOLIZER_PATH=$(FUZZ_SYMBOLIZER) ./$(FUZZ_VAULT_INPUT_TARGET) $(FUZZ_COMMON_ARGS) -artifact_prefix=results/fuzz/vault-input-

demo: check-deps $(TARGET)
	./demo/demo.sh

demo-tamper: check-deps $(TARGET)
	./demo/demo_tamper.sh

coverage: check-deps
	$(MAKE) BUILD_DIR=build/coverage OPT_CFLAGS=-O0 CFLAGS_EXTRA="-fprofile-arcs -ftest-coverage -g" LDLIBS_EXTRA="-fprofile-arcs -ftest-coverage" test
	@mkdir -p results/coverage
	gcov -o build/coverage/src $(LIB_SRC) > results/coverage/gcov.txt

install: check-deps $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(INSTALL_NAME)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(INSTALL_NAME)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(TEST_TARGET) $(BENCH_TARGETS) $(FUZZ_TARGETS) $(addsuffix .dSYM,$(FUZZ_TARGETS)) $(SCHEMA_HEADER) *.gcov coverage.info coverage_report results/coverage results/fuzz results/*.db results/*.db-shm results/*.db-wal

-include $(APP_OBJ:.o=.d)
-include $(BENCH_COMPREHENSIVE_OBJ:.o=.d)
-include $(TEST_OBJ:.o=.d)
-include $(BENCH_ROTATION_OBJ:.o=.d)
