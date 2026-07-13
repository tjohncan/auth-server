# Database backend selection (sqlite or postgresql)
# Override with: make DB_BACKEND=postgresql
DB_BACKEND ?= sqlite

# Email support (0 or 1)
# Override with: make EMAIL_SUPPORT=1
EMAIL_SUPPORT ?= 0

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -Iinclude
LDFLAGS = -lpthread -lm -ldl -largon2 -lssl -lcrypto

# Configure database backend
ifeq ($(DB_BACKEND),sqlite)
    CFLAGS += -Ivendor/sqlite -DDB_BACKEND_SQLITE
    DB_VENDOR_SRCS = vendor/sqlite/sqlite3.c
    ifeq ($(wildcard vendor/sqlite/sqlite3.c),)
        # The fuzz targets compile only the parser and its two utils — no database.
        # Exempt them so a fresh clone can fuzz before vendoring the amalgamation.
        ifeq ($(filter clean fuzz fuzz-regress,$(MAKECMDGOALS)),)
            $(error SQLite amalgamation not found at vendor/sqlite/sqlite3.c — see vendor/setup_notes.txt)
        endif
    endif
else ifeq ($(DB_BACKEND),postgresql)
    CFLAGS += -DDB_BACKEND_POSTGRESQL -I$(shell pg_config --includedir)
    LDFLAGS += -lpq
    DB_VENDOR_SRCS =
else
    $(error Invalid DB_BACKEND: $(DB_BACKEND). Must be 'sqlite' or 'postgresql')
endif

# Configure email support
ifeq ($(EMAIL_SUPPORT),1)
    CFLAGS += -DEMAIL_SUPPORT
endif

# Security hardening flags (enabled by default)
# - fstack-protector-strong: Stack buffer overflow protection
# - D_FORTIFY_SOURCE=2: Buffer overflow detection in libc (requires -O1+)
# - fPIE: Position-independent executable for ASLR
# - Wformat-security: Warn about dangerous format strings
SECURITY_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wformat -Wformat-security
SECURITY_LDFLAGS = -pie -Wl,-z,relro,-z,now

# Debug flags (use with: make debug)
DEBUG_FLAGS = -g -O0 -DDEBUG
RELEASE_FLAGS = -O2 -DNDEBUG

# Source files (organized by subdirectory)
SERVER_SRCS = src/server/event_loop.c src/server/http.c src/server/router.c
UTIL_SRCS = src/util/log.c src/util/str.c src/util/config.c src/util/data.c src/util/validation.c src/util/json.c src/util/template.c
ifeq ($(EMAIL_SUPPORT),1)
    UTIL_SRCS += src/util/email.c
endif
HANDLER_SRCS = src/handlers/common.c src/handlers/health.c src/handlers/admin.c src/handlers/admin_http.c \
               src/handlers/admin_org_http.c src/handlers/session.c src/handlers/session_http.c \
               src/handlers/oauth.c src/handlers/oauth_http.c src/handlers/static.c \
               src/handlers/mfa.c src/handlers/mfa_http.c \
               src/handlers/rs.c src/handlers/rs_http.c
DB_SRCS = src/db/db.c src/db/db_pool.c src/db/cleaner.c src/db/init/db_init.c src/db/init/db_history.c \
          src/db/queries/org.c src/db/queries/user.c src/db/queries/client.c src/db/queries/resource_server.c src/db/queries/oauth.c \
          src/db/queries/mfa.c
CRYPTO_SRCS = src/crypto/random.c src/crypto/argon2.c src/crypto/pbkdf2.c src/crypto/password.c src/crypto/hmac.c src/crypto/sha256.c src/crypto/jwt.c src/crypto/signing_keys.c src/crypto/totp.c src/crypto/encrypt.c

SRCS = src/main.c $(SERVER_SRCS) $(UTIL_SRCS) $(HANDLER_SRCS) $(DB_SRCS) $(CRYPTO_SRCS) $(DB_VENDOR_SRCS)
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = auth-server

# Default target - builds the server
all: $(TARGET)

# Link object files into executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "Build complete! Run with: ./$(TARGET)"

# Compile .c files into .o files
%.o: %.c
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) -c $< -o $@

# Debug build (security flags applied except _FORTIFY_SOURCE which requires -O1+)
debug: CFLAGS += $(DEBUG_FLAGS)
debug: SECURITY_FLAGS = -fstack-protector-strong -fPIE -Wformat -Wformat-security
debug: clean $(TARGET)

# Release build (full security hardening)
release: CFLAGS += $(RELEASE_FLAGS)
release: clean $(TARGET)

# Clean build artifacts
clean:
	rm -f src/*.o src/**/*.o src/**/**/*.o vendor/**/*.o $(TARGET) test-str test-http test-router test-db test-crypto test-email
	rm -rf fuzz-replay fuzz-replay-http fuzz-replay-jwt fuzz_http fuzz_jwt fuzz_http_replay auth-server-asan .fuzz-work
	@echo "Cleaned build artifacts (crash seeds in test/fuzz/crashes/ are kept — they are tests)"

# Test programs
test-str:
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_str.c src/util/str.c src/util/json.c src/util/log.c -o test-str $(SECURITY_LDFLAGS)
	@echo "Test built! Run with: ./test-str"

test-http:
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_http.c src/server/http.c src/handlers/common.c $(UTIL_SRCS) $(DB_SRCS) $(CRYPTO_SRCS) $(DB_VENDOR_SRCS) -o test-http $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "HTTP parser test built! Run with: ./test-http"

test-router:
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_router.c src/server/router.c src/server/http.c src/handlers/common.c $(UTIL_SRCS) $(DB_SRCS) $(CRYPTO_SRCS) $(DB_VENDOR_SRCS) -o test-router $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "Router test built! Run with: ./test-router"

test-db:
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_db.c $(UTIL_SRCS) $(DB_SRCS) $(CRYPTO_SRCS) $(DB_VENDOR_SRCS) -o test-db $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "Database test built! Run with: ./test-db"

test-crypto:
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_crypto.c $(CRYPTO_SRCS) $(UTIL_SRCS) $(DB_SRCS) $(DB_VENDOR_SRCS) -o test-crypto $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "Crypto test built! Run with: ./test-crypto"

test-email:
ifeq ($(EMAIL_SUPPORT),1)
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) test/test_email.c $(UTIL_SRCS) -o test-email $(LDFLAGS) $(SECURITY_LDFLAGS)
	@echo "Email test built! Run with: ./test-email <recipient_email> [config_file]"
else
	@echo "Email support not enabled. Build with: make EMAIL_SUPPORT=1 test-email"
endif

test: test-str test-http test-router test-db test-crypto
	@echo "All tests built! Running..."
	./test-str && ./test-http && ./test-router && ./test-db && ./test-crypto
	@$(MAKE) --no-print-directory fuzz-regress

# ============================================================================
# Fuzzing and sanitizers (see test/fuzz/README.md)
# ============================================================================
#
# These build with ASan+UBSan, which is incompatible with _FORTIFY_SOURCE, so they
# carry their own flags instead of reusing SECURITY_FLAGS.
#
# -fno-sanitize-recover=undefined matters: by default UBSan only PRINTS a diagnostic
# and keeps running, so a check that greps for a crash reports "clean" on code that
# is quietly undefined. This makes UB abort like ASan does.
#
# Per fuzz target: the harness, and the extra TUs it links (the http parser needs no
# database or crypto; the jwt decoder needs the hmac/base64/json stack). Each target
# owns its own corpus/ and crashes/ subdirectory.
FUZZ_SAN         = -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
FUZZ_HTTP_SRCS   = test/fuzz/fuzz_http.c src/server/http.c src/util/str.c src/util/json.c
FUZZ_JWT_SRCS    = test/fuzz/fuzz_jwt.c src/crypto/jwt.c src/crypto/hmac.c src/crypto/random.c \
                   src/crypto/sha256.c src/util/data.c src/util/str.c src/util/json.c src/util/log.c
FUZZ_TIME       ?= 60
FUZZ_TARGET     ?= http

# Replay every saved crash and seed through its parser under ASan+UBSan. Needs only
# gcc, runs in seconds, and is what makes test/fuzz/crashes/ a real regression test
# instead of a folder of souvenirs. Runs as part of `make test`.
fuzz-regress:
	@$(CC) -std=c11 -g -O1 -Iinclude $(FUZZ_SAN) -DFUZZ_STANDALONE \
	    $(FUZZ_HTTP_SRCS) -lcrypto -o fuzz-replay-http
	@$(CC) -std=c11 -g -O1 -Iinclude $(FUZZ_SAN) -DFUZZ_STANDALONE \
	    $(FUZZ_JWT_SRCS) -lcrypto -o fuzz-replay-jwt
	@echo "=== Fuzz regression seeds (ASan+UBSan) ==="
	@fail=0; for target in http jwt; do \
	    for f in test/fuzz/crashes/$$target/* test/fuzz/corpus/$$target/*; do \
	        [ -f "$$f" ] || continue; \
	        if ./fuzz-replay-$$target "$$f" >/dev/null 2>&1; then \
	            printf '  \342\234\223 %s\n' "$$f"; \
	        else \
	            printf '  \342\234\227 %s  <-- SANITIZER FIRED\n' "$$f"; \
	            ./fuzz-replay-$$target "$$f" 2>&1 | head -20; \
	            fail=1; \
	        fi; \
	    done; \
	done; \
	if [ $$fail -ne 0 ]; then echo "FAILED: a known-bad input is crashing again."; exit 1; fi; \
	echo "=== All seeds clean ==="

# Coverage-guided fuzz run. Needs clang (libFuzzer). Pick target and budget:
#   make fuzz                              # http, 60s
#   make fuzz FUZZ_TARGET=jwt FUZZ_TIME=3600
fuzz:
	@./test/fuzz/run.sh $(FUZZ_TARGET) $(FUZZ_TIME)

# ASan+UBSan build of the whole server, to drive by hand (login, OAuth, sandbox).
sanitize:
	@./test/sanitize.sh

# Show help
help:
	@echo "Available targets:"
	@echo "  make                - Build the server (default)"
	@echo "  make debug          - Build with debug symbols"
	@echo "  make release        - Build optimized version"
	@echo "  make test-str       - Build string utilities test"
	@echo "  make test-http      - Build HTTP parser test"
	@echo "  make test-router    - Build router test"
	@echo "  make test-db        - Build database integration test"
	@echo "  make test-crypto    - Build crypto test (random generation, password hashing, hmac, jwt)"
	@echo "  make test-email     - Build email delivery test (requires EMAIL_SUPPORT=1)"
	@echo "  make test           - Build and run all tests (excludes test-email)"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make help           - Show this help"
	@echo ""
	@echo "Memory safety (see test/fuzz/README.md):"
	@echo "  make fuzz-regress   - Replay saved crash seeds under ASan+UBSan (gcc, seconds)"
	@echo "  make fuzz           - Coverage-guided fuzz (clang; FUZZ_TARGET=http|jwt, FUZZ_TIME=60)"
	@echo "  make sanitize       - Build the whole server with ASan+UBSan to drive by hand"

.PHONY: all debug release clean help test test-str test-http test-router test-db test-crypto test-email \
        fuzz fuzz-regress sanitize
