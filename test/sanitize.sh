#!/usr/bin/env bash
#
# Build the server with AddressSanitizer + UndefinedBehaviorSanitizer and print
# how to exercise it. Self-contained: does not touch the Makefile.
#
# ASan/UBSan compile instrumentation into the binary that watches every memory
# access and arithmetic operation at run time. The build stays SILENT unless
# something is actually wrong — then it prints a stack trace and aborts. There is
# nothing to click. "Exercising" the server means driving its real code paths so
# the instrumentation has live code to watch (see EXERCISE below).
#
# Usage:
#   make sanitize               # same thing
#   ./test/sanitize.sh          # build ./auth-server-asan
#   ./test/sanitize.sh run      # build, then run it in the foreground
#
# This is the hand-driven half of the memory-safety tooling: it watches the WHOLE
# server (database, crypto, handlers) while a human clicks through real flows. The
# automated half is the fuzzer, which hammers one function with machine-generated
# input and needs no human at all — see test/fuzz/README.md.
#
# Requires: gcc (with libasan/libubsan — present in gcc by default), libssl-dev,
# libargon2-dev, and the SQLite amalgamation (see vendor/setup_notes.txt).
#
# Source list mirrors the Makefile default backend (SQLite, EMAIL_SUPPORT off).
# If you build with a different backend, adjust DB flags/sources to match.

set -euo pipefail
cd "$(dirname "$0")/.."

OUT=auth-server-asan

# -fno-sanitize-recover=undefined: by DEFAULT UBSan prints a diagnostic and keeps
# running, so undefined behavior scrolls past in the log and the server carries on
# looking healthy. This makes UB abort at the point it happens, like ASan does, so
# it cannot be missed. (UBSAN_OPTIONS=halt_on_error=1 below does the same at run
# time — this is the belt to that pair of braces, since env vars get forgotten.)
SAN_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
# ASan is incompatible with _FORTIFY_SOURCE; keep the other hardening flags.
CFLAGS="-Wall -Wextra -std=c11 -O1 -g -Iinclude -Ivendor/sqlite -DDB_BACKEND_SQLITE
        -fstack-protector-strong -fPIE -Wformat -Wformat-security ${SAN_FLAGS}"
LDLIBS="-lpthread -lm -ldl -largon2 -lssl -lcrypto"

# Every .c the default build compiles: all of src/ except the email module
# (compiled only under EMAIL_SUPPORT), plus the SQLite amalgamation.
mapfile -t SRCS < <(find src -name '*.c' ! -name 'email.c' | sort)
SRCS+=(vendor/sqlite/sqlite3.c)

echo "Compiling ${#SRCS[@]} translation units with ASan+UBSan (this is slower than a normal build)..."
# shellcheck disable=SC2086
gcc ${CFLAGS} "${SRCS[@]}" ${LDLIBS} ${SAN_FLAGS} -pie -o "${OUT}"

echo
echo "Built ./${OUT}"
echo
cat <<'EXERCISE'
NEXT — run it and drive the app so the sanitizer has live code to watch:

    ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    ./auth-server-asan

Then, against the running server, exercise the real paths — the more the better:
    - open the login page, log in, log out
    - walk each sandbox panel (client-credentials, introspect, revoke, refresh, replay)
    - drive the OAuth flow end to end: /authorize -> /token -> /userinfo -> /revoke
    - throw a little garbage at it too: malformed headers, oversized bodies, odd methods

WHAT A PASS LOOKS LIKE: nothing. The server runs normally and prints no sanitizer output.
WHAT A FAILURE LOOKS LIKE: a red "==ERROR: AddressSanitizer/UndefinedBehavior..." block
with a stack trace, and the process aborts. That trace is the bug; save it.
EXERCISE

if [[ "${1:-}" == "run" ]]; then
    echo
    echo "Starting ./${OUT} ..."
    ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    exec "./${OUT}"
fi
