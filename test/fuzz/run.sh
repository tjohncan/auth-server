#!/usr/bin/env bash
#
# Coverage-guided fuzz run, with a report card.
#
# Usage:
#   ./test/fuzz/run.sh [target] [seconds]
#
#   ./test/fuzz/run.sh              # http target, 60-second smoke run
#   ./test/fuzz/run.sh http 3600    # http target, one-hour soak
#   ./test/fuzz/run.sh jwt 3600     # jwt target, one-hour soak
#
# Targets:
#   http  - http_request_parse + accessors (the socket-facing request parser)
#   jwt   - jwt_decode_auth_request (the authorization-code JWT decoder)
#
# Single process on purpose. These targets saturate their reachable edges within
# seconds, so extra cores buy no coverage — they only scatter per-worker logs and
# muddy the stats below. If you ever want them anyway: add -jobs=N -workers=N.
#
# Requires clang (libFuzzer ships with clang; gcc has no equivalent):
#   sudo apt-get install -y clang
#
# To replay the saved crash seeds without clang, use `make fuzz-regress` instead.

set -euo pipefail
cd "$(dirname "$0")/../.."

# Back-compat: the first arg used to be the duration. If it looks like a number,
# treat it as such and default the target to http.
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    TARGET="http"; DURATION="${1}"
else
    TARGET="${1:-http}"; DURATION="${2:-60}"
fi

# Per-target config: the TUs to link, and whether it uses a dictionary. Keeping the
# source lists here (not in the harness) is what lets one runner serve both targets.
case "${TARGET}" in
    http)
        SRCS="test/fuzz/fuzz_http.c src/server/http.c src/util/str.c src/util/json.c"
        DICT="test/fuzz/http.dict"
        DESC="http_request_parse + accessors"
        MAXLEN=65536
        ;;
    jwt)
        SRCS="test/fuzz/fuzz_jwt.c src/crypto/jwt.c src/crypto/hmac.c src/crypto/random.c \
              src/crypto/sha256.c src/util/data.c src/util/str.c src/util/json.c src/util/log.c"
        DICT="test/fuzz/jwt.dict"
        DESC="jwt_decode_auth_request"
        # The harness caps the payload at 1200B to keep the signed token under 2048.
        MAXLEN=1200
        ;;
    *)
        echo "error: unknown target '${TARGET}'. Use 'http' or 'jwt'." >&2
        exit 2
        ;;
esac

WORK=".fuzz-work/${TARGET}"     # gitignored: libFuzzer's evolving corpus + logs live here
BIN="${WORK}/fuzz_${TARGET}"
SEEDS="test/fuzz/corpus/${TARGET}"
CRASHES="test/fuzz/crashes/${TARGET}"

if ! command -v clang >/dev/null 2>&1; then
    echo "error: clang not found. Install it (apt-get install -y clang), or run" >&2
    echo "       'make fuzz-regress' to replay the saved crash seeds under gcc." >&2
    exit 1
fi

mkdir -p "${WORK}/corpus" "${CRASHES}"

# Seed the working corpus from the committed seeds AND the saved crashes, so every
# run re-proves the old bugs stay dead and keeps mutating around them. -n: never
# clobber a corpus the fuzzer has already grown.
cp -n "${SEEDS}"/* "${WORK}/corpus/" 2>/dev/null || true
cp -n "${CRASHES}"/* "${WORK}/corpus/" 2>/dev/null || true

echo "Building ${BIN} (clang + libFuzzer + ASan + UBSan)..."
# -fno-sanitize-recover=undefined is load-bearing: by DEFAULT UBSan only prints a
# diagnostic and keeps running, so libFuzzer never sees a crash and a run with real
# undefined behavior in it still reports "no findings". This makes UB abort.
# shellcheck disable=SC2086
clang -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
      -fno-omit-frame-pointer -g -O1 \
      -Iinclude -Ivendor/sqlite -DDB_BACKEND_SQLITE \
      ${SRCS} -lcrypto -o "${BIN}"

DICT_ARG=()
[ -f "${DICT}" ] && DICT_ARG=(-dict="${DICT}")

echo "Fuzzing '${TARGET}' for ${DURATION}s. Ctrl-C to stop early."
echo

# -artifact_prefix: a new crash lands in test/fuzz/crashes/<target>/ (a tracked
# regression seed), not loose in the repo root.
set +e
"${BIN}" "${WORK}/corpus" \
    "${DICT_ARG[@]}" \
    -max_len="${MAXLEN}" \
    -max_total_time="${DURATION}" \
    -print_final_stats=1 \
    -artifact_prefix="${CRASHES}/" \
    2>&1 | tee "${WORK}/last-run.log"
STATUS="${PIPESTATUS[0]}"
set -e

LOG="${WORK}/last-run.log"

echo
echo "================ FUZZ REPORT CARD ================"
echo "  target:     ${DESC}"
echo "  duration:   ${DURATION}s"
echo "  build:      ASan + UBSan (no-recover), libFuzzer"

# Final coverage line: "cov: <edges> ft: <features> corp: <n>/<bytes>"
COV=$(grep -oE 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+/[0-9]+b' "${LOG}" | tail -1 || true)
[ -n "${COV}" ] && echo "  coverage:   ${COV}"

for k in number_of_executed_units average_exec_per_sec new_units_added peak_rss_mb; do
    V=$(grep -oE "stat::${k}: *[0-9]+" "${LOG}" | tail -1 | grep -oE '[0-9]+$' || true)
    [ -n "${V}" ] && printf '  %-11s %s\n' "${k#stat::}:" "${V}"
done

if [ "${STATUS}" -eq 0 ]; then
    echo "  crashes:    0"
    echo "  RESULT:     CLEAN"
    echo "================================================="
else
    echo "  RESULT:     CRASH FOUND (exit ${STATUS})"
    echo "================================================="
    echo
    echo "The reproducer was saved under ${CRASHES}/. Triage it with:"
    echo "    ${BIN} ${CRASHES}/<file>"
    echo "Once fixed, keep the file: it is now a permanent regression seed."
fi

exit "${STATUS}"
