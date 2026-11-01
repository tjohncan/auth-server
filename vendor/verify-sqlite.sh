#!/bin/sh
# Verify the vendored SQLite amalgamation: sqlite3.c and sqlite3.h, the two files
# the build compiles (sqlite3.h is included by src/db/db.c). They pass when both
# match the same release on the approved list below.
#
# Each line of the list is a release: its version, the year sqlite.org files its
# download under, and the SHA3-256 of its sqlite3.c and of its sqlite3.h.
#
# sqlite3.c: the "SHA3-256 for sqlite3.c" that SQLite publishes for the release, in
#   https://www.sqlite.org/releaselog/<version, with underscores for dots>.html
#
# sqlite3.h: SQLite publishes no hash for the header on its own. Each value was
#   taken from the same archive whose sqlite3.c matched the published hash, so it
#   is trust-on-first-use anchored to that download. (The header is also embedded
#   in sqlite3.c, but rewritten in places, so it cannot be compared byte-for-byte.)
#
# Both are hashes of the files that are compiled, not of the archive they came
# in, so the check holds however the files arrived. The Makefile runs it on every
# build that compiles the amalgamation, and test/sanitize.sh before its own compile;
# setup_notes.txt, CI and the Docker build also run it straight after the download,
# so a bad one fails where it happened.
#
# Approving a release is adding its line, in any position: the published sqlite3.c
# hash, and the hash of the sqlite3.h from an archive whose sqlite3.c matched it.
# setup_notes.txt downloads the newest release listed, and CI builds and tests the
# oldest and the newest, so nothing else changes. Taking a line out refuses that
# release. None up to 3.51.2 is listed: those carry the WAL-reset bug
# (https://www.sqlite.org/wal.html#walresetbug), which needs a WAL database written
# through several connections at once, and every worker and the cleaner has one.
#
# Usage:
#   sh vendor/verify-sqlite.sh [DIR]
#       check DIR's sqlite3.c and sqlite3.h (DIR defaults to vendor/sqlite)
#   sh vendor/verify-sqlite.sh --expect VERSION [DIR]
#       the same, and they must be that release
#   sh vendor/verify-sqlite.sh --version oldest|newest
#       print that listed release's version
#   sh vendor/verify-sqlite.sh --url oldest|newest|VERSION
#       print where that listed release's amalgamation downloads from
set -e

APPROVED='
3.51.3 2026 32d5424f97e0a7fc5ed2f6335afbb58be4e0298bd7117a34e39d345ff13d859e f6af1852a4d3c5a32f55ff383ca41b83c2eb78e8405784bb452a4c063c266170
3.53.4 2026 67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16 89d0de498b1012938bb78dc18b68fea52e26f7f7b6db6347d126a2e58b86a05c
3.54.1 2026 e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81 15ef3f5dbc4a7a980f828fa0d1e473cee5a124e7bb77e9bc70fc0bfa3f9a2af8
'

usage() {
    echo "usage: sh vendor/verify-sqlite.sh [--expect VERSION] [DIR]" >&2
    echo "       sh vendor/verify-sqlite.sh --version oldest|newest" >&2
    echo "       sh vendor/verify-sqlite.sh --url oldest|newest|VERSION" >&2
    exit 2
}

# The listed releases, oldest first, whatever order their lines are in
releases() {
    printf '%s\n' "$APPROVED" | grep . | sort -t. -k1,1n -k2,2n -k3,3n
}

# One listed release's line: the oldest, the newest, or the one with that version
release() {
    case "$1" in
        oldest) releases | head -n 1 ;;
        newest) releases | tail -n 1 ;;
        *)
            line=$(releases | awk -v v="$1" '$1 == v')
            if [ -z "$line" ]; then
                echo "verify-sqlite.sh: SQLite $1 is not an approved release; approved:" \
                     $(releases | cut -d' ' -f1) >&2
                exit 1
            fi
            printf '%s\n' "$line" ;;
    esac
}

expect=
case "${1:-}" in
    --version)
        [ $# -eq 2 ] || usage
        line=$(release "$2")
        echo "${line%% *}"
        exit 0 ;;
    --url)
        [ $# -eq 2 ] || usage
        line=$(release "$2")
        printf '%s\n' "$line" | awk '{
            split($1, v, ".")
            printf "https://www.sqlite.org/%s/sqlite-amalgamation-%d%02d%02d00.zip\n", $2, v[1], v[2], v[3]
        }'
        exit 0 ;;
    --expect)
        [ $# -ge 2 ] || usage
        expect="$2"
        shift 2 ;;
    -*)
        usage ;;
esac
[ $# -le 1 ] || usage
DIR="${1:-vendor/sqlite}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "verify-sqlite.sh: the openssl command-line tool is needed to check the SQLite files" >&2
    exit 1
fi

for file in "$DIR/sqlite3.c" "$DIR/sqlite3.h"; do
    if [ ! -f "$file" ]; then
        echo "$file: missing (see vendor/setup_notes.txt)" >&2
        exit 1
    fi
done

sha3() {
    openssl dgst -sha3-256 -r "$1" | cut -d' ' -f1
}
c_hash=$(sha3 "$DIR/sqlite3.c")
h_hash=$(sha3 "$DIR/sqlite3.h")

# Which release this sqlite3.c is, then whether the header is that release's too
version=$(releases | awk -v c="$c_hash" '$3 == c { print $1 }')
if [ -z "$version" ]; then
    # The header is unverified, but the version it names is usually the whole story
    named=$(sed -n 's/^#define SQLITE_VERSION[[:space:]]*"\([^"]*\)".*/\1/p' "$DIR/sqlite3.h" | head -n 1)
    echo "$DIR/sqlite3.c: SHA3-256 $c_hash is no approved release's" \
         "(its sqlite3.h names ${named:-no version}); approved:" $(releases | cut -d' ' -f1) \
         "(see vendor/setup_notes.txt)" >&2
    exit 1
fi
h_expected=$(release "$version" | cut -d' ' -f4)
if [ "$h_hash" != "$h_expected" ]; then
    echo "$DIR/sqlite3.h: SHA3-256 $h_hash is not the header of SQLite $version," \
         "whose sqlite3.c is beside it (expected $h_expected)" >&2
    exit 1
fi
if [ -n "$expect" ] && [ "$version" != "$expect" ]; then
    echo "$DIR: SQLite $version, which is approved, but $expect was expected" >&2
    exit 1
fi
echo "$DIR: SQLite $version (sqlite3.c and sqlite3.h match its approved hashes)"
