#!/bin/sh
# Verify the vendored SQLite 3.51.2 amalgamation: sqlite3.c and sqlite3.h, the two
# files the build compiles (sqlite3.h is included by src/db/db.c).
#
# sqlite3.c: checked against the "SHA3-256 for sqlite3.c" that SQLite publishes in
#   https://www.sqlite.org/releaselog/3_51_2.html
#
# sqlite3.h: SQLite publishes no hash for the header on its own. This value was
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
# Bumping SQLite means changing the URL in setup_notes.txt and both CI jobs, the
# published sqlite3.c hash below, and a fresh sqlite3.h hash from the new archive.
#
# Usage: sh vendor/verify-sqlite.sh [dir containing sqlite3.c and sqlite3.h]
set -e

DIR="${1:-vendor/sqlite}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "verify-sqlite.sh: the openssl command-line tool is needed to check the SQLite files" >&2
    exit 1
fi

check() {
    file="$1"
    expected="$2"
    if [ ! -f "$file" ]; then
        echo "$file: missing (see vendor/setup_notes.txt)" >&2
        exit 1
    fi
    actual=$(openssl dgst -sha3-256 -r "$file" | cut -d' ' -f1)
    if [ "$actual" != "$expected" ]; then
        echo "$file: SHA3-256 $actual does not match the expected $expected" >&2
        exit 1
    fi
    echo "$file: OK"
}

check "$DIR/sqlite3.c" 733b3fcc6cccb1e334424b9b91a9d68b618385b76ebfcbb106690bd3a9e61367
check "$DIR/sqlite3.h" 8365bfda03f0ee17635c5117503ac9f34723a95e885b2aea1fb913bb679cf832
