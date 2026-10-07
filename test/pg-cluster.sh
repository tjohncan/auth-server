#!/bin/sh
# A throwaway PostgreSQL cluster for the database suites (make test-postgresql).
# It lives in a directory of its own and is reachable only through a Unix socket
# there: no TCP listener, trust authentication, and fsync off, since nothing in it
# is kept. UTF-8 with the C locale, which needs no locale installed and refuses
# ill-formed text as a deployment's database would.
#
#   test/pg-cluster.sh run COMMAND...  start one in a new temporary directory, run
#                                      COMMAND with AUTH_TEST_PG naming it, then
#                                      stop and remove it; exits as COMMAND does
#   test/pg-cluster.sh start DIR       start one in DIR (new, or empty) and print
#                                      the connection string for AUTH_TEST_PG
#   test/pg-cluster.sh stop DIR        stop it and remove DIR
#
# initdb and pg_ctl come from PG_BIN if it's set, else from PATH, else from the
# newest /usr/lib/postgresql/<version>/bin (Debian's and Ubuntu's server packages,
# which keep them off PATH). initdb won't run as root.

PORT=5432

bin_dir() {
    if [ -n "$PG_BIN" ]; then
        echo "$PG_BIN"
    elif command -v initdb > /dev/null 2>&1; then
        dirname "$(command -v initdb)"
    else
        ls -d /usr/lib/postgresql/*/bin 2> /dev/null | sort -t/ -k5,5n | tail -n 1
    fi
}

start() {
    dir=$1
    case "$dir" in
        /*) ;;
        *) echo "pg-cluster: DIR must be an absolute path" >&2; return 1;;
    esac
    case "$dir" in
        *[!A-Za-z0-9/._-]*) echo "pg-cluster: DIR may hold only letters, digits and / . _ -" >&2; return 1;;
    esac
    if [ -e "$dir" ] && [ -n "$(ls -A "$dir")" ]; then
        echo "pg-cluster: $dir isn't empty" >&2
        return 1
    fi
    bin=$(bin_dir)
    if [ -z "$bin" ] || [ ! -x "$bin/initdb" ]; then
        echo "pg-cluster: no initdb found: install PostgreSQL's server programs, or set PG_BIN" >&2
        return 1
    fi
    mkdir -p "$dir" || return 1
    if ! "$bin/initdb" -D "$dir/data" -U postgres -A trust -E UTF8 --locale=C --no-sync \
            > "$dir/initdb.log" 2>&1; then
        cat "$dir/initdb.log" >&2
        return 1
    fi
    if ! "$bin/pg_ctl" -D "$dir/data" -l "$dir/server.log" -w -o "-c listen_addresses= \
            -c unix_socket_directories=$dir -c port=$PORT -c fsync=off \
            -c synchronous_commit=off -c full_page_writes=off" start > /dev/null; then
        cat "$dir/server.log" >&2
        return 1
    fi
    echo "host=$dir port=$PORT user=postgres dbname=postgres"
}

stop() {
    dir=$1
    # Only what this script made: a directory it ran initdb in, or one still empty
    if [ ! -f "$dir/initdb.log" ]; then
        rmdir "$dir" 2> /dev/null && return 0
        echo "pg-cluster: $dir isn't a cluster this script started" >&2
        return 1
    fi
    if [ -f "$dir/data/postmaster.pid" ]; then
        "$(bin_dir)/pg_ctl" -D "$dir/data" -m immediate stop > /dev/null 2>&1
    fi
    rm -rf "$dir"
}

case "$1" in
run)
    shift
    [ $# -gt 0 ] || { echo "usage: pg-cluster.sh run COMMAND..." >&2; exit 2; }
    dir=$(mktemp -d "${TMPDIR:-/tmp}/auth-test-pg.XXXXXX") || exit 1
    trap 'stop "$dir"' EXIT
    trap 'exit 130' INT TERM
    AUTH_TEST_PG=$(start "$dir") || exit 1
    export AUTH_TEST_PG
    "$@"
    exit $?
    ;;
start)
    [ -n "$2" ] || { echo "usage: pg-cluster.sh start DIR" >&2; exit 2; }
    start "$2"
    ;;
stop)
    [ -n "$2" ] || { echo "usage: pg-cluster.sh stop DIR" >&2; exit 2; }
    stop "$2"
    ;;
*)
    echo "usage: pg-cluster.sh run COMMAND... | start DIR | stop DIR" >&2
    exit 2
    ;;
esac
