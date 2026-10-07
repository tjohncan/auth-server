#ifndef SCRATCH_DB_H
#define SCRATCH_DB_H

/*
 * Scratch databases: one of the test's own for each test that writes, on the
 * backend the build has, so nothing a test does reaches a database anyone keeps.
 *
 * SQLite: in memory, a new one with each connection.
 * PostgreSQL: a new database on the server AUTH_TEST_PG names: a libpq
 *   connection string, in key=value form, for a role that may create databases
 *   (test/pg-cluster.sh starts a throwaway server and prints one). Each is named
 *   auth_test_<pid>_<n>, and every one made is dropped when the program exits.
 *   Without AUTH_TEST_PG the database suites skip, so `make test` still passes
 *   on a PostgreSQL build where there's no server to run them against.
 */

#include "db/db.h"
#include "util/config.h"
#include <stddef.h>

#ifdef DB_BACKEND_POSTGRESQL
#define SCRATCH_DB_TYPE DB_TYPE_POSTGRESQL
#else
#define SCRATCH_DB_TYPE DB_TYPE_SQLITE
#endif

/* 1 if the database suites can run here; 0, having said why, if they can't */
int scratch_db_available(void);

/* An empty database: what db_connect takes to reach it, into conninfo. 0, or -1. */
int scratch_db_new(char *conninfo, size_t size);

/* A new database with the schema db_init_schema makes from config's schema_dir,
   connected (on PostgreSQL, copied from a template made the first time). NULL
   on failure. */
db_handle_t *scratch_db_open(const config_t *config);

/* The same, and into conninfo what connects to that database again: for tests of
   two connections at once, on PostgreSQL (on SQLite, each connection to
   ":memory:" is a database of its own) */
db_handle_t *scratch_db_open_shared(const config_t *config, char *conninfo, size_t size);

/* The schema's owner role, for db_init_schema. On PostgreSQL, the role
   AUTH_TEST_PG connects as: the one auth.conf names needn't exist there. */
const char *scratch_db_owner_role(const config_t *config);

#ifdef DB_BACKEND_POSTGRESQL
/* A new role, NOLOGIN, dropped at exit once the databases are: its name into
   name. 0, or -1. */
int scratch_db_role(char *name, size_t size);
#endif

/*
 * SQL the tests write for either backend, beside db_sql.h's:
 *   ID_HEX(col)            an id column as 32 lowercase hex digits
 *   ID_FROM_HEX(hex)       an id from 32 hex digits (in a format, "%s")
 *   NEW_ID                 a new random id
 *   SECONDS_BEFORE(col, n) a time column moved n seconds back (n a string literal)
 *   HISTORY_OF(s, t)       the history table of table t, in schema s on PostgreSQL
 */
#ifdef DB_BACKEND_POSTGRESQL
#define ID_HEX(col)            "replace(" col "::text, '-', '')"
#define ID_FROM_HEX(hex)       "'" hex "'::uuid"
#define NEW_ID                 "gen_random_uuid()"
#define SECONDS_BEFORE(col, n) "(" col " - INTERVAL '" n " seconds')"
#define HISTORY_OF(s, t)       s "_history." t
#else
#define ID_HEX(col)            "lower(hex(" col "))"
#define ID_FROM_HEX(hex)       "x'" hex "'"
#define NEW_ID                 "randomblob(16)"
#define SECONDS_BEFORE(col, n) "datetime(" col ", '-" n " seconds')"
#define HISTORY_OF(s, t)       "history__" t
#endif

#endif /* SCRATCH_DB_H */
