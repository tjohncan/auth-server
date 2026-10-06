#include "db/maintenance.h"
#include "db/db_sql.h"
#include "db/init/db_history.h"
#include "util/log.h"

#include <stdio.h>
#include <string.h>

/* A catalog name as an SQL identifier: in double quotes, any inside doubled */
static void quote_ident(char *out, size_t size, const char *name) {
    size_t n = 0;
    out[n++] = '"';
    for (const char *c = name; *c && n + 3 < size; c++) {
        if (*c == '"') out[n++] = '"';
        out[n++] = *c;
    }
    out[n++] = '"';
    out[n] = '\0';
}

/* Run one DROP of a catalog object (schema may be NULL), logging what went */
static int drop(db_handle_t *db, const char *format, const char *schema, const char *name) {
    char quoted_schema[160] = "", quoted_name[160], target[330], sql[400];
    if (schema) quote_ident(quoted_schema, sizeof(quoted_schema), schema);
    quote_ident(quoted_name, sizeof(quoted_name), name);
    snprintf(target, sizeof(target), "%s%s%s", quoted_schema, schema ? "." : "", quoted_name);
    snprintf(sql, sizeof(sql), format, target);
    if (db_execute_direct(db, sql) != 0) {
        log_error("Failed: %s", sql);
        return -1;
    }
    log_info("%s", sql);
    return 0;
}

int maintenance_drop_history(db_handle_t *db, db_type_t type, int rebuild,
                             drophistory_report_t *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* What fills the history tables, then the tables. SQLite: the triggers that
       insert into a history__ table, whatever their name, so one left behind by
       hand is found too. PostgreSQL: the trigger functions and tables in the
       history schemas, read from the catalogs, which list them whatever this
       role may do with them. */
    const char *fillers_sql, *tables_sql, *drop_filler, *drop_table;
    if (type == DB_TYPE_SQLITE) {
        fillers_sql = "SELECT NULL, name FROM sqlite_master WHERE type = 'trigger' "
                      "AND sql LIKE '%INSERT INTO \"history\\_\\_%' ESCAPE '\\' ORDER BY name";
        tables_sql = "SELECT NULL, name FROM sqlite_master WHERE type = 'table' "
                     "AND name LIKE 'history\\_\\_%' ESCAPE '\\' ORDER BY name";
        drop_filler = "DROP TRIGGER %s";
        drop_table = "DROP TABLE %s";
    } else {
        fillers_sql = "SELECT n.nspname, p.proname FROM pg_proc p "
                      "JOIN pg_namespace n ON n.oid = p.pronamespace "
                      "WHERE n.nspname IN ('security_history', 'session_history', "
                      "'logging_history', 'lookup_history') "
                      "AND p.proname LIKE 'tg\\_fn\\_%' ORDER BY 1, 2";
        tables_sql = "SELECT schemaname, tablename FROM pg_tables "
                     "WHERE schemaname IN ('security_history', 'session_history', "
                     "'logging_history', 'lookup_history') ORDER BY 1, 2";
        drop_filler = "DROP FUNCTION %s() CASCADE";
        drop_table = "DROP TABLE %s";
    }

    db_result_t *fillers = NULL, *tables = NULL;
    if (db_query(db, &fillers, "%s", fillers_sql) != 0 ||
        db_query(db, &tables, "%s", tables_sql) != 0) {
        log_error("Failed to list the history tables and what fills them");
        db_result_free(fillers);
        return -1;
    }

    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin the history drop");
        db_result_free(fillers);
        db_result_free(tables);
        return -1;
    }

    /* Fillers first: a trigger left pointing at a dropped table fails every
       update and delete on its main table */
    int failed = 0;
    for (int i = 0; i < db_result_row_count(fillers) && !failed; i++) {
        failed = drop(db, drop_filler, db_result_get(fillers, i, 0),
                      db_result_get(fillers, i, 1)) != 0;
        out->triggers_dropped += !failed;
    }
    for (int i = 0; i < db_result_row_count(tables) && !failed; i++) {
        failed = drop(db, drop_table, db_result_get(tables, i, 0),
                      db_result_get(tables, i, 1)) != 0;
        out->tables_dropped += !failed;
    }
    db_result_free(fillers);
    db_result_free(tables);

    if (!failed && rebuild) {
        failed = db_init_history_tables(db, type, 0) != 0;
        if (failed) {
            log_error("Failed to make the history tables again. On a PostgreSQL hardened "
                      "per setup_reference.sql, grant the owner role to the login role for "
                      "the run (grant auth_dbo to auth_service), and revoke it after; or turn "
                      "enable_history_tables off first.");
        }
        out->rebuilt = !failed;
    }

    if (failed || db_execute_trusted(db, "COMMIT") != 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_error("The history drop was rolled back: nothing changed");
        memset(out, 0, sizeof(*out));
        return -1;
    }

    if (type != DB_TYPE_SQLITE) return 0;

    /* The dropped rows' pages are free but still in the file, and their page
       images may be in the -wal file: VACUUM rewrites the one, a truncating
       checkpoint empties the other */
    db_result_t *checkpoint = NULL;
    if (db_execute_direct(db, "VACUUM") != 0 ||
        db_query(db, &checkpoint, "%s", "PRAGMA wal_checkpoint(TRUNCATE)") != 0) {
        log_error("History is gone, but the file couldn't be scrubbed: run VACUUM, then "
                  "PRAGMA wal_checkpoint(TRUNCATE), with every instance stopped");
        return -2;
    }
    const char *busy = db_result_row_count(checkpoint) == 1 ? db_result_get(checkpoint, 0, 0) : NULL;
    int scrubbed = busy && strcmp(busy, "0") == 0;
    db_result_free(checkpoint);
    if (!scrubbed) {
        log_error("History is gone, but another connection held the -wal file, which may still "
                  "hold its pages: with every instance stopped, run PRAGMA wal_checkpoint(TRUNCATE)");
        return -2;
    }
    return 0;
}
