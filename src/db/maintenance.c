#include "db/maintenance.h"
#include "db/db_sql.h"
#include "db/encryption_params.h"
#include "db/init/db_history.h"
#include "util/log.h"
#include "util/str.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
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

/* SQLite, after a run: VACUUM rewrites the file without the old contents of
   freed pages, and a truncating checkpoint empties the -wal file, which must find
   no other connection busy. Returns 0, or -1. */
static int sqlite_scrub(db_handle_t *db) {
    db_result_t *checkpoint = NULL;
    if (db_execute_direct(db, "VACUUM") != 0 ||
        db_query(db, &checkpoint, "%s", "PRAGMA wal_checkpoint(TRUNCATE)") != 0) {
        return -1;
    }
    const char *busy = db_result_row_count(checkpoint) == 1 ? db_result_get(checkpoint, 0, 0) : NULL;
    int scrubbed = busy && strcmp(busy, "0") == 0;
    db_result_free(checkpoint);
    return scrubbed ? 0 : -1;
}

/* Each relation's file node, into nodes. Returns 0, or -1. */
static int pg_filenodes(db_handle_t *db, const char *const *relations, size_t count,
                        char nodes[][24]) {
    for (size_t i = 0; i < count; i++) {
        db_result_t *result = NULL;
        if (db_query(db, &result, "SELECT pg_relation_filenode('%s')", relations[i]) != 0 ||
            db_result_row_count(result) != 1 || !db_result_get(result, 0, 0)) {
            db_result_free(result);
            return -1;
        }
        snprintf(nodes[i], 24, "%s", db_result_get(result, 0, 0));
        db_result_free(result);
    }
    return 0;
}

#define PG_REWRITE_MAX 16

/* PostgreSQL, after a run: VACUUM FULL rewrites each relation, with its indexes
   and TOAST, into new files without its dead rows. A role that may not vacuum
   one gets only a WARNING and it skipped, the statement succeeding all the
   same, so what proves it is each one's file having changed. Names each one
   left as it was; returns how many, or -1 if the statement failed. */
static int pg_rewrite(db_handle_t *db, const char *const *relations, size_t count) {
    char sql[512], before[PG_REWRITE_MAX][24], after[PG_REWRITE_MAX][24];
    size_t pos = 0;
    int built = count <= PG_REWRITE_MAX && str_appendf(sql, sizeof(sql), &pos, "VACUUM FULL") == 0;
    for (size_t i = 0; built && i < count; i++) {
        built = str_appendf(sql, sizeof(sql), &pos, "%s %s", i ? "," : "", relations[i]) == 0;
    }
    if (!built || pg_filenodes(db, relations, count, before) != 0 ||
        db_execute_direct(db, sql) != 0 || pg_filenodes(db, relations, count, after) != 0) {
        return -1;
    }
    int kept = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(before[i], after[i]) == 0) {
            log_error("%s wasn't rewritten: its old rows are still in its file", relations[i]);
            kept++;
        }
    }
    return kept;
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

    if (type != DB_TYPE_SQLITE) {
        /* DROP TABLE removes a table's files, but not its planner statistics, a
           sample of each column: they're dead rows in pg_statistic now. Every
           run rewrites it, so one that found nothing left to drop still finishes
           an earlier run that couldn't. */
        static const char *const statistics[] = { "pg_catalog.pg_statistic" };
        if (pg_rewrite(db, statistics, 1) != 0) {
            log_error("History is gone, but a sample of it may still be in pg_statistic's file, "
                      "and rewriting that takes the database's owner. Run --drophistory again "
                      "as a role that has it (on a deployment hardened per setup_reference.sql, "
                      "grant auth_dbo to auth_service for the run), or as the owner run VACUUM "
                      "FULL pg_catalog.pg_statistic");
            return -2;
        }
        return 0;
    }

    /* The dropped rows' pages are free but still in the file, and their page
       images may be in the -wal file */
    if (sqlite_scrub(db) != 0) {
        log_error("History is gone, but the file may still hold its pages (VACUUM failed, or "
                  "another connection held the -wal file): with every instance stopped, run "
                  "VACUUM, then PRAGMA wal_checkpoint(TRUNCATE)");
        return -2;
    }
    return 0;
}

/* ============================================================================
 * --rekey
 * ========================================================================== */

/* A row to re-seal: its key (a pin, or a 16-byte id) and its sealed value */
typedef struct {
    long long pin;
    unsigned char id[16];
    char *sealed;
} reseal_row_t;

static void free_rows(reseal_row_t *rows, int count) {
    for (int i = 0; i < count; i++) {
        if (rows[i].sealed) OPENSSL_cleanse(rows[i].sealed, strlen(rows[i].sealed));
        free(rows[i].sealed);
    }
    free(rows);
}

/* Every (key, sealed value) a statement reads, read in full before anything is
   written. Returns 0, or -1. */
static int load_rows(db_handle_t *db, const char *sql, int by_id,
                     reseal_row_t **out, int *count) {
    *out = NULL;
    *count = 0;
    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) return -1;

    int capacity = 0, rc;
    while ((rc = db_step(stmt)) == DB_ROW) {
        if (*count == capacity) {
            capacity = capacity ? capacity * 2 : 64;
            reseal_row_t *grown = realloc(*out, (size_t)capacity * sizeof(**out));
            if (!grown) break;
            *out = grown;
        }
        reseal_row_t *row = &(*out)[*count];
        memset(row, 0, sizeof(*row));
        if (by_id) {
            const unsigned char *id = db_column_blob(stmt, 0);
            if (!id || db_column_bytes(stmt, 0) != 16) break;
            memcpy(row->id, id, 16);
        } else {
            row->pin = db_column_int64(stmt, 0);
        }
        const char *value = db_column_text(stmt, 1);
        row->sealed = value ? str_dup(value) : NULL;
        if (value && !row->sealed) break;
        (*count)++;
    }
    db_finalize(stmt);
    if (rc != DB_DONE) {
        free_rows(*out, *count);
        *out = NULL;
        *count = 0;
        return -1;
    }
    return 0;
}

/* The tables with sealed values, keyed by pin or id; those with a blind index
   also have it written (P2), and their key binds third rather than second */
static const struct {
    const char *table;
    const char *select;
    const char *update;
    int by_id;
    int indexed;
} RESEALED[] = {
    { "user_account", "SELECT pin, username FROM " TBL_USER_ACCOUNT " WHERE username IS NOT NULL",
      "UPDATE " TBL_USER_ACCOUNT " SET username = " P"1, username_hash = " P"2 WHERE pin = " P"3",
      0, 1 },
    { "user_email", "SELECT pin, email_address FROM " TBL_USER_EMAIL,
      "UPDATE " TBL_USER_EMAIL " SET email_address = " P"1, email_hash = " P"2 WHERE pin = " P"3",
      0, 1 },
    { "passwordless_login_token", "SELECT id, email_address FROM " TBL_PASSWORDLESS_LOGIN_TOKEN,
      "UPDATE " TBL_PASSWORDLESS_LOGIN_TOKEN " SET email_address = " P"1 WHERE id = " P"2",
      1, 0 },
    { "user_mfa", "SELECT pin, secret FROM " TBL_USER_MFA,
      "UPDATE " TBL_USER_MFA " SET secret = " P"1 WHERE pin = " P"2",
      0, 0 },
};
#define RESEALED_COUNT (sizeof(RESEALED) / sizeof(RESEALED[0]))

/* Re-seal one table's values, and its blind index. Returns the rows done, or -1. */
static int reseal_table(db_handle_t *db, size_t t, const encrypt_keys_t *old_keys,
                        const encrypt_keys_t *new_keys) {
    reseal_row_t *rows = NULL;
    int count = 0;
    if (load_rows(db, RESEALED[t].select, RESEALED[t].by_id, &rows, &count) != 0) {
        log_error("Failed to read %s", RESEALED[t].table);
        return -1;
    }

    int done = 0;
    for (int i = 0; i < count; i++) {
        /* lower is the size every lookup lowercases into, so the index matches theirs */
        char plaintext[ENCRYPT_FIELD_MAX_LENGTH + 1], sealed[512], lower[256];
        char index[65];
        int ok = rows[i].sealed &&
                 decrypt_field_with(old_keys, rows[i].sealed, plaintext, sizeof(plaintext)) == 0;
        if (!ok) {
            if (RESEALED[t].by_id) {
                char id_hex[33];
                for (int b = 0; b < 16; b++) snprintf(id_hex + 2 * b, 3, "%02x", rows[i].id[b]);
                log_error("encryption_key_previous doesn't open %s id %s", RESEALED[t].table, id_hex);
            } else {
                log_error("encryption_key_previous doesn't open %s pin %lld",
                          RESEALED[t].table, rows[i].pin);
            }
            break;
        }
        str_to_lower(lower, sizeof(lower), plaintext);
        ok = encrypt_field_with(new_keys, plaintext, sealed, sizeof(sealed)) == 0 &&
             (!RESEALED[t].indexed || hash_field_with(new_keys, lower, index, sizeof(index)) == 0);
        OPENSSL_cleanse(plaintext, sizeof(plaintext));
        OPENSSL_cleanse(lower, sizeof(lower));
        if (!ok) break;

        db_stmt_t *stmt = NULL;
        if (db_prepare(db, &stmt, RESEALED[t].update) != 0) break;
        int key_at = 2;
        db_bind_text(stmt, 1, sealed, -1);
        if (RESEALED[t].indexed) db_bind_text(stmt, key_at++, index, -1);
        if (RESEALED[t].by_id) db_bind_blob(stmt, key_at, rows[i].id, 16);
        else db_bind_int64(stmt, key_at, rows[i].pin);
        int rc = db_step(stmt);
        db_finalize(stmt);
        if (rc != DB_DONE) {
            log_error("Failed to write %s", RESEALED[t].table);
            break;
        }
        done++;
    }

    int all = done == count;
    free_rows(rows, count);
    return all ? done : -1;
}

/* The signing keys: e1: values, current and prior, re-sealed in both tables.
   One stored in plaintext is left as it is. Returns the values done, or -1. */
static int reseal_signing_keys(db_handle_t *db, const encrypt_keys_t *old_keys,
                               const encrypt_keys_t *new_keys) {
    static const struct { const char *table, *select, *update; } TABLES[] = {
        { TBL_AUTH_REQUEST_SIGNING,
          "SELECT current_secret, prior_secret FROM " TBL_AUTH_REQUEST_SIGNING,
          "UPDATE " TBL_AUTH_REQUEST_SIGNING " SET current_secret = " P"1, prior_secret = " P"2 "
          "WHERE singleton = " BOOL_TRUE },
        { TBL_ACCESS_TOKEN_SIGNING,
          "SELECT current_private_key, prior_private_key FROM " TBL_ACCESS_TOKEN_SIGNING,
          "UPDATE " TBL_ACCESS_TOKEN_SIGNING " SET current_private_key = " P"1, "
          "prior_private_key = " P"2 WHERE singleton = " BOOL_TRUE },
    };

    int done = 0;
    for (size_t t = 0; t < sizeof(TABLES) / sizeof(TABLES[0]); t++) {
        db_result_t *row = NULL;
        if (db_query(db, &row, "%s", TABLES[t].select) != 0) {
            log_error("Failed to read %s", TABLES[t].table);
            return -1;
        }
        if (db_result_row_count(row) != 1) {  /* no keys made yet */
            db_result_free(row);
            continue;
        }

        char resealed[2][520];
        const char *values[2];
        int failed = 0;
        for (int c = 0; c < 2 && !failed; c++) {
            const char *stored = db_result_get(row, 0, c);
            values[c] = stored;
            if (!stored || strncmp(stored, "e1:", 3) != 0) continue;

            char plaintext[ENCRYPT_FIELD_MAX_LENGTH + 1];
            memcpy(resealed[c], "e1:", 3);
            failed = decrypt_field_with(old_keys, stored + 3, plaintext, sizeof(plaintext)) != 0 ||
                     encrypt_field_with(new_keys, plaintext, resealed[c] + 3,
                                        sizeof(resealed[c]) - 3) != 0;
            OPENSSL_cleanse(plaintext, sizeof(plaintext));
            if (failed) {
                log_error("encryption_key_previous doesn't open %s's %s key",
                          TABLES[t].table, c == 0 ? "current" : "prior");
            } else {
                values[c] = resealed[c];
                done++;
            }
        }

        db_stmt_t *stmt = NULL;
        if (!failed && db_prepare(db, &stmt, TABLES[t].update) == 0) {
            db_bind_text_or_null(stmt, 1, values[0]);
            db_bind_text_or_null(stmt, 2, values[1]);
            failed = db_step(stmt) != DB_DONE;
            db_finalize(stmt);
        } else {
            failed = 1;
        }
        OPENSSL_cleanse(resealed, sizeof(resealed));
        db_result_free(row);
        if (failed) return -1;
    }
    return done;
}

/* How many of the re-sealed tables' history tables have rows, made before the
   re-key and sealed under the old key. Only user_account, user_email and
   user_mfa have history (the others aren't keyed by pin). */
static int history_holding_old_values(db_handle_t *db, db_type_t type) {
    static const char *tables[] = { "user_account", "user_email", "user_mfa" };
    int holding = 0;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char exists_sql[200], rows_sql[200];
        if (type == DB_TYPE_SQLITE) {
            snprintf(exists_sql, sizeof(exists_sql), "SELECT count(*) FROM sqlite_master "
                     "WHERE type = 'table' AND name = 'history__%s'", tables[i]);
            snprintf(rows_sql, sizeof(rows_sql),
                     "SELECT EXISTS (SELECT 1 FROM \"history__%s\")", tables[i]);
        } else {
            snprintf(exists_sql, sizeof(exists_sql), "SELECT count(*) FROM pg_tables "
                     "WHERE schemaname = 'security_history' AND tablename = '%s'", tables[i]);
            snprintf(rows_sql, sizeof(rows_sql),
                     "SELECT EXISTS (SELECT 1 FROM security_history.\"%s\")", tables[i]);
        }
        db_result_t *result = NULL;
        int exists = db_query(db, &result, "%s", exists_sql) == 0 &&
                     db_result_row_count(result) == 1 && atoi(db_result_get(result, 0, 0)) > 0;
        db_result_free(result);
        result = NULL;
        if (exists && db_query(db, &result, "%s", rows_sql) == 0 &&
            db_result_row_count(result) == 1) {
            const char *v = db_result_get(result, 0, 0);
            holding += v && (v[0] == '1' || v[0] == 't');
        }
        db_result_free(result);
    }
    return holding;
}

/* What --rekey rewrites on PostgreSQL: the tables it re-sealed; encryption_params,
   whose replaced row holds the old salt; and pg_statistic, where planner
   statistics replaced or dropped are dead rows */
static const char *const RESCRUBBED[] = {
    TBL_USER_ACCOUNT, TBL_USER_EMAIL, TBL_PASSWORDLESS_LOGIN_TOKEN, TBL_USER_MFA,
    TBL_AUTH_REQUEST_SIGNING, TBL_ACCESS_TOKEN_SIGNING, TBL_ENCRYPTION_PARAMS,
    "pg_catalog.pg_statistic",
};
#define RESCRUBBED_COUNT (sizeof(RESCRUBBED) / sizeof(RESCRUBBED[0]))

/* The sealed columns and blind indexes, as pg_stats names them. Planner
   statistics hold a sample of a column's values in pg_statistic, which no
   rewrite reaches while it's live, so schema.sql keeps these out of them. */
static const char SEALED_COLUMNS[] =
    "'" TBL_USER_ACCOUNT ".username', '" TBL_USER_ACCOUNT ".username_hash', "
    "'" TBL_USER_EMAIL ".email_address', '" TBL_USER_EMAIL ".email_hash', "
    "'" TBL_PASSWORDLESS_LOGIN_TOKEN ".email_address', '" TBL_USER_MFA ".secret', "
    "'" TBL_AUTH_REQUEST_SIGNING ".current_secret', '" TBL_AUTH_REQUEST_SIGNING ".prior_secret', "
    "'" TBL_ACCESS_TOKEN_SIGNING ".current_private_key', "
    "'" TBL_ACCESS_TOKEN_SIGNING ".prior_private_key'";

/* Which sealed columns have planner statistics, comma-separated into out.
   Returns how many, or -1. */
static int pg_sealed_statistics(db_handle_t *db, char *out, size_t size) {
    db_result_t *result = NULL;
    if (db_query(db, &result, "SELECT schemaname || '.' || tablename || '.' || attname "
                 "FROM pg_stats WHERE schemaname || '.' || tablename || '.' || attname IN (%s) "
                 "ORDER BY 1", SEALED_COLUMNS) != 0) {
        return -1;
    }
    size_t pos = 0;
    out[0] = '\0';
    int count = db_result_row_count(result);
    for (int i = 0; i < count; i++) {
        str_appendf(out, size, &pos, "%s%s", i ? ", " : "", db_result_get(result, i, 0));
    }
    db_result_free(result);
    return count;
}

int maintenance_rekey(db_handle_t *db, db_type_t type, const encrypt_keys_t *old_keys,
                      const encrypt_keys_t *new_keys, const encrypt_params_t *new_params,
                      rekey_report_t *out) {
    if (!db || !old_keys || !new_keys || !new_params || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* What writes history for the re-sealed tables, saved to be put back exactly:
       SQLite, the history triggers' SQL; PostgreSQL, the before-update functions'
       definitions (the re-key only updates) */
    db_result_t *saved = NULL;
    const char *saved_sql = type == DB_TYPE_SQLITE
        ? "SELECT NULL, name, sql FROM sqlite_master WHERE type = 'trigger' "
          "AND tbl_name IN ('user_account', 'user_email', 'passwordless_login_token', 'user_mfa') "
          "AND sql LIKE '%INSERT INTO \"history\\_\\_%' ESCAPE '\\'"
        : "SELECT n.nspname, p.proname, pg_get_functiondef(p.oid) FROM pg_proc p "
          "JOIN pg_namespace n ON n.oid = p.pronamespace "
          "WHERE n.nspname IN ('security_history', 'session_history', 'logging_history', "
          "'lookup_history') AND p.proname IN ('tg_fn_user_account_before_update', "
          "'tg_fn_user_email_before_update', 'tg_fn_passwordless_login_token_before_update', "
          "'tg_fn_user_mfa_before_update')";
    if (db_query(db, &saved, "%s", saved_sql) != 0) {
        log_error("Failed to read the history triggers of the re-sealed tables");
        return -1;
    }

    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin the re-key");
        db_result_free(saved);
        return -1;
    }

    int failed = 0;
    for (int i = 0; i < db_result_row_count(saved) && !failed; i++) {
        if (type == DB_TYPE_SQLITE) {
            failed = drop(db, "DROP TRIGGER %s", NULL, db_result_get(saved, i, 1)) != 0;
        } else {
            char quoted_schema[160], quoted_name[160], sql[512];
            quote_ident(quoted_schema, sizeof(quoted_schema), db_result_get(saved, i, 0));
            quote_ident(quoted_name, sizeof(quoted_name), db_result_get(saved, i, 1));
            snprintf(sql, sizeof(sql),
                     "CREATE OR REPLACE FUNCTION %s.%s() RETURNS trigger LANGUAGE plpgsql "
                     "AS $$ BEGIN RETURN NEW; END $$", quoted_schema, quoted_name);
            failed = db_execute_direct(db, sql) != 0;
            if (failed) {
                log_error("Failed to set history aside for the run. On a PostgreSQL hardened per "
                          "setup_reference.sql, grant the owner role to the login role for the "
                          "run (grant auth_dbo to auth_service), and revoke it after.");
            }
        }
    }

    int *counts[] = { &out->usernames, &out->addresses, &out->passwordless, &out->mfa_secrets };
    for (size_t t = 0; t < RESEALED_COUNT && !failed; t++) {
        int done = reseal_table(db, t, old_keys, new_keys);
        failed = done < 0;
        if (!failed) *counts[t] = done;
    }
    if (!failed) {
        out->signing_keys = reseal_signing_keys(db, old_keys, new_keys);
        failed = out->signing_keys < 0;
    }
    if (!failed) {
        failed = encryption_params_store(db, new_params) != 0;
    }

    /* History written as before, from here on */
    for (int i = 0; i < db_result_row_count(saved) && !failed; i++) {
        failed = db_execute_direct(db, db_result_get(saved, i, 2)) != 0;
        if (failed) log_error("Failed to put back %s", db_result_get(saved, i, 1));
    }
    db_result_free(saved);

    if (failed || db_execute_trusted(db, "COMMIT") != 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_error("The re-key was rolled back: nothing changed");
        memset(out, 0, sizeof(*out));
        return -1;
    }

    /* History made before still holds old-key values */
    out->history_tables = history_holding_old_values(db, type);

    /* The replaced old-key ciphertext is still in the files, and so are the old
       blind indexes in the old index entries */
    if (type == DB_TYPE_SQLITE) {
        if (sqlite_scrub(db) != 0) {
            log_error("Re-keyed, but the file may still hold old-key values (VACUUM failed, or "
                      "another connection held the -wal file): with every instance stopped, run "
                      "VACUUM, then PRAGMA wal_checkpoint(TRUNCATE)");
            return -2;
        }
    } else {
        int kept = pg_rewrite(db, RESCRUBBED, RESCRUBBED_COUNT);
        if (kept != 0) {
            log_error("Re-keyed, but not scrubbed: the replaced values are still in dead tuples, and "
                      "the old blind indexes in old index entries. The run's role may not VACUUM "
                      "these tables (on a deployment hardened per setup_reference.sql, grant "
                      "auth_dbo to auth_service for the run). As the tables' owner, run VACUUM FULL "
                      "on user_account, user_email, passwordless_login_token, user_mfa, both "
                      "signing tables and encryption_params; as the database's, on "
                      "pg_catalog.pg_statistic.");
        }
        char columns[640];
        int sampled = pg_sealed_statistics(db, columns, sizeof(columns));
        if (sampled < 0) {
            log_error("Re-keyed, but couldn't read which sealed columns have planner statistics");
        } else if (sampled > 0) {
            log_error("Re-keyed, but not scrubbed: pg_statistic keeps a sample of %s, which may be "
                      "under the old key (planner statistics, which no rewrite reaches). Set "
                      "each one's statistics target to 0 and change it to its own type, which "
                      "drops its sample, then run --rekey again (sql/README.md, --rekey).",
                      columns);
        }
        if (kept != 0 || sampled != 0) return -2;
    }
    return 0;
}
