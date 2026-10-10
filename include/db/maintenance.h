#ifndef MAINTENANCE_H
#define MAINTENANCE_H

#include "db/db.h"
#include "crypto/encrypt.h"

/*
 * Maintenance modes: one-shot runs of the same binary against the database,
 * with every instance stopped (the caller holds the exclusive instance lock,
 * db/instance_lock.h).
 */

/* What --drophistory did */
typedef struct {
    int tables_dropped;     /* history tables */
    int triggers_dropped;   /* SQLite: triggers; PostgreSQL: trigger functions (each takes its trigger) */
    int rebuilt;            /* 1 if empty history was made again */
} drophistory_report_t;

/*
 * maintenance_drop_history - Remove every history table and what fills them
 *
 * After a key leak, or a change of mind about keeping history, the old values
 * the history tables copied should go; lowering retention only purges them
 * gradually. Dropping the tables alone isn't enough: their triggers live on the
 * main tables and would then fail every update and delete.
 *
 * In one transaction:
 *   SQLite: every trigger that inserts into a history__ table, then the tables.
 *   PostgreSQL: each history table and its tg_fn_* trigger functions, with
 *     CASCADE, which takes their triggers on the main tables (PostgreSQL prints
 *     a NOTICE for each). The history schemas stay. The login role owns all of
 *     these (the server made them after schema.sql's reset role), so dropping
 *     needs no owner role, hardened or not.
 *   With rebuild set (enable_history_tables), empty history is then made again
 *   with the startup code, as the same role, so ownership is what the first
 *   start made. On a PostgreSQL hardened per setup_reference.sql that needs the
 *   owner role's privileges, for the duration of the run.
 * A failure rolls back, changing nothing.
 *
 * After COMMIT, on SQLite: VACUUM, then wal_checkpoint(TRUNCATE), so no page of
 * the dropped rows stays in the file or its -wal file. The checkpoint must
 * report no other connection busy. PostgreSQL's DROP TABLE removes the files,
 * but each table's planner statistics, a sample of its columns, are then dead
 * rows in pg_statistic: VACUUM FULL rewrites it, which takes the database's
 * owner, proven by its file node changing. Every run does, dropping or not,
 * so running again finishes a run that couldn't. WAL archives, replicas and
 * backups keep what they had.
 *
 * Returns: 0; -1 if nothing changed (rolled back, or failed before);
 *          -2 if history is gone but the scrub after it failed
 */
int maintenance_drop_history(db_handle_t *db, db_type_t type, int rebuild,
                             drophistory_report_t *out);

/* What --rekey re-sealed, per table */
typedef struct {
    int usernames;       /* user_account, with username_hash */
    int addresses;       /* user_email, with email_hash */
    int passwordless;    /* passwordless_login_token */
    int mfa_secrets;     /* user_mfa */
    int signing_keys;    /* both signing tables, current and prior */
    int history_tables;  /* the re-sealed tables' history tables with rows: old-key values */
} rekey_report_t;

/*
 * maintenance_rekey - Re-seal everything sealed under old_keys with new_keys
 *
 * In one transaction:
 *   - Every sealed value is opened with old_keys and sealed again with
 *     new_keys: usernames, addresses (an account's and a passwordless link's),
 *     TOTP secrets, and the e1: signing keys, current and prior. A signing key
 *     stored in plaintext is left as it is.
 *   - Every blind index (username_hash, email_hash) is recomputed under
 *     new_keys from the opened value, lowercased as on every lookup.
 *   - new_params becomes the encryption_params row.
 *   - The re-key writes no history of its own: a history trigger keeps the row
 *     as it was, which would copy every old-key value into history again.
 *     SQLite: the re-sealed tables' history triggers are dropped and made
 *     again from their saved SQL. PostgreSQL: their before-update functions
 *     return without writing until they're restored from their saved
 *     definitions. Replacing a function takes its ownership, which the login
 *     role has, and CREATE on its schema, which on a deployment hardened per
 *     setup_reference.sql only the owner role has.
 *   - A value that won't open under old_keys rolls everything back, naming
 *     its table and row.
 * After COMMIT the old-key ciphertext the re-key replaced is still in the
 * files: SQLite's free space and -wal, PostgreSQL's dead tuples and old index
 * entries. SQLite: VACUUM, then a truncating checkpoint. PostgreSQL: VACUUM
 * FULL on the re-sealed tables, on encryption_params (the old salt) and on
 * pg_statistic, proven by each file node changing; the tables need their
 * owner, pg_statistic the database's (the owner role, on a deployment
 * hardened per setup_reference.sql). Planner statistics are a sample of a
 * column's values that no rewrite reaches while they're live, so schema.sql
 * keeps sealed columns out of them; one that has some isn't scrubbed.
 *
 * History made before stays sealed under the old key until it's purged:
 * --drophistory next (out->history_tables says how many tables hold some).
 *
 * Returns: 0; -1 if nothing changed; -2 if re-keyed but not scrubbed
 */
int maintenance_rekey(db_handle_t *db, db_type_t type, const encrypt_keys_t *old_keys,
                      const encrypt_keys_t *new_keys, const encrypt_params_t *new_params,
                      rekey_report_t *out);

#endif /* MAINTENANCE_H */
