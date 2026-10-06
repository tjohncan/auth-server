#ifndef MAINTENANCE_H
#define MAINTENANCE_H

#include "db/db.h"

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
 *     these (the server made them after schema.sql's reset role), so this needs
 *     no owner role, hardened or not.
 *   With rebuild set (enable_history_tables), empty history is then made again
 *   with the startup code, as the same role, so ownership is what the first
 *   start made. On a PostgreSQL hardened per setup_reference.sql that needs the
 *   owner role's privileges, for the duration of the run.
 * A failure rolls back, changing nothing.
 *
 * After COMMIT, on SQLite: VACUUM, then wal_checkpoint(TRUNCATE), so no page of
 * the dropped rows stays in the file or its -wal file. The checkpoint must
 * report no other connection busy. (PostgreSQL's DROP TABLE removes the files.)
 * WAL archives, replicas and backups keep what they had.
 *
 * Returns: 0; -1 if nothing changed (rolled back, or failed before);
 *          -2 if history is gone but the SQLite scrub after it failed
 */
int maintenance_drop_history(db_handle_t *db, db_type_t type, int rebuild,
                             drophistory_report_t *out);

#endif /* MAINTENANCE_H */
