#ifndef INSTANCE_LOCK_H
#define INSTANCE_LOCK_H

#include <stddef.h>
#include "db/db.h"

/*
 * The instance lock
 *
 * A running server holds it shared, a maintenance mode (--drophistory)
 * exclusively. A maintenance mode replaces what every running instance relies
 * on, so it runs only once every instance has stopped, and an instance doesn't
 * start while one runs. With several instances behind a load balancer, one left
 * running is the likely mistake, and its damage would be silent.
 *
 * SQLite: flock on a file of its own beside the database, <db_path>.lock.
 *   Not the database file: SQLite's locks on it are POSIX locks, which a
 *   process loses when it closes any descriptor of that file. An in-memory
 *   database has nothing to lock.
 * PostgreSQL: a session advisory lock in the database, held by one connection.
 *   Session locks don't survive a transaction-pooling proxy, so the server and
 *   the maintenance modes reach PostgreSQL directly.
 */

/*
 * instance_lock_path - The lock file for an SQLite database: <db_path>.lock
 *
 * Returns: 0, or -1 if db_path is in memory or out is too small
 */
int instance_lock_path(const char *db_path, char *out, size_t out_size);

/*
 * instance_lock_file - Take the SQLite lock, shared for a server or exclusive
 * for a maintenance mode, without waiting. The descriptor holds it until
 * instance_lock_file_release or exit. The file is created if missing, and
 * never removed: removing it would let a new taker lock a different file.
 *
 * Returns: 0 with *out_fd set; 1 if it's held the other way (an instance, for
 *          an exclusive take; a maintenance run, for a shared one); -1 on error
 */
int instance_lock_file(const char *lock_path, int exclusive, int *out_fd);
void instance_lock_file_release(int fd);

/*
 * instance_lock_pg - Take the PostgreSQL lock on this connection, shared for a
 * server or exclusive for a maintenance mode, without waiting. Held until the
 * connection ends.
 *
 * Returns: 0 taken, 1 held the other way, -1 on error
 */
int instance_lock_pg(db_handle_t *db, int exclusive);

/*
 * instance_lock_pg_held - Does this connection hold the shared lock? A
 * reconnect (after PostgreSQL restarts, say) starts a session without it.
 *
 * Returns: 1 held, 0 not, -1 on error (a dead connection, reconnected for the next call)
 */
int instance_lock_pg_held(db_handle_t *db);

#endif /* INSTANCE_LOCK_H */
