#ifndef DB_POOL_H
#define DB_POOL_H

#include "db/db.h"
#include <stddef.h>

/*
 * Database Connection Pool
 *
 * Thread-local connection pool for worker threads.
 * Each worker gets its own connection stored in thread-local storage.
 */

/*
 * Initialize connection pool
 *
 * Creates N connections (one per worker thread).
 * Must be called before starting worker threads.
 *
 * Parameters:
 *   - num_workers: Number of worker threads
 *   - type: Database type (SQLite or PostgreSQL)
 *   - connection_string: Connection string for db_connect
 *
 * Returns: 0 on success, negative on error
 */
int db_pool_init(size_t num_workers, db_type_t type, const char *connection_string);

/*
 * Get connection for current thread
 *
 * Returns thread-local database connection.
 * Must be called from worker thread after db_pool_init().
 *
 * Returns: Database handle, or NULL if not initialized
 */
db_handle_t *db_pool_get_connection(void);

/*
 * Set connection for current thread
 *
 * Internal function used during pool initialization.
 * Worker threads should use db_pool_get_connection() instead.
 */
void db_pool_set_connection(db_handle_t *db);

/*
 * Get connection by index
 *
 * Used by worker threads to bind themselves to a specific connection.
 * Index must be < num_workers passed to db_pool_init().
 *
 * Returns: Database handle, or NULL if index out of bounds
 */
db_handle_t *db_pool_get_connection_by_index(size_t index);

/*
 * Shutdown connection pool
 *
 * Closes all connections and frees resources.
 */
void db_pool_shutdown(void);

#endif /* DB_POOL_H */
