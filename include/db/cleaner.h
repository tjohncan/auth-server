#ifndef DB_CLEANER_H
#define DB_CLEANER_H

#include "db/db.h"
#include "util/config.h"
#include <pthread.h>

/*
 * Database Cleaner - Background Thread for Purging Transient Data
 *
 * Continuously purges old records from high-volume tables (sessions, tokens,
 * usage logs, history tables) to prevent unbounded database growth.
 *
 * Design:
 * - Single background thread with dedicated DB connection (NOT from pool)
 * - Randomized table rotation to prevent thundering herd in horizontal scaling
 * - Small batch deletes (gentle on database, brief locks)
 * - Incremental vacuum (SQLite) / regular vacuum (PostgreSQL) to reclaim space
 * - Graceful shutdown via condition variable (interruptible sleep)
 */

typedef struct {
    /* Database connection info (cleaner creates its own connection) */
    db_type_t db_type;
    const char *connection_string;

    /* Operational parameters */
    int enabled;                           /* Master switch: 0=off, 1=on */
    int interval_seconds;                  /* Sleep between table checks */
    int batch_size;                        /* Rows deleted per batch */
    int sqlite_vacuum_pages;               /* SQLite: pages freed per vacuum iteration */
    int postgres_vacuum_enabled;           /* PostgreSQL: run VACUUM after deletes (0=off, 1=on) */

    /* Configurable retention periods (days) */
    int retention_usage_days;              /* Usage log tables (*_usage) */
    int retention_history_days;            /* History tables (history__* / *_history.*) */
    int retention_sessions_grace_days;     /* Browser sessions (grace after expected_expiry) */
    int retention_tokens_grace_days;       /* Tokens (grace after expected_expiry) */
} cleaner_config_t;

/*
 * Initialize cleaner config with defaults
 */
void cleaner_config_defaults(cleaner_config_t *config);

/*
 * Load cleaner config from main config_t structure
 * Extracts cleaner-specific settings from the global config
 */
void cleaner_config_from_main_config(cleaner_config_t *cleaner_cfg,
                                      const config_t *main_cfg);

/*
 * Start cleaner thread (returns 0 on success, -1 on failure)
 * The cleaner runs until cleaner_request_stop() is called.
 */
int cleaner_start(cleaner_config_t *config, pthread_t *thread_out);

/*
 * Signal cleaner to stop (non-blocking)
 * Call pthread_join() afterward to wait for thread exit
 */
void cleaner_request_stop(void);

#endif /* DB_CLEANER_H */
