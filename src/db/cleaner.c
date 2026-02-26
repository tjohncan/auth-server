/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "db/cleaner.h"
#include "db/db.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/config.h"
#include "util/str.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

/* Maximum number of tables we can monitor */
#define MAX_TABLES 64

/* Hardcoded retention periods (days) - not configurable */
#define RETENTION_AUTH_CODE_DAYS 1           /* 24 hours */
#define RETENTION_PASSWORDLESS_TOKEN_DAYS 1  /* 24 hours */
#define RETENTION_EMAIL_VERIFICATION_DAYS 7
#define RETENTION_PASSWORD_RESET_DAYS 7
#define RETENTION_UNCONFIRMED_MFA_DAYS 7
#define RETENTION_USED_RECOVERY_CODE_DAYS 30
#define RETENTION_REVOKED_RECOVERY_SET_DAYS 30

/*
 * Table cleaner descriptor
 */
typedef struct {
    const char *table_name;        /* Schema-qualified (use TBL_* macro) */
    const char *description;       /* Human-readable for logging */
    const char *pk_column;         /* "id", "pin", "rowid", or "ctid" */
    const char *timestamp_column;  /* Column to compare against retention */
    const char *extra_where;       /* Additional WHERE clause or NULL */
    int retention_days;            /* Retention period in days */
    int configurable;              /* 1 = read from config, 0 = hardcoded */
} table_cleaner_t;

/* Global state */
static table_cleaner_t g_active_cleaners[MAX_TABLES];
static int g_num_active_cleaners = 0;
static pthread_mutex_t g_cleaner_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cleaner_cond = PTHREAD_COND_INITIALIZER;
static int g_cleaner_stop_flag = 0;

/*
 * Default config values
 */
void cleaner_config_defaults(cleaner_config_t *config) {
    config->db_type = DB_TYPE_SQLITE;
    config->connection_string = NULL;
    config->enabled = 1;
    config->interval_seconds = 10;
    config->batch_size = 1000;
    config->sqlite_vacuum_pages = 100;
    config->postgres_vacuum_enabled = 1;
    config->retention_usage_days = 60;
    config->retention_history_days = 90;
    config->retention_sessions_grace_days = 8;
    config->retention_tokens_grace_days = 8;
}

/*
 * Load cleaner config from main config
 */
void cleaner_config_from_main_config(cleaner_config_t *cleaner_cfg,
                                      const config_t *main_cfg) {
    cleaner_cfg->db_type = main_cfg->db_type;
    cleaner_cfg->enabled = main_cfg->cleaner_enabled;
    cleaner_cfg->interval_seconds = main_cfg->cleaner_interval_seconds;
    cleaner_cfg->batch_size = main_cfg->cleaner_batch_size;
    cleaner_cfg->sqlite_vacuum_pages = main_cfg->cleaner_sqlite_vacuum_pages;
    cleaner_cfg->postgres_vacuum_enabled = main_cfg->cleaner_postgres_vacuum_enabled;
    cleaner_cfg->retention_usage_days = main_cfg->retention_usage_logs_days;
    cleaner_cfg->retention_history_days = main_cfg->retention_history_days;
    cleaner_cfg->retention_sessions_grace_days = main_cfg->retention_sessions_grace_days;
    cleaner_cfg->retention_tokens_grace_days = main_cfg->retention_tokens_grace_days;
}

/*
 * Check if stop requested (without sleeping)
 */
static int cleaner_should_stop(void) {
    pthread_mutex_lock(&g_cleaner_mutex);
    int stop = g_cleaner_stop_flag;
    pthread_mutex_unlock(&g_cleaner_mutex);
    return stop;
}

/*
 * Interruptible sleep with condition variable
 * Returns 1 if stop requested, 0 on normal timeout
 */
static int cleaner_wait(int seconds) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += seconds;

    pthread_mutex_lock(&g_cleaner_mutex);
    while (!g_cleaner_stop_flag) {
        int rc = pthread_cond_timedwait(&g_cleaner_cond, &g_cleaner_mutex, &ts);
        if (rc == ETIMEDOUT) break;
    }
    int should_stop = g_cleaner_stop_flag;
    pthread_mutex_unlock(&g_cleaner_mutex);
    return should_stop;
}

/*
 * Signal cleaner to stop (called from main thread)
 */
void cleaner_request_stop(void) {
    pthread_mutex_lock(&g_cleaner_mutex);
    g_cleaner_stop_flag = 1;
    pthread_cond_signal(&g_cleaner_cond);
    pthread_mutex_unlock(&g_cleaner_mutex);
}

/*
 * Fisher-Yates shuffle for table rotation randomization
 */
static void shuffle_cleaners(table_cleaner_t *arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = crypto_random_int_range(0, i);
        table_cleaner_t tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

/*
 * Check if table exists in database
 */
static int table_exists(db_handle_t *db, const char *table_name) {
#ifdef DB_BACKEND_SQLITE
    /* SQLite: flat namespace */
    const char *sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=" P"1" " LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        return 0;
    }

    if (db_bind_text(stmt, 1, table_name, -1) != 0) {
        db_finalize(stmt);
        return 0;
    }

    int exists = (db_step(stmt) == DB_ROW);
    db_finalize(stmt);
    return exists;
#endif

#ifdef DB_BACKEND_POSTGRESQL
    /* PostgreSQL: schema.table format */
    const char *dot = strchr(table_name, '.');
    if (!dot) {
        log_warn("Cleaner: PostgreSQL table name missing schema: %s", table_name);
        return 0;
    }

    char schema[128], table[128];
    size_t schema_len = dot - table_name;
    if (schema_len >= sizeof(schema)) return 0;

    memcpy(schema, table_name, schema_len);
    schema[schema_len] = '\0';
    str_copy(table, sizeof(table), dot + 1);

    const char *sql =
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema=" P"1" " AND table_name=" P"2" " LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        return 0;
    }

    if (db_bind_text(stmt, 1, schema, -1) != 0 || db_bind_text(stmt, 2, table, -1) != 0) {
        db_finalize(stmt);
        return 0;
    }

    int exists = (db_step(stmt) == DB_ROW);
    db_finalize(stmt);
    return exists;
#endif
}

/*
 * Discover history tables and add to cleaner list
 */
static void discover_history_tables(db_handle_t *db, cleaner_config_t *config) {
#ifdef DB_BACKEND_SQLITE
    /* SQLite: history__* tables in flat namespace */
    const char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'history__%' ORDER BY name";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_warn("Cleaner: failed to discover history tables");
        return;
    }

    while (db_step(stmt) == DB_ROW) {
        const char *table_name = (const char *)db_column_text(stmt, 0);
        if (table_name && g_num_active_cleaners < MAX_TABLES) {
            char *name_copy = str_dup(table_name);
            if (name_copy) {
                g_active_cleaners[g_num_active_cleaners++] = (table_cleaner_t){
                    .table_name = name_copy,
                    .description = "History table",
                    .pk_column = "rowid",
                    .timestamp_column = "history_created_at",
                    .extra_where = NULL,
                    .retention_days = config->retention_history_days,
                    .configurable = 1
                };
                log_debug("Cleaner: discovered history table: %s", name_copy);
            }
        }
    }
    db_finalize(stmt);
#endif

#ifdef DB_BACKEND_POSTGRESQL
    /* PostgreSQL: *_history.* tables (schema LIKE '%_history') */
    const char *sql =
        "SELECT table_schema || '.' || table_name FROM information_schema.tables "
        "WHERE table_schema LIKE '%_history' AND table_type='BASE TABLE' "
        "ORDER BY table_schema, table_name";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_warn("Cleaner: failed to discover history tables");
        return;
    }

    while (db_step(stmt) == DB_ROW) {
        const char *full_table_name = (const char *)db_column_text(stmt, 0);
        if (full_table_name && g_num_active_cleaners < MAX_TABLES) {
            char *name_copy = str_dup(full_table_name);
            if (name_copy) {
                g_active_cleaners[g_num_active_cleaners++] = (table_cleaner_t){
                    .table_name = name_copy,
                    .description = "History table",
                    .pk_column = "ctid",  /* PostgreSQL system column */
                    .timestamp_column = "history_created_at",
                    .extra_where = NULL,
                    .retention_days = config->retention_history_days,
                    .configurable = 1
                };
                log_debug("Cleaner: discovered history table: %s", name_copy);
            }
        }
    }
    db_finalize(stmt);
#endif
}

/*
 * Build CHECK query (fast existence probe)
 * Returns 1 if query built successfully, 0 on error
 */
static int build_check_sql(char *buf, size_t bufsize, table_cleaner_t *cleaner) {
    /* Build time cutoff expression */
    char days_str[16];
    snprintf(days_str, sizeof(days_str), "%d", cleaner->retention_days);

    /* Unified query for both backends (DAYS_AGO macro handles the difference) */
    snprintf(buf, bufsize,
        "SELECT 1 FROM %s WHERE %s < " DAYS_AGO("%s") " %s LIMIT 1",
        cleaner->table_name,
        cleaner->timestamp_column,
        days_str,
        cleaner->extra_where ? cleaner->extra_where : "");

    return 1;
}

/*
 * Build PURGE query (batch delete)
 * Returns 1 if query built successfully, 0 on error
 */
static int build_purge_sql(char *buf, size_t bufsize, table_cleaner_t *cleaner, int batch_size) {
    /* Build time cutoff expression */
    char days_str[16];
    snprintf(days_str, sizeof(days_str), "%d", cleaner->retention_days);

    /* Unified query for both backends (DAYS_AGO macro handles the difference) */
    snprintf(buf, bufsize,
        "DELETE FROM %s WHERE %s IN ("
        "SELECT %s FROM %s WHERE %s < " DAYS_AGO("%s") " %s LIMIT %d)",
        cleaner->table_name, cleaner->pk_column,
        cleaner->pk_column, cleaner->table_name,
        cleaner->timestamp_column, days_str,
        cleaner->extra_where ? cleaner->extra_where : "",
        batch_size);

    return 1;
}

/*
 * Check if table has purgeable rows
 * Returns 1 if work exists, 0 if nothing to purge, -1 on error
 */
static int check_table(db_handle_t *db, table_cleaner_t *cleaner) {
    char sql[1024];
    if (!build_check_sql(sql, sizeof(sql), cleaner)) {
        return -1;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_warn("Cleaner: failed to prepare check query for %s", cleaner->table_name);
        return -1;
    }

    int has_work = (db_step(stmt) == DB_ROW);
    db_finalize(stmt);
    return has_work;
}

/*
 * Purge one batch of old rows
 * Returns 0 on success, -1 on error
 */
static int purge_batch(db_handle_t *db, table_cleaner_t *cleaner, int batch_size) {
    char sql[1024];
    if (!build_purge_sql(sql, sizeof(sql), cleaner, batch_size)) {
        return -1;
    }

    if (db_execute_trusted(db, sql) != 0) {
        log_warn("Cleaner: failed to purge from %s", cleaner->table_name);
        return -1;
    }

    return 0;
}

/*
 * Vacuum table to reclaim space
 */
static void vacuum_table(db_handle_t *db, cleaner_config_t *config,
                         table_cleaner_t *cleaner) {
#ifdef DB_BACKEND_SQLITE
    /* SQLite: incremental vacuum */
    (void)cleaner;  /* Not used in SQLite (global vacuum, not per-table) */
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA incremental_vacuum(%d)", config->sqlite_vacuum_pages);
    if (db_execute_trusted(db, sql) != 0) {
        log_debug("Cleaner: incremental_vacuum failed (may not be enabled)");
    }
#endif

#ifdef DB_BACKEND_POSTGRESQL
    /* PostgreSQL: regular VACUUM (only if enabled in config) */
    if (config->postgres_vacuum_enabled) {
        char sql[512];
        snprintf(sql, sizeof(sql), "VACUUM %s", cleaner->table_name);
        if (db_execute_trusted(db, sql) != 0) {
            log_debug("Cleaner: VACUUM failed for %s", cleaner->table_name);
        }
    }
#endif
}

/*
 * Initialize cleaner with static table list + dynamic history tables
 */
static void cleaner_init(db_handle_t *db, cleaner_config_t *config) {
    g_num_active_cleaners = 0;

    /* Define all possible static cleaners (14 tables) */
#ifdef DB_BACKEND_SQLITE
    #define PK_SUB "rowid"
#endif
#ifdef DB_BACKEND_POSTGRESQL
    #define PK_SUB "ctid"
#endif

    table_cleaner_t all_possible[] = {
        /* Tier 1: High-volume usage logs */
        {TBL_CLIENT_KEY_USAGE, "Client key usage log", PK_SUB, "authenticated_at", NULL,
         config->retention_usage_days, 1},
        {TBL_RESOURCE_SERVER_KEY_USAGE, "Resource server key usage log", PK_SUB, "authenticated_at", NULL,
         config->retention_usage_days, 1},
        {TBL_ORGANIZATION_KEY_USAGE, "Organization key usage log", PK_SUB, "authenticated_at", NULL,
         config->retention_usage_days, 1},
        {TBL_USER_MFA_USAGE, "MFA usage log", PK_SUB, "submitted_at", NULL,
         config->retention_usage_days, 1},

        /* Tier 2: High-volume sessions and tokens */
        {TBL_BROWSER, "Browser sessions", "id", "expected_expiry", NULL,
         config->retention_sessions_grace_days, 1},
        {TBL_ACCESS_TOKEN, "Access tokens", "id", "expected_expiry", NULL,
         config->retention_tokens_grace_days, 1},
        {TBL_REFRESH_TOKEN, "Refresh tokens", "id", "expected_expiry",
         " AND NOT EXISTS (SELECT 1 FROM " TBL_REFRESH_TOKEN " AS X "
         " WHERE X.origin_refresh_token_id = " TBL_REFRESH_TOKEN ".id) "
         " AND NOT EXISTS (SELECT 1 FROM " TBL_ACCESS_TOKEN
         " WHERE refresh_token_id = " TBL_REFRESH_TOKEN ".id)",
         config->retention_tokens_grace_days, 1},

        /* Tier 3: Medium-volume short-lived tokens */
        {TBL_AUTHORIZATION_CODE, "Authorization codes", "id", "expected_expiry",
         " AND NOT EXISTS (SELECT 1 FROM " TBL_REFRESH_TOKEN
         " WHERE authorization_code_id = " TBL_AUTHORIZATION_CODE ".id) "
         " AND NOT EXISTS (SELECT 1 FROM " TBL_ACCESS_TOKEN
         " WHERE authorization_code_id = " TBL_AUTHORIZATION_CODE ".id)",
         RETENTION_AUTH_CODE_DAYS, 0},
        {TBL_PASSWORDLESS_LOGIN_TOKEN, "Passwordless login tokens", "id", "expected_expiry", NULL,
         RETENTION_PASSWORDLESS_TOKEN_DAYS, 0},
        {TBL_EMAIL_VERIFICATION_TOKEN, "Email verification tokens", "id", "expected_expiry", NULL,
         RETENTION_EMAIL_VERIFICATION_DAYS, 0},
        {TBL_PASSWORD_RESET_TOKEN, "Password reset tokens", "id", "expected_expiry", NULL,
         RETENTION_PASSWORD_RESET_DAYS, 0},

        /* Tier 4: Low-volume cleanup */
        {TBL_USER_MFA, "Unconfirmed MFA methods", "pin", "created_at",
         " AND is_confirmed = " BOOL_FALSE, RETENTION_UNCONFIRMED_MFA_DAYS, 0},
        {TBL_RECOVERY_CODE, "Used recovery codes", "pin", "used_at",
         " AND is_used = " BOOL_TRUE, RETENTION_USED_RECOVERY_CODE_DAYS, 0},
        {TBL_RECOVERY_CODE_SET, "Revoked recovery code sets", "pin", "revoked_at",
         " AND is_active = " BOOL_FALSE " AND NOT EXISTS (SELECT 1 FROM " TBL_RECOVERY_CODE
         " WHERE recovery_code_set_pin = " TBL_RECOVERY_CODE_SET ".pin)",
         RETENTION_REVOKED_RECOVERY_SET_DAYS, 0},
    };

    int num_all = sizeof(all_possible) / sizeof(all_possible[0]);

    /* Filter: only include tables that exist */
    for (int i = 0; i < num_all; i++) {
        if (table_exists(db, all_possible[i].table_name)) {
            if (g_num_active_cleaners < MAX_TABLES) {
                g_active_cleaners[g_num_active_cleaners++] = all_possible[i];
                log_info("Cleaner: monitoring %s (retention: %d days)",
                         all_possible[i].description, all_possible[i].retention_days);
            }
        } else {
            log_debug("Cleaner: table not found, skipping: %s", all_possible[i].table_name);
        }
    }

    /* Auto-discover history tables */
    discover_history_tables(db, config);

    log_info("Cleaner: initialized with %d tables", g_num_active_cleaners);
}

/*
 * Main cleaner thread
 */
static void* cleaner_thread_main(void *arg) {
    cleaner_config_t *config = (cleaner_config_t *)arg;

    log_info("Cleaner: thread starting");

    /* Create dedicated DB connection (NOT from pool) */
    db_handle_t *db = NULL;
    if (db_connect(&db, config->db_type, config->connection_string) != 0) {
        log_error("Cleaner: failed to create database connection");
        free((char *)config->connection_string);
        free(config);
        return NULL;
    }

    /* Apply SQLite pragmas (same as worker connections) */
#ifdef DB_BACKEND_SQLITE
    if (config->db_type == DB_TYPE_SQLITE) {
        db_execute_trusted(db, "PRAGMA journal_mode = WAL;");
        db_execute_trusted(db, "PRAGMA synchronous = NORMAL;");
        db_execute_trusted(db, "PRAGMA foreign_keys = ON;");
    }
#endif

    /* Build dynamic table list */
    cleaner_init(db, config);

    if (g_num_active_cleaners == 0) {
        log_warn("Cleaner: no tables to monitor, exiting");
        db_disconnect(db);
        free((char *)config->connection_string);
        free(config);
        return NULL;
    }

    /* Initial shuffle */
    shuffle_cleaners(g_active_cleaners, g_num_active_cleaners);

    log_info("Cleaner: started (monitoring %d tables, interval=%ds, batch=%d)",
             g_num_active_cleaners, config->interval_seconds, config->batch_size);

    int current_idx = 0;
    int iteration = 0;

    /* Hourly stats */
    int total_purged = 0;
    int total_checks = 0;
    time_t last_stats_time = time(NULL);

    while (!cleaner_should_stop()) {
        /* Re-shuffle after completing full rotation */
        if (current_idx == 0 && iteration > 0) {
            shuffle_cleaners(g_active_cleaners, g_num_active_cleaners);
            log_debug("Cleaner: re-shuffled table order for next pass");
        }

        table_cleaner_t *cleaner = &g_active_cleaners[current_idx];
        total_checks++;

        /* Step 1: Quick check - any rows to purge? */
        int has_work = check_table(db, cleaner);

        if (has_work == 1) {
            /* Step 2: Purge small batch */
            if (purge_batch(db, cleaner, config->batch_size) == 0) {
                log_debug("Cleaner: purged batch from %s", cleaner->description);
                total_purged++;

                /* Step 3: Vacuum (reclaim space) */
                vacuum_table(db, config, cleaner);
            }
        } else if (has_work < 0) {
            log_warn("Cleaner: check failed for %s", cleaner->description);
        }

        /* Step 4: Move to next table */
        current_idx = (current_idx + 1) % g_num_active_cleaners;
        if (current_idx == 0) iteration++;

        /* Hourly stats summary */
        time_t now = time(NULL);
        if (now - last_stats_time >= 3600) {
            log_info("Cleaner: hourly stats: %d batches purged (%d tables checked %d times)",
                     total_purged, g_num_active_cleaners, total_checks);
            total_purged = 0;
            total_checks = 0;
            last_stats_time = now;
        }

        /* Step 5: Interruptible sleep */
        if (cleaner_wait(config->interval_seconds)) {
            break;  /* Stop flag set */
        }
    }

    log_info("Cleaner: stopped (purged %d batches total)", total_purged);
    db_disconnect(db);
    free((char *)config->connection_string);
    free(config);
    return NULL;
}

/*
 * Start cleaner thread
 */
int cleaner_start(cleaner_config_t *config, pthread_t *thread_out) {
    if (!config || !config->enabled) {
        log_info("Cleaner: disabled in configuration");
        return 0;  /* Not an error, just disabled */
    }

    if (!config->connection_string) {
        log_error("Cleaner: connection_string is NULL");
        return -1;
    }

    /* Allocate config copy for thread (thread will free it) */
    cleaner_config_t *config_copy = malloc(sizeof(cleaner_config_t));
    if (!config_copy) {
        log_error("Cleaner: failed to allocate config");
        return -1;
    }
    memcpy(config_copy, config, sizeof(cleaner_config_t));

    /* Own the connection string (caller's may be stack-allocated) */
    config_copy->connection_string = str_dup(config->connection_string);
    if (!config_copy->connection_string) {
        log_error("Cleaner: failed to duplicate connection_string");
        free(config_copy);
        return -1;
    }

    /* Start thread */
    if (pthread_create(thread_out, NULL, cleaner_thread_main, config_copy) != 0) {
        log_error("Cleaner: failed to create thread");
        free((char *)config_copy->connection_string);
        free(config_copy);
        return -1;
    }

    return 0;
}

