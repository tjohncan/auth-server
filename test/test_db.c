#include "util/config.h"
#include "util/log.h"
#include "db/db.h"
#include "db/db_sql.h"
#include "db/init/db_init.h"
#include "db/init/db_history.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    log_init(LOG_INFO);
    log_info("Database Integration Test");

    /* Load configuration */
    log_info("Loading configuration...");
    config_t *config = config_load("auth.conf");
    if (!config) {
        log_error("Failed to load configuration");
        return 1;
    }

    log_info("Configuration loaded:");
    log_info("  Server: %s:%d (workers=%d)", config->host, config->port, config->workers);
    log_info("  Database type: %s", config->db_type == DB_TYPE_SQLITE ? "SQLite" : "PostgreSQL");
    log_info("  Database path: %s", config->db_path ? config->db_path : "(none)");
    log_info("  Schema dir: %s", config->schema_dir);

    /* Connect to database */
    log_info("Connecting to database...");
    db_handle_t *db = NULL;
    const char *connection_string = config->db_type == DB_TYPE_SQLITE
        ? config->db_path
        : ""; /* PostgreSQL connection string not yet implemented */

    int result = db_connect(&db, config->db_type, connection_string);
    if (result != 0) {
        log_error("Failed to connect to database");
        config_free(config);
        return 1;
    }

    log_info("Connected successfully");

    /* Initialize schema */
    log_info("Initializing schema...");
    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    result = db_init_schema(db, config->db_type, config->schema_dir, owner_role);
    if (result < 0) {
        log_error("Failed to initialize schema");
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    int fresh_schema = (result == 0);
    log_info("Schema initialized (%s)", fresh_schema ? "created" : "already existed");

    /* Initialize history tables if enabled */
    if (config->enable_history_tables) {
        result = db_init_history_tables(db, config->db_type, fresh_schema);
        if (result != 0) {
            log_error("Failed to initialize history tables");
            db_disconnect(db);
            config_free(config);
            return 1;
        }
    } else {
        log_info("History tables disabled in configuration");
    }

    /* Test query: List all tables */
    log_info("Testing query...");
    db_result_t *query_result = NULL;
#ifdef DB_BACKEND_SQLITE
    result = db_query(db, &query_result, "SELECT name FROM sqlite_master WHERE type='table';");
#endif
#ifdef DB_BACKEND_POSTGRESQL
    result = db_query(db, &query_result,
        "SELECT table_schema || '.' || table_name "
        "FROM information_schema.tables "
        "WHERE table_schema IN ('keys','security','session','lookup','logging') "
        "ORDER BY table_schema, table_name;");
#endif
    if (result != 0) {
        log_error("Query failed: %s", db_error(db));
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    int row_count = db_result_row_count(query_result);
    int col_count = db_result_column_count(query_result);
    log_info("Query returned %d rows, %d columns", row_count, col_count);

    /* Print table names */
    log_info("Tables in database:");
    for (int i = 0; i < row_count; i++) {
        const char *table_name = db_result_get(query_result, i, 0);
        log_info("  - %s", table_name ? table_name : "(null)");
    }

    db_result_free(query_result);

    /* Test prepared statement: Query grant_type lookup table */
    log_info("\nTesting prepared statement API...");

    const char *sql =
        "SELECT grant_type, description "
        "FROM " TBL_GRANT_TYPE " "
        "WHERE grant_type = " P"1";

    db_stmt_t *stmt = NULL;
    result = db_prepare(db, &stmt, sql);
    if (result != 0) {
        log_error("Prepare failed: %s", db_error(db));
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    log_info("Statement prepared successfully");

    /* Test 1: Query for 'authorization_code' */
    db_bind_text(stmt, 1, "authorization_code", -1);

    result = db_step(stmt);
    if (result == DB_ROW) {
        const char *grant_type = db_column_text(stmt, 0);
        const char *description = db_column_text(stmt, 1);
        log_info("Found: %s - %s", grant_type, description);
    } else if (result == DB_DONE) {
        log_warn("No rows returned for 'authorization_code'");
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Test 2: Reset and query for 'client_credentials' */
    db_reset(stmt);
    db_bind_text(stmt, 1, "client_credentials", -1);

    result = db_step(stmt);
    if (result == DB_ROW) {
        const char *grant_type = db_column_text(stmt, 0);
        const char *description = db_column_text(stmt, 1);
        log_info("Found: %s - %s", grant_type, description);
    } else if (result == DB_DONE) {
        log_warn("No rows returned for 'client_credentials'");
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Test 3: Query for non-existent grant type */
    db_reset(stmt);
    db_bind_text(stmt, 1, "nonexistent_grant", -1);

    result = db_step(stmt);
    if (result == DB_DONE) {
        log_info("Correctly returned no rows for nonexistent grant type");
    } else if (result == DB_ROW) {
        log_error("Unexpectedly found row for nonexistent grant type");
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    db_finalize(stmt);
    log_info("Prepared statement tests passed!");

    /* TODO: Add tests for db_bind_int(), db_bind_int64(), db_bind_blob(), db_bind_null(), and unbound parameter detection */

    /* Disconnect */
    log_info("\nDisconnecting...");
    db_disconnect(db);

    /* Cleanup */
    config_free(config);

    log_info("=== Database Integration Test Passed! ===");
    return 0;
}
