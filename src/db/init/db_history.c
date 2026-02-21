/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "db/init/db_history.h"
#include "db/db_sql.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Maximum SQL buffer sizes */
#define MAX_SQL_SIZE (256 * 1024)  /* 256KB for DDL generation */
#define MAX_COLUMN_DEF_SIZE 1024
#define MAX_TABLE_NAME_SIZE 128

/* Safety margin for buffer overflow checks (enough for final statement + safety) */
#define DDL_BUFFER_SAFETY_MARGIN 4096

/*
 * Check if DDL buffer has enough space remaining
 * Returns 0 if safe, -1 if buffer would overflow
 */
#define CHECK_DDL_BUFFER_SPACE(offset, buffer_size, table_name) \
    do { \
        if ((offset) >= (buffer_size) - DDL_BUFFER_SAFETY_MARGIN) { \
            log_error("DDL buffer overflow risk for table: %s (offset=%d, size=%d)", \
                     (table_name), (offset), (buffer_size)); \
            return -1; \
        } \
    } while (0)

/*
 * Quote identifier for SQL (double-quote escaping)
 * SQLite and PostgreSQL both use double quotes for identifiers
 * Input identifier is trusted (from system catalogs), but we quote defensively
 */
static void quote_identifier(char *dest, size_t dest_size, const char *identifier) {
    size_t i = 0, j = 0;
    dest[j++] = '"';

    while (identifier[i] && j < dest_size - 2) {
        if (identifier[i] == '"') {
            /* Escape double quotes by doubling them */
            if (j < dest_size - 3) {
                dest[j++] = '"';
                dest[j++] = '"';
            }
        } else {
            dest[j++] = identifier[i];
        }
        i++;
    }

    dest[j++] = '"';
    dest[j] = '\0';
}

/*
 * Column definition structure
 */
typedef struct {
    char name[MAX_TABLE_NAME_SIZE];
    char type[MAX_TABLE_NAME_SIZE];
    int ordinal_position;
} column_def_t;

/*
 * Table list structure
 */
typedef struct {
    char schema_name[MAX_TABLE_NAME_SIZE];
    char table_name[MAX_TABLE_NAME_SIZE];
} table_info_t;

/* ============================================================================
 * SQLite Implementation
 * ============================================================================ */

#ifdef DB_BACKEND_SQLITE

/*
 * Get list of tables with "pin" as primary key in SQLite
 * Returns tables from the flat namespace (no real schemas)
 *
 * SECURITY NOTE: Table names come from sqlite_master (trusted system catalog).
 * These names are used in subsequent DDL generation without user input.
 */
static int get_eligible_tables_sqlite(db_handle_t *db, table_info_t **tables, int *table_count) {
    db_result_t *result = NULL;
    int rc;

    /* Query for tables that have a "pin" column as primary key
     * We need to check:
     * 1. Table exists in sqlite_master
     * 2. Table has a column named "pin"
     * 3. That column is the primary key
     *
     * SQLite stores table metadata in sqlite_master and pragma_table_info()
     */
    const char *sql =
        "SELECT DISTINCT m.name AS table_name "
        "FROM sqlite_master AS m "
        "WHERE m.type = 'table' "
        "AND m.name NOT LIKE 'sqlite_%' "
        "AND m.name NOT LIKE 'history__%' "
        "AND EXISTS ( "
        "  SELECT 1 FROM pragma_table_info(m.name) "
        "  WHERE name = 'pin' AND pk = 1 "
        ") "
        "ORDER BY m.name;";

    rc = db_query(db, &result, "%s", sql);
    if (rc != 0) {
        log_error("Failed to query eligible tables");
        return -1;
    }

    int row_count = db_result_row_count(result);
    if (row_count == 0) {
        log_info("No eligible tables found for history");
        db_result_free(result);
        *tables = NULL;
        *table_count = 0;
        return 0;
    }

    /* Allocate array for table info */
    table_info_t *table_list = calloc(row_count, sizeof(table_info_t));
    if (!table_list) {
        log_error("Failed to allocate memory for table list");
        db_result_free(result);
        return -1;
    }

    /* Populate table list */
    for (int i = 0; i < row_count; i++) {
        const char *table_name = db_result_get(result, i, 0);
        if (!table_name) {
            log_error("NULL table name in result");
            free(table_list);
            db_result_free(result);
            return -1;
        }

        /* SQLite doesn't have schemas, so schema_name is empty */
        table_list[i].schema_name[0] = '\0';
        snprintf(table_list[i].table_name, MAX_TABLE_NAME_SIZE, "%s", table_name);
    }

    db_result_free(result);
    *tables = table_list;
    *table_count = row_count;

    log_info("Found %d eligible tables for history", row_count);
    return 0;
}

/*
 * Get column definitions for a table in SQLite
 *
 * SECURITY NOTE: table_name comes from get_eligible_tables_sqlite() which reads
 * from sqlite_master (trusted system catalog). Column names/types returned by
 * pragma_table_info are also from the trusted system catalog.
 */
static int get_column_defs_sqlite(db_handle_t *db, const char *table_name,
                                  column_def_t **columns, int *column_count) {
    db_result_t *result = NULL;
    int rc;

    /* Use pragma_table_info to get column definitions */
    char sql[512];
    snprintf(sql, sizeof(sql),
            "SELECT name, type, cid FROM pragma_table_info('%s') ORDER BY cid;",
            table_name);

    rc = db_query(db, &result, "%s", sql);
    if (rc != 0) {
        log_error("Failed to query column definitions for table: %s", table_name);
        return -1;
    }

    int row_count = db_result_row_count(result);
    if (row_count == 0) {
        log_error("No columns found for table: %s", table_name);
        db_result_free(result);
        return -1;
    }

    /* Allocate array for column definitions */
    column_def_t *col_list = calloc(row_count, sizeof(column_def_t));
    if (!col_list) {
        log_error("Failed to allocate memory for column definitions");
        db_result_free(result);
        return -1;
    }

    /* Populate column list */
    for (int i = 0; i < row_count; i++) {
        const char *col_name = db_result_get(result, i, 0);
        const char *col_type = db_result_get(result, i, 1);
        const char *col_cid = db_result_get(result, i, 2);

        if (!col_name || !col_type || !col_cid) {
            log_error("NULL column metadata in result");
            free(col_list);
            db_result_free(result);
            return -1;
        }

        snprintf(col_list[i].name, MAX_TABLE_NAME_SIZE, "%s", col_name);
        snprintf(col_list[i].type, MAX_TABLE_NAME_SIZE, "%s", col_type);
        col_list[i].ordinal_position = atoi(col_cid);
    }

    db_result_free(result);
    *columns = col_list;
    *column_count = row_count;

    return 0;
}

/*
 * Create history table for SQLite
 * Table name format: history__<base_table_name>
 *
 * Returns:
 *   0 - Table created successfully
 *   1 - Table already exists (caller should skip trigger creation)
 *  -1 - Error occurred
 */
static int create_history_table_sqlite(db_handle_t *db, const char *base_table_name) {
    column_def_t *columns = NULL;
    int column_count = 0;
    char *ddl = NULL;
    int rc;

    /* Check if history table already exists */
    char history_table_name[MAX_TABLE_NAME_SIZE];
    snprintf(history_table_name, sizeof(history_table_name), "history__%s", base_table_name);

    db_result_t *check_result = NULL;
    rc = db_query(db, &check_result,
                 "SELECT name FROM sqlite_master WHERE type='table' AND name='%s';",
                 history_table_name);
    if (rc == 0 && db_result_row_count(check_result) > 0) {
        log_info("History table already exists: %s (skipping)", history_table_name);
        db_result_free(check_result);
        return 1;  /* Signal to caller: skip trigger creation */
    }
    if (check_result) {
        db_result_free(check_result);
    }

    log_info("Creating history table and triggers for: %s", base_table_name);

    /* Get column definitions from base table */
    rc = get_column_defs_sqlite(db, base_table_name, &columns, &column_count);
    if (rc != 0) {
        log_error("Failed to get column definitions for: %s", base_table_name);
        return -1;
    }

    /* Allocate buffer for DDL */
    ddl = malloc(MAX_SQL_SIZE);
    if (!ddl) {
        log_error("Failed to allocate DDL buffer");
        free(columns);
        return -1;
    }

    /* Build CREATE TABLE DDL */
    int offset = 0;
    char quoted_history_table[MAX_TABLE_NAME_SIZE * 2];
    char quoted_col[MAX_TABLE_NAME_SIZE * 2];

    quote_identifier(quoted_history_table, sizeof(quoted_history_table), history_table_name);

    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TABLE %s (\n", quoted_history_table);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Add history-specific columns */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      "  \"history_created_at\" TEXT NOT NULL DEFAULT (" NOW ")\n");
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", \"history_triggering_action_code\" TEXT NOT NULL\n");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Add all columns from base table */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s %s\n", quoted_col, columns[i].type);

        /* Check buffer every 10 columns to avoid excessive checks */
        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    /* Add history_pin as primary key */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", \"history_pin\" INTEGER PRIMARY KEY AUTOINCREMENT\n");

    /* Add constraint for action code */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", CONSTRAINT \"ck_history_%s_action_code\" CHECK (\"history_triggering_action_code\" IN ('U', 'D'))\n",
                      base_table_name);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset, ");");

    /* Execute DDL */
    rc = db_execute_direct(db, ddl);
    if (rc != 0) {
        log_error("Failed to create history table: %s", history_table_name);
        free(columns);
        free(ddl);
        return -1;
    }

    /* Create index on history_created_at for efficient cleanup */
    char index_ddl[512];
    snprintf(index_ddl, sizeof(index_ddl),
             "CREATE INDEX IF NOT EXISTS \"idx_%s_created_at\" ON \"%s\"(\"history_created_at\");",
             history_table_name, history_table_name);

    rc = db_execute_direct(db, index_ddl);
    if (rc != 0) {
        log_warn("Failed to create history table index: %s (non-fatal)", history_table_name);
        /* Non-fatal - continue */
    }

    free(columns);
    free(ddl);
    return 0;
}

/*
 * Create triggers for SQLite history table
 */
static int create_history_triggers_sqlite(db_handle_t *db, const char *base_table_name) {
    column_def_t *columns = NULL;
    int column_count = 0;
    char *trigger_ddl = NULL;
    int rc;

    /* Get column definitions */
    rc = get_column_defs_sqlite(db, base_table_name, &columns, &column_count);
    if (rc != 0) {
        log_error("Failed to get column definitions for triggers: %s", base_table_name);
        return -1;
    }

    /* Allocate buffer for trigger DDL */
    trigger_ddl = malloc(MAX_SQL_SIZE);
    if (!trigger_ddl) {
        log_error("Failed to allocate trigger DDL buffer");
        free(columns);
        return -1;
    }

    char history_table_name[MAX_TABLE_NAME_SIZE];
    char quoted_table[MAX_TABLE_NAME_SIZE * 2];
    char quoted_history_table[MAX_TABLE_NAME_SIZE * 2];
    char quoted_col[MAX_TABLE_NAME_SIZE * 2];

    snprintf(history_table_name, sizeof(history_table_name), "history__%s", base_table_name);
    quote_identifier(quoted_table, sizeof(quoted_table), base_table_name);
    quote_identifier(quoted_history_table, sizeof(quoted_history_table), history_table_name);

    /* ========================================================================
     * BEFORE UPDATE Trigger
     * ======================================================================== */
    int offset = 0;
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TRIGGER IF NOT EXISTS \"tg_%s_before_update\"\n", base_table_name);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEFORE UPDATE ON %s\n", quoted_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "FOR EACH ROW\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEGIN\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "  INSERT INTO %s (\n", quoted_history_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "    \"history_created_at\", \"history_triggering_action_code\"");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* List all column names */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "\n  ) VALUES (\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "    " NOW ", 'U'");

    /* List all OLD column values */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          ", OLD.%s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "\n  );\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "END;\n\n");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* ========================================================================
     * BEFORE DELETE Trigger
     * ======================================================================== */
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TRIGGER IF NOT EXISTS \"tg_%s_before_delete\"\n", base_table_name);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEFORE DELETE ON %s\n", quoted_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "FOR EACH ROW\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEGIN\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "  INSERT INTO %s (\n", quoted_history_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "    \"history_created_at\", \"history_triggering_action_code\"");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* List all column names */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "\n  ) VALUES (\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "    " NOW ", 'D'");

    /* List all OLD column values */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          ", OLD.%s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "\n  );\n");
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset, "END;");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Execute trigger DDL */
    rc = db_execute_direct(db, trigger_ddl);
    if (rc != 0) {
        log_error("Failed to create history triggers for: %s", base_table_name);
        free(columns);
        free(trigger_ddl);
        return -1;
    }

    free(columns);
    free(trigger_ddl);
    return 0;
}

#endif /* DB_BACKEND_SQLITE */

/* ============================================================================
 * PostgreSQL Implementation
 * ============================================================================ */

#ifdef DB_BACKEND_POSTGRESQL

/*
 * Get list of tables with "pin" as primary key in PostgreSQL
 * Returns tables from 'lookup' and 'security' schemas
 *
 * SECURITY NOTE: Table and schema names come from information_schema (trusted
 * system catalog). These names are used in subsequent DDL generation without user input.
 */
static int get_eligible_tables_postgresql(db_handle_t *db, table_info_t **tables, int *table_count) {
    db_result_t *result = NULL;
    int rc;

    /* Query for tables in lookup and security schemas with "pin" as PK */
    const char *sql =
        "SELECT t.table_schema, t.table_name "
        "FROM information_schema.tables AS t "
        "INNER JOIN information_schema.table_constraints AS tc "
        "  ON t.table_schema = tc.table_schema "
        "  AND t.table_name = tc.table_name "
        "  AND tc.constraint_type = 'PRIMARY KEY' "
        "INNER JOIN information_schema.key_column_usage AS kcu "
        "  ON tc.constraint_schema = kcu.constraint_schema "
        "  AND tc.constraint_name = kcu.constraint_name "
        "WHERE t.table_schema IN ('lookup', 'security') "
        "AND t.table_type = 'BASE TABLE' "
        "AND kcu.column_name = 'pin' "
        "ORDER BY t.table_schema, t.table_name;";

    rc = db_query(db, &result, "%s", sql);
    if (rc != 0) {
        log_error("Failed to query eligible tables");
        return -1;
    }

    int row_count = db_result_row_count(result);
    if (row_count == 0) {
        log_info("No eligible tables found for history");
        db_result_free(result);
        *tables = NULL;
        *table_count = 0;
        return 0;
    }

    /* Allocate array for table info */
    table_info_t *table_list = calloc(row_count, sizeof(table_info_t));
    if (!table_list) {
        log_error("Failed to allocate memory for table list");
        db_result_free(result);
        return -1;
    }

    /* Populate table list */
    for (int i = 0; i < row_count; i++) {
        const char *schema_name = db_result_get(result, i, 0);
        const char *table_name = db_result_get(result, i, 1);

        if (!schema_name || !table_name) {
            log_error("NULL schema/table name in result");
            free(table_list);
            db_result_free(result);
            return -1;
        }

        snprintf(table_list[i].schema_name, MAX_TABLE_NAME_SIZE, "%s", schema_name);
        snprintf(table_list[i].table_name, MAX_TABLE_NAME_SIZE, "%s", table_name);
    }

    db_result_free(result);
    *tables = table_list;
    *table_count = row_count;

    log_info("Found %d eligible tables for history", row_count);
    return 0;
}

/*
 * Get column definitions for a table in PostgreSQL
 *
 * SECURITY NOTE: schema_name and table_name come from get_eligible_tables_postgresql()
 * which reads from information_schema (trusted system catalog). Column names/types
 * returned are also from the trusted system catalog.
 */
static int get_column_defs_postgresql(db_handle_t *db, const char *schema_name,
                                     const char *table_name,
                                     column_def_t **columns, int *column_count) {
    db_result_t *result = NULL;
    int rc;
    char sql[1024];

    /* Query information_schema for column definitions */
    snprintf(sql, sizeof(sql),
            "SELECT column_name, "
            "CASE "
            "  WHEN data_type = 'character varying' THEN 'text' "
            "  WHEN data_type = 'timestamp without time zone' THEN 'timestamp' "
            "  WHEN data_type = 'USER-DEFINED' AND udt_name = 'uuid' THEN 'uuid' "
            "  WHEN data_type = 'ARRAY' THEN ltrim(udt_name, '_') || '[]' "
            "  ELSE data_type "
            "END AS data_type, "
            "ordinal_position "
            "FROM information_schema.columns "
            "WHERE table_schema = '%s' AND table_name = '%s' "
            "ORDER BY ordinal_position;",
            schema_name, table_name);

    rc = db_query(db, &result, "%s", sql);
    if (rc != 0) {
        log_error("Failed to query column definitions for: %s.%s", schema_name, table_name);
        return -1;
    }

    int row_count = db_result_row_count(result);
    if (row_count == 0) {
        log_error("No columns found for table: %s.%s", schema_name, table_name);
        db_result_free(result);
        return -1;
    }

    /* Allocate array for column definitions */
    column_def_t *col_list = calloc(row_count, sizeof(column_def_t));
    if (!col_list) {
        log_error("Failed to allocate memory for column definitions");
        db_result_free(result);
        return -1;
    }

    /* Populate column list */
    for (int i = 0; i < row_count; i++) {
        const char *col_name = db_result_get(result, i, 0);
        const char *col_type = db_result_get(result, i, 1);
        const char *col_pos = db_result_get(result, i, 2);

        if (!col_name || !col_type || !col_pos) {
            log_error("NULL column metadata in result");
            free(col_list);
            db_result_free(result);
            return -1;
        }

        snprintf(col_list[i].name, MAX_TABLE_NAME_SIZE, "%s", col_name);
        snprintf(col_list[i].type, MAX_TABLE_NAME_SIZE, "%s", col_type);
        col_list[i].ordinal_position = atoi(col_pos);
    }

    db_result_free(result);
    *columns = col_list;
    *column_count = row_count;

    return 0;
}

/*
 * Create history schema if it doesn't exist (PostgreSQL)
 */
static int ensure_history_schema_postgresql(db_handle_t *db, const char *base_schema) {
    char history_schema[MAX_TABLE_NAME_SIZE];
    snprintf(history_schema, sizeof(history_schema), "%s_history", base_schema);

    /* Check if schema already exists (avoids NOTICE from IF NOT EXISTS) */
    char check_sql[256];
    snprintf(check_sql, sizeof(check_sql),
             "SELECT 1 FROM information_schema.schemata WHERE schema_name = '%s';",
             history_schema);

    db_result_t *result = NULL;
    int rc = db_query(db, &result, "%s", check_sql);
    if (rc != 0) {
        log_error("Failed to check history schema: %s", history_schema);
        return -1;
    }

    if (db_result_row_count(result) > 0) {
        db_result_free(result);
        return 0;  /* Already exists */
    }
    db_result_free(result);

    char sql[256];
    snprintf(sql, sizeof(sql), "CREATE SCHEMA IF NOT EXISTS %s;", history_schema);

    rc = db_execute_direct(db, sql);
    if (rc != 0) {
        log_error("Failed to create history schema: %s", history_schema);
        return -1;
    }

    log_info("Created history schema: %s", history_schema);
    return 0;
}

/*
 * Create history table for PostgreSQL
 * Table name format: <schema>_history.<table_name>
 *
 * Returns:
 *   0 - Table created successfully
 *   1 - Table already exists (caller should skip trigger creation)
 *  -1 - Error occurred
 */
static int create_history_table_postgresql(db_handle_t *db, const char *base_schema,
                                           const char *base_table_name) {
    column_def_t *columns = NULL;
    int column_count = 0;
    char *ddl = NULL;
    int rc;

    char history_schema[MAX_TABLE_NAME_SIZE];
    snprintf(history_schema, sizeof(history_schema), "%s_history", base_schema);

    /* Check if history table already exists */
    db_result_t *check_result = NULL;
    char check_sql[512];
    snprintf(check_sql, sizeof(check_sql),
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = '%s' AND table_name = '%s';",
            history_schema, base_table_name);

    rc = db_query(db, &check_result, "%s", check_sql);
    if (rc == 0 && db_result_row_count(check_result) > 0) {
        log_info("History table already exists: %s.%s (skipping)", history_schema, base_table_name);
        db_result_free(check_result);
        return 1;  /* Signal to caller: skip trigger creation */
    }
    if (check_result) {
        db_result_free(check_result);
    }

    log_info("Creating history table and triggers for: %s.%s", base_schema, base_table_name);

    /* Get column definitions from base table */
    rc = get_column_defs_postgresql(db, base_schema, base_table_name, &columns, &column_count);
    if (rc != 0) {
        log_error("Failed to get column definitions for: %s.%s", base_schema, base_table_name);
        return -1;
    }

    /* Allocate buffer for DDL */
    ddl = malloc(MAX_SQL_SIZE);
    if (!ddl) {
        log_error("Failed to allocate DDL buffer");
        free(columns);
        return -1;
    }

    /* Build CREATE TABLE DDL */
    int offset = 0;
    char quoted_schema[MAX_TABLE_NAME_SIZE * 2];
    char quoted_table[MAX_TABLE_NAME_SIZE * 2];
    char quoted_col[MAX_TABLE_NAME_SIZE * 2];

    quote_identifier(quoted_schema, sizeof(quoted_schema), history_schema);
    quote_identifier(quoted_table, sizeof(quoted_table), base_table_name);

    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TABLE %s.%s (\n", quoted_schema, quoted_table);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Add history-specific columns */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      "  \"history_created_at\" TIMESTAMP NOT NULL DEFAULT current_timestamp\n");
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", \"history_triggering_action_code\" CHAR(1) NOT NULL\n");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Add all columns from base table */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s %s\n", quoted_col, columns[i].type);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    /* Add history_pin as primary key */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", \"history_pin\" BIGINT NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1 INCREMENT BY 1)\n");

    /* Add constraints */
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", CONSTRAINT \"pk_history_%s\" PRIMARY KEY (\"history_pin\")\n",
                      base_table_name);
    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset,
                      ", CONSTRAINT \"ck_history_%s_action_code\" CHECK (\"history_triggering_action_code\" IN ('U', 'D'))\n",
                      base_table_name);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    offset += snprintf(ddl + offset, MAX_SQL_SIZE - offset, ");");

    /* Execute DDL */
    rc = db_execute_direct(db, ddl);
    if (rc != 0) {
        log_error("Failed to create history table: %s.%s", history_schema, base_table_name);
        free(columns);
        free(ddl);
        return -1;
    }

    /* Create index on history_created_at for efficient cleanup */
    char index_ddl[512];
    snprintf(index_ddl, sizeof(index_ddl),
             "CREATE INDEX IF NOT EXISTS \"idx_%s_history_%s_created_at\" ON %s.\"%s\"(\"history_created_at\");",
             base_schema, base_table_name, quoted_schema, base_table_name);

    rc = db_execute_direct(db, index_ddl);
    if (rc != 0) {
        log_warn("Failed to create history table index: %s.%s (non-fatal)", history_schema, base_table_name);
        /* Non-fatal - continue */
    }

    free(columns);
    free(ddl);
    return 0;
}

/*
 * Create triggers for PostgreSQL history table
 * Uses trigger functions similar to the old utility schema approach
 */
static int create_history_triggers_postgresql(db_handle_t *db, const char *base_schema,
                                              const char *base_table_name, int fresh_schema) {
    column_def_t *columns = NULL;
    int column_count = 0;
    char *function_ddl = NULL;
    char *trigger_ddl = NULL;
    int rc;

    /* Get column definitions */
    rc = get_column_defs_postgresql(db, base_schema, base_table_name, &columns, &column_count);
    if (rc != 0) {
        log_error("Failed to get column definitions for triggers: %s.%s", base_schema, base_table_name);
        return -1;
    }

    char history_schema[MAX_TABLE_NAME_SIZE];
    char quoted_base_schema[MAX_TABLE_NAME_SIZE * 2];
    char quoted_history_schema[MAX_TABLE_NAME_SIZE * 2];
    char quoted_table[MAX_TABLE_NAME_SIZE * 2];
    char quoted_col[MAX_TABLE_NAME_SIZE * 2];

    snprintf(history_schema, sizeof(history_schema), "%s_history", base_schema);
    quote_identifier(quoted_base_schema, sizeof(quoted_base_schema), base_schema);
    quote_identifier(quoted_history_schema, sizeof(quoted_history_schema), history_schema);
    quote_identifier(quoted_table, sizeof(quoted_table), base_table_name);

    /* Allocate buffers for DDL */
    function_ddl = malloc(MAX_SQL_SIZE);
    trigger_ddl = malloc(MAX_SQL_SIZE);
    if (!function_ddl || !trigger_ddl) {
        log_error("Failed to allocate DDL buffers");
        free(columns);
        free(function_ddl);
        free(trigger_ddl);
        return -1;
    }

    /* ========================================================================
     * Create trigger function for UPDATE
     * ======================================================================== */
    int offset = 0;
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE OR REPLACE FUNCTION %s.\"tg_fn_%s_before_update\"() RETURNS TRIGGER AS $$\n",
                      quoted_history_schema, base_table_name);
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEGIN\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "  INSERT INTO %s.%s (\n", quoted_history_schema, quoted_table);
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "    \"history_created_at\", \"history_triggering_action_code\"");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* List all column names */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset, "\n  ) VALUES (\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "    current_timestamp, 'U'");

    /* List all OLD column values */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                          ", OLD.%s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset, "\n  );\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "  RETURN NEW;\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "END;\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "$$ LANGUAGE plpgsql;\n\n");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* ========================================================================
     * Create trigger function for DELETE
     * ======================================================================== */
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE OR REPLACE FUNCTION %s.\"tg_fn_%s_before_delete\"() RETURNS TRIGGER AS $$\n",
                      quoted_history_schema, base_table_name);
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEGIN\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "  INSERT INTO %s.%s (\n", quoted_history_schema, quoted_table);
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "    \"history_created_at\", \"history_triggering_action_code\"");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* List all column names */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                          ", %s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset, "\n  ) VALUES (\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "    current_timestamp, 'D'");

    /* List all OLD column values */
    for (int i = 0; i < column_count; i++) {
        quote_identifier(quoted_col, sizeof(quoted_col), columns[i].name);
        offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                          ", OLD.%s", quoted_col);

        if (i % 10 == 0) {
            CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);
        }
    }

    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset, "\n  );\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "  RETURN OLD;\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "END;\n");
    offset += snprintf(function_ddl + offset, MAX_SQL_SIZE - offset,
                      "$$ LANGUAGE plpgsql;");
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Execute function DDL */
    rc = db_execute_direct(db, function_ddl);
    if (rc != 0) {
        log_error("Failed to create history trigger functions for: %s.%s", base_schema, base_table_name);
        free(columns);
        free(function_ddl);
        free(trigger_ddl);
        return -1;
    }

    /* ========================================================================
     * Create triggers
     * ======================================================================== */
    offset = 0;
    if (!fresh_schema) {
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          "DROP TRIGGER IF EXISTS \"tg_%s_before_update\" ON %s.%s;\n",
                          base_table_name, quoted_base_schema, quoted_table);
    }
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TRIGGER \"tg_%s_before_update\"\n", base_table_name);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEFORE UPDATE ON %s.%s\n", quoted_base_schema, quoted_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "FOR EACH ROW EXECUTE FUNCTION %s.\"tg_fn_%s_before_update\"();\n\n",
                      quoted_history_schema, base_table_name);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    if (!fresh_schema) {
        offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                          "DROP TRIGGER IF EXISTS \"tg_%s_before_delete\" ON %s.%s;\n",
                          base_table_name, quoted_base_schema, quoted_table);
    }
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "CREATE TRIGGER \"tg_%s_before_delete\"\n", base_table_name);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "BEFORE DELETE ON %s.%s\n", quoted_base_schema, quoted_table);
    offset += snprintf(trigger_ddl + offset, MAX_SQL_SIZE - offset,
                      "FOR EACH ROW EXECUTE FUNCTION %s.\"tg_fn_%s_before_delete\"();",
                      quoted_history_schema, base_table_name);
    CHECK_DDL_BUFFER_SPACE(offset, MAX_SQL_SIZE, base_table_name);

    /* Execute trigger DDL */
    rc = db_execute_direct(db, trigger_ddl);
    if (rc != 0) {
        log_error("Failed to create history triggers for: %s.%s", base_schema, base_table_name);
        free(columns);
        free(function_ddl);
        free(trigger_ddl);
        return -1;
    }

    free(columns);
    free(function_ddl);
    free(trigger_ddl);
    return 0;
}

#endif /* DB_BACKEND_POSTGRESQL */

/* ============================================================================
 * Public API
 * ============================================================================ */

int db_init_history_tables(db_handle_t *db, db_type_t type, int fresh_schema) {
    if (!db) {
        log_error("Invalid database handle");
        return -1;
    }

    table_info_t *tables = NULL;
    int table_count = 0;
    int rc = 0;

#ifdef DB_BACKEND_SQLITE
    (void)fresh_schema;  /* Only used by PostgreSQL path */
    if (type == DB_TYPE_SQLITE) {
        /* Get eligible tables */
        rc = get_eligible_tables_sqlite(db, &tables, &table_count);
        if (rc != 0) {
            log_error("Failed to get eligible tables for SQLite");
            return -1;
        }

        /* Create history tables and triggers for each table */
        for (int i = 0; i < table_count; i++) {
            rc = create_history_table_sqlite(db, tables[i].table_name);
            if (rc < 0) {
                log_error("Failed to create history table for: %s", tables[i].table_name);
                free(tables);
                return -1;
            } else if (rc == 1) {
                /* Table already exists, skip trigger creation */
                continue;
            }

            rc = create_history_triggers_sqlite(db, tables[i].table_name);
            if (rc != 0) {
                log_error("Failed to create history triggers for: %s", tables[i].table_name);
                free(tables);
                return -1;
            }

            log_info("Created history table and triggers for: %s", tables[i].table_name);
        }
    }
#endif

#ifdef DB_BACKEND_POSTGRESQL
    if (type == DB_TYPE_POSTGRESQL) {
        /* Get eligible tables */
        rc = get_eligible_tables_postgresql(db, &tables, &table_count);
        if (rc != 0) {
            log_error("Failed to get eligible tables for PostgreSQL");
            return -1;
        }

        /* Create history schemas upfront (once per unique base schema) */
        char ensured_schemas[8][MAX_TABLE_NAME_SIZE];
        int ensured_count = 0;
        for (int i = 0; i < table_count; i++) {
            int already_ensured = 0;
            for (int j = 0; j < ensured_count; j++) {
                if (strcmp(ensured_schemas[j], tables[i].schema_name) == 0) {
                    already_ensured = 1;
                    break;
                }
            }
            if (!already_ensured && ensured_count < 8) {
                rc = ensure_history_schema_postgresql(db, tables[i].schema_name);
                if (rc != 0) {
                    free(tables);
                    return -1;
                }
                snprintf(ensured_schemas[ensured_count], MAX_TABLE_NAME_SIZE,
                         "%s", tables[i].schema_name);
                ensured_count++;
            }
        }

        /* Create history tables and triggers for each table */
        for (int i = 0; i < table_count; i++) {
            rc = create_history_table_postgresql(db, tables[i].schema_name,
                                                 tables[i].table_name);
            if (rc < 0) {
                log_error("Failed to create history table for: %s.%s",
                         tables[i].schema_name, tables[i].table_name);
                free(tables);
                return -1;
            } else if (rc == 1) {
                /* Table already exists, skip trigger creation */
                continue;
            }

            rc = create_history_triggers_postgresql(db, tables[i].schema_name,
                                                    tables[i].table_name, fresh_schema);
            if (rc != 0) {
                log_error("Failed to create history triggers for: %s.%s",
                         tables[i].schema_name, tables[i].table_name);
                free(tables);
                return -1;
            }

            log_info("Created history table and triggers for: %s.%s",
                    tables[i].schema_name, tables[i].table_name);
        }
    }
#endif

    if (tables) {
        free(tables);
    }

    log_info("History tables initialized successfully (%d tables)", table_count);
    return 0;
}
