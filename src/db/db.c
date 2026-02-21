#include "db/db.h"
#include "util/log.h"
#include "util/str.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* Backend-specific includes (conditionally compiled) */
#ifdef DB_BACKEND_SQLITE
#include "sqlite3.h"
#endif

#ifdef DB_BACKEND_POSTGRESQL
#include <libpq-fe.h>
#endif

/* Maximum SQL statement length after formatting */
#define MAX_SQL_LENGTH 8192

/*
 * Database handle structure
 */
struct db_handle_t {
    db_type_t type;
    void *connection;  /* sqlite3* or PGconn* */
    char error_msg[512];
};

/*
 * Result set structure
 */
struct db_result_t {
    int row_count;
    int column_count;
    char **column_names;  /* Array of column names */
    char ***data;         /* 2D array: data[row][col] */
};

/*
 * Prepared statement structure
 */
struct db_stmt_t {
    db_type_t type;
    void *stmt;  /* sqlite3_stmt* (unused for PostgreSQL) */
    db_handle_t *db;  /* Parent database handle */
    char error_msg[512];
    int param_count;  /* Total parameters in query */
    int bound_count;  /* Number of parameters bound */
#ifdef DB_BACKEND_POSTGRESQL
    char *pg_query;             /* SQL string (duped from prepare) */
    char **pg_param_values;     /* Parameter value strings */
    int *pg_param_lengths;      /* Parameter lengths */
    int *pg_param_formats;      /* 0=text per param */
    char **pg_param_bufs;       /* Allocated buffers for int/blob conversions (to free) */
    PGresult *pg_result;        /* Current result set from PQexecParams */
    int pg_current_row;         /* Cursor position for step() emulation */
    int pg_total_rows;          /* PQntuples(result) */
    int pg_executed;            /* Has step() been called? */
    unsigned char *pg_blob_buf; /* Decoded blob buffer (reused per column_blob call) */
    size_t pg_blob_len;         /* Length of last decoded blob */
#endif
};

/*
 * Helper: Format SQL with variadic args
 *
 * WARNING: SQL INJECTION RISK
 * This function uses vsnprintf string formatting, NOT prepared statements.
 * It should ONLY be used for:
 * - Static SQL (schema, system queries)
 * - Trusted compile-time constants
 *
 * NEVER use with user input:
 *   BAD:  db_execute_trusted(db, "SELECT * FROM user WHERE name='%s'", user_input)
 *   GOOD: Use prepared statements via db_prepare/db_bind_XXX/db_step API
 */
static int format_sql(char *buffer, size_t size, const char *format, va_list args) {
    int result = vsnprintf(buffer, size, format, args);
    if (result < 0 || (size_t)result >= size) {
        log_error("SQL statement too long or formatting error");
        return -1;
    }
    return 0;
}

/* ============================================================================
 * SQLite Backend (conditionally compiled)
 * ============================================================================ */

#ifdef DB_BACKEND_SQLITE

/*
 * SQLite: Connect to database
 */
static int sqlite_connect(db_handle_t *db, const char *path) {
    sqlite3 *conn = NULL;
    int rc = sqlite3_open(path, &conn);

    if (rc != SQLITE_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite open failed: %s", sqlite3_errmsg(conn));
        log_error("%s", db->error_msg);
        if (conn) {
            sqlite3_close_v2(conn);
        }
        return -1;
    }

    db->connection = conn;
    log_info("Connected to SQLite database: %s", path);
    return 0;
}

/*
 * SQLite: Disconnect
 */
static int sqlite_disconnect(db_handle_t *db) {
    if (!db->connection) {
        return 0;
    }

    sqlite3 *conn = (sqlite3 *)db->connection;
    int rc = sqlite3_close_v2(conn);

    if (rc != SQLITE_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite close failed: %s", sqlite3_errmsg(conn));
        log_error("%s", db->error_msg);
        return -1;
    }

    db->connection = NULL;
    log_info("Disconnected from SQLite database");
    return 0;
}

/*
 * SQLite: Execute statement (no result)
 */
static int sqlite_execute(db_handle_t *db, const char *sql) {
    sqlite3 *conn = (sqlite3 *)db->connection;
    char *err_msg = NULL;

    int rc = sqlite3_exec(conn, sql, NULL, NULL, &err_msg);

    if (rc != SQLITE_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite execute failed: %s", err_msg ? err_msg : "unknown error");
        log_error("%s", db->error_msg);
        log_debug("Failed SQL: %s", sql);
        if (err_msg) {
            sqlite3_free(err_msg);
        }
        return -1;
    }

    return 0;
}

/*
 * Helper: Cleanup partially constructed result on error
 */
static void cleanup_partial_result(db_result_t *res, char ***temp_data,
                                   int rows_allocated, int col_count) {
    if (!res) return;

    /* Free temp_data rows */
    if (temp_data) {
        for (int r = 0; r < rows_allocated; r++) {
            if (temp_data[r]) {
                for (int c = 0; c < col_count; c++) {
                    free(temp_data[r][c]);
                }
                free(temp_data[r]);
            }
        }
        free(temp_data);
    }

    /* Free column names */
    if (res->column_names) {
        for (int i = 0; i < col_count; i++) {
            free(res->column_names[i]);
        }
        free(res->column_names);
    }

    free(res);
}

/*
 * SQLite: Query (with results)
 */
static int sqlite_query(db_handle_t *db, db_result_t **result, const char *sql) {
    sqlite3 *conn = (sqlite3 *)db->connection;
    sqlite3_stmt *stmt = NULL;

    /* Initialize result to NULL */
    *result = NULL;

    /* Prepare statement */
    int rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite prepare failed: %s", sqlite3_errmsg(conn));
        log_error("%s", db->error_msg);
        log_debug("Failed SQL: %s", sql);
        return -1;
    }

    /* Get column count */
    int col_count = sqlite3_column_count(stmt);

    /* Allocate result structure */
    db_result_t *res = calloc(1, sizeof(db_result_t));
    if (!res) {
        log_error("Failed to allocate result structure");
        sqlite3_finalize(stmt);
        return -1;
    }

    res->column_count = col_count;
    res->row_count = 0;

    /* Store column names */
    res->column_names = calloc(col_count, sizeof(char *));
    if (!res->column_names) {
        log_error("Failed to allocate column names");
        free(res);
        sqlite3_finalize(stmt);
        return -1;
    }

    for (int i = 0; i < col_count; i++) {
        const char *name = sqlite3_column_name(stmt, i);
        res->column_names[i] = str_dup(name ? name : "");
        if (!res->column_names[i]) {
            log_error("Failed to duplicate column name at index %d", i);
            cleanup_partial_result(res, NULL, 0, col_count);
            sqlite3_finalize(stmt);
            return -1;
        }
    }

    /* Count rows first */
    int capacity = 16;  /* Initial capacity */
    char ***temp_data = calloc(capacity, sizeof(char **));
    if (!temp_data) {
        log_error("Failed to allocate data array");
        cleanup_partial_result(res, NULL, 0, col_count);
        sqlite3_finalize(stmt);
        return -1;
    }

    /* Fetch all rows */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        /* Expand capacity if needed */
        if (res->row_count >= capacity) {
            capacity *= 2;
            char ***new_data = realloc(temp_data, capacity * sizeof(char **));
            if (!new_data) {
                log_error("Failed to expand data array");
                cleanup_partial_result(res, temp_data, res->row_count, col_count);
                sqlite3_finalize(stmt);
                return -1;
            }
            temp_data = new_data;
        }

        /* Allocate row */
        temp_data[res->row_count] = calloc(col_count, sizeof(char *));
        if (!temp_data[res->row_count]) {
            log_error("Failed to allocate row");
            cleanup_partial_result(res, temp_data, res->row_count, col_count);
            sqlite3_finalize(stmt);
            return -1;
        }

        /* Copy column values */
        for (int i = 0; i < col_count; i++) {
            const unsigned char *text = sqlite3_column_text(stmt, i);
            if (text) {
                temp_data[res->row_count][i] = str_dup((const char *)text);
                if (!temp_data[res->row_count][i]) {
                    log_error("Failed to duplicate column value at row %d, col %d",
                              res->row_count, i);
                    /* Increment row_count to ensure cleanup of partially filled row */
                    res->row_count++;
                    cleanup_partial_result(res, temp_data, res->row_count, col_count);
                    sqlite3_finalize(stmt);
                    return -1;
                }
            } else {
                temp_data[res->row_count][i] = NULL;
            }
        }

        res->row_count++;
    }

    if (rc != SQLITE_DONE) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite step failed: %s", sqlite3_errmsg(conn));
        log_error("%s", db->error_msg);
        cleanup_partial_result(res, temp_data, res->row_count, col_count);
        sqlite3_finalize(stmt);
        return -1;
    }

    /* Finalize statement */
    sqlite3_finalize(stmt);

    /* Store data in result */
    res->data = temp_data;
    *result = res;

    log_debug("Query returned %d rows, %d columns", res->row_count, res->column_count);
    return 0;
}

/*
 * SQLite: Prepare statement
 */
static int sqlite_prepare(db_handle_t *db, db_stmt_t **stmt, const char *sql) {
    sqlite3 *conn = (sqlite3 *)db->connection;
    sqlite3_stmt *sqlite_stmt = NULL;

    /* Prepare statement */
    int rc = sqlite3_prepare_v2(conn, sql, -1, &sqlite_stmt, NULL);
    if (rc != SQLITE_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                "SQLite prepare failed: %s", sqlite3_errmsg(conn));
        log_error("%s", db->error_msg);
        log_debug("Failed SQL: %s", sql);
        return -1;
    }

    /* Allocate statement handle */
    db_stmt_t *s = calloc(1, sizeof(db_stmt_t));
    if (!s) {
        log_error("Failed to allocate statement handle");
        sqlite3_finalize(sqlite_stmt);
        return -1;
    }

    s->type = db->type;
    s->stmt = sqlite_stmt;
    s->db = db;
    s->error_msg[0] = '\0';
    s->param_count = sqlite3_bind_parameter_count(sqlite_stmt);
    s->bound_count = 0;

    *stmt = s;
    return 0;
}

/*
 * SQLite: Bind text parameter
 */
static int sqlite_bind_text(db_stmt_t *stmt, int index, const char *value, int len) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    /* Use SQLITE_TRANSIENT to copy the string internally */
    int rc = sqlite3_bind_text(sqlite_stmt, index, value, len, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite bind_text failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    stmt->bound_count++;
    return 0;
}

/*
 * SQLite: Bind int parameter
 */
static int sqlite_bind_int(db_stmt_t *stmt, int index, int value) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    int rc = sqlite3_bind_int(sqlite_stmt, index, value);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite bind_int failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    stmt->bound_count++;
    return 0;
}

/*
 * SQLite: Bind int64 parameter
 */
static int sqlite_bind_int64(db_stmt_t *stmt, int index, long long value) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    int rc = sqlite3_bind_int64(sqlite_stmt, index, value);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite bind_int64 failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    stmt->bound_count++;
    return 0;
}

/*
 * SQLite: Bind blob parameter
 */
static int sqlite_bind_blob(db_stmt_t *stmt, int index, const void *value, int len) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    /* Use SQLITE_TRANSIENT to copy the data internally */
    int rc = sqlite3_bind_blob(sqlite_stmt, index, value, len, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite bind_blob failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    stmt->bound_count++;
    return 0;
}

/*
 * SQLite: Bind NULL parameter
 */
static int sqlite_bind_null(db_stmt_t *stmt, int index) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    int rc = sqlite3_bind_null(sqlite_stmt, index);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite bind_null failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    stmt->bound_count++;
    return 0;
}

/*
 * SQLite: Execute statement / fetch next row
 */
static int sqlite_step(db_stmt_t *stmt) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    /* Validate all parameters are bound */
    if (stmt->bound_count < stmt->param_count) {
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "Not all parameters bound: %d of %d bound",
                stmt->bound_count, stmt->param_count);
        log_error("%s", stmt->error_msg);
        return -1;
    }

    int rc = sqlite3_step(sqlite_stmt);

    if (rc == SQLITE_ROW) {
        return 100;  /* DB_ROW */
    } else if (rc == SQLITE_DONE) {
        return 101;  /* DB_DONE */
    } else {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite step failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }
}

/*
 * SQLite: Reset statement
 */
static int sqlite_reset(db_stmt_t *stmt) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;

    int rc = sqlite3_reset(sqlite_stmt);
    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite reset failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        return -1;
    }

    /* Reset bindings cleared, need to rebind parameters */
    stmt->bound_count = 0;

    return 0;
}

/*
 * SQLite: Get text column
 */
static const char *sqlite_column_text(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    return (const char *)sqlite3_column_text(sqlite_stmt, col);
}

/*
 * SQLite: Get int column
 */
static int sqlite_column_int(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    return sqlite3_column_int(sqlite_stmt, col);
}

/*
 * SQLite: Get int64 column
 */
static long long sqlite_column_int64(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    return sqlite3_column_int64(sqlite_stmt, col);
}

/*
 * SQLite: Get blob column
 */
static const void *sqlite_column_blob(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    return sqlite3_column_blob(sqlite_stmt, col);
}

/*
 * SQLite: Get column size in bytes
 */
static int sqlite_column_bytes(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    return sqlite3_column_bytes(sqlite_stmt, col);
}

/*
 * SQLite: Get column type
 */
static int sqlite_column_type(db_stmt_t *stmt, int col) {
    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    int sqlite_type = sqlite3_column_type(sqlite_stmt, col);

    /* Map SQLite types to our type constants */
    switch (sqlite_type) {
        case SQLITE_INTEGER: return DB_INTEGER;
        case SQLITE_FLOAT:   return DB_FLOAT;
        case SQLITE_TEXT:    return DB_TEXT;
        case SQLITE_BLOB:    return DB_BLOB;
        case SQLITE_NULL:    return DB_NULL;
        default:             return DB_NULL;
    }
}

/*
 * SQLite: Finalize statement
 */
static int sqlite_finalize(db_stmt_t *stmt) {
    if (!stmt || !stmt->stmt) {
        return 0;
    }

    sqlite3_stmt *sqlite_stmt = (sqlite3_stmt *)stmt->stmt;
    int rc = sqlite3_finalize(sqlite_stmt);

    if (rc != SQLITE_OK) {
        sqlite3 *conn = (sqlite3 *)stmt->db->connection;
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                "SQLite finalize failed: %s", sqlite3_errmsg(conn));
        log_error("%s", stmt->error_msg);
        free(stmt);
        return -1;
    }

    free(stmt);
    return 0;
}

#endif /* DB_BACKEND_SQLITE */

/* ============================================================================
 * PostgreSQL Backend (conditionally compiled)
 * ============================================================================ */

#ifdef DB_BACKEND_POSTGRESQL

/* PostgreSQL type OIDs for blob decoding */
#define PG_BOOL_OID    16
#define PG_BYTEA_OID   17
#define PG_INT8_OID    20
#define PG_INT4_OID    23
#define PG_TEXT_OID    25
#define PG_UUID_OID    2950

/*
 * Connect to PostgreSQL database
 */
static int pg_connect(db_handle_t *db, const char *connection_string) {
    PGconn *conn = PQconnectdb(connection_string);
    if (PQstatus(conn) != CONNECTION_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                 "PostgreSQL connection failed: %s", PQerrorMessage(conn));
        log_error("%s", db->error_msg);
        PQfinish(conn);
        return -1;
    }

    db->connection = conn;

    /* Force UTC for all timestamp operations on this connection.
     * The schema uses 'timestamp' (without time zone) columns, and C's
     * time(NULL) returns UTC epoch — so PG must interpret naive timestamps
     * as UTC to keep EXTRACT(EPOCH FROM ...) consistent. */
    PGresult *tz_result = PQexec(conn, "SET timezone = 'UTC'");
    if (PQresultStatus(tz_result) != PGRES_COMMAND_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                 "Failed to set timezone: %s", PQresultErrorMessage(tz_result));
        log_error("%s", db->error_msg);
        PQclear(tz_result);
        PQfinish(conn);
        db->connection = NULL;
        return -1;
    }
    PQclear(tz_result);

    log_debug("PostgreSQL connected to %s:%s/%s",
              PQhost(conn), PQport(conn), PQdb(conn));
    return 0;
}

/*
 * Disconnect from PostgreSQL database
 */
static int pg_disconnect(db_handle_t *db) {
    PGconn *conn = (PGconn *)db->connection;
    if (conn) {
        PQfinish(conn);
        db->connection = NULL;
    }
    return 0;
}

/*
 * Execute SQL directly (no parameters, no result set)
 */
static int pg_execute(db_handle_t *db, const char *sql) {
    PGconn *conn = (PGconn *)db->connection;
    PGresult *result = PQexec(conn, sql);
    ExecStatusType status = PQresultStatus(result);

    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                 "PostgreSQL execute failed: %s", PQresultErrorMessage(result));
        log_error("%s", db->error_msg);
        PQclear(result);
        return -1;
    }

    PQclear(result);
    return 0;
}

/*
 * Execute SQL and collect results into db_result_t
 */
static int pg_query(db_handle_t *db, const char *sql, db_result_t **out) {
    PGconn *conn = (PGconn *)db->connection;
    PGresult *pg_result = PQexec(conn, sql);
    ExecStatusType status = PQresultStatus(pg_result);

    if (status != PGRES_TUPLES_OK) {
        snprintf(db->error_msg, sizeof(db->error_msg),
                 "PostgreSQL query failed: %s", PQresultErrorMessage(pg_result));
        log_error("%s", db->error_msg);
        PQclear(pg_result);
        return -1;
    }

    int row_count = PQntuples(pg_result);
    int col_count = PQnfields(pg_result);

    /* Allocate result structure */
    db_result_t *result = calloc(1, sizeof(db_result_t));
    if (!result) {
        log_error("Failed to allocate result structure");
        PQclear(pg_result);
        return -1;
    }

    result->row_count = row_count;
    result->column_count = col_count;

    /* Column names */
    result->column_names = calloc(col_count, sizeof(char *));
    if (!result->column_names) {
        log_error("Failed to allocate column names");
        free(result);
        PQclear(pg_result);
        return -1;
    }

    for (int i = 0; i < col_count; i++) {
        result->column_names[i] = str_dup(PQfname(pg_result, i));
        if (!result->column_names[i]) {
            for (int j = 0; j < i; j++) free(result->column_names[j]);
            free(result->column_names);
            free(result);
            PQclear(pg_result);
            return -1;
        }
    }

    /* Row data */
    if (row_count > 0) {
        result->data = calloc(row_count, sizeof(char **));
        if (!result->data) {
            for (int i = 0; i < col_count; i++) free(result->column_names[i]);
            free(result->column_names);
            free(result);
            PQclear(pg_result);
            return -1;
        }

        for (int r = 0; r < row_count; r++) {
            result->data[r] = calloc(col_count, sizeof(char *));
            if (!result->data[r]) {
                log_error("Failed to allocate row data");
                db_result_free(result);
                PQclear(pg_result);
                return -1;
            }

            for (int c = 0; c < col_count; c++) {
                if (PQgetisnull(pg_result, r, c)) {
                    result->data[r][c] = NULL;
                } else {
                    result->data[r][c] = str_dup(PQgetvalue(pg_result, r, c));
                    if (!result->data[r][c]) {
                        log_error("Failed to duplicate cell value");
                        db_result_free(result);
                        PQclear(pg_result);
                        return -1;
                    }
                }
            }
        }
    }

    PQclear(pg_result);
    *out = result;
    return 0;
}

/*
 * Count maximum $N parameter placeholder in SQL string
 */
static int pg_count_params(const char *sql) {
    int max_param = 0;
    const char *p = sql;

    while ((p = strchr(p, '$')) != NULL) {
        p++;
        if (*p >= '1' && *p <= '9') {
            int n = 0;
            while (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                p++;
            }
            if (n > max_param) {
                max_param = n;
            }
        }
    }

    return max_param;
}

/*
 * Free parameter buffers allocated during binding
 */
static void pg_free_param_bufs(db_stmt_t *stmt) {
    if (!stmt->pg_param_bufs) return;
    for (int i = 0; i < stmt->param_count; i++) {
        free(stmt->pg_param_bufs[i]);
        stmt->pg_param_bufs[i] = NULL;
    }
}

/*
 * Clear parameter values (for reset/rebind)
 */
static void pg_clear_params(db_stmt_t *stmt) {
    pg_free_param_bufs(stmt);
    if (stmt->pg_param_values) {
        memset(stmt->pg_param_values, 0, stmt->param_count * sizeof(char *));
    }
    if (stmt->pg_param_lengths) {
        memset(stmt->pg_param_lengths, 0, stmt->param_count * sizeof(int));
    }
    if (stmt->pg_param_formats) {
        memset(stmt->pg_param_formats, 0, stmt->param_count * sizeof(int));
    }
}

/*
 * Prepare a PostgreSQL statement
 */
static int pg_prepare(db_handle_t *db, db_stmt_t **stmt_out, const char *sql) {
    int param_count = pg_count_params(sql);

    db_stmt_t *stmt = calloc(1, sizeof(db_stmt_t));
    if (!stmt) {
        log_error("Failed to allocate statement");
        return -1;
    }

    stmt->type = DB_TYPE_POSTGRESQL;
    stmt->db = db;
    stmt->param_count = param_count;
    stmt->bound_count = 0;
    stmt->pg_executed = 0;
    stmt->pg_current_row = -1;
    stmt->pg_total_rows = 0;
    stmt->pg_result = NULL;
    stmt->pg_blob_buf = NULL;
    stmt->pg_blob_len = 0;

    /* Duplicate SQL string */
    stmt->pg_query = str_dup(sql);
    if (!stmt->pg_query) {
        log_error("Failed to duplicate SQL");
        free(stmt);
        return -1;
    }

    /* Allocate parameter arrays */
    if (param_count > 0) {
        stmt->pg_param_values = calloc(param_count, sizeof(char *));
        stmt->pg_param_lengths = calloc(param_count, sizeof(int));
        stmt->pg_param_formats = calloc(param_count, sizeof(int));
        stmt->pg_param_bufs = calloc(param_count, sizeof(char *));

        if (!stmt->pg_param_values || !stmt->pg_param_lengths ||
            !stmt->pg_param_formats || !stmt->pg_param_bufs) {
            log_error("Failed to allocate parameter arrays");
            free(stmt->pg_query);
            free(stmt->pg_param_values);
            free(stmt->pg_param_lengths);
            free(stmt->pg_param_formats);
            free(stmt->pg_param_bufs);
            free(stmt);
            return -1;
        }
    }

    *stmt_out = stmt;
    return 0;
}

/*
 * Bind text parameter
 */
static int pg_bind_text(db_stmt_t *stmt, int index, const char *value, int len) {
    int idx = index - 1;  /* Convert 1-based to 0-based */
    if (idx < 0 || idx >= stmt->param_count) {
        log_error("Parameter index %d out of range (1-%d)", index, stmt->param_count);
        return -1;
    }

    /* Free any previous buffer for this param slot */
    free(stmt->pg_param_bufs[idx]);
    stmt->pg_param_bufs[idx] = NULL;

    if (len < 0) {
        /* Null-terminated string, store pointer directly */
        stmt->pg_param_values[idx] = (char *)value;
    } else {
        /* Explicit length: must copy and null-terminate */
        char *buf = malloc(len + 1);
        if (!buf) {
            log_error("Failed to allocate text param buffer");
            return -1;
        }
        memcpy(buf, value, len);
        buf[len] = '\0';
        stmt->pg_param_bufs[idx] = buf;
        stmt->pg_param_values[idx] = buf;
    }

    stmt->pg_param_lengths[idx] = 0;  /* Text format */
    stmt->pg_param_formats[idx] = 0;  /* Text format */
    stmt->bound_count++;
    return 0;
}

/*
 * Bind integer parameter (convert to text)
 */
static int pg_bind_int(db_stmt_t *stmt, int index, int value) {
    int idx = index - 1;
    if (idx < 0 || idx >= stmt->param_count) {
        log_error("Parameter index %d out of range (1-%d)", index, stmt->param_count);
        return -1;
    }

    char *buf = malloc(16);
    if (!buf) {
        log_error("Failed to allocate int param buffer");
        return -1;
    }

    snprintf(buf, 16, "%d", value);

    free(stmt->pg_param_bufs[idx]);
    stmt->pg_param_bufs[idx] = buf;
    stmt->pg_param_values[idx] = buf;
    stmt->pg_param_lengths[idx] = 0;
    stmt->pg_param_formats[idx] = 0;
    stmt->bound_count++;
    return 0;
}

/*
 * Bind 64-bit integer parameter (convert to text)
 */
static int pg_bind_int64(db_stmt_t *stmt, int index, long long value) {
    int idx = index - 1;
    if (idx < 0 || idx >= stmt->param_count) {
        log_error("Parameter index %d out of range (1-%d)", index, stmt->param_count);
        return -1;
    }

    char *buf = malloc(24);
    if (!buf) {
        log_error("Failed to allocate int64 param buffer");
        return -1;
    }

    snprintf(buf, 24, "%lld", value);

    free(stmt->pg_param_bufs[idx]);
    stmt->pg_param_bufs[idx] = buf;
    stmt->pg_param_values[idx] = buf;
    stmt->pg_param_lengths[idx] = 0;
    stmt->pg_param_formats[idx] = 0;
    stmt->bound_count++;
    return 0;
}

/*
 * Bind blob parameter
 * 16-byte values are formatted as UUID strings (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
 * All other lengths are hex-encoded for bytea (\x prefix + hex pairs)
 */
static int pg_bind_blob(db_stmt_t *stmt, int index, const void *value, int len) {
    int idx = index - 1;
    if (idx < 0 || idx >= stmt->param_count) {
        log_error("Parameter index %d out of range (1-%d)", index, stmt->param_count);
        return -1;
    }

    const unsigned char *bytes = (const unsigned char *)value;
    char *buf;

    if (len == 16) {
        /* UUID format: 8-4-4-4-12 with dashes (36 chars + null) */
        buf = malloc(37);
        if (!buf) {
            log_error("Failed to allocate UUID param buffer");
            return -1;
        }
        snprintf(buf, 37,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 bytes[0], bytes[1], bytes[2], bytes[3],
                 bytes[4], bytes[5], bytes[6], bytes[7],
                 bytes[8], bytes[9], bytes[10], bytes[11],
                 bytes[12], bytes[13], bytes[14], bytes[15]);
    } else {
        /* Bytea hex format: \x prefix + 2 hex chars per byte + null */
        size_t hex_len = 2 + (len * 2) + 1;
        buf = malloc(hex_len);
        if (!buf) {
            log_error("Failed to allocate blob param buffer");
            return -1;
        }
        buf[0] = '\\';
        buf[1] = 'x';
        for (int i = 0; i < len; i++) {
            snprintf(buf + 2 + (i * 2), 3, "%02x", bytes[i]);
        }
    }

    free(stmt->pg_param_bufs[idx]);
    stmt->pg_param_bufs[idx] = buf;
    stmt->pg_param_values[idx] = buf;
    stmt->pg_param_lengths[idx] = 0;
    stmt->pg_param_formats[idx] = 0;
    stmt->bound_count++;
    return 0;
}

/*
 * Bind NULL parameter
 */
static int pg_bind_null(db_stmt_t *stmt, int index) {
    int idx = index - 1;
    if (idx < 0 || idx >= stmt->param_count) {
        log_error("Parameter index %d out of range (1-%d)", index, stmt->param_count);
        return -1;
    }

    free(stmt->pg_param_bufs[idx]);
    stmt->pg_param_bufs[idx] = NULL;
    stmt->pg_param_values[idx] = NULL;
    stmt->pg_param_lengths[idx] = 0;
    stmt->pg_param_formats[idx] = 0;
    stmt->bound_count++;
    return 0;
}

/*
 * Execute prepared statement / advance cursor
 */
static int pg_step(db_stmt_t *stmt) {
    /* Validate all parameters are bound */
    if (stmt->bound_count < stmt->param_count) {
        snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                 "Not all parameters bound: %d/%d", stmt->bound_count, stmt->param_count);
        log_error("%s", stmt->error_msg);
        return -1;
    }

    if (!stmt->pg_executed) {
        /* First call: execute the query */
        PGconn *conn = (PGconn *)stmt->db->connection;

        stmt->pg_result = PQexecParams(conn,
            stmt->pg_query,
            stmt->param_count,
            NULL,                    /* Let server infer types */
            (const char * const *)stmt->pg_param_values,
            stmt->pg_param_lengths,
            stmt->pg_param_formats,
            0);                      /* Text format results */

        ExecStatusType status = PQresultStatus(stmt->pg_result);

        if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
            snprintf(stmt->error_msg, sizeof(stmt->error_msg),
                     "PostgreSQL step failed: %s", PQresultErrorMessage(stmt->pg_result));
            log_error("%s", stmt->error_msg);
            PQclear(stmt->pg_result);
            stmt->pg_result = NULL;
            return -1;
        }

        stmt->pg_executed = 1;

        if (status == PGRES_COMMAND_OK) {
            /* INSERT/UPDATE/DELETE with no RETURNING — no rows */
            stmt->pg_total_rows = 0;
            return DB_DONE;
        }

        /* TUPLES_OK — may have rows */
        stmt->pg_total_rows = PQntuples(stmt->pg_result);
        if (stmt->pg_total_rows == 0) {
            return DB_DONE;
        }

        stmt->pg_current_row = 0;
        return DB_ROW;
    }

    /* Subsequent calls: advance cursor */
    /* Free previous blob decode if any */
    free(stmt->pg_blob_buf);
    stmt->pg_blob_buf = NULL;
    stmt->pg_blob_len = 0;

    stmt->pg_current_row++;
    if (stmt->pg_current_row < stmt->pg_total_rows) {
        return DB_ROW;
    }

    return DB_DONE;
}

/*
 * Reset statement for reuse
 */
static int pg_reset(db_stmt_t *stmt) {
    if (stmt->pg_result) {
        PQclear(stmt->pg_result);
        stmt->pg_result = NULL;
    }

    free(stmt->pg_blob_buf);
    stmt->pg_blob_buf = NULL;
    stmt->pg_blob_len = 0;

    pg_clear_params(stmt);

    stmt->pg_executed = 0;
    stmt->pg_current_row = -1;
    stmt->pg_total_rows = 0;
    stmt->bound_count = 0;

    return 0;
}

/*
 * Helper: decode a single hex character to its value (0-15)
 * Returns -1 on invalid input
 */
static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Decode a UUID string "550e8400-e29b-41d4-a716-446655440000" to 16 raw bytes
 * Returns 0 on success, -1 on error
 */
static int pg_decode_uuid(const char *str, unsigned char *out) {
    int byte_idx = 0;
    for (const char *p = str; *p && byte_idx < 16; p++) {
        if (*p == '-') continue;
        int hi = hex_char_val(*p);
        p++;
        if (!*p) return -1;
        int lo = hex_char_val(*p);
        if (hi < 0 || lo < 0) return -1;
        out[byte_idx++] = (unsigned char)((hi << 4) | lo);
    }
    return (byte_idx == 16) ? 0 : -1;
}

/*
 * Get column value as text
 */
static const char *pg_column_text(db_stmt_t *stmt, int col) {
    if (!stmt->pg_result || stmt->pg_current_row < 0) return NULL;
    if (PQgetisnull(stmt->pg_result, stmt->pg_current_row, col)) return NULL;
    return PQgetvalue(stmt->pg_result, stmt->pg_current_row, col);
}

/*
 * Get column value as integer
 */
static int pg_column_int(db_stmt_t *stmt, int col) {
    const char *val = pg_column_text(stmt, col);
    if (!val) return 0;

    /* Handle PostgreSQL boolean text format */
    if (val[0] == 't' && val[1] == '\0') return 1;
    if (val[0] == 'f' && val[1] == '\0') return 0;

    return atoi(val);
}

/*
 * Get column value as 64-bit integer
 */
static long long pg_column_int64(db_stmt_t *stmt, int col) {
    const char *val = pg_column_text(stmt, col);
    if (!val) return 0;
    return strtoll(val, NULL, 10);
}

/*
 * Get column value as raw blob bytes
 * Decodes UUID text or bytea hex format. Stores result in stmt->pg_blob_buf.
 * Returned pointer valid until next column_blob/step/reset/finalize.
 */
static const void *pg_column_blob(db_stmt_t *stmt, int col) {
    if (!stmt->pg_result || stmt->pg_current_row < 0) return NULL;
    if (PQgetisnull(stmt->pg_result, stmt->pg_current_row, col)) return NULL;

    /* Free previous decode */
    free(stmt->pg_blob_buf);
    stmt->pg_blob_buf = NULL;
    stmt->pg_blob_len = 0;

    Oid col_type = PQftype(stmt->pg_result, col);
    const char *val = PQgetvalue(stmt->pg_result, stmt->pg_current_row, col);

    if (col_type == PG_UUID_OID) {
        /* UUID text: "550e8400-e29b-41d4-a716-446655440000" → 16 bytes */
        stmt->pg_blob_buf = malloc(16);
        if (!stmt->pg_blob_buf) return NULL;
        if (pg_decode_uuid(val, stmt->pg_blob_buf) != 0) {
            free(stmt->pg_blob_buf);
            stmt->pg_blob_buf = NULL;
            log_error("Failed to decode UUID: %s", val);
            return NULL;
        }
        stmt->pg_blob_len = 16;
        return stmt->pg_blob_buf;
    }

    if (col_type == PG_BYTEA_OID) {
        /* bytea hex format: \x0102... → raw bytes */
        size_t decoded_len = 0;
        unsigned char *decoded = PQunescapeBytea((const unsigned char *)val, &decoded_len);
        if (!decoded) {
            log_error("Failed to decode bytea value");
            return NULL;
        }
        /* Copy to our own buffer so we can free with free() consistently */
        stmt->pg_blob_buf = malloc(decoded_len);
        if (!stmt->pg_blob_buf) {
            PQfreemem(decoded);
            return NULL;
        }
        memcpy(stmt->pg_blob_buf, decoded, decoded_len);
        stmt->pg_blob_len = decoded_len;
        PQfreemem(decoded);
        return stmt->pg_blob_buf;
    }

    /* Unknown type: return raw text value as bytes */
    stmt->pg_blob_len = PQgetlength(stmt->pg_result, stmt->pg_current_row, col);
    return val;
}

/*
 * Get blob column byte length (from last column_blob decode)
 */
static int pg_column_bytes(db_stmt_t *stmt, int col) {
    if (!stmt->pg_result || stmt->pg_current_row < 0) return 0;
    if (PQgetisnull(stmt->pg_result, stmt->pg_current_row, col)) return 0;

    /* If we have a decoded blob, return its length */
    if (stmt->pg_blob_buf) {
        return (int)stmt->pg_blob_len;
    }

    /* Fallback: raw value length */
    return PQgetlength(stmt->pg_result, stmt->pg_current_row, col);
}

/*
 * Get column type
 */
static int pg_column_type(db_stmt_t *stmt, int col) {
    if (!stmt->pg_result || stmt->pg_current_row < 0) return DB_NULL;
    if (PQgetisnull(stmt->pg_result, stmt->pg_current_row, col)) return DB_NULL;

    Oid oid = PQftype(stmt->pg_result, col);
    switch (oid) {
        case PG_INT4_OID:
        case PG_INT8_OID:
        case PG_BOOL_OID:
            return DB_INTEGER;
        case PG_TEXT_OID:
        case 1043:  /* VARCHAR OID */
            return DB_TEXT;
        case PG_BYTEA_OID:
        case PG_UUID_OID:
            return DB_BLOB;
        default:
            return DB_TEXT;  /* Default to text for unknown types */
    }
}

/*
 * Finalize (clean up) a prepared statement
 */
static int pg_finalize(db_stmt_t *stmt) {
    if (stmt->pg_result) {
        PQclear(stmt->pg_result);
    }

    free(stmt->pg_query);
    pg_free_param_bufs(stmt);
    free(stmt->pg_param_values);
    free(stmt->pg_param_lengths);
    free(stmt->pg_param_formats);
    free(stmt->pg_param_bufs);
    free(stmt->pg_blob_buf);

    free(stmt);
    return 0;
}

#endif /* DB_BACKEND_POSTGRESQL */

/* ============================================================================
 * Public API
 * ============================================================================ */

int db_connect(db_handle_t **db, db_type_t type, const char *connection_string) {
    if (!db || !connection_string) {
        log_error("Invalid arguments to db_connect");
        return -1;
    }

    /* Allocate handle */
    db_handle_t *handle = calloc(1, sizeof(db_handle_t));
    if (!handle) {
        log_error("Failed to allocate database handle");
        return -1;
    }

    handle->type = type;
    handle->connection = NULL;
    handle->error_msg[0] = '\0';

    /* Connect based on type */
    int result = -1;
    switch (type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            result = sqlite_connect(handle, connection_string);
            break;
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            result = pg_connect(handle, connection_string);
            break;
#endif

        default:
            snprintf(handle->error_msg, sizeof(handle->error_msg),
                    "Database backend not compiled: %d", type);
            log_error("%s", handle->error_msg);
            break;
    }

    if (result != 0) {
        free(handle);
        return -1;
    }

    *db = handle;
    return 0;
}

int db_disconnect(db_handle_t *db) {
    if (!db) {
        return 0;
    }

    int result = -1;
    switch (db->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            result = sqlite_disconnect(db);
            break;
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            result = pg_disconnect(db);
            break;
#endif

        default:
            log_error("Database backend not compiled: %d", db->type);
            break;
    }

    free(db);
    return result;
}

int db_execute_trusted(db_handle_t *db, const char *sql, ...) {
    if (!db || !sql) {
        log_error("Invalid arguments to db_execute_trusted");
        return -1;
    }

    /* Format SQL with variadic args */
    char formatted_sql[MAX_SQL_LENGTH];
    va_list args;
    va_start(args, sql);
    int format_result = format_sql(formatted_sql, sizeof(formatted_sql), sql, args);
    va_end(args);

    if (format_result != 0) {
        return -1;
    }

    /* Execute based on type */
    switch (db->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_execute(db, formatted_sql);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_execute(db, formatted_sql);
#endif

        default:
            log_error("Database backend not compiled: %d", db->type);
            return -1;
    }
}

int db_execute_direct(db_handle_t *db, const char *sql) {
    if (!db || !sql) {
        log_error("Invalid arguments to db_execute_direct");
        return -1;
    }

    /* Execute directly without formatting */
    switch (db->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_execute(db, sql);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_execute(db, sql);
#endif

        default:
            log_error("Database backend not compiled: %d", db->type);
            return -1;
    }
}

int db_query(db_handle_t *db, db_result_t **result, const char *sql, ...) {
    if (!db || !result || !sql) {
        log_error("Invalid arguments to db_query");
        return -1;
    }

    /* Format SQL with variadic args */
    char formatted_sql[MAX_SQL_LENGTH];
    va_list args;
    va_start(args, sql);
    int format_result = format_sql(formatted_sql, sizeof(formatted_sql), sql, args);
    va_end(args);

    if (format_result != 0) {
        return -1;
    }

    /* Query based on type */
    switch (db->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_query(db, result, formatted_sql);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_query(db, formatted_sql, result);
#endif

        default:
            log_error("Database backend not compiled: %d", db->type);
            return -1;
    }
}

int db_result_row_count(db_result_t *result) {
    return result ? result->row_count : 0;
}

int db_result_column_count(db_result_t *result) {
    return result ? result->column_count : 0;
}

const char *db_result_column_name(db_result_t *result, int col_index) {
    if (!result || col_index < 0 || col_index >= result->column_count) {
        return NULL;
    }
    return result->column_names[col_index];
}

const char *db_result_get(db_result_t *result, int row, int col) {
    if (!result || row < 0 || row >= result->row_count ||
        col < 0 || col >= result->column_count) {
        return NULL;
    }
    return result->data[row][col];
}

void db_result_free(db_result_t *result) {
    if (!result) {
        return;
    }

    /* Free data */
    if (result->data) {
        for (int r = 0; r < result->row_count; r++) {
            if (result->data[r]) {
                for (int c = 0; c < result->column_count; c++) {
                    free(result->data[r][c]);
                }
                free(result->data[r]);
            }
        }
        free(result->data);
    }

    /* Free column names */
    if (result->column_names) {
        for (int i = 0; i < result->column_count; i++) {
            free(result->column_names[i]);
        }
        free(result->column_names);
    }

    free(result);
}

const char *db_error(db_handle_t *db) {
    return db ? db->error_msg : "No database handle";
}

/* ============================================================================
 * Prepared Statement API
 * ============================================================================ */

int db_prepare(db_handle_t *db, db_stmt_t **stmt, const char *sql) {
    if (!db || !stmt || !sql) {
        log_error("Invalid arguments to db_prepare");
        return -1;
    }

    switch (db->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_prepare(db, stmt, sql);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_prepare(db, stmt, sql);
#endif

        default:
            log_error("Database backend not compiled: %d", db->type);
            return -1;
    }
}

int db_bind_text(db_stmt_t *stmt, int index, const char *value, int len) {
    if (!stmt || !value) {
        log_error("Invalid arguments to db_bind_text");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_bind_text(stmt, index, value, len);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_bind_text(stmt, index, value, len);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_bind_int(db_stmt_t *stmt, int index, int value) {
    if (!stmt) {
        log_error("Invalid arguments to db_bind_int");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_bind_int(stmt, index, value);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_bind_int(stmt, index, value);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_bind_int64(db_stmt_t *stmt, int index, long long value) {
    if (!stmt) {
        log_error("Invalid arguments to db_bind_int64");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_bind_int64(stmt, index, value);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_bind_int64(stmt, index, value);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_bind_blob(db_stmt_t *stmt, int index, const void *value, int len) {
    if (!stmt || !value) {
        log_error("Invalid arguments to db_bind_blob");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_bind_blob(stmt, index, value, len);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_bind_blob(stmt, index, value, len);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_bind_null(db_stmt_t *stmt, int index) {
    if (!stmt) {
        log_error("Invalid arguments to db_bind_null");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_bind_null(stmt, index);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_bind_null(stmt, index);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_step(db_stmt_t *stmt) {
    if (!stmt) {
        log_error("Invalid arguments to db_step");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_step(stmt);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_step(stmt);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

int db_reset(db_stmt_t *stmt) {
    if (!stmt) {
        log_error("Invalid arguments to db_reset");
        return -1;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_reset(stmt);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_reset(stmt);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return -1;
    }
}

const char *db_column_text(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return NULL;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_text(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_text(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return NULL;
    }
}

int db_column_int(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return 0;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_int(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_int(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return 0;
    }
}

long long db_column_int64(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return 0;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_int64(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_int64(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return 0;
    }
}

const void *db_column_blob(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return NULL;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_blob(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_blob(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return NULL;
    }
}

int db_column_bytes(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return 0;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_bytes(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_bytes(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return 0;
    }
}

int db_column_type(db_stmt_t *stmt, int col) {
    if (!stmt) {
        return DB_NULL;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_column_type(stmt, col);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_column_type(stmt, col);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            return DB_NULL;
    }
}

int db_finalize(db_stmt_t *stmt) {
    if (!stmt) {
        return 0;
    }

    switch (stmt->type) {
#ifdef DB_BACKEND_SQLITE
        case DB_TYPE_SQLITE:
            return sqlite_finalize(stmt);
#endif

#ifdef DB_BACKEND_POSTGRESQL
        case DB_TYPE_POSTGRESQL:
            return pg_finalize(stmt);
#endif

        default:
            log_error("Database backend not compiled: %d", stmt->type);
            free(stmt);
            return -1;
    }
}

/* ============================================================================
 * Multi-Record Query Result Helpers
 * ============================================================================ */

/*
 * Append data to result list
 *
 * Single allocation for node + data (cache-friendly).
 * Appends to end of list (preserves insertion order).
 */
int db_results_append(db_result_node_t **head, db_result_node_t **tail,
                      const void *data, size_t size) {
    if (!head || !tail || !data || size == 0) {
        log_error("Invalid arguments to db_results_append");
        return -1;
    }

    /* Allocate node + data in single malloc (flexible array member) */
    db_result_node_t *node = malloc(sizeof(db_result_node_t) + size);
    if (!node) {
        log_error("Failed to allocate result node (%zu bytes)", sizeof(db_result_node_t) + size);
        return -1;
    }

    /* Copy data into flexible array member */
    memcpy(node->data, data, size);
    node->next = NULL;

    /* O(1) append via tail pointer */
    if (*tail) {
        (*tail)->next = node;
    } else {
        *head = node;
    }
    *tail = node;

    return 0;
}

/*
 * Convert linked list to array
 *
 * Allocates contiguous array with exact size.
 * ALWAYS frees the input list (even on malloc failure).
 */
void *db_results_to_array(db_result_node_t *head, int *out_count, size_t elem_size) {
    if (!out_count) {
        log_error("Invalid arguments to db_results_to_array (out_count is NULL)");
        db_results_free(head);
        return NULL;
    }

    if (elem_size == 0) {
        log_error("Invalid arguments to db_results_to_array (elem_size is 0)");
        db_results_free(head);
        *out_count = 0;
        return NULL;
    }

    /* Count nodes */
    int count = 0;
    for (db_result_node_t *n = head; n != NULL; n = n->next) {
        count++;
    }

    *out_count = count;

    /* Handle empty list */
    if (count == 0) {
        db_results_free(head);
        return NULL;
    }

    /* Allocate contiguous array */
    void *array = malloc(count * elem_size);
    if (!array) {
        log_error("Failed to allocate result array (%d elements, %zu bytes each)",
                  count, elem_size);
        db_results_free(head);
        *out_count = 0;
        return NULL;
    }

    /* Copy data from linked list to array */
    char *dest = (char *)array;
    db_result_node_t *node = head;
    for (int i = 0; i < count; i++) {
        memcpy(dest + (i * elem_size), node->data, elem_size);
        node = node->next;
    }

    /* Free linked list */
    db_results_free(head);

    log_debug("Converted result list to array (%d elements, %zu bytes each)",
              count, elem_size);

    return array;
}

/*
 * Free result list without converting
 *
 * NULL-safe, handles partial lists.
 */
void db_results_free(db_result_node_t *head) {
    while (head) {
        db_result_node_t *next = head->next;
        free(head);
        head = next;
    }
}
