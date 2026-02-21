#ifndef DB_H
#define DB_H

#include <stddef.h>
#include "util/config.h"  /* For db_type_t */

/*
 * Database Abstraction Layer
 *
 * Provides unified interface for SQLite and PostgreSQL.
 * Phase 1: SQLite only
 * Phase 2: Add PostgreSQL support via conditional compilation
 */

/* Forward declarations */
typedef struct db_handle_t db_handle_t;
typedef struct db_result_t db_result_t;
typedef struct db_stmt_t db_stmt_t;

/*
 * Connect to database
 *
 * Creates connection based on type and connection string.
 * Connection string format:
 *   - SQLite: File path (e.g., "./data/auth.db")
 *   - PostgreSQL: "host=X port=Y dbname=Z user=W password=P"
 *
 * Returns: 0 on success, negative on error
 */
int db_connect(db_handle_t **db, db_type_t type, const char *connection_string);

/*
 * Disconnect from database
 *
 * Closes connection and frees resources.
 *
 * Returns: 0 on success, negative on error
 */
int db_disconnect(db_handle_t *db);

/*
 * Execute SQL statement (no result expected) — INTERNAL ONLY
 *
 * For trusted SQL only: transactions (BEGIN/COMMIT/ROLLBACK), PRAGMAs,
 * and internal DDL. NEVER use with user input.
 * Supports printf-style formatting for convenience.
 *
 * Returns: 0 on success, negative on error
 */
int db_execute_trusted(db_handle_t *db, const char *sql, ...);

/*
 * Execute SQL statement directly (no formatting)
 *
 * For large SQL scripts (like schema files) that don't need parameter formatting.
 * Bypasses the formatting buffer size limit.
 *
 * Returns: 0 on success, negative on error
 */
int db_execute_direct(db_handle_t *db, const char *sql);

/*
 * Execute SQL query (returns rows)
 *
 * For SELECT statements.
 * Caller must free result with db_result_free().
 *
 * Returns: 0 on success, negative on error
 */
int db_query(db_handle_t *db, db_result_t **result, const char *sql, ...);

/*
 * Get number of rows in result
 */
int db_result_row_count(db_result_t *result);

/*
 * Get number of columns in result
 */
int db_result_column_count(db_result_t *result);

/*
 * Get column name by index (0-based)
 */
const char *db_result_column_name(db_result_t *result, int col_index);

/*
 * Get value at row/column (0-based)
 * Returns NULL if value is NULL or indices out of bounds
 */
const char *db_result_get(db_result_t *result, int row, int col);

/*
 * Free result set
 */
void db_result_free(db_result_t *result);

/*
 * Get last error message
 */
const char *db_error(db_handle_t *db);

/* ============================================================================
 * Prepared Statement API - Safe parameterized queries
 * ============================================================================
 *
 * Use this API for all queries involving user input to prevent SQL injection.
 *
 * For portable SQL across database backends, use db_sql.h macros:
 *   #include "db/db_sql.h"
 *
 *   const char *sql = "SELECT * FROM " TBL_USER_ACCOUNT " WHERE email = " P"1";
 *   db_prepare(db, &stmt, sql);
 *   db_bind_text(stmt, 1, email, -1);
 *
 *   while (db_step(stmt) == DB_ROW) {
 *       const char *username = db_column_text(stmt, 0);
 *       // ... process row
 *   }
 *
 *   db_finalize(stmt);
 */

/* Return codes for db_step() */
#define DB_ROW  100  /* Row ready */
#define DB_DONE 101  /* No more rows */

/* Column type codes for db_column_type() */
#define DB_INTEGER 1
#define DB_FLOAT   2
#define DB_TEXT    3
#define DB_BLOB    4
#define DB_NULL    5

/*
 * Prepare SQL statement with placeholders
 *
 * Parameters:
 *   db   - Database handle
 *   stmt - Output: statement handle (caller must finalize)
 *   sql  - SQL with numbered placeholders (use P macro from db_sql.h)
 *
 * Returns: 0 on success, negative on error
 */
int db_prepare(db_handle_t *db, db_stmt_t **stmt, const char *sql);

/*
 * Bind text/string parameter
 *
 * Parameters:
 *   stmt  - Prepared statement
 *   index - Parameter index (1-based: ?1, ?2, ...)
 *   value - String value (copied internally)
 *   len   - Length of string, or -1 to use strlen()
 *
 * Returns: 0 on success, negative on error
 */
int db_bind_text(db_stmt_t *stmt, int index, const char *value, int len);

/*
 * Bind integer parameter (32-bit)
 */
int db_bind_int(db_stmt_t *stmt, int index, int value);

/*
 * Bind integer parameter (64-bit)
 */
int db_bind_int64(db_stmt_t *stmt, int index, long long value);

/*
 * Bind binary data parameter
 */
int db_bind_blob(db_stmt_t *stmt, int index, const void *value, int len);

/*
 * Bind NULL parameter
 */
int db_bind_null(db_stmt_t *stmt, int index);

/*
 * Execute statement / fetch next row
 *
 * Returns:
 *   DB_ROW  (100) - Row available, use db_column_* to access
 *   DB_DONE (101) - No more rows
 *   negative      - Error occurred
 */
int db_step(db_stmt_t *stmt);

/*
 * Reset statement for re-execution
 *
 * Clears bindings and result, allows re-binding parameters.
 * More efficient than finalize + prepare for repeated queries.
 *
 * Returns: 0 on success, negative on error
 */
int db_reset(db_stmt_t *stmt);

/*
 * Get text column from current row (0-based column index)
 *
 * Returns: String value, or NULL if column is NULL
 * Note: Pointer valid until next db_step() or db_finalize()
 */
const char *db_column_text(db_stmt_t *stmt, int col);

/*
 * Get integer column (32-bit)
 */
int db_column_int(db_stmt_t *stmt, int col);

/*
 * Get integer column (64-bit)
 */
long long db_column_int64(db_stmt_t *stmt, int col);

/*
 * Get blob column
 *
 * Returns: Pointer to binary data, or NULL if column is NULL
 * Note: Use db_column_bytes() to get length
 */
const void *db_column_blob(db_stmt_t *stmt, int col);

/*
 * Get column size in bytes
 */
int db_column_bytes(db_stmt_t *stmt, int col);

/*
 * Get column type
 *
 * Returns one of: DB_INTEGER, DB_FLOAT, DB_TEXT, DB_BLOB, DB_NULL
 */
int db_column_type(db_stmt_t *stmt, int col);

/*
 * Finalize statement and free resources
 *
 * Returns: 0 on success, negative on error
 */
int db_finalize(db_stmt_t *stmt);

/* ============================================================================
 * Multi-Record Query Result Helpers
 * ============================================================================
 *
 * Linked list pattern for dynamic multi-record query results.
 * Use when query result count is unknown or needs pagination.
 *
 * Pattern:
 *   1. Build linked list with db_results_append() in query loop
 *   2. Convert to array with db_results_to_array()
 *   3. Return array to caller (caller frees with free())
 *
 * Benefits:
 *   - No wasted memory (exact allocation)
 *   - No arbitrary limits
 *   - Single allocation per node (node + data together)
 *   - Automatic cleanup on conversion
 */

/*
 * Linked list node for query results
 *
 * Uses flexible array member for single-allocation optimization:
 * Node metadata and data are allocated together for cache efficiency.
 */
typedef struct db_result_node {
    struct db_result_node *next;
    char data[];  /* Flexible array member - data embedded after node */
} db_result_node_t;

/*
 * Append data to result list
 *
 * Allocates new node with data embedded (single malloc).
 * Appends to end of list (maintains insertion order).
 *
 * Parameters:
 *   head - Pointer to list head (updated on first append)
 *   tail - Pointer to list tail (tracked for O(1) append)
 *   data - Pointer to data to copy (e.g., &my_struct)
 *   size - Size of data in bytes (e.g., sizeof(my_struct))
 *
 * Returns: 0 on success, -1 on malloc failure
 *
 * Example:
 *   db_result_node_t *list = NULL, *list_tail = NULL;
 *   while (db_step(stmt) == DB_ROW) {
 *       my_struct_t item;
 *       // ... populate item from row ...
 *       if (db_results_append(&list, &list_tail, &item, sizeof(item)) != 0) {
 *           db_results_free(list);
 *           return -1;
 *       }
 *   }
 */
int db_results_append(db_result_node_t **head, db_result_node_t **tail,
                      const void *data, size_t size);

/*
 * Convert linked list to array
 *
 * Allocates contiguous array with exact size for all elements.
 * ALWAYS frees the input linked list (even on malloc failure).
 *
 * Parameters:
 *   head      - List head (will be freed)
 *   out_count - Output: number of elements in array
 *   elem_size - Size of each element in bytes
 *
 * Returns: Pointer to array, or NULL on malloc failure
 *          Caller must free() the returned array
 *
 * Example:
 *   my_struct_t *items = DB_RESULTS_TO_ARRAY(list, &count, my_struct_t);
 *   if (!items) return -1;
 *   // ... use items ...
 *   free(items);
 */
void *db_results_to_array(db_result_node_t *head, int *out_count, size_t elem_size);

/*
 * Free result list without converting
 *
 * Use when abandoning query results on error.
 * NULL-safe (can pass NULL list).
 *
 * Parameters:
 *   head - List head to free
 */
void db_results_free(db_result_node_t *head);

/*
 * Type-safe array conversion macro
 *
 * Casts result to proper type pointer.
 * Automatically passes sizeof(type) for element size.
 *
 * Parameters:
 *   list  - Linked list (db_result_node_t *)
 *   count - Pointer to int for count output
 *   type  - Result structure type (e.g., my_struct_t)
 *
 * Returns: Typed pointer (type *) or NULL
 *
 * Example:
 *   my_struct_t *arr = DB_RESULTS_TO_ARRAY(list, &count, my_struct_t);
 */
#define DB_RESULTS_TO_ARRAY(list, count, type) \
    ((type *)db_results_to_array((list), (count), sizeof(type)))

#endif /* DB_H */
