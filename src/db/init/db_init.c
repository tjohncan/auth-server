/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "db/init/db_init.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Maximum schema file size: 1MB */
#define MAX_SCHEMA_SIZE (1024 * 1024)

#ifdef DB_BACKEND_POSTGRESQL
/* Placeholder in postgresql/schema.sql replaced with configured owner role */
#define OWNER_ROLE_PLACEHOLDER "$$$$$$$DB$$$$$$$OWNER$$$$$$$ROLE$$$$$$$"
#define OWNER_ROLE_PLACEHOLDER_LEN 39
#define MAX_OWNER_ROLE_LEN 32
/*
 * Validate that a string is a safe PostgreSQL identifier.
 * Allows only [a-zA-Z_][a-zA-Z0-9_]* to prevent SQL injection.
 */
static int validate_sql_identifier(const char *name) {
    if (!name || name[0] == '\0') {
        return -1;
    }

    size_t len = strlen(name);
    if (len > MAX_OWNER_ROLE_LEN) {
        return -1;
    }

    /* First character: letter or underscore */
    char c = name[0];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')) {
        return -1;
    }

    /* Remaining characters: letter, digit, or underscore */
    for (size_t i = 1; i < len; i++) {
        c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return -1;
        }
    }

    return 0;
}
#endif /* DB_BACKEND_POSTGRESQL */

/*
 * Read entire file into memory
 */
static char *read_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        log_error("Failed to open file: %s", path);
        return NULL;
    }

    /* Get file size using fstat (portable, works for files >2GB) */
    int fd = fileno(file);
    if (fd < 0) {
        log_error("Failed to get file descriptor");
        fclose(file);
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        log_error("Failed to stat file: %s", path);
        fclose(file);
        return NULL;
    }

    off_t size = st.st_size;
    if (size <= 0 || size > MAX_SCHEMA_SIZE) {
        log_error("Invalid file size: %lld bytes", (long long)size);
        fclose(file);
        return NULL;
    }

    /* Allocate buffer */
    char *content = malloc(size + 1);
    if (!content) {
        log_error("Failed to allocate buffer for file");
        fclose(file);
        return NULL;
    }

    /* Read file */
    size_t read_size = fread(content, 1, size, file);
    fclose(file);

    if ((off_t)read_size != size) {
        log_error("Failed to read file completely");
        free(content);
        return NULL;
    }

    content[size] = '\0';
    return content;
}

/*
 * Check if schema is already initialized
 * Looks for the "organization" table as a sentinel
 */
static int schema_exists(db_handle_t *db, db_type_t type) {
    db_result_t *result = NULL;
    int exists = 0;

#ifdef DB_BACKEND_SQLITE
    if (type == DB_TYPE_SQLITE) {
        /* Query SQLite system table */
        int rc = db_query(db, &result,
                "SELECT name FROM sqlite_master WHERE type='table' AND name='organization';");
        if (rc == 0 && db_result_row_count(result) > 0) {
            exists = 1;
        }
    }
#endif

#ifdef DB_BACKEND_POSTGRESQL
    if (type == DB_TYPE_POSTGRESQL) {
        /* Query PostgreSQL system catalog */
        int rc = db_query(db, &result,
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema='security' AND table_name='organization';");
        if (rc == 0 && db_result_row_count(result) > 0) {
            exists = 1;
        }
    }
#endif

    if (result) {
        db_result_free(result);
    }

    return exists;
}

/*
 * Enable SQLite optimizations (conditionally compiled)
 */
#ifdef DB_BACKEND_SQLITE
static int enable_sqlite_optimizations(db_handle_t *db) {
    log_info("Enabling SQLite optimizations");

    /* Enable WAL mode for concurrent access */
    if (db_execute_trusted(db, "PRAGMA journal_mode = WAL;") != 0) {
        log_error("Failed to enable WAL mode");
        return -1;
    }

    /* Set synchronous to NORMAL (good balance of safety and speed) */
    if (db_execute_trusted(db, "PRAGMA synchronous = NORMAL;") != 0) {
        log_error("Failed to set synchronous mode");
        return -1;
    }

    /* Enable foreign keys */
    if (db_execute_trusted(db, "PRAGMA foreign_keys = ON;") != 0) {
        log_error("Failed to enable foreign keys");
        return -1;
    }

    /* Enable incremental vacuum (must be set on empty database before tables) */
    if (db_execute_trusted(db, "PRAGMA auto_vacuum = INCREMENTAL;") != 0) {
        log_warn("Failed to set auto_vacuum=INCREMENTAL "
                 "(may already have tables; cleaner vacuum will be a no-op)");
    }

    log_info("SQLite optimizations enabled");
    return 0;
}
#endif /* DB_BACKEND_SQLITE */

/*
 * Validate path to prevent directory traversal attacks
 */
static int validate_schema_dir(const char *schema_dir) {
    if (!schema_dir || schema_dir[0] == '\0') {
        log_error("Empty schema directory");
        return -1;
    }

    /* Reject absolute paths (should be relative for safety) */
    if (schema_dir[0] == '/') {
        log_error("Absolute paths not allowed for schema_dir: %s", schema_dir);
        return -1;
    }

    /* Reject paths with ".." (directory traversal) */
    if (strstr(schema_dir, "..") != NULL) {
        log_error("Directory traversal detected in schema_dir: %s", schema_dir);
        return -1;
    }

    /* Length check */
    size_t len = strlen(schema_dir);
    if (len > 256) {
        log_error("schema_dir path too long: %zu bytes", len);
        return -1;
    }

    return 0;
}

int db_init_schema(db_handle_t *db, db_type_t type, const char *schema_dir,
                   const char *owner_role) {
    if (!db || !schema_dir) {
        log_error("Invalid arguments to db_init_schema");
        return -1;
    }

    /* Validate schema_dir to prevent path traversal */
    if (validate_schema_dir(schema_dir) != 0) {
        return -1;
    }

    /* Backend-specific setup */
#ifdef DB_BACKEND_SQLITE
    if (type == DB_TYPE_SQLITE) {
        if (enable_sqlite_optimizations(db) != 0) {
            return -1;
        }
    }
#endif

    /* Check if schema already exists */
    if (schema_exists(db, type)) {
        log_info("Database schema already initialized");
        return 1;
    }

    log_info("Initializing database schema");

    /* Build path to schema file (based on compiled backend) */
    char schema_path[512];
    int path_len = 0;

#ifdef DB_BACKEND_SQLITE
    if (type == DB_TYPE_SQLITE) {
        path_len = snprintf(schema_path, sizeof(schema_path), "%s/sqlite/schema.sql", schema_dir);
    } else
#endif
#ifdef DB_BACKEND_POSTGRESQL
    if (type == DB_TYPE_POSTGRESQL) {
        path_len = snprintf(schema_path, sizeof(schema_path), "%s/postgresql/schema.sql", schema_dir);
    } else
#endif
    {
        log_error("Database backend not compiled: %d", type);
        return -1;
    }

    /* Check for path truncation */
    if (path_len < 0 || (size_t)path_len >= sizeof(schema_path)) {
        log_error("Schema path truncated or formatting error");
        return -1;
    }

    log_info("Reading schema from: %s", schema_path);

    /* Read schema file */
    char *schema_sql = read_file(schema_path);
    if (!schema_sql) {
        log_error("Failed to read schema file: %s", schema_path);
        return -1;
    }

    /* Replace owner role placeholder for PostgreSQL schemas */
#ifdef DB_BACKEND_POSTGRESQL
    if (type == DB_TYPE_POSTGRESQL) {
        if (!owner_role || validate_sql_identifier(owner_role) != 0) {
            log_error("Invalid db_owner_role: must be 1-%d chars, "
                      "only letters/digits/underscores, starting with letter or underscore",
                      MAX_OWNER_ROLE_LEN);
            free(schema_sql);
            return -1;
        }

        char *placeholder = strstr(schema_sql, OWNER_ROLE_PLACEHOLDER);
        if (!placeholder) {
            log_error("Owner role placeholder not found in schema file");
            free(schema_sql);
            return -1;
        }

        size_t role_len = strlen(owner_role);
        size_t tail_len = strlen(placeholder + OWNER_ROLE_PLACEHOLDER_LEN) + 1; /* +1 for null */

        /* Overwrite placeholder with role name, shift remainder left */
        memcpy(placeholder, owner_role, role_len);
        memmove(placeholder + role_len, placeholder + OWNER_ROLE_PLACEHOLDER_LEN, tail_len);

        log_info("Schema owner role: %s", owner_role);
    }
#endif
    (void)owner_role; /* Suppress unused warning for SQLite builds */

    /* Execute schema - use direct execution to avoid formatting buffer limits */
    log_info("Executing schema");
    int result = db_execute_direct(db, schema_sql);
    free(schema_sql);

    if (result != 0) {
        log_error("Failed to execute schema");
        return -1;
    }

    log_info("Database schema initialized successfully");
    return 0;
}
