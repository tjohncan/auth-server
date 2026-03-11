#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>    /* For size_t */
#include "util/log.h"  /* For LogLevel enum */

/*
 * Configuration System
 *
 * Loads settings from config file + environment variables.
 * Config file format: INI-style [section] key=value
 * Environment variables override config file values.
 */

/* Database type enumeration */
typedef enum {
    DB_TYPE_SQLITE,
    DB_TYPE_POSTGRESQL
} db_type_t;

/* Password hashing algorithm enumeration */
typedef enum {
    PASSWORD_HASH_ARGON2ID,
    PASSWORD_HASH_PBKDF2_SHA256
} password_hash_algorithm_t;

/* Configuration structure */
typedef struct {
    /* Server settings */
    char *host;
    int port;
    int workers;

    /* Database settings */
    db_type_t db_type;
    char *db_path;         /* SQLite: file path */
    char *db_host;         /* PostgreSQL: hostname */
    int db_port;           /* PostgreSQL: port */
    char *db_name;         /* PostgreSQL: database name */
    char *db_user;         /* PostgreSQL: username */
    char *db_password;     /* PostgreSQL: password (from env var) */
    char *db_owner_role;   /* PostgreSQL: schema owner role for SET ROLE during init (fallback: db_user) */

    /* Paths */
    char *schema_dir;

    /* Database features */
    int enable_history_tables;  /* Boolean: 0=disabled, 1=enabled */

    /* Password hashing settings */
    password_hash_algorithm_t secret_hashing_algorithm;
    int secret_hash_min_iterations;
    int secret_hash_max_iterations;

    /* OAuth2 token limits */
    int max_access_token_ttl_seconds;  /* Maximum TTL for client access tokens (default 60 days) */

    /* JWT settings */
    int jwt_clock_skew_seconds;  /* Clock skew tolerance for JWT validation (default 0) */

    /* Database cleaner settings */
    int cleaner_enabled;                    /* Master switch: 0=off, 1=on */
    int cleaner_interval_seconds;           /* Sleep between table checks */
    int cleaner_batch_size;                 /* Rows deleted per batch */
    int cleaner_sqlite_vacuum_pages;        /* SQLite only: pages freed per vacuum iteration */
    int cleaner_postgres_vacuum_enabled;    /* PostgreSQL only: run VACUUM after deletes (0=off, 1=on) */
    int retention_usage_logs_days;          /* Usage log tables (*_usage) */
    int retention_history_days;             /* History tables (history__* / *_history.*) */
    int retention_sessions_grace_days;      /* Browser sessions (grace after expected_expiry) */
    int retention_tokens_grace_days;        /* Tokens (grace after expected_expiry) */

    /* Encryption */
    char *encryption_key;          /* Passphrase for encrypting sensitive data at rest (AES-256-GCM) */

    /* Logging settings */
    LogLevel log_level;    /* Parsed log level enum (stored directly, no string) */

    /* Environment variable names (optional overrides) */
    char *log_level_env;   /* ENV var name for log_level */
    char *db_type_env;     /* ENV var name for db_type */
    char *db_host_env;     /* ENV var name for db_host */
    char *db_port_env;     /* ENV var name for db_port */
    char *db_name_env;     /* ENV var name for db_name */
    char *db_user_env;     /* ENV var name for db_user */
    char *db_password_env; /* ENV var name for db_password */
    char *db_owner_role_env; /* ENV var name for db_owner_role */
    char *encryption_key_env;       /* ENV var name for encryption_key */
    char *server_host_env;  /* ENV var name for server_host */
    char *server_port_env;  /* ENV var name for server_port */
    char *mothership_url_env; /* ENV var name for mothership_url */

    /* Branding */
    char *mothership_url;  /* Optional parent/brand URL shown on index page */

#ifdef EMAIL_SUPPORT
    /* Email delivery */
    char *email_command;     /* Shell command to exec for sending email (receives JSON on stdin) */
    char *email_from;        /* Sender email address */
    char *email_from_name;   /* Sender display name */

    /* Email token TTLs */
    int password_reset_token_ttl_seconds;        /* How long password reset tokens are valid (default 1 hour) */
    int email_verification_token_ttl_seconds;    /* How long email verification tokens are valid (default 24 hours) */

    /* Email environment variable overrides */
    char *email_command_env;
    char *email_from_env;
    char *email_from_name_env;
#endif
} config_t;

/*
 * Load configuration from file and environment variables
 *
 * Load order: config file → environment variables
 * Environment variables that override config:
 *   - AUTH_DB_TYPE: Database type ("sqlite" or "postgresql")
 *   - AUTH_DB_PASSWORD: PostgreSQL password
 *
 * Returns: Allocated config_t on success, NULL on failure
 */
config_t *config_load(const char *config_file);

/*
 * Build a libpq connection string with properly quoted values.
 * Returns 0 on success, -1 on overflow.
 */
int config_build_pg_connection_string(const config_t *config, char *out, size_t out_size);

/*
 * Free configuration structure
 */
void config_free(config_t *config);

#endif /* CONFIG_H */
