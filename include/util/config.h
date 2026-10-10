#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>    /* For size_t */
#include "util/log.h"  /* For LogLevel enum */

/*
 * Configuration System
 *
 * Loads settings from config file + environment variables.
 * Config file format: key = value (one per line, # comments)
 * Environment variables override config file values.
 */

/* Database type enumeration */
typedef enum {
    DB_TYPE_SQLITE,
    DB_TYPE_POSTGRESQL
} db_type_t;

/* Password hashing algorithm enumeration */
typedef enum {
    PASSWORD_HASH_UNSET = -1,  /* machine_secret_hashing_algorithm left out: the user one's */
    PASSWORD_HASH_ARGON2ID,
    PASSWORD_HASH_PBKDF2_SHA256
} password_hash_algorithm_t;

/* Longest public_base_url config_load accepts. The buffers that hold it with a
 * path and a token appended are sized with room for it. */
#define PUBLIC_BASE_URL_MAX 200

/* Configuration structure */
typedef struct {
    /* Server settings */
    char *host;
    int port;
    int admin_port;        /* The admin API on loopback TCP too (0: not) */
    char *admin_socket;    /* The admin API's Unix socket ("" or NULL: none) */
    int admin_socket_mode; /* Its file mode, which decides who may connect */
    int workers;
    /* Not a setting: derived from host and port by config_load. The address
     * browsers and resource servers reach this server at: http://localhost:PORT
     * when host is localhost, https://HOST otherwise. Every absolute URL the
     * server hands out starts with it, and it is every access token's iss. */
    char public_base_url[PUBLIC_BASE_URL_MAX + 1];

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

    /* Machine secrets (crypto/password.h): each one left out takes the password
       setting's value, which config_load fills in */
    password_hash_algorithm_t machine_secret_hashing_algorithm;
    int machine_secret_hash_min_iterations;
    int machine_secret_hash_max_iterations;

    /* Password policy */
    int password_min_length;  /* Minimum password length (default 1, minimum 1) */

    /* Refuse to start on the shipped defaults fit only for trying the server out
       (config_check_weak_defaults). Off by default, so a fresh clone runs. */
    int strict;

    /* Patterns a value created or set must match (util/validation.h): NULL for
       the default, "" for none */
    char *username_pattern;
    char *email_pattern;
    char *code_name_pattern;
    char *password_pattern;
    char *machine_secret_pattern;

    /* OAuth2 token limits */
    int max_access_token_ttl_seconds;  /* Maximum TTL for client access tokens (default 59 days) */

    /* JWT settings */
    int jwt_clock_skew_seconds;  /* Clock skew tolerance for JWT validation (default 0) */

    /* Invitation token TTL (not gated by EMAIL_SUPPORT — RS provisioning always needs this) */
    int invitation_token_ttl_seconds;  /* How long invitation tokens are valid (default 72 hours) */

    /* Browser session TTL */
    int session_ttl_seconds;  /* How long login sessions are valid (default 7 days) */

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
    char *encryption_key_previous; /* --rekey only: the passphrase the data is sealed under now (NULL: unset) */

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
    char *encryption_key_previous_env; /* ENV var name for encryption_key_previous */
    char *server_host_env;  /* ENV var name for server_host */
    char *server_port_env;  /* ENV var name for server_port */
    char *admin_port_env;   /* ENV var name for admin_port */
    char *admin_socket_env; /* ENV var name for admin_socket */
    char *mothership_url_env; /* ENV var name for mothership_url */

    /* Branding */
    char *mothership_url;  /* Optional parent/brand URL shown on index page */

    /* Which header the proxy in front sets with the client's address (NULL: x-real-ip) */
    char *client_ip_header;

#ifdef EMAIL_SUPPORT
    /* Email delivery */
    char *email_command;     /* Shell command to exec for sending email (receives JSON on stdin) */
    char *email_from;        /* Sender email address */
    char *email_from_name;   /* Sender display name */

    /* Email token TTLs */
    int password_reset_token_ttl_seconds;        /* How long password reset tokens are valid (default 1 hour) */
    int email_verification_token_ttl_seconds;    /* How long email verification tokens are valid (default 24 hours) */
    int passwordless_login_token_ttl_seconds;    /* How long passwordless login tokens are valid (default 10 min) */

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

/* The shortest password_min_length strict accepts: NIST SP 800-63B's minimum
   for a password a person chooses */
#define STRICT_PASSWORD_MIN_LENGTH 8

/*
 * config_check_weak_defaults - The shipped defaults fit only for trying the
 * server out: encryption_key left at customize_me, which anyone can read, and
 * password_min_length under STRICT_PASSWORD_MIN_LENGTH. Without strict, the key
 * is a warning and the length nothing; with strict, each is an error.
 *
 * Returns: 0, or -1 if strict is set and either is in use
 */
int config_check_weak_defaults(const config_t *config);

/*
 * Free configuration structure
 */
void config_free(config_t *config);

#endif /* CONFIG_H */
