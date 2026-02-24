#include "util/config.h"
#include "util/log.h"
#include "util/str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>

/* Default values */
#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 8080
#define DEFAULT_WORKERS 0  /* 0 = auto-detect */
#define DEFAULT_DB_TYPE DB_TYPE_SQLITE
#define DEFAULT_DB_PATH "./data/auth.db"
#define DEFAULT_DB_PORT 5432
#define DEFAULT_SCHEMA_DIR "./sql"
#define DEFAULT_ENABLE_HISTORY_TABLES 0  /* Disabled by default */
#define DEFAULT_MAX_ACCESS_TOKEN_TTL_SECONDS (60 * 24 * 3600)  /* 60 days */
#define DEFAULT_JWT_CLOCK_SKEW_SECONDS 0  /* Strict validation by default */
#define DEFAULT_LOG_LEVEL "info"  /* Log level: debug, info, warn, error */

/* Database cleaner defaults */
#define DEFAULT_CLEANER_ENABLED 1  /* Enabled by default */
#define DEFAULT_CLEANER_INTERVAL_SECONDS 10
#define DEFAULT_CLEANER_BATCH_SIZE 1000
#define DEFAULT_CLEANER_SQLITE_VACUUM_PAGES 100
#define DEFAULT_CLEANER_POSTGRES_VACUUM_ENABLED 1  /* Enabled by default */
#define DEFAULT_RETENTION_USAGE_LOGS_DAYS 60
#define DEFAULT_RETENTION_HISTORY_DAYS 90
#define DEFAULT_RETENTION_SESSIONS_GRACE_DAYS 8
#define DEFAULT_RETENTION_TOKENS_GRACE_DAYS 8

/* Maximum line length in config file */
#define MAX_LINE_LENGTH 1024

/*
 * Parse log level string to LogLevel enum
 * Returns: LogLevel on success, LOG_INFO on unknown value
 */
static LogLevel parse_log_level(const char *level_str) {
    if (!level_str) return LOG_INFO;

    if (strcmp(level_str, "debug") == 0) {
        return LOG_DEBUG;
    } else if (strcmp(level_str, "info") == 0) {
        return LOG_INFO;
    } else if (strcmp(level_str, "warn") == 0) {
        return LOG_WARN;
    } else if (strcmp(level_str, "error") == 0) {
        return LOG_ERROR;
    } else {
        log_warn("Unknown log level '%s', defaulting to 'info'", level_str);
        return LOG_INFO;
    }
}

/*
 * Safe integer parsing (replaces atoi)
 * Returns 0 on success, -1 on error (overflow, non-numeric input, empty string)
 */
static int parse_int(const char *str, int *out) {
    if (!str || !*str) return -1;
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    if (errno == ERANGE || val > INT_MAX || val < INT_MIN) return -1;
    if (endptr == str || *endptr != '\0') return -1;
    *out = (int)val;
    return 0;
}

/*
 * Trim whitespace from both ends of a string (in-place)
 */
static void trim(char *str) {
    if (!str) return;

    /* Trim leading whitespace */
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    /* If string is all whitespace */
    if (*start == '\0') {
        *str = '\0';
        return;
    }

    /* Trim trailing whitespace */
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    /* Move trimmed string to start if needed */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/*
 * Parse a line and extract key=value
 * Returns: 0 on success, -1 if not a key=value line
 */
static int parse_key_value(const char *line, char *key, size_t key_size,
                          char *value, size_t value_size) {
    const char *equals = strchr(line, '=');
    if (!equals) {
        return -1;
    }

    /* Extract key */
    size_t key_len = equals - line;
    if (key_len >= key_size) {
        log_warn("Config key too long (max %zu bytes)", key_size - 1);
        return -1;
    }
    memcpy(key, line, key_len);
    key[key_len] = '\0';
    trim(key);

    /* Check for empty key after trimming */
    if (key[0] == '\0') {
        return -1;
    }

    /* Extract value */
    str_copy(value, value_size, equals + 1);
    trim(value);

    return 0;
}

/*
 * Set configuration value based on key
 */
static void set_config_value(config_t *config, const char *key, const char *value) {
    char *new_value;

    /* Server settings */
    if (strcmp(key, "server_host") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->host);
            config->host = new_value;
        } else {
            log_error("Failed to allocate memory for server_host");
        }
    } else if (strcmp(key, "server_port") == 0) {
        int port = 0;
        if (parse_int(value, &port) != 0 || port < 1 || port > 65535) {
            log_warn("Invalid port value '%s', must be 1-65535. Keeping current: %d", value, config->port);
        } else {
            config->port = port;
        }
    } else if (strcmp(key, "server_workers") == 0) {
        int workers = -1;
        if (parse_int(value, &workers) != 0 || workers < 0) {
            log_warn("Invalid workers value '%s', must be >= 0. Keeping current: %d", value, config->workers);
        } else {
            config->workers = workers;
        }
    }
    /* Database settings */
    else if (strcmp(key, "db_type") == 0) {
        if (strcmp(value, "sqlite") == 0) {
            config->db_type = DB_TYPE_SQLITE;
        } else if (strcmp(value, "postgresql") == 0) {
            config->db_type = DB_TYPE_POSTGRESQL;
        } else {
            log_warn("Unknown db_type '%s', keeping current value", value);
        }
    } else if (strcmp(key, "db_path") == 0) {
        /* Reject obvious path traversal attempts (defense in depth) */
        if (strstr(value, "..") != NULL) {
            log_warn("Rejected db_path with path traversal sequence: %s", value);
        } else {
            new_value = str_dup(value);
            if (new_value) {
                free(config->db_path);
                config->db_path = new_value;
            } else {
                log_error("Failed to allocate memory for db_path");
            }
        }
    } else if (strcmp(key, "db_host") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_host);
            config->db_host = new_value;
        } else {
            log_error("Failed to allocate memory for db_host");
        }
    } else if (strcmp(key, "db_port") == 0) {
        int port = 0;
        if (parse_int(value, &port) != 0 || port < 1 || port > 65535) {
            log_warn("Invalid db_port value '%s', must be 1-65535. Keeping current: %d", value, config->db_port);
        } else {
            config->db_port = port;
        }
    } else if (strcmp(key, "db_name") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_name);
            config->db_name = new_value;
        } else {
            log_error("Failed to allocate memory for db_name");
        }
    } else if (strcmp(key, "db_user") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_user);
            config->db_user = new_value;
        } else {
            log_error("Failed to allocate memory for db_user");
        }
    } else if (strcmp(key, "db_password") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_password);
            config->db_password = new_value;
        } else {
            log_error("Failed to allocate memory for db_password");
        }
    } else if (strcmp(key, "db_owner_role") == 0) {
        if (strlen(value) > 32) {
            log_warn("db_owner_role too long (max 32 characters): '%s'", value);
        } else {
            new_value = str_dup(value);
            if (new_value) {
                free(config->db_owner_role);
                config->db_owner_role = new_value;
            } else {
                log_error("Failed to allocate memory for db_owner_role");
            }
        }
    }
    /* Environment variable name overrides */
    else if (strcmp(key, "db_type_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_type_env);
            config->db_type_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_type_env");
        }
    } else if (strcmp(key, "db_host_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_host_env);
            config->db_host_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_host_env");
        }
    } else if (strcmp(key, "db_port_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_port_env);
            config->db_port_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_port_env");
        }
    } else if (strcmp(key, "db_name_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_name_env);
            config->db_name_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_name_env");
        }
    } else if (strcmp(key, "db_user_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_user_env);
            config->db_user_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_user_env");
        }
    } else if (strcmp(key, "db_password_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_password_env);
            config->db_password_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_password_env");
        }
    } else if (strcmp(key, "db_owner_role_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->db_owner_role_env);
            config->db_owner_role_env = new_value;
        } else {
            log_error("Failed to allocate memory for db_owner_role_env");
        }
    } else if (strcmp(key, "enable_history_tables_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->enable_history_tables_env);
            config->enable_history_tables_env = new_value;
        } else {
            log_error("Failed to allocate memory for enable_history_tables_env");
        }
    }
    /* Paths */
    else if (strcmp(key, "schema_dir") == 0) {
        /* Reject obvious path traversal attempts (defense in depth) */
        if (strstr(value, "..") != NULL) {
            log_warn("Rejected schema_dir with path traversal sequence: %s", value);
        } else {
            new_value = str_dup(value);
            if (new_value) {
                free(config->schema_dir);
                config->schema_dir = new_value;
            } else {
                log_error("Failed to allocate memory for schema_dir");
            }
        }
    }
    /* Database features */
    else if (strcmp(key, "enable_history_tables") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
            config->enable_history_tables = 1;
        } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
            config->enable_history_tables = 0;
        } else {
            log_warn("Invalid enable_history_tables value '%s', must be true/false or 1/0. Keeping current: %d",
                    value, config->enable_history_tables);
        }
    }
    /* Password hashing settings */
    else if (strcmp(key, "secret_hashing_algorithm") == 0) {
        if (strcmp(value, "argon2id") == 0) {
            config->secret_hashing_algorithm = PASSWORD_HASH_ARGON2ID;
        } else if (strcmp(value, "pbkdf2-sha256") == 0) {
            config->secret_hashing_algorithm = PASSWORD_HASH_PBKDF2_SHA256;
        } else {
            log_warn("Unknown secret_hashing_algorithm '%s', keeping current value", value);
        }
    } else if (strcmp(key, "secret_hash_min_iterations") == 0) {
        int iterations = 0;
        if (parse_int(value, &iterations) != 0 || iterations < 1) {
            log_warn("Invalid secret_hash_min_iterations '%s', must be >= 1. Keeping current: %d",
                    value, config->secret_hash_min_iterations);
        } else {
            config->secret_hash_min_iterations = iterations;
        }
    } else if (strcmp(key, "secret_hash_max_iterations") == 0) {
        int iterations = 0;
        if (parse_int(value, &iterations) != 0 || iterations < 1) {
            log_warn("Invalid secret_hash_max_iterations '%s', must be >= 1. Keeping current: %d",
                    value, config->secret_hash_max_iterations);
        } else {
            config->secret_hash_max_iterations = iterations;
        }
    }

    /* OAuth2 token limits */
    else if (strcmp(key, "max_access_token_ttl_seconds") == 0) {
        int ttl = 0;
        if (parse_int(value, &ttl) != 0 || ttl < 1) {
            log_warn("Invalid max_access_token_ttl_seconds '%s', must be >= 1. Keeping current: %d",
                    value, config->max_access_token_ttl_seconds);
        } else {
            config->max_access_token_ttl_seconds = ttl;
        }
    }

    /* JWT settings */
    else if (strcmp(key, "jwt_clock_skew_seconds") == 0) {
        int skew = -1;
        if (parse_int(value, &skew) != 0 || skew < 0) {
            log_warn("Invalid jwt_clock_skew_seconds '%s', must be >= 0. Keeping current: %d",
                    value, config->jwt_clock_skew_seconds);
        } else {
            config->jwt_clock_skew_seconds = skew;
        }
    }

    /* Database cleaner settings */
    else if (strcmp(key, "cleaner_enabled") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
            config->cleaner_enabled = 1;
        } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
            config->cleaner_enabled = 0;
        } else {
            log_warn("Invalid cleaner_enabled value '%s', must be true/false or 1/0. Keeping current: %d",
                    value, config->cleaner_enabled);
        }
    } else if (strcmp(key, "cleaner_interval_seconds") == 0) {
        int interval = 0;
        if (parse_int(value, &interval) != 0 || interval < 1) {
            log_warn("Invalid cleaner_interval_seconds '%s', must be >= 1. Keeping current: %d",
                    value, config->cleaner_interval_seconds);
        } else {
            config->cleaner_interval_seconds = interval;
        }
    } else if (strcmp(key, "cleaner_batch_size") == 0) {
        int batch = 0;
        if (parse_int(value, &batch) != 0 || batch < 1) {
            log_warn("Invalid cleaner_batch_size '%s', must be >= 1. Keeping current: %d",
                    value, config->cleaner_batch_size);
        } else {
            config->cleaner_batch_size = batch;
        }
    } else if (strcmp(key, "cleaner_sqlite_vacuum_pages") == 0) {
        int pages = 0;
        if (parse_int(value, &pages) != 0 || pages < 1) {
            log_warn("Invalid cleaner_sqlite_vacuum_pages '%s', must be >= 1. Keeping current: %d",
                    value, config->cleaner_sqlite_vacuum_pages);
        } else {
            config->cleaner_sqlite_vacuum_pages = pages;
        }
    } else if (strcmp(key, "cleaner_postgres_vacuum_enabled") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
            config->cleaner_postgres_vacuum_enabled = 1;
        } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
            config->cleaner_postgres_vacuum_enabled = 0;
        } else {
            log_warn("Invalid cleaner_postgres_vacuum_enabled value '%s', must be true/false or 1/0. Keeping current: %d",
                    value, config->cleaner_postgres_vacuum_enabled);
        }
    } else if (strcmp(key, "retention_usage_logs_days") == 0) {
        int days = 0;
        if (parse_int(value, &days) != 0 || days < 1) {
            log_warn("Invalid retention_usage_logs_days '%s', must be >= 1. Keeping current: %d",
                    value, config->retention_usage_logs_days);
        } else {
            config->retention_usage_logs_days = days;
        }
    } else if (strcmp(key, "retention_history_days") == 0) {
        int days = 0;
        if (parse_int(value, &days) != 0 || days < 1) {
            log_warn("Invalid retention_history_days '%s', must be >= 1. Keeping current: %d",
                    value, config->retention_history_days);
        } else {
            config->retention_history_days = days;
        }
    } else if (strcmp(key, "retention_sessions_grace_days") == 0) {
        int days = 0;
        if (parse_int(value, &days) != 0 || days < 1) {
            log_warn("Invalid retention_sessions_grace_days '%s', must be >= 1. Keeping current: %d",
                    value, config->retention_sessions_grace_days);
        } else {
            config->retention_sessions_grace_days = days;
        }
    } else if (strcmp(key, "retention_tokens_grace_days") == 0) {
        int days = 0;
        if (parse_int(value, &days) != 0 || days < 1) {
            log_warn("Invalid retention_tokens_grace_days '%s', must be >= 1. Keeping current: %d",
                    value, config->retention_tokens_grace_days);
        } else {
            config->retention_tokens_grace_days = days;
        }
    }

    /* Encryption */
    else if (strcmp(key, "encryption_key") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->encryption_key);
            config->encryption_key = new_value;
        } else {
            log_error("Failed to allocate memory for encryption_key");
        }
    } else if (strcmp(key, "encryption_key_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->encryption_key_env);
            config->encryption_key_env = new_value;
        } else {
            log_error("Failed to allocate memory for encryption_key_env");
        }
    }

    /* Logging settings */
    else if (strcmp(key, "log_level") == 0) {
        /* Parse string to enum immediately, don't store string */
        config->log_level = parse_log_level(value);
    } else if (strcmp(key, "log_level_env") == 0) {
        new_value = str_dup(value);
        if (new_value) {
            free(config->log_level_env);
            config->log_level_env = new_value;
        } else {
            log_error("Failed to allocate memory for log_level_env");
        }
    }
}

/*
 * Apply environment variable overrides
 */
static void apply_env_overrides(config_t *config) {
    char *env_value;
    const char *env_var_name;

    /* DB_TYPE: Use custom env var name if specified, else default AUTH_DB_TYPE */
    env_var_name = config->db_type_env ? config->db_type_env : "AUTH_DB_TYPE";
    env_value = getenv(env_var_name);
    if (env_value) {
        if (strcmp(env_value, "sqlite") == 0) {
            config->db_type = DB_TYPE_SQLITE;
            log_info("Config override from %s: sqlite", env_var_name);
        } else if (strcmp(env_value, "postgresql") == 0) {
            config->db_type = DB_TYPE_POSTGRESQL;
            log_info("Config override from %s: postgresql", env_var_name);
        }
    }

    /* DB_HOST */
    env_var_name = config->db_host_env ? config->db_host_env : "AUTH_DB_HOST";
    env_value = getenv(env_var_name);
    if (env_value) {
        char *new_value = str_dup(env_value);
        if (new_value) {
            free(config->db_host);
            config->db_host = new_value;
            log_info("Config override from %s", env_var_name);
        } else {
            log_error("Failed to allocate memory for %s override", env_var_name);
        }
    }

    /* DB_PORT */
    env_var_name = config->db_port_env ? config->db_port_env : "AUTH_DB_PORT";
    env_value = getenv(env_var_name);
    if (env_value) {
        int port = 0;
        parse_int(env_value, &port);
        if (port > 0 && port <= 65535) {
            config->db_port = port;
            log_info("Config override from %s: %d", env_var_name, port);
        } else {
            log_warn("Invalid port in %s: %s", env_var_name, env_value);
        }
    }

    /* DB_NAME */
    env_var_name = config->db_name_env ? config->db_name_env : "AUTH_DB_NAME";
    env_value = getenv(env_var_name);
    if (env_value) {
        char *new_value = str_dup(env_value);
        if (new_value) {
            free(config->db_name);
            config->db_name = new_value;
            log_info("Config override from %s", env_var_name);
        } else {
            log_error("Failed to allocate memory for %s override", env_var_name);
        }
    }

    /* DB_USER */
    env_var_name = config->db_user_env ? config->db_user_env : "AUTH_DB_USER";
    env_value = getenv(env_var_name);
    if (env_value) {
        char *new_value = str_dup(env_value);
        if (new_value) {
            free(config->db_user);
            config->db_user = new_value;
            log_info("Config override from %s", env_var_name);
        } else {
            log_error("Failed to allocate memory for %s override", env_var_name);
        }
    }

    /* DB_PASSWORD */
    env_var_name = config->db_password_env ? config->db_password_env : "AUTH_DB_PASSWORD";
    env_value = getenv(env_var_name);
    if (env_value) {
        char *new_value = str_dup(env_value);
        if (new_value) {
            free(config->db_password);
            config->db_password = new_value;
            log_info("Config override from %s: [REDACTED]", env_var_name);
        } else {
            log_error("Failed to allocate memory for %s override", env_var_name);
        }
    }

    /* DB_OWNER_ROLE */
    env_var_name = config->db_owner_role_env ? config->db_owner_role_env : "AUTH_DB_OWNER_ROLE";
    env_value = getenv(env_var_name);
    if (env_value) {
        if (strlen(env_value) > 32) {
            log_warn("Ignoring %s: value too long (max 32 characters)", env_var_name);
        } else {
            char *new_value = str_dup(env_value);
            if (new_value) {
                free(config->db_owner_role);
                config->db_owner_role = new_value;
                log_info("Config override from %s", env_var_name);
            } else {
                log_error("Failed to allocate memory for %s override", env_var_name);
            }
        }
    }

    /* ENCRYPTION_KEY */
    env_var_name = config->encryption_key_env ? config->encryption_key_env : "AUTH_ENCRYPTION_KEY";
    env_value = getenv(env_var_name);
    if (env_value) {
        char *new_value = str_dup(env_value);
        if (new_value) {
            free(config->encryption_key);
            config->encryption_key = new_value;
            log_info("Config override from %s: [REDACTED]", env_var_name);
        } else {
            log_error("Failed to allocate memory for %s override", env_var_name);
        }
    }

    /* LOG_LEVEL */
    env_var_name = config->log_level_env ? config->log_level_env : "AUTH_LOG_LEVEL";
    env_value = getenv(env_var_name);
    if (env_value) {
        /* Parse string to enum immediately, don't store string */
        config->log_level = parse_log_level(env_value);
        log_info("Config override from %s: %s", env_var_name, env_value);
    }

    /* CLEANER_ENABLED */
    env_value = getenv("AUTH_CLEANER_ENABLED");
    if (env_value) {
        if (strcmp(env_value, "true") == 0 || strcmp(env_value, "1") == 0) {
            config->cleaner_enabled = 1;
            log_info("Config override from AUTH_CLEANER_ENABLED: enabled");
        } else if (strcmp(env_value, "false") == 0 || strcmp(env_value, "0") == 0) {
            config->cleaner_enabled = 0;
            log_info("Config override from AUTH_CLEANER_ENABLED: disabled");
        }
    }

    /* CLEANER_INTERVAL_SECONDS */
    env_value = getenv("AUTH_CLEANER_INTERVAL_SECONDS");
    if (env_value) {
        int interval = 0;
        parse_int(env_value, &interval);
        if (interval >= 1) {
            config->cleaner_interval_seconds = interval;
            log_info("Config override from AUTH_CLEANER_INTERVAL_SECONDS: %d", interval);
        } else {
            log_warn("Invalid AUTH_CLEANER_INTERVAL_SECONDS: %s", env_value);
        }
    }

    /* CLEANER_BATCH_SIZE */
    env_value = getenv("AUTH_CLEANER_BATCH_SIZE");
    if (env_value) {
        int batch = 0;
        parse_int(env_value, &batch);
        if (batch >= 1) {
            config->cleaner_batch_size = batch;
            log_info("Config override from AUTH_CLEANER_BATCH_SIZE: %d", batch);
        } else {
            log_warn("Invalid AUTH_CLEANER_BATCH_SIZE: %s", env_value);
        }
    }

    /* CLEANER_SQLITE_VACUUM_PAGES */
    env_value = getenv("AUTH_CLEANER_SQLITE_VACUUM_PAGES");
    if (env_value) {
        int pages = 0;
        parse_int(env_value, &pages);
        if (pages >= 1) {
            config->cleaner_sqlite_vacuum_pages = pages;
            log_info("Config override from AUTH_CLEANER_SQLITE_VACUUM_PAGES: %d", pages);
        } else {
            log_warn("Invalid AUTH_CLEANER_SQLITE_VACUUM_PAGES: %s", env_value);
        }
    }

    /* CLEANER_POSTGRES_VACUUM_ENABLED */
    env_value = getenv("AUTH_CLEANER_POSTGRES_VACUUM_ENABLED");
    if (env_value) {
        if (strcmp(env_value, "true") == 0 || strcmp(env_value, "1") == 0) {
            config->cleaner_postgres_vacuum_enabled = 1;
            log_info("Config override from AUTH_CLEANER_POSTGRES_VACUUM_ENABLED: enabled");
        } else if (strcmp(env_value, "false") == 0 || strcmp(env_value, "0") == 0) {
            config->cleaner_postgres_vacuum_enabled = 0;
            log_info("Config override from AUTH_CLEANER_POSTGRES_VACUUM_ENABLED: disabled");
        }
    }

    /* RETENTION_USAGE_LOGS_DAYS */
    env_value = getenv("AUTH_RETENTION_USAGE_LOGS_DAYS");
    if (env_value) {
        int days = 0;
        parse_int(env_value, &days);
        if (days >= 1) {
            config->retention_usage_logs_days = days;
            log_info("Config override from AUTH_RETENTION_USAGE_LOGS_DAYS: %d", days);
        } else {
            log_warn("Invalid AUTH_RETENTION_USAGE_LOGS_DAYS: %s", env_value);
        }
    }

    /* RETENTION_HISTORY_DAYS */
    env_value = getenv("AUTH_RETENTION_HISTORY_DAYS");
    if (env_value) {
        int days = 0;
        parse_int(env_value, &days);
        if (days >= 1) {
            config->retention_history_days = days;
            log_info("Config override from AUTH_RETENTION_HISTORY_DAYS: %d", days);
        } else {
            log_warn("Invalid AUTH_RETENTION_HISTORY_DAYS: %s", env_value);
        }
    }

    /* RETENTION_SESSIONS_GRACE_DAYS */
    env_value = getenv("AUTH_RETENTION_SESSIONS_GRACE_DAYS");
    if (env_value) {
        int days = 0;
        parse_int(env_value, &days);
        if (days >= 1) {
            config->retention_sessions_grace_days = days;
            log_info("Config override from AUTH_RETENTION_SESSIONS_GRACE_DAYS: %d", days);
        } else {
            log_warn("Invalid AUTH_RETENTION_SESSIONS_GRACE_DAYS: %s", env_value);
        }
    }

    /* RETENTION_TOKENS_GRACE_DAYS */
    env_value = getenv("AUTH_RETENTION_TOKENS_GRACE_DAYS");
    if (env_value) {
        int days = 0;
        parse_int(env_value, &days);
        if (days >= 1) {
            config->retention_tokens_grace_days = days;
            log_info("Config override from AUTH_RETENTION_TOKENS_GRACE_DAYS: %d", days);
        } else {
            log_warn("Invalid AUTH_RETENTION_TOKENS_GRACE_DAYS: %s", env_value);
        }
    }

    /* ENABLE_HISTORY_TABLES */
    env_var_name = config->enable_history_tables_env ?
                   config->enable_history_tables_env :
                   "AUTH_ENABLE_HISTORY_TABLES";
    env_value = getenv(env_var_name);
    if (env_value) {
        if (strcmp(env_value, "true") == 0 || strcmp(env_value, "1") == 0) {
            config->enable_history_tables = 1;
            log_info("Config override from %s: enabled", env_var_name);
        } else if (strcmp(env_value, "false") == 0 || strcmp(env_value, "0") == 0) {
            config->enable_history_tables = 0;
            log_info("Config override from %s: disabled", env_var_name);
        } else {
            log_warn("Invalid %s value: %s", env_var_name, env_value);
        }
    }
}

config_t *config_load(const char *config_file) {
    /* Allocate config with defaults */
    config_t *config = calloc(1, sizeof(config_t));
    if (!config) {
        log_error("Failed to allocate config");
        return NULL;
    }

    /* Set defaults - check allocations */
    config->host = str_dup(DEFAULT_HOST);
    if (!config->host) {
        log_error("Failed to allocate default host");
        config_free(config);
        return NULL;
    }

    config->port = DEFAULT_PORT;
    config->workers = DEFAULT_WORKERS;
    config->db_type = DEFAULT_DB_TYPE;

    config->db_path = str_dup(DEFAULT_DB_PATH);
    if (!config->db_path) {
        log_error("Failed to allocate default db_path");
        config_free(config);
        return NULL;
    }

    config->db_host = NULL;
    config->db_port = DEFAULT_DB_PORT;
    config->db_name = NULL;
    config->db_user = NULL;
    config->db_password = NULL;
    config->db_owner_role = NULL;

    /* ENV variable name overrides (NULL = use defaults) */
    config->db_type_env = NULL;
    config->db_host_env = NULL;
    config->db_port_env = NULL;
    config->db_name_env = NULL;
    config->db_user_env = NULL;
    config->db_password_env = NULL;
    config->db_owner_role_env = NULL;
    config->enable_history_tables_env = NULL;
    config->encryption_key_env = NULL;

    /* Encryption default */
    config->encryption_key = str_dup("customize_me");
    if (!config->encryption_key) {
        log_error("Failed to allocate default encryption_key");
        config_free(config);
        return NULL;
    }

    /* Password hashing defaults */
    config->secret_hashing_algorithm = PASSWORD_HASH_ARGON2ID;  /* Default to Argon2id */
    config->secret_hash_min_iterations = 4;                     /* Default constant iterations */
    config->secret_hash_max_iterations = 4;

    /* OAuth2 token limits */
    config->max_access_token_ttl_seconds = DEFAULT_MAX_ACCESS_TOKEN_TTL_SECONDS;

    /* JWT settings */
    config->jwt_clock_skew_seconds = DEFAULT_JWT_CLOCK_SKEW_SECONDS;

    /* Database cleaner defaults */
    config->cleaner_enabled = DEFAULT_CLEANER_ENABLED;
    config->cleaner_interval_seconds = DEFAULT_CLEANER_INTERVAL_SECONDS;
    config->cleaner_batch_size = DEFAULT_CLEANER_BATCH_SIZE;
    config->cleaner_sqlite_vacuum_pages = DEFAULT_CLEANER_SQLITE_VACUUM_PAGES;
    config->cleaner_postgres_vacuum_enabled = DEFAULT_CLEANER_POSTGRES_VACUUM_ENABLED;
    config->retention_usage_logs_days = DEFAULT_RETENTION_USAGE_LOGS_DAYS;
    config->retention_history_days = DEFAULT_RETENTION_HISTORY_DAYS;
    config->retention_sessions_grace_days = DEFAULT_RETENTION_SESSIONS_GRACE_DAYS;
    config->retention_tokens_grace_days = DEFAULT_RETENTION_TOKENS_GRACE_DAYS;

    /* Logging defaults */
    config->log_level = parse_log_level(DEFAULT_LOG_LEVEL);
    config->log_level_env = NULL;

    config->schema_dir = str_dup(DEFAULT_SCHEMA_DIR);
    if (!config->schema_dir) {
        log_error("Failed to allocate default schema_dir");
        config_free(config);
        return NULL;
    }

    config->enable_history_tables = DEFAULT_ENABLE_HISTORY_TABLES;

    /* Try to open config file */
    FILE *file = fopen(config_file, "r");
    if (!file) {
        /* Check if an example file exists and hint to the user */
        char example_path[512];
        snprintf(example_path, sizeof(example_path), "%s.example", config_file);
        FILE *example = fopen(example_path, "r");
        if (example) {
            fclose(example);
            log_warn("Config file '%s' not found — copy '%s' to '%s' and customize it",
                     config_file, example_path, config_file);
        } else {
            log_warn("Config file '%s' not found, using defaults", config_file);
        }
        apply_env_overrides(config);
        return config;
    }

    log_info("Loading config from '%s'", config_file);

    /* Parse config file */
    char line[MAX_LINE_LENGTH];
    int line_num = 0;

    while (fgets(line, sizeof(line), file)) {
        line_num++;

        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Trim whitespace */
        trim(line);

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') {
            continue;
        }

        /* Parse key=value */
        char key[128], value[MAX_LINE_LENGTH];
        if (parse_key_value(line, key, sizeof(key), value, sizeof(value)) == 0) {
            set_config_value(config, key, value);
        } else {
            log_warn("Line %d: Invalid line format", line_num);
        }
    }

    fclose(file);

    /* Apply environment variable overrides */
    apply_env_overrides(config);

    /* Validate password hashing iterations */
    if (config->secret_hash_max_iterations < config->secret_hash_min_iterations) {
        log_warn("secret_hash_max_iterations (%d) < secret_hash_min_iterations (%d). "
                "Setting max = min.",
                config->secret_hash_max_iterations, config->secret_hash_min_iterations);
        config->secret_hash_max_iterations = config->secret_hash_min_iterations;
    }

    log_info("Configuration loaded successfully");
    return config;
}

void config_free(config_t *config) {
    if (!config) return;

    free(config->host);
    free(config->db_path);
    free(config->db_host);
    free(config->db_name);
    free(config->db_user);
    free(config->db_owner_role);
    /* Cleanse sensitive values before freeing */
    if (config->db_password) {
        OPENSSL_cleanse(config->db_password, strlen(config->db_password));
    }
    if (config->encryption_key) {
        OPENSSL_cleanse(config->encryption_key, strlen(config->encryption_key));
    }

    free(config->db_password);
    free(config->schema_dir);

    /* Free ENV variable name overrides */
    free(config->db_type_env);
    free(config->db_host_env);
    free(config->db_port_env);
    free(config->db_name_env);
    free(config->db_user_env);
    free(config->db_password_env);
    free(config->db_owner_role_env);
    free(config->enable_history_tables_env);
    free(config->encryption_key_env);
    free(config->log_level_env);

    free(config->encryption_key);

    free(config);
}
