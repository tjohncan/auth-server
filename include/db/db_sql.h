#ifndef DB_SQL_H
#define DB_SQL_H

/*
 * Database SQL Abstraction Layer
 *
 * Provides compile-time macros to write portable SQL queries.
 * Handles differences between database technologies:
 *   - Parameter placeholder syntax (? vs $)
 *   - Schema qualification (flat vs schema.table)
 */

/* ============================================================================
 * Parameter Placeholder
 * ============================================================================
 *
 * Use P with string concatenation for numbered parameters.
 */

#ifdef DB_BACKEND_SQLITE
    #define P "?"
#endif

#ifdef DB_BACKEND_POSTGRESQL
    #define P "$"
#endif

/* ============================================================================
 * Boolean Literals
 * ============================================================================
 *
 * Use for boolean comparisons in WHERE clauses.
 */

#ifdef DB_BACKEND_SQLITE
    #define BOOL_TRUE  "1"
    #define BOOL_FALSE "0"
#endif

#ifdef DB_BACKEND_POSTGRESQL
    #define BOOL_TRUE  "true"
    #define BOOL_FALSE "false"
#endif

/* ============================================================================
 * Transaction Control
 * ============================================================================
 *
 * BEGIN_WRITE starts a transaction with write intent.
 * SQLite: BEGIN IMMEDIATE acquires write lock upfront (prevents deadlocks).
 * PostgreSQL: plain BEGIN (MVCC handles concurrency).
 */

#ifdef DB_BACKEND_SQLITE
    #define BEGIN_WRITE "BEGIN IMMEDIATE"
#endif

#ifdef DB_BACKEND_POSTGRESQL
    #define BEGIN_WRITE "BEGIN"
#endif

/* ============================================================================
 * Date/Time Functions
 * ============================================================================
 *
 * Use for current timestamp in queries.
 * UNIX_TS(expr) converts a datetime expression to Unix epoch seconds.
 * INTERVAL_SECONDS(expr) creates a relative time offset from now.
 * DAYS_AGO(n) creates a timestamp N days in the past (for cleanup queries).
 *   Note: n must be a string literal or char array, not an integer.
 *   Example: DAYS_AGO("90") or with snprintf: sprintf(buf, "%d", days); DAYS_AGO(buf)
 */

#ifdef DB_BACKEND_SQLITE
    #define NOW "datetime('now')"
    #define UNIX_TS(expr) "strftime('%s', " expr ")"
    #define INTERVAL_SECONDS(expr) "datetime('now', '+' || " expr " || ' seconds')"
    #define DAYS_AGO(n) "datetime('now', '-" n " days')"
#endif

#ifdef DB_BACKEND_POSTGRESQL
    #define NOW "NOW()"
    #define UNIX_TS(expr) "EXTRACT(EPOCH FROM " expr ")"
    #define INTERVAL_SECONDS(expr) "(NOW() + (" expr " || ' seconds')::interval)"
    #define DAYS_AGO(n) "(NOW() - INTERVAL '" n " days')"
#endif

/* ============================================================================
 * Schema Prefixes
 * ============================================================================
 *
 * PostgreSQL uses schemas (security.user_account).
 * SQLite uses flat namespace (user_account).
 */

#ifdef DB_BACKEND_SQLITE
    #define KEYS_      ""
    #define SECURITY_  ""
    #define SESSION_   ""
    #define LOOKUP_    ""
    #define LOGGING_   ""
#endif

#ifdef DB_BACKEND_POSTGRESQL
    #define KEYS_      "keys."
    #define SECURITY_  "security."
    #define SESSION_   "session."
    #define LOOKUP_    "lookup."
    #define LOGGING_   "logging."
#endif

/* ============================================================================
 * Table Names (defined once, schema prefix applied automatically)
 * ============================================================================ */

/* KEYS schema */
#define TBL_AUTH_REQUEST_SIGNING      KEYS_ "auth_request_signing"
#define TBL_ACCESS_TOKEN_SIGNING      KEYS_ "access_token_signing"

/* SECURITY schema */
#define TBL_ORGANIZATION              SECURITY_ "organization"
#define TBL_ORGANIZATION_KEY          SECURITY_ "organization_key"
#define TBL_RESOURCE_SERVER           SECURITY_ "resource_server"
#define TBL_RESOURCE_SERVER_KEY       SECURITY_ "resource_server_key"
#define TBL_CLIENT                    SECURITY_ "client"
#define TBL_CLIENT_KEY                SECURITY_ "client_key"
#define TBL_CLIENT_REDIRECT_URI       SECURITY_ "client_redirect_uri"
#define TBL_CLIENT_RESOURCE_SERVER    SECURITY_ "client_resource_server"
#define TBL_USER_ACCOUNT              SECURITY_ "user_account"
#define TBL_USER_EMAIL                SECURITY_ "user_email"
#define TBL_USER_MFA                  SECURITY_ "user_mfa"
#define TBL_CLIENT_USER               SECURITY_ "client_user"
#define TBL_RECOVERY_CODE_SET         SECURITY_ "recovery_code_set"
#define TBL_RECOVERY_CODE             SECURITY_ "recovery_code"
#define TBL_ORGANIZATION_ADMIN        SECURITY_ "organization_admin"

/* SESSION schema */
#define TBL_BROWSER                   SESSION_ "browser"
#define TBL_AUTHORIZATION_CODE        SESSION_ "authorization_code"
#define TBL_REFRESH_TOKEN             SESSION_ "refresh_token"
#define TBL_ACCESS_TOKEN              SESSION_ "access_token"
#define TBL_PASSWORDLESS_LOGIN_TOKEN  SESSION_ "passwordless_login_token"
#define TBL_EMAIL_VERIFICATION_TOKEN  SESSION_ "email_verification_token"
#define TBL_PASSWORD_RESET_TOKEN      SESSION_ "password_reset_token"

/* LOOKUP schema */
#define TBL_GRANT_TYPE                LOOKUP_ "grant_type"
#define TBL_CLIENT_TYPE               LOOKUP_ "client_type"
#define TBL_MFA_METHOD                LOOKUP_ "mfa_method"
#define TBL_CODE_CHALLENGE_METHOD     LOOKUP_ "code_challenge_method"

/* LOGGING schema */
#define TBL_CLIENT_KEY_USAGE          LOGGING_ "client_key_usage"
#define TBL_RESOURCE_SERVER_KEY_USAGE LOGGING_ "resource_server_key_usage"
#define TBL_ORGANIZATION_KEY_USAGE    LOGGING_ "organization_key_usage"
#define TBL_USER_MFA_USAGE            LOGGING_ "user_mfa_usage"

/* ============================================================================
 * Example Usage
 * ============================================================================
 *
 * Write SQL once, works for both backends:
 *
 *   const char *sql =
 *       "SELECT username, email "
 *       "FROM " TBL_USER_ACCOUNT " "
 *       "WHERE email = " P"1" " AND is_active = " P"2";
 *
 * SQLite expands to:
 *   "SELECT username, email FROM user_account WHERE email = ?1 AND is_active = ?2"
 *
 * PostgreSQL expands to:
 *   "SELECT username, email FROM security.user_account WHERE email = $1 AND is_active = $2"
 */

#endif /* DB_SQL_H */
