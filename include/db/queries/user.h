#ifndef DB_QUERIES_USER_H
#define DB_QUERIES_USER_H

#include "db/db.h"

/*
 * User Account Query Functions
 *
 * Entity-based query layer for user_account and user_email operations.
 * Reusable across bootstrap, invitation, registration, and login flows.
 */

/*
 * Check if username exists (case-insensitive)
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int user_username_exists(db_handle_t *db, const char *username);

/*
 * Check if email exists (case-insensitive)
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int user_email_exists(db_handle_t *db, const char *email);

/*
 * Check if user exists by ID
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int user_id_exists(db_handle_t *db, const unsigned char *user_id);

/*
 * Look up user ID by username
 *
 * Parameters:
 *   db         - Database handle
 *   username   - Username to look up
 *   out_user_id - Output: 16-byte UUID of user
 *
 * Returns: 0 on success, -1 on error or user not found
 */
int user_lookup_id_by_username(db_handle_t *db, const char *username,
                                unsigned char *out_user_id);

/*
 * Create user account with optional email
 *
 * Creates user_account record, optionally with user_email record.
 * Hashes password using crypto/password module (must be initialized first).
 * If email provided, it's marked as primary but not verified.
 *
 * Parameters:
 *   db           - Database handle
 *   username     - Unique username (can be NULL for email-only accounts)
 *   email        - Email address (optional, can be NULL)
 *   password     - Plaintext password (will be hashed)
 *   out_user_id  - Output: 16-byte UUID for created user
 *
 * Transaction: Creates user_account + user_email in single transaction if email provided
 *
 * Returns: 0 on success, -1 on error
 */
int user_create(db_handle_t *db, const char *username,
                const char *email, const char *password,
                unsigned char *out_user_id);

/*
 * Verify user password
 *
 * Looks up user by username and verifies password hash.
 * Uses timing-safe comparison.
 * Optionally returns user PIN and ID on successful authentication.
 *
 * Parameters:
 *   db       - Database handle
 *   username - Username to authenticate
 *   password - Plaintext password to verify
 *   out_pin  - Output: User PIN (optional, can be NULL)
 *   out_id   - Output: User ID (16-byte UUID, optional, can be NULL)
 *
 * Returns: 1 if password valid (and sets out_pin/out_id if provided),
 *          0 if invalid,
 *          -1 on error
 */
int user_verify_password(db_handle_t *db, const char *username,
                         const char *password, long long *out_pin,
                         unsigned char *out_id);

/*
 * Make user an admin of organization
 *
 * Creates organization_admin record.
 *
 * Parameters:
 *   db            - Database handle
 *   user_id       - User UUID (16 bytes)
 *   org_code_name - Organization code name (e.g., "system")
 *
 * Returns: 0 on success, -1 on error
 */
int user_make_org_admin(db_handle_t *db, const unsigned char *user_id,
                        const char *org_code_name);

/*
 * Management UI Setup Info
 *
 * Represents a valid management UI configuration that the user can access.
 */
typedef struct {
    char org_code_name[64];
    char org_display_name[256];
    unsigned char client_id[16];
    char client_code_name[64];
    char client_display_name[256];
    char resource_server_address[256];
} management_ui_setup_t;

/*
 * Get management UI setups for user
 *
 * Returns valid management UI configurations that:
 * - User is an org admin for
 * - Have active org, client, and resource server
 * - Client redirect_uri matches the provided callback URL (exact match)
 * - Resource server address matches the provided API URL (exact match)
 *
 * Results ordered by: org_code_name ASC, client_code_name ASC (stable pagination)
 *
 * Parameters:
 *   db                - Database handle
 *   user_account_pin  - User account PIN
 *   callback_url      - Expected callback URL (e.g., "http://localhost:8080/callback")
 *   api_url           - Expected API URL (e.g., "http://localhost:8080/api")
 *   limit             - Maximum number of records to return
 *   offset            - Number of records to skip (for pagination)
 *   out_setups        - Output: Array of setups (caller must free)
 *   out_count         - Output: Number of setups found
 *
 * Returns: 0 on success, -1 on error
 */
int user_get_management_ui_setups(db_handle_t *db, long long user_account_pin,
                                   const char *callback_url, const char *api_url,
                                   int limit, int offset,
                                   management_ui_setup_t **out_setups, int *out_count);

/* User profile data structure */
typedef struct {
    unsigned char user_id[16];  /* User UUID */
    char username[256];          /* Username (may be empty string if not set) */
    int has_mfa;                 /* 1 if user has at least one confirmed MFA method */
    int require_mfa;             /* 1 if user opted in to enforce MFA themselves */
} user_profile_t;

/*
 * Get user profile by PIN
 *
 * Returns basic profile information for authenticated user.
 * Username may be empty string if not set (email-only accounts).
 *
 * Parameters:
 *   db                - Database handle
 *   user_account_pin  - User account PIN (from session)
 *   out_profile       - Output: User profile data
 *
 * Returns: 0 on success, -1 on error or user not found
 */
int user_get_profile(db_handle_t *db, long long user_account_pin,
                     user_profile_t *out_profile);

/* OpenID Connect UserInfo data structure */
typedef struct {
    unsigned char user_id[16];   /* User UUID */
    char username[256];          /* Decrypted username */
    char email[256];             /* Decrypted primary email (empty if none) */
    int email_verified;          /* 1 if primary email is verified */
} user_userinfo_t;

/*
 * Get UserInfo by user UUID (for OIDC /userinfo endpoint)
 *
 * Looks up user by UUID, returns username and primary email.
 * Used when authenticating via Bearer token (JWT sub claim).
 *
 * Parameters:
 *   db       - Database handle
 *   user_id  - User UUID (16 bytes)
 *   out      - Output: UserInfo data
 *
 * Returns: 0 on success, -1 on error or user not found
 */
int user_get_userinfo_by_id(db_handle_t *db, const unsigned char *user_id,
                            user_userinfo_t *out);

/* User email data structure */
typedef struct {
    char email_address[256];
    int is_primary;
    int is_verified;
} user_email_t;

/*
 * Get user emails by PIN
 *
 * Returns email addresses for the authenticated user.
 * Users may have zero emails (username-only accounts).
 *
 * Results ordered by: is_primary DESC, created_at ASC (stable pagination)
 *
 * Parameters:
 *   db                - Database handle
 *   user_account_pin  - User account PIN (from session)
 *   limit             - Maximum number of records to return
 *   offset            - Number of records to skip (for pagination)
 *   out_emails        - Output: Array of emails (caller must free)
 *   out_count         - Output: Number of emails returned in this page
 *   out_total         - Output: Total number of emails across all pages (optional, can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int user_get_emails(db_handle_t *db, long long user_account_pin,
                    int limit, int offset,
                    user_email_t **out_emails, int *out_count, int *out_total);

/*
 * Change user password
 *
 * Verifies current password and updates to new password.
 * Uses crypto/password module for secure bcrypt hashing.
 *
 * Parameters:
 *   db                  - Database handle
 *   user_account_pin    - User account PIN (from session)
 *   user_account_id     - User UUID (for logging)
 *   current_password    - Current plaintext password (for verification)
 *   new_password        - New plaintext password (will be hashed)
 *
 * Returns: 1 if password changed successfully,
 *          0 if current password is invalid,
 *          -1 on error
 */
int user_change_password(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *current_password,
                         const char *new_password);

/*
 * Change username
 *
 * Validates format, checks uniqueness, and updates username.
 *
 * Parameters:
 *   db                  - Database handle
 *   user_account_pin    - User account PIN (from session)
 *   user_account_id     - User UUID (for logging)
 *   new_username        - New username (validated and checked for uniqueness)
 *
 * Returns: 1 if username changed successfully,
 *          0 if username already taken,
 *          -1 on error (validation failure or database error)
 */
int user_change_username(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *new_username);

#endif /* DB_QUERIES_USER_H */
