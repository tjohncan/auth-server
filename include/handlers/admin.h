#ifndef HANDLERS_ADMIN_H
#define HANDLERS_ADMIN_H

#include "db/db.h"
#include "db/queries/org.h"
#include "db/queries/resource_server.h"
#include "db/queries/client.h"
#include "util/config.h"

/*
 * Admin Handler Functions
 *
 * Business logic layer for all security schema operations.
 * These handlers wrap database queries with validation and error handling.
 * Used by: localhost admin API, management API, management UI.
 *
 * All handlers:
 * - Perform input validation
 * - Run existence pre-checks where appropriate
 * - Call underlying query functions
 * - Return 0 on success, -1 on error
 *
 * Note: HTTP layer (localhost check, JSON parsing) is separate.
 */

/* ============================================================================
 * BOOTSTRAP
 * ========================================================================== */

/*
 * Bootstrap the authentication system
 *
 * Creates:
 * - System organization
 * - Management API resource server
 * - Management UI client (public, universal)
 * - First admin user with org-admin privileges
 *
 * Fails if system org already exists (not idempotent at org level).
 *
 * Parameters:
 *   db                - Database handle
 *   config            - Server config (for port to build addresses)
 *   org_code_name     - Organization code name (e.g., "system")
 *   org_display_name  - Organization display name (e.g., "System")
 *   username          - Admin username
 *   password          - Admin password (plaintext, will be hashed)
 *
 * Returns: 0 on success, -1 on error
 */
int admin_bootstrap(db_handle_t *db,
                   const config_t *config,
                   const char *org_code_name,
                   const char *org_display_name,
                   const char *username,
                   const char *password);

/* ============================================================================
 * ORGANIZATION OPERATIONS
 * ========================================================================== */

/* Admin type aliases for query-layer structs (single source of truth) */
typedef org_data_t admin_organization_t;

/*
 * Create organization
 *
 * Validates that code_name doesn't exist, then creates organization.
 *
 * Parameters:
 *   db            - Database handle
 *   code_name     - Unique organization code name
 *   display_name  - Human-readable name
 *   note          - Optional description (can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int admin_create_organization(db_handle_t *db,
                              const char *code_name,
                              const char *display_name,
                              const char *note);

/*
 * List all organizations where user is admin
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session) or -1 (org key)
 *   organization_key_pin - Key PIN (org key) or -1 (session)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   filter_is_active     - Filter by active status (optional)
 *   out_orgs             - Output: array of organizations (caller must free)
 *   out_count            - Output: number of organizations in array
 *
 * Returns: 0 on success, -1 on error
 */
int admin_list_organizations(db_handle_t *db, long long user_account_pin,
                             long long organization_key_pin,
                             int limit, int offset,
                             const int *filter_is_active,
                             admin_organization_t **out_orgs,
                             int *out_count,
                             int *out_total);

/*
 * Get single organization by ID
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session) or -1 (org key)
 *   organization_key_pin - Key PIN (org key) or -1 (session)
 *   org_id               - Organization UUID (16 bytes)
 *   out_org              - Output: organization data
 *
 * Returns: 0 on success (found), -1 on error or not found
 */
int admin_get_organization(db_handle_t *db, long long user_account_pin,
                           long long organization_key_pin,
                           const unsigned char *org_id,
                           admin_organization_t *out_org);

/*
 * Update organization
 *
 * Dual-auth capable: session user OR organization key.
 * Pass NULL for fields you don't want to update.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session) or -1 (org key)
 *   organization_key_pin - Key PIN (org key) or -1 (session)
 *   org_id               - Organization UUID (16 bytes)
 *   display_name         - New display name (NULL = no change)
 *   note                 - New note (NULL = no change)
 *   is_active            - New active status pointer (NULL = no change)
 *
 * Returns: 0 on success, -1 on error or not found
 */
int admin_update_organization(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *org_id,
                              const char *display_name,
                              const char *note,
                              const int *is_active);

/* ============================================================================
 * RESOURCE SERVER OPERATIONS
 * ========================================================================== */

/*
 * Create resource server
 *
 * Validates code_name and address uniqueness within org, then creates.
 *
 * Parameters:
 *   db            - Database handle
 *   org_code_name - Organization code name (must exist)
 *   code_name     - Unique resource server code name within org
 *   display_name  - Human-readable name
 *   address       - API base URL
 *   note          - Optional description (can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int admin_create_resource_server_bootstrap(db_handle_t *db,
                                            const char *org_code_name,
                                            const char *code_name,
                                            const char *display_name,
                                            const char *address,
                                            const char *note);

typedef resource_server_data_t admin_resource_server_t;

int admin_list_resource_servers(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *organization_id,
                                 int limit, int offset,
                                 const int *filter_is_active,
                                 admin_resource_server_t **out_servers,
                                 int *out_count,
                                 int *out_total);

int admin_create_resource_server(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *organization_id,
                                   const char *code_name,
                                   const char *display_name,
                                   const char *address,
                                   const char *note,
                                   unsigned char *out_id);

int admin_get_resource_server(db_handle_t *db, long long user_account_pin,
                               long long organization_key_pin,
                               const unsigned char *server_id,
                               admin_resource_server_t *out_server);

int admin_update_resource_server(db_handle_t *db, long long user_account_pin,
                                  long long organization_key_pin,
                                  const unsigned char *server_id,
                                  const char *display_name,
                                  const char *address,
                                  const char *note,
                                  const int *is_active);

/* ============================================================================
 * CLIENT OPERATIONS
 * ========================================================================== */

/*
 * Create client (bootstrap use)
 *
 * Validates code_name uniqueness within org, then creates client.
 * Full parameter list for all possible client configurations.
 *
 * Parameters:
 *   db                          - Database handle
 *   org_code_name               - Organization code name (must exist)
 *   code_name                   - Unique client code name within org
 *   display_name                - Human-readable name
 *   client_type                 - "public" or "confidential"
 *   grant_type                  - "authorization_code" or "client_credentials"
 *   note                        - Optional description (can be NULL)
 *   require_mfa                 - 1 to require MFA, 0 otherwise
 *   access_token_ttl_seconds    - Access token lifetime
 *   issue_refresh_tokens        - 1 to issue refresh tokens, 0 otherwise
 *   refresh_token_ttl_seconds   - Refresh token lifetime (use -1 for NULL)
 *   maximum_session_seconds     - Maximum session duration (use -1 for NULL)
 *   secret_rotation_seconds     - Secret rotation interval (use -1 for NULL)
 *   is_universal                - 1 if universal client, 0 otherwise
 *   out_client_id               - Output: 16-byte client UUID
 *
 * Returns: 0 on success, -1 on error
 */
int admin_create_client_bootstrap(db_handle_t *db,
                                   const char *org_code_name,
                                   const char *code_name,
                                   const char *display_name,
                                   const char *client_type,
                                   const char *grant_type,
                                   const char *note,
                                   int require_mfa,
                                   int access_token_ttl_seconds,
                                   int issue_refresh_tokens,
                                   int refresh_token_ttl_seconds,
                                   int maximum_session_seconds,
                                   int secret_rotation_seconds,
                                   int is_universal,
                                   unsigned char *out_client_id);

/*
 * Add redirect URI to client (bootstrap use)
 *
 * Validates client exists, then adds redirect URI.
 *
 * Parameters:
 *   db          - Database handle
 *   client_id   - Client UUID (16 bytes)
 *   redirect_uri - OAuth2 callback URL
 *   note        - Optional description (can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int admin_add_client_redirect_uri_bootstrap(db_handle_t *db,
                                            const unsigned char *client_id,
                                            const char *redirect_uri,
                                            const char *note);

/*
 * Link client to resource server (bootstrap use)
 *
 * Grants client permission to access resource server API.
 * Validates both client and resource server exist in same org.
 *
 * Parameters:
 *   db                      - Database handle
 *   org_code_name           - Organization code name
 *   client_id               - Client UUID (16 bytes)
 *   resource_server_address - Resource server address
 *
 * Returns: 0 on success, -1 on error
 */
int admin_link_client_resource_server_bootstrap(db_handle_t *db,
                                                const char *org_code_name,
                                                const unsigned char *client_id,
                                                const char *resource_server_address);

typedef client_data_t admin_client_t;

int admin_list_clients(db_handle_t *db, long long user_account_pin,
                       long long organization_key_pin,
                       const unsigned char *organization_id,
                       int limit, int offset,
                       const int *filter_is_active,
                       admin_client_t **out_clients,
                       int *out_count,
                       int *out_total);

int admin_create_client(db_handle_t *db, long long user_account_pin,
                         long long organization_key_pin,
                         const unsigned char *organization_id,
                         const char *code_name,
                         const char *display_name,
                         const char *client_type,
                         const char *grant_type,
                         const char *note,
                         int require_mfa,
                         int access_token_ttl_seconds,
                         int issue_refresh_tokens,
                         int refresh_token_ttl_seconds,
                         int maximum_session_seconds,
                         int secret_rotation_seconds,
                         unsigned char *out_id);

int admin_get_client(db_handle_t *db, long long user_account_pin,
                     long long organization_key_pin,
                     const unsigned char *client_id,
                     admin_client_t *out_client);

int admin_update_client(db_handle_t *db, long long user_account_pin,
                        long long organization_key_pin,
                        const unsigned char *client_id,
                        const char *display_name,
                        const char *note,
                        const int *require_mfa,
                        const int *access_token_ttl_seconds,
                        const int *issue_refresh_tokens,
                        const int *refresh_token_ttl_seconds,
                        const int *maximum_session_seconds,
                        const int *secret_rotation_seconds,
                        const int *is_active);

typedef client_redirect_uri_data_t admin_client_redirect_uri_t;

int admin_list_client_redirect_uris(db_handle_t *db, long long user_account_pin,
                                     long long organization_key_pin,
                                     const unsigned char *client_id,
                                     int limit, int offset,
                                     admin_client_redirect_uri_t **out_uris,
                                     int *out_count,
                                     int *out_total);

int admin_create_client_redirect_uri(db_handle_t *db, long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *client_id,
                                      const char *redirect_uri,
                                      const char *note);

int admin_delete_client_redirect_uri(db_handle_t *db, long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *client_id,
                                      const char *redirect_uri);

typedef client_resource_server_data_t admin_client_resource_server_t;
typedef resource_server_client_data_t admin_resource_server_client_t;

int admin_list_client_resource_servers(db_handle_t *db, long long user_account_pin,
                                        long long organization_key_pin,
                                        const unsigned char *client_id,
                                        int limit, int offset,
                                        admin_client_resource_server_t **out_links,
                                        int *out_count,
                                        int *out_total);

int admin_list_resource_server_clients(db_handle_t *db, long long user_account_pin,
                                        long long organization_key_pin,
                                        const unsigned char *resource_server_id,
                                        int limit, int offset,
                                        admin_resource_server_client_t **out_links,
                                        int *out_count,
                                        int *out_total);

int admin_create_client_resource_server_link(db_handle_t *db, long long user_account_pin,
                                              long long organization_key_pin,
                                              const unsigned char *client_id,
                                              const unsigned char *resource_server_id);

int admin_delete_client_resource_server_link(db_handle_t *db, long long user_account_pin,
                                              long long organization_key_pin,
                                              const unsigned char *client_id,
                                              const unsigned char *resource_server_id);

/* ============================================================================
 * RESOURCE SERVER KEY OPERATIONS
 * ========================================================================== */

typedef resource_server_key_data_t admin_resource_server_key_t;

int admin_create_resource_server_key(db_handle_t *db,
                                      long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *resource_server_id,
                                      const char *secret,
                                      const char *note,
                                      unsigned char *out_key_id);

int admin_list_resource_server_keys(db_handle_t *db,
                                     long long user_account_pin,
                                     long long organization_key_pin,
                                     const unsigned char *resource_server_id,
                                     int limit, int offset,
                                     const int *filter_is_active,
                                     admin_resource_server_key_t **out_keys,
                                     int *out_count,
                                     int *out_total);

int admin_revoke_resource_server_key(db_handle_t *db,
                                      long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *key_id);

/* ============================================================================
 * CLIENT KEY OPERATIONS
 * ========================================================================== */

typedef client_key_data_t admin_client_key_t;

int admin_create_client_key(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *client_id,
                             const char *secret,
                             const char *note,
                             unsigned char *out_key_id);

int admin_list_client_keys(db_handle_t *db,
                            long long user_account_pin,
                            long long organization_key_pin,
                            const unsigned char *client_id,
                            int limit, int offset,
                            const int *filter_is_active,
                            admin_client_key_t **out_keys,
                            int *out_count,
                            int *out_total);

int admin_revoke_client_key(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *key_id);

/* ============================================================================
 * USER OPERATIONS
 * ========================================================================== */

/*
 * Create user account
 *
 * Validates username/email don't exist, then creates user.
 * Returns user ID for further operations (e.g., making them an org admin).
 *
 * Parameters:
 *   db           - Database handle
 *   username     - Unique username (can be NULL for email-only accounts)
 *   email        - Email address (optional, can be NULL)
 *   password     - Plaintext password (will be hashed)
 *   out_user_id  - Output: 16-byte UUID of created user
 *
 * Returns: 0 on success, -1 on error
 */
int admin_create_user(db_handle_t *db,
                     const char *username,
                     const char *email,
                     const char *password,
                     unsigned char *out_user_id);

/*
 * Make user an organization admin
 *
 * Validates that user and org exist, then grants org-admin privileges.
 * Idempotent - safe to call if user is already an admin.
 *
 * Parameters:
 *   db            - Database handle
 *   user_id       - User UUID (16 bytes)
 *   org_code_name - Organization code name
 *
 * Returns: 0 on success, -1 on error
 */
int admin_make_org_admin(db_handle_t *db,
                        const unsigned char *user_id,
                        const char *org_code_name);

/* ============================================================================
 * ORGANIZATION KEY OPERATIONS
 * ========================================================================== */

typedef organization_key_data_t admin_organization_key_t;

/*
 * List organization keys
 *
 * Used by dual-auth endpoints (localhost OR org key).
 *
 * Parameters:
 *   db                   - Database handle
 *   organization_code_name - Organization code name
 *   limit                - Maximum results
 *   offset               - Skip count
 *   filter_is_active     - Filter by status (NULL = all)
 *   out_keys             - Output: array (caller must free)
 *   out_count            - Output: count
 *
 * Returns: 0 on success, -1 on error
 */
int admin_list_organization_keys(db_handle_t *db,
                                  const char *organization_code_name,
                                  int limit, int offset,
                                  const int *filter_is_active,
                                  admin_organization_key_t **out_keys,
                                  int *out_count,
                                  int *out_total);

/*
 * Revoke organization key
 *
 * Used by dual-auth endpoints (localhost OR org key).
 * Can revoke any key in the org (including self-revocation).
 *
 * Parameters:
 *   db     - Database handle
 *   key_id - Key UUID (16 bytes)
 *
 * Returns: 0 on success, -1 on error
 */
int admin_revoke_organization_key(db_handle_t *db,
                                   const unsigned char *key_id);

#endif /* HANDLERS_ADMIN_H */
