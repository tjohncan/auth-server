#ifndef DB_QUERIES_CLIENT_H
#define DB_QUERIES_CLIENT_H

#include "db/db.h"

/*
 * Client Query Functions
 *
 * Entity-based query layer for client, client_redirect_uri, and
 * client_resource_server operations.
 */

/*
 * Check if active client with code_name exists in organization
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int client_code_name_exists(db_handle_t *db, const char *org_code_name,
                            const char *code_name);

/*
 * Create client (bootstrap use)
 *
 * Creates client record within an organization.
 * Uses RETURNING clause to get pin in same query.
 * NO AUTHORIZATION - for bootstrap use only.
 *
 * Parameters:
 *   db                          - Database handle
 *   org_code_name               - Organization code name
 *   code_name                   - Unique code name within org
 *   display_name                - Human-readable name
 *   client_type                 - "public" or "confidential"
 *   grant_type                  - "authorization_code" or "client_credentials"
 *   note                        - Optional description (can be NULL)
 *   require_mfa                 - 1 to require MFA, 0 otherwise
 *   access_token_ttl_seconds    - Access token lifetime (required)
 *   issue_refresh_tokens        - 1 to issue refresh tokens, 0 otherwise
 *   refresh_token_ttl_seconds   - Refresh token lifetime (use -1 for NULL)
 *   maximum_session_seconds     - Maximum session duration (use -1 for NULL)
 *   secret_rotation_seconds     - Secret rotation interval (use -1 for NULL)
 *   is_universal                - 1 if universal client, 0 otherwise
 *   out_id                      - Output: 16-byte UUID
 *   out_pin                     - Output: Client PIN (for adding redirect URIs)
 *
 * Returns: 0 on success, -1 on error
 */
int client_create_bootstrap(db_handle_t *db, const char *org_code_name,
                             const char *code_name, const char *display_name,
                             const char *client_type, const char *grant_type,
                             const char *note,
                             int require_mfa, int access_token_ttl_seconds,
                             int issue_refresh_tokens, int refresh_token_ttl_seconds,
                             int maximum_session_seconds, int secret_rotation_seconds,
                             int is_universal,
                             unsigned char *out_id, long long *out_pin);

/*
 * Add redirect URI to client (bootstrap use)
 *
 * Creates client_redirect_uri record.
 * NOT idempotent - fails if URI already registered for this client.
 * NO AUTHORIZATION - for bootstrap use only.
 *
 * Parameters:
 *   db          - Database handle
 *   client_id   - Client UUID (16 bytes)
 *   redirect_uri - Callback URL
 *   note        - Optional description (can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int client_add_redirect_uri_bootstrap(db_handle_t *db, const unsigned char *client_id,
                                       const char *redirect_uri, const char *note);

/*
 * Create client
 *
 * Dual-auth capable: session user OR organization key.
 * Creates client with authorization check.
 * is_universal is hardcoded to FALSE (only bootstrap can create universal clients).
 *
 * Parameters:
 *   db                          - Database handle
 *   user_account_pin            - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin        - Key PIN (org key auth) or -1 (session auth)
 *   organization_id             - Organization UUID (16 bytes)
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
 *   out_id                      - Output: 16-byte client UUID
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_create(db_handle_t *db,
                  long long user_account_pin,
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

/*
 * Redirect URI data structure
 */
typedef struct {
    char redirect_uri[512];
    char note[512];
} client_redirect_uri_data_t;

/*
 * List redirect URIs for client
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   out_uris             - Output: array of redirect URIs (caller must free)
 *   out_count            - Output: number of URIs in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_redirect_uri_list(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *client_id,
                              int limit, int offset,
                              client_redirect_uri_data_t **out_uris,
                              int *out_count,
                              int *out_total);

/*
 * Create redirect URI for client
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   redirect_uri         - Callback URL
 *   note                 - Optional description (can be NULL)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_redirect_uri_create(db_handle_t *db, long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *client_id,
                                const char *redirect_uri,
                                const char *note);

/*
 * Delete redirect URI (by natural key)
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   redirect_uri         - Callback URL to delete
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_redirect_uri_delete(db_handle_t *db, long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *client_id,
                                const char *redirect_uri);

/*
 * Link client to resource server (bootstrap use)
 *
 * Creates client_resource_server record (client can access this API).
 * Idempotent - succeeds if link already exists.
 * NO AUTHORIZATION - for bootstrap use only.
 *
 * Parameters:
 *   db                      - Database handle
 *   org_code_name           - Organization code name
 *   client_id               - Client UUID (16 bytes)
 *   resource_server_address - Resource server address
 *
 * Returns: 0 on success, -1 on error
 */
int client_link_resource_server_bootstrap(db_handle_t *db, const char *org_code_name,
                                           const unsigned char *client_id,
                                           const char *resource_server_address);

/*
 * Client-resource-server link data structure (for querying by client_id)
 * Returns resource server details only
 */
typedef struct {
    unsigned char resource_server_id[16];
    char resource_server_code_name[128];
    char resource_server_display_name[256];
    char resource_server_address[512];
} client_resource_server_data_t;

/*
 * Resource-server-client link data structure (for querying by resource_server_id)
 * Returns client details only
 */
typedef struct {
    unsigned char client_id[16];
    char client_code_name[128];
    char client_display_name[256];
} resource_server_client_data_t;

/*
 * List resource servers linked to client
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   out_links            - Output: array of links (caller must free)
 *   out_count            - Output: number of links in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_resource_server_list(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *client_id,
                                 int limit, int offset,
                                 client_resource_server_data_t **out_links,
                                 int *out_count,
                                 int *out_total);

/*
 * List clients linked to resource server
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   resource_server_id   - Resource server UUID (16 bytes)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   out_links            - Output: array of links (caller must free)
 *   out_count            - Output: number of links in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int resource_server_client_list(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *resource_server_id,
                                 int limit, int offset,
                                 resource_server_client_data_t **out_links,
                                 int *out_count,
                                 int *out_total);

/*
 * Create client-resource-server link
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   resource_server_id   - Resource server UUID (16 bytes)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_resource_server_create(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *resource_server_id);

/*
 * Delete client-resource-server link
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   resource_server_id   - Resource server UUID (16 bytes)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_resource_server_delete(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *resource_server_id);

/*
 * Client data structure for queries
 */
typedef struct {
    unsigned char id[16];
    long long pin;
    long long organization_pin;
    char code_name[128];
    char display_name[256];
    char client_type[32];
    char grant_type[32];
    char note[512];
    int require_mfa;
    int access_token_ttl_seconds;
    int issue_refresh_tokens;
    int refresh_token_ttl_seconds;
    int maximum_session_seconds;
    int secret_rotation_seconds;
    int is_universal;
    int is_active;
} client_data_t;

/*
 * List clients for organization where user is admin
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   organization_id      - Organization UUID (16 bytes)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   filter_is_active     - Filter by active status (NULL = all, &1 = active only, &0 = inactive only)
 *   out_clients          - Output: array of clients (caller must free)
 *   out_count            - Output: number of clients in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_list_all(db_handle_t *db, long long user_account_pin,
                    long long organization_key_pin,
                    const unsigned char *organization_id,
                    int limit, int offset,
                    const int *filter_is_active,
                    client_data_t **out_clients, int *out_count,
                    int *out_total);

/*
 * Get client by ID
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   client_id            - Client UUID (16 bytes)
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   out_client           - Output: client data
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error or not found
 */
int client_get_by_id(db_handle_t *db, const unsigned char *client_id,
                     long long user_account_pin,
                     long long organization_key_pin,
                     client_data_t *out_client);

/*
 * Update client
 *
 * Dual-auth capable: session user OR organization key.
 * Pass NULL for fields you don't want to update.
 *
 * Parameters:
 *   db                          - Database handle
 *   client_id                   - Client UUID (16 bytes)
 *   user_account_pin            - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin        - Key PIN (org key auth) or -1 (session auth)
 *   display_name                - New display name (NULL = no change)
 *   note                        - New note (NULL = no change)
 *   require_mfa                 - New MFA requirement (NULL = no change)
 *   access_token_ttl_seconds    - New access token TTL (NULL = no change)
 *   issue_refresh_tokens        - New refresh token setting (NULL = no change)
 *   refresh_token_ttl_seconds   - New refresh token TTL (NULL = no change)
 *   maximum_session_seconds     - New max session duration (NULL = no change)
 *   secret_rotation_seconds     - New secret rotation interval (NULL = no change)
 *   is_active                   - New active status (NULL = no change)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error or not found
 */
int client_update(db_handle_t *db, const unsigned char *client_id,
                  long long user_account_pin,
                  long long organization_key_pin,
                  const char *display_name, const char *note,
                  const int *require_mfa,
                  const int *access_token_ttl_seconds,
                  const int *issue_refresh_tokens,
                  const int *refresh_token_ttl_seconds,
                  const int *maximum_session_seconds,
                  const int *secret_rotation_seconds,
                  const int *is_active);

/*
 * Client Key data structure
 *
 * Used for API key management for client_credentials flow authentication.
 * Never includes salt, hash_iterations, or secret_hash (security).
 * Only applies to confidential clients.
 */
typedef struct {
    unsigned char id[16];        /* key_id - shown to users */
    int is_active;
    char generated_at[32];
    char note[256];
} client_key_data_t;

/*
 * Create Client API key
 *
 * Dual-auth capable: session user OR organization key.
 * Creates authentication key for confidential client (client_credentials flow).
 * Hashes secret with configured algorithm before storage.
 * Only works for confidential clients (enforced in SQL).
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes, must be confidential)
 *   secret               - Plaintext secret to hash and store
 *   note                 - Optional description (can be NULL)
 *   out_key_id           - Output: 16-byte UUID key_id
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error (or if client is not confidential)
 */
int client_key_create(db_handle_t *db,
                      long long user_account_pin,
                      long long organization_key_pin,
                      const unsigned char *client_id,
                      const char *secret,
                      const char *note,
                      unsigned char *out_key_id);

/*
 * List Client API keys
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   client_id            - Client UUID (16 bytes)
 *   limit                - Maximum number of results
 *   offset               - Number of results to skip
 *   filter_is_active     - Filter by active status (NULL = all, &1 = active only, &0 = inactive only)
 *   out_keys             - Output: array of keys (caller must free)
 *   out_count            - Output: number of keys in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_key_list(db_handle_t *db,
                    long long user_account_pin,
                    long long organization_key_pin,
                    const unsigned char *client_id,
                    int limit, int offset,
                    const int *filter_is_active,
                    client_key_data_t **out_keys,
                    int *out_count,
                    int *out_total);

/*
 * Revoke Client API key (soft delete)
 *
 * Dual-auth capable: session user OR organization key.
 * Sets is_active = 0 to preserve audit trail.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   key_id               - Key UUID (16 bytes)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int client_key_revoke(db_handle_t *db,
                      long long user_account_pin,
                      long long organization_key_pin,
                      const unsigned char *key_id);

/*
 * Verify Client API key authentication
 *
 * Verifies key_id + secret combination for client_credentials flow.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * Parameters:
 *   db             - Database handle
 *   key_id         - Key UUID (16 bytes)
 *   secret         - Plaintext secret to verify
 *   out_client_pin - Output: Client PIN (for token generation)
 *
 * Returns: 1 if valid, 0 if invalid, -1 on error
 */
int client_key_verify(db_handle_t *db,
                      const unsigned char *key_id,
                      const char *secret,
                      long long *out_client_pin);

#endif /* DB_QUERIES_CLIENT_H */
