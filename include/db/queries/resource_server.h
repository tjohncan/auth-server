#ifndef DB_QUERIES_RESOURCE_SERVER_H
#define DB_QUERIES_RESOURCE_SERVER_H

#include "db/db.h"

/*
 * Resource Server Query Functions
 *
 * Entity-based query layer for resource_server operations.
 * Reusable across bootstrap and management UI handlers.
 */

/*
 * Check if active resource server with code_name exists in organization
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int resource_server_code_name_exists(db_handle_t *db, const char *org_code_name,
                                     const char *code_name);

/*
 * Check if active resource server with address exists in organization
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int resource_server_address_exists(db_handle_t *db, const char *org_code_name,
                                   const char *address);

/*
 * Create resource server (bootstrap use)
 *
 * Creates resource_server record within an organization.
 * Uses RETURNING clause to get pin in same query.
 * NO AUTHORIZATION - for bootstrap use only.
 *
 * Parameters:
 *   db            - Database handle
 *   org_code_name - Organization code name
 *   code_name     - Unique code name within organization
 *   display_name  - Human-readable name
 *   address       - Base URL of the API (e.g., "http://localhost:8080/api")
 *   note          - Optional description (can be NULL)
 *   out_pin       - Output: Resource server PIN
 *
 * Returns: 0 on success, -1 on error
 */
int resource_server_create_bootstrap(db_handle_t *db, const char *org_code_name,
                                      const char *code_name, const char *display_name,
                                      const char *address, const char *note,
                                      long long *out_pin);

/*
 * Create resource server
 *
 * Dual-auth capable: session user OR organization key.
 * Creates resource_server with authorization check.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   organization_id      - Organization UUID (16 bytes)
 *   code_name            - Unique code name within organization
 *   display_name         - Human-readable name
 *   address              - Base URL of the API
 *   note                 - Optional description (can be NULL)
 *   out_id               - Output: 16-byte UUID
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int resource_server_create(db_handle_t *db,
                            long long user_account_pin,
                            long long organization_key_pin,
                            const unsigned char *organization_id,
                            const char *code_name,
                            const char *display_name,
                            const char *address,
                            const char *note,
                            unsigned char *out_id);

/*
 * Resource server data structure for queries
 */
typedef struct {
    unsigned char id[16];
    long long pin;
    long long organization_pin;
    char code_name[128];
    char display_name[256];
    char address[512];
    char note[512];
    int is_active;
} resource_server_data_t;

/*
 * List resource servers for organization where user is admin
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
 *   out_servers          - Output: array of resource servers (caller must free)
 *   out_count            - Output: number of servers in array
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int resource_server_list_all(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *organization_id,
                              int limit, int offset,
                              const int *filter_is_active,
                              resource_server_data_t **out_servers, int *out_count,
                              int *out_total);

/*
 * Get resource server by ID
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   server_id            - Resource server UUID (16 bytes)
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   out_server           - Output: resource server data
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error or not found
 */
int resource_server_get_by_id(db_handle_t *db, const unsigned char *server_id,
                               long long user_account_pin,
                               long long organization_key_pin,
                               resource_server_data_t *out_server);

/*
 * Update resource server
 *
 * Dual-auth capable: session user OR organization key.
 * Pass NULL for fields you don't want to update.
 *
 * Parameters:
 *   db                   - Database handle
 *   server_id            - Resource server UUID (16 bytes)
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   display_name         - New display name (NULL = no change)
 *   address              - New address (NULL = no change)
 *   note                 - New note (NULL = no change)
 *   is_active            - New active status pointer (NULL = no change)
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error or not found
 */
int resource_server_update(db_handle_t *db, const unsigned char *server_id,
                           long long user_account_pin,
                           long long organization_key_pin,
                           const char *display_name, const char *address,
                           const char *note, const int *is_active);

/*
 * Resource Server Key data structure
 *
 * Used for API key management for introspection authentication.
 * Never includes salt, hash_iterations, or secret_hash (security).
 */
typedef struct {
    unsigned char id[16];        /* key_id - shown to users */
    int is_active;
    char generated_at[32];
    char note[256];
} resource_server_key_data_t;

/*
 * Create Resource Server API key
 *
 * Dual-auth capable: session user OR organization key.
 * Creates authentication key for resource server introspection endpoint.
 * Hashes secret with Argon2id before storage.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   resource_server_id   - Resource server UUID (16 bytes)
 *   secret               - Plaintext secret to hash and store
 *   note                 - Optional description (can be NULL)
 *   out_key_id           - Output: 16-byte UUID key_id
 *
 * Authorization:
 * - Session auth: Verifies user is org admin
 * - Org key auth: Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error
 */
int resource_server_key_create(db_handle_t *db,
                                long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *resource_server_id,
                                const char *secret,
                                const char *note,
                                unsigned char *out_key_id);

/*
 * List Resource Server API keys
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
int resource_server_key_list(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *resource_server_id,
                             int limit, int offset,
                             const int *filter_is_active,
                             resource_server_key_data_t **out_keys,
                             int *out_count,
                             int *out_total);

/*
 * Revoke Resource Server API key (soft delete)
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
int resource_server_key_revoke(db_handle_t *db,
                               long long user_account_pin,
                               long long organization_key_pin,
                               const unsigned char *key_id);

/*
 * Verify Resource Server API key authentication
 *
 * Verifies key_id + secret combination.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * Parameters:
 *   db                      - Database handle
 *   key_id                  - Key UUID (16 bytes)
 *   secret                  - Plaintext secret to verify
 *   out_resource_server_pin - Output: Resource server PIN (for introspection)
 *
 * Returns: 1 if valid, 0 if invalid, -1 on error
 */
int resource_server_key_verify(db_handle_t *db,
                               const unsigned char *key_id,
                               const char *secret,
                               long long *out_resource_server_pin);

#endif /* DB_QUERIES_RESOURCE_SERVER_H */
