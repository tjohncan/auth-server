#ifndef DB_QUERIES_ORG_H
#define DB_QUERIES_ORG_H

#include "db/db.h"

/*
 * Organization Query Functions
 *
 * Entity-based query layer for organization table operations.
 * Reusable across bootstrap, admin endpoints, and management UI handlers.
 */

/*
 * Create organization
 *
 * Generates UUID for organization and inserts record.
 * Uses RETURNING clause to get pin in same query.
 *
 * Parameters:
 *   db            - Database handle
 *   code_name     - Unique organization code name (e.g., "system", "acme-corp")
 *   display_name  - Human-readable name
 *   note          - Optional description (can be NULL)
 *   out_pin       - Output: Organization PIN (internal ID)
 *
 * Returns: 0 on success, -1 on error
 */
int org_create(db_handle_t *db, const char *code_name,
               const char *display_name, const char *note,
               long long *out_pin);

/*
 * Check if organization exists by code_name
 *
 * Returns: 1 if exists, 0 if not exists, -1 on error
 */
int org_exists(db_handle_t *db, const char *code_name);

/*
 * Organization data structure for queries
 *
 * Note: Does NOT include created_at/updated_at (database artifacts only)
 */
typedef struct {
    unsigned char id[16];   /* Organization UUID */
    long long pin;          /* Internal PIN (for backend lookups, not API) */
    char code_name[128];    /* Unique code name */
    char display_name[256]; /* Human-readable name */
    char note[512];         /* Optional description */
    int is_active;          /* 1 if active, 0 if inactive */
} org_data_t;

/*
 * List organizations where user is an admin
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   user_account_pin     - User PIN (session) or -1 (org key)
 *   organization_key_pin - Key PIN (org key) or -1 (session)
 *   limit                - Maximum number of results (0 = unlimited)
 *   offset               - Number of results to skip
 *   filter_is_active     - Filter by active status (NULL = all, &1 = active only, &0 = inactive only)
 *   out_orgs             - Output: array of organizations (caller must free)
 *   out_count            - Output: number of organizations in array
 *
 * Authorization:
 * - Session auth: Returns orgs where user is admin
 * - Org key auth: Returns the single org that owns the key
 *
 * Returns: 0 on success, -1 on error
 */
int org_list_all(db_handle_t *db, long long user_account_pin,
                 long long organization_key_pin,
                 int limit, int offset,
                 const int *filter_is_active,
                 org_data_t **out_orgs, int *out_count,
                 int *out_total);

/*
 * List all organizations (unscoped - no user authorization filter)
 *
 * Used by localhost-only endpoints for administrative access.
 *
 * Parameters:
 *   db               - Database handle
 *   limit            - Maximum number of results (0 = unlimited)
 *   offset           - Number of results to skip
 *   filter_is_active - Filter by active status (NULL = all, &1 = active only, &0 = inactive only)
 *   out_orgs         - Output: array of organizations (caller must free)
 *   out_count        - Output: number of organizations in array
 *
 * Returns: 0 on success, -1 on error
 */
int org_list_all_unscoped(db_handle_t *db,
                          int limit, int offset,
                          const int *filter_is_active,
                          org_data_t **out_orgs, int *out_count,
                          int *out_total);

/*
 * Get organization by ID
 *
 * Dual-auth capable: session user OR organization key.
 *
 * Parameters:
 *   db                   - Database handle
 *   org_id               - Organization UUID (16 bytes)
 *   user_account_pin     - User PIN (session auth) or -1 (org key auth)
 *   organization_key_pin - Key PIN (org key auth) or -1 (session auth)
 *   out_org              - Output: organization data
 *
 * Authorization:
 * - Session auth (user_account_pin != -1): Verifies user is org admin
 * - Org key auth (user_account_pin == -1): Verifies specific key is active
 *
 * Returns: 0 on success, -1 on error or not found
 */
int org_get_by_id(db_handle_t *db, const unsigned char *org_id,
                  long long user_account_pin, long long organization_key_pin,
                  org_data_t *out_org);

/*
 * Update organization
 *
 * Dual-auth capable: session user OR organization key.
 * Pass NULL for fields you don't want to update.
 *
 * Parameters:
 *   db                   - Database handle
 *   org_id               - Organization UUID (16 bytes)
 *   user_account_pin     - User PIN (session) or -1 (org key)
 *   organization_key_pin - Key PIN (org key) or -1 (session)
 *   display_name         - New display name (NULL = no change)
 *   note                 - New note (NULL = no change)
 *   is_active            - New active status pointer (NULL = no change)
 *
 * Returns: 0 on success, -1 on error or not found
 */
int org_update(db_handle_t *db, const unsigned char *org_id,
               long long user_account_pin, long long organization_key_pin,
               const char *display_name, const char *note,
               const int *is_active);

/* ============================================================================
 * ORGANIZATION KEY MANAGEMENT
 * ========================================================================== */

/*
 * Organization key data structure
 *
 * Organization keys provide API authentication for programmatic access
 * to organization admin endpoints (alternative to session cookies).
 *
 * Security: These keys grant FULL admin access to the organization.
 */
typedef struct {
    unsigned char id[16];        /* key_id - shown to users */
    int is_active;
    char generated_at[32];       /* ISO 8601 timestamp */
    char note[256];
} organization_key_data_t;

/*
 * Get organization PIN by code name
 *
 * Simple lookup for authorization checks. Used to verify org key credentials
 * match the requested organization.
 *
 * Parameters:
 *   db                   - Database handle
 *   organization_code_name - Organization code name
 *   out_organization_pin - Output: Organization PIN
 *
 * Returns: 0 on success, -1 if not found or error
 */
int organization_get_pin_by_code_name(db_handle_t *db,
                                       const char *organization_code_name,
                                       long long *out_organization_pin);

/*
 * Get organization code name by PIN
 *
 * Reverse lookup for authorization checks. Used when org key auth is used
 * without explicitly providing organization_code_name.
 *
 * Parameters:
 *   db                   - Database handle
 *   organization_pin     - Organization PIN
 *   out_code_name        - Output buffer (must be at least 128 bytes)
 *
 * Returns: 0 on success, -1 if not found or error
 */
int organization_get_code_name_by_pin(db_handle_t *db,
                                       long long organization_pin,
                                       char *out_code_name);

/*
 * Get organization PIN for a given key
 *
 * Lookup which organization owns a specific key. Used for authorization
 * checks when revoking keys.
 *
 * Parameters:
 *   db                   - Database handle
 *   key_id               - Organization key UUID (16 bytes)
 *   out_organization_pin - Output: Organization PIN
 *
 * Returns: 0 on success, -1 if not found or error
 */
int organization_key_get_organization_pin(db_handle_t *db,
                                           const unsigned char *key_id,
                                           long long *out_organization_pin);

/*
 * Create organization key
 *
 * Dual-mode secret provisioning:
 * - If secret is provided: Use as-is (BYOS - bring your own secret)
 * - If secret is NULL: Generate secure 32-byte base64url token
 *
 * Secret is hashed using crypto_password_hash() before storage.
 * Returned key_id is used for authentication (X-Org-Key-Id header).
 *
 * SECURITY WARNING: Organization keys grant FULL admin access.
 * This operation should be localhost-gated.
 *
 * Parameters:
 *   db                   - Database handle
 *   organization_code_name - Organization code name (e.g., "system")
 *   secret               - Secret to hash (NULL = generate secure token)
 *   note                 - Optional description
 *   out_key_id           - Output: Generated key UUID (16 bytes)
 *
 * Returns: 0 on success, -1 on error
 */
int organization_key_create(db_handle_t *db,
                            const char *organization_code_name,
                            const char *secret,
                            const char *note,
                            unsigned char *out_key_id);

/*
 * List organization keys
 *
 * Parameters:
 *   db                   - Database handle
 *   organization_code_name - Organization code name
 *   limit                - Maximum results (0 = unlimited)
 *   offset               - Skip count
 *   filter_is_active     - Filter by status (NULL = all, &1 = active, &0 = inactive)
 *   out_keys             - Output: array of keys (caller must free)
 *   out_count            - Output: count
 *
 * Returns: 0 on success, -1 on error
 */
int organization_key_list(db_handle_t *db,
                          const char *organization_code_name,
                          int limit, int offset,
                          const int *filter_is_active,
                          organization_key_data_t **out_keys,
                          int *out_count,
                          int *out_total);

/*
 * Revoke organization key (soft delete via is_active=FALSE)
 *
 * Parameters:
 *   db                   - Database handle
 *   key_id               - Key UUID (16 bytes)
 *
 * Returns: 0 on success, -1 on error
 */
int organization_key_revoke(db_handle_t *db,
                            const unsigned char *key_id);

/*
 * Verify organization key secret (for authentication)
 *
 * Uses timing-safe password verification.
 *
 * Parameters:
 *   db                   - Database handle
 *   key_id               - Key UUID (16 bytes)
 *   secret               - Secret to verify
 *   out_organization_pin - Output: Organization PIN if valid
 *   out_key_pin          - Output: Organization key PIN (for re-verification)
 *
 * Returns: 0 if valid, -1 if invalid or error
 */
int organization_key_verify(db_handle_t *db,
                            const unsigned char *key_id,
                            const char *secret,
                            long long *out_organization_pin,
                            long long *out_key_pin);

#endif /* DB_QUERIES_ORG_H */
