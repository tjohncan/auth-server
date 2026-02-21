#ifndef DB_QUERIES_OAUTH_H
#define DB_QUERIES_OAUTH_H

#include "db/db.h"
#include <time.h>

/*
 * OAuth2 Query Functions
 *
 * Query layer for OAuth2 flows: client validation, sessions, authorization codes,
 * tokens, and redirect URI validation.
 */

/* Client information structure for OAuth2 flows */
typedef struct {
    unsigned char id[16];           /* Client UUID */
    long long pin;                  /* Internal PIN */
    long long organization_pin;     /* Organization PIN */
    char code_name[128];            /* Client code name */
    char client_type[16];           /* "public" or "confidential" */
    char grant_type[32];            /* "authorization_code" or "client_credentials" */
    int require_mfa;                /* 1 if MFA required, 0 otherwise */
    int access_token_ttl_seconds;   /* Access token TTL */
    int issue_refresh_tokens;       /* 1 if refresh tokens issued, 0 otherwise */
    int refresh_token_ttl_seconds;  /* Refresh token TTL (-1 if NULL) */
    int maximum_session_seconds;    /* Maximum session duration (-1 if NULL) */
    int secret_rotation_seconds;    /* Key max age (-1 if NULL) */
    int is_universal;               /* 1 if universal client, 0 otherwise */
} oauth_client_info_t;

/*
 * Look up client by ID and retrieve configuration
 *
 * Used at /authorize endpoint to validate client_id and get client settings.
 *
 * Parameters:
 *   db          - Database handle
 *   client_id   - Client UUID (16 bytes)
 *   out_client  - Output: Client configuration
 *
 * Returns: 0 on success (client found and active), -1 on error or not found
 */
int oauth_client_lookup(db_handle_t *db, const unsigned char *client_id,
                        oauth_client_info_t *out_client);

/*
 * Validate redirect URI is registered for client
 *
 * Performs exact match validation (case-insensitive for URI).
 * OAuth2 security requirement: no wildcard matching allowed.
 *
 * Parameters:
 *   db           - Database handle
 *   client_pin   - Client PIN (from oauth_client_lookup)
 *   redirect_uri - Redirect URI to validate
 *
 * Returns: 1 if valid (registered), 0 if not registered, -1 on error
 */
int oauth_redirect_uri_validate(db_handle_t *db, long long client_pin,
                                 const char *redirect_uri);

/*
 * Create authenticated browser session
 *
 * Creates session after successful user authentication.
 * Session token should be pre-generated random value (used as cookie value).
 *
 * Parameters:
 *   db                - Database handle
 *   user_account_pin  - User PIN (REQUIRED - only called after successful auth)
 *   user_account_id   - User UUID (for logging purposes)
 *   session_token     - Pre-generated session token (random, base64url)
 *   authentication_method - Authentication method used (e.g., "password", "passwordless")
 *   source_ip         - Client IP address (optional, can be NULL)
 *   user_agent        - Browser user agent (optional, can be NULL)
 *   ttl_seconds       - Session lifetime in seconds
 *   out_id            - Output: 16-byte session UUID
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_session_create(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *session_token,
                         const char *authentication_method,
                         const char *source_ip, const char *user_agent,
                         int ttl_seconds,
                         unsigned char *out_id);

/* Session information structure */
typedef struct {
    unsigned char id[16];           /* Session UUID */
    long long user_account_pin;     /* User PIN (for internal DB operations) */
    unsigned char user_account_id[16]; /* User account UUID (for external JWTs) */
    int authentication_complete;    /* 1 if auth complete, 0 otherwise */
    int mfa_completed;              /* 1 if MFA done, 0 otherwise */
    int user_requires_mfa;          /* 1 if user opted in to enforce MFA (preference flag) */
    time_t started_at;              /* Session creation time (Unix epoch) */
} oauth_session_info_t;

/*
 * Look up browser session by session token
 *
 * Used to validate session cookie and retrieve session state.
 * Only returns active, non-expired sessions.
 *
 * Parameters:
 *   db            - Database handle
 *   session_token - Session token from cookie
 *   out_session   - Output: Session information
 *
 * Returns: 0 on success (found active session), -1 on error or not found
 */
int oauth_session_get_by_token(db_handle_t *db, const char *session_token,
                                oauth_session_info_t *out_session);

/*
 * Close browser session (logout)
 *
 * Marks session as closed, preventing further use.
 * Used for explicit logout operations.
 *
 * Parameters:
 *   db            - Database handle
 *   session_token - Session token from cookie
 *
 * Returns: 0 on success (session closed), -1 on error or not found
 */
int oauth_session_close(db_handle_t *db, const char *session_token);

/*
 * Mark session MFA as completed
 *
 * Sets mfa_completed = TRUE after successful MFA verification.
 *
 * Parameters:
 *   db            - Database handle
 *   session_token - Session token from cookie
 *
 * Returns: 0 on success, -1 on error or not found
 */
int oauth_session_set_mfa_completed(db_handle_t *db, const char *session_token);

/*
 * Create authorization code
 *
 * Generates short-lived code for OAuth2 authorization code flow.
 * Code expires quickly (typically 60-90 seconds).
 * Note: redirect_uri and scopes validated at /authorize and /token, not stored in DB.
 *
 * Parameters:
 *   db                    - Database handle
 *   client_pin            - Client PIN
 *   client_id             - Client UUID (for logging)
 *   user_account_pin      - User PIN
 *   user_account_id       - User UUID (for logging)
 *   code                  - Pre-generated authorization code (random, base64url)
 *   code_challenge        - PKCE code challenge (optional for confidential, required for public)
 *   code_challenge_method - PKCE method: "plain" or "S256" (NULL if no PKCE)
 *   ttl_seconds           - Code lifetime
 *   out_id                - Output: 16-byte authorization code UUID
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_auth_code_create(db_handle_t *db, long long client_pin,
                            const unsigned char *client_id,
                            long long user_account_pin,
                            const unsigned char *user_account_id,
                            const char *code,
                            const char *code_challenge,
                            const char *code_challenge_method,
                            int ttl_seconds,
                            unsigned char *out_id);

/* Authorization code data structure */
typedef struct {
    unsigned char id[16];           /* Authorization code UUID */
    long long client_pin;           /* Client PIN */
    long long user_account_pin;     /* User PIN */
    /* Note: redirect_uri, scope, and PKCE fields are in JWT and validated there */
} oauth_auth_code_data_t;

/*
 * Consume authorization code (atomic single-use)
 *
 * Atomically retrieves code data and marks as exchanged.
 * Critical for security: prevents authorization code replay attacks.
 * Should be called within a transaction that also creates tokens.
 *
 * Parameters:
 *   db           - Database handle
 *   code         - Authorization code from client
 *   out_data     - Output: Authorization code data
 *
 * Returns: 0 on success (code valid and consumed),
 *          1 if already exchanged (replay attack detected),
 *          -1 on error or not found/expired
 */
int oauth_auth_code_consume(db_handle_t *db, const char *code,
                             oauth_auth_code_data_t *out_data);

/*
 * Create access token
 *
 * Creates access token for any grant type.
 * Handles authorization_code, refresh_token, and client_credentials flows.
 *
 * Parameters:
 *   db                   - Database handle
 *   resource_server_pin  - Resource server PIN (audience)
 *   client_pin           - Client PIN
 *   user_account_pin     - User PIN (0 for client_credentials grant, will bind NULL)
 *   authorization_code_id - Auth code UUID (NULL for refresh/client_credentials)
 *   refresh_token_id     - Refresh token UUID (NULL for auth_code/client_credentials)
 *   token                - Pre-generated token string (JWT or random)
 *   scopes               - Space-separated scopes (optional, can be NULL)
 *   ttl_seconds          - Token lifetime (from client.access_token_ttl_seconds)
 *   out_id               - Output: 16-byte access token UUID
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_token_create_access(db_handle_t *db, long long resource_server_pin,
                               long long client_pin, long long user_account_pin,
                               const unsigned char *authorization_code_id,
                               const unsigned char *refresh_token_id,
                               const char *token, const char *scopes,
                               int ttl_seconds,
                               unsigned char *out_id);

/*
 * Create refresh token
 *
 * Creates refresh token for authorization_code grant (initial creation).
 * For rotation (creating new from old), use oauth_token_rotate_refresh() instead.
 *
 * Parameters:
 *   db                   - Database handle
 *   client_pin           - Client PIN
 *   user_account_pin     - User PIN
 *   authorization_code_id - Auth code UUID (links to original authorization)
 *   token                - Pre-generated refresh token (random, base64url)
 *   scopes               - Space-separated scopes (optional, can be NULL)
 *   ttl_seconds          - Token lifetime (from client.refresh_token_ttl_seconds, -1 if NULL/infinite)
 *   out_id               - Output: 16-byte refresh token UUID
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_token_create_refresh(db_handle_t *db, long long client_pin,
                                long long user_account_pin,
                                const unsigned char *authorization_code_id,
                                const char *token, const char *scopes,
                                int ttl_seconds,
                                unsigned char *out_id);

/* Refresh token data structure */
typedef struct {
    unsigned char id[16];                    /* Refresh token UUID */
    unsigned char origin_id[16];             /* Origin token UUID (first in chain, or self if gen 1) */
    long long client_pin;                    /* Client PIN */
    long long user_account_pin;              /* User PIN */
    unsigned char authorization_code_id[16]; /* Original auth code UUID */
    int generation;                          /* Generation number */
    char scopes[256];                        /* Scopes (empty string if NULL) */
} oauth_refresh_token_data_t;

/*
 * Rotate refresh token (atomic consume + create)
 *
 * Atomically consumes old refresh token and creates new one.
 * Critical for security: prevents refresh token replay attacks.
 * Should be called within transaction that also creates access token.
 *
 * Parameters:
 *   db           - Database handle
 *   old_token    - Old refresh token from client
 *   new_token    - Pre-generated new refresh token
 *   ttl_seconds  - Token lifetime (-1 for infinite)
 *   out_data     - Output: Old token data (for creating access token)
 *   out_new_id   - Output: New refresh token UUID
 *
 * Returns: 0 on success (rotated),
 *          1 if already exchanged (replay attack detected),
 *          -1 on error or not found/expired/revoked
 */
int oauth_token_rotate_refresh(db_handle_t *db, const char *old_token,
                                const char *new_token, int ttl_seconds,
                                oauth_refresh_token_data_t *out_data,
                                unsigned char *out_new_id);

/*
 * Authenticate confidential client with secret
 *
 * Validates client_id, client_key_id, and client_secret for confidential clients.
 * Used in client_credentials grant and confidential client authentication.
 *
 * Requires explicit client_key_id to:
 * - Support key rotation (client may have multiple active keys)
 * - Avoid timing attacks from trying multiple keys
 * - Be explicit about which key is being used
 *
 * Parameters:
 *   db            - Database handle
 *   client_id     - Client UUID (16 bytes)
 *   client_key_id - Client key UUID (16 bytes, identifies which key)
 *   secret        - Client secret (plaintext, will be verified against hash)
 *   source_ip     - Client IP address (optional, can be NULL)
 *   user_agent    - Client user agent (optional, can be NULL)
 *   out_pin       - Output: Client PIN if authentication successful
 *
 * Returns: 1 if authenticated, 0 if invalid credentials, -1 on error
 *
 * Logs successful authentications to client_key_usage table.
 */
int oauth_client_authenticate(db_handle_t *db,
                               const unsigned char *client_id,
                               const unsigned char *client_key_id,
                               const char *secret,
                               const char *source_ip,
                               const char *user_agent,
                               long long *out_pin);

/*
 * Resolve resource server for token issuance
 *
 * Implements RFC 8707 Resource Indicators with fallback logic:
 * 1. If resource_address provided: look up by address and validate client linkage
 * 2. If resource_address NULL: return single linked resource server if exactly 1 exists
 *
 * Validates is_active on both client and resource_server (required for token operations).
 *
 * Parameters:
 *   db                      - Database handle
 *   client_pin              - Client PIN
 *   resource_address        - Resource server address (optional, can be NULL)
 *   out_resource_server_pin - Output: Resource server PIN
 *   out_resource_server_id  - Output: Resource server UUID (16 bytes)
 *
 * Returns: 0 on success (resource resolved),
 *          -1 on error (not found, not linked, inactive, or ambiguous)
 */
int oauth_resolve_resource_server(db_handle_t *db, long long client_pin,
                                    const char *resource_address,
                                    long long *out_resource_server_pin,
                                    unsigned char *out_resource_server_id);

/*
 * Authenticate resource server with secret
 *
 * Validates resource_server_id, resource_server_key_id, and secret for resource servers.
 * Used in token introspection endpoint to authenticate the caller.
 *
 * Requires explicit resource_server_key_id to:
 * - Support key rotation (resource server may have multiple active keys)
 * - Avoid timing attacks from trying multiple keys
 * - Be explicit about which key is being used
 *
 * Parameters:
 *   db                      - Database handle
 *   resource_server_id      - Resource server UUID (16 bytes)
 *   resource_server_key_id  - Resource server key UUID (16 bytes, identifies which key)
 *   secret                  - Resource server secret (plaintext, will be verified against hash)
 *   source_ip               - Client IP address (optional, can be NULL)
 *   user_agent              - Client user agent (optional, can be NULL)
 *   out_pin                 - Output: Resource server PIN if authentication successful
 *
 * Returns: 1 if authenticated, 0 if invalid credentials, -1 on error
 *
 * Logs successful authentications to resource_server_key_usage table.
 */
int oauth_resource_server_authenticate(db_handle_t *db,
                                        const unsigned char *resource_server_id,
                                        const unsigned char *resource_server_key_id,
                                        const char *secret,
                                        const char *source_ip,
                                        const char *user_agent,
                                        long long *out_pin);

/*
 * Introspect a token (RFC 7662 Token Introspection)
 *
 * Returns token metadata for resource servers to validate tokens.
 * Used by POST /introspect endpoint.
 *
 * Security considerations:
 * - Only resource servers can introspect (must authenticate with resource_server_key)
 * - Returns active=false for invalid/revoked/expired tokens
 * - Returns token details only if active=true
 *
 * Response structure (matches RFC 7662):
 *   active: boolean (required) - true if token is active
 *   If active=true, also includes:
 *     - scope: space-separated scopes
 *     - client_id: client PIN
 *     - token_type: "Bearer"
 *     - exp: expiration timestamp (Unix epoch)
 *     - iat: issued-at timestamp (Unix epoch)
 *     - sub: user account PIN (NULL for client_credentials tokens)
 *     - aud: resource server PIN
 *
 * Parameters:
 *   db                     - Database handle
 *   token                  - Token string to introspect
 *   token_type_hint        - Optional hint: "access_token" or "refresh_token" (can be NULL)
 *   resource_server_pin    - Authenticated resource server PIN (must be target of token)
 *   out_active             - Output: 1 if token is active, 0 otherwise
 *   out_scope              - Output: scopes (caller must free, NULL if not active)
 *   out_client_pin         - Output: client PIN (0 if not active)
 *   out_user_account_pin   - Output: user PIN (0 if not active or no user context)
 *   out_resource_server_pin- Output: resource server PIN (0 if not active)
 *   out_expires_at         - Output: expiration timestamp (0 if not active)
 *   out_issued_at          - Output: issued timestamp (0 if not active)
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_introspect_token(db_handle_t *db,
                           const char *token,
                           const char *token_type_hint,
                           long long resource_server_pin,
                           int *out_active,
                           char **out_scope,
                           unsigned char *out_client_id,
                           unsigned char *out_user_id,
                           unsigned char *out_resource_server_id,
                           long long *out_expires_at,
                           long long *out_issued_at);

/*
 * Revoke a single token (RFC 7009 Token Revocation)
 *
 * Revokes an access or refresh token owned by the authenticated client/resource server.
 * Used by POST /revoke endpoint.
 *
 * Security considerations:
 * - Validates token belongs to authenticated client_pin
 * - Returns success even if token doesn't exist (prevents enumeration)
 * - Idempotent (revoking already-revoked token succeeds)
 * - Does NOT revoke related tokens (single token only, not chain)
 *
 * Parameters:
 *   db              - Database handle
 *   token           - Token string to revoke (access or refresh token)
 *   token_type_hint - Optional hint: "access_token" or "refresh_token" (can be NULL)
 *   client_pin      - Authenticated client PIN (must own the token)
 *
 * Returns: 0 on success (token revoked or not found), -1 on error
 *
 * Note: Per RFC 7009, this endpoint returns 200 OK even if token is invalid/unknown
 *       to prevent information disclosure to unauthorized parties.
 */
int oauth_revoke_token(db_handle_t *db,
                       const char *token,
                       const char *token_type_hint,
                       long long client_pin);

/*
 * Revoke entire token chain from replay attack detection
 *
 * When a replay attack is detected (authorization code or refresh token reuse),
 * revoke all descendant tokens in the chain to prevent further use of compromised tokens.
 *
 * For authorization code replay:
 *   - Pass the authorization_code_id as origin_id
 *   - Revokes all refresh tokens derived from that code
 *   - Revokes all access tokens linked to those refresh tokens
 *
 * For refresh token replay:
 *   - Pass the origin_refresh_token_id as origin_id
 *   - Revokes all refresh tokens in the rotation chain
 *   - Revokes all access tokens linked to those refresh tokens
 *
 * Implementation:
 *   - Sets is_revoked = 1, revoked_at = current_timestamp on all affected tokens
 *   - Uses transaction for atomicity
 *   - Does NOT revoke ancestor tokens (only descendants)
 *
 * Parameters:
 *   db                    - Database handle
 *   origin_id             - Origin UUID (authorization_code_id or origin_refresh_token_id)
 *   is_authorization_code - 1 if origin_id is authorization_code_id, 0 if origin_refresh_token_id
 *   out_refresh_revoked   - Output: Count of refresh tokens revoked (optional, can be NULL)
 *   out_access_revoked    - Output: Count of access tokens revoked (optional, can be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_revoke_token_chain(db_handle_t *db,
                              const unsigned char *origin_id,
                              int is_authorization_code,
                              int *out_refresh_revoked,
                              int *out_access_revoked);

#endif /* DB_QUERIES_OAUTH_H */
