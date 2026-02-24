#ifndef HANDLERS_OAUTH_H
#define HANDLERS_OAUTH_H

#include "db/db.h"

/*
 * OAuth2 Handler Functions
 *
 * Business logic layer for OAuth2 token endpoint operations.
 * These handlers coordinate authorization code exchange, token refresh,
 * and client credentials flow.
 *
 * All handlers:
 * - Perform validation
 * - Coordinate multiple query operations within transactions
 * - Return 0 on success, specific error codes on failure
 *
 * Note: HTTP layer (JSON parsing, response formatting) is separate.
 */

/* Token response structure */
typedef struct {
    char *access_token;      /* Access token (JWT or opaque) - caller must free */
    char *refresh_token;     /* Refresh token (optional) - caller must free */
    int expires_in;          /* Access token TTL in seconds */
    const char *token_type;  /* "Bearer" (string literal, not heap-allocated) */
    char *scope;             /* Space-separated scopes (optional) - caller must free */
} oauth_token_response_t;

/*
 * Free token response structure
 *
 * Frees all allocated strings in response.
 */
void oauth_token_response_free(oauth_token_response_t *resp);

/* Authorization response structure */
typedef struct {
    char *code;  /* Authorization code (stateless JWT) - caller must free */
    char *state; /* State parameter (CSRF protection) - caller must free */
    long long user_account_pin;  /* Set on rc=-3 (MFA required) for method lookup */
} oauth_authorize_response_t;

/*
 * Free authorization response structure
 *
 * Frees all allocated strings in response.
 */
void oauth_authorize_response_free(oauth_authorize_response_t *resp);

/*
 * Process authorization request
 *
 * Validates client, redirect_uri, and session.
 * Generates stateless JWT authorization code and creates DB record.
 *
 * Parameters:
 *   db              - Database handle
 *   client_id       - Client UUID (16 bytes)
 *   redirect_uri    - Redirect URI (must be registered for client)
 *   scope           - Requested scopes (optional, space-separated)
 *   code_challenge  - PKCE code challenge (optional for confidential, required for public)
 *   code_challenge_method - PKCE method: "plain" or "S256" (NULL if no PKCE)
 *   state           - State parameter from client (CSRF protection, optional)
 *   session_token   - Browser session token from cookie
 *   out_response    - Output: Authorization response (caller must free)
 *
 * Returns: 0 on success,
 *          -1 on error or validation failure,
 *          -2 if session not authenticated (need login),
 *          -3 if MFA required but not completed
 */
int oauth_authorize(db_handle_t *db,
                    const unsigned char *client_id,
                    const char *redirect_uri,
                    const char *scope,
                    const char *code_challenge,
                    const char *code_challenge_method,
                    const char *state,
                    const char *session_token,
                    oauth_authorize_response_t *out_response);

/*
 * Exchange authorization code for tokens
 *
 * Validates authorization code, PKCE verifier, and redirect URI.
 * Atomically consumes code and issues access token + optional refresh token.
 * All operations within a transaction.
 *
 * Parameters:
 *   db             - Database handle
 *   client_id      - Client UUID (16 bytes)
 *   code           - Authorization code from client
 *   redirect_uri   - Redirect URI (must match code's redirect_uri)
 *   code_verifier  - PKCE code verifier (optional for confidential clients, required for public)
 *   resource       - Resource server address (RFC 8707, optional - NULL uses client's single linked resource if unambiguous)
 *   out_response   - Output: Token response (caller must free with oauth_token_response_free)
 *
 * Returns: 0 on success,
 *          1 if code already exchanged (replay attack - should revoke tokens),
 *          -1 on error or validation failure
 */
int oauth_exchange_authorization_code(db_handle_t *db,
                                       const unsigned char *client_id,
                                       const char *code,
                                       const char *redirect_uri,
                                       const char *code_verifier,
                                       const char *resource,
                                       oauth_token_response_t *out_response);

/*
 * Refresh access token
 *
 * Validates refresh token and rotates it (consumes old, issues new).
 * Issues new access token.
 * All operations within a transaction.
 *
 * Parameters:
 *   db             - Database handle
 *   client_id      - Client UUID (16 bytes)
 *   refresh_token  - Refresh token from client
 *   scope          - Requested scope (optional, must be subset of original)
 *   resource       - Resource server address (RFC 8707, optional - NULL uses client's single linked resource if unambiguous)
 *   out_response   - Output: Token response (caller must free with oauth_token_response_free)
 *
 * Returns: 0 on success,
 *          1 if refresh token already exchanged (replay attack - should revoke chain),
 *          -1 on error or validation failure
 */
int oauth_refresh_access_token(db_handle_t *db,
                                const unsigned char *client_id,
                                const char *refresh_token,
                                const char *scope,
                                const char *resource,
                                oauth_token_response_t *out_response);

/*
 * Issue access token for client credentials grant
 *
 * Machine-to-machine authentication (RFC 6749 Section 4.4).
 * No user context - client authenticates with client_id + client_secret.
 *
 * Parameters:
 *   db              - Database handle
 *   client_id       - Client UUID (16 bytes)
 *   client_key_id   - Client key UUID (16 bytes, identifies which key)
 *   client_secret   - Client secret (plaintext)
 *   scope           - Requested scopes (optional)
 *   resource        - Resource server address (RFC 8707, optional)
 *   source_ip       - Client IP address (optional, for audit logging)
 *   user_agent      - Client user agent (optional, for audit logging)
 *   out_response    - Output: Token response (caller must free)
 *
 * Returns: 0 on success, -1 on error or authentication failure
 */
int oauth_client_credentials(db_handle_t *db,
                              const unsigned char *client_id,
                              const unsigned char *client_key_id,
                              const char *client_secret,
                              const char *scope,
                              const char *resource,
                              const char *source_ip,
                              const char *user_agent,
                              oauth_token_response_t *out_response);

/*
 * Authenticate client
 *
 * Validates client credentials and logs usage.
 *
 * Parameters:
 *   db            - Database handle
 *   client_id     - Client UUID (16 bytes)
 *   client_key_id - Client key UUID (16 bytes)
 *   secret        - Client secret (plaintext)
 *   source_ip     - Source IP (optional, for audit)
 *   user_agent    - User agent (optional, for audit)
 *   out_pin       - Output: Client PIN if authentication succeeds
 *
 * Returns: 1 on success (authenticated), 0 on auth failure, -1 on error
 */
int oauth_handler_client_authenticate(db_handle_t *db,
                                       const unsigned char *client_id,
                                       const unsigned char *client_key_id,
                                       const char *secret,
                                       const char *source_ip,
                                       const char *user_agent,
                                       long long *out_pin);

/*
 * Authenticate resource server
 *
 * Validates resource server credentials and logs usage.
 *
 * Parameters:
 *   db                      - Database handle
 *   resource_server_id      - Resource server UUID (16 bytes)
 *   resource_server_key_id  - Resource server key UUID (16 bytes)
 *   secret                  - Resource server secret (plaintext)
 *   source_ip               - Source IP (optional, for audit)
 *   user_agent              - User agent (optional, for audit)
 *   out_pin                 - Output: Resource server PIN if authentication succeeds
 *
 * Returns: 1 on success (authenticated), 0 on auth failure, -1 on error
 */
int oauth_handler_resource_server_authenticate(db_handle_t *db,
                                                const unsigned char *resource_server_id,
                                                const unsigned char *resource_server_key_id,
                                                const char *secret,
                                                const char *source_ip,
                                                const char *user_agent,
                                                long long *out_pin);

/*
 * Revoke token
 *
 * Revokes an access or refresh token (RFC 7009).
 * Per RFC 7009, succeeds even if token is invalid or already revoked.
 *
 * Parameters:
 *   db              - Database handle
 *   token           - Token to revoke
 *   token_type_hint - Hint: "access_token" or "refresh_token" (optional)
 *   client_pin      - Authenticated client PIN
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_handler_revoke_token(db_handle_t *db,
                                const char *token,
                                const char *token_type_hint,
                                long long client_pin);

/*
 * Introspect token
 *
 * Returns token metadata (RFC 7662).
 *
 * Parameters:
 *   db                        - Database handle
 *   token                     - Token to introspect
 *   token_type_hint           - Hint: "access_token" or "refresh_token" (optional)
 *   resource_server_pin       - Authenticated resource server PIN
 *   out_active                - Output: 1 if valid and active, 0 otherwise
 *   out_scope                 - Output: Space-separated scopes (caller must free, may be NULL)
 *   out_client_id             - Output: Client UUID (16 bytes, zeroed if not active)
 *   out_user_id               - Output: User UUID (16 bytes, zeroed for client_credentials)
 *   out_resource_server_id    - Output: Resource server UUID (16 bytes, zeroed if not active)
 *   out_expires_at            - Output: Expiration timestamp (may be NULL)
 *   out_issued_at             - Output: Issuance timestamp (may be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int oauth_handler_introspect_token(db_handle_t *db,
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

#endif /* HANDLERS_OAUTH_H */
