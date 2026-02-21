#ifndef HANDLERS_H
#define HANDLERS_H

#include "server/http.h"
#include "server/router.h"

/*
 * Handler function declarations
 *
 * All handlers follow the RouteHandler signature:
 *   HttpResponse *handler(const HttpRequest *req, const RouteParams *params)
 */

/* ============================================================================
 * Content-Type Constants
 * ============================================================================ */

#define CONTENT_TYPE_JSON "application/json; charset=utf-8"
#define CONTENT_TYPE_HTML "text/html; charset=utf-8"

/* ============================================================================
 * Common Response Helpers
 * ============================================================================ */

/*
 * Validate Content-Type header on request
 *
 * Checks that the request Content-Type starts with the expected type.
 * Use at the top of POST/PUT handlers to reject mistyped requests.
 *
 * Parameters:
 *   req      - HTTP request to check
 *   expected - Expected Content-Type prefix (e.g., "application/json")
 *
 * Returns: NULL if Content-Type matches, or 415 error response if not
 */
HttpResponse *require_content_type(const HttpRequest *req, const char *expected);

/* Create 200 OK response with JSON body */
HttpResponse *response_json_ok(const char *json);

/* Create error response with JSON error format: {"error":"message"} */
HttpResponse *response_json_error(int status_code, const char *message);

/*
 * Escape string for JSON output
 *
 * Escapes: " \ and control characters (0x00-0x1F) per RFC 8259.
 * Use this for ALL user-supplied values in JSON responses.
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer
 *   src      - Source string to escape
 *
 * Returns: Number of bytes written (excluding null terminator)
 */
size_t json_escape(char *dst, size_t dst_size, const char *src);

/*
 * Parse query string parameter
 *
 * Extracts value for given key from URL query string.
 *
 * Parameters:
 *   query_string - Query string (e.g., "key1=value1&key2=value2")
 *   key          - Parameter key to find
 *
 * Returns: Dynamically allocated value (caller must free), or NULL if not found
 */
char *http_query_get_param(const char *query_string, const char *key);

/*
 * Parse integer query parameter with bounds checking
 *
 * Extracts and parses integer from query string with default and bounds.
 *
 * Parameters:
 *   query_string  - Query string
 *   param_name    - Parameter key to find
 *   default_value - Value to return if parameter not found
 *   min_value     - Minimum allowed value (clamps if below)
 *   max_value     - Maximum allowed value (clamps if above)
 *
 * Returns: Parsed and bounded integer value
 */
int parse_query_int(const char *query_string, const char *param_name,
                   int default_value, int min_value, int max_value);

/*
 * Parse boolean query parameter
 *
 * Extracts and parses boolean from query string.
 * Accepts: "true"/"1" for true, "false"/"0" for false.
 *
 * Parameters:
 *   query_string - Query string
 *   param_name   - Parameter key to find
 *   out_value    - Output: 1 for true, 0 for false
 *
 * Returns: 0 on success, -1 if parameter not found or invalid value
 */
int parse_query_bool(const char *query_string, const char *param_name, int *out_value);

/*
 * Parse cookie value from Cookie header
 *
 * Extracts value for given cookie name from Cookie header.
 *
 * Parameters:
 *   cookie_header - Cookie header value (e.g., "session=abc; user=xyz")
 *   name          - Cookie name to find
 *
 * Returns: Dynamically allocated value (caller must free), or NULL if not found
 */
char *http_cookie_get_value(const char *cookie_header, const char *name);

/*
 * Attempt organization key authentication
 *
 * Extracts X-Org-Key-Id and X-Org-Key-Secret headers and validates them.
 *
 * Parameters:
 *   req         - HTTP request containing auth headers
 *   out_org_pin - Output: organization pin on success
 *   out_key_pin - Output: key pin on success
 *
 * Returns: 0 on success, -1 on failure
 */
int try_org_key_auth(const HttpRequest *req, long long *out_org_pin, long long *out_key_pin);

/* ============================================================================
 * Endpoint Handlers
 * ============================================================================ */

/* GET /health - Health check endpoint */
HttpResponse *health_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * Admin API Endpoints (Localhost-Only)
 * ============================================================================ */

/* POST /api/admin/bootstrap - Bootstrap system with initial org and admin user */
HttpResponse *admin_bootstrap_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/admin/organizations - Create organization */
HttpResponse *admin_create_organization_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/admin/users - Create user */
HttpResponse *admin_create_user_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/admin/org-admins - Grant org admin privileges */
HttpResponse *admin_make_org_admin_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/admin/list-all-organizations - List all organizations (localhost-only) */
HttpResponse *admin_list_all_organizations_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/admin/organization-keys - Create organization key (localhost-only) */
HttpResponse *admin_create_organization_key_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/admin/organization-keys - List organization keys (dual-auth) */
HttpResponse *admin_list_organization_keys_handler(const HttpRequest *req, const RouteParams *params);

/* DELETE /api/admin/organization-keys - Revoke organization key (dual-auth) */
HttpResponse *admin_revoke_organization_key_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * Authentication Endpoints
 * ============================================================================ */

/* POST /login - User login (creates session) */
HttpResponse *login_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/user/management-setups - Get management UI setups for current user */
HttpResponse *management_setups_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/user/profile - Get current user's profile */
HttpResponse *profile_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/user/emails - Get current user's email addresses */
HttpResponse *emails_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/password - Change current user's password */
HttpResponse *change_password_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/username - Change current user's username */
HttpResponse *change_username_handler(const HttpRequest *req, const RouteParams *params);

/* POST /logout - User logout (closes session) */
HttpResponse *logout_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * MFA Endpoints (Session Auth)
 * ============================================================================ */

/* POST /api/user/mfa/totp/setup - Begin TOTP enrollment */
HttpResponse *mfa_totp_setup_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/mfa/totp/confirm - Confirm TOTP enrollment */
HttpResponse *mfa_totp_confirm_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/mfa/verify - Verify TOTP code during authentication */
HttpResponse *mfa_verify_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/mfa/recover - Verify recovery code */
HttpResponse *mfa_recover_handler(const HttpRequest *req, const RouteParams *params);

/* GET /api/user/mfa/methods - List MFA methods */
HttpResponse *mfa_list_methods_handler(const HttpRequest *req, const RouteParams *params);

/* DELETE /api/user/mfa/methods/:id - Delete MFA method */
HttpResponse *mfa_delete_method_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/mfa/recovery-codes/regenerate - Regenerate recovery codes */
HttpResponse *mfa_regenerate_recovery_codes_handler(const HttpRequest *req, const RouteParams *params);

/* POST /api/user/mfa/require - Set user MFA preference (enforce or not) */
HttpResponse *mfa_set_require_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * OAuth2 Endpoints
 * ============================================================================ */

/* GET /authorize - OAuth2 authorization endpoint (authorization code flow) */
HttpResponse *authorize_handler(const HttpRequest *req, const RouteParams *params);

/* POST /token - OAuth2 token endpoint (authorization_code, refresh_token grants) */
HttpResponse *token_handler(const HttpRequest *req, const RouteParams *params);

/* GET /.well-known/jwks.json - JWKS endpoint (public keys for token verification) */
HttpResponse *jwks_handler(const HttpRequest *req, const RouteParams *params);

/* POST /revoke - OAuth2 token revocation endpoint (RFC 7009) */
HttpResponse *revoke_handler(const HttpRequest *req, const RouteParams *params);

/* POST /introspect - OAuth2 token introspection endpoint (RFC 7662) */
HttpResponse *introspect_handler(const HttpRequest *req, const RouteParams *params);

/* GET /userinfo - OIDC UserInfo endpoint (Bearer token auth) */
HttpResponse *userinfo_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * Admin Organization Management API (Authenticated Org-Admin)
 * ============================================================================ */

/* Organizations */
HttpResponse *admin_get_organizations_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_update_organization_handler(const HttpRequest *req, const RouteParams *params);

/* Resource Servers */
HttpResponse *admin_get_resource_servers_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_create_resource_server_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_update_resource_server_handler(const HttpRequest *req, const RouteParams *params);

/* Clients */
HttpResponse *admin_get_clients_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_create_client_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_update_client_handler(const HttpRequest *req, const RouteParams *params);

/* Client Redirect URIs */
HttpResponse *admin_get_client_redirect_uris_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_create_client_redirect_uri_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_delete_client_redirect_uri_handler(const HttpRequest *req, const RouteParams *params);

/* Client-Resource-Server Links */
HttpResponse *admin_get_client_resource_servers_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_get_resource_server_clients_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_create_client_resource_server_link_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_delete_client_resource_server_link_handler(const HttpRequest *req, const RouteParams *params);

/* Resource Server Key Management */
HttpResponse *admin_create_resource_server_key_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_get_resource_server_keys_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_delete_resource_server_key_handler(const HttpRequest *req, const RouteParams *params);

/* Client Key Management */
HttpResponse *admin_create_client_key_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_get_client_keys_handler(const HttpRequest *req, const RouteParams *params);
HttpResponse *admin_delete_client_key_handler(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * Static File Serving
 * ============================================================================ */

/* GET / - Serves index.html */
HttpResponse *index_handler(const HttpRequest *req, const RouteParams *params);

/* GET /static/... - Serves static files from ./static/ directory */
HttpResponse *static_file_handler(const HttpRequest *req, const RouteParams *params);

/* Register all static files from ./static/ directory as routes */
void register_static_files(Router *router);

#endif /* HANDLERS_H */
