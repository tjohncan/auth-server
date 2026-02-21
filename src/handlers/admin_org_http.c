/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers.h"
#include "handlers/admin.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/org.h"
#include "db/queries/resource_server.h"
#include "db/queries/client.h"
#include "db/queries/oauth.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/str.h"
#include "util/data.h"
#include "util/json.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================================
 * Authentication Helpers (Dual Auth: Session Cookie OR Organization Key)
 * ========================================================================== */

/*
 * Authentication Context
 *
 * Represents the result of authentication, capturing both the method used
 * and the relevant identifiers for authorization.
 *
 * Fields:
 * - user_account_pin: Valid user PIN if auth_method == 0, or -1 if auth_method == 1
 * - organization_pin: Valid org PIN if auth_method == 1, or -1 if auth_method == 0
 * - organization_key_pin: Key PIN if auth_method == 1, or -1 if auth_method == 0
 * - auth_method: Source of truth - 0 = session cookie, 1 = organization key
 *
 * Security: organization_key_pin is re-checked at query time to ensure the key hasn't
 * been revoked between authentication and query execution.
 *
 * Note: Both PIN sentinels use -1 (impossible value, all PINs are positive).
 */
typedef struct {
    long long user_account_pin;
    long long organization_pin;
    long long organization_key_pin;
    int auth_method;
} auth_context_t;

/*
 * get_authenticated_user_pin - Extract user PIN from session cookie
 *
 * Internal helper used by get_auth_context() for the session cookie
 * leg of dual authentication (session OR org key).
 *
 * Returns: 0 on success with user_pin populated, -1 on failure
 */
static int get_authenticated_user_pin(const HttpRequest *req, long long *out_user_pin) {
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return -1;
    }

    const char *cookie_header = http_request_get_header(req, "Cookie");
    char *session_token = NULL;
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, "session");
    }

    if (!session_token) {
        return -1;
    }

    oauth_session_info_t session;
    int result = oauth_session_get_by_token(db, session_token, &session);
    free(session_token);

    if (result != 0) {
        return -1;
    }

    *out_user_pin = session.user_account_pin;
    return 0;
}

/*
 * get_auth_context - Get authentication context (session OR org key)
 *
 * Attempts authentication in this order:
 *   1. Session cookie authentication
 *   2. Organization key header authentication
 *
 * The auth_method field determines which authentication was successful.
 * Query layer functions receive user_account_pin (session) or -1 (org key).
 * The -1 sentinel signals to query layer: "use org-based auth, not user-based".
 *
 * Returns: 0 on success with ctx populated, -1 if both methods fail
 */
static int get_auth_context(const HttpRequest *req, auth_context_t *ctx) {
    long long user_pin;

    /* Try session authentication first */
    if (get_authenticated_user_pin(req, &user_pin) == 0) {
        /* Session auth succeeded */
        ctx->user_account_pin = user_pin;
        ctx->organization_pin = -1;  /* Sentinel: not org key auth */
        ctx->organization_key_pin = -1;  /* Sentinel: not org key auth */
        ctx->auth_method = 0;  /* Session */
        return 0;
    }

    /* Try org key authentication */
    long long org_pin, key_pin;
    if (try_org_key_auth(req, &org_pin, &key_pin) == 0) {
        /* Org key auth succeeded */
        ctx->user_account_pin = -1;  /* Sentinel: not session auth */
        ctx->organization_pin = org_pin;
        ctx->organization_key_pin = key_pin;
        ctx->auth_method = 1;  /* Org key */
        return 0;
    }

    /* Both methods failed */
    return -1;
}

/* ============================================================================
 * Organizations Endpoints
 * ========================================================================== */

/*
 * GET /api/admin/organizations
 *
 * Handles both list and get-single operations:
 * - No 'id' param: List organizations where user is admin
 * - With 'id' param: Get single organization
 *
 * Query params (list mode):
 *   limit     - Max results (default 20, max 100)
 *   offset    - Skip N results (default 0)
 *   is_active - Filter by active status (optional)
 *
 * Query params (single mode):
 *   id - Organization UUID (hex)
 */
HttpResponse *admin_get_organizations_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Dual authentication: session OR org key */
    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Check if this is get-single or list operation */
    char *id_str = NULL;
    if (req->query_string) {
        id_str = http_query_get_param(req->query_string, "id");
    }

    if (id_str) {
        /* GET SINGLE MODE */
        unsigned char org_id[16];
        if (hex_to_bytes(id_str, org_id, 16) != 0) {
            free(id_str);
            return response_json_error(400, "Invalid organization ID format");
        }
        free(id_str);

        admin_organization_t org;
        if (admin_get_organization(db, ctx.user_account_pin, ctx.organization_key_pin, org_id, &org) != 0) {
            return response_json_error(404, "Organization not found or access denied");
        }

        /* Build JSON response */
        char org_id_hex[33];
        bytes_to_hex(org.id, 16, org_id_hex, sizeof(org_id_hex));

        char escaped_code_name[256];
        char escaped_display_name[512];
        char escaped_note[1024];
        json_escape(escaped_code_name, sizeof(escaped_code_name), org.code_name);
        json_escape(escaped_display_name, sizeof(escaped_display_name), org.display_name);
        json_escape(escaped_note, sizeof(escaped_note), org.note);

        char response_body[4096];
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                 "\"note\":\"%s\",\"is_active\":%s}",
                 org_id_hex, escaped_code_name, escaped_display_name,
                 escaped_note, org.is_active ? "true" : "false");

        return response_json_ok(response_body);
    }

    /* LIST MODE */
    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Parse is_active filter (optional) */
    int is_active_filter;
    int *is_active_ptr = NULL;
    if (parse_query_bool(req->query_string, "is_active", &is_active_filter) == 0) {
        is_active_ptr = &is_active_filter;
    }

    /* Get organizations */
    admin_organization_t *orgs = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_organizations(db, ctx.user_account_pin, ctx.organization_key_pin, limit, offset, is_active_ptr, &orgs, &count, &total) != 0) {
        return response_json_error(500, "Failed to list organizations");
    }

    /* Build JSON array response */
    char response_body[16384];
    int pos = snprintf(response_body, sizeof(response_body), "{\"organizations\":[");

    for (int i = 0; i < count; i++) {
        char org_id_hex[33];
        bytes_to_hex(orgs[i].id, 16, org_id_hex, sizeof(org_id_hex));

        char escaped_code_name[256];
        char escaped_display_name[512];
        char escaped_note[1024];
        json_escape(escaped_code_name, sizeof(escaped_code_name), orgs[i].code_name);
        json_escape(escaped_display_name, sizeof(escaped_display_name), orgs[i].display_name);
        json_escape(escaped_note, sizeof(escaped_note), orgs[i].note);

        pos += snprintf(response_body + pos, sizeof(response_body) - pos,
                       "%s{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                       "\"note\":\"%s\",\"is_active\":%s}",
                       i > 0 ? "," : "",
                       org_id_hex, escaped_code_name, escaped_display_name,
                       escaped_note, orgs[i].is_active ? "true" : "false");
        if (pos >= (int)sizeof(response_body)) {
            free(orgs);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response_body + pos, sizeof(response_body) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(orgs);
    return response_json_ok(response_body);
}

/*
 * PUT /api/admin/organizations
 *
 * Update organization properties.
 *
 * Query params:
 *   id - Organization UUID (hex, required)
 *
 * Body (all optional):
 *   display_name - New display name
 *   note         - New note
 *   is_active    - New active status (boolean)
 */
HttpResponse *admin_update_organization_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Dual authentication: session OR org key */
    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Extract organization ID from query params */
    if (!req->query_string) {
        return response_json_error(400, "Organization ID required in query params");
    }

    char *id_str = http_query_get_param(req->query_string, "id");
    if (!id_str) {
        return response_json_error(400, "Organization ID required");
    }

    unsigned char org_id[16];
    if (hex_to_bytes(id_str, org_id, 16) != 0) {
        free(id_str);
        return response_json_error(400, "Invalid organization ID format");
    }
    free(id_str);

    /* Parse request body (all fields optional) */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *display_name = json_get_string(req->body, "display_name");
    char *note = json_get_string(req->body, "note");

    int is_active_val;
    int *is_active = NULL;
    if (json_get_bool(req->body, "is_active", &is_active_val) == 0) {
        is_active = &is_active_val;
    }

    /* At least one field must be provided */
    if (!display_name && !note && !is_active) {
        free(display_name);
        free(note);
        return response_json_error(400, "At least one field must be provided for update");
    }

    /* Call update handler */
    int result = admin_update_organization(db, ctx.user_account_pin, ctx.organization_key_pin, org_id, display_name, note, is_active);

    /* Clean up */
    free(display_name);
    free(note);

    if (result != 0) {
        return response_json_error(404, "Organization not found or update failed");
    }

    /* Return updated organization */
    admin_organization_t org;
    if (admin_get_organization(db, ctx.user_account_pin, ctx.organization_key_pin, org_id, &org) != 0) {
        return response_json_error(500, "Update succeeded but failed to retrieve updated organization");
    }

    char org_id_hex[33];
    bytes_to_hex(org.id, 16, org_id_hex, sizeof(org_id_hex));

    char escaped_code_name[256];
    char escaped_display_name[512];
    char escaped_note[1024];
    json_escape(escaped_code_name, sizeof(escaped_code_name), org.code_name);
    json_escape(escaped_display_name, sizeof(escaped_display_name), org.display_name);
    json_escape(escaped_note, sizeof(escaped_note), org.note);

    char response_body[4096];
    snprintf(response_body, sizeof(response_body),
             "{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
             "\"note\":\"%s\",\"is_active\":%s}",
             org_id_hex, escaped_code_name, escaped_display_name,
             escaped_note, org.is_active ? "true" : "false");

    return response_json_ok(response_body);
}

/* ============================================================================
 * Resource Servers Endpoints
 * ========================================================================== */

/*
 * GET /api/admin/resource-servers
 *
 * Handles both list and get-single:
 * - With 'id' param: Get single resource server
 * - With 'organization_id' param: List resource servers in org
 *
 * Query params (list mode):
 *   organization_id - Organization UUID (hex, required)
 *   limit          - Max results (default 20, max 100)
 *   offset         - Skip N results (default 0)
 *   is_active      - Filter by active status (optional)
 *
 * Query params (single mode):
 *   id - Resource server UUID (hex)
 */
HttpResponse *admin_get_resource_servers_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Dual authentication: session OR org key */
    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Check for get-single mode */
    char *id_str = NULL;
    if (req->query_string) {
        id_str = http_query_get_param(req->query_string, "id");
    }

    if (id_str) {
        /* GET SINGLE MODE */
        unsigned char server_id[16];
        if (hex_to_bytes(id_str, server_id, 16) != 0) {
            free(id_str);
            return response_json_error(400, "Invalid resource server ID format");
        }
        free(id_str);

        admin_resource_server_t server;
        if (admin_get_resource_server(db, ctx.user_account_pin, ctx.organization_key_pin, server_id, &server) != 0) {
            return response_json_error(404, "Resource server not found or access denied");
        }

        char server_id_hex[33];
        bytes_to_hex(server.id, 16, server_id_hex, sizeof(server_id_hex));

        char escaped_code_name[256], escaped_display_name[512];
        char escaped_address[1024], escaped_note[1024];
        json_escape(escaped_code_name, sizeof(escaped_code_name), server.code_name);
        json_escape(escaped_display_name, sizeof(escaped_display_name), server.display_name);
        json_escape(escaped_address, sizeof(escaped_address), server.address);
        json_escape(escaped_note, sizeof(escaped_note), server.note);

        char response_body[4096];
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                 "\"address\":\"%s\",\"note\":\"%s\",\"is_active\":%s}",
                 server_id_hex, escaped_code_name, escaped_display_name,
                 escaped_address, escaped_note, server.is_active ? "true" : "false");

        return response_json_ok(response_body);
    }

    /* LIST MODE - requires organization_id */
    if (!req->query_string) {
        return response_json_error(400, "organization_id required");
    }

    char *org_id_str = http_query_get_param(req->query_string, "organization_id");
    if (!org_id_str) {
        return response_json_error(400, "organization_id required");
    }

    unsigned char org_id[16];
    if (hex_to_bytes(org_id_str, org_id, 16) != 0) {
        free(org_id_str);
        return response_json_error(400, "Invalid organization_id format");
    }
    free(org_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    int is_active_filter;
    int *is_active_ptr = NULL;
    if (parse_query_bool(req->query_string, "is_active", &is_active_filter) == 0) {
        is_active_ptr = &is_active_filter;
    }

    admin_resource_server_t *servers = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_resource_servers(db, ctx.user_account_pin, ctx.organization_key_pin, org_id, limit, offset, is_active_ptr, &servers, &count, &total) != 0) {
        return response_json_error(500, "Failed to list resource servers");
    }

    char response_body[16384];
    int pos = snprintf(response_body, sizeof(response_body), "{\"resource_servers\":[");

    for (int i = 0; i < count; i++) {
        char server_id_hex[33];
        bytes_to_hex(servers[i].id, 16, server_id_hex, sizeof(server_id_hex));

        char escaped_code_name[256], escaped_display_name[512];
        char escaped_address[1024], escaped_note[1024];
        json_escape(escaped_code_name, sizeof(escaped_code_name), servers[i].code_name);
        json_escape(escaped_display_name, sizeof(escaped_display_name), servers[i].display_name);
        json_escape(escaped_address, sizeof(escaped_address), servers[i].address);
        json_escape(escaped_note, sizeof(escaped_note), servers[i].note);

        pos += snprintf(response_body + pos, sizeof(response_body) - pos,
                       "%s{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                       "\"address\":\"%s\",\"note\":\"%s\",\"is_active\":%s}",
                       i > 0 ? "," : "", server_id_hex, escaped_code_name, escaped_display_name,
                       escaped_address, escaped_note, servers[i].is_active ? "true" : "false");
        if (pos >= (int)sizeof(response_body)) {
            free(servers);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response_body + pos, sizeof(response_body) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(servers);
    return response_json_ok(response_body);
}

/*
 * POST /api/admin/resource-servers
 *
 * Create new resource server.
 *
 * Body:
 *   organization_id - Organization UUID (hex, required)
 *   code_name      - Unique code name (required)
 *   display_name   - Display name (required)
 *   address        - API base URL (required)
 *   note           - Description (optional)
 */
HttpResponse *admin_create_resource_server_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *org_id_str = json_get_string(req->body, "organization_id");
    char *code_name = json_get_string(req->body, "code_name");
    char *display_name = json_get_string(req->body, "display_name");
    char *address = json_get_string(req->body, "address");
    char *note = json_get_string(req->body, "note");

    if (!org_id_str || !code_name || !*code_name || !display_name || !*display_name || !address || !*address) {
        free(org_id_str); free(code_name); free(display_name); free(address); free(note);
        return response_json_error(400, "organization_id, code_name, display_name, and address are required");
    }

    unsigned char org_id[16];
    if (hex_to_bytes(org_id_str, org_id, 16) != 0) {
        free(org_id_str); free(code_name); free(display_name); free(address); free(note);
        return response_json_error(400, "Invalid organization_id format");
    }
    free(org_id_str);

    unsigned char server_id[16];
    int result = admin_create_resource_server(db, ctx.user_account_pin, ctx.organization_key_pin,
                                               org_id, code_name, display_name, address, note, server_id);

    free(code_name); free(display_name); free(address); free(note);

    if (result != 0) {
        return response_json_error(409, "Resource server creation failed (possibly duplicate code_name or address)");
    }

    char server_id_hex[33];
    bytes_to_hex(server_id, 16, server_id_hex, sizeof(server_id_hex));

    char response_body[256];
    snprintf(response_body, sizeof(response_body),
             "{\"id\":\"%s\",\"message\":\"Resource server created successfully\"}",
             server_id_hex);

    return response_json_ok(response_body);
}

/*
 * PUT /api/admin/resource-servers
 *
 * Update resource server.
 *
 * Query params:
 *   id - Resource server UUID (hex, required)
 *
 * Body (all optional):
 *   display_name - New display name
 *   address      - New address
 *   note         - New note
 *   is_active    - New active status
 */
HttpResponse *admin_update_resource_server_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "Resource server ID required in query params");
    }

    char *id_str = http_query_get_param(req->query_string, "id");
    if (!id_str) {
        return response_json_error(400, "Resource server ID required");
    }

    unsigned char server_id[16];
    if (hex_to_bytes(id_str, server_id, 16) != 0) {
        free(id_str);
        return response_json_error(400, "Invalid resource server ID format");
    }
    free(id_str);

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *display_name = json_get_string(req->body, "display_name");
    char *address = json_get_string(req->body, "address");
    char *note = json_get_string(req->body, "note");

    int is_active_val;
    int *is_active = NULL;
    if (json_get_bool(req->body, "is_active", &is_active_val) == 0) {
        is_active = &is_active_val;
    }

    if (!display_name && !address && !note && !is_active) {
        free(display_name); free(address); free(note);
        return response_json_error(400, "At least one field must be provided for update");
    }

    int result = admin_update_resource_server(db, ctx.user_account_pin, ctx.organization_key_pin, server_id, display_name, address, note, is_active);

    free(display_name); free(address); free(note);

    if (result != 0) {
        return response_json_error(404, "Resource server not found or update failed");
    }

    return response_json_ok("{\"message\":\"Resource server updated successfully\"}");
}

/* ============================================================================
 * Clients Endpoints
 * ========================================================================== */

/*
 * GET /api/admin/clients
 *
 * Query params (list): organization_id, limit, offset, is_active
 * Query params (single): id
 */
HttpResponse *admin_get_clients_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    char *id_str = NULL;
    if (req->query_string) {
        id_str = http_query_get_param(req->query_string, "id");
    }

    if (id_str) {
        /* GET SINGLE */
        unsigned char client_id[16];
        if (hex_to_bytes(id_str, client_id, 16) != 0) {
            free(id_str);
            return response_json_error(400, "Invalid client ID format");
        }
        free(id_str);

        admin_client_t client;
        if (admin_get_client(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, &client) != 0) {
            return response_json_error(404, "Client not found or access denied");
        }

        char client_id_hex[33];
        bytes_to_hex(client.id, 16, client_id_hex, sizeof(client_id_hex));

        char esc_code[256], esc_display[512], esc_type[64], esc_grant[64], esc_note[1024];
        json_escape(esc_code, sizeof(esc_code), client.code_name);
        json_escape(esc_display, sizeof(esc_display), client.display_name);
        json_escape(esc_type, sizeof(esc_type), client.client_type);
        json_escape(esc_grant, sizeof(esc_grant), client.grant_type);
        json_escape(esc_note, sizeof(esc_note), client.note);

        char response[4096];
        snprintf(response, sizeof(response),
                 "{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                 "\"client_type\":\"%s\",\"grant_type\":\"%s\",\"note\":\"%s\","
                 "\"require_mfa\":%s,\"access_token_ttl_seconds\":%d,"
                 "\"issue_refresh_tokens\":%s,\"refresh_token_ttl_seconds\":%d,"
                 "\"maximum_session_seconds\":%d,\"secret_rotation_seconds\":%d,"
                 "\"is_active\":%s}",
                 client_id_hex, esc_code, esc_display, esc_type, esc_grant, esc_note,
                 client.require_mfa ? "true" : "false", client.access_token_ttl_seconds,
                 client.issue_refresh_tokens ? "true" : "false", client.refresh_token_ttl_seconds,
                 client.maximum_session_seconds, client.secret_rotation_seconds,
                 client.is_active ? "true" : "false");

        return response_json_ok(response);
    }

    /* LIST MODE */
    if (!req->query_string) {
        return response_json_error(400, "organization_id required");
    }

    char *org_id_str = http_query_get_param(req->query_string, "organization_id");
    if (!org_id_str) {
        return response_json_error(400, "organization_id required");
    }

    unsigned char org_id[16];
    if (hex_to_bytes(org_id_str, org_id, 16) != 0) {
        free(org_id_str);
        return response_json_error(400, "Invalid organization_id format");
    }
    free(org_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    int is_active_filter;
    int *is_active_ptr = NULL;
    if (parse_query_bool(req->query_string, "is_active", &is_active_filter) == 0) {
        is_active_ptr = &is_active_filter;
    }

    admin_client_t *clients = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_clients(db, ctx.user_account_pin, ctx.organization_key_pin, org_id, limit, offset, is_active_ptr, &clients, &count, &total) != 0) {
        return response_json_error(500, "Failed to list clients");
    }

    char response[32768];
    int pos = snprintf(response, sizeof(response), "{\"clients\":[");

    for (int i = 0; i < count; i++) {
        char client_id_hex[33];
        bytes_to_hex(clients[i].id, 16, client_id_hex, sizeof(client_id_hex));

        char esc_code[256], esc_display[512], esc_type[64], esc_grant[64], esc_note[1024];
        json_escape(esc_code, sizeof(esc_code), clients[i].code_name);
        json_escape(esc_display, sizeof(esc_display), clients[i].display_name);
        json_escape(esc_type, sizeof(esc_type), clients[i].client_type);
        json_escape(esc_grant, sizeof(esc_grant), clients[i].grant_type);
        json_escape(esc_note, sizeof(esc_note), clients[i].note);

        pos += snprintf(response + pos, sizeof(response) - pos,
                       "%s{\"id\":\"%s\",\"code_name\":\"%s\",\"display_name\":\"%s\","
                       "\"client_type\":\"%s\",\"grant_type\":\"%s\",\"note\":\"%s\","
                       "\"require_mfa\":%s,\"access_token_ttl_seconds\":%d,"
                       "\"issue_refresh_tokens\":%s,\"refresh_token_ttl_seconds\":%d,"
                       "\"maximum_session_seconds\":%d,\"secret_rotation_seconds\":%d,"
                       "\"is_active\":%s}",
                       i > 0 ? "," : "", client_id_hex, esc_code, esc_display,
                       esc_type, esc_grant, esc_note,
                       clients[i].require_mfa ? "true" : "false", clients[i].access_token_ttl_seconds,
                       clients[i].issue_refresh_tokens ? "true" : "false", clients[i].refresh_token_ttl_seconds,
                       clients[i].maximum_session_seconds, clients[i].secret_rotation_seconds,
                       clients[i].is_active ? "true" : "false");
        if (pos >= (int)sizeof(response)) {
            free(clients);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response + pos, sizeof(response) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(clients);
    return response_json_ok(response);
}

/*
 * POST /api/admin/clients
 *
 * Body: organization_id, code_name, display_name, client_type, grant_type,
 *       note, require_mfa, access_token_ttl_seconds, issue_refresh_tokens,
 *       refresh_token_ttl_seconds, maximum_session_seconds, secret_rotation_seconds
 */
HttpResponse *admin_create_client_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *org_id_str = json_get_string(req->body, "organization_id");
    char *code_name = json_get_string(req->body, "code_name");
    char *display_name = json_get_string(req->body, "display_name");
    char *client_type = json_get_string(req->body, "client_type");
    char *grant_type = json_get_string(req->body, "grant_type");
    char *note = json_get_string(req->body, "note");

    int require_mfa = 0, access_ttl, issue_refresh = 0, refresh_ttl, max_session, secret_rotation;
    if (!org_id_str || !code_name || !*code_name || !display_name || !*display_name ||
        !client_type || !*client_type || !grant_type || !*grant_type ||
        json_get_int(req->body, "access_token_ttl_seconds", &access_ttl) != 0) {
        free(org_id_str); free(code_name); free(display_name);
        free(client_type); free(grant_type); free(note);
        return response_json_error(400, "Missing required fields");
    }

    /* Optional fields - default to 0/false if not provided */
    json_get_bool(req->body, "require_mfa", &require_mfa);
    json_get_bool(req->body, "issue_refresh_tokens", &issue_refresh);
    if (json_get_int(req->body, "refresh_token_ttl_seconds", &refresh_ttl) != 0) refresh_ttl = -1;
    if (json_get_int(req->body, "maximum_session_seconds", &max_session) != 0) max_session = -1;
    if (json_get_int(req->body, "secret_rotation_seconds", &secret_rotation) != 0) secret_rotation = -1;

    unsigned char org_id[16], client_id[16];
    if (hex_to_bytes(org_id_str, org_id, 16) != 0) {
        free(org_id_str); free(code_name); free(display_name);
        free(client_type); free(grant_type); free(note);
        return response_json_error(400, "Invalid organization_id format");
    }
    free(org_id_str);

    int result = admin_create_client(db, ctx.user_account_pin, ctx.organization_key_pin,
                                      org_id, code_name, display_name,
                                     client_type, grant_type, note, require_mfa, access_ttl,
                                     issue_refresh, refresh_ttl, max_session, secret_rotation, client_id);

    free(code_name); free(display_name); free(client_type); free(grant_type); free(note);

    if (result != 0) {
        return response_json_error(409, "Client creation failed");
    }

    char client_id_hex[33];
    bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));

    char response[256];
    snprintf(response, sizeof(response),
             "{\"id\":\"%s\",\"message\":\"Client created successfully\"}",
             client_id_hex);

    return response_json_ok(response);
}

/*
 * PUT /api/admin/clients
 *
 * Query: id
 * Body (all optional): display_name, note, require_mfa, access_token_ttl_seconds,
 *       issue_refresh_tokens, refresh_token_ttl_seconds, maximum_session_seconds,
 *       secret_rotation_seconds, is_active
 */
HttpResponse *admin_update_client_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "Client ID required");
    }

    char *id_str = http_query_get_param(req->query_string, "id");
    if (!id_str) {
        return response_json_error(400, "Client ID required");
    }

    unsigned char client_id[16];
    if (hex_to_bytes(id_str, client_id, 16) != 0) {
        free(id_str);
        return response_json_error(400, "Invalid client ID format");
    }
    free(id_str);

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *display_name = json_get_string(req->body, "display_name");
    char *note = json_get_string(req->body, "note");

    int require_mfa_val, access_ttl_val, issue_refresh_val, refresh_ttl_val;
    int max_session_val, secret_rotation_val, is_active_val;
    int *require_mfa = NULL, *access_ttl = NULL, *issue_refresh = NULL;
    int *refresh_ttl = NULL, *max_session = NULL, *secret_rotation = NULL, *is_active = NULL;

    if (json_get_bool(req->body, "require_mfa", &require_mfa_val) == 0) require_mfa = &require_mfa_val;
    if (json_get_int(req->body, "access_token_ttl_seconds", &access_ttl_val) == 0) access_ttl = &access_ttl_val;
    if (json_get_bool(req->body, "issue_refresh_tokens", &issue_refresh_val) == 0) issue_refresh = &issue_refresh_val;
    if (json_get_int(req->body, "refresh_token_ttl_seconds", &refresh_ttl_val) == 0) refresh_ttl = &refresh_ttl_val;
    if (json_get_int(req->body, "maximum_session_seconds", &max_session_val) == 0) max_session = &max_session_val;
    if (json_get_int(req->body, "secret_rotation_seconds", &secret_rotation_val) == 0) secret_rotation = &secret_rotation_val;
    if (json_get_bool(req->body, "is_active", &is_active_val) == 0) is_active = &is_active_val;

    if (!display_name && !note && !require_mfa && !access_ttl && !issue_refresh &&
        !refresh_ttl && !max_session && !secret_rotation && !is_active) {
        free(display_name); free(note);
        return response_json_error(400, "At least one field must be provided");
    }

    int result = admin_update_client(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, display_name, note, require_mfa,
                                     access_ttl, issue_refresh, refresh_ttl, max_session,
                                     secret_rotation, is_active);

    free(display_name); free(note);

    if (result != 0) {
        return response_json_error(404, "Client not found or update failed");
    }

    return response_json_ok("{\"message\":\"Client updated successfully\"}");
}

/* ============================================================================
 * Client Redirect URIs Endpoints
 * ========================================================================== */

/*
 * GET /api/admin/client-redirect-uris
 * Query: client_id, limit, offset
 */
HttpResponse *admin_get_client_redirect_uris_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "client_id required");
    }

    char *client_id_str = http_query_get_param(req->query_string, "client_id");
    if (!client_id_str) {
        return response_json_error(400, "client_id required");
    }

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    admin_client_redirect_uri_t *uris = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_client_redirect_uris(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, limit, offset, &uris, &count, &total) != 0) {
        return response_json_error(500, "Failed to list redirect URIs");
    }

    char response[16384];
    int pos = snprintf(response, sizeof(response), "{\"redirect_uris\":[");

    for (int i = 0; i < count; i++) {
        char esc_uri[1024], esc_note[1024];
        json_escape(esc_uri, sizeof(esc_uri), uris[i].redirect_uri);
        json_escape(esc_note, sizeof(esc_note), uris[i].note);

        pos += snprintf(response + pos, sizeof(response) - pos,
                       "%s{\"redirect_uri\":\"%s\",\"note\":\"%s\"}",
                       i > 0 ? "," : "", esc_uri, esc_note);
        if (pos >= (int)sizeof(response)) {
            free(uris);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response + pos, sizeof(response) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(uris);
    return response_json_ok(response);
}

/*
 * POST /api/admin/client-redirect-uris
 * Body: client_id, redirect_uri, note
 */
HttpResponse *admin_create_client_redirect_uri_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *client_id_str = json_get_string(req->body, "client_id");
    char *redirect_uri = json_get_string(req->body, "redirect_uri");
    char *note = json_get_string(req->body, "note");

    if (!client_id_str || !redirect_uri) {
        free(client_id_str); free(redirect_uri); free(note);
        return response_json_error(400, "client_id and redirect_uri required");
    }

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str); free(redirect_uri); free(note);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int result = admin_create_client_redirect_uri(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, redirect_uri, note);

    free(redirect_uri); free(note);

    if (result != 0) {
        return response_json_error(409, "Failed to create redirect URI");
    }

    return response_json_ok("{\"message\":\"Redirect URI created successfully\"}");
}

/*
 * DELETE /api/admin/client-redirect-uris
 * Query: client_id, redirect_uri
 */
HttpResponse *admin_delete_client_redirect_uri_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "client_id and redirect_uri required");
    }

    char *client_id_str = http_query_get_param(req->query_string, "client_id");
    char *redirect_uri_enc = http_query_get_param(req->query_string, "redirect_uri");

    if (!client_id_str || !redirect_uri_enc) {
        free(client_id_str); free(redirect_uri_enc);
        return response_json_error(400, "client_id and redirect_uri required");
    }

    /* URL-decode redirect_uri */
    char *redirect_uri = malloc(strlen(redirect_uri_enc) + 1);
    if (!redirect_uri) {
        free(client_id_str); free(redirect_uri_enc);
        return response_json_error(500, "Internal server error");
    }
    if (str_url_decode(redirect_uri, strlen(redirect_uri_enc) + 1, redirect_uri_enc) < 0) {
        free(client_id_str); free(redirect_uri_enc); free(redirect_uri);
        return response_json_error(400, "Invalid URL encoding in redirect_uri");
    }
    free(redirect_uri_enc);

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str); free(redirect_uri);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int result = admin_delete_client_redirect_uri(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, redirect_uri);

    free(redirect_uri);

    if (result != 0) {
        return response_json_error(404, "Redirect URI not found or delete failed");
    }

    return response_json_ok("{\"message\":\"Redirect URI deleted successfully\"}");
}

/* ============================================================================
 * Client-Resource-Server Links Endpoints
 * ========================================================================== */

/*
 * GET /api/admin/client-resource-servers
 * Query: client_id, limit, offset
 */
HttpResponse *admin_get_client_resource_servers_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "client_id required");
    }

    char *client_id_str = http_query_get_param(req->query_string, "client_id");
    if (!client_id_str) {
        return response_json_error(400, "client_id required");
    }

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    admin_client_resource_server_t *links = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_client_resource_servers(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, limit, offset, &links, &count, &total) != 0) {
        return response_json_error(500, "Failed to list resource servers");
    }

    char response[16384];
    int pos = snprintf(response, sizeof(response), "{\"links\":[");

    for (int i = 0; i < count; i++) {
        char server_id_hex[33];
        bytes_to_hex(links[i].resource_server_id, 16, server_id_hex, sizeof(server_id_hex));

        char esc_server_code[256], esc_server_display[512], esc_address[1024];
        json_escape(esc_server_code, sizeof(esc_server_code), links[i].resource_server_code_name);
        json_escape(esc_server_display, sizeof(esc_server_display), links[i].resource_server_display_name);
        json_escape(esc_address, sizeof(esc_address), links[i].resource_server_address);

        pos += snprintf(response + pos, sizeof(response) - pos,
                       "%s{\"resource_server_id\":\"%s\","
                       "\"resource_server_code_name\":\"%s\","
                       "\"resource_server_display_name\":\"%s\","
                       "\"resource_server_address\":\"%s\"}",
                       i > 0 ? "," : "", server_id_hex,
                       esc_server_code, esc_server_display, esc_address);
        if (pos >= (int)sizeof(response)) {
            free(links);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response + pos, sizeof(response) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(links);
    return response_json_ok(response);
}

/*
 * GET /api/admin/resource-server-clients
 * Query: resource_server_id, limit, offset
 */
HttpResponse *admin_get_resource_server_clients_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "resource_server_id required");
    }

    char *server_id_str = http_query_get_param(req->query_string, "resource_server_id");
    if (!server_id_str) {
        return response_json_error(400, "resource_server_id required");
    }

    unsigned char resource_server_id[16];
    if (hex_to_bytes(server_id_str, resource_server_id, 16) != 0) {
        free(server_id_str);
        return response_json_error(400, "Invalid resource_server_id format");
    }
    free(server_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    admin_resource_server_client_t *links = NULL;
    int count = 0;
    int total = 0;
    if (admin_list_resource_server_clients(db, ctx.user_account_pin, ctx.organization_key_pin, resource_server_id, limit, offset, &links, &count, &total) != 0) {
        return response_json_error(500, "Failed to list clients");
    }

    char response[16384];
    int pos = snprintf(response, sizeof(response), "{\"links\":[");

    for (int i = 0; i < count; i++) {
        char client_id_hex[33];
        bytes_to_hex(links[i].client_id, 16, client_id_hex, sizeof(client_id_hex));

        char esc_client_code[256], esc_client_display[512];
        json_escape(esc_client_code, sizeof(esc_client_code), links[i].client_code_name);
        json_escape(esc_client_display, sizeof(esc_client_display), links[i].client_display_name);

        pos += snprintf(response + pos, sizeof(response) - pos,
                       "%s{\"client_id\":\"%s\","
                       "\"client_code_name\":\"%s\","
                       "\"client_display_name\":\"%s\"}",
                       i > 0 ? "," : "", client_id_hex,
                       esc_client_code, esc_client_display);
        if (pos >= (int)sizeof(response)) {
            free(links);
            return response_json_error(500, "Response too large");
        }
    }

    snprintf(response + pos, sizeof(response) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(links);
    return response_json_ok(response);
}

/*
 * POST /api/admin/client-resource-servers
 * Body: client_id, resource_server_id
 */
HttpResponse *admin_create_client_resource_server_link_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *client_id_str = json_get_string(req->body, "client_id");
    char *server_id_str = json_get_string(req->body, "resource_server_id");

    if (!client_id_str || !server_id_str) {
        free(client_id_str); free(server_id_str);
        return response_json_error(400, "client_id and resource_server_id required");
    }

    unsigned char client_id[16], server_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0 ||
        hex_to_bytes(server_id_str, server_id, 16) != 0) {
        free(client_id_str); free(server_id_str);
        return response_json_error(400, "Invalid ID format");
    }
    free(client_id_str); free(server_id_str);

    int result = admin_create_client_resource_server_link(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, server_id);

    if (result != 0) {
        return response_json_error(409, "Failed to create link");
    }

    return response_json_ok("{\"message\":\"Link created successfully\"}");
}

/*
 * DELETE /api/admin/client-resource-servers
 * Query: client_id, resource_server_id
 */
HttpResponse *admin_delete_client_resource_server_link_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "client_id and resource_server_id required");
    }

    char *client_id_str = http_query_get_param(req->query_string, "client_id");
    char *server_id_str = http_query_get_param(req->query_string, "resource_server_id");

    if (!client_id_str || !server_id_str) {
        free(client_id_str); free(server_id_str);
        return response_json_error(400, "client_id and resource_server_id required");
    }

    unsigned char client_id[16], server_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0 ||
        hex_to_bytes(server_id_str, server_id, 16) != 0) {
        free(client_id_str); free(server_id_str);
        return response_json_error(400, "Invalid ID format");
    }
    free(client_id_str); free(server_id_str);

    int result = admin_delete_client_resource_server_link(db, ctx.user_account_pin, ctx.organization_key_pin, client_id, server_id);

    if (result != 0) {
        return response_json_error(404, "Link not found or delete failed");
    }

    return response_json_ok("{\"message\":\"Link deleted successfully\"}");
}

/* ============================================================================
 * RESOURCE SERVER KEY OPERATIONS
 * ========================================================================== */

/*
 * POST /api/admin/resource-server-keys
 *
 * Create new resource server API key.
 *
 * Body:
 *   resource_server_id - Resource server UUID (hex, required)
 *   secret            - Secret (optional - if omitted, one is generated)
 *   note              - Description (optional)
 *
 * Response (generated secret):
 *   { "id": "uuid", "key_id": "uuid", "secret": "...", "message": "Save the secret now..." }
 *
 * Response (user-provided secret):
 *   { "id": "uuid", "key_id": "uuid", "message": "Key created successfully" }
 */
HttpResponse *admin_create_resource_server_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *rs_id_str = json_get_string(req->body, "resource_server_id");
    char *note = json_get_string(req->body, "note");
    char *user_secret = json_get_string(req->body, "secret");

    if (!rs_id_str) {
        free(note); free(user_secret);
        return response_json_error(400, "resource_server_id required");
    }

    /* Determine mode: generate or use provided secret */
    char generated_secret[64];
    const char *secret_to_use;
    int is_generated = 0;

    if (user_secret && strlen(user_secret) > 0) {
        /* Bring-your-own mode */
        secret_to_use = user_secret;
        is_generated = 0;
    } else {
        /* Generate mode */
        if (crypto_random_token(generated_secret, sizeof(generated_secret), 32) < 0) {
            free(rs_id_str); free(note); free(user_secret);
            return response_json_error(500, "Failed to generate secret");
        }
        secret_to_use = generated_secret;
        is_generated = 1;
    }

    unsigned char rs_id[16], key_id[16];
    if (hex_to_bytes(rs_id_str, rs_id, 16) != 0) {
        free(rs_id_str); free(note); free(user_secret);
        return response_json_error(400, "Invalid resource_server_id format");
    }
    free(rs_id_str);

    int result = admin_create_resource_server_key(db, ctx.user_account_pin, ctx.organization_key_pin,
                                                   rs_id, secret_to_use, note, key_id);

    free(note); free(user_secret);

    if (result != 0) {
        return response_json_error(409, "Key creation failed");
    }

    char key_id_hex[33];
    bytes_to_hex(key_id, 16, key_id_hex, sizeof(key_id_hex));

    char response_body[1024];
    if (is_generated) {
        /* Include secret in response */
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"key_id\":\"%s\",\"secret\":\"%s\","
                 "\"message\":\"Save the secret now - it cannot be retrieved later!\"}",
                 key_id_hex, key_id_hex, generated_secret);
    } else {
        /* Don't include secret (user already has it) */
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"key_id\":\"%s\","
                 "\"message\":\"Key created successfully\"}",
                 key_id_hex, key_id_hex);
    }

    return response_json_ok(response_body);
}

/*
 * GET /api/admin/resource-server-keys
 *
 * List resource server API keys.
 *
 * Query params:
 *   resource_server_id - Resource server UUID (hex, required)
 *   limit             - Max results (default 100, max 1000)
 *   offset            - Skip N results (default 0)
 *   is_active         - Filter by active status (optional)
 */
HttpResponse *admin_get_resource_server_keys_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "resource_server_id required");
    }

    char *rs_id_str = http_query_get_param(req->query_string, "resource_server_id");
    if (!rs_id_str) {
        return response_json_error(400, "resource_server_id required");
    }

    unsigned char rs_id[16];
    if (hex_to_bytes(rs_id_str, rs_id, 16) != 0) {
        free(rs_id_str);
        return response_json_error(400, "Invalid resource_server_id format");
    }
    free(rs_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Parse is_active filter */
    int *filter_is_active = NULL;
    int is_active_val;
    if (parse_query_bool(req->query_string, "is_active", &is_active_val) == 0) {
        filter_is_active = &is_active_val;
    }

    admin_resource_server_key_t *keys = NULL;
    int count = 0;
    int total = 0;

    if (admin_list_resource_server_keys(db, ctx.user_account_pin, ctx.organization_key_pin,
                                         rs_id, limit, offset, filter_is_active, &keys, &count, &total) != 0) {
        return response_json_error(500, "Failed to list keys");
    }

    /* Build JSON array */
    char *response_body = malloc(4096 + (count * 1024));
    if (!response_body) {
        free(keys);
        return response_json_error(500, "Memory allocation failed");
    }

    int pos = snprintf(response_body, 4096, "{\"keys\":[");

    for (int i = 0; i < count; i++) {
        char key_id_hex[33];
        bytes_to_hex(keys[i].id, 16, key_id_hex, sizeof(key_id_hex));

        char escaped_note[1024], escaped_generated_at[64];
        json_escape(escaped_note, sizeof(escaped_note), keys[i].note);
        json_escape(escaped_generated_at, sizeof(escaped_generated_at), keys[i].generated_at);

        pos += snprintf(response_body + pos, 4096 + (count * 1024) - pos,
                       "%s{\"id\":\"%s\",\"key_id\":\"%s\",\"is_active\":%s,"
                       "\"generated_at\":\"%s\",\"note\":\"%s\"}",
                       i > 0 ? "," : "",
                       key_id_hex, key_id_hex,
                       keys[i].is_active ? "true" : "false",
                       escaped_generated_at, escaped_note);
    }

    snprintf(response_body + pos, 4096 + (count * 1024) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(keys);

    HttpResponse *resp = response_json_ok(response_body);
    free(response_body);
    return resp;
}

/*
 * DELETE /api/admin/resource-server-keys
 *
 * Revoke (soft delete) resource server API key.
 *
 * Query params:
 *   id - Key UUID (hex, required)
 */
HttpResponse *admin_delete_resource_server_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "id required");
    }

    char *key_id_str = http_query_get_param(req->query_string, "id");
    if (!key_id_str) {
        return response_json_error(400, "id required");
    }

    unsigned char key_id[16];
    if (hex_to_bytes(key_id_str, key_id, 16) != 0) {
        free(key_id_str);
        return response_json_error(400, "Invalid key ID format");
    }
    free(key_id_str);

    int result = admin_revoke_resource_server_key(db, ctx.user_account_pin, ctx.organization_key_pin, key_id);

    if (result != 0) {
        return response_json_error(404, "Key not found or revoke failed");
    }

    return response_json_ok("{\"message\":\"Key revoked successfully\"}");
}

/* ============================================================================
 * CLIENT KEY OPERATIONS
 * ========================================================================== */

/*
 * POST /api/admin/client-keys
 *
 * Create new client API key (confidential clients only).
 *
 * Body:
 *   client_id - Client UUID (hex, required, must be confidential)
 *   secret    - Secret (optional - if omitted, one is generated)
 *   note      - Description (optional)
 *
 * Response (generated secret):
 *   { "id": "uuid", "key_id": "uuid", "secret": "...", "message": "Save the secret now..." }
 *
 * Response (user-provided secret):
 *   { "id": "uuid", "key_id": "uuid", "message": "Key created successfully" }
 */
HttpResponse *admin_create_client_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *client_id_str = json_get_string(req->body, "client_id");
    char *note = json_get_string(req->body, "note");
    char *user_secret = json_get_string(req->body, "secret");

    if (!client_id_str) {
        free(note); free(user_secret);
        return response_json_error(400, "client_id required");
    }

    /* Determine mode: generate or use provided secret */
    char generated_secret[64];
    const char *secret_to_use;
    int is_generated = 0;

    if (user_secret && strlen(user_secret) > 0) {
        /* Bring-your-own mode */
        secret_to_use = user_secret;
        is_generated = 0;
    } else {
        /* Generate mode */
        if (crypto_random_token(generated_secret, sizeof(generated_secret), 32) < 0) {
            free(client_id_str); free(note); free(user_secret);
            return response_json_error(500, "Failed to generate secret");
        }
        secret_to_use = generated_secret;
        is_generated = 1;
    }

    unsigned char client_id[16], key_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str); free(note); free(user_secret);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int result = admin_create_client_key(db, ctx.user_account_pin, ctx.organization_key_pin,
                                          client_id, secret_to_use, note, key_id);

    free(note); free(user_secret);

    if (result != 0) {
        return response_json_error(409, "Key creation failed (client must be confidential)");
    }

    char key_id_hex[33];
    bytes_to_hex(key_id, 16, key_id_hex, sizeof(key_id_hex));

    char response_body[1024];
    if (is_generated) {
        /* Include secret in response */
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"key_id\":\"%s\",\"secret\":\"%s\","
                 "\"message\":\"Save the secret now - it cannot be retrieved later!\"}",
                 key_id_hex, key_id_hex, generated_secret);
    } else {
        /* Don't include secret (user already has it) */
        snprintf(response_body, sizeof(response_body),
                 "{\"id\":\"%s\",\"key_id\":\"%s\","
                 "\"message\":\"Key created successfully\"}",
                 key_id_hex, key_id_hex);
    }

    return response_json_ok(response_body);
}

/*
 * GET /api/admin/client-keys
 *
 * List client API keys.
 *
 * Query params:
 *   client_id - Client UUID (hex, required)
 *   limit     - Max results (default 100, max 1000)
 *   offset    - Skip N results (default 0)
 *   is_active - Filter by active status (optional)
 */
HttpResponse *admin_get_client_keys_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "client_id required");
    }

    char *client_id_str = http_query_get_param(req->query_string, "client_id");
    if (!client_id_str) {
        return response_json_error(400, "client_id required");
    }

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Parse is_active filter */
    int *filter_is_active = NULL;
    int is_active_val;
    if (parse_query_bool(req->query_string, "is_active", &is_active_val) == 0) {
        filter_is_active = &is_active_val;
    }

    admin_client_key_t *keys = NULL;
    int count = 0;
    int total = 0;

    if (admin_list_client_keys(db, ctx.user_account_pin, ctx.organization_key_pin,
                                client_id, limit, offset, filter_is_active, &keys, &count, &total) != 0) {
        return response_json_error(500, "Failed to list keys");
    }

    /* Build JSON array */
    char *response_body = malloc(4096 + (count * 1024));
    if (!response_body) {
        free(keys);
        return response_json_error(500, "Memory allocation failed");
    }

    int pos = snprintf(response_body, 4096, "{\"keys\":[");

    for (int i = 0; i < count; i++) {
        char key_id_hex[33];
        bytes_to_hex(keys[i].id, 16, key_id_hex, sizeof(key_id_hex));

        char escaped_note[1024], escaped_generated_at[64];
        json_escape(escaped_note, sizeof(escaped_note), keys[i].note);
        json_escape(escaped_generated_at, sizeof(escaped_generated_at), keys[i].generated_at);

        pos += snprintf(response_body + pos, 4096 + (count * 1024) - pos,
                       "%s{\"id\":\"%s\",\"key_id\":\"%s\",\"is_active\":%s,"
                       "\"generated_at\":\"%s\",\"note\":\"%s\"}",
                       i > 0 ? "," : "",
                       key_id_hex, key_id_hex,
                       keys[i].is_active ? "true" : "false",
                       escaped_generated_at, escaped_note);
    }

    snprintf(response_body + pos, 4096 + (count * 1024) - pos,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total);

    free(keys);

    HttpResponse *resp = response_json_ok(response_body);
    free(response_body);
    return resp;
}

/*
 * DELETE /api/admin/client-keys
 *
 * Revoke (soft delete) client API key.
 *
 * Query params:
 *   id - Key UUID (hex, required)
 */
HttpResponse *admin_delete_client_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    auth_context_t ctx;
    if (get_auth_context(req, &ctx) != 0) {
        return response_json_error(401, "Authentication required");
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    if (!req->query_string) {
        return response_json_error(400, "id required");
    }

    char *key_id_str = http_query_get_param(req->query_string, "id");
    if (!key_id_str) {
        return response_json_error(400, "id required");
    }

    unsigned char key_id[16];
    if (hex_to_bytes(key_id_str, key_id, 16) != 0) {
        free(key_id_str);
        return response_json_error(400, "Invalid key ID format");
    }
    free(key_id_str);

    int result = admin_revoke_client_key(db, ctx.user_account_pin, ctx.organization_key_pin, key_id);

    if (result != 0) {
        return response_json_error(404, "Key not found or revoke failed");
    }

    return response_json_ok("{\"message\":\"Key revoked successfully\"}");
}
