/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers.h"
#include "handlers/admin.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/user.h"
#include "db/queries/org.h"
#include "crypto/random.h"
#include "util/config.h"
#include "util/log.h"
#include "util/str.h"
#include "util/data.h"
#include "util/validation.h"
#include "util/json.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>

/* ============================================================================
 * Authentication Helpers
 * ========================================================================== */

/*
 * is_localhost - Check if request is from direct localhost connection
 *
 * Security policy: Localhost-only endpoints MUST be accessed via direct
 * connection (not through reverse proxy). This prevents header spoofing.
 *
 * Returns: 1 if localhost, 0 if not
 */
static int is_localhost(const HttpRequest *req) {
    /* Reject any request with proxy headers (X-Real-IP, X-Forwarded-For) */
    /* These indicate the request came through a reverse proxy */
    const char *real_ip = http_request_get_header(req, "X-Real-IP");
    const char *forwarded = http_request_get_header(req, "X-Forwarded-For");

    if ((real_ip && real_ip[0] != '\0') || (forwarded && forwarded[0] != '\0')) {
        /* Request came through proxy - reject for localhost-only endpoints */
        return 0;
    }

    /* Direct connection - check socket IP */
    const char *socket_ip = req->remote_ip;
    return (strcmp(socket_ip, "127.0.0.1") == 0 || strcmp(socket_ip, "::1") == 0);
}

/* ============================================================================
 * POST /api/admin/bootstrap
 * ========================================================================== */

HttpResponse *admin_bootstrap_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse request body */
    if (!req->body || req->body_length == 0) {
        return response_json_error(400, "Request body required");
    }

    /* Extract parameters with defaults */
    char *org_code_name = json_get_string(req->body, "org_code_name");
    if (!org_code_name) {
        org_code_name = str_dup("system");
    }

    char *org_display_name = json_get_string(req->body, "org_display_name");
    if (!org_display_name) {
        org_display_name = str_dup("System Organization");
    }

    char *username = json_get_string(req->body, "username");
    char *password = json_get_string(req->body, "password");

    /* Validate required fields */
    if (!username || !password) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        if (password) OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, "username and password are required");
    }

    /* Validate input formats */
    char validation_error[256];

    if (validate_code_name(org_code_name, validation_error, sizeof(validation_error)) != 0) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, validation_error);
    }

    if (validate_display_name(org_display_name, validation_error, sizeof(validation_error)) != 0) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, validation_error);
    }

    if (validate_username(username, validation_error, sizeof(validation_error)) != 0) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, validation_error);
    }

    /* Get config from global context */
    extern const config_t *g_config;

    /* Check if organization already exists (409 Conflict) */
    int org_ex = org_exists(db, org_code_name);
    if (org_ex < 0) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(500, "Failed to check organization existence");
    } else if (org_ex == 1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                 "Organization '%s' already exists. Use a different org_code_name.",
                 org_code_name);
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(409, error_msg);
    }

    /* Check if username already exists (409 Conflict) */
    int user_ex = user_username_exists(db, username);
    if (user_ex < 0) {
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(500, "Failed to check username existence");
    } else if (user_ex == 1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                 "Username '%s' already exists. Use a different username.",
                 username);
        free(org_code_name);
        free(org_display_name);
        free(username);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(409, error_msg);
    }

    /* Call bootstrap handler */
    int result = admin_bootstrap(db, g_config, org_code_name, org_display_name,
                                 username, password);

    /* Build response before cleanup */
    HttpResponse *resp;
    if (result != 0) {
        resp = response_json_error(500, "Bootstrap failed");
    } else {
        JsonBuf *jb = jsonbuf_new(2048);
        jsonbuf_appendf(jb, "{\"message\":\"Bootstrap successful\",\"organization_code_name\":\"");
        jsonbuf_append_escaped(jb, org_code_name);
        jsonbuf_appendf(jb, "\"}");
        resp = jsonbuf_to_response(jb, 200);
    }

    /* Clean up */
    free(org_code_name);
    free(org_display_name);
    free(username);
    OPENSSL_cleanse(password, strlen(password));
    free(password);

    return resp;
}

/* ============================================================================
 * POST /api/admin/organizations
 * ========================================================================== */

HttpResponse *admin_create_organization_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse request body */
    if (!req->body || req->body_length == 0) {
        return response_json_error(400, "Request body required");
    }

    char *code_name = json_get_string(req->body, "code_name");
    char *display_name = json_get_string(req->body, "display_name");
    char *note = json_get_string(req->body, "note");

    /* Validate required fields */
    if (!code_name || !*code_name || !display_name || !*display_name) {
        free(code_name);
        free(display_name);
        free(note);
        return response_json_error(400, "code_name and display_name are required");
    }

    /* Validate input formats */
    char validation_error[256];

    if (validate_code_name(code_name, validation_error, sizeof(validation_error)) != 0) {
        free(code_name);
        free(display_name);
        free(note);
        return response_json_error(400, validation_error);
    }

    if (validate_display_name(display_name, validation_error, sizeof(validation_error)) != 0) {
        free(code_name);
        free(display_name);
        free(note);
        return response_json_error(400, validation_error);
    }

    if (validate_note(note, validation_error, sizeof(validation_error)) != 0) {
        free(code_name);
        free(display_name);
        free(note);
        return response_json_error(400, validation_error);
    }

    /* Call handler */
    int result = admin_create_organization(db, code_name, display_name, note);

    /* Build response */
    HttpResponse *resp;
    if (result == 0) {
        JsonBuf *jb = jsonbuf_new(2048);
        jsonbuf_appendf(jb, "{\"code_name\":\"");
        jsonbuf_append_escaped(jb, code_name);
        jsonbuf_appendf(jb, "\",\"display_name\":\"");
        jsonbuf_append_escaped(jb, display_name);
        jsonbuf_appendf(jb, "\"}");
        resp = jsonbuf_to_response(jb, 200);
    } else {
        resp = response_json_error(409, "Organization already exists or creation failed");
    }

    /* Clean up */
    free(code_name);
    free(display_name);
    free(note);

    return resp;
}

/* ============================================================================
 * POST /api/admin/users
 * ========================================================================== */

HttpResponse *admin_create_user_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse request body */
    if (!req->body || req->body_length == 0) {
        return response_json_error(400, "Request body required");
    }

    char *username = json_get_string(req->body, "username");
    char *email = json_get_string(req->body, "email");
    char *password = json_get_string(req->body, "password");

    /* Validate required fields */
    if (!password) {
        free(username);
        free(email);
        return response_json_error(400, "password is required");
    }

    if (!username && !email) {
        free(username);
        free(email);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, "At least one of username or email is required");
    }

    /* Validate input formats */
    char validation_error[256];

    if (username && validate_username(username, validation_error, sizeof(validation_error)) != 0) {
        free(username);
        free(email);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, validation_error);
    }

    if (email && validate_email(email, validation_error, sizeof(validation_error)) != 0) {
        free(username);
        free(email);
        OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, validation_error);
    }

    /* Call handler */
    unsigned char user_id[16];
    int result = admin_create_user(db, username, email, password, user_id);

    /* Build response */
    HttpResponse *resp;
    if (result == 0) {
        char user_id_hex[33];
        bytes_to_hex(user_id, 16, user_id_hex, sizeof(user_id_hex));

        JsonBuf *jb = jsonbuf_new(2048);
        jsonbuf_appendf(jb, "{\"user_id\":\"%s\"", user_id_hex);

        if (username) {
            jsonbuf_appendf(jb, ",\"username\":\"");
            jsonbuf_append_escaped(jb, username);
            jsonbuf_appendf(jb, "\"");
        }
        if (email) {
            jsonbuf_appendf(jb, ",\"email\":\"");
            jsonbuf_append_escaped(jb, email);
            jsonbuf_appendf(jb, "\"");
        }

        jsonbuf_appendf(jb, "}");
        resp = jsonbuf_to_response(jb, 200);
    } else {
        resp = response_json_error(409, "User already exists or creation failed");
    }

    /* Clean up */
    free(username);
    free(email);
    OPENSSL_cleanse(password, strlen(password));
    free(password);

    return resp;
}

/* ============================================================================
 * POST /api/admin/org-admins
 * ========================================================================== */

HttpResponse *admin_make_org_admin_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse request body */
    if (!req->body || req->body_length == 0) {
        return response_json_error(400, "Request body required");
    }

    char *username = json_get_string(req->body, "username");
    char *org_code_name = json_get_string(req->body, "org_code_name");

    /* Validate required fields */
    if (!username || !org_code_name) {
        free(username);
        free(org_code_name);
        return response_json_error(400, "username and org_code_name are required");
    }

    /* Validate input formats */
    char validation_error[256];

    if (validate_username(username, validation_error, sizeof(validation_error)) != 0) {
        free(username);
        free(org_code_name);
        return response_json_error(400, validation_error);
    }

    if (validate_code_name(org_code_name, validation_error, sizeof(validation_error)) != 0) {
        free(username);
        free(org_code_name);
        return response_json_error(400, validation_error);
    }

    /* Look up user by username to get user_id */
    unsigned char user_id[16];
    if (user_lookup_id_by_username(db, username, user_id) != 0) {
        free(username);
        free(org_code_name);
        return response_json_error(404, "User not found");
    }

    /* Call handler */
    int result = admin_make_org_admin(db, user_id, org_code_name);

    /* Build response */
    HttpResponse *resp;
    if (result == 0) {
        char user_id_hex[33];
        bytes_to_hex(user_id, 16, user_id_hex, sizeof(user_id_hex));

        JsonBuf *jb = jsonbuf_new(2048);
        jsonbuf_appendf(jb, "{\"user_id\":\"%s\",\"message\":\"User '", user_id_hex);
        jsonbuf_append_escaped(jb, username);
        jsonbuf_appendf(jb, "' is now an admin of organization '");
        jsonbuf_append_escaped(jb, org_code_name);
        jsonbuf_appendf(jb, "'\"}");
        resp = jsonbuf_to_response(jb, 200);
    } else {
        resp = response_json_error(404, "Organization not found or operation failed");
    }

    /* Clean up */
    free(username);
    free(org_code_name);

    return resp;
}

/* ============================================================================
 * GET /api/admin/list-all-organizations
 * ========================================================================== */

HttpResponse *admin_list_all_organizations_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse query parameters */
    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Parse is_active filter (optional) */
    int is_active_filter;
    int *is_active_ptr = NULL;
    if (parse_query_bool(req->query_string, "is_active", &is_active_filter) == 0) {
        is_active_ptr = &is_active_filter;
    }

    /* Query all organizations (no user filter) */
    org_data_t *orgs = NULL;
    int count = 0;
    int total = 0;

    if (org_list_all_unscoped(db, limit, offset, is_active_ptr, &orgs, &count, &total) != 0) {
        return response_json_error(500, "Failed to list organizations");
    }

    /* Build JSON array response */
    JsonBuf *jb = jsonbuf_new(4096 + count * 512);
    jsonbuf_appendf(jb, "{\"organizations\":[");

    for (int i = 0; i < count; i++) {
        char org_id_hex[33];
        bytes_to_hex(orgs[i].id, 16, org_id_hex, sizeof(org_id_hex));

        jsonbuf_appendf(jb, "%s{\"id\":\"%s\",\"code_name\":\"",
                        i > 0 ? "," : "", org_id_hex);
        jsonbuf_append_escaped(jb, orgs[i].code_name);
        jsonbuf_appendf(jb, "\",\"display_name\":\"");
        jsonbuf_append_escaped(jb, orgs[i].display_name);
        jsonbuf_appendf(jb, "\",\"note\":\"");
        jsonbuf_append_escaped(jb, orgs[i].note);
        jsonbuf_appendf(jb, "\",\"is_active\":%s}",
                        orgs[i].is_active ? "true" : "false");
    }

    jsonbuf_appendf(jb, "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
                    limit, offset, count, total);

    free(orgs);

    return jsonbuf_to_response(jb, 200);
}

/* ============================================================================
 * POST /api/admin/organization-keys
 * ========================================================================== */

HttpResponse *admin_create_organization_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Localhost validation */
    if (!is_localhost(req)) {
        return response_json_error(403, "Admin endpoints only accessible from localhost");
    }

    /* Get database connection from pool */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Parse request body */
    if (!req->body || req->body_length == 0) {
        return response_json_error(400, "Request body required");
    }

    char *org_code_name = json_get_string(req->body, "organization_code_name");
    char *user_secret = json_get_string(req->body, "secret");
    char *note = json_get_string(req->body, "note");

    /* Validate required fields */
    if (!org_code_name) {
        free(org_code_name);
        if (user_secret) OPENSSL_cleanse(user_secret, strlen(user_secret));
        free(user_secret);
        free(note);
        return response_json_error(400, "organization_code_name is required");
    }

    /* Validate input formats */
    char validation_error[256];

    if (validate_note(note, validation_error, sizeof(validation_error)) != 0) {
        free(org_code_name);
        if (user_secret) OPENSSL_cleanse(user_secret, strlen(user_secret));
        free(user_secret);
        free(note);
        return response_json_error(400, validation_error);
    }

    /* Dual-mode secret provisioning */
    char generated_secret[64];
    const char *secret_to_use;
    int is_generated = 0;

    if (user_secret && strlen(user_secret) > 0) {
        /* User provided their own secret (BYOS) */
        secret_to_use = user_secret;
        is_generated = 0;
    } else {
        /* Generate secure 32-byte base64url token */
        if (crypto_random_token(generated_secret, sizeof(generated_secret), 32) < 0) {
            free(org_code_name);
            if (user_secret) OPENSSL_cleanse(user_secret, strlen(user_secret));
            free(user_secret);
            free(note);
            return response_json_error(500, "Failed to generate secret");
        }
        secret_to_use = generated_secret;
        is_generated = 1;
    }

    /* Create organization key */
    unsigned char key_id[16];
    if (organization_key_create(db, org_code_name, secret_to_use, note, key_id) != 0) {
        free(org_code_name);
        if (user_secret) OPENSSL_cleanse(user_secret, strlen(user_secret));
        free(user_secret);
        OPENSSL_cleanse(generated_secret, sizeof(generated_secret));
        free(note);
        return response_json_error(500, "Failed to create organization key");
    }

    /* Build response */
    char key_id_hex[33];
    bytes_to_hex(key_id, 16, key_id_hex, sizeof(key_id_hex));

    JsonBuf *jb = jsonbuf_new(2048);
    jsonbuf_appendf(jb, "{\"key_id\":\"%s\"", key_id_hex);

    /* Include secret only if generated (show once) */
    if (is_generated) {
        jsonbuf_appendf(jb, ",\"secret\":\"%s\",\"warning\":\"Save the secret now - it cannot be retrieved later!\"",
                        generated_secret);
    }

    if (note) {
        jsonbuf_appendf(jb, ",\"note\":\"");
        jsonbuf_append_escaped(jb, note);
        jsonbuf_appendf(jb, "\"");
    }

    jsonbuf_appendf(jb, "}");

    free(org_code_name);
    if (user_secret) OPENSSL_cleanse(user_secret, strlen(user_secret));
    free(user_secret);
    OPENSSL_cleanse(generated_secret, sizeof(generated_secret));
    free(note);

    return jsonbuf_to_response(jb, 200);
}

/* ============================================================================
 * GET /api/admin/organization-keys
 * ========================================================================== */

HttpResponse *admin_list_organization_keys_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection first (needed for both auth methods) */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Get organization_code_name from query string (optional for org key auth) */
    char *org_code_name_enc = NULL;
    char org_code_name_param_buf[128];
    char *org_code_name_param = NULL;
    if (req->query_string) {
        org_code_name_enc = http_query_get_param(req->query_string, "organization_code_name");
        if (org_code_name_enc) {
            if (str_url_decode(org_code_name_param_buf, sizeof(org_code_name_param_buf), org_code_name_enc) < 0) {
                free(org_code_name_enc);
                return response_json_error(400, "Invalid URL encoding in organization_code_name");
            }
            free(org_code_name_enc);
            org_code_name_param = org_code_name_param_buf;
        }
    }

    /* Dual authentication: localhost OR org key */
    int is_localhost_access = is_localhost(req);
    int is_org_key_access = 0;
    long long auth_org_pin = 0;
    char org_code_name_from_key[128] = "";

    if (!is_localhost_access) {
        /* Try org key authentication */
        long long auth_key_pin;
        if (try_org_key_auth(req, "list_organization_keys", &auth_org_pin, &auth_key_pin) == 0) {
            if (org_code_name_param) {
                /* Org code_name provided - verify it matches the key's org */
                long long requested_org_pin;
                if (organization_get_pin_by_code_name(db, org_code_name_param, &requested_org_pin) == 0) {
                    if (auth_org_pin == requested_org_pin) {
                        is_org_key_access = 1;
                    }
                }
            } else {
                /* No org code_name provided - use the key's org */
                if (organization_get_code_name_by_pin(db, auth_org_pin, org_code_name_from_key) == 0) {
                    is_org_key_access = 1;
                }
            }
        }
    }

    if (!is_localhost_access && !is_org_key_access) {
        return response_json_error(403, "Forbidden - requires localhost or org key authentication");
    }

    /* For localhost: organization_code_name is required */
    if (is_localhost_access && !org_code_name_param) {
        return response_json_error(400, "organization_code_name query parameter required for localhost access");
    }

    /* Determine which org code_name to use */
    const char *org_code_name = org_code_name_param ? org_code_name_param : org_code_name_from_key;

    /* Parse query parameters */
    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Parse is_active filter (optional) */
    int is_active_filter;
    int *is_active_ptr = NULL;
    if (parse_query_bool(req->query_string, "is_active", &is_active_filter) == 0) {
        is_active_ptr = &is_active_filter;
    }

    /* List organization keys */
    admin_organization_key_t *keys = NULL;
    int count = 0;
    int total = 0;

    if (admin_list_organization_keys(db, org_code_name, limit, offset, is_active_ptr, &keys, &count, &total) != 0) {
        return response_json_error(500, "Failed to list organization keys");
    }

    /* Build JSON response */
    JsonBuf *jb = jsonbuf_new(4096 + count * 512);
    jsonbuf_appendf(jb, "{\"keys\":[");

    for (int i = 0; i < count; i++) {
        char key_id_hex[33];
        bytes_to_hex(keys[i].id, 16, key_id_hex, sizeof(key_id_hex));

        jsonbuf_appendf(jb, "%s{\"key_id\":\"%s\",\"is_active\":%s,\"generated_at\":\"%s\",\"note\":\"",
                        i > 0 ? "," : "",
                        key_id_hex,
                        keys[i].is_active ? "true" : "false",
                        keys[i].generated_at);
        jsonbuf_append_escaped(jb, keys[i].note);
        jsonbuf_appendf(jb, "\"}");
    }

    jsonbuf_appendf(jb, "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
                    limit, offset, count, total);

    free(keys);

    return jsonbuf_to_response(jb, 200);
}

/* ============================================================================
 * DELETE /api/admin/organization-keys
 * ========================================================================== */

HttpResponse *admin_revoke_organization_key_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection first (needed for both auth methods) */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        return response_json_error(500, "Database connection unavailable");
    }

    /* Get key_id from query string */
    char *key_id_str = NULL;
    if (req->query_string) {
        key_id_str = http_query_get_param(req->query_string, "id");
    }

    if (!key_id_str) {
        return response_json_error(400, "id query parameter required");
    }

    /* Parse key_id from hex */
    unsigned char key_id[16];
    if (hex_to_bytes(key_id_str, key_id, 16) != 0) {
        free(key_id_str);
        return response_json_error(400, "Invalid key ID format");
    }
    free(key_id_str);

    /* Dual authentication: localhost OR org key */
    int is_localhost_access = is_localhost(req);
    int is_org_key_access = 0;

    if (!is_localhost_access) {
        /* Try org key authentication */
        long long auth_org_pin, auth_key_pin;
        if (try_org_key_auth(req, "revoke_organization_key", &auth_org_pin, &auth_key_pin) == 0) {
            /* Org key auth succeeded - verify it matches the key being revoked */
            long long key_org_pin;
            if (organization_key_get_organization_pin(db, key_id, &key_org_pin) == 0) {
                if (auth_org_pin == key_org_pin) {
                    is_org_key_access = 1;
                    /* Note: Self-revocation is allowed (revoking the key you're using) */
                }
            }
        }
    }

    if (!is_localhost_access && !is_org_key_access) {
        return response_json_error(403, "Forbidden - requires localhost or org key authentication");
    }

    /* Revoke key */
    if (admin_revoke_organization_key(db, key_id) != 0) {
        return response_json_error(500, "Failed to revoke organization key");
    }

    return response_json_ok("{\"message\":\"Organization key revoked successfully\"}");
}
