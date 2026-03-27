#include "handlers.h"
#include "handlers/rs.h"
#include "handlers/oauth.h"
#include "db/db_pool.h"
#include "db/queries/oauth.h"
#include "util/log.h"
#include "util/data.h"
#include "util/json.h"
#include "util/config.h"
#include "util/validation.h"
#ifdef EMAIL_SUPPORT
#include "util/email.h"
#include "util/template.h"
#endif

#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================================
 * RS Key Auth Helper
 * ========================================================================== */

typedef struct {
    db_handle_t *db;
    long long rs_pin;
} rs_auth_t;

/*
 * Authenticate RS key from JSON body.
 * Returns NULL on success (out populated), or error HttpResponse on failure.
 */
static HttpResponse *rs_authenticate(const HttpRequest *req,
                                      const char *operation,
                                      rs_auth_t *out) {
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    out->db = db_pool_get_connection();
    if (!out->db) {
        log_error("Failed to acquire database connection");
        return response_json_error(503, "Service unavailable");
    }

    const char *body = req->body ? req->body : "";

    char *rs_id_str = json_get_string(body, "resource_server_id");
    char *rs_key_id_str = json_get_string(body, "resource_server_key_id");
    char *rs_secret = json_get_string(body, "resource_server_secret");

    if (!rs_id_str || !rs_key_id_str || !rs_secret) {
        free(rs_id_str);
        free(rs_key_id_str);
        if (rs_secret) OPENSSL_cleanse(rs_secret, strlen(rs_secret));
        free(rs_secret);
        return response_json_error(400,
            "resource_server_id, resource_server_key_id, and resource_server_secret required");
    }

    unsigned char rs_id[16];
    if (hex_to_bytes(rs_id_str, rs_id, 16) != 0) {
        free(rs_id_str);
        free(rs_key_id_str);
        OPENSSL_cleanse(rs_secret, strlen(rs_secret));
        free(rs_secret);
        return response_json_error(400, "Invalid resource_server_id format");
    }
    free(rs_id_str);

    unsigned char rs_key_id[16];
    if (hex_to_bytes(rs_key_id_str, rs_key_id, 16) != 0) {
        free(rs_key_id_str);
        OPENSSL_cleanse(rs_secret, strlen(rs_secret));
        free(rs_secret);
        return response_json_error(400, "Invalid resource_server_key_id format");
    }
    free(rs_key_id_str);

    long long rs_key_pin = 0;
    int auth_result = oauth_handler_resource_server_authenticate(
        out->db, rs_id, rs_key_id, rs_secret, &out->rs_pin, &rs_key_pin);

    OPENSSL_cleanse(rs_secret, strlen(rs_secret));
    free(rs_secret);

    if (auth_result != 1) {
        log_warn("RS authentication failed for %s", operation);
        return response_json_error(401, "Authentication failed");
    }

    log_key_usage(out->db, KEY_USAGE_RESOURCE_SERVER, rs_key_pin, operation,
                  http_request_get_client_ip(req, NULL),
                  http_request_get_header(req, "User-Agent"));

    return NULL;
}

/* ============================================================================
 * JSON Response Helpers
 * ========================================================================== */

/* Append user info JSON (user_id, username, is_active, emails array) */
static void append_user_json(JsonBuf *jb, const rs_user_info_t *info) {
    char id_hex[33];
    bytes_to_hex(info->user_id, 16, id_hex, sizeof(id_hex));

    jsonbuf_appendf(jb, "{\"user_id\":\"%s\",\"username\":\"", id_hex);
    jsonbuf_append_escaped(jb, info->username);
    jsonbuf_appendf(jb, "\",\"is_active\":%s,\"emails\":[",
                    info->is_active ? "true" : "false");

    for (int i = 0; i < info->email_count; i++) {
        jsonbuf_appendf(jb, "%s{\"address\":\"", i > 0 ? "," : "");
        jsonbuf_append_escaped(jb, info->emails[i].email_address);
        jsonbuf_appendf(jb, "\",\"is_verified\":%s,\"is_primary\":%s}",
                        info->emails[i].is_verified ? "true" : "false",
                        info->emails[i].is_primary ? "true" : "false");
    }

    jsonbuf_appendf(jb, "]");
}

/* Map RS handler return codes to HTTP error responses */
static HttpResponse *rs_error_response(int rc, const char *context) {
    switch (rc) {
    case 1: return response_json_error(403, "User provisioning not enabled");
    case 2: return response_json_error(409, "Ambiguous match: username and email resolve to different users");
    case 3: return response_json_error(403, "User provisioning not enabled");
    default:
        log_error("RS handler error: %s", context);
        return response_json_error(500, "Internal error");
    }
}

/* ============================================================================
 * Endpoint Handlers
 * ========================================================================== */

HttpResponse *rs_provision_user_handler(const HttpRequest *req,
                                         const RouteParams *params) {
    (void)params;

    if (req->method != HTTP_POST)
        return response_method_not_allowed("POST");

    rs_auth_t auth;
    HttpResponse *err = rs_authenticate(req, "rs_provision_user", &auth);
    if (err) return err;

    const char *body = req->body;
    char *username = json_get_string(body, "username");
    char *email = json_get_string(body, "email");

    if (!username && !email) {
        return response_json_error(400, "username and/or email required");
    }

    char validation_error[256];
    if (username && validate_username(username, validation_error, sizeof(validation_error)) != 0) {
        free(username); free(email);
        return response_json_error(400, validation_error);
    }
    if (email && validate_email(email, validation_error, sizeof(validation_error)) != 0) {
        free(username); free(email);
        return response_json_error(400, validation_error);
    }

    rs_user_info_t info = {0};
    int rc = rs_handler_provision_user(auth.db, auth.rs_pin, username, email,
                                        g_config->invitation_token_ttl_seconds,
                                        http_request_get_client_ip(req, NULL),
                                        &info);

    if (rc != 0) {
        free(username);
        free(email);
        rs_user_info_free(&info);
        return rs_error_response(rc, "provision_user");
    }

    /* Build response */
    JsonBuf *jb = jsonbuf_new(2048);
    append_user_json(jb, &info);
    jsonbuf_appendf(jb, ",\"created\":%s", info.was_created ? "true" : "false");

    if (info.was_created && info.invitation_token[0]) {
        char invite_url[512];
        if (strcmp(g_config->host, "localhost") == 0) {
            snprintf(invite_url, sizeof(invite_url),
                     "http://localhost:%d/accept-invitation?token=%s",
                     g_config->port, info.invitation_token);
        } else {
            snprintf(invite_url, sizeof(invite_url),
                     "https://%s/accept-invitation?token=%s",
                     g_config->host, info.invitation_token);
        }

        jsonbuf_appendf(jb, ",\"invitation\":{\"token\":\"");
        jsonbuf_append_escaped(jb, info.invitation_token);
        jsonbuf_appendf(jb, "\",\"url\":\"");
        jsonbuf_append_escaped(jb, invite_url);
        jsonbuf_appendf(jb, "\"}");

#ifdef EMAIL_SUPPORT
        /* Send invitation email if user has an email */
        if (email && info.was_created) {
            char *body_text = template_render("emails/invitation.txt",
                                               "URL", invite_url, NULL);
            char *body_html = template_render("emails/invitation.html",
                                               "URL", invite_url, NULL);

            if (body_text && body_html)
                email_send(g_config, email, "Set up your account",
                           body_text, body_html);

            if (body_text) OPENSSL_cleanse(body_text, strlen(body_text));
            free(body_text);
            if (body_html) OPENSSL_cleanse(body_html, strlen(body_html));
            free(body_html);
        }
#endif
        OPENSSL_cleanse(invite_url, sizeof(invite_url));
    }

    jsonbuf_appendf(jb, "}");

    free(username);
    free(email);
    rs_user_info_free(&info);
    return jsonbuf_to_response(jb, 200);
}

HttpResponse *rs_lookup_user_handler(const HttpRequest *req,
                                      const RouteParams *params) {
    (void)params;

    rs_auth_t auth;
    HttpResponse *err = rs_authenticate(req, "rs_lookup_user", &auth);
    if (err) return err;

    const char *body = req->body;
    char *user_id_str = json_get_string(body, "user_id");
    char *username = json_get_string(body, "username");
    char *email = json_get_string(body, "email");

    unsigned char user_id[16];
    unsigned char *user_id_ptr = NULL;

    if (user_id_str) {
        if (hex_to_bytes(user_id_str, user_id, 16) != 0) {
            free(user_id_str);
            free(username);
            free(email);
            return response_json_error(400, "Invalid user_id format");
        }
        user_id_ptr = user_id;
    }
    free(user_id_str);

    if (!user_id_ptr && !username && !email) {
        return response_json_error(400, "user_id, username, and/or email required");
    }

    rs_user_info_t info = {0};
    int rc = rs_handler_lookup_user(auth.db, auth.rs_pin,
                                     user_id_ptr, username, email, &info);

    free(username);
    free(email);

    if (rc != 0) {
        rs_user_info_free(&info);
        if (rc == 1) return response_json_error(404, "User not found");
        if (rc == 2) return response_json_error(409,
            "Ambiguous match: username and email resolve to different users");
        if (rc == 3) return response_json_error(403, "User provisioning not enabled");
        return response_json_error(500, "Internal error");
    }

    JsonBuf *jb = jsonbuf_new(2048);
    append_user_json(jb, &info);
    jsonbuf_appendf(jb, "}");

    rs_user_info_free(&info);
    return jsonbuf_to_response(jb, 200);
}

HttpResponse *rs_link_client_user_handler(const HttpRequest *req,
                                            const RouteParams *params) {
    (void)params;

    if (req->method != HTTP_POST)
        return response_method_not_allowed("POST");

    rs_auth_t auth;
    HttpResponse *err = rs_authenticate(req, "rs_link_client_user", &auth);
    if (err) return err;

    const char *body = req->body;
    char *client_id_str = json_get_string(body, "client_id");
    char *user_id_str = json_get_string(body, "user_id");

    if (!client_id_str || !user_id_str) {
        free(client_id_str);
        free(user_id_str);
        return response_json_error(400, "client_id and user_id required");
    }

    unsigned char client_id[16], user_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        free(user_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    if (hex_to_bytes(user_id_str, user_id, 16) != 0) {
        free(user_id_str);
        return response_json_error(400, "Invalid user_id format");
    }
    free(user_id_str);

    int rc = rs_handler_link_client_user(auth.db, auth.rs_pin, client_id, user_id);

    if (rc == 2) return response_json_error(404, "Client not linked to this resource server");
    if (rc == 3) return response_json_error(404, "User not found");
    if (rc != 0) return rs_error_response(rc, "link_client_user");

    return response_json_ok("{\"message\":\"User linked to client\"}");
}

HttpResponse *rs_unlink_client_user_handler(const HttpRequest *req,
                                              const RouteParams *params) {
    (void)params;

    if (req->method != HTTP_DELETE)
        return response_method_not_allowed("DELETE");

    rs_auth_t auth;
    HttpResponse *err = rs_authenticate(req, "rs_unlink_client_user", &auth);
    if (err) return err;

    const char *body = req->body;
    char *client_id_str = json_get_string(body, "client_id");
    char *user_id_str = json_get_string(body, "user_id");

    if (!client_id_str || !user_id_str) {
        free(client_id_str);
        free(user_id_str);
        return response_json_error(400, "client_id and user_id required");
    }

    unsigned char client_id[16], user_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        free(user_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    if (hex_to_bytes(user_id_str, user_id, 16) != 0) {
        free(user_id_str);
        return response_json_error(400, "Invalid user_id format");
    }
    free(user_id_str);

    int rc = rs_handler_unlink_client_user(auth.db, auth.rs_pin, client_id, user_id);

    if (rc == 2) return response_json_error(404, "Client not linked to this resource server");
    if (rc != 0) return rs_error_response(rc, "unlink_client_user");

    return response_json_ok("{\"message\":\"User unlinked from client\"}");
}

HttpResponse *rs_list_client_users_handler(const HttpRequest *req,
                                             const RouteParams *params) {
    (void)params;

    rs_auth_t auth;
    HttpResponse *err = rs_authenticate(req, "rs_list_client_users", &auth);
    if (err) return err;

    const char *body = req->body;
    char *client_id_str = json_get_string(body, "client_id");

    if (!client_id_str)
        return response_json_error(400, "client_id required");

    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(client_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    int limit = 20, offset = 0;
    json_get_int(body, "limit", &limit);
    json_get_int(body, "offset", &offset);
    if (limit < 1) limit = 1;
    if (limit > 100) limit = 100;
    if (offset < 0) offset = 0;

    rs_client_user_t *users = NULL;
    int count = 0, total = 0;
    int rc = rs_handler_list_client_users(auth.db, auth.rs_pin, client_id,
                                           limit, offset, &users, &count, &total);

    if (rc == 2) return response_json_error(404, "Client not linked to this resource server");
    if (rc != 0) return rs_error_response(rc, "list_client_users");

    JsonBuf *jb = jsonbuf_new(2048 + count * 256);
    jsonbuf_appendf(jb, "{\"users\":[");

    for (int i = 0; i < count; i++) {
        char id_hex[33];
        bytes_to_hex(users[i].user_id, 16, id_hex, sizeof(id_hex));

        jsonbuf_appendf(jb, "%s{\"user_id\":\"%s\",\"username\":\"",
                        i > 0 ? "," : "", id_hex);
        jsonbuf_append_escaped(jb, users[i].username);
        jsonbuf_appendf(jb, "\",\"is_active\":%s}",
                        users[i].is_active ? "true" : "false");
    }

    jsonbuf_appendf(jb, "],\"pagination\":{\"limit\":%d,\"offset\":%d,"
                        "\"count\":%d,\"total\":%d}}",
                    limit, offset, count, total);

    free(users);
    return jsonbuf_to_response(jb, 200);
}
