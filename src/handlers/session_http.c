/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers.h"
#include "handlers/session.h"
#include "handlers/oauth.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/user.h"
#include "db/queries/oauth.h"
#include "db/queries/mfa.h"
#include "util/data.h"
#include "util/log.h"
#include "util/str.h"
#include "util/json.h"
#include "util/validation.h"
#ifdef EMAIL_SUPPORT
#include "util/email.h"
#endif
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Default session TTL: 7 days */
#define DEFAULT_SESSION_TTL_SECONDS (7 * 24 * 60 * 60)

/* Cookie name for session token */
#define SESSION_COOKIE_NAME "session"

/* ============================================================================
 * Auth Helper
 * ========================================================================== */

/*
 * require_authenticated_session - Validate session cookie and MFA completion
 *
 * Returns NULL on success (session populated), or error response on failure.
 */
static HttpResponse *require_authenticated_session(const HttpRequest *req,
                                                    db_handle_t *db,
                                                    oauth_session_info_t *out_session) {
    const char *cookie_header = http_request_get_header(req, "Cookie");
    char *session_token = NULL;
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, SESSION_COOKIE_NAME);
    }

    if (!session_token) {
        return response_json_error(401, "Authentication required");
    }

    if (oauth_session_get_by_token(db, session_token, out_session) != 0) {
        free(session_token);
        return response_json_error(401, "Invalid or expired session");
    }

    free(session_token);

    if (out_session->user_requires_mfa && !out_session->mfa_completed) {
        return response_json_error(403, "MFA verification required");
    }

    return NULL;
}

/* ============================================================================
 * Login Handler
 * ========================================================================== */

/*
 * POST /login
 *
 * Request body:
 *   {"username":"alice","password":"secret"}
 *
 * Response (success):
 *   200 OK
 *   Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
 *   {"message":"Login successful"}
 *
 * Response (failure):
 *   401 Unauthorized
 *   {"error":"invalid_credentials","message":"Invalid username or password"}
 */
HttpResponse *login_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;  /* Unused */
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Parse JSON request body */
    const char *body = req->body;
    if (!body) {
        return response_json_error(400, "Request body required");
    }

    char *username = json_get_string(body, "username");
    char *password = json_get_string(body, "password");

    if (!username || !password) {
        free(username);
        if (password) OPENSSL_cleanse(password, strlen(password));
        free(password);
        return response_json_error(400, "username and password required");
    }

    /* Authenticate and create session */
    char *session_token = NULL;
    long long user_pin = 0;

    int rc = session_authenticate_and_create(
        db, username, password,
        http_request_get_client_ip(req, NULL),  /* source_ip */
        http_request_get_header(req, "User-Agent"),  /* user_agent */
        DEFAULT_SESSION_TTL_SECONDS,
        &session_token,
        &user_pin
    );

    free(username);
    OPENSSL_cleanse(password, strlen(password));
    free(password);

    if (rc != 0) {
        return response_json_error(401, "Invalid credentials");
    }

    /* Build Set-Cookie header */
    char cookie_header[512];
    snprintf(cookie_header, sizeof(cookie_header),
             "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d",
             SESSION_COOKIE_NAME, session_token, DEFAULT_SESSION_TTL_SECONDS);

    /* Get user profile to check MFA preference */
    user_profile_t profile;
    if (user_get_profile(db, user_pin, &profile) != 0) {
        free(session_token);
        return response_json_error(500, "Failed to retrieve user profile");
    }

    /* Check if user has MFA configured */
    mfa_method_t *mfa_methods = NULL;
    int mfa_count = 0;
    if (mfa_method_list(db, user_pin, 1, &mfa_methods, &mfa_count) != 0) {
        free(session_token);
        return response_json_error(500, "Failed to retrieve MFA methods");
    }

    /* Build JSON response body */
    HttpResponse *resp;
    if (profile.require_mfa && mfa_count > 0) {
        JsonBuf *jb = jsonbuf_new(2048 + mfa_count * 256);
        jsonbuf_appendf(jb, "{\"message\":\"Login successful\","
                        "\"mfa_required\":true,\"mfa_methods\":[");
        for (int i = 0; i < mfa_count; i++) {
            char id_hex[33];
            bytes_to_hex(mfa_methods[i].id, 16, id_hex, sizeof(id_hex));
            jsonbuf_appendf(jb, "%s{\"id\":\"%s\",\"type\":\"",
                            i > 0 ? "," : "", id_hex);
            jsonbuf_append_escaped(jb, mfa_methods[i].mfa_method);
            jsonbuf_appendf(jb, "\",\"display_name\":\"");
            jsonbuf_append_escaped(jb, mfa_methods[i].display_name);
            jsonbuf_appendf(jb, "\"}");
        }
        jsonbuf_appendf(jb, "]}");
        free(mfa_methods);
        resp = jsonbuf_to_response(jb, 200);
    } else {
        free(mfa_methods);
        resp = response_json_ok("{\"message\":\"Login successful\"}");
    }

    if (!resp) {
        free(session_token);
        log_error("Failed to create HTTP response");
        return response_json_error(500, "Internal server error");
    }

    http_response_set_header(resp, "Set-Cookie", cookie_header);

    free(session_token);

    return resp;
}

/*
 * GET /api/user/management-setups
 *
 * Returns management UI setups that the current user can access.
 * Requires valid session cookie.
 *
 * Query parameters:
 *   callback_url - Expected callback URL (e.g., http://localhost:8080/callback)
 *   api_url      - Expected API URL (e.g., http://localhost:8080/api)
 *
 * Response (success):
 *   200 OK
 *   {
 *     "setups": [
 *       {
 *         "org_code_name": "testorg",
 *         "org_display_name": "Test Organization",
 *         "client_id": "abc123...",
 *         "client_code_name": "management_ui",
 *         "client_display_name": "Management UI",
 *         "resource_server_address": "http://localhost:8080/api"
 *       }
 *     ]
 *   }
 */
HttpResponse *management_setups_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Parse query parameters */
    const char *query_string = req->query_string;
    if (!query_string) {
        return response_json_error(400, "callback_url and api_url query parameters required");
    }

    char *callback_url_encoded = http_query_get_param(query_string, "callback_url");
    char *api_url_encoded = http_query_get_param(query_string, "api_url");

    if (!callback_url_encoded || !api_url_encoded) {
        free(callback_url_encoded);
        free(api_url_encoded);
        return response_json_error(400, "callback_url and api_url query parameters required");
    }

    /* URL-decode the parameters */
    char callback_url[512];
    char api_url[256];

    if (str_url_decode(callback_url, sizeof(callback_url), callback_url_encoded) < 0 ||
        str_url_decode(api_url, sizeof(api_url), api_url_encoded) < 0) {
        free(callback_url_encoded);
        free(api_url_encoded);
        return response_json_error(400, "Invalid URL encoding in parameters");
    }

    free(callback_url_encoded);
    free(api_url_encoded);

    /* Parse session cookie */
    const char *cookie_header = http_request_get_header(req, "Cookie");
    char *session_token = NULL;
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, "session");
    }

    if (!session_token) {
        return response_json_error(401, "Authentication required");
    }

    /* Get session info */
    oauth_session_info_t session;
    if (oauth_session_get_by_token(db, session_token, &session) != 0) {
        free(session_token);
        return response_json_error(401, "Invalid or expired session");
    }
    free(session_token);

    /* Get management UI setups */
    management_ui_setup_t *setups = NULL;
    int count = 0;
    if (user_get_management_ui_setups(db, session.user_account_pin, callback_url, api_url, 50, 0, &setups, &count) != 0) {
        return response_json_error(500, "Failed to get management UI setups");
    }

    /* Build JSON response */
    JsonBuf *jb = jsonbuf_new(4096 + count * 512);
    jsonbuf_appendf(jb, "{\"setups\":[");

    for (int i = 0; i < count; i++) {
        char client_id_hex[33];
        bytes_to_hex(setups[i].client_id, 16, client_id_hex, sizeof(client_id_hex));

        jsonbuf_appendf(jb, "%s{\"org_code_name\":\"", i > 0 ? "," : "");
        jsonbuf_append_escaped(jb, setups[i].org_code_name);
        jsonbuf_appendf(jb, "\",\"org_display_name\":\"");
        jsonbuf_append_escaped(jb, setups[i].org_display_name);
        jsonbuf_appendf(jb, "\",\"client_id\":\"%s\",\"client_code_name\":\"", client_id_hex);
        jsonbuf_append_escaped(jb, setups[i].client_code_name);
        jsonbuf_appendf(jb, "\",\"client_display_name\":\"");
        jsonbuf_append_escaped(jb, setups[i].client_display_name);
        jsonbuf_appendf(jb, "\",\"resource_server_address\":\"");
        jsonbuf_append_escaped(jb, setups[i].resource_server_address);
        jsonbuf_appendf(jb, "\"}");
    }

    jsonbuf_appendf(jb, "]}");

    free(setups);

    return jsonbuf_to_response(jb, 200);
}

/*
 * GET /api/user/profile
 *
 * Returns profile information for the authenticated user.
 * Requires valid session cookie.
 */
HttpResponse *profile_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Get user profile */
    user_profile_t profile;
    if (user_get_profile(db, session.user_account_pin, &profile) != 0) {
        return response_json_error(500, "Failed to get user profile");
    }

    /* Convert user_id to hex */
    char user_id_hex[33];
    bytes_to_hex(profile.user_id, 16, user_id_hex, sizeof(user_id_hex));

    /* Build JSON response */
    JsonBuf *jb = jsonbuf_new(2048);
    jsonbuf_appendf(jb, "{\"user_id\":\"%s\",\"username\":\"", user_id_hex);
    jsonbuf_append_escaped(jb, profile.username);
    jsonbuf_appendf(jb, "\",\"has_mfa\":%s,\"require_mfa\":%s}",
                    profile.has_mfa ? "true" : "false",
                    profile.require_mfa ? "true" : "false");

    return jsonbuf_to_response(jb, 200);
}

/*
 * GET /api/user/emails
 *
 * Returns email addresses for the authenticated user.
 * Requires valid session cookie.
 */
HttpResponse *emails_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    int limit = parse_query_int(req->query_string, "limit", 20, 1, 100);
    int offset = parse_query_int(req->query_string, "offset", 0, 0, 9999);

    /* Get user emails */
    user_email_t *emails = NULL;
    int count = 0;
    int total_count = 0;
    if (user_get_emails(db, session.user_account_pin, limit, offset, &emails, &count, &total_count) != 0) {
        return response_json_error(500, "Failed to get user emails");
    }

    /* Build JSON response with pagination metadata */
    JsonBuf *jb = jsonbuf_new(4096 + count * 256);
    jsonbuf_appendf(jb, "{\"emails\":[");

    for (int i = 0; i < count; i++) {
        jsonbuf_appendf(jb, "%s{\"email_address\":\"", i > 0 ? "," : "");
        jsonbuf_append_escaped(jb, emails[i].email_address);
        jsonbuf_appendf(jb, "\",\"is_primary\":%s,\"is_verified\":%s}",
                        emails[i].is_primary ? "true" : "false",
                        emails[i].is_verified ? "true" : "false");
    }

    jsonbuf_appendf(jb, "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
                    limit, offset, count, total_count);

    free(emails);

    return jsonbuf_to_response(jb, 200);
}

/*
 * POST /api/user/password
 *
 * Changes the authenticated user's password.
 * Requires valid session cookie and correct current password.
 */
HttpResponse *change_password_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *current_password = json_get_string(req->body, "current_password");
    char *new_password = json_get_string(req->body, "new_password");

    if (!current_password || !new_password) {
        if (current_password) OPENSSL_cleanse(current_password, strlen(current_password));
        if (new_password) OPENSSL_cleanse(new_password, strlen(new_password));
        free(current_password);
        free(new_password);
        return response_json_error(400, "current_password and new_password required");
    }

    /* Change password */
    int result = user_change_password(db, session.user_account_pin, session.user_account_id,
                                      current_password, new_password);

    OPENSSL_cleanse(current_password, strlen(current_password));
    OPENSSL_cleanse(new_password, strlen(new_password));
    free(current_password);
    free(new_password);

    if (result == 1) {
        /* Success */
        return response_json_ok("{\"message\":\"Password changed successfully\"}");
    } else if (result == 0) {
        /* Invalid current password */
        return response_json_error(401, "Current password is incorrect");
    } else {
        /* Error */
        return response_json_error(500, "Failed to change password");
    }
}

/*
 * POST /api/user/username
 *
 * Changes the authenticated user's username.
 * Requires valid session cookie.
 */
HttpResponse *change_username_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *new_username = json_get_string(req->body, "new_username");
    if (!new_username) {
        return response_json_error(400, "new_username required");
    }

    char validation_error[256];
    if (validate_username(new_username, validation_error, sizeof(validation_error)) != 0) {
        free(new_username);
        return response_json_error(400, validation_error);
    }

    /* Change username */
    int result = user_change_username(db, session.user_account_pin, session.user_account_id,
                                      new_username);

    free(new_username);

    if (result == 1) {
        return response_json_ok("{\"message\":\"Username changed successfully\"}");
    } else if (result == 0) {
        return response_json_error(400, "Invalid username change");
    } else {
        return response_json_error(500, "Failed to change username");
    }
}

/*
 * POST /api/user/emails
 *
 * Adds a new email address to the authenticated user's account.
 * The email is added as unverified and non-primary.
 */
HttpResponse *add_email_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *email = json_get_string(req->body, "email");
    if (!email) {
        return response_json_error(400, "email required");
    }

    char validation_error[256];
    if (validate_email(email, validation_error, sizeof(validation_error)) != 0) {
        free(email);
        return response_json_error(400, validation_error);
    }

    int exists = user_email_exists(db, email, session.user_account_pin);
    if (exists < 0) {
        free(email);
        return response_json_error(500, "Failed to check email");
    } else if (exists == 1) {
        free(email);
        return response_json_error(409, "Email already taken");
    }

    if (user_add_email(db, session.user_account_pin, email) != 0) {
        free(email);
        return response_json_error(500, "Failed to add email");
    }

    free(email);
    return response_json_ok("{\"message\":\"Email added\"}");
}

/*
 * DELETE /api/user/emails
 *
 * Removes an email address from the authenticated user's account.
 * Idempotent: returns success even if the email was already gone.
 */
HttpResponse *delete_email_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *email = json_get_string(req->body, "email");
    if (!email) {
        return response_json_error(400, "email required");
    }

    int result = user_delete_email(db, session.user_account_pin, email);
    free(email);

    if (result < 0) {
        return response_json_error(500, "Failed to delete email");
    }

    return response_json_ok("{\"message\":\"Email deleted\"}");
}

/*
 * POST /api/user/emails/set-primary
 *
 * Sets an email address as the primary email for the authenticated user.
 */
HttpResponse *set_primary_email_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *email = json_get_string(req->body, "email");

    int result = user_set_primary_email(db, session.user_account_pin, email);
    free(email);  /* safe if NULL */

    if (result == 1) {
        return response_json_error(404, "Email not found");
    } else if (result < 0) {
        return response_json_error(500, "Failed to set primary email");
    }

    return response_json_ok("{\"message\":\"Primary email updated\"}");
}

#ifdef EMAIL_SUPPORT

/*
 * POST /email-verification-token
 *
 * Creates a verification token and sends a verification email.
 * Requires valid session cookie.
 *
 * Request body:
 *   {"email":"user@example.com"}
 */
HttpResponse *create_email_verification_token_handler(const HttpRequest *req,
                                                       const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    oauth_session_info_t session;
    HttpResponse *auth_err = require_authenticated_session(req, db, &session);
    if (auth_err) return auth_err;

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *email = json_get_string(req->body, "email");
    if (!email) {
        return response_json_error(400, "email required");
    }

    char validation_error[256];
    if (validate_email(email, validation_error, sizeof(validation_error)) != 0) {
        free(email);
        return response_json_error(400, validation_error);
    }

    extern const config_t *g_config;

    char token[44];
    int result = user_create_email_verification_token(
        db, session.user_account_pin, email,
        g_config->email_verification_token_ttl_seconds,
        http_request_get_client_ip(req, NULL),
        token);

    if (result != 0) {
        free(email);
        if (result == 1) {
            return response_json_error(400, "Unable to send verification email");
        }
        return response_json_error(500, "Failed to create verification token");
    }

    /* Build verification URL */
    char verify_url[512];
    if (strcmp(g_config->host, "localhost") == 0) {
        snprintf(verify_url, sizeof(verify_url),
                 "http://localhost:%d/verify-email?token=%s",
                 g_config->port, token);
    } else {
        snprintf(verify_url, sizeof(verify_url),
                 "https://%s/verify-email?token=%s",
                 g_config->host, token);
    }

    /* Send verification email */
    char body_text[1024];
    snprintf(body_text, sizeof(body_text),
             "Click the link below to verify your email address:\n\n%s\n\n"
             "If you did not request this, you can safely ignore this email.",
             verify_url);

    char body_html[2048];
    snprintf(body_html, sizeof(body_html),
             "<p>Click the link below to verify your email address:</p>"
             "<p><a href=\"%s\">%s</a></p>"
             "<p>If you did not request this, you can safely ignore this email.</p>",
             verify_url, verify_url);

    email_send(g_config, email, "Verify your email address", body_text, body_html);

    free(email);
    return response_json_ok("{\"message\":\"Verification email sent\"}");
}

/*
 * GET /verify-email?token=...
 *
 * Public endpoint (no auth). Renders confirmation page showing the email
 * address and username so the user can confirm before verifying.
 */
HttpResponse *verify_email_page_handler(const HttpRequest *req,
                                         const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        HttpResponse *resp = http_response_new(500);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Internal server error</p></body></html>");
        return resp;
    }

    char *token = http_query_get_param(req->query_string, "token");
    if (!token) {
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Missing token</p></body></html>");
        return resp;
    }

    email_verification_result_t result;
    int rc = user_lookup_email_verification_token(db, token, &result);

    if (rc != 0) {
        free(token);
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body>"
            "<p>This verification link is invalid or has expired.</p>"
            "</body></html>");
        return resp;
    }

    /* Render confirmation page */
    char html[4096];
    char escaped_email[512];
    str_html_escape(escaped_email, sizeof(escaped_email), result.email_address);

    char user_id_hex[33];
    bytes_to_hex(result.user_id, 16, user_id_hex, sizeof(user_id_hex));

    char username_display[640];
    if (result.username[0] != '\0') {
        char escaped_username[512];
        str_html_escape(escaped_username, sizeof(escaped_username), result.username);
        snprintf(username_display, sizeof(username_display),
                 "<strong>%s</strong>", escaped_username);
    } else {
        snprintf(username_display, sizeof(username_display),
                 "<em style=\"color:#666;\">not set</em>");
    }

    snprintf(html, sizeof(html),
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Verify Email</title>"
        "<link rel=\"stylesheet\" href=\"/css/base.css\">"
        "<style>"
        ".verify-container{width:100%%;max-width:400px;margin-top:40px;}"
        "h1{margin-bottom:24px;font-size:28px;}"
        ".info{margin-bottom:24px;padding:16px;border:1px solid #444;border-radius:4px;}"
        ".info p{margin:4px 0;font-size:14px;color:#ccc;}"
        ".info strong{color:#fff;}"
        "button[type=\"submit\"]{width:100%%;padding:14px;font-size:16px;font-weight:600;"
        "background:#28a745;color:white;border:none;border-radius:4px;cursor:pointer;}"
        "button[type=\"submit\"]:hover{background:#218838;}"
        "</style></head><body>"
        "<div class=\"verify-container\">"
        "<h1>Verify Email</h1>"
        "<div class=\"info\">"
        "<p>Email: <strong>%s</strong></p>"
        "<p>Username: %s</p>"
        "<p>User ID: <span style=\"font-family:monospace;font-size:12px;color:#888;\">%s</span></p>"
        "</div>"
        "<form method=\"POST\" action=\"/verify-email\">"
        "<input type=\"hidden\" name=\"token\" value=\"%s\">"
        "<button type=\"submit\">Confirm Verification</button>"
        "</form>"
        "<p style=\"margin-top:16px;font-size:14px;color:#999;\">"
        "If you did not request this, close this page.</p>"
        "</div></body></html>",
        escaped_email, username_display, user_id_hex, token);

    free(token);

    HttpResponse *resp = http_response_new(200);
    http_response_set(resp, CONTENT_TYPE_HTML, html);
    return resp;
}

/*
 * POST /verify-email
 *
 * Public endpoint (no auth). Consumes the token and marks the email verified.
 * Expects form-encoded body: token=...
 */
HttpResponse *verify_email_handler(const HttpRequest *req,
                                    const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        HttpResponse *resp = http_response_new(500);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Internal server error</p></body></html>");
        return resp;
    }

    /* Parse token from form body */
    char *token = NULL;
    if (req->body) {
        token = http_query_get_param(req->body, "token");
    }

    if (!token) {
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Missing token</p></body></html>");
        return resp;
    }

    email_verification_result_t result;
    int rc = user_verify_email_token(db, token, &result);
    free(token);

    if (rc != 0) {
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><head>"
            "<meta charset=\"UTF-8\">"
            "<title>Verification Failed</title>"
            "<link rel=\"stylesheet\" href=\"/css/base.css\">"
            "<style>.verify-container{width:100%%;max-width:400px;margin-top:40px;}"
            "h1{margin-bottom:24px;font-size:28px;}</style>"
            "</head><body><div class=\"verify-container\">"
            "<h1>Verification Failed</h1>"
            "<p>This verification link is invalid, expired, or has already been used.</p>"
            "<p style=\"margin-top:24px;\"><a href=\"/admin\">Go to your profile</a></p>"
            "</div></body></html>");
        return resp;
    }

    char html[2048];
    char escaped_email[512];
    str_html_escape(escaped_email, sizeof(escaped_email), result.email_address);

    snprintf(html, sizeof(html),
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Email Verified</title>"
        "<link rel=\"stylesheet\" href=\"/css/base.css\">"
        "<style>.verify-container{width:100%%;max-width:400px;margin-top:40px;}"
        "h1{margin-bottom:24px;font-size:28px;color:#28a745;}</style>"
        "</head><body><div class=\"verify-container\">"
        "<h1>Email Verified</h1>"
        "<p><strong>%s</strong> has been verified.</p>"
        "<p style=\"margin-top:24px;\"><a href=\"/admin\">Go to your profile</a></p>"
        "</div></body></html>",
        escaped_email);

    HttpResponse *resp = http_response_new(200);
    http_response_set(resp, CONTENT_TYPE_HTML, html);
    return resp;
}

/*
 * GET /request-password-reset
 *
 * Renders a page with an email input form for requesting a password reset.
 */
HttpResponse *request_password_reset_page_handler(const HttpRequest *req,
                                                    const RouteParams *params) {
    (void)req;
    (void)params;

    const char *html =
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Request Password Reset</title>"
        "<link rel=\"stylesheet\" href=\"/css/base.css\">"
        "<style>"
        ".reset-container{width:100%%;max-width:400px;margin-top:40px;}"
        "h1{margin-bottom:24px;font-size:28px;}"
        ".form-field{margin-bottom:24px;}"
        "label{display:block;margin-bottom:8px;font-size:14px;font-weight:500;}"
        "input[type=\"email\"]{width:100%%;padding:12px 16px;font-size:16px;"
        "border:1px solid #444;border-radius:4px;background:#1a1a1a;color:#fff;box-sizing:border-box;}"
        "input:focus{outline:none;border-color:#87ceeb;}"
        "button[type=\"submit\"]{width:100%%;padding:14px;font-size:16px;font-weight:600;"
        "background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;margin-top:8px;}"
        "button[type=\"submit\"]:hover{background:#0056b3;}"
        "button[type=\"submit\"]:disabled{background:#555;cursor:not-allowed;}"
        "#message{margin-top:20px;padding:12px;border-radius:4px;text-align:center;font-size:14px;}"
        "</style></head><body>"
        "<div class=\"reset-container\">"
        "<h1>Request Password Reset</h1>"
        "<form id=\"resetForm\">"
        "<div class=\"form-field\">"
        "<label for=\"email\">Email Address</label>"
        "<input type=\"email\" id=\"email\" name=\"email\" placeholder=\"you@example.com\" required>"
        "</div>"
        "<button type=\"submit\">Send Reset Link</button>"
        "</form>"
        "<div id=\"message\"></div>"
        "<p style=\"margin-top:40px;\"><a href=\"/login\">&larr; Back to Login</a></p>"
        "</div>"
        "<script>"
        "document.getElementById('resetForm').addEventListener('submit',async(e)=>{"
        "e.preventDefault();"
        "const btn=e.target.querySelector('button[type=\"submit\"]');"
        "const msg=document.getElementById('message');"
        "btn.disabled=true;"
        "try{"
        "const res=await fetch('/request-password-reset',{"
        "method:'POST',headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({email:document.getElementById('email').value})"
        "});"
        "const data=await res.json();"
        "msg.style.background='#1a2a1a';msg.style.border='1px solid #3a3';msg.style.color='#6c6';"
        "msg.innerHTML='If that email belongs to a verified account,<br>a reset link has been sent.<br><br>Check your inbox.';"
        "e.target.style.display='none';"
        "}catch(err){"
        "btn.disabled=false;"
        "msg.style.background='#3a1a1a';msg.style.border='1px solid #c33';msg.style.color='#ff6b6b';"
        "msg.textContent='Error: '+err.message;"
        "}"
        "});"
        "</script></body></html>";

    HttpResponse *resp = http_response_new(200);
    http_response_set(resp, CONTENT_TYPE_HTML, html);
    return resp;
}

/*
 * POST /request-password-reset
 *
 * Creates a password reset token and sends a reset email.
 * Always returns 200 to prevent user enumeration.
 *
 * Request body: {"email":"user@example.com"}
 */
HttpResponse *request_password_reset_handler(const HttpRequest *req,
                                               const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *email = json_get_string(req->body, "email");
    if (!email) {
        return response_json_error(400, "email required");
    }

    char validation_error[256];
    if (validate_email(email, validation_error, sizeof(validation_error)) != 0) {
        free(email);
        return response_json_error(400, validation_error);
    }

    extern const config_t *g_config;

    char token[44];
    int result = user_create_password_reset_token(
        db, email,
        g_config->password_reset_token_ttl_seconds,
        http_request_get_client_ip(req, NULL),
        token);

    if (result == 0) {
        /* Token created — send email */
        char reset_url[512];
        if (strcmp(g_config->host, "localhost") == 0) {
            snprintf(reset_url, sizeof(reset_url),
                     "http://localhost:%d/reset-password?token=%s",
                     g_config->port, token);
        } else {
            snprintf(reset_url, sizeof(reset_url),
                     "https://%s/reset-password?token=%s",
                     g_config->host, token);
        }

        char body_text[1024];
        snprintf(body_text, sizeof(body_text),
                 "Click the link below to reset your password:\n\n%s\n\n"
                 "If you did not request this, you can safely ignore this email.",
                 reset_url);

        char body_html[2048];
        snprintf(body_html, sizeof(body_html),
                 "<p>Click the link below to reset your password:</p>"
                 "<p><a href=\"%s\">%s</a></p>"
                 "<p>If you did not request this, you can safely ignore this email.</p>",
                 reset_url, reset_url);

        email_send(g_config, email, "Password Reset", body_text, body_html);
    }

    free(email);

    /* Always return success to prevent enumeration */
    return response_json_ok(
        "{\"message\":\"If that email belongs to a verified account, "
        "a reset link has been sent. Check your inbox.\"}");
}

/*
 * GET /reset-password?token=...
 *
 * Public endpoint (no auth). Validates the token and renders
 * a "Set New Password" page with password input.
 */
HttpResponse *reset_password_page_handler(const HttpRequest *req,
                                            const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        HttpResponse *resp = http_response_new(500);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Internal server error</p></body></html>");
        return resp;
    }

    char *token = http_query_get_param(req->query_string, "token");
    if (!token) {
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Missing token</p></body></html>");
        return resp;
    }

    int rc = user_lookup_password_reset_token(db, token);

    if (rc != 0) {
        free(token);
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><head>"
            "<meta charset=\"UTF-8\">"
            "<title>Invalid Link</title>"
            "<link rel=\"stylesheet\" href=\"/css/base.css\">"
            "<style>.reset-container{width:100%%;max-width:400px;margin-top:40px;}"
            "h1{margin-bottom:24px;font-size:28px;}</style>"
            "</head><body><div class=\"reset-container\">"
            "<h1>Invalid Link</h1>"
            "<p>This password reset link is invalid or has expired.</p>"
            "<p style=\"margin-top:24px;\"><a href=\"/request-password-reset\">"
            "Request a new reset link</a></p>"
            "</div></body></html>");
        return resp;
    }

    char html[4096];
    snprintf(html, sizeof(html),
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Set New Password</title>"
        "<link rel=\"stylesheet\" href=\"/css/base.css\">"
        "<style>"
        ".reset-container{width:100%%;max-width:400px;margin-top:40px;}"
        "h1{margin-bottom:24px;font-size:28px;}"
        ".form-field{margin-bottom:24px;}"
        "label{display:block;margin-bottom:8px;font-size:14px;font-weight:500;}"
        "input[type=\"password\"]{width:100%%;padding:12px 16px;font-size:16px;"
        "border:1px solid #444;border-radius:4px;background:#1a1a1a;color:#fff;box-sizing:border-box;}"
        "input:focus{outline:none;border-color:#87ceeb;}"
        "button[type=\"submit\"]{width:100%%;padding:14px;font-size:16px;font-weight:600;"
        "background:#28a745;color:white;border:none;border-radius:4px;cursor:pointer;margin-top:8px;}"
        "button[type=\"submit\"]:hover{background:#218838;}"
        "#error{margin-top:12px;padding:12px;border-radius:4px;text-align:center;font-size:14px;"
        "background:#3a1a1a;border:1px solid #c33;color:#ff6b6b;display:none;}"
        "</style></head><body>"
        "<div class=\"reset-container\">"
        "<h1>Set New Password</h1>"
        "<form method=\"POST\" action=\"/reset-password\" id=\"resetForm\">"
        "<input type=\"hidden\" name=\"token\" value=\"%s\">"
        "<div class=\"form-field\">"
        "<label for=\"password\">New Password</label>"
        "<input type=\"password\" id=\"password\" name=\"password\" required>"
        "</div>"
        "<div class=\"form-field\">"
        "<label for=\"confirm\">Confirm Password</label>"
        "<input type=\"password\" id=\"confirm\" required>"
        "</div>"
        "<button type=\"submit\">Set New Password</button>"
        "</form>"
        "<div id=\"error\"></div>"
        "</div>"
        "<script>"
        "document.getElementById('resetForm').addEventListener('submit',function(e){"
        "var p=document.getElementById('password').value;"
        "var c=document.getElementById('confirm').value;"
        "if(p!==c){"
        "e.preventDefault();"
        "var el=document.getElementById('error');"
        "el.textContent='Passwords do not match.';"
        "el.style.display='block';"
        "}"
        "});"
        "</script></body></html>",
        token);

    free(token);

    HttpResponse *resp = http_response_new(200);
    http_response_set(resp, CONTENT_TYPE_HTML, html);
    return resp;
}

/*
 * POST /reset-password
 *
 * Public endpoint (no auth). Consumes the token and sets the new password.
 * Expects form-encoded body: token=...&password=...
 */
HttpResponse *reset_password_handler(const HttpRequest *req,
                                       const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        HttpResponse *resp = http_response_new(500);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Internal server error</p></body></html>");
        return resp;
    }

    char *token = NULL;
    char *password_enc = NULL;
    if (req->body) {
        token = http_query_get_param(req->body, "token");
        password_enc = http_query_get_param(req->body, "password");
    }

    if (!token || !password_enc) {
        free(token);
        free(password_enc);
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Missing token or password</p></body></html>");
        return resp;
    }

    /* URL-decode password (form-encoded) */
    char password[256];
    if (str_url_decode(password, sizeof(password), password_enc) < 0) {
        free(token);
        OPENSSL_cleanse(password_enc, strlen(password_enc));
        free(password_enc);
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><body><p>Invalid request</p></body></html>");
        return resp;
    }
    OPENSSL_cleanse(password_enc, strlen(password_enc));
    free(password_enc);

    int rc = user_consume_password_reset_token(db, token, password);
    OPENSSL_cleanse(password, strlen(password));
    free(token);

    if (rc != 0) {
        HttpResponse *resp = http_response_new(400);
        http_response_set(resp, CONTENT_TYPE_HTML,
            "<!DOCTYPE html><html><head>"
            "<meta charset=\"UTF-8\">"
            "<title>Reset Failed</title>"
            "<link rel=\"stylesheet\" href=\"/css/base.css\">"
            "<style>.reset-container{width:100%%;max-width:400px;margin-top:40px;}"
            "h1{margin-bottom:24px;font-size:28px;}</style>"
            "</head><body><div class=\"reset-container\">"
            "<h1>Reset Failed</h1>"
            "<p>This password reset link is invalid, expired, or has already been used.</p>"
            "<p style=\"margin-top:24px;\"><a href=\"/request-password-reset\">"
            "Request a new reset link</a></p>"
            "</div></body></html>");
        return resp;
    }

    HttpResponse *resp = http_response_new(200);
    http_response_set(resp, CONTENT_TYPE_HTML,
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Password Updated</title>"
        "<link rel=\"stylesheet\" href=\"/css/base.css\">"
        "<style>.reset-container{width:100%%;max-width:400px;margin-top:40px;}"
        "h1{margin-bottom:24px;font-size:28px;color:#28a745;}</style>"
        "</head><body><div class=\"reset-container\">"
        "<h1>Password Updated</h1>"
        "<p>Your password has been set successfully.</p>"
        "<p style=\"margin-top:24px;\"><a href=\"/login\">Log in</a></p>"
        "</div></body></html>");
    return resp;
}

#endif /* EMAIL_SUPPORT */

HttpResponse *logout_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Database connection failed");
    }

    /* Get session cookie */
    char *session_token = NULL;
    const char *cookie_header = http_request_get_header(req, "Cookie");
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, SESSION_COOKIE_NAME);
    }

    if (!session_token) {
        return response_json_error(401, "No session to logout");
    }

    /* Close session in database */
    int result = oauth_session_close(db, session_token);
    free(session_token);

    if (result != 0) {
        return response_json_error(500, "Failed to close session");
    }

    /* Build response with Set-Cookie header to clear cookie */
    HttpResponse *response = response_json_ok("{\"message\":\"Logged out successfully\"}");

    if (response) {
        char clear_cookie[256];
        snprintf(clear_cookie, sizeof(clear_cookie),
                 "%s=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
                 SESSION_COOKIE_NAME);
        http_response_set_header(response, "Set-Cookie", clear_cookie);
    }

    return response;
}
