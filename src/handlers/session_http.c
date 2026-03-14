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
        /* Authentication failed */
        return response_json_error(401, "Invalid username or password");
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
