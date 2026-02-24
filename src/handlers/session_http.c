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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Default session TTL: 7 days */
#define DEFAULT_SESSION_TTL_SECONDS (7 * 24 * 60 * 60)

/* Cookie name for session token */
#define SESSION_COOKIE_NAME "session"

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
 *   {"message":"Login successful","user_pin":123}
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
    char response_body[4096];
    if (profile.require_mfa && mfa_count > 0) {
        int off = snprintf(response_body, sizeof(response_body),
                           "{\"message\":\"Login successful\","
                           "\"mfa_required\":true,\"mfa_methods\":[");
        for (int i = 0; i < mfa_count; i++) {
            char id_hex[33];
            bytes_to_hex(mfa_methods[i].id, 16, id_hex, sizeof(id_hex));
            char type_esc[32];
            char name_esc[256];
            json_escape(type_esc, sizeof(type_esc), mfa_methods[i].mfa_method);
            json_escape(name_esc, sizeof(name_esc), mfa_methods[i].display_name);
            off += snprintf(response_body + off, sizeof(response_body) - off,
                            "%s{\"id\":\"%s\",\"type\":\"%s\",\"display_name\":\"%s\"}",
                            i > 0 ? "," : "", id_hex, type_esc, name_esc);
        }
        snprintf(response_body + off, sizeof(response_body) - off, "]}");
    } else {
        snprintf(response_body, sizeof(response_body), "{\"message\":\"Login successful\"}");
    }
    free(mfa_methods);

    /* Create response */
    HttpResponse *resp = http_response_new(200);
    if (!resp) {
        free(session_token);
        log_error("Failed to create HTTP response");
        return response_json_error(500, "Internal server error");
    }

    http_response_set(resp, CONTENT_TYPE_JSON, response_body);
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
    char response_body[8192];
    int offset = snprintf(response_body, sizeof(response_body), "{\"setups\":[");

    for (int i = 0; i < count; i++) {
        /* Convert client_id to hex */
        char client_id_hex[33];
        for (int j = 0; j < 16; j++) {
            snprintf(client_id_hex + j * 2, 3, "%02x", setups[i].client_id[j]);
        }

        /* Escape strings for JSON */
        char org_code_esc[128], org_display_esc[512], client_code_esc[128];
        char client_display_esc[512], rs_address_esc[512];

        json_escape(org_code_esc, sizeof(org_code_esc), setups[i].org_code_name);
        json_escape(org_display_esc, sizeof(org_display_esc), setups[i].org_display_name);
        json_escape(client_code_esc, sizeof(client_code_esc), setups[i].client_code_name);
        json_escape(client_display_esc, sizeof(client_display_esc), setups[i].client_display_name);
        json_escape(rs_address_esc, sizeof(rs_address_esc), setups[i].resource_server_address);

        offset += snprintf(response_body + offset, sizeof(response_body) - offset,
                           "%s{\"org_code_name\":\"%s\",\"org_display_name\":\"%s\","
                           "\"client_id\":\"%s\",\"client_code_name\":\"%s\","
                           "\"client_display_name\":\"%s\",\"resource_server_address\":\"%s\"}",
                           i > 0 ? "," : "",
                           org_code_esc, org_display_esc, client_id_hex,
                           client_code_esc, client_display_esc, rs_address_esc);
    }

    snprintf(response_body + offset, sizeof(response_body) - offset, "]}");

    free(setups);

    return response_json_ok(response_body);
}

/*
 * GET /api/user/profile
 *
 * Returns profile information for the authenticated user.
 * Requires valid session cookie.
 */
HttpResponse *profile_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

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

    /* Get user profile */
    user_profile_t profile;
    if (user_get_profile(db, session.user_account_pin, &profile) != 0) {
        return response_json_error(500, "Failed to get user profile");
    }

    /* Convert user_id to hex */
    char user_id_hex[33];
    for (int i = 0; i < 16; i++) {
        snprintf(user_id_hex + i * 2, 3, "%02x", profile.user_id[i]);
    }

    /* Escape username for JSON */
    char username_esc[512];
    json_escape(username_esc, sizeof(username_esc), profile.username);

    /* Build JSON response */
    char response_body[1024];
    snprintf(response_body, sizeof(response_body),
             "{\"user_id\":\"%s\",\"username\":\"%s\","
             "\"has_mfa\":%s,\"require_mfa\":%s}",
             user_id_hex, username_esc,
             profile.has_mfa ? "true" : "false",
             profile.require_mfa ? "true" : "false");

    return response_json_ok(response_body);
}

/*
 * GET /api/user/emails
 *
 * Returns email addresses for the authenticated user.
 * Requires valid session cookie.
 */
HttpResponse *emails_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

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
    char response_body[4096];
    int json_offset = snprintf(response_body, sizeof(response_body),
                               "{\"emails\":[");

    for (int i = 0; i < count; i++) {
        /* Escape email address for JSON */
        char email_esc[512];
        json_escape(email_esc, sizeof(email_esc), emails[i].email_address);

        json_offset += snprintf(response_body + json_offset, sizeof(response_body) - json_offset,
                                "%s{\"email_address\":\"%s\",\"is_primary\":%s,\"is_verified\":%s}",
                                i > 0 ? "," : "",
                                email_esc,
                                emails[i].is_primary ? "true" : "false",
                                emails[i].is_verified ? "true" : "false");
    }

    snprintf(response_body + json_offset, sizeof(response_body) - json_offset,
             "],\"pagination\":{\"limit\":%d,\"offset\":%d,\"count\":%d,\"total\":%d}}",
             limit, offset, count, total_count);

    free(emails);

    return response_json_ok(response_body);
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

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

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

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *current_password = json_get_string(req->body, "current_password");
    char *new_password = json_get_string(req->body, "new_password");

    if (!current_password || !new_password) {
        free(current_password);
        free(new_password);
        return response_json_error(400, "current_password and new_password required");
    }

    /* Change password */
    int result = user_change_password(db, session.user_account_pin, session.user_account_id,
                                      current_password, new_password);

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

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

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

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *new_username = json_get_string(req->body, "new_username");
    if (!new_username) {
        return response_json_error(400, "new_username required");
    }

    /* Change username */
    int result = user_change_username(db, session.user_account_pin, session.user_account_id,
                                      new_username);

    free(new_username);

    if (result == 1) {
        return response_json_ok("{\"message\":\"Username changed successfully\"}");
    } else if (result == 0) {
        return response_json_error(409, "Username already taken");
    } else {
        return response_json_error(400, "Invalid username");
    }
}

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
