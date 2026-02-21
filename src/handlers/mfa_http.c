/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers.h"
#include "handlers/mfa.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/oauth.h"
#include "db/queries/user.h"
#include "db/queries/mfa.h"
#include "crypto/totp.h"
#include "util/config.h"
#include "util/data.h"
#include "util/log.h"
#include "util/json.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================================
 * Auth Helper
 * ========================================================================== */

/*
 * require_session - Validate session cookie and populate session struct
 *
 * Returns NULL on success (session populated), or error response on failure.
 */
static HttpResponse *require_session(const HttpRequest *req, db_handle_t *db,
                                     oauth_session_info_t *out_session) {
    const char *cookie_header = http_request_get_header(req, "Cookie");
    char *session_token = NULL;
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, "session");
    }

    if (!session_token) {
        return response_json_error(401, "Authentication required");
    }

    if (oauth_session_get_by_token(db, session_token, out_session) != 0) {
        free(session_token);
        return response_json_error(401, "Invalid or expired session");
    }

    free(session_token);
    return NULL;
}

/* ============================================================================
 * POST /api/user/mfa/totp/setup
 * ========================================================================== */

/*
 * POST /api/user/mfa/totp/setup
 *
 * Begin TOTP enrollment. Generates secret and returns QR URL for scanning.
 * Must be confirmed with POST /api/user/mfa/totp/confirm.
 *
 * Request body:
 *   {"display_name":"My Phone"}
 *
 * Response (success):
 *   200 OK
 *   {"method_id":"<32hex>","secret":"<base32>","qr_url":"otpauth://..."}
 */
HttpResponse *mfa_totp_setup_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *display_name = json_get_string(req->body, "display_name");
    if (!display_name) {
        return response_json_error(400, "display_name required");
    }

    /* Get username for authenticator label */
    user_profile_t profile;
    if (user_get_profile(db, session.user_account_pin, &profile) != 0) {
        free(display_name);
        log_error("Failed to get user profile for MFA setup");
        return response_json_error(500, "Internal server error");
    }

    /* Use server host as issuer */
    extern const config_t *g_config;
    const char *issuer = (g_config && g_config->host) ? g_config->host : "auth";

    /* Set up TOTP method */
    unsigned char method_id[16];
    char secret[TOTP_SECRET_BASE32_LEN + 1];
    char qr_url[1024];

    int rc = mfa_totp_setup(db, session.user_account_pin,
                            display_name, issuer, profile.username,
                            method_id, secret, sizeof(secret),
                            qr_url, sizeof(qr_url));
    free(display_name);

    if (rc != 0) {
        return response_json_error(500, "Failed to set up MFA");
    }

    /* Convert method_id to hex */
    char method_id_hex[33];
    bytes_to_hex(method_id, 16, method_id_hex, sizeof(method_id_hex));

    /* Escape values for JSON */
    char secret_esc[128];
    char qr_url_esc[2048];
    json_escape(secret_esc, sizeof(secret_esc), secret);
    json_escape(qr_url_esc, sizeof(qr_url_esc), qr_url);

    /* Build response */
    char response_body[2560];
    snprintf(response_body, sizeof(response_body),
             "{\"method_id\":\"%s\",\"secret\":\"%s\",\"qr_url\":\"%s\"}",
             method_id_hex, secret_esc, qr_url_esc);

    return response_json_ok(response_body);
}

/* ============================================================================
 * POST /api/user/mfa/totp/confirm
 * ========================================================================== */

/*
 * POST /api/user/mfa/totp/confirm
 *
 * Confirm TOTP enrollment by verifying the first code from the authenticator.
 * Returns recovery codes if this is the user's first confirmed MFA method.
 *
 * Request body:
 *   {"method_id":"<32hex>","code":"123456"}
 *
 * Response (no recovery codes):
 *   200 OK
 *   {"message":"MFA method confirmed"}
 *
 * Response (first method - includes recovery codes):
 *   200 OK
 *   {"message":"MFA method confirmed","recovery_codes":["...","...",...]}
 *
 * Response (invalid code):
 *   400 Bad Request
 *   {"error":"Invalid TOTP code"}
 */
HttpResponse *mfa_totp_confirm_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *method_id_hex = json_get_string(req->body, "method_id");
    char *code = json_get_string(req->body, "code");

    if (!method_id_hex || !code) {
        free(method_id_hex);
        free(code);
        return response_json_error(400, "method_id and code required");
    }

    /* Decode method_id from hex */
    unsigned char method_id[16];
    if (hex_to_bytes(method_id_hex, method_id, 16) != 0) {
        free(method_id_hex);
        free(code);
        return response_json_error(400, "Invalid method_id");
    }

    free(method_id_hex);

    /* Confirm TOTP method */
    char **recovery_codes = NULL;
    int recovery_count = 0;

    int rc = mfa_totp_confirm(db, session.user_account_pin,
                              method_id, code,
                              &recovery_codes, &recovery_count);
    free(code);

    if (rc == 1) {
        return response_json_error(400, "Invalid TOTP code");
    }
    if (rc != 0) {
        return response_json_error(500, "Failed to confirm MFA method");
    }

    /* Build response */
    char response_body[1024];

    if (recovery_codes && recovery_count > 0) {
        /* Include recovery codes */
        int offset = snprintf(response_body, sizeof(response_body),
                              "{\"message\":\"MFA method confirmed\",\"recovery_codes\":[");

        for (int i = 0; i < recovery_count; i++) {
            offset += snprintf(response_body + offset, sizeof(response_body) - offset,
                               "%s\"%s\"", i > 0 ? "," : "", recovery_codes[i]);
        }

        snprintf(response_body + offset, sizeof(response_body) - offset, "]}");

        for (int i = 0; i < recovery_count; i++) free(recovery_codes[i]);
        free(recovery_codes);
    } else {
        snprintf(response_body, sizeof(response_body),
                 "{\"message\":\"MFA method confirmed\"}");
    }

    return response_json_ok(response_body);
}

/* ============================================================================
 * POST /api/user/mfa/verify
 * ========================================================================== */

/*
 * POST /api/user/mfa/verify
 *
 * Verify a TOTP code during authentication.
 *
 * Request body:
 *   {"method_id":"<32hex>","code":"123456"}
 *
 * Response:
 *   200 OK
 *   {"valid":true} or {"valid":false}
 */
HttpResponse *mfa_verify_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *method_id_hex = json_get_string(req->body, "method_id");
    char *code = json_get_string(req->body, "code");

    if (!method_id_hex || !code) {
        free(method_id_hex);
        free(code);
        return response_json_error(400, "method_id and code required");
    }

    /* Decode method_id from hex */
    unsigned char method_id[16];
    if (hex_to_bytes(method_id_hex, method_id, 16) != 0) {
        free(method_id_hex);
        free(code);
        return response_json_error(400, "Invalid method_id");
    }

    free(method_id_hex);

    /* Verify TOTP code */
    int result = mfa_verify(db, session.user_account_pin, method_id, code,
                            http_request_get_client_ip(req, NULL),
                            http_request_get_header(req, "User-Agent"));
    free(code);

    if (result == 1) {
        /* Mark session MFA as completed */
        const char *cookie_header = http_request_get_header(req, "Cookie");
        if (cookie_header) {
            char *session_token = http_cookie_get_value(cookie_header, "session");
            if (session_token) {
                oauth_session_set_mfa_completed(db, session_token);
                free(session_token);
            }
        }
        return response_json_ok("{\"valid\":true}");
    } else if (result == 0) {
        return response_json_ok("{\"valid\":false}");
    } else {
        return response_json_error(500, "MFA verification error");
    }
}

/* ============================================================================
 * POST /api/user/mfa/recover
 * ========================================================================== */

/*
 * POST /api/user/mfa/recover
 *
 * Verify a recovery code during authentication.
 *
 * Request body:
 *   {"recovery_code":"<20hex>"}
 *
 * Response:
 *   200 OK
 *   {"valid":true} or {"valid":false}
 */
HttpResponse *mfa_recover_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    char *recovery_code = json_get_string(req->body, "recovery_code");
    if (!recovery_code) {
        return response_json_error(400, "recovery_code required");
    }

    /* Verify recovery code */
    int result = mfa_recover(db, session.user_account_pin, recovery_code);
    free(recovery_code);

    if (result == 1) {
        /* Mark session MFA as completed */
        const char *cookie_header = http_request_get_header(req, "Cookie");
        if (cookie_header) {
            char *session_token = http_cookie_get_value(cookie_header, "session");
            if (session_token) {
                oauth_session_set_mfa_completed(db, session_token);
                free(session_token);
            }
        }
        return response_json_ok("{\"valid\":true}");
    } else if (result == 0) {
        return response_json_ok("{\"valid\":false}");
    } else {
        return response_json_error(500, "Recovery code verification error");
    }
}

/* ============================================================================
 * GET /api/user/mfa/methods
 * ========================================================================== */

/*
 * GET /api/user/mfa/methods
 *
 * List MFA methods for the authenticated user.
 *
 * Response:
 *   200 OK
 *   {"methods":[{"id":"<32hex>","type":"TOTP","display_name":"My Phone",
 *                "is_confirmed":true,"confirmed_at":"2024-01-01T00:00:00Z"},...]}
 */
HttpResponse *mfa_list_methods_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* List all methods (confirmed and unconfirmed) */
    mfa_method_t *methods = NULL;
    int count = 0;
    if (mfa_method_list(db, session.user_account_pin, 0, &methods, &count) != 0) {
        return response_json_error(500, "Failed to list MFA methods");
    }

    /* Build JSON response */
    char response_body[4096];
    int offset = snprintf(response_body, sizeof(response_body), "{\"methods\":[");

    for (int i = 0; i < count; i++) {
        char id_hex[33];
        bytes_to_hex(methods[i].id, 16, id_hex, sizeof(id_hex));

        char type_esc[32];
        char name_esc[512];
        json_escape(type_esc, sizeof(type_esc), methods[i].mfa_method);
        json_escape(name_esc, sizeof(name_esc), methods[i].display_name);

        /* Build confirmed_at as quoted string or null */
        char confirmed_at_json[68];
        if (methods[i].confirmed_at[0] != '\0') {
            char confirmed_at_esc[64];
            json_escape(confirmed_at_esc, sizeof(confirmed_at_esc), methods[i].confirmed_at);
            snprintf(confirmed_at_json, sizeof(confirmed_at_json), "\"%s\"", confirmed_at_esc);
        } else {
            strcpy(confirmed_at_json, "null");
        }

        offset += snprintf(response_body + offset, sizeof(response_body) - offset,
                           "%s{\"id\":\"%s\",\"type\":\"%s\",\"display_name\":\"%s\","
                           "\"is_confirmed\":%s,\"confirmed_at\":%s}",
                           i > 0 ? "," : "",
                           id_hex, type_esc, name_esc,
                           methods[i].is_confirmed ? "true" : "false",
                           confirmed_at_json);
    }

    snprintf(response_body + offset, sizeof(response_body) - offset, "]}");

    free(methods);

    return response_json_ok(response_body);
}

/* ============================================================================
 * DELETE /api/user/mfa/methods
 * ========================================================================== */

/*
 * DELETE /api/user/mfa/methods?id=<method_id>
 *
 * Delete an MFA method.
 *
 * Response:
 *   200 OK
 *   {"message":"MFA method deleted"}
 */
HttpResponse *mfa_delete_method_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Get method ID from query string */
    if (!req->query_string) {
        return response_json_error(400, "id required");
    }

    char *id_hex = http_query_get_param(req->query_string, "id");
    if (!id_hex) {
        return response_json_error(400, "id required");
    }

    unsigned char method_id[16];
    if (hex_to_bytes(id_hex, method_id, 16) != 0) {
        free(id_hex);
        return response_json_error(400, "Invalid method id");
    }
    free(id_hex);

    /* Delete method */
    if (mfa_delete_method(db, session.user_account_pin, method_id) != 0) {
        return response_json_error(500, "Failed to delete MFA method");
    }

    return response_json_ok("{\"message\":\"MFA method deleted\"}");
}

/* ============================================================================
 * POST /api/user/mfa/recovery-codes/regenerate
 * ========================================================================== */

/*
 * POST /api/user/mfa/recovery-codes/regenerate
 *
 * Regenerate recovery codes. Revokes existing set.
 * Requires at least one confirmed MFA method.
 *
 * Response:
 *   200 OK
 *   {"recovery_codes":["...","...",...]}
 */
HttpResponse *mfa_regenerate_recovery_codes_handler(const HttpRequest *req,
                                                    const RouteParams *params) {
    (void)params;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Regenerate recovery codes */
    char **codes = NULL;
    int count = 0;

    if (mfa_regenerate_recovery_codes(db, session.user_account_pin, &codes, &count) != 0) {
        return response_json_error(500, "Failed to regenerate recovery codes");
    }

    /* Build response */
    char response_body[1024];
    int offset = snprintf(response_body, sizeof(response_body), "{\"recovery_codes\":[");

    for (int i = 0; i < count; i++) {
        offset += snprintf(response_body + offset, sizeof(response_body) - offset,
                           "%s\"%s\"", i > 0 ? "," : "", codes[i]);
    }

    snprintf(response_body + offset, sizeof(response_body) - offset, "]}");

    for (int i = 0; i < count; i++) free(codes[i]);
    free(codes);

    return response_json_ok(response_body);
}

/* ============================================================================
 * POST /api/user/mfa/require
 * ========================================================================== */

/*
 * POST /api/user/mfa/require
 *
 * Set user MFA preference — whether to enforce MFA on this user or not.
 *
 * Request body:
 *   {"enabled":true} or {"enabled":false}
 *
 * Response:
 *   200 OK
 *   {"message":"MFA requirement updated"}
 */
HttpResponse *mfa_set_require_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/json");
    if (ct_err) return ct_err;

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Validate session */
    oauth_session_info_t session;
    HttpResponse *auth_err = require_session(req, db, &session);
    if (auth_err) return auth_err;

    /* Parse JSON body */
    if (!req->body) {
        return response_json_error(400, "Request body required");
    }

    /* Parse "enabled" field from JSON */
    const char *body = req->body;
    int enabled = 0;

    /* Simple JSON parse: look for "enabled":true or "enabled":false */
    const char *enabled_pos = strstr(body, "\"enabled\"");
    if (enabled_pos) {
        const char *colon = strchr(enabled_pos, ':');
        if (colon) {
            while (*colon && (*colon == ':' || *colon == ' ')) colon++;
            if (strncmp(colon, "true", 4) == 0) {
                enabled = 1;
            } else if (strncmp(colon, "false", 5) == 0) {
                enabled = 0;
            } else {
                return response_json_error(400, "enabled must be true or false");
            }
        } else {
            return response_json_error(400, "enabled field malformed");
        }
    } else {
        return response_json_error(400, "enabled field required");
    }

    /* Validate: can only enable if user has confirmed methods */
    if (enabled) {
        int confirmed_count = 0;
        if (mfa_method_count_confirmed(db, session.user_account_pin, &confirmed_count) != 0) {
            return response_json_error(500, "Failed to check MFA methods");
        }
        if (confirmed_count == 0) {
            return response_json_error(400, "Cannot require MFA without any confirmed methods");
        }
    }

    /* Update require_mfa flag */
    if (mfa_update_require_mfa_flag(db, session.user_account_pin, enabled) != 0) {
        return response_json_error(500, "Failed to update MFA requirement");
    }

    return response_json_ok("{\"message\":\"MFA requirement updated\"}");
}
