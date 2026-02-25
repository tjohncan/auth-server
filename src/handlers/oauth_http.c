/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers.h"
#include "handlers/oauth.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/oauth.h"
#include "db/queries/client.h"
#include "db/queries/resource_server.h"
#include "db/queries/user.h"
#include "db/queries/mfa.h"
#include "crypto/signing_keys.h"
#include "crypto/jwt.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/* ============================================================================
 * JSON/Form Parsing Helpers
 * ========================================================================== */

/* Parse form-urlencoded parameter (application/x-www-form-urlencoded)
 * OAuth2-specific: automatically URL-decodes values.
 * Kept local since form parsing is only needed for /token endpoint. */
static char *form_get_param(const char *body, const char *key) {
    if (!body || !key) return NULL;

    char search[128];
    snprintf(search, sizeof(search), "%s=", key);
    size_t search_len = strlen(search);

    /* Find exact parameter name match (not substring of another param) */
    const char *p = body;
    const char *param = NULL;

    while ((p = strstr(p, search)) != NULL) {
        /* Verify we're at start of body or after '&' separator */
        if (p == body || *(p - 1) == '&') {
            param = p;
            break;
        }
        p += search_len;
    }

    if (!param) return NULL;

    const char *value_start = param + search_len;
    const char *value_end = strchr(value_start, '&');

    size_t len;
    if (value_end) {
        len = value_end - value_start;
    } else {
        len = strlen(value_start);
    }

    char *value_encoded = malloc(len + 1);
    if (!value_encoded) return NULL;

    memcpy(value_encoded, value_start, len);
    value_encoded[len] = '\0';

    /* URL decode using safe utility function */
    char *value = malloc(len + 1);  /* Decoded is always <= original */
    if (!value) {
        free(value_encoded);
        return NULL;
    }

    if (str_url_decode(value, len + 1, value_encoded) < 0) {
        free(value_encoded);
        free(value);
        return NULL;
    }

    free(value_encoded);
    return value;
}

/* ============================================================================
 * Token Endpoint
 * ========================================================================== */

/*
 * POST /token
 *
 * OAuth2 token endpoint (RFC 6749 Section 3.2)
 * Supports grant types: authorization_code, refresh_token
 *
 * Request (authorization_code):
 *   Content-Type: application/x-www-form-urlencoded
 *   grant_type=authorization_code&code=<code>&redirect_uri=<uri>&client_id=<id>&code_verifier=<verifier>
 *
 * Request (refresh_token):
 *   Content-Type: application/x-www-form-urlencoded
 *   grant_type=refresh_token&refresh_token=<token>&client_id=<id>&scope=<scope>
 *
 * Response (success):
 *   200 OK
 *   {"access_token":"...","token_type":"Bearer","expires_in":3600,"refresh_token":"...","scope":"..."}
 *
 * Response (error):
 *   400 Bad Request / 401 Unauthorized
 *   {"error":"invalid_grant","error_description":"..."}
 */
HttpResponse *token_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/x-www-form-urlencoded");
    if (ct_err) return ct_err;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    const char *body = req->body;
    if (!body) {
        return response_json_error(400, "Request body required");
    }

    /* Parse grant_type */
    char *grant_type = form_get_param(body, "grant_type");
    if (!grant_type) {
        return response_json_error(400, "grant_type required");
    }

    /* Parse client_id */
    char *client_id_str = form_get_param(body, "client_id");
    if (!client_id_str) {
        free(grant_type);
        return response_json_error(400, "client_id required");
    }

    /* Decode client_id from hex */
    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, sizeof(client_id)) != 0) {
        free(grant_type);
        free(client_id_str);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    HttpResponse *resp = NULL;

    if (strcmp(grant_type, "authorization_code") == 0) {
        /* Authorization code grant */
        char *code = form_get_param(body, "code");
        char *redirect_uri = form_get_param(body, "redirect_uri");
        char *code_verifier = form_get_param(body, "code_verifier");
        char *resource = form_get_param(body, "resource");  /* RFC 8707 */

        if (!code || !redirect_uri) {
            free(grant_type);
            free(code);
            free(redirect_uri);
            free(code_verifier);
            free(resource);
            return response_json_error(400, "code and redirect_uri required");
        }

        oauth_token_response_t token_resp;
        int rc = oauth_exchange_authorization_code(db, client_id, code, redirect_uri,
                                                    code_verifier, resource, &token_resp);

        free(code);
        free(redirect_uri);
        free(code_verifier);
        free(resource);

        if (rc == 1) {
            /* Replay attack detected - token chain revoked automatically */
            free(grant_type);
            return response_json_error(400, "Authorization code has already been used");
        } else if (rc != 0) {
            free(grant_type);
            return response_json_error(400, "Invalid authorization code");
        }

        /* Build JSON response */
        char json[2048];
        int json_len = snprintf(json, sizeof(json),
            "{\"access_token\":\"%s\",\"token_type\":\"%s\",\"expires_in\":%d",
            token_resp.access_token, token_resp.token_type, token_resp.expires_in);

        if (token_resp.refresh_token) {
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"refresh_token\":\"%s\"", token_resp.refresh_token);
        }

        if (token_resp.scope) {
            char escaped_scope[512];
            json_escape(escaped_scope, sizeof(escaped_scope), token_resp.scope);
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"scope\":\"%s\"", escaped_scope);
        }

        json_len += snprintf(json + json_len, sizeof(json) - json_len, "}");

        if (json_len >= (int)sizeof(json)) {
            oauth_token_response_free(&token_resp);
            free(grant_type);
            return response_json_error(500, "Internal server error");
        }

        resp = response_json_ok(json);
        oauth_token_response_free(&token_resp);

    } else if (strcmp(grant_type, "refresh_token") == 0) {
        /* Refresh token grant */
        char *refresh_token = form_get_param(body, "refresh_token");
        char *scope = form_get_param(body, "scope");
        char *resource = form_get_param(body, "resource");  /* RFC 8707 */

        if (!refresh_token) {
            free(grant_type);
            free(refresh_token);
            free(scope);
            free(resource);
            return response_json_error(400, "refresh_token required");
        }

        oauth_token_response_t token_resp;
        int rc = oauth_refresh_access_token(db, client_id, refresh_token, scope, resource, &token_resp);

        free(refresh_token);
        free(scope);
        free(resource);

        if (rc == 1) {
            /* Replay attack detected - token chain revoked automatically */
            free(grant_type);
            return response_json_error(400, "Refresh token has already been used");
        } else if (rc != 0) {
            free(grant_type);
            return response_json_error(400, "Invalid refresh token");
        }

        /* Build JSON response */
        char json[2048];
        int json_len = snprintf(json, sizeof(json),
            "{\"access_token\":\"%s\",\"token_type\":\"%s\",\"expires_in\":%d",
            token_resp.access_token, token_resp.token_type, token_resp.expires_in);

        if (token_resp.refresh_token) {
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"refresh_token\":\"%s\"", token_resp.refresh_token);
        }

        if (token_resp.scope) {
            char escaped_scope[512];
            json_escape(escaped_scope, sizeof(escaped_scope), token_resp.scope);
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"scope\":\"%s\"", escaped_scope);
        }

        json_len += snprintf(json + json_len, sizeof(json) - json_len, "}");

        if (json_len >= (int)sizeof(json)) {
            oauth_token_response_free(&token_resp);
            free(grant_type);
            return response_json_error(500, "Internal server error");
        }

        resp = response_json_ok(json);
        oauth_token_response_free(&token_resp);

    } else if (strcmp(grant_type, "client_credentials") == 0) {
        /* Client credentials grant (RFC 6749 Section 4.4) */
        char *client_key_id_str = form_get_param(body, "client_key_id");
        char *client_secret = form_get_param(body, "client_secret");
        char *scope = form_get_param(body, "scope");
        char *resource = form_get_param(body, "resource");  /* RFC 8707 */

        if (!client_key_id_str || !client_secret) {
            free(grant_type);
            free(client_key_id_str);
            free(client_secret);
            free(scope);
            free(resource);
            return response_json_error(400, "client_key_id and client_secret required");
        }

        /* Parse client_key_id UUID */
        unsigned char client_key_id[16];
        if (hex_to_bytes(client_key_id_str, client_key_id, 16) != 0) {
            free(grant_type);
            free(client_key_id_str);
            free(client_secret);
            free(scope);
            free(resource);
            return response_json_error(400, "Invalid client_key_id format");
        }
        free(client_key_id_str);

        /* Get source IP and user agent for audit logging */
        const char *source_ip = http_request_get_client_ip(req, NULL);
        const char *user_agent = http_request_get_header(req, "User-Agent");

        oauth_token_response_t token_resp;
        int rc = oauth_client_credentials(db, client_id, client_key_id, client_secret,
                                           scope, resource, source_ip, user_agent,
                                           &token_resp);

        free(client_secret);
        free(scope);
        free(resource);

        if (rc != 0) {
            free(grant_type);
            return response_json_error(400, "Invalid client credentials");
        }

        /* Build JSON response */
        char json[2048];
        int json_len = snprintf(json, sizeof(json),
            "{\"access_token\":\"%s\",\"token_type\":\"%s\",\"expires_in\":%d",
            token_resp.access_token, token_resp.token_type, token_resp.expires_in);

        if (token_resp.scope) {
            char escaped_scope[512];
            json_escape(escaped_scope, sizeof(escaped_scope), token_resp.scope);
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"scope\":\"%s\"", escaped_scope);
        }

        json_len += snprintf(json + json_len, sizeof(json) - json_len, "}");

        if (json_len >= (int)sizeof(json)) {
            oauth_token_response_free(&token_resp);
            free(grant_type);
            return response_json_error(500, "Internal server error");
        }

        resp = response_json_ok(json);
        oauth_token_response_free(&token_resp);

    } else {
        free(grant_type);
        return response_json_error(400, "Unsupported grant_type");
    }

    free(grant_type);
    return resp;
}

/* ============================================================================
 * Authorization Endpoint
 * ========================================================================== */

/*
 * Build OAuth2 error redirect URI (RFC 6749 Section 4.1.2.1)
 *
 * Creates redirect URI with error query parameters.
 *
 * Parameters:
 *   redirect_uri - Base redirect URI
 *   error - OAuth2 error code
 *   description - Human-readable error description
 *   state - State parameter (optional, can be NULL)
 *   out_location - Output buffer for redirect URI
 *   location_len - Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 */
static int build_error_redirect(const char *redirect_uri,
                                  const char *error,
                                  const char *description,
                                  const char *state,
                                  char *out_location,
                                  size_t location_len) {
    if (!redirect_uri || !error || !out_location) {
        return -1;
    }

    int offset = snprintf(out_location, location_len, "%s", redirect_uri);
    if (offset < 0 || (size_t)offset >= location_len) {
        return -1;
    }

    /* Check if redirect_uri already has query params */
    char separator = strchr(out_location, '?') ? '&' : '?';

    /* Add error */
    offset += snprintf(out_location + offset, location_len - offset,
                       "%cerror=%s", separator, error);

    if (offset < 0 || (size_t)offset >= location_len) {
        return -1;
    }

    /* Add error_description if provided */
    if (description) {
        /* Percent-encode description per RFC 3986 */
        char encoded_desc[768];
        const char *src = description;
        char *dst = encoded_desc;
        char *dst_end = encoded_desc + sizeof(encoded_desc) - 4;
        while (*src && dst < dst_end) {
            unsigned char c = (unsigned char)*src;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                *dst++ = c;
            } else {
                snprintf(dst, 4, "%%%02X", c);
                dst += 3;
            }
            src++;
        }
        *dst = '\0';

        offset += snprintf(out_location + offset, location_len - offset,
                           "&error_description=%s", encoded_desc);

        if (offset < 0 || (size_t)offset >= location_len) {
            return -1;
        }
    }

    /* Add state if provided */
    if (state) {
        offset += snprintf(out_location + offset, location_len - offset,
                           "&state=%s", state);

        if (offset < 0 || (size_t)offset >= location_len) {
            return -1;
        }
    }

    return 0;
}

/* ============================================================================
 * Authorization Endpoint
 * ========================================================================== */

/*
 * GET /authorize
 *
 * OAuth2 authorization endpoint (RFC 6749 Section 3.1)
 * Initiates authorization code flow.
 *
 * Request:
 *   GET /authorize?response_type=code&client_id=<uuid>&redirect_uri=<uri>&scope=<scope>&state=<state>&code_challenge=<challenge>&code_challenge_method=S256
 *   Cookie: session=<token>
 *
 * Response (success):
 *   302 Found
 *   Location: <redirect_uri>?code=<authorization_code>&state=<state>
 *
 * Response (not authenticated):
 *   302 Found
 *   Location: /login?redirect=<current_url>
 *
 * Response (error):
 *   400 Bad Request
 *   {"error":"invalid_request","error_description":"..."}
 */
HttpResponse *authorize_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    const char *query_string = req->query_string;
    if (!query_string) {
        return response_json_error(400, "Query parameters required");
    }

    /* Parse required parameters (encoded) */
    char *response_type_enc = http_query_get_param(query_string, "response_type");
    char *client_id_enc = http_query_get_param(query_string, "client_id");
    char *redirect_uri_enc = http_query_get_param(query_string, "redirect_uri");
    char *state_enc = http_query_get_param(query_string, "state");

    /* Per RFC 6749: If redirect_uri is missing or invalid, return error directly (don't redirect) */
    if (!response_type_enc || !client_id_enc || !redirect_uri_enc) {
        free(response_type_enc);
        free(client_id_enc);
        free(redirect_uri_enc);
        free(state_enc);
        return response_json_error(400, "response_type, client_id, and redirect_uri required");
    }

    /* URL decode required parameters */
    char response_type[64];
    char client_id_str[128];
    char redirect_uri[512];
    char state[256];

    if (str_url_decode(response_type, sizeof(response_type), response_type_enc) < 0 ||
        str_url_decode(client_id_str, sizeof(client_id_str), client_id_enc) < 0 ||
        str_url_decode(redirect_uri, sizeof(redirect_uri), redirect_uri_enc) < 0) {
        free(response_type_enc);
        free(client_id_enc);
        free(redirect_uri_enc);
        free(state_enc);
        return response_json_error(400, "Invalid URL encoding in parameters");
    }

    if (state_enc) {
        if (str_url_decode(state, sizeof(state), state_enc) < 0) {
            free(response_type_enc);
            free(client_id_enc);
            free(redirect_uri_enc);
            free(state_enc);
            return response_json_error(400, "Invalid URL encoding in state parameter");
        }
    } else {
        state[0] = '\0';
    }

    free(response_type_enc);
    free(client_id_enc);
    free(redirect_uri_enc);
    free(state_enc);

    /* Validate response_type early (before we trust redirect_uri) */
    if (strcmp(response_type, "code") != 0) {
        return response_json_error(400, "Only response_type=code is supported");
    }

    /* Parse client_id UUID (before we trust redirect_uri) */
    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        return response_json_error(400, "Invalid client_id format");
    }

    /* Parse optional parameters (encoded) */
    char *scope_enc = http_query_get_param(query_string, "scope");
    char *code_challenge_enc = http_query_get_param(query_string, "code_challenge");
    char *code_challenge_method_enc = http_query_get_param(query_string, "code_challenge_method");

    /* URL decode optional parameters */
    char scope[256];
    char code_challenge[128];
    char code_challenge_method[16];

    if (scope_enc) {
        if (str_url_decode(scope, sizeof(scope), scope_enc) < 0) {
            free(scope_enc);
            free(code_challenge_enc);
            free(code_challenge_method_enc);
            return response_json_error(400, "Invalid URL encoding in scope parameter");
        }
        free(scope_enc);
    } else {
        scope[0] = '\0';
    }

    if (code_challenge_enc) {
        if (str_url_decode(code_challenge, sizeof(code_challenge), code_challenge_enc) < 0) {
            free(code_challenge_enc);
            free(code_challenge_method_enc);
            return response_json_error(400, "Invalid URL encoding in code_challenge parameter");
        }
        free(code_challenge_enc);
    } else {
        code_challenge[0] = '\0';
    }

    if (code_challenge_method_enc) {
        if (str_url_decode(code_challenge_method, sizeof(code_challenge_method), code_challenge_method_enc) < 0) {
            free(code_challenge_method_enc);
            return response_json_error(400, "Invalid URL encoding in code_challenge_method parameter");
        }
        free(code_challenge_method_enc);
    } else {
        code_challenge_method[0] = '\0';
    }

    /* Parse session cookie */
    const char *cookie_header = http_request_get_header(req, "Cookie");
    char *session_token = NULL;
    if (cookie_header) {
        session_token = http_cookie_get_value(cookie_header, "session");
    }

    /* Call business logic (this validates redirect_uri is registered) */
    oauth_authorize_response_t auth_response;
    int rc = oauth_authorize(db, client_id,
                             redirect_uri[0] ? redirect_uri : NULL,
                             scope[0] ? scope : NULL,
                             code_challenge[0] ? code_challenge : NULL,
                             code_challenge_method[0] ? code_challenge_method : NULL,
                             state[0] ? state : NULL,
                             session_token,
                             &auth_response);

    free(session_token);

    /* After this point, redirect_uri is validated - use OAuth2 error redirects */

    if (rc == -2) {
        /* Not authenticated - redirect to login page */
        char current_url[2048];
        char encoded_url[4096];
        char login_location[4112];  /* encoded_url + "/login?return=" prefix */

        /* Build current request URL (path + query string) */
        snprintf(current_url, sizeof(current_url), "%s%s%s",
                 req->path,
                 req->query_string ? "?" : "",
                 req->query_string ? req->query_string : "");

        /* URL-encode the return parameter */
        if (str_url_encode(encoded_url, sizeof(encoded_url), current_url) < 0) {
            log_error("Failed to URL-encode return parameter");
            return response_json_error(500, "Internal server error");
        }

        /* Build login redirect with return parameter */
        snprintf(login_location, sizeof(login_location),
                 "/login?return=%s", encoded_url);

        HttpResponse *resp = http_response_new(302);
        if (!resp) {
            return response_json_error(500, "Internal server error");
        }

        http_response_set_header(resp, "Location", login_location);
        http_response_set_body_str(resp, "");
        log_info("Authentication required, redirecting to login");
        return resp;
    }

    if (rc == -3) {
        /* MFA required - check if user has enrolled MFA methods */
        int mfa_count = 0;
        mfa_method_count_confirmed(db, auth_response.user_account_pin, &mfa_count);

        if (mfa_count > 0) {
            /* User has MFA methods - redirect to login page MFA challenge */
            char current_url[2048];
            char encoded_url[4096];
            char login_location[4128];  /* encoded_url + "/login?mfa_step=1&return=" prefix */

            snprintf(current_url, sizeof(current_url), "%s%s%s",
                     req->path,
                     req->query_string ? "?" : "",
                     req->query_string ? req->query_string : "");

            if (str_url_encode(encoded_url, sizeof(encoded_url), current_url) < 0) {
                log_error("Failed to URL-encode return parameter");
                return response_json_error(500, "Internal server error");
            }

            snprintf(login_location, sizeof(login_location),
                     "/login?mfa_step=1&return=%s", encoded_url);

            HttpResponse *resp = http_response_new(302);
            if (!resp) {
                return response_json_error(500, "Internal server error");
            }

            http_response_set_header(resp, "Location", login_location);
            http_response_set_body_str(resp, "");
            log_info("MFA required, redirecting to MFA challenge");
            return resp;
        }

        /* No MFA methods enrolled - redirect with access_denied */
        char location[2048];
        if (build_error_redirect(redirect_uri, "access_denied",
                                  "MFA required but no methods enrolled",
                                  state[0] ? state : NULL,
                                  location, sizeof(location)) != 0) {
            return response_json_error(500, "Internal server error");
        }

        HttpResponse *resp = http_response_new(302);
        if (!resp) {
            return response_json_error(500, "Internal server error");
        }

        http_response_set_header(resp, "Location", location);
        http_response_set_body_str(resp, "");
        return resp;
    }

    if (rc == -4) {
        /* Client not found or redirect_uri not registered — do NOT redirect
         * (RFC 6749 Section 4.1.2.1: must not redirect to unverified URI) */
        return response_json_error(400, "Invalid client_id or redirect_uri");
    }

    if (rc != 0) {
        /* Validation error - redirect with invalid_request */
        char location[2048];
        if (build_error_redirect(redirect_uri, "invalid_request",
                                  "Invalid authorization request", state[0] ? state : NULL,
                                  location, sizeof(location)) != 0) {
            return response_json_error(500, "Internal server error");
        }

        HttpResponse *resp = http_response_new(302);
        if (!resp) {
            return response_json_error(500, "Internal server error");
        }

        http_response_set_header(resp, "Location", location);
        http_response_set_body_str(resp, "");
        return resp;
    }

    /* Build redirect URI with code and state (URL-encoded) */
    char encoded_code[2048];
    str_url_encode(encoded_code, sizeof(encoded_code), auth_response.code);

    char location[4096];
    int offset = snprintf(location, sizeof(location), "%s", redirect_uri);

    /* Check if redirect_uri already has query params */
    char separator = strchr(location, '?') ? '&' : '?';

    offset += snprintf(location + offset, sizeof(location) - offset,
                       "%ccode=%s", separator, encoded_code);

    if (auth_response.state) {
        char encoded_state[512];
        str_url_encode(encoded_state, sizeof(encoded_state), auth_response.state);
        offset += snprintf(location + offset, sizeof(location) - offset,
                           "&state=%s", encoded_state);
    }

    oauth_authorize_response_free(&auth_response);

    /* Create 302 redirect response */
    HttpResponse *resp = http_response_new(302);
    if (!resp) {
        log_error("Failed to create HTTP response");
        return response_json_error(500, "Internal server error");
    }

    http_response_set_header(resp, "Location", location);
    http_response_set_body_str(resp, "");

    log_info("Authorization successful, redirecting to client");
    return resp;
}

/* ============================================================================
 * JWKS Endpoint
 * ========================================================================== */

/* Stringify macro for embedding numeric constants in string literals */
#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

/* Thread-local JWKS response cache (one per worker, no locks needed) */
static __thread char jwks_cache[4096];
static __thread time_t jwks_cache_time = 0;

/*
 * Extract EC public key coordinates from PEM format to JWK (x, y)
 *
 * Returns: 0 on success, -1 on error
 */
static int ec_public_key_to_jwk(const char *pem_public_key,
                                 char *out_x_b64, size_t x_b64_len,
                                 char *out_y_b64, size_t y_b64_len) {
    if (!pem_public_key || !out_x_b64 || !out_y_b64) {
        return -1;
    }

    /* Parse PEM public key */
    BIO *bio = BIO_new_mem_buf(pem_public_key, -1);
    if (!bio) {
        log_error("Failed to create BIO for PEM parsing");
        return -1;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        log_error("Failed to parse PEM public key");
        return -1;
    }

    /* Extract x and y coordinates directly (OpenSSL 3.0+ API) */
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, "qx", &x) ||
        !EVP_PKEY_get_bn_param(pkey, "qy", &y)) {
        BN_free(x);
        BN_free(y);
        EVP_PKEY_free(pkey);
        log_error("Failed to extract EC public key coordinates");
        return -1;
    }

    /* Convert to bytes (32 bytes for P-256) */
    unsigned char x_bytes[32];
    unsigned char y_bytes[32];

    int x_len = BN_bn2binpad(x, x_bytes, 32);
    int y_len = BN_bn2binpad(y, y_bytes, 32);

    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(pkey);

    if (x_len != 32 || y_len != 32) {
        log_error("Invalid coordinate length: x=%d, y=%d", x_len, y_len);
        return -1;
    }

    /* Base64url encode coordinates */
    size_t x_encoded = crypto_base64url_encode(x_bytes, 32, out_x_b64, x_b64_len);
    size_t y_encoded = crypto_base64url_encode(y_bytes, 32, out_y_b64, y_b64_len);

    if (x_encoded == 0 || y_encoded == 0) {
        log_error("Failed to base64url encode coordinates");
        return -1;
    }

    return 0;
}

/*
 * GET /.well-known/jwks.json
 *
 * JSON Web Key Set endpoint (RFC 7517)
 * Returns public keys for verifying OAuth2 access tokens (ES256).
 *
 * Response:
 *   200 OK
 *   Cache-Control: max-age=3600
 *   {
 *     "keys": [
 *       {
 *         "kty": "EC",
 *         "use": "sig",
 *         "crv": "P-256",
 *         "kid": "1234567890",
 *         "x": "base64url...",
 *         "y": "base64url...",
 *         "alg": "ES256"
 *       }
 *     ]
 *   }
 */
HttpResponse *jwks_handler(const HttpRequest *req, const RouteParams *params) {
    (void)req;
    (void)params;

    /* Serve from thread-local cache if fresh */
    time_t now = time(NULL);
    if (jwks_cache_time > 0 && (now - jwks_cache_time) < JWKS_CACHE_TTL_SECONDS) {
        HttpResponse *resp = http_response_new(200);
        if (!resp) {
            return response_json_error(500, "Internal server error");
        }
        http_response_set(resp, CONTENT_TYPE_JSON, jwks_cache);
        http_response_set_header(resp, "Cache-Control", "max-age=" STRINGIFY(JWKS_CACHE_CONTROL_SECONDS) ", public");
        return resp;
    }

    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection");
        return response_json_error(500, "Internal server error");
    }

    /* Get access token signing keys */
    signing_key_t *key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_ACCESS_TOKEN, &key) != 0) {
        log_error("Failed to get access token signing key");
        return response_json_error(500, "Internal server error");
    }

    /* Extract current public key coordinates */
    char current_x[64];  /* 32 bytes -> ~43 chars base64url */
    char current_y[64];

    if (ec_public_key_to_jwk(key->current_public_key,
                              current_x, sizeof(current_x),
                              current_y, sizeof(current_y)) != 0) {
        signing_key_free(key);
        log_error("Failed to convert current public key to JWK");
        return response_json_error(500, "Internal server error");
    }

    /* Build kid (key ID) from timestamp */
    char current_kid[32];
    snprintf(current_kid, sizeof(current_kid), "%lld", (long long)key->current_generated_at);

    /* Start building JWKS JSON */
    char jwks[4096];
    int offset = snprintf(jwks, sizeof(jwks),
        "{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\","
        "\"kid\":\"%s\",\"x\":\"%s\",\"y\":\"%s\",\"alg\":\"ES256\"}",
        current_kid, current_x, current_y);

    /* Add prior key if present */
    if (key->prior_public_key) {
        char prior_x[64];
        char prior_y[64];

        if (ec_public_key_to_jwk(key->prior_public_key,
                                  prior_x, sizeof(prior_x),
                                  prior_y, sizeof(prior_y)) == 0) {
            char prior_kid[32];
            snprintf(prior_kid, sizeof(prior_kid), "%lld", (long long)key->prior_generated_at);

            offset += snprintf(jwks + offset, sizeof(jwks) - offset,
                ",{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\","
                "\"kid\":\"%s\",\"x\":\"%s\",\"y\":\"%s\",\"alg\":\"ES256\"}",
                prior_kid, prior_x, prior_y);
        } else {
            log_warn("Failed to convert prior public key to JWK, omitting from JWKS");
        }
    }

    offset += snprintf(jwks + offset, sizeof(jwks) - offset, "]}");

    signing_key_free(key);

    /* Update thread-local cache */
    memcpy(jwks_cache, jwks, (size_t)offset + 1);
    jwks_cache_time = now;

    /* Create response with cache headers */
    HttpResponse *resp = http_response_new(200);
    if (!resp) {
        log_error("Failed to create HTTP response");
        return response_json_error(500, "Internal server error");
    }

    http_response_set(resp, CONTENT_TYPE_JSON, jwks);
    http_response_set_header(resp, "Cache-Control", "max-age=" STRINGIFY(JWKS_CACHE_CONTROL_SECONDS) ", public");

    log_info("JWKS request served successfully");
    return resp;
}

/* ============================================================================
 * Token Revocation Endpoint
 * ========================================================================== */

/*
 * POST /revoke
 *
 * OAuth2 token revocation endpoint (RFC 7009)
 * Revokes access or refresh tokens owned by the authenticated client.
 *
 * Request:
 *   Content-Type: application/x-www-form-urlencoded
 *   Body: token=<token>&token_type_hint=<hint>&client_id=<uuid>&client_key_id=<uuid>&client_secret=<secret>
 *
 * Response:
 *   200 OK (always, even if token is invalid or already revoked)
 *   Per RFC 7009: prevents information disclosure to unauthorized parties
 */
HttpResponse *revoke_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/x-www-form-urlencoded");
    if (ct_err) return ct_err;

    if (req->method != HTTP_POST) {
        return response_json_error(405, "Method not allowed");
    }

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to acquire database connection");
        return response_json_error(503, "Service unavailable");
    }

    const char *body = req->body ? req->body : "";

    /* Parse required parameters */
    char *token = form_get_param(body, "token");
    char *client_id_str = form_get_param(body, "client_id");
    char *client_key_id_str = form_get_param(body, "client_key_id");
    char *client_secret = form_get_param(body, "client_secret");

    /* Parse optional parameter */
    char *token_type_hint = form_get_param(body, "token_type_hint");

    if (!token || !client_id_str || !client_key_id_str || !client_secret) {
        free(token);
        free(client_id_str);
        free(client_key_id_str);
        free(client_secret);
        free(token_type_hint);
        return response_json_error(400, "token, client_id, client_key_id, and client_secret required");
    }

    /* Parse client_id UUID */
    unsigned char client_id[16];
    if (hex_to_bytes(client_id_str, client_id, 16) != 0) {
        free(token);
        free(client_id_str);
        free(client_key_id_str);
        free(client_secret);
        free(token_type_hint);
        return response_json_error(400, "Invalid client_id format");
    }
    free(client_id_str);

    /* Parse client_key_id UUID */
    unsigned char client_key_id[16];
    if (hex_to_bytes(client_key_id_str, client_key_id, 16) != 0) {
        free(token);
        free(client_key_id_str);
        free(client_secret);
        free(token_type_hint);
        return response_json_error(400, "Invalid client_key_id format");
    }
    free(client_key_id_str);

    /* Get source IP and user agent for audit logging */
    const char *source_ip = http_request_get_client_ip(req, NULL);
    const char *user_agent = http_request_get_header(req, "User-Agent");

    /* Authenticate client */
    long long client_pin;
    int auth_result = oauth_handler_client_authenticate(db, client_id, client_key_id,
                                                         client_secret, source_ip, user_agent,
                                                         &client_pin);

    free(client_secret);

    if (auth_result != 1) {
        free(token);
        free(token_type_hint);
        log_warn("Client authentication failed for revoke request");
        /* Per RFC 7009: return 200 OK even on auth failure to prevent enumeration */
        return response_json_ok("{}");
    }

    /* Revoke the token */
    int revoke_result = oauth_handler_revoke_token(db, token, token_type_hint, client_pin);

    free(token);
    free(token_type_hint);

    if (revoke_result != 0) {
        log_error("Error during token revocation");
        /* Still return 200 OK per RFC 7009 */
    }

    /* RFC 7009: The authorization server responds with HTTP status code 200
     * if the token has been revoked successfully or if the client submitted
     * an invalid token. */
    return response_json_ok("{}");
}

/* ============================================================================
 * Token Introspection Endpoint
 * ========================================================================== */

/*
 * POST /introspect
 *
 * OAuth2 token introspection endpoint (RFC 7662)
 * Resource servers use this to validate access tokens.
 *
 * Request:
 *   Content-Type: application/x-www-form-urlencoded
 *   Body: token=<token>&resource_server_id=<uuid>&resource_server_key_id=<uuid>&resource_server_secret=<secret>
 *
 * Response (active token):
 *   {
 *     "active": true,
 *     "scope": "read write",
 *     "client_id": "ab12cd...",  // client UUID hex
 *     "token_type": "Bearer",
 *     "exp": 1234567890,
 *     "iat": 1234567890,
 *     "sub": "abc123...", // user UUID hex (omitted for client_credentials)
 *     "aud": "def456..."  // resource server UUID hex
 *   }
 *
 * Response (inactive token):
 *   {"active": false}
 */
HttpResponse *introspect_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;
    HttpResponse *ct_err = require_content_type(req, "application/x-www-form-urlencoded");
    if (ct_err) return ct_err;

    if (req->method != HTTP_POST) {
        return response_json_error(405, "Method not allowed");
    }

    /* Get database connection */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to acquire database connection");
        return response_json_error(503, "Service unavailable");
    }

    const char *body = req->body ? req->body : "";

    /* Parse required parameters */
    char *token = form_get_param(body, "token");
    char *resource_server_id_str = form_get_param(body, "resource_server_id");
    char *resource_server_key_id_str = form_get_param(body, "resource_server_key_id");
    char *resource_server_secret = form_get_param(body, "resource_server_secret");

    /* Parse optional parameter */
    char *token_type_hint = form_get_param(body, "token_type_hint");

    if (!token || !resource_server_id_str || !resource_server_key_id_str || !resource_server_secret) {
        free(token);
        free(resource_server_id_str);
        free(resource_server_key_id_str);
        free(resource_server_secret);
        free(token_type_hint);
        return response_json_error(400, "token, resource_server_id, resource_server_key_id, and resource_server_secret required");
    }

    /* Parse resource_server_id UUID */
    unsigned char resource_server_id[16];
    if (hex_to_bytes(resource_server_id_str, resource_server_id, 16) != 0) {
        free(token);
        free(resource_server_id_str);
        free(resource_server_key_id_str);
        free(resource_server_secret);
        free(token_type_hint);
        return response_json_error(400, "Invalid resource_server_id format");
    }
    free(resource_server_id_str);

    /* Parse resource_server_key_id UUID */
    unsigned char resource_server_key_id[16];
    if (hex_to_bytes(resource_server_key_id_str, resource_server_key_id, 16) != 0) {
        free(token);
        free(resource_server_key_id_str);
        free(resource_server_secret);
        free(token_type_hint);
        return response_json_error(400, "Invalid resource_server_key_id format");
    }
    free(resource_server_key_id_str);

    /* Get source IP and user agent for audit logging */
    const char *source_ip = http_request_get_client_ip(req, NULL);
    const char *user_agent = http_request_get_header(req, "User-Agent");

    /* Authenticate resource server */
    long long resource_server_pin;
    int auth_result = oauth_handler_resource_server_authenticate(db, resource_server_id,
                                                                  resource_server_key_id,
                                                                  resource_server_secret,
                                                                  source_ip, user_agent,
                                                                  &resource_server_pin);

    free(resource_server_secret);

    if (auth_result != 1) {
        free(token);
        free(token_type_hint);
        log_warn("Resource server authentication failed for introspect request");
        /* Return inactive per RFC 7662 (don't leak auth failures) */
        return response_json_ok("{\"active\":false}");
    }

    /* Introspect the token */
    int active;
    char *scope = NULL;
    unsigned char client_id[16] = {0};
    unsigned char user_id[16] = {0};
    unsigned char token_resource_server_id[16] = {0};
    long long expires_at = 0;
    long long issued_at = 0;

    int introspect_result = oauth_handler_introspect_token(db, token, token_type_hint,
                                                            resource_server_pin,
                                                            &active, &scope,
                                                            client_id, user_id,
                                                            token_resource_server_id,
                                                            &expires_at, &issued_at);

    free(token);
    free(token_type_hint);

    if (introspect_result != 0) {
        free(scope);
        log_error("Error during token introspection");
        return response_json_ok("{\"active\":false}");
    }

    /* Build JSON response */
    char json[2048];
    int json_len;

    if (!active) {
        json_len = snprintf(json, sizeof(json), "{\"active\":false}");
    } else {
        /* Format UUIDs as hex strings */
        char client_id_hex[33];
        char aud_hex[33];
        bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));
        bytes_to_hex(token_resource_server_id, 16, aud_hex, sizeof(aud_hex));

        json_len = snprintf(json, sizeof(json),
            "{\"active\":true,\"token_type\":\"Bearer\",\"client_id\":\"%s\",\"aud\":\"%s\"",
            client_id_hex, aud_hex);

        if (scope) {
            char escaped_scope[512];
            json_escape(escaped_scope, sizeof(escaped_scope), scope);
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"scope\":\"%s\"", escaped_scope);
        }

        /* Check if user_id is non-zero (present for authorization_code, absent for client_credentials) */
        static const unsigned char zero_id[16] = {0};
        if (memcmp(user_id, zero_id, 16) != 0) {
            char user_id_hex[33];
            bytes_to_hex(user_id, 16, user_id_hex, sizeof(user_id_hex));
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"sub\":\"%s\"", user_id_hex);
        }

        if (expires_at > 0) {
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"exp\":%lld", expires_at);
        }

        if (issued_at > 0) {
            json_len += snprintf(json + json_len, sizeof(json) - json_len,
                ",\"iat\":%lld", issued_at);
        }

        json_len += snprintf(json + json_len, sizeof(json) - json_len, "}");
    }

    free(scope);

    if (json_len >= (int)sizeof(json)) {
        return response_json_error(500, "Internal server error");
    }

    return response_json_ok(json);
}

/* ============================================================================
 * UserInfo Endpoint (OIDC Core Section 5.3)
 * ========================================================================== */

/*
 * GET /userinfo
 *
 * Returns claims about the authenticated user. Requires Bearer token
 * (ES256 JWT access token) in Authorization header.
 *
 * Request:
 *   Authorization: Bearer <access_token>
 *
 * Response (success):
 *   200 OK
 *   {
 *     "sub": "ab12cd34...",
 *     "preferred_username": "alice",
 *     "email": "alice@example.com",
 *     "email_verified": true,
 *     "server_time": 1739800000
 *   }
 *
 * Response (error):
 *   401 Unauthorized (missing/invalid/expired token)
 */
HttpResponse *userinfo_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Extract Bearer token from Authorization header */
    const char *auth_header = http_request_get_header(req, "Authorization");
    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0) {
        return response_json_error(401, "Bearer token required");
    }
    const char *token = auth_header + 7;
    if (*token == '\0') {
        return response_json_error(401, "Bearer token required");
    }

    /* Get signing keys for JWT verification */
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection for userinfo");
        return response_json_error(500, "Internal server error");
    }

    signing_key_t *key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_ACCESS_TOKEN, &key) != 0) {
        log_error("Failed to get signing key for userinfo");
        return response_json_error(500, "Internal server error");
    }

    /* Verify and decode the JWT */
    jwt_claims_t claims;
    if (jwt_decode_es256(token, key->current_public_key,
                         key->prior_public_key, &claims) != 0) {
        signing_key_free(key);
        return response_json_error(401, "Invalid or expired token");
    }
    signing_key_free(key);

    /* Extract user UUID from sub claim */
    if (claims.sub[0] == '\0') {
        return response_json_error(401, "Token has no subject");
    }

    unsigned char user_id[16];
    if (hex_to_bytes(claims.sub, user_id, 16) != 0) {
        return response_json_error(401, "Invalid subject in token");
    }

    /* Look up user profile */
    user_userinfo_t info;
    if (user_get_userinfo_by_id(db, user_id, &info) != 0) {
        return response_json_error(401, "User not found");
    }

    /* Build JSON response */
    char json[1024];
    char escaped_username[512];
    char escaped_email[512];

    json_escape(escaped_username, sizeof(escaped_username), info.username);
    json_escape(escaped_email, sizeof(escaped_email), info.email);

    int len = snprintf(json, sizeof(json),
        "{\"sub\":\"%s\"", claims.sub);

    if (info.username[0] != '\0') {
        len += snprintf(json + len, sizeof(json) - len,
            ",\"preferred_username\":\"%s\"", escaped_username);
    }

    if (info.email[0] != '\0') {
        len += snprintf(json + len, sizeof(json) - len,
            ",\"email\":\"%s\",\"email_verified\":%s",
            escaped_email, info.email_verified ? "true" : "false");
    }

    len += snprintf(json + len, sizeof(json) - len,
        ",\"server_time\":%lld}", (long long)time(NULL));

    if (len >= (int)sizeof(json)) {
        return response_json_error(500, "Internal server error");
    }

    return response_json_ok(json);
}
