/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "handlers/oauth.h"
#include "db/queries/oauth.h"
#include "db/queries/client.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/hmac.h"
#include "crypto/signing_keys.h"
#include "crypto/jwt.h"
#include "util/log.h"
#include "util/str.h"
#include "util/data.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>

/* Token sizes (before base64url encoding) */
#define ACCESS_TOKEN_BYTES 32   /* 256 bits */
#define REFRESH_TOKEN_BYTES 32  /* 256 bits */

/* Authorization code TTL (per OAuth2 spec: short-lived, 60-90 seconds) */
#define AUTHORIZATION_CODE_TTL_SECONDS 60

void oauth_token_response_free(oauth_token_response_t *resp) {
    if (!resp) return;
    free(resp->access_token);
    free(resp->refresh_token);
    free(resp->scope);
    memset(resp, 0, sizeof(*resp));
}

/*
 * Validate PKCE code verifier against code challenge
 *
 * Supports "plain" and "S256" methods.
 * Per RFC 7636: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 *
 * Returns: 1 if valid, 0 if invalid
 */
static int validate_pkce(const char *code_verifier,
                          const char *code_challenge,
                          const char *code_challenge_method) {
    if (!code_verifier || !code_challenge || !code_challenge_method) {
        return 0;
    }

    if (strcmp(code_challenge_method, "plain") == 0) {
        /* Plain: verifier must exactly match challenge */
        return strcmp(code_verifier, code_challenge) == 0 ? 1 : 0;
    } else if (strcmp(code_challenge_method, "S256") == 0) {
        /* S256: BASE64URL(SHA256(code_verifier)) must match code_challenge */

        /* Compute SHA256 hash of code_verifier */
        unsigned char hash[32];  /* SHA256 produces 32 bytes */
        unsigned int hash_len = 0;

        if (EVP_Digest(code_verifier, strlen(code_verifier),
                       hash, &hash_len, EVP_sha256(), NULL) != 1) {
            log_error("SHA256 hash failed for PKCE S256");
            return 0;
        }

        if (hash_len != 32) {
            log_error("Unexpected SHA256 hash length: %u", hash_len);
            return 0;
        }

        /* Base64url encode the hash */
        char encoded_hash[64];  /* 32 bytes -> 43 chars + null */
        size_t encoded_len = crypto_base64url_encode(hash, hash_len,
                                                      encoded_hash, sizeof(encoded_hash));

        if (encoded_len == 0) {
            log_error("Base64url encoding failed for PKCE S256");
            return 0;
        }

        /* Compare with provided code_challenge (timing-safe not critical here) */
        return strcmp(encoded_hash, code_challenge) == 0 ? 1 : 0;
    } else {
        log_error("Unknown PKCE method: %s", code_challenge_method);
        return 0;
    }
}

/*
 * Validate that requested scopes are a subset of allowed scopes
 *
 * OAuth2 scopes are space-delimited (e.g., "read write").
 * Used for scope downscoping in refresh token flow (RFC 6749 Section 6).
 *
 * Returns: 0 if valid subset, -1 if any requested scope not in allowed
 */
static int validate_scope_subset(const char *requested, const char *allowed) {
    if (!requested || !allowed) return -1;

    /* Empty requested scope means "use all original scopes" */
    if (requested[0] == '\0') return 0;

    /* Split both into arrays */
    int requested_count = 0, allowed_count = 0;
    char **requested_scopes = str_split(requested, ' ', &requested_count);
    char **allowed_scopes = str_split(allowed, ' ', &allowed_count);

    if (!requested_scopes || !allowed_scopes) {
        if (requested_scopes) {
            for (int i = 0; i < requested_count; i++) free(requested_scopes[i]);
            free(requested_scopes);
        }
        if (allowed_scopes) {
            for (int i = 0; i < allowed_count; i++) free(allowed_scopes[i]);
            free(allowed_scopes);
        }
        return -1;
    }

    /* Check each requested scope exists in allowed */
    int result = 0;
    for (int i = 0; i < requested_count; i++) {
        int found = 0;
        for (int j = 0; j < allowed_count; j++) {
            if (strcmp(requested_scopes[i], allowed_scopes[j]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            log_warn("Requested scope '%s' not in allowed scopes '%s'",
                     requested_scopes[i], allowed);
            result = -1;
            break;
        }
    }

    /* Cleanup */
    for (int i = 0; i < requested_count; i++) free(requested_scopes[i]);
    free(requested_scopes);
    for (int i = 0; i < allowed_count; i++) free(allowed_scopes[i]);
    free(allowed_scopes);

    return result;
}

void oauth_authorize_response_free(oauth_authorize_response_t *resp) {
    if (!resp) return;
    free(resp->code);
    free(resp->state);
    memset(resp, 0, sizeof(*resp));
}

int oauth_authorize(db_handle_t *db,
                    const unsigned char *client_id,
                    const char *redirect_uri,
                    const char *scope,
                    const char *code_challenge,
                    const char *code_challenge_method,
                    const char *state,
                    const char *session_token,
                    oauth_authorize_response_t *out_response) {
    if (!db || !client_id || !redirect_uri || !out_response) {
        log_error("Invalid arguments to oauth_authorize");
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));

    /* Step 1: Look up client */
    oauth_client_info_t client;
    if (oauth_client_lookup(db, client_id, &client) != 0) {
        log_error("Client not found or inactive");
        return -4;  /* Pre-trust: do NOT redirect to unverified URI */
    }

    /* Step 2: Validate redirect_uri is registered for client */
    int uri_valid = oauth_redirect_uri_validate(db, client.pin, redirect_uri);
    if (uri_valid != 1) {
        log_error("Redirect URI not registered for client");
        return -4;  /* Pre-trust: do NOT redirect to unverified URI */
    }

    /* Step 3: Validate session */
    if (!session_token) {
        log_error("Session token required");
        return -2;  /* Not authenticated */
    }

    oauth_session_info_t session;
    if (oauth_session_get_by_token(db, session_token, &session) != 0) {
        log_error("Session not found or expired");
        return -2;  /* Not authenticated */
    }

    /* Step 4: Check authentication complete */
    if (!session.authentication_complete) {
        log_error("Session authentication not complete");
        return -2;  /* Not authenticated */
    }

    /* Step 5: Check MFA if required by client or user preference */
    if ((client.require_mfa || session.user_requires_mfa) && !session.mfa_completed) {
        log_error("MFA required but not completed");
        out_response->user_account_pin = session.user_account_pin;
        return -3;  /* MFA required */
    }

    /* Step 5.1: Check maximum session duration for this client */
    if (client.maximum_session_seconds > 0) {
        time_t session_age = time(NULL) - session.started_at;
        if (session_age > client.maximum_session_seconds) {
            log_info("Session too old for client %s: age=%ld, max=%d",
                     client.code_name, (long)session_age, client.maximum_session_seconds);
            return -2;  /* Not authenticated — forces re-login */
        }
    }

    /* Step 5.5: Validate PKCE for public clients (RFC 7636) */
    if (strcmp(client.client_type, "public") == 0) {
        if (!code_challenge || code_challenge[0] == '\0') {
            log_error("Public client must provide PKCE code_challenge");
            return -1;
        }
        if (!code_challenge_method || code_challenge_method[0] == '\0') {
            log_error("Public client must provide PKCE code_challenge_method");
            return -1;
        }
    }

    /* Step 6: Get signing key for auth request JWTs */
    signing_key_t *auth_signing_key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_AUTH_REQUEST, &auth_signing_key) != 0) {
        log_error("Failed to get auth request signing key");
        return -1;
    }

    /* Step 7: Build JWT claims */
    auth_request_claims_t claims = {0};
    memcpy(claims.client_id, client_id, 16);
    memcpy(claims.user_account_id, session.user_account_id, 16);

    str_copy(claims.redirect_uri, sizeof(claims.redirect_uri), redirect_uri);
    if (scope) {
        str_copy(claims.scope, sizeof(claims.scope), scope);
    }

    if (code_challenge) {
        str_copy(claims.code_challenge, sizeof(claims.code_challenge), code_challenge);
    }
    if (code_challenge_method) {
        str_copy(claims.code_challenge_method, sizeof(claims.code_challenge_method), code_challenge_method);
    }

    claims.iat = time(NULL);
    claims.exp = claims.iat + AUTHORIZATION_CODE_TTL_SECONDS;

    /* Generate random nonce (16 bytes = 32 hex chars) */
    unsigned char nonce_bytes[16];
    if (crypto_random_bytes(nonce_bytes, sizeof(nonce_bytes)) != 0) {
        signing_key_free(auth_signing_key);
        log_error("Failed to generate nonce");
        return -1;
    }

    /* Convert nonce to hex string */
    for (size_t i = 0; i < sizeof(nonce_bytes) && i * 2 < sizeof(claims.nonce) - 1; i++) {
        snprintf(claims.nonce + i * 2, sizeof(claims.nonce) - i * 2, "%02x", nonce_bytes[i]);
    }

    /* Step 8: Decode base64url secret to raw bytes */
    unsigned char secret_bytes[256];
    int secret_len = crypto_base64url_decode(
        auth_signing_key->current_secret,
        strlen(auth_signing_key->current_secret),
        secret_bytes,
        sizeof(secret_bytes)
    );

    if (secret_len <= 0) {
        signing_key_free(auth_signing_key);
        log_error("Failed to decode signing secret");
        return -1;
    }

    signing_key_free(auth_signing_key);

    /* Step 9: Encode JWT authorization code */
    char *code_jwt = malloc(JWT_MAX_TOKEN_LENGTH);
    if (!code_jwt) {
        log_error("Failed to allocate memory for JWT");
        return -1;
    }

    if (jwt_encode_auth_request(&claims,
                                 secret_bytes,
                                 secret_len,
                                 code_jwt, JWT_MAX_TOKEN_LENGTH) != 0) {
        free(code_jwt);
        log_error("Failed to encode authorization code JWT");
        return -1;
    }

    /* Step 10: Create DB record (for replay detection) */
    unsigned char auth_code_id[16];
    if (oauth_auth_code_create(db, client.pin, client.id,
                                session.user_account_pin, session.user_account_id,
                                code_jwt,
                                code_challenge ? code_challenge : "",
                                code_challenge_method ? code_challenge_method : "",
                                AUTHORIZATION_CODE_TTL_SECONDS,
                                auth_code_id) != 0) {
        free(code_jwt);
        log_error("Failed to create authorization code record");
        return -1;
    }

    /* Step 11: Prepare response */
    out_response->code = code_jwt;

    if (state) {
        out_response->state = str_dup(state);
        if (!out_response->state) {
            free(code_jwt);
            log_error("Failed to duplicate state");
            return -1;
        }
    }

    char client_id_hex[33];
    char user_id_hex[33];
    bytes_to_hex(client.id, sizeof(client.id), client_id_hex, sizeof(client_id_hex));
    bytes_to_hex(session.user_account_id, sizeof(session.user_account_id), user_id_hex, sizeof(user_id_hex));
    log_info("Authorization code created for client_id=%s, user_id=%s",
             client_id_hex, user_id_hex);

    return 0;
}

int oauth_exchange_authorization_code(db_handle_t *db,
                                       const unsigned char *client_id,
                                       const char *code,
                                       const char *redirect_uri,
                                       const char *code_verifier,
                                       const char *resource,
                                       oauth_token_response_t *out_response) {
    if (!db || !client_id || !code || !redirect_uri || !out_response) {
        log_error("Invalid arguments to oauth_exchange_authorization_code");
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));

    /* Step 1: Look up client */
    oauth_client_info_t client;
    if (oauth_client_lookup(db, client_id, &client) != 0) {
        log_error("Client not found");
        return -1;
    }

    /* Step 2: Decode and verify authorization code JWT (stateless) */
    signing_key_t *auth_signing_key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_AUTH_REQUEST, &auth_signing_key) != 0) {
        log_error("Failed to get auth request signing key");
        return -1;
    }

    auth_request_claims_t auth_claims;
    if (jwt_decode_auth_request(code,
                                 auth_signing_key->current_secret,
                                 auth_signing_key->prior_secret,
                                 &auth_claims) != 0) {
        signing_key_free(auth_signing_key);
        log_error("Failed to decode or verify authorization code JWT");
        return -1;
    }

    signing_key_free(auth_signing_key);

    /* Step 3: Validate client_id matches */
    if (memcmp(auth_claims.client_id, client.id, 16) != 0) {
        log_error("Client ID mismatch in authorization code");
        return -1;
    }

    /* Step 4: Validate redirect_uri matches */
    if (strcmp(redirect_uri, auth_claims.redirect_uri) != 0) {
        log_error("Redirect URI mismatch");
        return -1;
    }

    /* Step 5: Validate PKCE (if present) */
    if (auth_claims.code_challenge[0] != '\0') {
        if (!code_verifier) {
            log_error("PKCE code_verifier required but not provided");
            return -1;
        }

        if (!validate_pkce(code_verifier, auth_claims.code_challenge,
                           auth_claims.code_challenge_method)) {
            log_error("PKCE validation failed");
            return -1;
        }
    } else if (strcmp(client.client_type, "public") == 0) {
        /* Public clients MUST use PKCE */
        log_error("Public client must use PKCE");
        return -1;
    }

    /* Step 6: Look up user_account_pin from user_account_id (UUID) for DB operations */
    long long user_account_pin = 0;
    const char *user_lookup_sql =
        "SELECT pin FROM " TBL_USER_ACCOUNT " "
        "WHERE id = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *user_stmt = NULL;
    if (db_prepare(db, &user_stmt, user_lookup_sql) != 0) {
        log_error("Failed to prepare user lookup statement");
        return -1;
    }

    db_bind_blob(user_stmt, 1, auth_claims.user_account_id, 16);

    int user_rc = db_step(user_stmt);
    if (user_rc == DB_ROW) {
        user_account_pin = db_column_int64(user_stmt, 0);
        db_finalize(user_stmt);
    } else {
        db_finalize(user_stmt);
        log_error("User account not found or inactive");
        return -1;
    }

    /* Step 6: Get signing key for access token (before transaction) */
    signing_key_t *signing_key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_ACCESS_TOKEN, &signing_key) != 0) {
        log_error("Failed to get access token signing key");
        return -1;
    }

    /* Begin transaction for token creation */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        signing_key_free(signing_key);
        log_error("Failed to begin transaction");
        return -1;
    }

    /* Step 7: Consume authorization code from DB (atomic, replay detection) */
    /* The DB record was created at /authorize time with is_exchanged=FALSE */
    /* This atomically updates to is_exchanged=TRUE and returns the record data */
    oauth_auth_code_data_t db_code_data;
    int consume_rc = oauth_auth_code_consume(db, code, &db_code_data);

    if (consume_rc == 1) {
        /* Replay attack detected - code already exchanged */
        db_execute_trusted(db, "ROLLBACK");

        /* Revoke all tokens derived from this authorization code */
        int refresh_revoked = 0, access_revoked = 0;
        if (oauth_revoke_token_chain(db, db_code_data.id, 1,
                                      &refresh_revoked, &access_revoked) == 0) {
            log_warn("Authorization code replay: revoked %d refresh, %d access tokens",
                     refresh_revoked, access_revoked);
        } else {
            log_error("Failed to revoke token chain after authorization code replay");
        }

        return 1;
    }

    if (consume_rc != 0) {
        /* Not found, expired, or error */
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to consume authorization code from DB");
        return -1;
    }

    /* Step 8: Validate JWT claims match DB record (integrity check) */
    if (db_code_data.client_pin != client.pin) {
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Client PIN mismatch between JWT and DB record");
        return -1;
    }

    if (db_code_data.user_account_pin != user_account_pin) {
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("User account PIN mismatch between JWT and DB record");
        return -1;
    }

    /* Use JWT claims for token creation (cryptographically verified) */

    /* Step 9: Resolve resource server (RFC 8707) */
    long long resource_server_pin;
    unsigned char resource_server_id[16];
    if (oauth_resolve_resource_server(db, client.pin, resource,
                                       &resource_server_pin, resource_server_id) != 0) {
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to resolve resource server");
        return -1;
    }

    /* Step 10: Build JWT claims for access token (UUIDs, not internal PINs) */
    char user_id_hex[33], rs_id_hex[33], client_id_hex[33];
    bytes_to_hex(auth_claims.user_account_id, 16, user_id_hex, sizeof(user_id_hex));
    bytes_to_hex(resource_server_id, 16, rs_id_hex, sizeof(rs_id_hex));
    bytes_to_hex(client.id, 16, client_id_hex, sizeof(client_id_hex));

    jwt_claims_t claims = {0};
    str_copy(claims.sub, sizeof(claims.sub), user_id_hex);
    str_copy(claims.aud, sizeof(claims.aud), rs_id_hex);
    str_copy(claims.client_id, sizeof(claims.client_id), client_id_hex);
    str_copy(claims.scope, sizeof(claims.scope), auth_claims.scope);
    claims.iat = time(NULL);
    claims.exp = claims.iat + client.access_token_ttl_seconds;

    char *access_token = malloc(JWT_MAX_TOKEN_LENGTH);
    if (!access_token) {
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to allocate access token");
        return -1;
    }

    if (jwt_encode_es256(&claims, signing_key_active_private(signing_key),
                         access_token, JWT_MAX_TOKEN_LENGTH) != 0) {
        free(access_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to generate ES256 JWT access token");
        return -1;
    }

    signing_key_free(signing_key);

    /* Step 11: Create access token in database */
    unsigned char access_token_id[16];
    if (oauth_token_create_access(db, resource_server_pin, client.pin,
                                   user_account_pin,
                                   db_code_data.id, NULL,  /* Link to authorization code */
                                   access_token, auth_claims.scope,
                                   client.access_token_ttl_seconds,
                                   access_token_id) != 0) {
        free(access_token);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to create access token");
        return -1;
    }

    /* Step 12: Create refresh token (if configured) */
    char *refresh_token = NULL;
    if (client.issue_refresh_tokens) {
        size_t refresh_token_size = crypto_token_encoded_size(REFRESH_TOKEN_BYTES);
        refresh_token = malloc(refresh_token_size);
        if (!refresh_token) {
            free(access_token);
            db_execute_trusted(db, "ROLLBACK");
            log_error("Failed to allocate refresh token");
            return -1;
        }

        if (crypto_random_token(refresh_token, refresh_token_size, REFRESH_TOKEN_BYTES) <= 0) {
            free(access_token);
            free(refresh_token);
            db_execute_trusted(db, "ROLLBACK");
            log_error("Failed to generate refresh token");
            return -1;
        }

        unsigned char refresh_token_id[16];
        if (oauth_token_create_refresh(db, client.pin, db_code_data.user_account_pin,
                                        db_code_data.id, refresh_token, auth_claims.scope,
                                        client.refresh_token_ttl_seconds,
                                        refresh_token_id) != 0) {
            free(access_token);
            free(refresh_token);
            db_execute_trusted(db, "ROLLBACK");
            log_error("Failed to create refresh token");
            return -1;
        }
    }

    /* Commit transaction */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        free(access_token);
        free(refresh_token);
        log_error("Failed to commit transaction");
        return -1;
    }

    /* Build response */
    out_response->access_token = access_token;
    out_response->refresh_token = refresh_token;  /* May be NULL */
    out_response->expires_in = client.access_token_ttl_seconds;

    out_response->token_type = "Bearer";

    if (auth_claims.scope[0] != '\0') {
        out_response->scope = str_dup(auth_claims.scope);
    } else {
        out_response->scope = NULL;
    }

    log_info("Exchanged authorization code for client_id=%s, user_id=%s",
             client_id_hex, user_id_hex);
    return 0;
}

int oauth_refresh_access_token(db_handle_t *db,
                                const unsigned char *client_id,
                                const char *refresh_token,
                                const char *scope,
                                const char *resource,
                                oauth_token_response_t *out_response) {
    if (!db || !client_id || !refresh_token || !out_response) {
        log_error("Invalid arguments to oauth_refresh_access_token");
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));

    /* Step 1: Look up client */
    oauth_client_info_t client;
    if (oauth_client_lookup(db, client_id, &client) != 0) {
        log_error("Client not found");
        return -1;
    }

    /* Check client issues refresh tokens */
    if (!client.issue_refresh_tokens) {
        log_error("Client not configured to issue refresh tokens");
        return -1;
    }

    /* Step 2: Get signing key for access token (before transaction) */
    signing_key_t *signing_key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_ACCESS_TOKEN, &signing_key) != 0) {
        log_error("Failed to get access token signing key");
        return -1;
    }

    /* Begin transaction */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        signing_key_free(signing_key);
        log_error("Failed to begin transaction");
        return -1;
    }

    /* Step 4: Generate new refresh token */
    size_t new_refresh_token_size = crypto_token_encoded_size(REFRESH_TOKEN_BYTES);
    char *new_refresh_token = malloc(new_refresh_token_size);
    if (!new_refresh_token) {
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to allocate new refresh token");
        return -1;
    }

    if (crypto_random_token(new_refresh_token, new_refresh_token_size, REFRESH_TOKEN_BYTES) <= 0) {
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to generate new refresh token");
        return -1;
    }

    /* Step 5: Rotate refresh token (atomic) */
    oauth_refresh_token_data_t token_data;
    unsigned char new_refresh_token_id[16];
    int rotate_rc = oauth_token_rotate_refresh(db, refresh_token, new_refresh_token,
                                                client.refresh_token_ttl_seconds,
                                                &token_data, new_refresh_token_id);

    if (rotate_rc == 1) {
        /* Replay attack detected */
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");

        /* Revoke all tokens in the rotation chain */
        int refresh_revoked = 0, access_revoked = 0;
        if (oauth_revoke_token_chain(db, token_data.origin_id, 0,
                                      &refresh_revoked, &access_revoked) == 0) {
            log_warn("Refresh token replay: revoked %d refresh, %d access tokens",
                     refresh_revoked, access_revoked);
        } else {
            log_error("Failed to revoke token chain after refresh token replay");
        }

        return 1;
    }

    if (rotate_rc != 0) {
        /* Not found, expired, revoked, or error */
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to rotate refresh token");
        return -1;
    }

    /* Step 6: Validate client matches */
    if (token_data.client_pin != client.pin) {
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Client PIN mismatch in refresh token");
        return -1;
    }

    /* Step 7: Validate scope (if requested, must be subset of original) */
    const char *final_scope = token_data.scopes;
    if (scope && scope[0] != '\0') {
        if (validate_scope_subset(scope, token_data.scopes) != 0) {
            free(new_refresh_token);
            signing_key_free(signing_key);
            db_execute_trusted(db, "ROLLBACK");
            log_error("Requested scope exceeds original grant");
            return -1;
        }
        final_scope = scope;  /* Use downscoped request */
        log_debug("Downscoped from '%s' to '%s'", token_data.scopes, scope);
    }

    /* Step 8: Resolve resource server (RFC 8707) */
    long long resource_server_pin;
    unsigned char resource_server_id[16];
    if (oauth_resolve_resource_server(db, client.pin, resource,
                                       &resource_server_pin, resource_server_id) != 0) {
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to resolve resource server");
        return -1;
    }

    /* Step 8b: Look up user UUID and verify still active */
    unsigned char user_account_id[16];
    const char *user_lookup_sql =
        "SELECT id FROM " TBL_USER_ACCOUNT " "
        "WHERE pin = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *user_stmt = NULL;
    if (db_prepare(db, &user_stmt, user_lookup_sql) != 0) {
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to prepare user lookup statement");
        return -1;
    }

    db_bind_int64(user_stmt, 1, token_data.user_account_pin);

    if (db_step(user_stmt) == DB_ROW) {
        const unsigned char *id_blob = db_column_blob(user_stmt, 0);
        if (id_blob) memcpy(user_account_id, id_blob, 16);
        db_finalize(user_stmt);
    } else {
        db_finalize(user_stmt);
        free(new_refresh_token);
        signing_key_free(signing_key);
        db_execute_trusted(db, "ROLLBACK");
        log_error("User account not found or inactive");
        return -1;
    }

    /* Step 9: Build JWT claims for access token (UUIDs, not internal PINs) */
    char user_id_hex[33], rs_id_hex[33], client_id_hex[33];
    bytes_to_hex(user_account_id, 16, user_id_hex, sizeof(user_id_hex));
    bytes_to_hex(resource_server_id, 16, rs_id_hex, sizeof(rs_id_hex));
    bytes_to_hex(client.id, 16, client_id_hex, sizeof(client_id_hex));

    jwt_claims_t claims = {0};
    str_copy(claims.sub, sizeof(claims.sub), user_id_hex);
    str_copy(claims.aud, sizeof(claims.aud), rs_id_hex);
    str_copy(claims.client_id, sizeof(claims.client_id), client_id_hex);
    str_copy(claims.scope, sizeof(claims.scope), final_scope);
    claims.iat = time(NULL);
    claims.exp = claims.iat + client.access_token_ttl_seconds;

    char *access_token = malloc(JWT_MAX_TOKEN_LENGTH);
    if (!access_token) {
        signing_key_free(signing_key);
        free(new_refresh_token);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to allocate access token");
        return -1;
    }

    if (jwt_encode_es256(&claims, signing_key_active_private(signing_key),
                         access_token, JWT_MAX_TOKEN_LENGTH) != 0) {
        free(access_token);
        signing_key_free(signing_key);
        free(new_refresh_token);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to generate ES256 JWT access token");
        return -1;
    }

    signing_key_free(signing_key);

    /* Step 10: Create access token in database */
    unsigned char access_token_id[16];
    if (oauth_token_create_access(db, resource_server_pin, client.pin,
                                   token_data.user_account_pin,
                                   NULL, new_refresh_token_id,  /* Link to rotated refresh token */
                                   access_token, final_scope,
                                   client.access_token_ttl_seconds,
                                   access_token_id) != 0) {
        free(access_token);
        free(new_refresh_token);
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to create access token");
        return -1;
    }

    /* Commit transaction */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        free(access_token);
        free(new_refresh_token);
        log_error("Failed to commit transaction");
        return -1;
    }

    /* Build response */
    out_response->access_token = access_token;
    out_response->refresh_token = new_refresh_token;
    out_response->expires_in = client.access_token_ttl_seconds;

    out_response->token_type = "Bearer";

    if (final_scope && final_scope[0] != '\0') {
        out_response->scope = str_dup(final_scope);
    } else {
        out_response->scope = NULL;
    }

    log_info("Refreshed access token for client_id=%s, generation=%d",
             client_id_hex, token_data.generation + 1);
    return 0;
}

int oauth_client_credentials(db_handle_t *db,
                              const unsigned char *client_id,
                              const unsigned char *client_key_id,
                              const char *client_secret,
                              const char *scope,
                              const char *resource,
                              const char *source_ip,
                              const char *user_agent,
                              oauth_token_response_t *out_response) {
    if (!db || !client_id || !client_key_id || !client_secret || !out_response) {
        log_error("Invalid arguments to oauth_client_credentials");
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));

    /* Step 1: Authenticate client */
    long long client_pin;
    int auth_result = oauth_client_authenticate(db, client_id, client_key_id,
                                                 client_secret, source_ip, user_agent,
                                                 &client_pin);

    if (auth_result != 1) {
        log_error("Client authentication failed");
        return -1;
    }

    /* Step 2: Look up client to validate grant type */
    oauth_client_info_t client;
    if (oauth_client_lookup(db, client_id, &client) != 0) {
        log_error("Client not found after successful authentication");
        return -1;
    }

    /* Validate grant type is client_credentials */
    if (strcmp(client.grant_type, "client_credentials") != 0) {
        log_error("Client not configured for client_credentials grant");
        return -1;
    }

    /* Validate client type is confidential */
    if (strcmp(client.client_type, "confidential") != 0) {
        log_error("Client credentials grant requires confidential client");
        return -1;
    }

    /* Step 3: Resolve resource server */
    long long resource_server_pin;
    unsigned char resource_server_id[16];
    if (oauth_resolve_resource_server(db, client.pin, resource,
                                       &resource_server_pin, resource_server_id) != 0) {
        log_error("Failed to resolve resource server");
        return -1;
    }

    /* Step 4: Get signing key for access token JWT */
    signing_key_t *signing_key = NULL;
    if (signing_key_get_or_rotate(db, SIGNING_KEY_ACCESS_TOKEN, &signing_key) != 0) {
        log_error("Failed to get access token signing key");
        return -1;
    }

    /* Step 5: Build JWT claims (RFC 9068 Section 2.2: sub = client_id for client_credentials) */
    char rs_id_hex[33], client_id_hex[33];
    bytes_to_hex(resource_server_id, 16, rs_id_hex, sizeof(rs_id_hex));
    bytes_to_hex(client.id, 16, client_id_hex, sizeof(client_id_hex));

    jwt_claims_t claims = {0};
    str_copy(claims.sub, sizeof(claims.sub), client_id_hex);
    str_copy(claims.aud, sizeof(claims.aud), rs_id_hex);
    str_copy(claims.client_id, sizeof(claims.client_id), client_id_hex);
    str_copy(claims.scope, sizeof(claims.scope), scope ? scope : "");
    claims.iat = time(NULL);
    claims.exp = claims.iat + client.access_token_ttl_seconds;

    char *access_token = malloc(JWT_MAX_TOKEN_LENGTH);
    if (!access_token) {
        signing_key_free(signing_key);
        log_error("Failed to allocate access token");
        return -1;
    }

    if (jwt_encode_es256(&claims, signing_key_active_private(signing_key),
                         access_token, JWT_MAX_TOKEN_LENGTH) != 0) {
        free(access_token);
        signing_key_free(signing_key);
        log_error("Failed to generate ES256 JWT access token");
        return -1;
    }

    signing_key_free(signing_key);

    /* Step 6: Create access token record (no user context for client_credentials) */
    unsigned char access_token_id[16];
    if (oauth_token_create_access(db, resource_server_pin, client.pin,
                                   0,    /* user_account_pin = 0 (no user) */
                                   NULL, /* authorization_code_id = NULL */
                                   NULL, /* refresh_token_id = NULL */
                                   access_token,
                                   scope ? scope : "",
                                   client.access_token_ttl_seconds,
                                   access_token_id) != 0) {
        free(access_token);
        log_error("Failed to create access token record");
        return -1;
    }

    /* Step 7: Build response */
    out_response->access_token = access_token;

    out_response->token_type = "Bearer";
    out_response->expires_in = client.access_token_ttl_seconds;

    if (scope && scope[0] != '\0') {
        out_response->scope = str_dup(scope);
    } else {
        out_response->scope = NULL;
    }

    /* Client credentials grant does not issue refresh tokens */
    out_response->refresh_token = NULL;

    log_info("Issued access token for client_credentials grant: client_id=%s", client_id_hex);
    return 0;
}

/* ============================================================================
 * Handler wrappers for authentication, revocation, and introspection
 * ========================================================================== */

int oauth_handler_client_authenticate(db_handle_t *db,
                                       const unsigned char *client_id,
                                       const unsigned char *client_key_id,
                                       const char *secret,
                                       const char *source_ip,
                                       const char *user_agent,
                                       long long *out_pin) {
    if (!db || !client_id || !client_key_id || !secret || !out_pin) {
        log_error("Invalid arguments to oauth_handler_client_authenticate");
        return -1;
    }

    /* Call query layer */
    return oauth_client_authenticate(db, client_id, client_key_id, secret,
                                      source_ip, user_agent, out_pin);
}

int oauth_handler_resource_server_authenticate(db_handle_t *db,
                                                const unsigned char *resource_server_id,
                                                const unsigned char *resource_server_key_id,
                                                const char *secret,
                                                const char *source_ip,
                                                const char *user_agent,
                                                long long *out_pin) {
    if (!db || !resource_server_id || !resource_server_key_id || !secret || !out_pin) {
        log_error("Invalid arguments to oauth_handler_resource_server_authenticate");
        return -1;
    }

    /* Call query layer */
    return oauth_resource_server_authenticate(db, resource_server_id, resource_server_key_id,
                                               secret, source_ip, user_agent, out_pin);
}

int oauth_handler_revoke_token(db_handle_t *db,
                                const char *token,
                                const char *token_type_hint,
                                long long client_pin) {
    if (!db || !token) {
        log_error("Invalid arguments to oauth_handler_revoke_token");
        return -1;
    }

    /* Call query layer */
    return oauth_revoke_token(db, token, token_type_hint, client_pin);
}

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
                                    long long *out_issued_at) {
    if (!db || !token || !out_active) {
        log_error("Invalid arguments to oauth_handler_introspect_token");
        return -1;
    }

    /* Call query layer */
    return oauth_introspect_token(db, token, token_type_hint, resource_server_pin,
                                   out_active, out_scope, out_client_id,
                                   out_user_id, out_resource_server_id,
                                   out_expires_at, out_issued_at);
}
