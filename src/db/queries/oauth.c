#include "db/queries/oauth.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/sha256.h"
#include "crypto/password.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <string.h>
#include <stdio.h>

int oauth_client_lookup(db_handle_t *db, const unsigned char *client_id,
                        oauth_client_info_t *out_client) {
    if (!db || !client_id || !out_client) {
        log_error("Invalid arguments to oauth_client_lookup");
        return -1;
    }

    const char *sql =
        "SELECT C.id, C.pin, C.organization_pin, C.code_name, C.client_type, C.grant_type, "
        "C.require_mfa, C.access_token_ttl_seconds, C.issue_refresh_tokens, "
        "C.refresh_token_ttl_seconds, C.maximum_session_seconds, C.secret_rotation_seconds, "
        "C.is_universal "
        "FROM " TBL_CLIENT " C "
        "JOIN " TBL_ORGANIZATION " O ON O.pin = C.organization_pin "
        "WHERE C.id = " P"1 "
        "AND C.is_active = " BOOL_TRUE " "
        "AND O.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_client_lookup statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract id (blob) */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len != 16) {
            log_error("Invalid client ID length: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_client->id, id_blob, 16);

        /* Extract scalar fields */
        out_client->pin = db_column_int64(stmt, 1);
        out_client->organization_pin = db_column_int64(stmt, 2);

        /* Extract text fields */
        const char *code_name = (const char *)db_column_text(stmt, 3);
        const char *client_type = (const char *)db_column_text(stmt, 4);
        const char *grant_type = (const char *)db_column_text(stmt, 5);

        if (!code_name || !client_type || !grant_type) {
            log_error("NULL fields in client record");
            db_finalize(stmt);
            return -1;
        }

        str_copy(out_client->code_name, sizeof(out_client->code_name), code_name);
        str_copy(out_client->client_type, sizeof(out_client->client_type), client_type);
        str_copy(out_client->grant_type, sizeof(out_client->grant_type), grant_type);

        /* Extract boolean and integer fields */
        out_client->require_mfa = db_column_int(stmt, 6);
        out_client->access_token_ttl_seconds = db_column_int(stmt, 7);
        out_client->issue_refresh_tokens = db_column_int(stmt, 8);

        /* Handle nullable integer fields */
        if (db_column_type(stmt, 9) == DB_NULL) {
            out_client->refresh_token_ttl_seconds = -1;
        } else {
            out_client->refresh_token_ttl_seconds = db_column_int(stmt, 9);
        }

        if (db_column_type(stmt, 10) == DB_NULL) {
            out_client->maximum_session_seconds = -1;
        } else {
            out_client->maximum_session_seconds = db_column_int(stmt, 10);
        }

        if (db_column_type(stmt, 11) == DB_NULL) {
            out_client->secret_rotation_seconds = -1;
        } else {
            out_client->secret_rotation_seconds = db_column_int(stmt, 11);
        }

        out_client->is_universal = db_column_int(stmt, 12);

        db_finalize(stmt);
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("Client not found by ID");
        return -1;
    } else {
        log_error("Error looking up client by ID");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_redirect_uri_validate(db_handle_t *db, long long client_pin,
                                 const char *redirect_uri) {
    if (!db || !redirect_uri) {
        log_error("Invalid arguments to oauth_redirect_uri_validate");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_CLIENT_REDIRECT_URI " "
        "WHERE client_pin = " P"1 AND redirect_uri = " P"2 "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_redirect_uri_validate statement");
        return -1;
    }

    db_bind_int64(stmt, 1, client_pin);
    db_bind_text(stmt, 2, redirect_uri, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Valid (registered) */
    } else if (rc == DB_DONE) {
        return 0;  /* Not registered */
    } else {
        log_error("Error validating redirect URI");
        return -1;
    }
}

int oauth_session_create(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *session_token,
                         const char *authentication_method,
                         const char *source_ip, const char *user_agent,
                         int ttl_seconds,
                         unsigned char *out_id) {
    if (!db || !user_account_id || !session_token || !authentication_method || !out_id) {
        log_error("Invalid arguments to oauth_session_create");
        return -1;
    }

    /* Generate UUID for session */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for session");
        return -1;
    }

    /* Build TTL string for SQL */
    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "%d", ttl_seconds);

    const char *sql =
        "INSERT INTO " TBL_BROWSER " "
        "(id, user_account_pin, session_token, started_at, authenticated_at, "
        "authentication_complete, authentication_method, mfa_completed, "
        "source_ip, user_agent, expected_expiry, is_closed) "
        "VALUES ("
        P"1, " P"2, " P"3, " NOW ", " NOW ", "
        BOOL_TRUE ", " P"4, " BOOL_FALSE ", "
        P"5, " P"6, " INTERVAL_SECONDS(P"7") ", " BOOL_FALSE
        ") "
        "RETURNING id";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_session_create statement");
        return -1;
    }

    /* Hash session token for storage */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(session_token, strlen(session_token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash session token");
        db_finalize(stmt);
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_int64(stmt, 2, user_account_pin);
    db_bind_text(stmt, 3, token_hash, -1);
    db_bind_text(stmt, 4, authentication_method, -1);

    if (source_ip != NULL) {
        db_bind_text(stmt, 5, source_ip, -1);
    } else {
        db_bind_null(stmt, 5);
    }

    if (user_agent != NULL) {
        db_bind_text(stmt, 6, user_agent, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    db_bind_text(stmt, 7, ttl_str, -1);

    /* Execute and get returned id */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Verify returned ID is a valid UUID */
        const void *returned_id = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);

        if (!returned_id || blob_len != 16) {
            log_error("Invalid session ID length returned: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }

        /* Copy UUID to output */
        memcpy(out_id, id, 16);

        db_finalize(stmt);
        char user_id_hex[33];
        bytes_to_hex(user_account_id, 16, user_id_hex, sizeof(user_id_hex));
        log_info("Created browser session for user_id=%s, method=%s",
                 user_id_hex, authentication_method);
        return 0;
    } else {
        char user_id_hex[33];
        bytes_to_hex(user_account_id, 16, user_id_hex, sizeof(user_id_hex));
        log_error("Failed to create browser session for user_id=%s",
                  user_id_hex);
        db_finalize(stmt);
        return -1;
    }
}

int oauth_session_get_by_token(db_handle_t *db, const char *session_token,
                                oauth_session_info_t *out_session) {
    if (!db || !session_token || !out_session) {
        log_error("Invalid arguments to oauth_session_get_by_token");
        return -1;
    }

    const char *sql =
        "SELECT B.id AS session_id, B.user_account_pin, U.id AS user_id, "
        "B.authentication_complete, B.mfa_completed, U.require_mfa, "
        UNIX_TS("B.started_at") " "
        "FROM " TBL_BROWSER " B "
        "JOIN " TBL_USER_ACCOUNT " U ON U.pin = B.user_account_pin "
        "WHERE B.session_token = " P"1 "
        "AND B.is_closed = " BOOL_FALSE " "
        "AND B.expected_expiry > " NOW " "
        "AND U.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    /* Hash session token for lookup */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(session_token, strlen(session_token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash session token");
        return -1;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_session_get_by_token statement");
        return -1;
    }

    db_bind_text(stmt, 1, token_hash, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract browser session id (blob) */
        const unsigned char *session_id_blob = db_column_blob(stmt, 0);
        int session_blob_len = db_column_bytes(stmt, 0);
        if (session_blob_len != 16) {
            log_error("Invalid session ID length: %d", session_blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_session->id, session_id_blob, 16);

        /* Extract user_account_pin (for internal DB operations) */
        out_session->user_account_pin = db_column_int64(stmt, 1);

        /* Extract user_account id (blob, for external JWTs) */
        const unsigned char *user_id_blob = db_column_blob(stmt, 2);
        int user_blob_len = db_column_bytes(stmt, 2);
        if (user_blob_len != 16) {
            log_error("Invalid user account ID length: %d", user_blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_session->user_account_id, user_id_blob, 16);

        /* Extract boolean fields */
        out_session->authentication_complete = db_column_int(stmt, 3);
        out_session->mfa_completed = db_column_int(stmt, 4);
        out_session->user_requires_mfa = db_column_int(stmt, 5);
        out_session->started_at = (time_t)db_column_int64(stmt, 6);

        db_finalize(stmt);
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("Session not found or expired for token");
        return -1;
    } else {
        log_error("Error looking up session by token");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_session_close(db_handle_t *db, const char *session_token) {
    if (!db || !session_token) {
        log_error("Invalid arguments to oauth_session_close");
        return -1;
    }

    /* Hash session token for lookup */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(session_token, strlen(session_token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash session token");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_BROWSER " "
        "SET is_closed = " BOOL_TRUE ", "
        "closed_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE session_token = " P"1 "
        "AND is_closed = " BOOL_FALSE " "
        "RETURNING id";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_session_close statement");
        return -1;
    }

    db_bind_text(stmt, 1, token_hash, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        db_finalize(stmt);
        log_info("Closed browser session for token");
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("Session not found or already closed");
        return -1;
    } else {
        log_error("Error closing session");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_session_set_mfa_completed(db_handle_t *db, const char *session_token) {
    if (!db || !session_token) {
        log_error("Invalid arguments to oauth_session_set_mfa_completed");
        return -1;
    }

    /* Hash session token for lookup */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(session_token, strlen(session_token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash session token");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_BROWSER " "
        "SET mfa_completed = " BOOL_TRUE ", "
        "updated_at = " NOW " "
        "WHERE session_token = " P"1 "
        "AND is_closed = " BOOL_FALSE " "
        "RETURNING id";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_session_set_mfa_completed statement");
        return -1;
    }

    db_bind_text(stmt, 1, token_hash, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        db_finalize(stmt);
        log_info("MFA completed for session");
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("Session not found or already closed");
        return -1;
    } else {
        log_error("Error setting MFA completed on session");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_auth_code_create(db_handle_t *db, long long client_pin,
                            const unsigned char *client_id,
                            long long user_account_pin,
                            const unsigned char *user_account_id,
                            const char *code,
                            const char *code_challenge,
                            const char *code_challenge_method,
                            int ttl_seconds,
                            unsigned char *out_id) {
    if (!db || !client_id || !user_account_id || !code || !out_id) {
        log_error("Invalid arguments to oauth_auth_code_create");
        return -1;
    }

    /* Generate UUID for authorization code */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for authorization code");
        return -1;
    }

    /* Build TTL string for SQL */
    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "%d", ttl_seconds);

    const char *sql =
        "INSERT INTO " TBL_AUTHORIZATION_CODE " "
        "(id, client_pin, user_account_pin, code, "
        "code_challenge, code_challenge_method, issued_at, expected_expiry, is_exchanged) "
        "VALUES ("
        P"1, " P"2, " P"3, " P"4, " P"5, " P"6, "
        NOW ", " INTERVAL_SECONDS(P"7") ", " BOOL_FALSE
        ") "
        "RETURNING id";

    /* Hash authorization code for storage */
    char code_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(code, strlen(code),
                          code_hash, sizeof(code_hash)) != 0) {
        log_error("Failed to hash authorization code");
        return -1;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_auth_code_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_int64(stmt, 2, client_pin);
    db_bind_int64(stmt, 3, user_account_pin);
    db_bind_text(stmt, 4, code_hash, -1);

    if (code_challenge != NULL) {
        db_bind_text(stmt, 5, code_challenge, -1);
    } else {
        db_bind_null(stmt, 5);
    }

    if (code_challenge_method != NULL) {
        db_bind_text(stmt, 6, code_challenge_method, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    db_bind_text(stmt, 7, ttl_str, -1);

    /* Execute and get returned id */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Copy UUID to output */
        memcpy(out_id, id, 16);

        db_finalize(stmt);
        return 0;
    } else {
        char client_id_hex[33];
        bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));
        log_error("Failed to create authorization code for client_id=%s",
                  client_id_hex);
        db_finalize(stmt);
        return -1;
    }
}

int oauth_auth_code_consume(db_handle_t *db, const char *code,
                             oauth_auth_code_data_t *out_data) {
    if (!db || !code || !out_data) {
        log_error("Invalid arguments to oauth_auth_code_consume");
        return -1;
    }

    /* Hash authorization code for lookup */
    char code_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(code, strlen(code),
                          code_hash, sizeof(code_hash)) != 0) {
        log_error("Failed to hash authorization code");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_AUTHORIZATION_CODE " "
        "SET is_exchanged = " BOOL_TRUE ", "
        "exchanged_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE code = " P"1 "
        "AND is_exchanged = " BOOL_FALSE " "
        "AND expected_expiry > " NOW " "
        "RETURNING id, client_pin, user_account_pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_auth_code_consume statement");
        return -1;
    }

    db_bind_text(stmt, 1, code_hash, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract id (blob) */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len != 16) {
            log_error("Invalid authorization code ID length: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_data->id, id_blob, 16);

        /* Extract scalar fields */
        out_data->client_pin = db_column_int64(stmt, 1);
        out_data->user_account_pin = db_column_int64(stmt, 2);

        db_finalize(stmt);
        log_info("Consumed authorization code");
        return 0;
    } else if (rc == DB_DONE) {
        /* No rows updated - check if already exchanged (replay attack) */
        db_finalize(stmt);

        const char *check_sql =
            "SELECT id FROM " TBL_AUTHORIZATION_CODE " "
            "WHERE code = " P"1 AND is_exchanged = " BOOL_TRUE " "
            "LIMIT 1";

        db_stmt_t *check_stmt = NULL;
        if (db_prepare(db, &check_stmt, check_sql) != 0) {
            log_error("Failed to prepare replay check statement");
            return -1;
        }

        db_bind_text(check_stmt, 1, code_hash, -1);
        int check_rc = db_step(check_stmt);

        if (check_rc == DB_ROW) {
            /* Extract authorization code ID for chain revocation */
            const unsigned char *id_blob = db_column_blob(check_stmt, 0);
            int blob_len = db_column_bytes(check_stmt, 0);
            if (blob_len == 16) {
                memcpy(out_data->id, id_blob, 16);
            }
            db_finalize(check_stmt);
            log_warn("Authorization code replay attack detected");
            return 1;  /* Already exchanged - replay attack */
        } else {
            db_finalize(check_stmt);
            log_debug("Authorization code not found or expired");
            return -1;  /* Not found or expired */
        }
    } else {
        log_error("Error consuming authorization code");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_token_create_access(db_handle_t *db, long long resource_server_pin,
                               long long client_pin, long long user_account_pin,
                               const unsigned char *authorization_code_id,
                               const unsigned char *refresh_token_id,
                               const char *token, const char *scopes,
                               int ttl_seconds,
                               unsigned char *out_id) {
    if (!db || !token || !out_id) {
        log_error("Invalid arguments to oauth_token_create_access");
        return -1;
    }

    /* Generate UUID for access token */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for access token");
        return -1;
    }

    /* Build TTL string for SQL */
    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "%d", ttl_seconds);

    const char *sql =
        "INSERT INTO " TBL_ACCESS_TOKEN " "
        "(id, resource_server_pin, client_pin, user_account_pin, "
        "authorization_code_id, refresh_token_id, token, scopes, "
        "issued_at, expected_expiry, is_revoked) "
        "VALUES ("
        P"1, " P"2, " P"3, " P"4, " P"5, " P"6, " P"7, " P"8, "
        NOW ", " INTERVAL_SECONDS(P"9") ", " BOOL_FALSE
        ") "
        "RETURNING id";

    /* Hash access token for storage */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(token, strlen(token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash access token");
        return -1;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_token_create_access statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_int64(stmt, 2, resource_server_pin);
    db_bind_int64(stmt, 3, client_pin);

    /* Bind user_account_pin (NULL if 0, for client_credentials grant) */
    if (user_account_pin > 0) {
        db_bind_int64(stmt, 4, user_account_pin);
    } else {
        db_bind_null(stmt, 4);
    }

    /* Bind authorization_code_id (NULL for refresh/client_credentials) */
    if (authorization_code_id != NULL) {
        db_bind_blob(stmt, 5, authorization_code_id, 16);
    } else {
        db_bind_null(stmt, 5);
    }

    /* Bind refresh_token_id (NULL for auth_code/client_credentials) */
    if (refresh_token_id != NULL) {
        db_bind_blob(stmt, 6, refresh_token_id, 16);
    } else {
        db_bind_null(stmt, 6);
    }

    db_bind_text(stmt, 7, token_hash, -1);

    /* Bind scopes (optional) */
    if (scopes != NULL) {
        db_bind_text(stmt, 8, scopes, -1);
    } else {
        db_bind_null(stmt, 8);
    }

    db_bind_text(stmt, 9, ttl_str, -1);

    /* Execute and get returned id */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Copy UUID to output */
        memcpy(out_id, id, 16);

        db_finalize(stmt);
        /* Entity details logged at handler level - skipping here for performance */
        log_info("Created access token (ttl=%d)", ttl_seconds);
        return 0;
    } else {
        log_error("Failed to create access token");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_token_create_refresh(db_handle_t *db, long long client_pin,
                                long long user_account_pin,
                                const unsigned char *authorization_code_id,
                                const char *token, const char *scopes,
                                int ttl_seconds,
                                unsigned char *out_id) {
    if (!db || !authorization_code_id || !token || !out_id) {
        log_error("Invalid arguments to oauth_token_create_refresh");
        return -1;
    }

    /* Generate UUID for refresh token */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for refresh token");
        return -1;
    }

    /* Build TTL string for SQL */
    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "%d", ttl_seconds);

    const char *sql =
        "INSERT INTO " TBL_REFRESH_TOKEN " "
        "(id, client_pin, user_account_pin, authorization_code_id, "
        "origin_refresh_token_id, generation, token, scopes, issued_at, "
        "expected_expiry, is_exchanged, is_revoked) "
        "VALUES ("
        P"1, " P"2, " P"3, " P"4, NULL, 1, " P"5, " P"6, " NOW ", "
        "CASE WHEN " P"7 = -1 THEN NULL ELSE " INTERVAL_SECONDS(P"7") " END, "
        BOOL_FALSE ", " BOOL_FALSE
        ") "
        "RETURNING id";

    /* Hash refresh token for storage */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(token, strlen(token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash refresh token");
        return -1;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_token_create_refresh statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_int64(stmt, 2, client_pin);
    db_bind_int64(stmt, 3, user_account_pin);
    db_bind_blob(stmt, 4, authorization_code_id, 16);
    db_bind_text(stmt, 5, token_hash, -1);

    /* Bind scopes (optional) */
    if (scopes != NULL) {
        db_bind_text(stmt, 6, scopes, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    db_bind_text(stmt, 7, ttl_str, -1);

    /* Execute and get returned id */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Copy UUID to output */
        memcpy(out_id, id, 16);

        db_finalize(stmt);
        /* Entity details logged at handler level - skipping here for performance */
        log_info("Created refresh token (generation 1)");
        return 0;
    } else {
        log_error("Failed to create refresh token");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_token_rotate_refresh(db_handle_t *db, const char *old_token,
                                const char *new_token, int ttl_seconds,
                                oauth_refresh_token_data_t *out_data,
                                unsigned char *out_new_id) {
    if (!db || !old_token || !new_token || !out_data || !out_new_id) {
        log_error("Invalid arguments to oauth_token_rotate_refresh");
        return -1;
    }

    /* Hash both tokens upfront */
    char old_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(old_token, strlen(old_token),
                          old_hash, sizeof(old_hash)) != 0) {
        log_error("Failed to hash old refresh token");
        return -1;
    }

    char new_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(new_token, strlen(new_token),
                          new_hash, sizeof(new_hash)) != 0) {
        log_error("Failed to hash new refresh token");
        return -1;
    }

    /* Step 1: Consume old refresh token */
    const char *update_sql =
        "UPDATE " TBL_REFRESH_TOKEN " "
        "SET is_exchanged = " BOOL_TRUE ", "
        "exchanged_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE token = " P"1 "
        "AND is_exchanged = " BOOL_FALSE " "
        "AND is_revoked = " BOOL_FALSE " "
        "AND (expected_expiry IS NULL OR expected_expiry > " NOW ") "
        "RETURNING id, origin_refresh_token_id, client_pin, user_account_pin, "
        "authorization_code_id, generation, scopes";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, update_sql) != 0) {
        log_error("Failed to prepare oauth_token_rotate_refresh UPDATE statement");
        return -1;
    }

    db_bind_text(stmt, 1, old_hash, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract old token data */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len != 16) {
            log_error("Invalid refresh token ID length: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_data->id, id_blob, 16);

        /* Extract origin_refresh_token_id (NULL for generation 1) */
        if (db_column_type(stmt, 1) == DB_NULL) {
            /* Generation 1: origin is self */
            memcpy(out_data->origin_id, out_data->id, 16);
        } else {
            const unsigned char *origin_blob = db_column_blob(stmt, 1);
            int origin_len = db_column_bytes(stmt, 1);
            if (origin_len != 16) {
                log_error("Invalid origin refresh token ID length: %d", origin_len);
                db_finalize(stmt);
                return -1;
            }
            memcpy(out_data->origin_id, origin_blob, 16);
        }

        out_data->client_pin = db_column_int64(stmt, 2);
        out_data->user_account_pin = db_column_int64(stmt, 3);

        /* authorization_code_id: set on generation-1 tokens, NULL on rotated tokens */
        if (db_column_type(stmt, 4) != DB_NULL) {
            const unsigned char *auth_code_blob = db_column_blob(stmt, 4);
            int auth_code_len = db_column_bytes(stmt, 4);
            if (auth_code_len != 16) {
                log_error("Invalid authorization code ID length: %d", auth_code_len);
                db_finalize(stmt);
                return -1;
            }
            memcpy(out_data->authorization_code_id, auth_code_blob, 16);
        } else {
            memset(out_data->authorization_code_id, 0, 16);
        }

        out_data->generation = db_column_int(stmt, 5);

        /* Extract scopes (optional) */
        const char *scopes = (const char *)db_column_text(stmt, 6);
        if (scopes) {
            str_copy(out_data->scopes, sizeof(out_data->scopes), scopes);
        } else {
            out_data->scopes[0] = '\0';
        }

        db_finalize(stmt);

        /* Step 2: Create new refresh token */
        unsigned char new_id[16];
        if (crypto_random_bytes(new_id, sizeof(new_id)) != 0) {
            log_error("Failed to generate UUID for new refresh token");
            return -1;
        }

        char ttl_str[32];
        snprintf(ttl_str, sizeof(ttl_str), "%d", ttl_seconds);

        const char *insert_sql =
            "INSERT INTO " TBL_REFRESH_TOKEN " "
            "(id, client_pin, user_account_pin, authorization_code_id, "
            "origin_refresh_token_id, generation, token, scopes, issued_at, "
            "expected_expiry, is_exchanged, is_revoked) "
            "VALUES ("
            P"1, " P"2, " P"3, " P"4, " P"5, " P"6, " P"7, " P"8, " NOW ", "
            "CASE WHEN " P"9 = -1 THEN NULL ELSE " INTERVAL_SECONDS(P"9") " END, "
            BOOL_FALSE ", " BOOL_FALSE
            ") "
            "RETURNING id";

        db_stmt_t *insert_stmt = NULL;
        if (db_prepare(db, &insert_stmt, insert_sql) != 0) {
            log_error("Failed to prepare oauth_token_rotate_refresh INSERT statement");
            return -1;
        }

        db_bind_blob(insert_stmt, 1, new_id, sizeof(new_id));
        db_bind_int64(insert_stmt, 2, out_data->client_pin);
        db_bind_int64(insert_stmt, 3, out_data->user_account_pin);
        db_bind_null(insert_stmt, 4);  /* authorization_code_id only on initial token from auth code exchange */
        db_bind_blob(insert_stmt, 5, out_data->origin_id, 16);
        db_bind_int(insert_stmt, 6, out_data->generation + 1);
        db_bind_text(insert_stmt, 7, new_hash, -1);

        if (out_data->scopes[0] != '\0') {
            db_bind_text(insert_stmt, 8, out_data->scopes, -1);
        } else {
            db_bind_null(insert_stmt, 8);
        }

        db_bind_text(insert_stmt, 9, ttl_str, -1);

        int insert_rc = db_step(insert_stmt);

        if (insert_rc == DB_ROW) {
            memcpy(out_new_id, new_id, 16);
            db_finalize(insert_stmt);
            /* Entity details logged at handler level - skipping here for performance */
            log_info("Rotated refresh token: generation %d -> %d",
                     out_data->generation, out_data->generation + 1);
            return 0;
        } else {
            log_error("Failed to insert new refresh token during rotation");
            db_finalize(insert_stmt);
            return -1;
        }
    } else if (rc == DB_DONE) {
        /* No rows updated - check if already exchanged (replay attack) */
        db_finalize(stmt);

        const char *check_sql =
            "SELECT origin_refresh_token_id FROM " TBL_REFRESH_TOKEN " "
            "WHERE token = " P"1 AND is_exchanged = " BOOL_TRUE " "
            "LIMIT 1";

        db_stmt_t *check_stmt = NULL;
        if (db_prepare(db, &check_stmt, check_sql) != 0) {
            log_error("Failed to prepare refresh token replay check statement");
            return -1;
        }

        db_bind_text(check_stmt, 1, old_hash, -1);
        int check_rc = db_step(check_stmt);

        if (check_rc == DB_ROW) {
            /* Extract origin_refresh_token_id for chain revocation */
            if (db_column_type(check_stmt, 0) != DB_NULL) {
                const unsigned char *origin_blob = db_column_blob(check_stmt, 0);
                int blob_len = db_column_bytes(check_stmt, 0);
                if (blob_len == 16) {
                    memcpy(out_data->origin_id, origin_blob, 16);
                }
            }
            db_finalize(check_stmt);
            log_warn("Refresh token replay attack detected");
            return 1;  /* Already exchanged - replay attack */
        } else {
            db_finalize(check_stmt);
            log_debug("Refresh token not found, expired, or revoked");
            return -1;  /* Not found, expired, or revoked */
        }
    } else {
        log_error("Error rotating refresh token");
        db_finalize(stmt);
        return -1;
    }
}

int oauth_client_authenticate(db_handle_t *db,
                               const unsigned char *client_id,
                               const unsigned char *client_key_id,
                               const char *secret,
                               const char *source_ip,
                               const char *user_agent,
                               long long *out_pin) {
    if (!db || !client_id || !client_key_id || !secret || !out_pin) {
        log_error("Invalid arguments to oauth_client_authenticate");
        return -1;
    }

    const char *sql =
        "SELECT CK.pin, CK.salt, CK.hash_iterations, CK.secret_hash, C.pin, "
        "C.secret_rotation_seconds, " UNIX_TS("CK.generated_at") " "
        "FROM " TBL_CLIENT_KEY " CK "
        "JOIN " TBL_CLIENT " C ON C.pin = CK.client_pin "
        "JOIN " TBL_ORGANIZATION " O ON O.pin = C.organization_pin "
        "WHERE C.id = " P"1 "
        "AND CK.id = " P"2 "
        "AND C.is_active = " BOOL_TRUE " "
        "AND O.is_active = " BOOL_TRUE " "
        "AND CK.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_client_authenticate statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_blob(stmt, 2, client_key_id, 16);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Client key not found or inactive");
        return 0;  /* Not found = invalid credentials */
    }

    long long client_key_pin = db_column_int64(stmt, 0);
    const char *salt_ptr = (const char *)db_column_text(stmt, 1);
    int iterations = db_column_int(stmt, 2);
    const char *hash_ptr = (const char *)db_column_text(stmt, 3);
    long long client_pin = db_column_int64(stmt, 4);
    int secret_rotation_seconds = (db_column_type(stmt, 5) == DB_NULL)
        ? -1 : db_column_int(stmt, 5);
    time_t key_generated_at = (time_t)db_column_int64(stmt, 6);

    /* Defensive check - these fields are NOT NULL in schema, but verify anyway */
    if (!salt_ptr || !hash_ptr) {
        log_error("NULL salt or hash in client_key record (should be impossible)");
        db_finalize(stmt);
        return -1;
    }

    /* Copy salt and hash before finalize — column pointers are invalid after */
    char salt[256], hash[256];
    snprintf(salt, sizeof(salt), "%s", salt_ptr);
    snprintf(hash, sizeof(hash), "%s", hash_ptr);

    db_finalize(stmt);

    /* Verify secret against hash */
    int valid = crypto_password_verify(secret, strlen(secret),
                                        salt, iterations, hash);

    if (valid != 1) {
        char client_id_hex[33];
        bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));
        log_warn("Invalid client secret for client_id=%s", client_id_hex);
        return 0;
    }

    /* Check key rotation expiry */
    if (secret_rotation_seconds > 0) {
        time_t key_age = time(NULL) - key_generated_at;
        if (key_age > secret_rotation_seconds) {
            char client_id_hex[33];
            bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));
            log_warn("Client key expired by rotation policy for client_id=%s: age=%ld, max=%d",
                     client_id_hex, (long)key_age, secret_rotation_seconds);
            return 0;
        }
    }

    /* Log successful authentication */
    const char *log_sql =
        "INSERT INTO " TBL_CLIENT_KEY_USAGE " "
        "(client_key_pin, authenticated_at, source_ip, user_agent) "
        "VALUES (" P"1, " NOW ", " P"2, " P"3)";

    db_stmt_t *log_stmt = NULL;
    if (db_prepare(db, &log_stmt, log_sql) == 0) {
        db_bind_int64(log_stmt, 1, client_key_pin);

        if (source_ip) {
            db_bind_text(log_stmt, 2, source_ip, -1);
        } else {
            db_bind_null(log_stmt, 2);
        }

        if (user_agent) {
            db_bind_text(log_stmt, 3, user_agent, -1);
        } else {
            db_bind_null(log_stmt, 3);
        }

        db_step(log_stmt);
        db_finalize(log_stmt);
    }

    *out_pin = client_pin;
    char client_id_hex[33];
    bytes_to_hex(client_id, 16, client_id_hex, sizeof(client_id_hex));
    log_info("Client authenticated successfully: client_id=%s", client_id_hex);
    return 1;
}

int oauth_resolve_resource_server(db_handle_t *db, long long client_pin,
                                    const char *resource_address,
                                    long long *out_resource_server_pin,
                                    unsigned char *out_resource_server_id) {
    if (!db || !out_resource_server_pin || !out_resource_server_id) {
        log_error("Invalid arguments to oauth_resolve_resource_server");
        return -1;
    }

    db_stmt_t *stmt = NULL;

    if (resource_address) {
        /* Path 1: Explicit resource address provided (RFC 8707) */
        /* Validate all entities (client, resource_server, organization) are active and linked */
        const char *sql =
            "SELECT RS.pin, RS.id "
            "FROM " TBL_RESOURCE_SERVER " RS "
            "JOIN " TBL_CLIENT_RESOURCE_SERVER " CRS ON CRS.resource_server_pin = RS.pin "
            "JOIN " TBL_CLIENT " C ON C.pin = CRS.client_pin "
            "JOIN " TBL_ORGANIZATION " O ON O.pin = C.organization_pin "
            "WHERE C.pin = " P"1 "
            "AND C.is_active = " BOOL_TRUE " "
            "AND lower(RS.address) = lower(" P"2) "
            "AND RS.is_active = " BOOL_TRUE " "
            "AND O.is_active = " BOOL_TRUE " "
            "LIMIT 1";

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare resource server lookup by address");
            return -1;
        }

        db_bind_int64(stmt, 1, client_pin);
        db_bind_text(stmt, 2, resource_address, -1);

        int rc = db_step(stmt);

        if (rc == DB_ROW) {
            *out_resource_server_pin = db_column_int64(stmt, 0);
            const unsigned char *id_blob = db_column_blob(stmt, 1);
            if (id_blob) memcpy(out_resource_server_id, id_blob, 16);
            db_finalize(stmt);
            log_debug("Resolved resource server by address: address='%s', pin=%lld",
                     resource_address, *out_resource_server_pin);
            return 0;
        } else if (rc == DB_DONE) {
            db_finalize(stmt);
            log_error("Resource server not found, inactive, or client not linked: address='%s'",
                     resource_address);
            return -1;
        } else {
            log_error("Error looking up resource server by address");
            db_finalize(stmt);
            return -1;
        }
    } else {
        /* Path 2: No resource specified, fallback to single linked active resource */
        /* Subquery enforces exactly 1 active link; outer join retrieves UUID */
        const char *sql =
            "SELECT sub.pin, RS.id "
            "FROM ("
            "  SELECT MIN(RS2.pin) AS pin "
            "  FROM " TBL_RESOURCE_SERVER " RS2 "
            "  JOIN " TBL_CLIENT_RESOURCE_SERVER " CRS ON CRS.resource_server_pin = RS2.pin "
            "  JOIN " TBL_CLIENT " C ON C.pin = CRS.client_pin "
            "  JOIN " TBL_ORGANIZATION " O ON O.pin = C.organization_pin "
            "  WHERE C.pin = " P"1 "
            "  AND C.is_active = " BOOL_TRUE " "
            "  AND RS2.is_active = " BOOL_TRUE " "
            "  AND O.is_active = " BOOL_TRUE " "
            "  HAVING COUNT(*) = 1"
            ") sub "
            "JOIN " TBL_RESOURCE_SERVER " RS ON RS.pin = sub.pin";

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare resource server fallback query");
            return -1;
        }

        db_bind_int64(stmt, 1, client_pin);

        int rc = db_step(stmt);

        if (rc == DB_ROW) {
            *out_resource_server_pin = db_column_int64(stmt, 0);
            const unsigned char *id_blob = db_column_blob(stmt, 1);
            if (id_blob) memcpy(out_resource_server_id, id_blob, 16);
            db_finalize(stmt);
            log_debug("Resolved single linked resource server: pin=%lld",
                     *out_resource_server_pin);
            return 0;
        } else if (rc == DB_DONE) {
            /* No result at all */
            db_finalize(stmt);
            log_error("Client has no linked active resource servers");
            return -1;
        } else {
            log_error("Error querying linked resource servers");
            db_finalize(stmt);
            return -1;
        }
    }
}

int oauth_resource_server_authenticate(db_handle_t *db,
                                        const unsigned char *resource_server_id,
                                        const unsigned char *resource_server_key_id,
                                        const char *secret,
                                        const char *source_ip,
                                        const char *user_agent,
                                        long long *out_pin) {
    if (!db || !resource_server_id || !resource_server_key_id || !secret || !out_pin) {
        log_error("Invalid arguments to oauth_resource_server_authenticate");
        return -1;
    }

    const char *sql =
        "SELECT RSK.pin, RSK.salt, RSK.hash_iterations, RSK.secret_hash, RS.pin "
        "FROM " TBL_RESOURCE_SERVER_KEY " RSK "
        "JOIN " TBL_RESOURCE_SERVER " RS ON RS.pin = RSK.resource_server_pin "
        "JOIN " TBL_ORGANIZATION " O ON O.pin = RS.organization_pin "
        "WHERE RS.id = " P"1 "
        "AND RSK.id = " P"2 "
        "AND RS.is_active = " BOOL_TRUE " "
        "AND O.is_active = " BOOL_TRUE " "
        "AND RSK.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_resource_server_authenticate statement");
        return -1;
    }

    db_bind_blob(stmt, 1, resource_server_id, 16);
    db_bind_blob(stmt, 2, resource_server_key_id, 16);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Resource server key not found or inactive");
        return 0;  /* Not found = invalid credentials */
    }

    long long resource_server_key_pin = db_column_int64(stmt, 0);
    const char *salt_ptr = (const char *)db_column_text(stmt, 1);
    int iterations = db_column_int(stmt, 2);
    const char *hash_ptr = (const char *)db_column_text(stmt, 3);
    long long resource_server_pin = db_column_int64(stmt, 4);

    /* Defensive check - these fields are NOT NULL in schema, but verify anyway */
    if (!salt_ptr || !hash_ptr) {
        log_error("NULL salt or hash in resource_server_key record (should be impossible)");
        db_finalize(stmt);
        return -1;
    }

    /* Copy salt and hash before finalize — column pointers are invalid after */
    char salt[256], hash[256];
    snprintf(salt, sizeof(salt), "%s", salt_ptr);
    snprintf(hash, sizeof(hash), "%s", hash_ptr);

    db_finalize(stmt);

    /* Verify secret against hash */
    int valid = crypto_password_verify(secret, strlen(secret),
                                        salt, iterations, hash);

    if (valid != 1) {
        char resource_server_id_hex[33];
        bytes_to_hex(resource_server_id, 16, resource_server_id_hex, sizeof(resource_server_id_hex));
        log_warn("Invalid resource server secret for resource_server_id=%s", resource_server_id_hex);
        return 0;
    }

    /* Log successful authentication */
    const char *log_sql =
        "INSERT INTO " TBL_RESOURCE_SERVER_KEY_USAGE " "
        "(resource_server_key_pin, authenticated_at, source_ip, user_agent) "
        "VALUES (" P"1, " NOW ", " P"2, " P"3)";

    db_stmt_t *log_stmt = NULL;
    if (db_prepare(db, &log_stmt, log_sql) == 0) {
        db_bind_int64(log_stmt, 1, resource_server_key_pin);

        if (source_ip) {
            db_bind_text(log_stmt, 2, source_ip, -1);
        } else {
            db_bind_null(log_stmt, 2);
        }

        if (user_agent) {
            db_bind_text(log_stmt, 3, user_agent, -1);
        } else {
            db_bind_null(log_stmt, 3);
        }

        db_step(log_stmt);
        db_finalize(log_stmt);
    }

    *out_pin = resource_server_pin;
    char resource_server_id_hex[33];
    bytes_to_hex(resource_server_id, 16, resource_server_id_hex, sizeof(resource_server_id_hex));
    log_info("Resource server authenticated successfully: resource_server_id=%s", resource_server_id_hex);
    return 1;
}

int oauth_introspect_token(db_handle_t *db,
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
    (void)token_type_hint;  /* Optional hint per RFC 7662, currently unused */

    if (!db || !token || !out_active) {
        log_error("Invalid arguments to oauth_introspect_token");
        return -1;
    }

    /* Initialize outputs to inactive state */
    *out_active = 0;
    if (out_scope) *out_scope = NULL;
    if (out_client_id) memset(out_client_id, 0, 16);
    if (out_user_id) memset(out_user_id, 0, 16);
    if (out_resource_server_id) memset(out_resource_server_id, 0, 16);
    if (out_expires_at) *out_expires_at = 0;
    if (out_issued_at) *out_issued_at = 0;

    /* Hash access token for lookup */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(token, strlen(token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash token for introspection");
        return -1;
    }

    /* Introspection is primarily for access tokens (resource servers validate them)
     * Refresh tokens are client-facing, not typically introspected by resource servers
     *
     * JOIN to return external UUIDs instead of internal PINs (PINs must never be
     * exposed via API - they are internal database identifiers) */

    const char *sql =
        "SELECT at.scopes, c.id, ua.id, rs.id, "
        UNIX_TS("at.expected_expiry") ", " UNIX_TS("at.issued_at") " "
        "FROM " TBL_ACCESS_TOKEN " at "
        "INNER JOIN " TBL_CLIENT " c ON c.pin = at.client_pin "
        "INNER JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = at.resource_server_pin "
        "LEFT JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = at.user_account_pin "
        "WHERE at.token = " P"1 "
        "AND at.resource_server_pin = " P"2 "
        "AND at.is_revoked = " BOOL_FALSE " "
        "AND c.is_active = " BOOL_TRUE " "
        "AND (at.expected_expiry IS NULL OR at.expected_expiry > " NOW ") "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare oauth_introspect_token statement");
        return -1;
    }

    db_bind_text(stmt, 1, token_hash, -1);
    db_bind_int64(stmt, 2, resource_server_pin);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        /* Token not found, expired, revoked, or wrong resource server */
        log_debug("Token introspection: token not active");
        return 0;  /* Not an error, just inactive token */
    }

    /* Token is active - extract details */
    *out_active = 1;

    /* Extract scope (may be NULL) */
    if (out_scope) {
        const char *scopes = db_column_text(stmt, 0);
        if (scopes && db_column_type(stmt, 0) != DB_NULL) {
            *out_scope = str_dup(scopes);
        }
    }

    /* Extract UUIDs (16-byte blobs) */
    if (out_client_id) {
        const void *blob = db_column_blob(stmt, 1);
        if (blob) memcpy(out_client_id, blob, 16);
    }

    if (out_user_id) {
        /* May be NULL for client_credentials tokens (LEFT JOIN) */
        if (db_column_type(stmt, 2) != DB_NULL) {
            const void *blob = db_column_blob(stmt, 2);
            if (blob) memcpy(out_user_id, blob, 16);
        }
    }

    if (out_resource_server_id) {
        const void *blob = db_column_blob(stmt, 3);
        if (blob) memcpy(out_resource_server_id, blob, 16);
    }

    if (out_expires_at) {
        /* Unix timestamp from UNIX_TS() */
        if (db_column_type(stmt, 4) != DB_NULL) {
            *out_expires_at = db_column_int64(stmt, 4);
        }
    }

    if (out_issued_at) {
        /* Unix timestamp from UNIX_TS() */
        if (db_column_type(stmt, 5) != DB_NULL) {
            *out_issued_at = db_column_int64(stmt, 5);
        }
    }

    db_finalize(stmt);

    log_info("Token introspection: token is active");
    return 0;
}

int oauth_revoke_token(db_handle_t *db,
                       const char *token,
                       const char *token_type_hint,
                       long long client_pin) {
    if (!db || !token) {
        log_error("Invalid arguments to oauth_revoke_token");
        return -1;
    }

    /* Hash token once for all revocation queries */
    char token_hash[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex(token, strlen(token),
                          token_hash, sizeof(token_hash)) != 0) {
        log_error("Failed to hash token for revocation");
        return -1;
    }

    int revoked = 0;

    /* Determine search order based on hint */
    int try_refresh_first = 1;
    if (token_type_hint && strcmp(token_type_hint, "access_token") == 0) {
        try_refresh_first = 0;
    }

    /* Try revoking as refresh token */
    if (try_refresh_first) {
        const char *refresh_sql =
            "UPDATE " TBL_REFRESH_TOKEN " "
            "SET is_revoked = " BOOL_TRUE ", "
            "revoked_at = " NOW ", "
            "updated_at = " NOW " "
            "WHERE token = " P"1 "
            "AND client_pin = " P"2 "
            "AND is_revoked = " BOOL_FALSE " "
            "RETURNING id";

        db_stmt_t *stmt = NULL;
        if (db_prepare(db, &stmt, refresh_sql) == 0) {
            db_bind_text(stmt, 1, token_hash, -1);
            db_bind_int64(stmt, 2, client_pin);

            if (db_step(stmt) == DB_ROW) {
                revoked = 1;
            }

            db_finalize(stmt);
        }

        if (revoked) {
            log_info("Revoked refresh token");
            return 0;
        }
    }

    /* Try revoking as access token */
    const char *access_sql =
        "UPDATE " TBL_ACCESS_TOKEN " "
        "SET is_revoked = " BOOL_TRUE ", "
        "revoked_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE token = " P"1 "
        "AND client_pin = " P"2 "
        "AND is_revoked = " BOOL_FALSE " "
        "RETURNING id";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, access_sql) == 0) {
        db_bind_text(stmt, 1, token_hash, -1);
        db_bind_int64(stmt, 2, client_pin);

        if (db_step(stmt) == DB_ROW) {
            revoked = 1;
        }

        db_finalize(stmt);
    }

    if (revoked) {
        log_info("Revoked access token");
        return 0;
    }

    /* If hint was access_token and we didn't find it, try refresh token as fallback */
    if (!try_refresh_first) {
        const char *refresh_sql =
            "UPDATE " TBL_REFRESH_TOKEN " "
            "SET is_revoked = " BOOL_TRUE ", "
            "revoked_at = " NOW ", "
            "updated_at = " NOW " "
            "WHERE token = " P"1 "
            "AND client_pin = " P"2 "
            "AND is_revoked = " BOOL_FALSE " "
            "RETURNING id";

        db_stmt_t *fallback_stmt = NULL;
        if (db_prepare(db, &fallback_stmt, refresh_sql) == 0) {
            db_bind_text(fallback_stmt, 1, token_hash, -1);
            db_bind_int64(fallback_stmt, 2, client_pin);

            if (db_step(fallback_stmt) == DB_ROW) {
                revoked = 1;
            }

            db_finalize(fallback_stmt);
        }

        if (revoked) {
            log_info("Revoked refresh token");
            return 0;
        }
    }

    /* Per RFC 7009: return success even if token not found (prevents enumeration) */
    log_debug("Token not found or already revoked");
    return 0;
}

int oauth_revoke_token_chain(db_handle_t *db,
                              const unsigned char *origin_id,
                              int is_authorization_code,
                              int *out_refresh_revoked,
                              int *out_access_revoked) {
    if (!db || !origin_id) {
        log_error("Invalid arguments to oauth_revoke_token_chain");
        return -1;
    }

    int refresh_count = 0;
    int access_count = 0;

    /* Begin transaction for atomicity */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction for token chain revocation");
        return -1;
    }

    /* Resolve chain origin: the gen-1 refresh token ID that anchors the chain.
     * Gen 1 has origin_refresh_token_id = NULL in DB, gen 2+ point back to gen 1.
     * For auth code replay, look up gen-1 by authorization_code_id first. */
    unsigned char chain_origin[16];

    if (is_authorization_code) {
        const char *lookup_sql =
            "SELECT id FROM " TBL_REFRESH_TOKEN " "
            "WHERE authorization_code_id = " P"1 "
            "LIMIT 1";

        db_stmt_t *lookup_stmt = NULL;
        if (db_prepare(db, &lookup_stmt, lookup_sql) != 0) {
            db_execute_trusted(db, "ROLLBACK");
            log_error("Failed to prepare chain origin lookup");
            return -1;
        }

        db_bind_blob(lookup_stmt, 1, origin_id, 16);

        if (db_step(lookup_stmt) == DB_ROW) {
            const unsigned char *id_blob = db_column_blob(lookup_stmt, 0);
            int blob_len = db_column_bytes(lookup_stmt, 0);
            if (blob_len != 16) {
                db_finalize(lookup_stmt);
                db_execute_trusted(db, "ROLLBACK");
                log_error("Invalid refresh token ID length in chain lookup");
                return -1;
            }
            memcpy(chain_origin, id_blob, 16);
        } else {
            db_finalize(lookup_stmt);
            db_execute_trusted(db, "ROLLBACK");
            log_debug("No refresh token found for authorization code");
            if (out_refresh_revoked) *out_refresh_revoked = 0;
            if (out_access_revoked) *out_access_revoked = 0;
            return 0;
        }
        db_finalize(lookup_stmt);
    } else {
        /* origin_id is already the gen-1 refresh token ID */
        memcpy(chain_origin, origin_id, 16);
    }

    /* Revoke entire chain: gen 1 (id = origin) + gen 2+ (origin_refresh_token_id = origin) */

    /* Step 1: Revoke access tokens via subquery */
    const char *access_sql =
        "UPDATE " TBL_ACCESS_TOKEN " "
        "SET is_revoked = " BOOL_TRUE ", "
        "revoked_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE refresh_token_id IN ("
            "SELECT id FROM " TBL_REFRESH_TOKEN " "
            "WHERE id = " P"1" " OR origin_refresh_token_id = " P"1"
        ") AND is_revoked = " BOOL_FALSE " "
        "RETURNING id";

    db_stmt_t *access_stmt = NULL;
    if (db_prepare(db, &access_stmt, access_sql) != 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to prepare access token revocation");
        return -1;
    }

    db_bind_blob(access_stmt, 1, chain_origin, 16);
    while (db_step(access_stmt) == DB_ROW) {
        access_count++;
    }
    db_finalize(access_stmt);

    /* Step 2: Revoke refresh tokens */
    const char *refresh_sql =
        "UPDATE " TBL_REFRESH_TOKEN " "
        "SET is_revoked = " BOOL_TRUE ", "
        "revoked_at = " NOW ", "
        "updated_at = " NOW " "
        "WHERE (id = " P"1" " OR origin_refresh_token_id = " P"1" ") "
        "AND is_revoked = " BOOL_FALSE " "
        "RETURNING id";

    db_stmt_t *refresh_stmt = NULL;
    if (db_prepare(db, &refresh_stmt, refresh_sql) != 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to prepare refresh token revocation");
        return -1;
    }

    db_bind_blob(refresh_stmt, 1, chain_origin, 16);
    while (db_step(refresh_stmt) == DB_ROW) {
        refresh_count++;
    }
    db_finalize(refresh_stmt);

    if (refresh_count == 0 && access_count == 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_debug("No tokens found to revoke for chain");
        if (out_refresh_revoked) *out_refresh_revoked = 0;
        if (out_access_revoked) *out_access_revoked = 0;
        return 0;
    }

    /* Commit transaction */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        db_execute_trusted(db, "ROLLBACK");
        log_error("Failed to commit token chain revocation");
        return -1;
    }

    log_warn("Revoked token chain: %d refresh tokens, %d access tokens",
             refresh_count, access_count);

    if (out_refresh_revoked) *out_refresh_revoked = refresh_count;
    if (out_access_revoked) *out_access_revoked = access_count;

    return 0;
}
