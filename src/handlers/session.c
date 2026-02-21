#include "handlers/session.h"
#include "db/queries/user.h"
#include "db/queries/oauth.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Session token size: 32 bytes (256 bits) */
#define SESSION_TOKEN_BYTES 32

int session_authenticate_and_create(db_handle_t *db,
                                     const char *username,
                                     const char *password,
                                     const char *source_ip,
                                     const char *user_agent,
                                     int session_ttl_seconds,
                                     char **out_session_token,
                                     long long *out_user_pin) {
    if (!db || !username || !password || !out_session_token || !out_user_pin) {
        log_error("Invalid arguments to session_authenticate_and_create");
        return -1;
    }

    /* Step 1: Verify password and get user PIN and ID */
    long long user_pin = 0;
    unsigned char user_id[16];
    int valid = user_verify_password(db, username, password, &user_pin, user_id);

    if (valid != 1) {
        if (valid == 0) {
            log_info("Authentication failed for username='%s' (invalid credentials)", username);
        } else {
            log_error("Error verifying password for username='%s'", username);
        }
        return -1;
    }

    /* Convert user_id to hex for logging */
    char user_id_hex[33];
    bytes_to_hex(user_id, 16, user_id_hex, sizeof(user_id_hex));

    /* Step 2: Generate session token */
    size_t token_buf_size = crypto_token_encoded_size(SESSION_TOKEN_BYTES);
    char *session_token = malloc(token_buf_size);
    if (!session_token) {
        log_error("Failed to allocate memory for session token");
        return -1;
    }

    int token_len = crypto_random_token(session_token, token_buf_size, SESSION_TOKEN_BYTES);
    if (token_len <= 0) {
        log_error("Failed to generate session token");
        free(session_token);
        return -1;
    }

    /* Step 3: Create session in database */
    unsigned char session_id[16];
    int rc = oauth_session_create(db, user_pin, user_id, session_token,
                                  "password",  /* authentication_method */
                                  source_ip, user_agent,
                                  session_ttl_seconds,
                                  session_id);

    if (rc != 0) {
        log_error("Failed to create session for user_id=%s", user_id_hex);
        free(session_token);
        return -1;
    }

    /* Success */
    *out_session_token = session_token;  /* Caller must free */
    *out_user_pin = user_pin;

    log_info("Created session for user_id=%s", user_id_hex);
    return 0;
}
