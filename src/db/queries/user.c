#define _POSIX_C_SOURCE 200809L

#include "db/queries/user.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/password.h"
#include "crypto/encrypt.h"
#include "crypto/hmac.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include "util/validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int user_username_exists(db_handle_t *db, const char *username) {
    if (!db || !username) {
        log_error("Invalid arguments to user_username_exists");
        return -1;
    }

    /* Compute HMAC hash for lookup */
    char lower_buf[256];
    str_to_lower(lower_buf, sizeof(lower_buf), username);
    char hash_hex[HMAC_SHA256_HEX_LENGTH];
    if (hash_field(lower_buf, hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash username for existence check");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_USER_ACCOUNT " "
        "WHERE username_hash = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_username_exists statement");
        return -1;
    }

    db_bind_text(stmt, 1, hash_hex, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Exists */
    } else if (rc == DB_DONE) {
        return 0;  /* Does not exist */
    } else {
        log_error("Error checking username existence");
        return -1;
    }
}

int user_email_exists(db_handle_t *db, const char *email) {
    if (!db || !email) {
        log_error("Invalid arguments to user_email_exists");
        return -1;
    }

    /* Compute HMAC hash for lookup */
    char lower_buf[256];
    str_to_lower(lower_buf, sizeof(lower_buf), email);
    char hash_hex[HMAC_SHA256_HEX_LENGTH];
    if (hash_field(lower_buf, hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash email for existence check");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_USER_EMAIL " "
        "WHERE email_hash = " P"1 "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_email_exists statement");
        return -1;
    }

    db_bind_text(stmt, 1, hash_hex, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Exists */
    } else if (rc == DB_DONE) {
        return 0;  /* Does not exist */
    } else {
        log_error("Error checking email existence");
        return -1;
    }
}

int user_id_exists(db_handle_t *db, const unsigned char *user_id) {
    if (!db || !user_id) {
        log_error("Invalid arguments to user_id_exists");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_USER_ACCOUNT " "
        "WHERE id = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_id_exists statement");
        return -1;
    }

    db_bind_blob(stmt, 1, user_id, 16);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Exists */
    } else if (rc == DB_DONE) {
        return 0;  /* Does not exist */
    } else {
        log_error("Error checking user ID existence");
        return -1;
    }
}

int user_lookup_id_by_username(db_handle_t *db, const char *username,
                                unsigned char *out_user_id) {
    if (!db || !username || !out_user_id) {
        log_error("Invalid arguments to user_lookup_id_by_username");
        return -1;
    }

    /* Compute HMAC hash for lookup */
    char lower_buf[256];
    str_to_lower(lower_buf, sizeof(lower_buf), username);
    char hash_hex[HMAC_SHA256_HEX_LENGTH];
    if (hash_field(lower_buf, hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash username for lookup");
        return -1;
    }

    const char *sql =
        "SELECT id FROM " TBL_USER_ACCOUNT " "
        "WHERE username_hash = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_lookup_id_by_username statement");
        return -1;
    }

    db_bind_text(stmt, 1, hash_hex, -1);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);

        if (blob_len != 16) {
            log_error("Invalid user ID length: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }

        memcpy(out_user_id, id_blob, 16);
        db_finalize(stmt);
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("User not found: username='%s'", username);
        return -1;
    } else {
        log_error("Error looking up user by username");
        db_finalize(stmt);
        return -1;
    }
}

int user_create(db_handle_t *db, const char *username,
                const char *email, const char *password,
                unsigned char *out_user_id) {
    if (!db || !password || !out_user_id) {
        log_error("Invalid arguments to user_create");
        return -1;
    }

    /* At least one of username or email must be provided */
    if (!username && !email) {
        log_error("Must provide either username or email");
        return -1;
    }

    /* Generate UUID for user */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for user");
        return -1;
    }

    /* Hash password */
    char salt[PASSWORD_SALT_HEX_MAX_LENGTH];
    int iterations;
    char hash[PASSWORD_HASH_HEX_MAX_LENGTH];

    if (crypto_password_hash(password, strlen(password),
                            salt, sizeof(salt),
                            &iterations,
                            hash, sizeof(hash)) != 0) {
        log_error("Failed to hash password");
        return -1;
    }

    /* Encrypt username and compute hash */
    char encrypted_username[512];
    char username_hash[HMAC_SHA256_HEX_LENGTH];
    if (username) {
        if (encrypt_field(username, encrypted_username, sizeof(encrypted_username)) != 0) {
            log_error("Failed to encrypt username");
            return -1;
        }
        char lower_buf[256];
        str_to_lower(lower_buf, sizeof(lower_buf), username);
        if (hash_field(lower_buf, username_hash, sizeof(username_hash)) != 0) {
            log_error("Failed to hash username");
            return -1;
        }
    }

    /* Encrypt email and compute hash */
    char encrypted_email[512];
    char email_hash[HMAC_SHA256_HEX_LENGTH];
    if (email) {
        if (encrypt_field(email, encrypted_email, sizeof(encrypted_email)) != 0) {
            log_error("Failed to encrypt email");
            return -1;
        }
        char lower_buf[256];
        str_to_lower(lower_buf, sizeof(lower_buf), email);
        if (hash_field(lower_buf, email_hash, sizeof(email_hash)) != 0) {
            log_error("Failed to hash email");
            return -1;
        }
    }

    /* Begin transaction if email provided (multi-table insert) */
    if (email) {
        if (db_execute_trusted(db, "BEGIN") != 0) {
            log_error("Failed to begin transaction");
            return -1;
        }
    }

    /* Insert user_account with RETURNING clause */
    const char *sql =
        "INSERT INTO " TBL_USER_ACCOUNT " "
        "(id, username, username_hash, salt, hash_iterations, secret_hash) "
        "VALUES (" P"1, " P"2, " P"3, " P"4, " P"5, " P"6) "
        "RETURNING pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_create statement");
        if (email) db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(stmt, 1, id, sizeof(id));

    if (username) {
        db_bind_text(stmt, 2, encrypted_username, -1);
        db_bind_text(stmt, 3, username_hash, -1);
    } else {
        db_bind_null(stmt, 2);
        db_bind_null(stmt, 3);
    }

    db_bind_text(stmt, 4, salt, -1);
    db_bind_int(stmt, 5, iterations);
    db_bind_text(stmt, 6, hash, -1);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        log_error("Failed to insert user_account");
        db_finalize(stmt);
        if (email) db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    long long user_pin = db_column_int64(stmt, 0);
    db_finalize(stmt);

    /* Insert user_email if provided */
    if (email) {
        const char *email_sql =
            "INSERT INTO " TBL_USER_EMAIL " "
            "(user_account_pin, email_address, email_hash, is_primary) "
            "VALUES (" P"1, " P"2, " P"3, " BOOL_TRUE ")";

        db_stmt_t *email_stmt = NULL;
        if (db_prepare(db, &email_stmt, email_sql) != 0) {
            log_error("Failed to prepare user_email insert");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        db_bind_int64(email_stmt, 1, user_pin);
        db_bind_text(email_stmt, 2, encrypted_email, -1);
        db_bind_text(email_stmt, 3, email_hash, -1);

        rc = db_step(email_stmt);
        db_finalize(email_stmt);

        if (rc != DB_DONE) {
            log_error("Failed to insert user_email");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        /* Commit transaction */
        if (db_execute_trusted(db, "COMMIT") != 0) {
            log_error("Failed to commit transaction");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }
    }

    /* Copy UUID to output */
    memcpy(out_user_id, id, 16);

    /* Log UUID only (username/email are PII) */
    char id_hex[33];
    bytes_to_hex(id, sizeof(id), id_hex, sizeof(id_hex));
    log_info("Created user: id=%s", id_hex);
    return 0;
}

int user_verify_password(db_handle_t *db, const char *username,
                         const char *password, long long *out_pin,
                         unsigned char *out_id) {
    if (!db || !username || !password) {
        log_error("Invalid arguments to user_verify_password");
        return -1;
    }

    /* Compute HMAC hash for lookup */
    char lower_buf[256];
    str_to_lower(lower_buf, sizeof(lower_buf), username);
    char hash_hex[HMAC_SHA256_HEX_LENGTH];
    if (hash_field(lower_buf, hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash username for password verification");
        return -1;
    }

    const char *sql =
        "SELECT pin, id, salt, hash_iterations, secret_hash FROM " TBL_USER_ACCOUNT " "
        "WHERE username_hash = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_verify_password statement");
        return -1;
    }

    db_bind_text(stmt, 1, hash_hex, -1);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        /* Perform dummy verification to equalize timing (prevents user enumeration) */
        crypto_password_verify(password, strlen(password),
                               "00000000000000000000000000000000",
                               crypto_password_min_iterations(),
                               "0000000000000000000000000000000000000000000000000000000000000000");
        return 0;  /* User not found = invalid password */
    }

    long long pin = db_column_int64(stmt, 0);
    const unsigned char *id = db_column_blob(stmt, 1);
    const char *salt = (const char *)db_column_text(stmt, 2);
    int iterations = db_column_int(stmt, 3);
    const char *hash = (const char *)db_column_text(stmt, 4);

    if (!id || !salt || !hash) {
        log_error("NULL fields in user_account");
        db_finalize(stmt);
        return -1;
    }

    /* Copy id before finalizing statement */
    unsigned char user_id[16];
    memcpy(user_id, id, 16);

    /* Verify password using crypto module */
    int valid = crypto_password_verify(password, strlen(password),
                                       salt, iterations, hash);

    db_finalize(stmt);

    /* If password valid, return pin and id if requested */
    if (valid == 1) {
        if (out_pin != NULL) {
            *out_pin = pin;
        }
        if (out_id != NULL) {
            memcpy(out_id, user_id, 16);
        }
    }

    return valid;  /* 1 if valid, 0 if invalid, -1 on error */
}

int user_make_org_admin(db_handle_t *db, const unsigned char *user_id,
                        const char *org_code_name) {
    if (!db || !user_id || !org_code_name) {
        log_error("Invalid arguments to user_make_org_admin");
        return -1;
    }

    const char *sql =
        "INSERT INTO " TBL_ORGANIZATION_ADMIN " (organization_pin, user_account_pin) "
        "SELECT A.pin, B.pin "
        "FROM " TBL_ORGANIZATION " A "
        "CROSS JOIN " TBL_USER_ACCOUNT " B "
        "LEFT JOIN " TBL_ORGANIZATION_ADMIN " C "
        "  ON C.organization_pin = A.pin AND C.user_account_pin = B.pin "
        "WHERE A.code_name = " P"1 AND B.id = " P"2 AND C.pin IS NULL "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_make_org_admin statement");
        return -1;
    }

    db_bind_text(stmt, 1, org_code_name, -1);
    db_bind_blob(stmt, 2, user_id, 16);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert organization_admin");
        return -1;
    }

    log_info("Made user org admin: org='%s'", org_code_name);
    return 0;
}

int user_get_management_ui_setups(db_handle_t *db, long long user_account_pin,
                                   const char *callback_url, const char *api_url,
                                   int limit, int offset,
                                   management_ui_setup_t **out_setups, int *out_count) {
    if (!db || !callback_url || !api_url || !out_setups || !out_count) {
        log_error("Invalid arguments to user_get_management_ui_setups");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    const char *sql =
        "SELECT DISTINCT "
        "  C.code_name, C.display_name, "
        "  D.id, D.code_name, D.display_name, "
        "  F.address "
        "FROM " TBL_USER_ACCOUNT " A "
        "JOIN " TBL_ORGANIZATION_ADMIN " B ON A.pin = B.user_account_pin "
        "JOIN " TBL_ORGANIZATION " C ON B.organization_pin = C.pin "
        "JOIN " TBL_CLIENT " D ON C.pin = D.organization_pin "
        "JOIN " TBL_CLIENT_RESOURCE_SERVER " E ON D.pin = E.client_pin "
        "JOIN " TBL_RESOURCE_SERVER " F ON E.resource_server_pin = F.pin "
        "JOIN " TBL_CLIENT_REDIRECT_URI " G ON D.pin = G.client_pin "
        "WHERE A.pin = " P"1 "
        "  AND A.is_active = " BOOL_TRUE " "
        "  AND C.is_active = " BOOL_TRUE " "
        "  AND D.is_active = " BOOL_TRUE " "
        "  AND F.is_active = " BOOL_TRUE " "
        "  AND lower(G.redirect_uri) = lower(" P"2) "
        "  AND lower(F.address) = lower(" P"3) "
        "ORDER BY C.code_name ASC, D.code_name ASC "
        "LIMIT " P"4 OFFSET " P"5";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_get_management_ui_setups statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);
    db_bind_text(stmt, 2, callback_url, -1);
    db_bind_text(stmt, 3, api_url, -1);
    db_bind_int(stmt, 4, limit);
    db_bind_int(stmt, 5, offset);

    /* Build linked list */
    db_result_node_t *list = NULL, *list_tail = NULL;

    while (db_step(stmt) == DB_ROW) {
        management_ui_setup_t setup;

        /* Extract row data */
        const char *org_code_name = (const char *)db_column_text(stmt, 0);
        const char *org_display_name = (const char *)db_column_text(stmt, 1);
        const unsigned char *client_id = db_column_blob(stmt, 2);
        const char *client_code_name = (const char *)db_column_text(stmt, 3);
        const char *client_display_name = (const char *)db_column_text(stmt, 4);
        const char *rs_address = (const char *)db_column_text(stmt, 5);

        /* Copy to struct */
        str_copy(setup.org_code_name, sizeof(setup.org_code_name), org_code_name);
        str_copy(setup.org_display_name, sizeof(setup.org_display_name), org_display_name);
        memcpy(setup.client_id, client_id, 16);
        str_copy(setup.client_code_name, sizeof(setup.client_code_name), client_code_name);
        str_copy(setup.client_display_name, sizeof(setup.client_display_name), client_display_name);
        str_copy(setup.resource_server_address, sizeof(setup.resource_server_address), rs_address);

        /* Append to list */
        if (db_results_append(&list, &list_tail, &setup, sizeof(setup)) != 0) {
            log_error("Failed to append management UI setup to result list");
            db_results_free(list);
            db_finalize(stmt);
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert linked list to array */
    int count;
    management_ui_setup_t *setups = DB_RESULTS_TO_ARRAY(list, &count, management_ui_setup_t);

    /* Handle empty result (returns NULL from macro) */
    if (count == 0) {
        *out_setups = NULL;
        *out_count = 0;
        log_info("No management UI setups found for user");
        return 0;
    }

    if (!setups) {
        log_error("Failed to convert management UI setups to array");
        *out_count = 0;
        return -1;
    }

    *out_setups = setups;
    *out_count = count;

    log_info("Found %d management UI setup%s for user (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int user_get_profile(db_handle_t *db, long long user_account_pin,
                     user_profile_t *out_profile) {
    if (!db || !out_profile) {
        log_error("Invalid arguments to user_get_profile");
        return -1;
    }

    const char *sql =
        "SELECT id, username, has_mfa, require_mfa FROM " TBL_USER_ACCOUNT " "
        "WHERE pin = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_get_profile statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract user_id (blob) */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len != 16) {
            log_error("Invalid user_id length: %d", blob_len);
            db_finalize(stmt);
            return -1;
        }
        memcpy(out_profile->user_id, id_blob, 16);

        /* Extract and decrypt username (may be NULL for email-only accounts) */
        const char *encrypted_username = (const char *)db_column_text(stmt, 1);
        if (encrypted_username) {
            if (decrypt_field(encrypted_username, out_profile->username,
                              sizeof(out_profile->username)) != 0) {
                log_error("Failed to decrypt username");
                db_finalize(stmt);
                return -1;
            }
        } else {
            out_profile->username[0] = '\0';
        }

        /* Extract MFA flags */
        out_profile->has_mfa = db_column_int(stmt, 2);
        out_profile->require_mfa = db_column_int(stmt, 3);

        db_finalize(stmt);
        return 0;
    } else {
        db_finalize(stmt);
        log_error("User not found or inactive");
        return -1;
    }
}

int user_get_emails(db_handle_t *db, long long user_account_pin,
                    int limit, int offset,
                    user_email_t **out_emails, int *out_count, int *out_total) {
    if (!db || !out_emails || !out_count) {
        log_error("Invalid arguments to user_get_emails");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    const char *sql =
        "SELECT email_address, is_primary, is_verified, COUNT(*) OVER() as total_count "
        "FROM " TBL_USER_EMAIL " "
        "WHERE user_account_pin = " P"1 "
        "ORDER BY is_primary DESC, created_at ASC "
        "LIMIT " P"2 OFFSET " P"3";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare user_get_emails statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);
    db_bind_int(stmt, 2, limit);
    db_bind_int(stmt, 3, offset);

    /* Build linked list */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        user_email_t email;

        /* Extract and decrypt email_address */
        const char *encrypted_email = (const char *)db_column_text(stmt, 0);
        int is_primary = db_column_int(stmt, 1);
        int is_verified = db_column_int(stmt, 2);

        /* Extract total count from first row (same in all rows) */
        if (first_row) {
            total_count = db_column_int(stmt, 3);
            first_row = 0;
        }

        /* Decrypt email address */
        if (decrypt_field(encrypted_email, email.email_address,
                          sizeof(email.email_address)) != 0) {
            log_error("Failed to decrypt email address");
            db_results_free(list);
            db_finalize(stmt);
            return -1;
        }
        email.is_primary = is_primary;
        email.is_verified = is_verified;

        /* Append to list */
        if (db_results_append(&list, &list_tail, &email, sizeof(email)) != 0) {
            log_error("Failed to append email to result list");
            db_results_free(list);
            db_finalize(stmt);
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert linked list to array */
    int count;
    user_email_t *emails = DB_RESULTS_TO_ARRAY(list, &count, user_email_t);

    /* Handle empty result (returns NULL from macro) */
    if (count == 0) {
        *out_emails = NULL;
        *out_count = 0;
        if (out_total) {
            *out_total = 0;
        }
        log_info("No emails found for user");
        return 0;
    }

    if (!emails) {
        log_error("Failed to convert emails to array");
        *out_count = 0;
        if (out_total) {
            *out_total = 0;
        }
        return -1;
    }

    *out_emails = emails;
    *out_count = count;
    if (out_total) {
        *out_total = total_count;
    }

    log_info("Found %d email%s for user (limit=%d, offset=%d, total=%d)",
             count, count == 1 ? "" : "s", limit, offset, total_count);
    return 0;
}

int user_change_password(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *current_password,
                         const char *new_password) {
    if (!db || !user_account_id || !current_password || !new_password) {
        log_error("Invalid arguments to user_change_password");
        return -1;
    }

    /* Step 1: Get current password hash for verification */
    const char *verify_sql =
        "SELECT salt, hash_iterations, secret_hash FROM " TBL_USER_ACCOUNT " "
        "WHERE pin = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *verify_stmt = NULL;
    if (db_prepare(db, &verify_stmt, verify_sql) != 0) {
        log_error("Failed to prepare password verification statement");
        return -1;
    }

    db_bind_int64(verify_stmt, 1, user_account_pin);

    int rc = db_step(verify_stmt);
    if (rc != DB_ROW) {
        db_finalize(verify_stmt);
        log_error("User not found or inactive");
        return -1;
    }

    const char *salt = (const char *)db_column_text(verify_stmt, 0);
    int iterations = db_column_int(verify_stmt, 1);
    const char *hash = (const char *)db_column_text(verify_stmt, 2);

    if (!salt || !hash) {
        log_error("NULL password fields in user_account");
        db_finalize(verify_stmt);
        return -1;
    }

    /* Step 2: Verify current password */
    int valid = crypto_password_verify(current_password, strlen(current_password),
                                       salt, iterations, hash);

    db_finalize(verify_stmt);

    if (valid != 1) {
        log_info("Current password verification failed for password change");
        return 0;  /* Invalid current password */
    }

    /* Step 3: Generate new password hash */
    char new_salt[PASSWORD_SALT_HEX_MAX_LENGTH];
    int new_iterations;
    char new_hash[PASSWORD_HASH_HEX_MAX_LENGTH];

    if (crypto_password_hash(new_password, strlen(new_password),
                            new_salt, sizeof(new_salt),
                            &new_iterations,
                            new_hash, sizeof(new_hash)) != 0) {
        log_error("Failed to hash new password");
        return -1;
    }

    /* Step 4: Update password in database */
    const char *update_sql =
        "UPDATE " TBL_USER_ACCOUNT " "
        "SET salt = " P"1, "
        "hash_iterations = " P"2, "
        "secret_hash = " P"3, "
        "updated_at = " NOW " "
        "WHERE pin = " P"4 AND is_active = " BOOL_TRUE;

    db_stmt_t *update_stmt = NULL;
    if (db_prepare(db, &update_stmt, update_sql) != 0) {
        log_error("Failed to prepare password update statement");
        return -1;
    }

    db_bind_text(update_stmt, 1, new_salt, -1);
    db_bind_int(update_stmt, 2, new_iterations);
    db_bind_text(update_stmt, 3, new_hash, -1);
    db_bind_int64(update_stmt, 4, user_account_pin);

    rc = db_step(update_stmt);
    db_finalize(update_stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update password");
        return -1;
    }

    char user_id_hex[33];
    bytes_to_hex(user_account_id, 16, user_id_hex, sizeof(user_id_hex));
    log_info("Password changed successfully for user_id=%s", user_id_hex);
    return 1;  /* Success */
}

int user_change_username(db_handle_t *db, long long user_account_pin,
                         const unsigned char *user_account_id,
                         const char *new_username) {
    if (!db || !user_account_id || !new_username) {
        log_error("Invalid arguments to user_change_username");
        return -1;
    }

    /* Validate username format */
    char error_msg[256];
    if (validate_username(new_username, error_msg, sizeof(error_msg)) != 0) {
        log_info("Username validation failed: %s", error_msg);
        return -1;
    }

    /* Check if username is already taken */
    int exists = user_username_exists(db, new_username);
    if (exists < 0) {
        log_error("Failed to check username existence");
        return -1;
    }
    if (exists == 1) {
        return 0;  /* Username taken */
    }

    /* Encrypt new username and compute hash */
    char encrypted_username[512];
    if (encrypt_field(new_username, encrypted_username, sizeof(encrypted_username)) != 0) {
        log_error("Failed to encrypt new username");
        return -1;
    }
    char lower_buf[256];
    str_to_lower(lower_buf, sizeof(lower_buf), new_username);
    char new_hash[HMAC_SHA256_HEX_LENGTH];
    if (hash_field(lower_buf, new_hash, sizeof(new_hash)) != 0) {
        log_error("Failed to hash new username");
        return -1;
    }

    /* Update username */
    const char *update_sql =
        "UPDATE " TBL_USER_ACCOUNT " "
        "SET username = " P"1, "
        "username_hash = " P"2, "
        "updated_at = " NOW " "
        "WHERE pin = " P"3 AND is_active = " BOOL_TRUE;

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, update_sql) != 0) {
        log_error("Failed to prepare username update statement");
        return -1;
    }

    db_bind_text(stmt, 1, encrypted_username, -1);
    db_bind_text(stmt, 2, new_hash, -1);
    db_bind_int64(stmt, 3, user_account_pin);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update username");
        return -1;
    }

    char user_id_hex[33];
    bytes_to_hex(user_account_id, 16, user_id_hex, sizeof(user_id_hex));
    log_info("Username changed for user_id=%s", user_id_hex);
    return 1;  /* Success */
}

int user_get_userinfo_by_id(db_handle_t *db, const unsigned char *user_id,
                            user_userinfo_t *out) {
    if (!db || !user_id || !out) {
        log_error("Invalid arguments to user_get_userinfo_by_id");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->user_id, user_id, 16);

    /* Look up user account + primary email in one query */
    const char *sql =
        "SELECT A.username, E.email_address, E.is_verified "
        "FROM " TBL_USER_ACCOUNT " A "
        "LEFT JOIN " TBL_USER_EMAIL " E "
        "ON E.user_account_pin = A.pin AND E.is_primary = " BOOL_TRUE " "
        "WHERE A.id = " P"1 AND A.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare userinfo lookup");
        return -1;
    }

    db_bind_blob(stmt, 1, user_id, 16);

    int rc = db_step(stmt);
    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_error("User not found or inactive for userinfo");
        return -1;
    }

    /* Decrypt username */
    const char *encrypted_username = (const char *)db_column_text(stmt, 0);
    if (encrypted_username) {
        if (decrypt_field(encrypted_username, out->username,
                          sizeof(out->username)) != 0) {
            log_error("Failed to decrypt username for userinfo");
            db_finalize(stmt);
            return -1;
        }
    }

    /* Decrypt primary email (NULL if no email on account) */
    const char *encrypted_email = (const char *)db_column_text(stmt, 1);
    if (encrypted_email) {
        if (decrypt_field(encrypted_email, out->email,
                          sizeof(out->email)) != 0) {
            log_error("Failed to decrypt email for userinfo");
            db_finalize(stmt);
            return -1;
        }
        out->email_verified = db_column_int(stmt, 2);
    }

    db_finalize(stmt);
    return 0;
}
