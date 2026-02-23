/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "db/queries/mfa.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/password.h"
#include "crypto/totp.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * MFA Method Management
 * ========================================================================== */

int mfa_method_create(db_handle_t *db,
                      long long user_account_pin,
                      const char *mfa_method,
                      const char *display_name,
                      const char *secret,
                      unsigned char *out_method_id) {
    if (!db || !mfa_method || !display_name || !secret || !out_method_id) {
        log_error("Invalid arguments to mfa_method_create");
        return -1;
    }

    /* Generate UUID for MFA method */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for MFA method");
        return -1;
    }

    /* Insert MFA method (is_confirmed defaults to 0) */
    const char *sql =
        "INSERT INTO " TBL_USER_MFA " "
        "(id, user_account_pin, mfa_method, display_name, secret) "
        "VALUES (" P"1, " P"2, " P"3, " P"4, " P"5)";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_method_create statement");
        return -1;
    }

    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_int64(stmt, 2, user_account_pin);
    db_bind_text(stmt, 3, mfa_method, -1);
    db_bind_text(stmt, 4, display_name, -1);
    db_bind_text(stmt, 5, secret, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert MFA method");
        return -1;
    }

    /* Copy UUID to output */
    memcpy(out_method_id, id, 16);

    char id_hex[33];
    bytes_to_hex(id, sizeof(id), id_hex, sizeof(id_hex));
    log_info("Created MFA method: id=%s, method=%s", id_hex, mfa_method);
    return 0;
}

int mfa_method_confirm(db_handle_t *db, const unsigned char *method_id) {
    if (!db || !method_id) {
        log_error("Invalid arguments to mfa_method_confirm");
        return -1;
    }

    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction");
        return -1;
    }

    const char *update_sql =
        "UPDATE " TBL_USER_MFA " "
        "SET is_confirmed = " BOOL_TRUE ", "
        "    confirmed_at = " NOW ", "
        "    updated_at = " NOW " "
        "WHERE id = " P"1 AND is_confirmed = " BOOL_FALSE " "
        "RETURNING user_account_pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, update_sql) != 0) {
        log_error("Failed to prepare mfa_method_confirm statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(stmt, 1, method_id, 16);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        log_error("Failed to confirm MFA method (not found or already confirmed)");
        db_finalize(stmt);
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    long long user_account_pin = db_column_int64(stmt, 0);
    db_finalize(stmt);

    const char *update_user_sql =
        "UPDATE " TBL_USER_ACCOUNT " "
        "SET has_mfa = " BOOL_TRUE ", updated_at = " NOW " "
        "WHERE pin = " P"1 AND has_mfa = " BOOL_FALSE;

    db_stmt_t *user_stmt = NULL;
    if (db_prepare(db, &user_stmt, update_user_sql) != 0) {
        log_error("Failed to prepare has_mfa update statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_int64(user_stmt, 1, user_account_pin);

    rc = db_step(user_stmt);
    db_finalize(user_stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update user has_mfa flag");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit transaction");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    log_info("Confirmed MFA method");
    return 0;
}

int mfa_method_get_by_id(db_handle_t *db,
                         const unsigned char *method_id,
                         mfa_method_t *out_method) {
    if (!db || !method_id || !out_method) {
        log_error("Invalid arguments to mfa_method_get_by_id");
        return -1;
    }

    const char *sql =
        "SELECT id, pin, user_account_pin, mfa_method, display_name, secret, "
        "       is_confirmed, confirmed_at "
        "FROM " TBL_USER_MFA " "
        "WHERE id = " P"1 "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_method_get_by_id statement");
        return -1;
    }

    db_bind_blob(stmt, 1, method_id, 16);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        /* Extract MFA method data */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        memcpy(out_method->id, id_blob, 16);

        out_method->pin = db_column_int64(stmt, 1);
        out_method->user_account_pin = db_column_int64(stmt, 2);

        const char *method_str = db_column_text(stmt, 3);
        str_copy(out_method->mfa_method, sizeof(out_method->mfa_method), method_str);

        const char *display_str = db_column_text(stmt, 4);
        str_copy(out_method->display_name, sizeof(out_method->display_name), display_str);

        const char *secret_str = db_column_text(stmt, 5);
        str_copy(out_method->secret, sizeof(out_method->secret), secret_str);

        out_method->is_confirmed = db_column_int(stmt, 6);

        const char *confirmed_at = db_column_text(stmt, 7);
        if (confirmed_at) {
            str_copy(out_method->confirmed_at, sizeof(out_method->confirmed_at), confirmed_at);
        } else {
            out_method->confirmed_at[0] = '\0';
        }

        db_finalize(stmt);
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("MFA method not found");
        return -1;
    } else {
        log_error("Error retrieving MFA method");
        db_finalize(stmt);
        return -1;
    }
}

int mfa_method_list(db_handle_t *db,
                    long long user_account_pin,
                    int filter_confirmed,
                    mfa_method_t **out_methods,
                    int *out_count) {
    if (!db || !out_methods || !out_count) {
        log_error("Invalid arguments to mfa_method_list");
        return -1;
    }

    static const char *sql_confirmed =
        "SELECT id, pin, user_account_pin, mfa_method, display_name, secret, "
        "       is_confirmed, confirmed_at "
        "FROM " TBL_USER_MFA " "
        "WHERE user_account_pin = " P"1 AND is_confirmed = " BOOL_TRUE " "
        "ORDER BY confirmed_at ASC";

    static const char *sql_all =
        "SELECT id, pin, user_account_pin, mfa_method, display_name, secret, "
        "       is_confirmed, confirmed_at "
        "FROM " TBL_USER_MFA " "
        "WHERE user_account_pin = " P"1 "
        "ORDER BY pin ASC";

    const char *sql = filter_confirmed ? sql_confirmed : sql_all;

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_method_list statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);

    /* Collect results */
    int count = 0;
    int capacity = 4;
    mfa_method_t *methods = malloc(capacity * sizeof(mfa_method_t));
    if (!methods) {
        log_error("Failed to allocate memory for MFA methods list");
        db_finalize(stmt);
        return -1;
    }

    int rc;
    while ((rc = db_step(stmt)) == DB_ROW) {
        if (count >= capacity) {
            capacity *= 2;
            mfa_method_t *new_methods = realloc(methods, capacity * sizeof(mfa_method_t));
            if (!new_methods) {
                log_error("Failed to reallocate memory for MFA methods list");
                free(methods);
                db_finalize(stmt);
                return -1;
            }
            methods = new_methods;
        }

        /* Extract MFA method data */
        mfa_method_t *method = &methods[count];

        const unsigned char *id_blob = db_column_blob(stmt, 0);
        memcpy(method->id, id_blob, 16);

        method->pin = db_column_int64(stmt, 1);
        method->user_account_pin = db_column_int64(stmt, 2);

        const char *method_str = db_column_text(stmt, 3);
        str_copy(method->mfa_method, sizeof(method->mfa_method), method_str);

        const char *display_str = db_column_text(stmt, 4);
        str_copy(method->display_name, sizeof(method->display_name), display_str);

        const char *secret_str = db_column_text(stmt, 5);
        str_copy(method->secret, sizeof(method->secret), secret_str);

        method->is_confirmed = db_column_int(stmt, 6);

        const char *confirmed_at = db_column_text(stmt, 7);
        if (confirmed_at) {
            str_copy(method->confirmed_at, sizeof(method->confirmed_at), confirmed_at);
        } else {
            method->confirmed_at[0] = '\0';
        }

        count++;
    }

    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Error listing MFA methods");
        free(methods);
        return -1;
    }

    *out_methods = methods;
    *out_count = count;
    return 0;
}

int mfa_method_delete(db_handle_t *db, const unsigned char *method_id) {
    if (!db || !method_id) {
        log_error("Invalid arguments to mfa_method_delete");
        return -1;
    }

    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction");
        return -1;
    }

    const char *select_sql =
        "SELECT user_account_pin FROM " TBL_USER_MFA " "
        "WHERE id = " P"1";

    db_stmt_t *select_stmt = NULL;
    if (db_prepare(db, &select_stmt, select_sql) != 0) {
        log_error("Failed to prepare select statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(select_stmt, 1, method_id, 16);

    int rc = db_step(select_stmt);

    if (rc != DB_ROW) {
        log_error("MFA method not found");
        db_finalize(select_stmt);
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    long long user_account_pin = db_column_int64(select_stmt, 0);
    db_finalize(select_stmt);

    const char *delete_sql =
        "DELETE FROM " TBL_USER_MFA " "
        "WHERE id = " P"1";

    db_stmt_t *delete_stmt = NULL;
    if (db_prepare(db, &delete_stmt, delete_sql) != 0) {
        log_error("Failed to prepare mfa_method_delete statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(delete_stmt, 1, method_id, 16);

    rc = db_step(delete_stmt);
    db_finalize(delete_stmt);

    if (rc != DB_DONE) {
        log_error("Failed to delete MFA method");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    const char *count_sql =
        "SELECT COUNT(*) FROM " TBL_USER_MFA " "
        "WHERE user_account_pin = " P"1 AND is_confirmed = " BOOL_TRUE;

    db_stmt_t *count_stmt = NULL;
    if (db_prepare(db, &count_stmt, count_sql) != 0) {
        log_error("Failed to prepare count statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_int64(count_stmt, 1, user_account_pin);

    rc = db_step(count_stmt);

    if (rc != DB_ROW) {
        log_error("Failed to count confirmed MFA methods");
        db_finalize(count_stmt);
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    int confirmed_count = db_column_int(count_stmt, 0);
    db_finalize(count_stmt);

    if (confirmed_count == 0) {
        /* Revoke active recovery codes since user has no MFA methods left */
        recovery_code_set_t active_set;
        if (recovery_code_set_get_active(db, user_account_pin, &active_set) == 0) {
            /* Found active set - revoke it */
            if (recovery_code_set_revoke(db, active_set.id) != 0) {
                log_error("Failed to revoke recovery codes");
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }
            log_info("Revoked recovery codes (no MFA methods remaining)");
        }

        const char *update_user_sql =
            "UPDATE " TBL_USER_ACCOUNT " "
            "SET has_mfa = " BOOL_FALSE ", require_mfa = " BOOL_FALSE ", updated_at = " NOW " "
            "WHERE pin = " P"1 AND has_mfa = " BOOL_TRUE;

        db_stmt_t *update_stmt = NULL;
        if (db_prepare(db, &update_stmt, update_user_sql) != 0) {
            log_error("Failed to prepare has_mfa update statement");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        db_bind_int64(update_stmt, 1, user_account_pin);

        rc = db_step(update_stmt);
        db_finalize(update_stmt);

        if (rc != DB_DONE) {
            log_error("Failed to update user has_mfa flag");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }
    }

    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit transaction");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    log_info("Deleted MFA method");
    return 0;
}

int mfa_method_count_confirmed(db_handle_t *db,
                                long long user_account_pin,
                                int *out_count) {
    if (!db || !out_count) {
        log_error("Invalid arguments to mfa_method_count_confirmed");
        return -1;
    }

    const char *sql =
        "SELECT COUNT(*) FROM " TBL_USER_MFA " "
        "WHERE user_account_pin = " P"1 AND is_confirmed = " BOOL_TRUE;

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_method_count_confirmed statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        *out_count = db_column_int(stmt, 0);
        db_finalize(stmt);
        return 0;
    } else {
        log_error("Error counting confirmed MFA methods");
        db_finalize(stmt);
        return -1;
    }
}

/* ============================================================================
 * Recovery Code Management
 * ========================================================================== */

int recovery_code_set_create(db_handle_t *db,
                              long long user_account_pin,
                              const char **plaintext_codes,
                              int code_count,
                              unsigned char *out_set_id) {
    if (!db || !plaintext_codes || code_count <= 0 || !out_set_id) {
        log_error("Invalid arguments to recovery_code_set_create");
        return -1;
    }

    unsigned char set_id[16];
    if (crypto_random_bytes(set_id, sizeof(set_id)) != 0) {
        log_error("Failed to generate UUID for recovery code set");
        return -1;
    }

    unsigned char salt_bytes[32];
    if (crypto_random_bytes(salt_bytes, sizeof(salt_bytes)) != 0) {
        log_error("Failed to generate salt for recovery codes");
        return -1;
    }

    char salt_hex[65];
    bytes_to_hex(salt_bytes, sizeof(salt_bytes), salt_hex, sizeof(salt_hex));

    int hash_iterations = crypto_password_min_iterations();

    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction");
        return -1;
    }

    /* Revoke existing active set for this user, if any */
    const char *revoke_sql =
        "UPDATE " TBL_RECOVERY_CODE_SET " "
        "SET is_active = " BOOL_FALSE ", "
        "    revoked_at = " NOW ", "
        "    updated_at = " NOW " "
        "WHERE user_account_pin = " P"1 AND is_active = " BOOL_TRUE;

    db_stmt_t *revoke_stmt = NULL;
    if (db_prepare(db, &revoke_stmt, revoke_sql) != 0) {
        log_error("Failed to prepare recovery code set revoke statement");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_int64(revoke_stmt, 1, user_account_pin);

    int rc = db_step(revoke_stmt);
    db_finalize(revoke_stmt);

    if (rc != DB_DONE) {
        log_error("Failed to revoke existing recovery code set");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    const char *set_sql =
        "INSERT INTO " TBL_RECOVERY_CODE_SET " "
        "(id, user_account_pin, generated_at, salt, hash_iterations) "
        "VALUES (" P"1, " P"2, " NOW ", " P"3, " P"4) "
        "RETURNING pin";

    db_stmt_t *set_stmt = NULL;
    if (db_prepare(db, &set_stmt, set_sql) != 0) {
        log_error("Failed to prepare recovery_code_set insert");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(set_stmt, 1, set_id, sizeof(set_id));
    db_bind_int64(set_stmt, 2, user_account_pin);
    db_bind_text(set_stmt, 3, salt_hex, -1);
    db_bind_int(set_stmt, 4, hash_iterations);

    rc = db_step(set_stmt);

    if (rc != DB_ROW) {
        log_error("Failed to insert recovery code set");
        db_finalize(set_stmt);
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    long long set_pin = db_column_int64(set_stmt, 0);
    db_finalize(set_stmt);

    /* Insert each recovery code (hashed) */
    const char *code_sql =
        "INSERT INTO " TBL_RECOVERY_CODE " "
        "(recovery_code_set_pin, secret_hash, plaintext_last4) "
        "VALUES (" P"1, " P"2, " P"3)";

    for (int i = 0; i < code_count; i++) {
        const char *plaintext = plaintext_codes[i];
        size_t plaintext_len = strlen(plaintext);

        if (plaintext_len < 4) {
            log_error("Recovery code too short (must be at least 4 characters)");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        char hash_hex[PASSWORD_HASH_HEX_MAX_LENGTH];
        if (crypto_password_hash_with_salt(plaintext, plaintext_len,
                                         salt_hex, hash_iterations,
                                         hash_hex, sizeof(hash_hex)) != 0) {
            log_error("Failed to hash recovery code");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        const char *last4 = plaintext + (plaintext_len - 4);

        db_stmt_t *code_stmt = NULL;
        if (db_prepare(db, &code_stmt, code_sql) != 0) {
            log_error("Failed to prepare recovery_code insert");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        db_bind_int64(code_stmt, 1, set_pin);
        db_bind_text(code_stmt, 2, hash_hex, -1);
        db_bind_text(code_stmt, 3, last4, -1);

        rc = db_step(code_stmt);
        db_finalize(code_stmt);

        if (rc != DB_DONE) {
            log_error("Failed to insert recovery code");
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }
    }

    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit transaction");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    memcpy(out_set_id, set_id, 16);

    log_info("Created recovery code set with %d codes", code_count);
    return 0;
}

int recovery_code_set_get_active(db_handle_t *db,
                                  long long user_account_pin,
                                  recovery_code_set_t *out_set) {
    if (!db || !out_set) {
        log_error("Invalid arguments to recovery_code_set_get_active");
        return -1;
    }

    const char *sql =
        "SELECT id, user_account_pin, salt, hash_iterations, is_active, generated_at "
        "FROM " TBL_RECOVERY_CODE_SET " "
        "WHERE user_account_pin = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare recovery_code_set_get_active statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_account_pin);

    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        memcpy(out_set->id, id_blob, 16);

        out_set->user_account_pin = db_column_int64(stmt, 1);

        const char *salt = db_column_text(stmt, 2);
        str_copy(out_set->salt, sizeof(out_set->salt), salt);

        out_set->hash_iterations = db_column_int(stmt, 3);
        out_set->is_active = db_column_int(stmt, 4);

        const char *generated_at = db_column_text(stmt, 5);
        str_copy(out_set->generated_at, sizeof(out_set->generated_at), generated_at);

        db_finalize(stmt);
        return 0;
    } else if (rc == DB_DONE) {
        db_finalize(stmt);
        log_debug("No active recovery code set found");
        return 1;  /* No active set */
    } else {
        log_error("Error retrieving active recovery code set");
        db_finalize(stmt);
        return -1;
    }
}

int recovery_code_verify(db_handle_t *db,
                         long long user_account_pin,
                         const char *code) {
    if (!db || !code) {
        log_error("Invalid arguments to recovery_code_verify");
        return -1;
    }

    /* Get active recovery code set */
    recovery_code_set_t set;
    int result = recovery_code_set_get_active(db, user_account_pin, &set);

    if (result != 0) {
        log_debug("No active recovery code set found");
        return 0;  /* Invalid - no active set */
    }

    /* Hash the provided code with the set's salt */
    char hash_hex[PASSWORD_HASH_HEX_MAX_LENGTH];
    if (crypto_password_hash_with_salt(code, strlen(code),
                                     set.salt, set.hash_iterations,
                                     hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash recovery code for verification");
        return -1;
    }

    /* Begin transaction (need to check and mark as used atomically) */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction");
        return -1;
    }

    const char *select_sql =
        "SELECT rc.pin "
        "FROM " TBL_RECOVERY_CODE " rc "
        "INNER JOIN " TBL_RECOVERY_CODE_SET " rcs ON rc.recovery_code_set_pin = rcs.pin "
        "WHERE rcs.id = " P"1 "
        "  AND rc.secret_hash = " P"2 "
        "  AND rc.is_used = " BOOL_FALSE " "
        "LIMIT 1";

    db_stmt_t *select_stmt = NULL;
    if (db_prepare(db, &select_stmt, select_sql) != 0) {
        log_error("Failed to prepare recovery code select");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_blob(select_stmt, 1, set.id, 16);
    db_bind_text(select_stmt, 2, hash_hex, -1);

    int rc = db_step(select_stmt);

    if (rc != DB_ROW) {
        db_finalize(select_stmt);
        db_execute_trusted(db, "ROLLBACK");
        log_debug("Recovery code not found or already used");
        return 0;  /* Invalid */
    }

    long long code_pin = db_column_int64(select_stmt, 0);
    db_finalize(select_stmt);

    /* Mark code as used */
    const char *update_sql =
        "UPDATE " TBL_RECOVERY_CODE " "
        "SET is_used = " BOOL_TRUE ", "
        "    used_at = " NOW ", "
        "    updated_at = " NOW " "
        "WHERE pin = " P"1 AND is_used = " BOOL_FALSE;

    db_stmt_t *update_stmt = NULL;
    if (db_prepare(db, &update_stmt, update_sql) != 0) {
        log_error("Failed to prepare recovery code update");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    db_bind_int64(update_stmt, 1, code_pin);

    rc = db_step(update_stmt);
    db_finalize(update_stmt);

    if (rc != DB_DONE) {
        log_error("Failed to mark recovery code as used");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    /* Commit transaction */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit transaction");
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    log_info("Recovery code verified and marked as used");
    return 1;  /* Valid */
}

int recovery_code_set_revoke(db_handle_t *db, const unsigned char *set_id) {
    if (!db || !set_id) {
        log_error("Invalid arguments to recovery_code_set_revoke");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_RECOVERY_CODE_SET " "
        "SET is_active = " BOOL_FALSE ", "
        "    revoked_at = " NOW ", "
        "    updated_at = " NOW " "
        "WHERE id = " P"1 AND is_active = " BOOL_TRUE;

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare recovery_code_set_revoke statement");
        return -1;
    }

    db_bind_blob(stmt, 1, set_id, 16);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to revoke recovery code set");
        return -1;
    }

    log_info("Revoked recovery code set");
    return 0;
}

int recovery_code_get_masked_list(db_handle_t *db,
                                   long long user_account_pin,
                                   char ***out_masked_codes,
                                   int *out_count) {
    if (!db || !out_masked_codes || !out_count) {
        log_error("Invalid arguments to recovery_code_get_masked_list");
        return -1;
    }

    /* Get active recovery code set */
    recovery_code_set_t set;
    int result = recovery_code_set_get_active(db, user_account_pin, &set);

    if (result != 0) {
        log_debug("No active recovery code set found");
        *out_masked_codes = NULL;
        *out_count = 0;
        return 0;  /* No active set - not an error */
    }

    /* Get masked codes (plaintext_last4 column) */
    const char *sql =
        "SELECT rc.plaintext_last4, rc.is_used "
        "FROM " TBL_RECOVERY_CODE " rc "
        "INNER JOIN " TBL_RECOVERY_CODE_SET " rcs ON rc.recovery_code_set_pin = rcs.pin "
        "WHERE rcs.id = " P"1 "
        "ORDER BY rc.pin ASC";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare recovery_code_get_masked_list statement");
        return -1;
    }

    db_bind_blob(stmt, 1, set.id, 16);

    /* Collect masked codes */
    int count = 0;
    int capacity = 10;
    char **masked_codes = malloc(capacity * sizeof(char *));
    if (!masked_codes) {
        log_error("Failed to allocate memory for masked codes list");
        db_finalize(stmt);
        return -1;
    }

    int rc;
    while ((rc = db_step(stmt)) == DB_ROW) {
        /* Resize array if needed */
        if (count >= capacity) {
            capacity *= 2;
            char **new_codes = realloc(masked_codes, capacity * sizeof(char *));
            if (!new_codes) {
                log_error("Failed to reallocate memory for masked codes list");
                for (int i = 0; i < count; i++) {
                    free(masked_codes[i]);
                }
                free(masked_codes);
                db_finalize(stmt);
                return -1;
            }
            masked_codes = new_codes;
        }

        const char *last4 = db_column_text(stmt, 0);
        int is_used = db_column_int(stmt, 1);

        /* Format: "********-last4 (used)" or "********-last4" */
        char masked[32];
        if (is_used) {
            snprintf(masked, sizeof(masked), "********-%s (used)", last4);
        } else {
            snprintf(masked, sizeof(masked), "********-%s", last4);
        }

        masked_codes[count] = str_dup(masked);
        if (!masked_codes[count]) {
            log_error("Failed to allocate memory for masked code string");
            for (int i = 0; i < count; i++) {
                free(masked_codes[i]);
            }
            free(masked_codes);
            db_finalize(stmt);
            return -1;
        }

        count++;
    }

    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Error listing recovery codes");
        for (int i = 0; i < count; i++) {
            free(masked_codes[i]);
        }
        free(masked_codes);
        return -1;
    }

    *out_masked_codes = masked_codes;
    *out_count = count;
    return 0;
}

/* ============================================================================
 * User Flag Management
 * ========================================================================== */

int mfa_update_require_mfa_flag(db_handle_t *db,
                                 long long user_account_pin,
                                 int require_mfa) {
    if (!db) {
        log_error("Invalid arguments to mfa_update_require_mfa_flag");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_USER_ACCOUNT " "
        "SET require_mfa = " P"1, updated_at = " NOW " "
        "WHERE pin = " P"2 AND require_mfa != " P"1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_update_require_mfa_flag statement");
        return -1;
    }

    db_bind_int(stmt, 1, require_mfa ? 1 : 0);
    db_bind_int64(stmt, 2, user_account_pin);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update require_mfa flag");
        return -1;
    }

    log_info("Updated require_mfa flag to %d", require_mfa);
    return 0;
}

/* ============================================================================
 * Logging
 * ========================================================================== */

int mfa_log_usage(db_handle_t *db,
                  long long user_mfa_pin,
                  int success,
                  const char *source_ip,
                  const char *user_agent) {
    if (!db) {
        log_error("Invalid arguments to mfa_log_usage");
        return -1;
    }

    const char *sql =
        "INSERT INTO " TBL_USER_MFA_USAGE " "
        "(user_mfa_pin, submitted_at, success, source_ip, user_agent) "
        "VALUES (" P"1, " NOW ", " P"2, " P"3, " P"4)";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare mfa_log_usage statement");
        return -1;
    }

    db_bind_int64(stmt, 1, user_mfa_pin);
    db_bind_int(stmt, 2, success ? 1 : 0);

    if (source_ip) {
        db_bind_text(stmt, 3, source_ip, -1);
    } else {
        db_bind_null(stmt, 3);
    }

    if (user_agent) {
        db_bind_text(stmt, 4, user_agent, -1);
    } else {
        db_bind_null(stmt, 4);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to log MFA usage");
        return -1;
    }

    return 0;
}
