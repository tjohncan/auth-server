#include "db/encryption_params.h"
#include "db/db_sql.h"
#include "util/log.h"

#include <stdio.h>
#include <string.h>

int encryption_params_table_exists(db_handle_t *db) {
#ifdef DB_BACKEND_POSTGRESQL
    const char *sql = "SELECT to_regclass('" TBL_ENCRYPTION_PARAMS "') IS NOT NULL";
#else
    const char *sql = "SELECT count(*) > 0 FROM sqlite_master "
                      "WHERE type = 'table' AND name = '" TBL_ENCRYPTION_PARAMS "'";
#endif
    db_result_t *result = NULL;
    if (db_query(db, &result, "%s", sql) != 0) return -1;
    const char *v = db_result_row_count(result) == 1 ? db_result_get(result, 0, 0) : NULL;
    int rc = !v ? -1 : (v[0] == 't' || v[0] == '1');
    db_result_free(result);
    return rc;
}

int encryption_params_load(db_handle_t *db, encrypt_params_t *out) {
    int exists = encryption_params_table_exists(db);
    if (exists != 1) return exists == 0 ? 1 : -1;

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, "SELECT method, iterations, salt FROM " TBL_ENCRYPTION_PARAMS) != 0) {
        log_error("Failed to read encryption_params");
        return -1;
    }
    int rc = db_step(stmt);
    if (rc != DB_ROW) {
        db_finalize(stmt);
        if (rc == DB_DONE) return 1;
        log_error("Failed to read encryption_params");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    const char *method = db_column_text(stmt, 0);
    const char *salt = db_column_text(stmt, 2);
    snprintf(out->method, sizeof(out->method), "%s", method ? method : "");
    out->iterations = db_column_int(stmt, 1);
    snprintf(out->salt, sizeof(out->salt), "%s", salt ? salt : "");
    db_finalize(stmt);

    if (out->iterations < 1 || strlen(out->salt) != 32) {
        log_error("encryption_params holds an unusable row (method %s, iterations %d)",
                  out->method, out->iterations);
        return -1;
    }
    return 0;
}

int encryption_params_store(db_handle_t *db, const encrypt_params_t *params) {
    if (db_execute_direct(db, "DELETE FROM " TBL_ENCRYPTION_PARAMS) != 0) {
        log_error("Failed to clear encryption_params");
        return -1;
    }
    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, "INSERT INTO " TBL_ENCRYPTION_PARAMS " (method, iterations, salt) "
                              "VALUES (" P"1, " P"2, " P"3)") != 0) {
        log_error("Failed to prepare the encryption_params write");
        return -1;
    }
    db_bind_text(stmt, 1, params->method, -1);
    db_bind_int(stmt, 2, params->iterations);
    db_bind_text(stmt, 3, params->salt, -1);
    int rc = db_step(stmt);
    db_finalize(stmt);
    if (rc != DB_DONE) {
        log_error("Failed to write encryption_params");
        return -1;
    }
    return 0;
}

/* Is any value sealed under the field keys yet? 1, 0, or -1 on error. These are
   the values --rekey re-seals (db/maintenance.h). */
static int anything_sealed(db_handle_t *db) {
    db_result_t *result = NULL;
    if (db_query(db, &result, "%s",
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM " TBL_USER_ACCOUNT " WHERE username IS NOT NULL) "
            "OR EXISTS (SELECT 1 FROM " TBL_USER_EMAIL ") "
            "OR EXISTS (SELECT 1 FROM " TBL_PASSWORDLESS_LOGIN_TOKEN ") "
            "OR EXISTS (SELECT 1 FROM " TBL_USER_MFA ") "
            "OR EXISTS (SELECT 1 FROM " TBL_AUTH_REQUEST_SIGNING ") "
            "OR EXISTS (SELECT 1 FROM " TBL_ACCESS_TOKEN_SIGNING ") THEN 1 ELSE 0 END") != 0) {
        return -1;
    }
    const char *v = db_result_row_count(result) == 1 ? db_result_get(result, 0, 0) : NULL;
    int rc = v ? v[0] == '1' : -1;
    db_result_free(result);
    return rc;
}

int encryption_params_get_or_make(db_handle_t *db, const char *method, int iterations,
                                  encrypt_params_t *out) {
    int have = encryption_params_load(db, out);
    if (have != 1 || encryption_params_table_exists(db) != 1) return have;

    int sealed = anything_sealed(db);
    if (sealed == -1) {
        log_error("Failed to check whether anything is sealed yet");
        return -1;
    }
    if (sealed == 0) {
        encrypt_params_t fresh;
        db_stmt_t *stmt = NULL;
        if (encrypt_params_new(method, iterations, &fresh) != 0 ||
            db_prepare(db, &stmt, "INSERT INTO " TBL_ENCRYPTION_PARAMS " (method, iterations, salt) "
                                  "VALUES (" P"1, " P"2, " P"3) ON CONFLICT DO NOTHING") != 0) {
            log_error("Failed to record how encryption_key is stretched");
            return -1;
        }
        db_bind_text(stmt, 1, fresh.method, -1);
        db_bind_int(stmt, 2, fresh.iterations);
        db_bind_text(stmt, 3, fresh.salt, -1);
        int rc = db_step(stmt);
        db_finalize(stmt);
        if (rc != DB_DONE) {
            log_error("Failed to record how encryption_key is stretched");
            return -1;
        }
    }

    /* Whichever row is there now: this one, another instance's, or none if
       values were sealed before stretching existed */
    return encryption_params_load(db, out);
}

int encryption_params_unchanged(db_handle_t *db, int have, const encrypt_params_t *params) {
    encrypt_params_t now;
    int have_now = encryption_params_load(db, &now);
    if (have_now == -1) return -1;
    if (have_now != have) return 0;
    if (have_now == 1) return 1;
    return strcmp(now.method, params->method) == 0 && now.iterations == params->iterations &&
           strcmp(now.salt, params->salt) == 0;
}
