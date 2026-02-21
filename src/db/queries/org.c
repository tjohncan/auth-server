#include "db/queries/org.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/password.h"
#include "util/log.h"
#include "util/str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int org_create(db_handle_t *db, const char *code_name,
               const char *display_name, const char *note,
               long long *out_pin) {
    if (!db || !code_name || !display_name || !out_pin) {
        log_error("Invalid arguments to org_create");
        return -1;
    }

    /* Generate UUID for organization */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for organization");
        return -1;
    }

    /* Insert organization with RETURNING clause */
    const char *sql =
        "INSERT INTO " TBL_ORGANIZATION " (id, code_name, display_name, note) "
        "VALUES (" P"1, " P"2, " P"3, " P"4) "
        "RETURNING pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_text(stmt, 2, code_name, -1);
    db_bind_text(stmt, 3, display_name, -1);

    if (note != NULL) {
        db_bind_text(stmt, 4, note, -1);
    } else {
        db_bind_null(stmt, 4);
    }

    /* Execute and get returned pin */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        *out_pin = db_column_int64(stmt, 0);
        db_finalize(stmt);
    } else {
        log_error("Failed to insert organization: code_name='%s'", code_name);
        db_finalize(stmt);
        return -1;
    }

    log_info("Created organization: code_name='%s', display_name='%s'",
             code_name, display_name);
    return 0;
}

int org_exists(db_handle_t *db, const char *code_name) {
    if (!db || !code_name) {
        log_error("Invalid arguments to org_exists");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_ORGANIZATION " "
        "WHERE code_name = " P"1 "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_exists statement");
        return -1;
    }

    db_bind_text(stmt, 1, code_name, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        /* Organization exists */
        return 1;
    } else if (rc == DB_DONE) {
        /* No rows returned, organization does not exist */
        return 0;
    } else {
        /* Error */
        log_error("Error checking if organization exists: code_name='%s'", code_name);
        return -1;
    }
}

int org_list_all_unscoped(db_handle_t *db,
                          int limit, int offset,
                          const int *filter_is_active,
                          org_data_t **out_orgs, int *out_count,
                          int *out_total) {
    if (!db || !out_orgs || !out_count) {
        log_error("Invalid arguments to org_list_all_unscoped");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    /* Build query with optional is_active filter (no user authorization) */
    char sql[1024];
    int pos = snprintf(sql, sizeof(sql),
        "SELECT o.id, o.pin, o.code_name, o.display_name, o.note, o.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_ORGANIZATION " o ");

    /* Add WHERE clause if is_active filter specified */
    int param_count = 1;
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "WHERE o.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY o.code_name "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_list_all_unscoped statement");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    if (filter_is_active) {
        db_bind_int(stmt, param++, *filter_is_active);
    }

    db_bind_int(stmt, param++, limit);
    db_bind_int(stmt, param++, offset);

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        org_data_t org;
        memset(&org, 0, sizeof(org));

        if (first_row) {
            total_count = db_column_int(stmt, 6);
            first_row = 0;
        }

        /* Extract id */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len == 16) {
            memcpy(org.id, id_blob, 16);
        }

        /* Extract scalar fields */
        org.pin = db_column_int64(stmt, 1);

        const char *code_name = db_column_text(stmt, 2);
        if (code_name) {
            str_copy(org.code_name, sizeof(org.code_name), code_name);
        }

        const char *display_name = db_column_text(stmt, 3);
        if (display_name) {
            str_copy(org.display_name, sizeof(org.display_name), display_name);
        }

        const char *note = db_column_text(stmt, 4);
        if (note) {
            str_copy(org.note, sizeof(org.note), note);
        }

        org.is_active = db_column_int(stmt, 5);

        /* Append to list */
        if (db_results_append(&list, &list_tail, &org, sizeof(org)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append org to results list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    org_data_t *orgs = DB_RESULTS_TO_ARRAY(list, &count, org_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_orgs = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        return 0;
    }

    if (!orgs) {
        log_error("Failed to convert organization list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_orgs = orgs;
    *out_count = count;
    if (out_total) *out_total = total_count;

    return 0;
}

int org_list_all(db_handle_t *db, long long user_account_pin,
                 long long organization_key_pin,
                 int limit, int offset,
                 const int *filter_is_active,
                 org_data_t **out_orgs, int *out_count,
                 int *out_total) {
    if (!db || !out_orgs || !out_count) {
        log_error("Invalid arguments to org_list_all");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);
    const char *sql_session =
        "SELECT o.id, o.pin, o.code_name, o.display_name, o.note, o.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_ORGANIZATION " o "
        "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = o.pin "
        "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
        "WHERE oa.user_account_pin = " P"1 "
        "AND ua.is_active = " BOOL_TRUE " ";

    const char *sql_org_key =
        "SELECT o.id, o.pin, o.code_name, o.display_name, o.note, o.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_ORGANIZATION " o "
        "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = o.pin "
        "WHERE ok.pin = " P"1 "
        "AND ok.is_active = " BOOL_TRUE " ";

    /* Build query with optional is_active filter */
    char sql[1024];
    int pos = snprintf(sql, sizeof(sql), "%s", is_org_key_auth ? sql_org_key : sql_session);

    /* Add is_active filter if specified */
    int param_count = 2;  /* Next parameter after ?1 */
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "AND o.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY o.code_name "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_list_all statement");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    if (is_org_key_auth) {
        db_bind_int64(stmt, param++, organization_key_pin);
    } else {
        db_bind_int64(stmt, param++, user_account_pin);
    }

    /* Bind filter if present */
    if (filter_is_active) {
        db_bind_int(stmt, param++, *filter_is_active);
    }

    db_bind_int(stmt, param++, limit);
    db_bind_int(stmt, param++, offset);

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        org_data_t org;
        memset(&org, 0, sizeof(org));

        if (first_row) {
            total_count = db_column_int(stmt, 6);
            first_row = 0;
        }

        /* Extract id */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len == 16) {
            memcpy(org.id, id_blob, 16);
        }

        /* Extract scalar fields */
        org.pin = db_column_int64(stmt, 1);

        const char *code_name = db_column_text(stmt, 2);
        if (code_name) {
            str_copy(org.code_name, sizeof(org.code_name), code_name);
        }

        const char *display_name = db_column_text(stmt, 3);
        if (display_name) {
            str_copy(org.display_name, sizeof(org.display_name), display_name);
        }

        const char *note = db_column_text(stmt, 4);
        if (note && db_column_type(stmt, 4) != DB_NULL) {
            str_copy(org.note, sizeof(org.note), note);
        }

        org.is_active = db_column_int(stmt, 5);

        /* Append to list */
        if (db_results_append(&list, &list_tail, &org, sizeof(org)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append organization to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    org_data_t *orgs = DB_RESULTS_TO_ARRAY(list, &count, org_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_orgs = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No organizations found for user");
        return 0;
    }

    if (!orgs) {
        log_error("Failed to convert organization list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_orgs = orgs;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d organization%s for user (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int org_get_by_id(db_handle_t *db, const unsigned char *org_id,
                  long long user_account_pin, long long organization_key_pin,
                  org_data_t *out_org) {
    if (!db || !org_id || !out_org) {
        log_error("Invalid arguments to org_get_by_id");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT o.id, o.pin, o.code_name, o.display_name, o.note, o.is_active "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = o.pin "
            "WHERE o.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT o.id, o.pin, o.code_name, o.display_name, o.note, o.is_active "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = o.pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE o.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_get_by_id statement");
        return -1;
    }

    db_bind_blob(stmt, 1, org_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Organization not found or user not authorized");
        return -1;
    }

    memset(out_org, 0, sizeof(*out_org));

    /* Extract id */
    const unsigned char *id_blob = db_column_blob(stmt, 0);
    int blob_len = db_column_bytes(stmt, 0);
    if (blob_len == 16) {
        memcpy(out_org->id, id_blob, 16);
    }

    /* Extract scalar fields */
    out_org->pin = db_column_int64(stmt, 1);

    const char *code_name = db_column_text(stmt, 2);
    if (code_name) {
        str_copy(out_org->code_name, sizeof(out_org->code_name), code_name);
    }

    const char *display_name = db_column_text(stmt, 3);
    if (display_name) {
        str_copy(out_org->display_name, sizeof(out_org->display_name), display_name);
    }

    const char *note = db_column_text(stmt, 4);
    if (note && db_column_type(stmt, 4) != DB_NULL) {
        str_copy(out_org->note, sizeof(out_org->note), note);
    }

    out_org->is_active = db_column_int(stmt, 5);

    db_finalize(stmt);
    return 0;
}

int org_update(db_handle_t *db, const unsigned char *org_id,
               long long user_account_pin, long long organization_key_pin,
               const char *display_name, const char *note,
               const int *is_active) {
    if (!db || !org_id) {
        log_error("Invalid arguments to org_update");
        return -1;
    }

    /* At least one field must be updated */
    if (!display_name && !note && !is_active) {
        log_error("No fields to update in org_update");
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);

    /* Build UPDATE query dynamically - single buffer, build sequentially */
    char sql[2048];
    int pos = 0;
    int param = 3;  /* ?1 is org_id, ?2 is auth PIN (user or key) */
    int conditions = 0;

    /* Start with UPDATE SET */
    pos += snprintf(sql + pos, sizeof(sql) - pos,
        "UPDATE " TBL_ORGANIZATION " SET updated_at = " NOW "");

    /* Add SET clauses */
    if (display_name) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", display_name = " P"%d", param++);
    }
    if (note) {
        if (note[0] == '\0') {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", note = NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", note = " P"%d", param++);
        }
    }
    if (is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", is_active = " P"%d", param++);
    }

    /* Build WHERE clause with dual-auth security check */
    pos += snprintf(sql + pos, sizeof(sql) - pos, " WHERE id = " P"1 AND EXISTS (");

    if (is_org_key_auth) {
        /* Org key auth - verify key is active */
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "SELECT 1 FROM " TBL_ORGANIZATION_KEY " ok "
            "WHERE ok.organization_pin = " TBL_ORGANIZATION ".pin "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE);
    } else {
        /* Session auth - verify user is org admin */
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "SELECT 1 FROM " TBL_ORGANIZATION_ADMIN " oa "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE oa.organization_pin = " TBL_ORGANIZATION ".pin "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE);
    }

    pos += snprintf(sql + pos, sizeof(sql) - pos, ") AND (");

    /* Add WHERE conditions (prevent no-op updates) */
    param = 3;  /* Reset to match SET clause params */
    if (display_name) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "display_name IS DISTINCT FROM " P"%d", param++);
    }
    if (note) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        if (note[0] == '\0') {
            pos += snprintf(sql + pos, sizeof(sql) - pos, "note IS NOT NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos,
                "note IS DISTINCT FROM " P"%d", param++);
        }
    }
    if (is_active) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "is_active IS DISTINCT FROM " P"%d", param++);
    }

    /* Close WHERE clause */
    snprintf(sql + pos, sizeof(sql) - pos, ")");

    /* Prepare statement */
    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare org_update statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, org_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    param = 3;
    if (display_name) {
        db_bind_text(stmt, param++, display_name, -1);
    }
    if (note && note[0] != '\0') {
        db_bind_text(stmt, param++, note, -1);
    }
    if (is_active) {
        db_bind_int(stmt, param++, *is_active);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update organization");
        return -1;
    }

    /* Note: If no rows updated, either values unchanged or user not authorized */
    log_info("Updated organization");
    return 0;
}

/* ============================================================================
 * ORGANIZATION KEY MANAGEMENT
 * ========================================================================== */

int organization_get_pin_by_code_name(db_handle_t *db,
                                       const char *organization_code_name,
                                       long long *out_organization_pin) {
    if (!db || !organization_code_name || !out_organization_pin) {
        log_error("Invalid arguments to organization_get_pin_by_code_name");
        return -1;
    }

    const char *sql =
        "SELECT pin FROM " TBL_ORGANIZATION " "
        "WHERE code_name = " P"1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare organization PIN lookup query");
        return -1;
    }

    db_bind_text(stmt, 1, organization_code_name, -1);

    int result = db_step(stmt);
    if (result != DB_ROW) {
        db_finalize(stmt);
        return -1;  /* Not found */
    }

    *out_organization_pin = db_column_int64(stmt, 0);
    db_finalize(stmt);

    return 0;
}

int organization_get_code_name_by_pin(db_handle_t *db,
                                       long long organization_pin,
                                       char *out_code_name) {
    if (!db || !out_code_name) {
        log_error("Invalid arguments to organization_get_code_name_by_pin");
        return -1;
    }

    const char *sql =
        "SELECT code_name FROM " TBL_ORGANIZATION " "
        "WHERE pin = " P"1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare organization code name lookup query");
        return -1;
    }

    db_bind_int64(stmt, 1, organization_pin);

    int result = db_step(stmt);
    if (result != DB_ROW) {
        db_finalize(stmt);
        return -1;  /* Not found */
    }

    const char *code_name = (const char *)db_column_text(stmt, 0);
    if (!code_name) {
        db_finalize(stmt);
        return -1;
    }

    str_copy(out_code_name, 128, code_name);
    db_finalize(stmt);

    return 0;
}

int organization_key_get_organization_pin(db_handle_t *db,
                                           const unsigned char *key_id,
                                           long long *out_organization_pin) {
    if (!db || !key_id || !out_organization_pin) {
        log_error("Invalid arguments to organization_key_get_organization_pin");
        return -1;
    }

    const char *sql =
        "SELECT organization_pin FROM " TBL_ORGANIZATION_KEY " "
        "WHERE id = " P"1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare key organization lookup query");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);

    int result = db_step(stmt);
    if (result != DB_ROW) {
        db_finalize(stmt);
        return -1;  /* Not found */
    }

    *out_organization_pin = db_column_int64(stmt, 0);
    db_finalize(stmt);

    return 0;
}

int organization_key_create(db_handle_t *db,
                            const char *organization_code_name,
                            const char *secret,
                            const char *note,
                            unsigned char *out_key_id) {
    if (!db || !organization_code_name || !secret || !out_key_id) {
        log_error("Invalid arguments to organization_key_create");
        return -1;
    }

    /* Look up organization pin by code_name */
    const char *lookup_sql =
        "SELECT pin FROM " TBL_ORGANIZATION " "
        "WHERE code_name = " P"1 AND is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *lookup_stmt = NULL;
    if (db_prepare(db, &lookup_stmt, lookup_sql) != 0) {
        log_error("Failed to prepare organization lookup");
        return -1;
    }

    db_bind_text(lookup_stmt, 1, organization_code_name, -1);

    long long org_pin = 0;
    int lookup_rc = db_step(lookup_stmt);
    if (lookup_rc == DB_ROW) {
        org_pin = db_column_int64(lookup_stmt, 0);
        db_finalize(lookup_stmt);
    } else {
        db_finalize(lookup_stmt);
        log_error("Organization not found or inactive: %s", organization_code_name);
        return -1;
    }

    /* Hash secret using configured algorithm */
    char salt_hex[PASSWORD_SALT_HEX_MAX_LENGTH];
    char hash_hex[PASSWORD_HASH_HEX_MAX_LENGTH];
    int iterations;

    if (crypto_password_hash(secret, strlen(secret),
                            salt_hex, sizeof(salt_hex),
                            &iterations,
                            hash_hex, sizeof(hash_hex)) != 0) {
        log_error("Failed to hash secret");
        return -1;
    }

    /* Generate UUID for key */
    unsigned char key_id[16];
    if (crypto_random_bytes(key_id, sizeof(key_id)) != 0) {
        log_error("Failed to generate key UUID");
        return -1;
    }

    /* Insert organization key */
    const char *insert_sql =
        "INSERT INTO " TBL_ORGANIZATION_KEY " "
        "(id, organization_pin, secret_hash, salt, hash_iterations, note) "
        "VALUES (" P"1, " P"2, " P"3, " P"4, " P"5, " P"6)";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, insert_sql) != 0) {
        log_error("Failed to prepare organization key insert");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);
    db_bind_int64(stmt, 2, org_pin);
    db_bind_text(stmt, 3, hash_hex, -1);
    db_bind_text(stmt, 4, salt_hex, -1);
    db_bind_int(stmt, 5, iterations);
    db_bind_text(stmt, 6, note ? note : "", -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert organization key");
        return -1;
    }

    memcpy(out_key_id, key_id, 16);
    log_info("Created organization key for org: %s", organization_code_name);
    return 0;
}

int organization_key_list(db_handle_t *db,
                          const char *organization_code_name,
                          int limit, int offset,
                          const int *filter_is_active,
                          organization_key_data_t **out_keys,
                          int *out_count,
                          int *out_total) {
    if (!db || !organization_code_name || !out_keys || !out_count) {
        log_error("Invalid arguments to organization_key_list");
        return -1;
    }

    *out_keys = NULL;
    *out_count = 0;

    /* Build SQL with optional is_active filter */
    char sql[1024];
    int param_count = 2;
    int sql_len = snprintf(sql, sizeof(sql),
        "SELECT ok.id, ok.is_active, ok.generated_at, ok.note, COUNT(*) OVER() as total_count "
        "FROM " TBL_ORGANIZATION_KEY " ok "
        "JOIN " TBL_ORGANIZATION " o ON ok.organization_pin = o.pin "
        "WHERE o.code_name = " P"1");

    if (filter_is_active) {
        sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                           " AND ok.is_active = " P"%d", param_count++);
    }

    sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                       " ORDER BY ok.generated_at DESC, ok.pin DESC");

    if (limit > 0) {
        sql_len += snprintf(sql + sql_len, sizeof(sql) - sql_len,
                           " LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);
        param_count += 2;
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare organization key list query");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    db_bind_text(stmt, param++, organization_code_name, -1);

    if (filter_is_active) {
        db_bind_int(stmt, param++, *filter_is_active);
    }

    if (limit > 0) {
        db_bind_int(stmt, param++, limit);
        db_bind_int(stmt, param++, offset);
    }

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        organization_key_data_t key;
        memset(&key, 0, sizeof(key));

        if (first_row) {
            total_count = db_column_int(stmt, 4);
            first_row = 0;
        }

        const unsigned char *id_blob = db_column_blob(stmt, 0);
        if (id_blob) {
            memcpy(key.id, id_blob, 16);
        }
        key.is_active = db_column_int(stmt, 1);

        const char *generated_at = db_column_text(stmt, 2);
        if (generated_at) {
            str_copy(key.generated_at, sizeof(key.generated_at), generated_at);
        }

        const char *note_text = db_column_text(stmt, 3);
        if (note_text) {
            str_copy(key.note, sizeof(key.note), note_text);
        }

        if (db_results_append(&list, &list_tail, &key, sizeof(key)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append organization key to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    organization_key_data_t *keys = DB_RESULTS_TO_ARRAY(list, &count, organization_key_data_t);

    if (count == 0) {
        *out_keys = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        return 0;
    }

    if (!keys) {
        log_error("Failed to convert organization key list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_keys = keys;
    *out_count = count;
    if (out_total) *out_total = total_count;
    return 0;
}

int organization_key_revoke(db_handle_t *db,
                            const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to organization_key_revoke");
        return -1;
    }

    const char *sql =
        "UPDATE " TBL_ORGANIZATION_KEY " "
        "SET is_active = " BOOL_FALSE ", updated_at = " NOW " "
        "WHERE id = " P"1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare organization key revoke");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to revoke organization key");
        return -1;
    }

    log_info("Revoked organization key");
    return 0;
}

int organization_key_verify(db_handle_t *db,
                            const unsigned char *key_id,
                            const char *secret,
                            long long *out_organization_pin,
                            long long *out_key_pin) {
    if (!db || !key_id || !secret || !out_organization_pin || !out_key_pin) {
        log_error("Invalid arguments to organization_key_verify");
        return -1;
    }

    const char *sql =
        "SELECT ok.pin, ok.organization_pin, ok.secret_hash, ok.salt, ok.hash_iterations "
        "FROM " TBL_ORGANIZATION_KEY " ok "
        "WHERE ok.id = " P"1 AND ok.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare organization key verify");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);

    int rc = db_step(stmt);
    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_error("Organization key not found or inactive");
        return -1;
    }

    long long key_pin = db_column_int64(stmt, 0);
    long long org_pin = db_column_int64(stmt, 1);
    const char *stored_hash = db_column_text(stmt, 2);
    const char *salt = db_column_text(stmt, 3);
    int iterations = db_column_int(stmt, 4);

    /* Verify password using timing-safe comparison */
    int valid = crypto_password_verify(secret, strlen(secret),
                                       salt, iterations, stored_hash);

    db_finalize(stmt);

    if (valid != 1) {
        log_error("Organization key secret verification failed");
        return -1;
    }

    *out_organization_pin = org_pin;
    *out_key_pin = key_pin;
    log_info("Organization key verified successfully");
    return 0;
}


