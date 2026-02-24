#include "db/queries/resource_server.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/password.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <stdio.h>
#include <string.h>

int resource_server_code_name_exists(db_handle_t *db, const char *org_code_name,
                                     const char *code_name) {
    if (!db || !org_code_name || !code_name) {
        log_error("Invalid arguments to resource_server_code_name_exists");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_RESOURCE_SERVER " A "
        "JOIN " TBL_ORGANIZATION " B ON A.organization_pin = B.pin "
        "WHERE B.code_name = " P"1 AND A.code_name = " P"2 AND A.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_code_name_exists statement");
        return -1;
    }

    db_bind_text(stmt, 1, org_code_name, -1);
    db_bind_text(stmt, 2, code_name, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Exists */
    } else if (rc == DB_DONE) {
        return 0;  /* Does not exist */
    } else {
        log_error("Error checking resource server code_name existence");
        return -1;
    }
}

int resource_server_address_exists(db_handle_t *db, const char *org_code_name,
                                   const char *address) {
    if (!db || !org_code_name || !address) {
        log_error("Invalid arguments to resource_server_address_exists");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_RESOURCE_SERVER " A "
        "JOIN " TBL_ORGANIZATION " B ON A.organization_pin = B.pin "
        "WHERE B.code_name = " P"1 AND A.address = " P"2 AND A.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_address_exists statement");
        return -1;
    }

    db_bind_text(stmt, 1, org_code_name, -1);
    db_bind_text(stmt, 2, address, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc == DB_ROW) {
        return 1;  /* Exists */
    } else if (rc == DB_DONE) {
        return 0;  /* Does not exist */
    } else {
        log_error("Error checking resource server address existence");
        return -1;
    }
}

int resource_server_create_bootstrap(db_handle_t *db, const char *org_code_name,
                                      const char *code_name, const char *display_name,
                                      const char *address, const char *note,
                                      long long *out_pin) {
    if (!db || !org_code_name || !code_name || !display_name || !address || !out_pin) {
        log_error("Invalid arguments to resource_server_create_bootstrap");
        return -1;
    }

    /* Generate UUID for resource server */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for resource server");
        return -1;
    }

    /* Insert resource server with subquery validation and RETURNING clause */
    const char *sql =
        "INSERT INTO " TBL_RESOURCE_SERVER " "
        "(id, organization_pin, code_name, display_name, address, note) "
        "SELECT " P"1, pin, " P"3, " P"4, " P"5, " P"6 "
        "FROM " TBL_ORGANIZATION " "
        "WHERE code_name = " P"2 "
        "LIMIT 1 "
        "RETURNING pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_create_bootstrap statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_text(stmt, 2, org_code_name, -1);
    db_bind_text(stmt, 3, code_name, -1);
    db_bind_text(stmt, 4, display_name, -1);
    db_bind_text(stmt, 5, address, -1);

    if (note != NULL) {
        db_bind_text(stmt, 6, note, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    /* Execute and get returned pin */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        *out_pin = db_column_int64(stmt, 0);
        db_finalize(stmt);
    } else {
        log_error("Failed to insert resource server: org_code_name='%s', code_name='%s'",
                  org_code_name, code_name);
        db_finalize(stmt);
        return -1;
    }

    log_info("Created resource server: code_name='%s', address='%s'",
             code_name, address);
    return 0;
}

int resource_server_create(db_handle_t *db,
                            long long user_account_pin,
                            long long organization_key_pin,
                            const unsigned char *organization_id,
                            const char *code_name,
                            const char *display_name,
                            const char *address,
                            const char *note,
                            unsigned char *out_id) {
    if (!db || !organization_id || !code_name || !display_name || !address || !out_id) {
        log_error("Invalid arguments to resource_server_create");
        return -1;
    }

    /* Generate UUID for resource server */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for resource server");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "INSERT INTO " TBL_RESOURCE_SERVER " "
            "(id, organization_pin, code_name, display_name, address, note) "
            "SELECT " P"1, o.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = o.pin "
            "LEFT JOIN " TBL_RESOURCE_SERVER " existing_code "
            "  ON existing_code.organization_pin = o.pin "
            "  AND existing_code.code_name = " P"3 "
            "  AND existing_code.is_active = " BOOL_TRUE " "
            "LEFT JOIN " TBL_RESOURCE_SERVER " existing_addr "
            "  ON existing_addr.organization_pin = o.pin "
            "  AND existing_addr.address = " P"5 "
            "  AND existing_addr.is_active = " BOOL_TRUE " "
            "WHERE o.id = " P"2 "
            "AND ok.pin = " P"7 "
            "AND ok.is_active = " BOOL_TRUE " "
            "AND existing_code.pin IS NULL "
            "AND existing_addr.pin IS NULL "
            "LIMIT 1 "
            "RETURNING pin";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_RESOURCE_SERVER " "
            "(id, organization_pin, code_name, display_name, address, note) "
            "SELECT " P"1, o.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = o.pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "LEFT JOIN " TBL_RESOURCE_SERVER " existing_code "
            "  ON existing_code.organization_pin = o.pin "
            "  AND existing_code.code_name = " P"3 "
            "  AND existing_code.is_active = " BOOL_TRUE " "
            "LEFT JOIN " TBL_RESOURCE_SERVER " existing_addr "
            "  ON existing_addr.organization_pin = o.pin "
            "  AND existing_addr.address = " P"5 "
            "  AND existing_addr.is_active = " BOOL_TRUE " "
            "WHERE o.id = " P"2 "
            "AND oa.user_account_pin = " P"7 "
            "AND ua.is_active = " BOOL_TRUE " "
            "AND existing_code.pin IS NULL "
            "AND existing_addr.pin IS NULL "
            "LIMIT 1 "
            "RETURNING pin";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_blob(stmt, 2, organization_id, 16);
    db_bind_text(stmt, 3, code_name, -1);
    db_bind_text(stmt, 4, display_name, -1);
    db_bind_text(stmt, 5, address, -1);

    if (note != NULL) {
        db_bind_text(stmt, 6, note, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    if (is_org_key_auth) {
        db_bind_int64(stmt, 7, organization_key_pin);
    } else {
        db_bind_int64(stmt, 7, user_account_pin);
    }

    /* Execute */
    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_ROW) {
        log_error("Failed to insert resource server (unauthorized or constraint violation)");
        return -1;
    }

    /* Return the generated ID */
    memcpy(out_id, id, 16);

    log_info("Created resource server: code_name='%s', address='%s'",
             code_name, address);
    return 0;
}

int resource_server_list_all(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *organization_id,
                              int limit, int offset,
                              const int *filter_is_active,
                              resource_server_data_t **out_servers, int *out_count,
                              int *out_total) {
    if (!db || !organization_id || !out_servers || !out_count) {
        log_error("Invalid arguments to resource_server_list_all");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);
    const char *sql_session =
        "SELECT rs.id, rs.pin, rs.organization_pin, rs.code_name, "
        "rs.display_name, rs.address, rs.note, rs.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_RESOURCE_SERVER " rs "
        "JOIN " TBL_ORGANIZATION " o ON o.pin = rs.organization_pin "
        "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
        "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
        "WHERE o.id = " P"1 "
        "AND oa.user_account_pin = " P"2 "
        "AND ua.is_active = " BOOL_TRUE " ";

    const char *sql_org_key =
        "SELECT rs.id, rs.pin, rs.organization_pin, rs.code_name, "
        "rs.display_name, rs.address, rs.note, rs.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_RESOURCE_SERVER " rs "
        "JOIN " TBL_ORGANIZATION " o ON o.pin = rs.organization_pin "
        "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
        "WHERE o.id = " P"1 "
        "AND ok.pin = " P"2 "
        "AND ok.is_active = " BOOL_TRUE " ";

    /* Build query with optional is_active filter */
    char sql[1024];
    int pos = snprintf(sql, sizeof(sql), "%s", is_org_key_auth ? sql_org_key : sql_session);

    /* Add is_active filter if specified */
    int param_count = 3;  /* Next parameter after ?1 (org_id) and ?2 (auth_pin) */
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "AND rs.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY rs.code_name "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_list_all statement");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    db_bind_blob(stmt, param++, organization_id, 16);
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
        resource_server_data_t server;
        memset(&server, 0, sizeof(server));

        if (first_row) {
            total_count = db_column_int(stmt, 8);
            first_row = 0;
        }

        /* Extract id */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len == 16) {
            memcpy(server.id, id_blob, 16);
        }

        /* Extract scalar fields */
        server.pin = db_column_int64(stmt, 1);
        server.organization_pin = db_column_int64(stmt, 2);

        const char *code_name = db_column_text(stmt, 3);
        if (code_name) {
            str_copy(server.code_name, sizeof(server.code_name), code_name);
        }

        const char *display_name = db_column_text(stmt, 4);
        if (display_name) {
            str_copy(server.display_name, sizeof(server.display_name), display_name);
        }

        const char *address = db_column_text(stmt, 5);
        if (address) {
            str_copy(server.address, sizeof(server.address), address);
        }

        const char *note = db_column_text(stmt, 6);
        if (note && db_column_type(stmt, 6) != DB_NULL) {
            str_copy(server.note, sizeof(server.note), note);
        }

        server.is_active = db_column_int(stmt, 7);

        /* Append to list */
        if (db_results_append(&list, &list_tail, &server, sizeof(server)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append resource server to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    resource_server_data_t *servers = DB_RESULTS_TO_ARRAY(list, &count, resource_server_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_servers = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No resource servers found");
        return 0;
    }

    if (!servers) {
        log_error("Failed to convert resource server list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_servers = servers;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d resource server%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int resource_server_get_by_id(db_handle_t *db, const unsigned char *server_id,
                               long long user_account_pin,
                               long long organization_key_pin,
                               resource_server_data_t *out_server) {
    if (!db || !server_id || !out_server) {
        log_error("Invalid arguments to resource_server_get_by_id");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT rs.id, rs.pin, rs.organization_pin, rs.code_name, "
            "rs.display_name, rs.address, rs.note, rs.is_active "
            "FROM " TBL_RESOURCE_SERVER " rs "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
            "WHERE rs.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT rs.id, rs.pin, rs.organization_pin, rs.code_name, "
            "rs.display_name, rs.address, rs.note, rs.is_active "
            "FROM " TBL_RESOURCE_SERVER " rs "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE rs.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_get_by_id statement");
        return -1;
    }

    db_bind_blob(stmt, 1, server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Resource server not found or user not authorized");
        return -1;
    }

    memset(out_server, 0, sizeof(*out_server));

    /* Extract id */
    const unsigned char *id_blob = db_column_blob(stmt, 0);
    int blob_len = db_column_bytes(stmt, 0);
    if (blob_len == 16) {
        memcpy(out_server->id, id_blob, 16);
    }

    /* Extract scalar fields */
    out_server->pin = db_column_int64(stmt, 1);
    out_server->organization_pin = db_column_int64(stmt, 2);

    const char *code_name = db_column_text(stmt, 3);
    if (code_name) {
        str_copy(out_server->code_name, sizeof(out_server->code_name), code_name);
    }

    const char *display_name = db_column_text(stmt, 4);
    if (display_name) {
        str_copy(out_server->display_name, sizeof(out_server->display_name), display_name);
    }

    const char *address = db_column_text(stmt, 5);
    if (address) {
        str_copy(out_server->address, sizeof(out_server->address), address);
    }

    const char *note = db_column_text(stmt, 6);
    if (note && db_column_type(stmt, 6) != DB_NULL) {
        str_copy(out_server->note, sizeof(out_server->note), note);
    }

    out_server->is_active = db_column_int(stmt, 7);

    db_finalize(stmt);
    return 0;
}

int resource_server_update(db_handle_t *db, const unsigned char *server_id,
                           long long user_account_pin,
                           long long organization_key_pin,
                           const char *display_name, const char *address,
                           const char *note, const int *is_active) {
    if (!db || !server_id) {
        log_error("Invalid arguments to resource_server_update");
        return -1;
    }

    /* At least one field must be updated */
    if (!display_name && !address && !note && !is_active) {
        log_error("No fields to update in resource_server_update");
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);

    /* Build UPDATE query dynamically */
    char sql[3072];
    int pos = 0;
    int param = 3;  /* ?1 is server_id, ?2 is auth PIN (user or key) */
    int conditions = 0;
    int address_check_param = 0;  /* Track address param for uniqueness check */

    /* Start with UPDATE SET */
    pos += snprintf(sql + pos, sizeof(sql) - pos,
        "UPDATE " TBL_RESOURCE_SERVER " SET updated_at = " NOW "");

    /* Add SET clauses */
    if (display_name) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", display_name = " P"%d", param++);
    }
    if (address) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", address = " P"%d", param++);
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
            "WHERE ok.organization_pin = " TBL_RESOURCE_SERVER ".organization_pin "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE);
    } else {
        /* Session auth - verify user is org admin */
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "SELECT 1 FROM " TBL_ORGANIZATION_ADMIN " oa "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE oa.organization_pin = " TBL_RESOURCE_SERVER ".organization_pin "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE);
    }

    pos += snprintf(sql + pos, sizeof(sql) - pos, ") ");

    /* Add uniqueness check for address if being updated */
    if (address) {
        address_check_param = param++;
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "AND NOT EXISTS ("
                "SELECT 1 FROM " TBL_RESOURCE_SERVER " other "
                "WHERE other.organization_pin = " TBL_RESOURCE_SERVER ".organization_pin "
                "AND other.address = " P"%d "
                "AND other.is_active = " BOOL_TRUE " "
                "AND other.id != " TBL_RESOURCE_SERVER ".id"
            ") ", address_check_param);
    }

    /* Add uniqueness check when reactivating (is_active -> TRUE) */
    /* Check existing address doesn't collide with active records */
    if (is_active && *is_active == 1) {
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "AND NOT EXISTS ("
                "SELECT 1 FROM " TBL_RESOURCE_SERVER " other "
                "WHERE other.organization_pin = " TBL_RESOURCE_SERVER ".organization_pin "
                "AND other.address = " TBL_RESOURCE_SERVER ".address "
                "AND other.is_active = " BOOL_TRUE " "
                "AND other.id != " TBL_RESOURCE_SERVER ".id"
            ") ");
    }

    pos += snprintf(sql + pos, sizeof(sql) - pos, "AND (");

    /* Add WHERE conditions (prevent no-op updates) */
    param = 3;
    if (display_name) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "display_name IS DISTINCT FROM " P"%d", param++);
    }
    if (address) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "address IS DISTINCT FROM " P"%d", param++);
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
        log_error("Failed to prepare resource_server_update statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    /* Bind SET clause parameters (also used for IS DISTINCT FROM) */
    param = 3;
    if (display_name) {
        db_bind_text(stmt, param++, display_name, -1);
    }
    if (address) {
        db_bind_text(stmt, param++, address, -1);
    }
    if (note && note[0] != '\0') {
        db_bind_text(stmt, param++, note, -1);
    }
    if (is_active) {
        db_bind_int(stmt, param++, *is_active);
    }

    /* Bind uniqueness check parameter for address if needed */
    if (address) {
        db_bind_text(stmt, address_check_param, address, -1);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update resource server");
        return -1;
    }

    log_info("Updated resource server");
    return 0;
}

/* ============================================================================
 * Resource Server Key Management Functions
 * ============================================================================ */

int resource_server_key_create(db_handle_t *db,
                                long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *resource_server_id,
                                const char *secret,
                                const char *note,
                                unsigned char *out_key_id) {
    if (!db || !resource_server_id || !secret || !out_key_id) {
        log_error("Invalid arguments to resource_server_key_create");
        return -1;
    }

    /* Generate UUID for key_id */
    unsigned char key_id[16];
    if (crypto_random_bytes(key_id, sizeof(key_id)) != 0) {
        log_error("Failed to generate key_id");
        return -1;
    }

    /* Hash secret with configured algorithm */
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

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "INSERT INTO " TBL_RESOURCE_SERVER_KEY " "
            "(id, resource_server_pin, salt, hash_iterations, secret_hash, note) "
            "SELECT " P"1, rs.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_RESOURCE_SERVER " rs "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
            "WHERE rs.id = " P"2 "
            "AND ok.pin = " P"7 "
            "AND ok.is_active = " BOOL_TRUE " "
            "AND rs.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_RESOURCE_SERVER_KEY " "
            "(id, resource_server_pin, salt, hash_iterations, secret_hash, note) "
            "SELECT " P"1, rs.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_RESOURCE_SERVER " rs "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE rs.id = " P"2 "
            "AND oa.user_account_pin = " P"7 "
            "AND ua.is_active = " BOOL_TRUE " "
            "AND rs.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_key_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, key_id, sizeof(key_id));
    db_bind_blob(stmt, 2, resource_server_id, 16);
    db_bind_text(stmt, 3, salt_hex, -1);
    db_bind_int(stmt, 4, iterations);
    db_bind_text(stmt, 5, hash_hex, -1);

    if (note != NULL) {
        db_bind_text(stmt, 6, note, -1);
    } else {
        db_bind_null(stmt, 6);
    }

    if (is_org_key_auth) {
        db_bind_int64(stmt, 7, organization_key_pin);
    } else {
        db_bind_int64(stmt, 7, user_account_pin);
    }

    /* Execute */
    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert resource server key (unauthorized or constraint violation)");
        return -1;
    }

    /* Return the generated key_id */
    memcpy(out_key_id, key_id, 16);

    log_info("Created resource server key");
    return 0;
}

int resource_server_key_list(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *resource_server_id,
                             int limit, int offset,
                             const int *filter_is_active,
                             resource_server_key_data_t **out_keys,
                             int *out_count,
                             int *out_total) {
    if (!db || !resource_server_id || !out_keys || !out_count) {
        log_error("Invalid arguments to resource_server_key_list");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);

    /* Build query with optional is_active filter */
    char sql[1024];
    int pos;

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        pos = snprintf(sql, sizeof(sql),
            "SELECT rsk.id, rsk.is_active, rsk.generated_at, rsk.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_RESOURCE_SERVER_KEY " rsk "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = rsk.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
            "WHERE rs.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " ");
    } else {
        /* Session authentication - verify user is org admin */
        pos = snprintf(sql, sizeof(sql),
            "SELECT rsk.id, rsk.is_active, rsk.generated_at, rsk.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_RESOURCE_SERVER_KEY " rsk "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = rsk.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE rs.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " ");
    }

    /* Add is_active filter if specified */
    int param_count = 3;  /* Next parameter after ?1 (rs_id) and ?2 (auth_pin) */
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "AND rsk.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY rsk.generated_at DESC, rsk.pin DESC "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_key_list statement");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    db_bind_blob(stmt, param++, resource_server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, param++, organization_key_pin);
    } else {
        db_bind_int64(stmt, param++, user_account_pin);
    }

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
        resource_server_key_data_t key;
        memset(&key, 0, sizeof(key));

        if (first_row) {
            total_count = db_column_int(stmt, 4);
            first_row = 0;
        }

        /* Extract id (key_id) */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len == 16) {
            memcpy(key.id, id_blob, 16);
        }

        /* Extract scalar fields */
        key.is_active = db_column_int(stmt, 1);

        const char *generated_at = db_column_text(stmt, 2);
        if (generated_at) {
            str_copy(key.generated_at, sizeof(key.generated_at), generated_at);
        }

        const char *note = db_column_text(stmt, 3);
        if (note && db_column_type(stmt, 3) != DB_NULL) {
            str_copy(key.note, sizeof(key.note), note);
        }

        /* Append to list */
        if (db_results_append(&list, &list_tail, &key, sizeof(key)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append resource server key to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    resource_server_key_data_t *keys = DB_RESULTS_TO_ARRAY(list, &count, resource_server_key_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_keys = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No resource server keys found");
        return 0;
    }

    if (!keys) {
        log_error("Failed to convert resource server key list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_keys = keys;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d resource server key%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int resource_server_key_revoke(db_handle_t *db,
                               long long user_account_pin,
                               long long organization_key_pin,
                               const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to resource_server_key_revoke");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "UPDATE " TBL_RESOURCE_SERVER_KEY " "
            "SET is_active = " BOOL_FALSE ", updated_at = " NOW " "
            "WHERE id = " P"1 "
            "AND EXISTS ("
                "SELECT 1 FROM " TBL_RESOURCE_SERVER " rs "
                "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
                "WHERE rs.pin = " TBL_RESOURCE_SERVER_KEY ".resource_server_pin "
                "AND ok.pin = " P"2 "
                "AND ok.is_active = " BOOL_TRUE
            ") "
            "AND is_active = " BOOL_TRUE;  /* Only revoke if currently active */
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "UPDATE " TBL_RESOURCE_SERVER_KEY " "
            "SET is_active = " BOOL_FALSE ", updated_at = " NOW " "
            "WHERE id = " P"1 "
            "AND EXISTS ("
                "SELECT 1 FROM " TBL_RESOURCE_SERVER " rs "
                "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
                "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
                "WHERE rs.pin = " TBL_RESOURCE_SERVER_KEY ".resource_server_pin "
                "AND oa.user_account_pin = " P"2 "
                "AND ua.is_active = " BOOL_TRUE
            ") "
            "AND is_active = " BOOL_TRUE;  /* Only revoke if currently active */
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_key_revoke statement");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to revoke resource server key");
        return -1;
    }

    log_info("Revoked resource server key");
    return 0;
}

int resource_server_key_verify(db_handle_t *db,
                               const unsigned char *key_id,
                               const char *secret,
                               long long *out_resource_server_pin) {
    if (!db || !key_id || !secret) {
        log_error("Invalid arguments to resource_server_key_verify");
        return -1;
    }

    const char *sql =
        "SELECT rsk.salt, rsk.hash_iterations, rsk.secret_hash, rsk.resource_server_pin "
        "FROM " TBL_RESOURCE_SERVER_KEY " rsk "
        "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = rsk.resource_server_pin "
        "WHERE rsk.id = " P"1 "
        "AND rsk.is_active = " BOOL_TRUE " "
        "AND rs.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_key_verify statement");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Resource server key not found or inactive");
        return 0;  /* Invalid key */
    }

    /* Extract stored hash parameters */
    const char *salt = (const char *)db_column_text(stmt, 0);
    int iterations = db_column_int(stmt, 1);
    const char *hash = (const char *)db_column_text(stmt, 2);
    long long resource_server_pin = db_column_int64(stmt, 3);

    if (!salt || !hash) {
        log_error("NULL hash fields in resource_server_key");
        db_finalize(stmt);
        return -1;
    }

    /* Verify secret using timing-safe comparison */
    int valid = crypto_password_verify(secret, strlen(secret), salt, iterations, hash);

    db_finalize(stmt);

    /* If valid, return resource server pin if requested */
    if (valid == 1) {
        if (out_resource_server_pin != NULL) {
            *out_resource_server_pin = resource_server_pin;
        }
        log_info("Resource server key verified successfully");
        return 1;  /* Valid */
    } else if (valid == 0) {
        log_info("Resource server key verification failed (invalid secret)");
        return 0;  /* Invalid */
    } else {
        log_error("Error during resource server key verification");
        return -1;  /* Error */
    }
}
