#include "db/queries/client.h"
#include "db/db_sql.h"
#include "crypto/random.h"
#include "crypto/password.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <stdio.h>
#include <string.h>

int client_code_name_exists(db_handle_t *db, const char *org_code_name,
                            const char *code_name) {
    if (!db || !org_code_name || !code_name) {
        log_error("Invalid arguments to client_code_name_exists");
        return -1;
    }

    const char *sql =
        "SELECT 1 FROM " TBL_CLIENT " A "
        "JOIN " TBL_ORGANIZATION " B ON A.organization_pin = B.pin "
        "WHERE B.code_name = " P"1 AND A.code_name = " P"2 AND A.is_active = " BOOL_TRUE " "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_code_name_exists statement");
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
        log_error("Error checking client code_name existence");
        return -1;
    }
}

int client_create_bootstrap(db_handle_t *db, const char *org_code_name,
                             const char *code_name, const char *display_name,
                             const char *client_type, const char *grant_type,
                             const char *note,
                             int require_mfa, int access_token_ttl_seconds,
                             int issue_refresh_tokens, int refresh_token_ttl_seconds,
                             int maximum_session_seconds, int secret_rotation_seconds,
                             int is_universal,
                             unsigned char *out_id, long long *out_pin) {
    if (!db || !org_code_name || !code_name || !display_name || !client_type || !grant_type || !out_id || !out_pin) {
        log_error("Invalid arguments to client_create_bootstrap");
        return -1;
    }

    /* Generate UUID for client */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for client");
        return -1;
    }

    /* Insert client with subquery validation and RETURNING clause */
    const char *sql =
        "INSERT INTO " TBL_CLIENT " "
        "(id, organization_pin, code_name, display_name, client_type, grant_type, note, "
        "require_mfa, access_token_ttl_seconds, issue_refresh_tokens, "
        "refresh_token_ttl_seconds, maximum_session_seconds, secret_rotation_seconds, is_universal) "
        "SELECT " P"1, pin, " P"3, " P"4, " P"5, " P"6, " P"7, " P"8, " P"9, " P"10, " P"11, " P"12, " P"13, " P"14 "
        "FROM " TBL_ORGANIZATION " "
        "WHERE code_name = " P"2 "
        "LIMIT 1 "
        "RETURNING pin";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_create_bootstrap statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_text(stmt, 2, org_code_name, -1);
    db_bind_text(stmt, 3, code_name, -1);
    db_bind_text(stmt, 4, display_name, -1);
    db_bind_text(stmt, 5, client_type, -1);
    db_bind_text(stmt, 6, grant_type, -1);

    if (note != NULL) {
        db_bind_text(stmt, 7, note, -1);
    } else {
        db_bind_null(stmt, 7);
    }

    db_bind_int(stmt, 8, require_mfa);
    db_bind_int(stmt, 9, access_token_ttl_seconds);
    db_bind_int(stmt, 10, issue_refresh_tokens);

    if (refresh_token_ttl_seconds >= 0) {
        db_bind_int(stmt, 11, refresh_token_ttl_seconds);
    } else {
        db_bind_null(stmt, 11);
    }

    if (maximum_session_seconds >= 0) {
        db_bind_int(stmt, 12, maximum_session_seconds);
    } else {
        db_bind_null(stmt, 12);
    }

    if (secret_rotation_seconds >= 0) {
        db_bind_int(stmt, 13, secret_rotation_seconds);
    } else {
        db_bind_null(stmt, 13);
    }

    db_bind_int(stmt, 14, is_universal);

    /* Execute and get returned pin */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        *out_pin = db_column_int64(stmt, 0);
        db_finalize(stmt);
    } else {
        log_error("Failed to insert client: org_code_name='%s', code_name='%s'",
                  org_code_name, code_name);
        db_finalize(stmt);
        return -1;
    }

    /* Copy UUID to output */
    memcpy(out_id, id, 16);

    log_info("Created client: code_name='%s', type='%s', grant_type='%s'",
             code_name, client_type, grant_type);
    return 0;
}

int client_add_redirect_uri_bootstrap(db_handle_t *db, const unsigned char *client_id,
                            const char *redirect_uri, const char *note) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to client_add_redirect_uri_bootstrap");
        return -1;
    }

    /* Insert redirect URI with subquery validation */
    const char *sql =
        "INSERT INTO " TBL_CLIENT_REDIRECT_URI " (client_pin, redirect_uri, note) "
        "SELECT pin, " P"2, " P"3 "
        "FROM " TBL_CLIENT " "
        "WHERE id = " P"1 "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_add_redirect_uri_bootstrap statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_text(stmt, 2, redirect_uri, -1);

    if (note != NULL) {
        db_bind_text(stmt, 3, note, -1);
    } else {
        db_bind_null(stmt, 3);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert redirect URI");
        return -1;
    }

    log_info("Added redirect URI: uri='%s'", redirect_uri);
    return 0;
}

int client_create(db_handle_t *db,
                  long long user_account_pin,
                  long long organization_key_pin,
                  const unsigned char *organization_id,
                  const char *code_name,
                  const char *display_name,
                  const char *client_type,
                  const char *grant_type,
                  const char *note,
                  int require_mfa,
                  int access_token_ttl_seconds,
                  int issue_refresh_tokens,
                  int refresh_token_ttl_seconds,
                  int maximum_session_seconds,
                  int secret_rotation_seconds,
                  unsigned char *out_id) {
    if (!db || !organization_id || !code_name || !display_name ||
        !client_type || !grant_type || !out_id) {
        log_error("Invalid arguments to client_create");
        return -1;
    }

    /* Generate UUID for client */
    unsigned char id[16];
    if (crypto_random_bytes(id, sizeof(id)) != 0) {
        log_error("Failed to generate UUID for client");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "INSERT INTO " TBL_CLIENT " "
            "(id, organization_pin, code_name, display_name, client_type, grant_type, note, "
            "require_mfa, access_token_ttl_seconds, issue_refresh_tokens, "
            "refresh_token_ttl_seconds, maximum_session_seconds, secret_rotation_seconds, is_universal) "
            "SELECT " P"1, o.pin, " P"3, " P"4, " P"5, " P"6, " P"7, "
            P"8, " P"9, " P"10, " P"11, " P"12, " P"13, " BOOL_FALSE " "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = o.pin "
            "LEFT JOIN " TBL_CLIENT " existing_code "
            "  ON existing_code.organization_pin = o.pin "
            "  AND existing_code.code_name = " P"3 "
            "  AND existing_code.is_active = " BOOL_TRUE " "
            "WHERE o.id = " P"2 "
            "AND ok.pin = " P"14 "
            "AND ok.is_active = " BOOL_TRUE " "
            "AND existing_code.pin IS NULL "
            "LIMIT 1 "
            "RETURNING pin";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_CLIENT " "
            "(id, organization_pin, code_name, display_name, client_type, grant_type, note, "
            "require_mfa, access_token_ttl_seconds, issue_refresh_tokens, "
            "refresh_token_ttl_seconds, maximum_session_seconds, secret_rotation_seconds, is_universal) "
            "SELECT " P"1, o.pin, " P"3, " P"4, " P"5, " P"6, " P"7, "
            P"8, " P"9, " P"10, " P"11, " P"12, " P"13, " BOOL_FALSE " "
            "FROM " TBL_ORGANIZATION " o "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = o.pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "LEFT JOIN " TBL_CLIENT " existing_code "
            "  ON existing_code.organization_pin = o.pin "
            "  AND existing_code.code_name = " P"3 "
            "  AND existing_code.is_active = " BOOL_TRUE " "
            "WHERE o.id = " P"2 "
            "AND oa.user_account_pin = " P"14 "
            "AND ua.is_active = " BOOL_TRUE " "
            "AND existing_code.pin IS NULL "
            "LIMIT 1 "
            "RETURNING pin";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, id, sizeof(id));
    db_bind_blob(stmt, 2, organization_id, 16);
    db_bind_text(stmt, 3, code_name, -1);
    db_bind_text(stmt, 4, display_name, -1);
    db_bind_text(stmt, 5, client_type, -1);
    db_bind_text(stmt, 6, grant_type, -1);

    if (note != NULL) {
        db_bind_text(stmt, 7, note, -1);
    } else {
        db_bind_null(stmt, 7);
    }

    db_bind_int(stmt, 8, require_mfa);
    db_bind_int(stmt, 9, access_token_ttl_seconds);
    db_bind_int(stmt, 10, issue_refresh_tokens);

    if (refresh_token_ttl_seconds >= 0) {
        db_bind_int(stmt, 11, refresh_token_ttl_seconds);
    } else {
        db_bind_null(stmt, 11);
    }

    if (maximum_session_seconds >= 0) {
        db_bind_int(stmt, 12, maximum_session_seconds);
    } else {
        db_bind_null(stmt, 12);
    }

    if (secret_rotation_seconds >= 0) {
        db_bind_int(stmt, 13, secret_rotation_seconds);
    } else {
        db_bind_null(stmt, 13);
    }

    if (is_org_key_auth) {
        db_bind_int64(stmt, 14, organization_key_pin);
    } else {
        db_bind_int64(stmt, 14, user_account_pin);
    }

    /* Execute and verify a row was actually inserted */
    int rc = db_step(stmt);

    if (rc == DB_ROW) {
        db_finalize(stmt);
    } else {
        db_finalize(stmt);
        log_error("Failed to insert client (unauthorized or constraint violation)");
        return -1;
    }

    /* Return the generated ID */
    memcpy(out_id, id, 16);

    log_info("Created client: code_name='%s', type='%s', grant='%s'",
             code_name, client_type, grant_type);
    return 0;
}

int client_link_resource_server_bootstrap(db_handle_t *db, const char *org_code_name,
                                           const unsigned char *client_id,
                                           const char *resource_server_address) {
    if (!db || !org_code_name || !client_id || !resource_server_address) {
        log_error("Invalid arguments to client_link_resource_server_bootstrap");
        return -1;
    }

    /* Insert client-resource-server link with composite FK validation and anti-join for idempotency */
    const char *sql =
        "INSERT INTO " TBL_CLIENT_RESOURCE_SERVER " (organization_pin, client_pin, resource_server_pin) "
        "SELECT C.pin, A.pin, B.pin "
        "FROM " TBL_ORGANIZATION " C "
        "JOIN " TBL_CLIENT " A ON A.organization_pin = C.pin "
        "JOIN " TBL_RESOURCE_SERVER " B ON B.organization_pin = C.pin "
        "LEFT JOIN " TBL_CLIENT_RESOURCE_SERVER " D "
        "  ON D.client_pin = A.pin AND D.resource_server_pin = B.pin "
        "WHERE C.code_name = " P"1 "
        "AND A.id = " P"2 "
        "AND B.address = " P"3 "
        "AND D.pin IS NULL "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_link_resource_server_bootstrap statement");
        return -1;
    }

    db_bind_text(stmt, 1, org_code_name, -1);
    db_bind_blob(stmt, 2, client_id, 16);
    db_bind_text(stmt, 3, resource_server_address, -1);

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to link client to resource server: org='%s', address='%s'",
                  org_code_name, resource_server_address);
        return -1;
    }

    log_info("Linked client to resource server: org='%s', address='%s'",
             org_code_name, resource_server_address);
    return 0;
}

int client_list_all(db_handle_t *db, long long user_account_pin,
                    long long organization_key_pin,
                    const unsigned char *organization_id,
                    int limit, int offset,
                    const int *filter_is_active,
                    client_data_t **out_clients, int *out_count,
                    int *out_total) {
    if (!db || !organization_id || !out_clients || !out_count) {
        log_error("Invalid arguments to client_list_all");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);
    const char *sql_session =
        "SELECT c.id, c.pin, c.organization_pin, c.code_name, c.display_name, "
        "c.client_type, c.grant_type, c.note, c.require_mfa, "
        "c.access_token_ttl_seconds, c.issue_refresh_tokens, "
        "c.refresh_token_ttl_seconds, c.maximum_session_seconds, "
        "c.secret_rotation_seconds, c.is_universal, c.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_CLIENT " c "
        "JOIN " TBL_ORGANIZATION " o ON o.pin = c.organization_pin "
        "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
        "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
        "WHERE o.id = " P"1 "
        "AND oa.user_account_pin = " P"2 "
        "AND ua.is_active = " BOOL_TRUE " ";

    const char *sql_org_key =
        "SELECT c.id, c.pin, c.organization_pin, c.code_name, c.display_name, "
        "c.client_type, c.grant_type, c.note, c.require_mfa, "
        "c.access_token_ttl_seconds, c.issue_refresh_tokens, "
        "c.refresh_token_ttl_seconds, c.maximum_session_seconds, "
        "c.secret_rotation_seconds, c.is_universal, c.is_active, "
        "COUNT(*) OVER() as total_count "
        "FROM " TBL_CLIENT " c "
        "JOIN " TBL_ORGANIZATION " o ON o.pin = c.organization_pin "
        "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
        "WHERE o.id = " P"1 "
        "AND ok.pin = " P"2 "
        "AND ok.is_active = " BOOL_TRUE " ";

    /* Build query with optional is_active filter */
    char sql[1024];
    int pos = snprintf(sql, sizeof(sql), "%s", is_org_key_auth ? sql_org_key : sql_session);

    /* Add is_active filter if specified */
    int param_count = 3;  /* Next parameter after ?1 (org_id) and ?2 (auth_pin) */
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "AND c.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY c.code_name "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_list_all statement");
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
        client_data_t client;
        memset(&client, 0, sizeof(client));

        if (first_row) {
            total_count = db_column_int(stmt, 16);
            first_row = 0;
        }

        /* Extract id */
        const unsigned char *id_blob = db_column_blob(stmt, 0);
        int blob_len = db_column_bytes(stmt, 0);
        if (blob_len == 16) {
            memcpy(client.id, id_blob, 16);
        }

        /* Extract scalar fields */
        client.pin = db_column_int64(stmt, 1);
        client.organization_pin = db_column_int64(stmt, 2);

        const char *code_name = db_column_text(stmt, 3);
        if (code_name) {
            str_copy(client.code_name, sizeof(client.code_name), code_name);
        }

        const char *display_name = db_column_text(stmt, 4);
        if (display_name) {
            str_copy(client.display_name, sizeof(client.display_name), display_name);
        }

        const char *client_type = db_column_text(stmt, 5);
        if (client_type) {
            str_copy(client.client_type, sizeof(client.client_type), client_type);
        }

        const char *grant_type = db_column_text(stmt, 6);
        if (grant_type) {
            str_copy(client.grant_type, sizeof(client.grant_type), grant_type);
        }

        const char *note = db_column_text(stmt, 7);
        if (note && db_column_type(stmt, 7) != DB_NULL) {
            str_copy(client.note, sizeof(client.note), note);
        }

        client.require_mfa = db_column_int(stmt, 8);
        client.access_token_ttl_seconds = db_column_int(stmt, 9);
        client.issue_refresh_tokens = db_column_int(stmt, 10);

        /* Handle nullable integer fields (use -1 as sentinel for NULL) */
        if (db_column_type(stmt, 11) == DB_NULL) {
            client.refresh_token_ttl_seconds = -1;
        } else {
            client.refresh_token_ttl_seconds = db_column_int(stmt, 11);
        }

        if (db_column_type(stmt, 12) == DB_NULL) {
            client.maximum_session_seconds = -1;
        } else {
            client.maximum_session_seconds = db_column_int(stmt, 12);
        }

        if (db_column_type(stmt, 13) == DB_NULL) {
            client.secret_rotation_seconds = -1;
        } else {
            client.secret_rotation_seconds = db_column_int(stmt, 13);
        }

        client.is_universal = db_column_int(stmt, 14);
        client.is_active = db_column_int(stmt, 15);

        /* Append to list */
        if (db_results_append(&list, &list_tail, &client, sizeof(client)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append client to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    client_data_t *clients = DB_RESULTS_TO_ARRAY(list, &count, client_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_clients = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No clients found");
        return 0;
    }

    if (!clients) {
        log_error("Failed to convert client list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_clients = clients;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d client%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int client_get_by_id(db_handle_t *db, const unsigned char *client_id,
                     long long user_account_pin,
                     long long organization_key_pin,
                     client_data_t *out_client) {
    if (!db || !client_id || !out_client) {
        log_error("Invalid arguments to client_get_by_id");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT c.id, c.pin, c.organization_pin, c.code_name, c.display_name, "
            "c.client_type, c.grant_type, c.note, c.require_mfa, "
            "c.access_token_ttl_seconds, c.issue_refresh_tokens, "
            "c.refresh_token_ttl_seconds, c.maximum_session_seconds, "
            "c.secret_rotation_seconds, c.is_universal, c.is_active "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT c.id, c.pin, c.organization_pin, c.code_name, c.display_name, "
            "c.client_type, c.grant_type, c.note, c.require_mfa, "
            "c.access_token_ttl_seconds, c.issue_refresh_tokens, "
            "c.refresh_token_ttl_seconds, c.maximum_session_seconds, "
            "c.secret_rotation_seconds, c.is_universal, c.is_active "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_get_by_id statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Client not found or user not authorized");
        return -1;
    }

    memset(out_client, 0, sizeof(*out_client));

    /* Extract id */
    const unsigned char *id_blob = db_column_blob(stmt, 0);
    int blob_len = db_column_bytes(stmt, 0);
    if (blob_len == 16) {
        memcpy(out_client->id, id_blob, 16);
    }

    /* Extract scalar fields */
    out_client->pin = db_column_int64(stmt, 1);
    out_client->organization_pin = db_column_int64(stmt, 2);

    const char *code_name = db_column_text(stmt, 3);
    if (code_name) {
        str_copy(out_client->code_name, sizeof(out_client->code_name), code_name);
    }

    const char *display_name = db_column_text(stmt, 4);
    if (display_name) {
        str_copy(out_client->display_name, sizeof(out_client->display_name), display_name);
    }

    const char *client_type = db_column_text(stmt, 5);
    if (client_type) {
        str_copy(out_client->client_type, sizeof(out_client->client_type), client_type);
    }

    const char *grant_type = db_column_text(stmt, 6);
    if (grant_type) {
        str_copy(out_client->grant_type, sizeof(out_client->grant_type), grant_type);
    }

    const char *note = db_column_text(stmt, 7);
    if (note && db_column_type(stmt, 7) != DB_NULL) {
        str_copy(out_client->note, sizeof(out_client->note), note);
    }

    out_client->require_mfa = db_column_int(stmt, 8);
    out_client->access_token_ttl_seconds = db_column_int(stmt, 9);
    out_client->issue_refresh_tokens = db_column_int(stmt, 10);

    /* Handle nullable integer fields (use -1 as sentinel for NULL) */
    if (db_column_type(stmt, 11) == DB_NULL) {
        out_client->refresh_token_ttl_seconds = -1;
    } else {
        out_client->refresh_token_ttl_seconds = db_column_int(stmt, 11);
    }

    if (db_column_type(stmt, 12) == DB_NULL) {
        out_client->maximum_session_seconds = -1;
    } else {
        out_client->maximum_session_seconds = db_column_int(stmt, 12);
    }

    if (db_column_type(stmt, 13) == DB_NULL) {
        out_client->secret_rotation_seconds = -1;
    } else {
        out_client->secret_rotation_seconds = db_column_int(stmt, 13);
    }

    out_client->is_universal = db_column_int(stmt, 14);
    out_client->is_active = db_column_int(stmt, 15);

    db_finalize(stmt);
    return 0;
}

int client_update(db_handle_t *db, const unsigned char *client_id,
                  long long user_account_pin,
                  long long organization_key_pin,
                  const char *display_name, const char *note,
                  const int *require_mfa,
                  const int *access_token_ttl_seconds,
                  const int *issue_refresh_tokens,
                  const int *refresh_token_ttl_seconds,
                  const int *maximum_session_seconds,
                  const int *secret_rotation_seconds,
                  const int *is_active) {
    if (!db || !client_id) {
        log_error("Invalid arguments to client_update");
        return -1;
    }

    /* At least one field must be updated */
    if (!display_name && !note && !require_mfa && !access_token_ttl_seconds &&
        !issue_refresh_tokens && !refresh_token_ttl_seconds &&
        !maximum_session_seconds && !secret_rotation_seconds && !is_active) {
        log_error("No fields to update in client_update");
        return -1;
    }

    int is_org_key_auth = (user_account_pin == -1);

    /* Build UPDATE query dynamically */
    char sql[3072];
    int pos = 0;
    int param = 3;  /* ?1 is client_id, ?2 is auth PIN (user or key) */
    int conditions = 0;

    /* Start with UPDATE SET */
    pos += snprintf(sql + pos, sizeof(sql) - pos,
        "UPDATE " TBL_CLIENT " SET updated_at = " NOW "");

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
    if (require_mfa) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", require_mfa = " P"%d", param++);
    }
    if (access_token_ttl_seconds) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", access_token_ttl_seconds = " P"%d", param++);
    }
    if (issue_refresh_tokens) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", issue_refresh_tokens = " P"%d", param++);
    }
    if (refresh_token_ttl_seconds) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, ", refresh_token_ttl_seconds = " P"%d", param++);
    }
    if (maximum_session_seconds) {
        if (*maximum_session_seconds < 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", maximum_session_seconds = NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", maximum_session_seconds = " P"%d", param++);
        }
    }
    if (secret_rotation_seconds) {
        if (*secret_rotation_seconds < 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", secret_rotation_seconds = NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos, ", secret_rotation_seconds = " P"%d", param++);
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
            "WHERE ok.organization_pin = " TBL_CLIENT ".organization_pin "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE);
    } else {
        /* Session auth - verify user is org admin */
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "SELECT 1 FROM " TBL_ORGANIZATION_ADMIN " oa "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE oa.organization_pin = " TBL_CLIENT ".organization_pin "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE);
    }

    pos += snprintf(sql + pos, sizeof(sql) - pos, ") ");

    /* Add uniqueness check when reactivating (is_active -> TRUE) */
    /* Check existing code_name doesn't collide with active records */
    if (is_active && *is_active == 1) {
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "AND NOT EXISTS ("
                "SELECT 1 FROM " TBL_CLIENT " other "
                "WHERE other.organization_pin = " TBL_CLIENT ".organization_pin "
                "AND lower(other.code_name) = lower(" TBL_CLIENT ".code_name) "
                "AND other.is_active = " BOOL_TRUE " "
                "AND other.id != " TBL_CLIENT ".id"
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
    if (require_mfa) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "require_mfa IS DISTINCT FROM " P"%d", param++);
    }
    if (access_token_ttl_seconds) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "access_token_ttl_seconds IS DISTINCT FROM " P"%d", param++);
    }
    if (issue_refresh_tokens) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "issue_refresh_tokens IS DISTINCT FROM " P"%d", param++);
    }
    if (refresh_token_ttl_seconds) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        pos += snprintf(sql + pos, sizeof(sql) - pos,
            "refresh_token_ttl_seconds IS DISTINCT FROM " P"%d", param++);
    }
    if (maximum_session_seconds) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        if (*maximum_session_seconds < 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos,
                "maximum_session_seconds IS NOT NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos,
                "maximum_session_seconds IS DISTINCT FROM " P"%d", param++);
        }
    }
    if (secret_rotation_seconds) {
        if (conditions++ > 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos, " OR ");
        }
        if (*secret_rotation_seconds < 0) {
            pos += snprintf(sql + pos, sizeof(sql) - pos,
                "secret_rotation_seconds IS NOT NULL");
        } else {
            pos += snprintf(sql + pos, sizeof(sql) - pos,
                "secret_rotation_seconds IS DISTINCT FROM " P"%d", param++);
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
        log_error("Failed to prepare client_update statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, client_id, 16);
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
    if (require_mfa) {
        db_bind_int(stmt, param++, *require_mfa);
    }
    if (access_token_ttl_seconds) {
        db_bind_int(stmt, param++, *access_token_ttl_seconds);
    }
    if (issue_refresh_tokens) {
        db_bind_int(stmt, param++, *issue_refresh_tokens);
    }
    if (refresh_token_ttl_seconds) {
        db_bind_int(stmt, param++, *refresh_token_ttl_seconds);
    }
    if (maximum_session_seconds && *maximum_session_seconds >= 0) {
        db_bind_int(stmt, param++, *maximum_session_seconds);
    }
    if (secret_rotation_seconds && *secret_rotation_seconds >= 0) {
        db_bind_int(stmt, param++, *secret_rotation_seconds);
    }
    if (is_active) {
        db_bind_int(stmt, param++, *is_active);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to update client");
        return -1;
    }

    log_info("Updated client");
    return 0;
}

int client_redirect_uri_list(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *client_id,
                              int limit, int offset,
                              client_redirect_uri_data_t **out_uris,
                              int *out_count,
                              int *out_total) {
    if (!db || !client_id || !out_uris || !out_count) {
        log_error("Invalid arguments to client_redirect_uri_list");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT cru.redirect_uri, cru.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_REDIRECT_URI " cru "
            "JOIN " TBL_CLIENT " c ON c.pin = cru.client_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "ORDER BY cru.redirect_uri "
            "LIMIT " P"3 OFFSET " P"4";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT cru.redirect_uri, cru.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_REDIRECT_URI " cru "
            "JOIN " TBL_CLIENT " c ON c.pin = cru.client_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "ORDER BY cru.redirect_uri "
            "LIMIT " P"3 OFFSET " P"4";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_redirect_uri_list statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }
    db_bind_int(stmt, 3, limit);
    db_bind_int(stmt, 4, offset);

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        client_redirect_uri_data_t uri;
        memset(&uri, 0, sizeof(uri));

        if (first_row) {
            total_count = db_column_int(stmt, 2);
            first_row = 0;
        }

        const char *redirect_uri = db_column_text(stmt, 0);
        if (redirect_uri) {
            str_copy(uri.redirect_uri, sizeof(uri.redirect_uri), redirect_uri);
        }

        const char *note = db_column_text(stmt, 1);
        if (note && db_column_type(stmt, 1) != DB_NULL) {
            str_copy(uri.note, sizeof(uri.note), note);
        }

        /* Append to list */
        if (db_results_append(&list, &list_tail, &uri, sizeof(uri)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append redirect URI to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    client_redirect_uri_data_t *uris = DB_RESULTS_TO_ARRAY(list, &count, client_redirect_uri_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_uris = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No redirect URIs found");
        return 0;
    }

    if (!uris) {
        log_error("Failed to convert redirect URI list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_uris = uris;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d redirect URI%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int client_redirect_uri_create(db_handle_t *db, long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *client_id,
                                const char *redirect_uri,
                                const char *note) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to client_redirect_uri_create");
        return -1;
    }

    /* Validate redirect URI has proper scheme (OAuth2 spec requires absolute URI) */
    if (strncmp(redirect_uri, "http://", 7) != 0 &&
        strncmp(redirect_uri, "https://", 8) != 0) {
        log_error("Invalid redirect URI: must start with http:// or https://");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "INSERT INTO " TBL_CLIENT_REDIRECT_URI " (client_pin, redirect_uri, note) "
            "SELECT c.pin, " P"2, " P"3 "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"1 "
            "AND ok.pin = " P"4 "
            "AND ok.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_CLIENT_REDIRECT_URI " (client_pin, redirect_uri, note) "
            "SELECT c.pin, " P"2, " P"3 "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"1 "
            "AND oa.user_account_pin = " P"4 "
            "AND ua.is_active = " BOOL_TRUE " "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_redirect_uri_create statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_text(stmt, 2, redirect_uri, -1);

    if (note != NULL) {
        db_bind_text(stmt, 3, note, -1);
    } else {
        db_bind_null(stmt, 3);
    }

    if (is_org_key_auth) {
        db_bind_int64(stmt, 4, organization_key_pin);
    } else {
        db_bind_int64(stmt, 4, user_account_pin);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to create redirect URI");
        return -1;
    }

    log_info("Created redirect URI: uri='%s'", redirect_uri);
    return 0;
}

int client_redirect_uri_delete(db_handle_t *db, long long user_account_pin,
                                long long organization_key_pin,
                                const unsigned char *client_id,
                                const char *redirect_uri) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to client_redirect_uri_delete");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "DELETE FROM " TBL_CLIENT_REDIRECT_URI " "
            "WHERE client_pin = ("
                "SELECT c.pin FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
                "WHERE c.id = " P"1 "
                "AND ok.pin = " P"3 "
                "AND ok.is_active = " BOOL_TRUE " "
                "LIMIT 1"
            ") "
            "AND redirect_uri = " P"2";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "DELETE FROM " TBL_CLIENT_REDIRECT_URI " "
            "WHERE client_pin = ("
                "SELECT c.pin FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
                "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
                "WHERE c.id = " P"1 "
                "AND oa.user_account_pin = " P"3 "
                "AND ua.is_active = " BOOL_TRUE " "
                "LIMIT 1"
            ") "
            "AND redirect_uri = " P"2";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_redirect_uri_delete statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_text(stmt, 2, redirect_uri, -1);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 3, organization_key_pin);
    } else {
        db_bind_int64(stmt, 3, user_account_pin);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to delete redirect URI");
        return -1;
    }

    log_info("Deleted redirect URI: uri='%s'", redirect_uri);
    return 0;
}

int client_resource_server_list(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *client_id,
                                 int limit, int offset,
                                 client_resource_server_data_t **out_links,
                                 int *out_count,
                                 int *out_total) {
    if (!db || !client_id || !out_links || !out_count) {
        log_error("Invalid arguments to client_resource_server_list");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT rs.id, rs.code_name, rs.display_name, rs.address, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_RESOURCE_SERVER " crs "
            "JOIN " TBL_CLIENT " c ON c.pin = crs.client_pin "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = crs.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "ORDER BY rs.code_name "
            "LIMIT " P"3 OFFSET " P"4";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT rs.id, rs.code_name, rs.display_name, rs.address, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_RESOURCE_SERVER " crs "
            "JOIN " TBL_CLIENT " c ON c.pin = crs.client_pin "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = crs.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "ORDER BY rs.code_name "
            "LIMIT " P"3 OFFSET " P"4";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_resource_server_list statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }
    db_bind_int(stmt, 3, limit);
    db_bind_int(stmt, 4, offset);

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        client_resource_server_data_t link;
        memset(&link, 0, sizeof(link));

        if (first_row) {
            total_count = db_column_int(stmt, 4);
            first_row = 0;
        }

        /* Extract resource_server_id */
        const unsigned char *rs_id_blob = db_column_blob(stmt, 0);
        int rs_blob_len = db_column_bytes(stmt, 0);
        if (rs_blob_len == 16) {
            memcpy(link.resource_server_id, rs_id_blob, 16);
        }

        const char *rs_code_name = db_column_text(stmt, 1);
        if (rs_code_name) {
            str_copy(link.resource_server_code_name, sizeof(link.resource_server_code_name), rs_code_name);
        }

        const char *rs_display_name = db_column_text(stmt, 2);
        if (rs_display_name) {
            str_copy(link.resource_server_display_name, sizeof(link.resource_server_display_name), rs_display_name);
        }

        const char *rs_address = db_column_text(stmt, 3);
        if (rs_address) {
            str_copy(link.resource_server_address, sizeof(link.resource_server_address), rs_address);
        }

        /* Append to list */
        if (db_results_append(&list, &list_tail, &link, sizeof(link)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append link to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    client_resource_server_data_t *links = DB_RESULTS_TO_ARRAY(list, &count, client_resource_server_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_links = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No resource server links found");
        return 0;
    }

    if (!links) {
        log_error("Failed to convert link list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_links = links;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d resource server link%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int resource_server_client_list(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *resource_server_id,
                                 int limit, int offset,
                                 resource_server_client_data_t **out_links,
                                 int *out_count,
                                 int *out_total) {
    if (!db || !resource_server_id || !out_links || !out_count) {
        log_error("Invalid arguments to resource_server_client_list");
        return -1;
    }

    if (limit <= 0 || offset < 0) {
        log_error("Invalid limit/offset parameters: limit=%d, offset=%d", limit, offset);
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "SELECT c.id, c.code_name, c.display_name, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_RESOURCE_SERVER " crs "
            "JOIN " TBL_CLIENT " c ON c.pin = crs.client_pin "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = crs.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = rs.organization_pin "
            "WHERE rs.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " "
            "ORDER BY c.code_name "
            "LIMIT " P"3 OFFSET " P"4";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "SELECT c.id, c.code_name, c.display_name, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_RESOURCE_SERVER " crs "
            "JOIN " TBL_CLIENT " c ON c.pin = crs.client_pin "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.pin = crs.resource_server_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = rs.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE rs.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " "
            "ORDER BY c.code_name "
            "LIMIT " P"3 OFFSET " P"4";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare resource_server_client_list statement");
        return -1;
    }

    db_bind_blob(stmt, 1, resource_server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 2, organization_key_pin);
    } else {
        db_bind_int64(stmt, 2, user_account_pin);
    }
    db_bind_int(stmt, 3, limit);
    db_bind_int(stmt, 4, offset);

    /* Build linked list of results */
    db_result_node_t *list = NULL, *list_tail = NULL;
    int total_count = 0;
    int first_row = 1;

    while (db_step(stmt) == DB_ROW) {
        resource_server_client_data_t link;
        memset(&link, 0, sizeof(link));

        if (first_row) {
            total_count = db_column_int(stmt, 3);
            first_row = 0;
        }

        /* Extract client_id */
        const unsigned char *client_id_blob = db_column_blob(stmt, 0);
        int client_blob_len = db_column_bytes(stmt, 0);
        if (client_blob_len == 16) {
            memcpy(link.client_id, client_id_blob, 16);
        }

        const char *client_code_name = db_column_text(stmt, 1);
        if (client_code_name) {
            str_copy(link.client_code_name, sizeof(link.client_code_name), client_code_name);
        }

        const char *client_display_name = db_column_text(stmt, 2);
        if (client_display_name) {
            str_copy(link.client_display_name, sizeof(link.client_display_name), client_display_name);
        }

        /* Append to list */
        if (db_results_append(&list, &list_tail, &link, sizeof(link)) != 0) {
            db_finalize(stmt);
            db_results_free(list);
            log_error("Failed to append client link to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    resource_server_client_data_t *links = DB_RESULTS_TO_ARRAY(list, &count, resource_server_client_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_links = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No client links found");
        return 0;
    }

    if (!links) {
        log_error("Failed to convert client link list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_links = links;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d client link%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int client_resource_server_create(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *resource_server_id) {
    if (!db || !client_id || !resource_server_id) {
        log_error("Invalid arguments to client_resource_server_create");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "INSERT INTO " TBL_CLIENT_RESOURCE_SERVER " (organization_pin, client_pin, resource_server_pin) "
            "SELECT c.organization_pin, c.pin, rs.pin "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.organization_pin = c.organization_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "LEFT JOIN " TBL_CLIENT_RESOURCE_SERVER " existing "
            "  ON existing.client_pin = c.pin AND existing.resource_server_pin = rs.pin "
            "WHERE c.id = " P"1 "
            "AND rs.id = " P"2 "
            "AND ok.pin = " P"3 "
            "AND ok.is_active = " BOOL_TRUE " "
            "AND existing.pin IS NULL "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_CLIENT_RESOURCE_SERVER " (organization_pin, client_pin, resource_server_pin) "
            "SELECT c.organization_pin, c.pin, rs.pin "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_RESOURCE_SERVER " rs ON rs.organization_pin = c.organization_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "LEFT JOIN " TBL_CLIENT_RESOURCE_SERVER " existing "
            "  ON existing.client_pin = c.pin AND existing.resource_server_pin = rs.pin "
            "WHERE c.id = " P"1 "
            "AND rs.id = " P"2 "
            "AND oa.user_account_pin = " P"3 "
            "AND ua.is_active = " BOOL_TRUE " "
            "AND existing.pin IS NULL "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_resource_server_create statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_blob(stmt, 2, resource_server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 3, organization_key_pin);
    } else {
        db_bind_int64(stmt, 3, user_account_pin);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to create client-resource-server link");
        return -1;
    }

    log_info("Created client-resource-server link");
    return 0;
}

int client_resource_server_delete(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *resource_server_id) {
    if (!db || !client_id || !resource_server_id) {
        log_error("Invalid arguments to client_resource_server_delete");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "DELETE FROM " TBL_CLIENT_RESOURCE_SERVER " "
            "WHERE client_pin = ("
                "SELECT c.pin FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
                "WHERE c.id = " P"1 "
                "AND ok.pin = " P"3 "
                "AND ok.is_active = " BOOL_TRUE " "
                "LIMIT 1"
            ") "
            "AND resource_server_pin = ("
                "SELECT rs.pin FROM " TBL_RESOURCE_SERVER " rs "
                "WHERE rs.id = " P"2 "
                "LIMIT 1"
            ")";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "DELETE FROM " TBL_CLIENT_RESOURCE_SERVER " "
            "WHERE client_pin = ("
                "SELECT c.pin FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
                "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
                "WHERE c.id = " P"1 "
                "AND oa.user_account_pin = " P"3 "
                "AND ua.is_active = " BOOL_TRUE " "
                "LIMIT 1"
            ") "
            "AND resource_server_pin = ("
                "SELECT rs.pin FROM " TBL_RESOURCE_SERVER " rs "
                "WHERE rs.id = " P"2 "
                "LIMIT 1"
            ")";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_resource_server_delete statement");
        return -1;
    }

    db_bind_blob(stmt, 1, client_id, 16);
    db_bind_blob(stmt, 2, resource_server_id, 16);
    if (is_org_key_auth) {
        db_bind_int64(stmt, 3, organization_key_pin);
    } else {
        db_bind_int64(stmt, 3, user_account_pin);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to delete client-resource-server link");
        return -1;
    }

    log_info("Deleted client-resource-server link");
    return 0;
}

/* ============================================================================
 * Client Key Management Functions
 * ============================================================================ */

int client_key_create(db_handle_t *db,
                      long long user_account_pin,
                      long long organization_key_pin,
                      const unsigned char *client_id,
                      const char *secret,
                      const char *note,
                      unsigned char *out_key_id) {
    if (!db || !client_id || !secret || !out_key_id) {
        log_error("Invalid arguments to client_key_create");
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
            "INSERT INTO " TBL_CLIENT_KEY " "
            "(id, client_pin, salt, hash_iterations, secret_hash, note) "
            "SELECT " P"1, c.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"2 "
            "AND ok.pin = " P"7 "
            "AND ok.is_active = " BOOL_TRUE " "
            "AND c.is_active = " BOOL_TRUE " "
            "AND c.client_type = 'confidential' "
            "LIMIT 1";
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "INSERT INTO " TBL_CLIENT_KEY " "
            "(id, client_pin, salt, hash_iterations, secret_hash, note) "
            "SELECT " P"1, c.pin, " P"3, " P"4, " P"5, " P"6 "
            "FROM " TBL_CLIENT " c "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"2 "
            "AND oa.user_account_pin = " P"7 "
            "AND ua.is_active = " BOOL_TRUE " "
            "AND c.is_active = " BOOL_TRUE " "
            "AND c.client_type = 'confidential' "
            "LIMIT 1";
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_key_create statement");
        return -1;
    }

    /* Bind parameters */
    db_bind_blob(stmt, 1, key_id, sizeof(key_id));
    db_bind_blob(stmt, 2, client_id, 16);
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
        log_error("Failed to insert client key (unauthorized, not confidential, or constraint violation)");
        return -1;
    }

    /* Return the generated key_id */
    memcpy(out_key_id, key_id, 16);

    log_info("Created client key");
    return 0;
}

int client_key_list(db_handle_t *db,
                    long long user_account_pin,
                    long long organization_key_pin,
                    const unsigned char *client_id,
                    int limit, int offset,
                    const int *filter_is_active,
                    client_key_data_t **out_keys,
                    int *out_count,
                    int *out_total) {
    if (!db || !client_id || !out_keys || !out_count) {
        log_error("Invalid arguments to client_key_list");
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
            "SELECT ck.id, ck.is_active, ck.generated_at, ck.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_KEY " ck "
            "JOIN " TBL_CLIENT " c ON c.pin = ck.client_pin "
            "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
            "WHERE c.id = " P"1 "
            "AND ok.pin = " P"2 "
            "AND ok.is_active = " BOOL_TRUE " ");
    } else {
        /* Session authentication - verify user is org admin */
        pos = snprintf(sql, sizeof(sql),
            "SELECT ck.id, ck.is_active, ck.generated_at, ck.note, "
            "COUNT(*) OVER() as total_count "
            "FROM " TBL_CLIENT_KEY " ck "
            "JOIN " TBL_CLIENT " c ON c.pin = ck.client_pin "
            "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
            "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
            "WHERE c.id = " P"1 "
            "AND oa.user_account_pin = " P"2 "
            "AND ua.is_active = " BOOL_TRUE " ");
    }

    /* Add is_active filter if specified */
    int param_count = 3;  /* Next parameter after ?1 (client_id) and ?2 (auth_pin) */
    if (filter_is_active) {
        pos += snprintf(sql + pos, sizeof(sql) - pos, "AND ck.is_active = " P"%d ", param_count++);
    }

    snprintf(sql + pos, sizeof(sql) - pos,
        "ORDER BY ck.generated_at DESC, ck.pin DESC "
        "LIMIT " P"%d OFFSET " P"%d", param_count, param_count + 1);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_key_list statement");
        return -1;
    }

    /* Bind parameters */
    int param = 1;
    db_bind_blob(stmt, param++, client_id, 16);
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
        client_key_data_t key;
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
            log_error("Failed to append client key to result list");
            return -1;
        }
    }

    db_finalize(stmt);

    /* Convert list to array */
    int count;
    client_key_data_t *keys = DB_RESULTS_TO_ARRAY(list, &count, client_key_data_t);

    /* Handle empty result */
    if (count == 0) {
        *out_keys = NULL;
        *out_count = 0;
        if (out_total) *out_total = 0;
        log_info("No client keys found");
        return 0;
    }

    if (!keys) {
        log_error("Failed to convert client key list to array");
        *out_count = 0;
        if (out_total) *out_total = 0;
        return -1;
    }

    *out_keys = keys;
    *out_count = count;
    if (out_total) *out_total = total_count;

    log_info("Found %d client key%s (limit=%d, offset=%d)",
             count, count == 1 ? "" : "s", limit, offset);
    return 0;
}

int client_key_revoke(db_handle_t *db,
                      long long user_account_pin,
                      long long organization_key_pin,
                      const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to client_key_revoke");
        return -1;
    }

    const char *sql;
    int is_org_key_auth = (user_account_pin == -1);

    if (is_org_key_auth) {
        /* Org key authentication - verify key is active */
        sql =
            "UPDATE " TBL_CLIENT_KEY " "
            "SET is_active = " BOOL_FALSE ", updated_at = " NOW " "
            "WHERE id = " P"1 "
            "AND EXISTS ("
                "SELECT 1 FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_KEY " ok ON ok.organization_pin = c.organization_pin "
                "WHERE c.pin = " TBL_CLIENT_KEY ".client_pin "
                "AND ok.pin = " P"2 "
                "AND ok.is_active = " BOOL_TRUE
            ") "
            "AND is_active = " BOOL_TRUE;  /* Only revoke if currently active */
    } else {
        /* Session authentication - verify user is org admin */
        sql =
            "UPDATE " TBL_CLIENT_KEY " "
            "SET is_active = " BOOL_FALSE ", updated_at = " NOW " "
            "WHERE id = " P"1 "
            "AND EXISTS ("
                "SELECT 1 FROM " TBL_CLIENT " c "
                "JOIN " TBL_ORGANIZATION_ADMIN " oa ON oa.organization_pin = c.organization_pin "
                "JOIN " TBL_USER_ACCOUNT " ua ON ua.pin = oa.user_account_pin "
                "WHERE c.pin = " TBL_CLIENT_KEY ".client_pin "
                "AND oa.user_account_pin = " P"2 "
                "AND ua.is_active = " BOOL_TRUE
            ") "
            "AND is_active = " BOOL_TRUE;  /* Only revoke if currently active */
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_key_revoke statement");
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
        log_error("Failed to revoke client key");
        return -1;
    }

    log_info("Revoked client key");
    return 0;
}

int client_key_verify(db_handle_t *db,
                      const unsigned char *key_id,
                      const char *secret,
                      long long *out_client_pin) {
    if (!db || !key_id || !secret) {
        log_error("Invalid arguments to client_key_verify");
        return -1;
    }

    const char *sql =
        "SELECT ck.salt, ck.hash_iterations, ck.secret_hash, ck.client_pin "
        "FROM " TBL_CLIENT_KEY " ck "
        "JOIN " TBL_CLIENT " c ON c.pin = ck.client_pin "
        "WHERE ck.id = " P"1 "
        "AND ck.is_active = " BOOL_TRUE " "
        "AND c.is_active = " BOOL_TRUE " "
        "AND c.client_type = 'confidential' "
        "LIMIT 1";

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare client_key_verify statement");
        return -1;
    }

    db_bind_blob(stmt, 1, key_id, 16);

    int rc = db_step(stmt);

    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_debug("Client key not found or inactive");
        return 0;  /* Invalid key */
    }

    /* Extract stored hash parameters */
    const char *salt = (const char *)db_column_text(stmt, 0);
    int iterations = db_column_int(stmt, 1);
    const char *hash = (const char *)db_column_text(stmt, 2);
    long long client_pin = db_column_int64(stmt, 3);

    if (!salt || !hash) {
        log_error("NULL hash fields in client_key");
        db_finalize(stmt);
        return -1;
    }

    /* Verify secret using timing-safe comparison */
    int valid = crypto_password_verify(secret, strlen(secret), salt, iterations, hash);

    db_finalize(stmt);

    /* If valid, return client pin if requested */
    if (valid == 1) {
        if (out_client_pin != NULL) {
            *out_client_pin = client_pin;
        }
        log_info("Client key verified successfully");
        return 1;  /* Valid */
    } else if (valid == 0) {
        log_info("Client key verification failed (invalid secret)");
        return 0;  /* Invalid */
    } else {
        log_error("Error during client key verification");
        return -1;  /* Error */
    }
}
