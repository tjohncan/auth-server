#include "util/config.h"
#include "util/log.h"
#include "db/db.h"
#include "db/db_sql.h"
#include "db/init/db_init.h"
#include "db/init/db_history.h"
#include "crypto/signing_keys.h"
#include "db/queries/oauth.h"
#include "db/queries/client.h"
#include "db/queries/resource_server.h"
#include "db/queries/org.h"
#include "crypto/password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A database of the test's own: SQLite in memory, schema applied, gone when the
 * handle closes. The tests below delete and rewrite rows on purpose, so they
 * never run against the configured database, and nothing they do reaches a file.
 *
 * Returns NULL on failure.
 */
static db_handle_t *open_test_db(const config_t *config) {
    db_handle_t *db = NULL;
    if (db_connect(&db, DB_TYPE_SQLITE, ":memory:") != 0) {
        return NULL;
    }
    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    if (db_init_schema(db, DB_TYPE_SQLITE, config->schema_dir, owner_role) < 0) {
        db_disconnect(db);
        return NULL;
    }
    return db;
}

/*
 * Signing-key cache — the claim is that it is VALIDATED on every use, never
 * trusted for an interval.
 *
 * Returns 0 on success.
 */
static int test_signing_key_cache(const config_t *config) {
    log_info("\nSigning-key cache tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Signing-key cache: could not open a test database");
        return 1;
    }

    signing_key_thread_cleanup();  /* start from an empty cache */

    int failed = 1;
    signing_key_t *first = NULL, *second = NULL, *third = NULL, *fourth = NULL;

    /* 1. Two calls agree, so the cache is actually being consulted. */
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &first) != 0 || !first ||
        signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &second) != 0 || !second) {
        log_error("Signing-key cache: could not obtain a key");
        goto done;
    }
    if (!first->current_private_key || !second->current_private_key ||
        strcmp(first->current_private_key, second->current_private_key) != 0) {
        log_error("Signing-key cache: two calls returned different material");
        goto done;
    }
    log_info("  repeat call returns the same key material (OK)");

    /*
     * 2. The load-bearing one. Move current_generated_at out of band and the very
     * next call must observe it. This is the whole design: a cache validated
     * against the row on every use rather than trusted for a period. If someone
     * later "optimises" the validation SELECT away, every other assertion here
     * still passes and this one does not.
     */
    if (db_execute_direct(sdb,
            "UPDATE access_token_signing SET current_generated_at = "
            "datetime(current_generated_at, '-1 second') WHERE singleton = " BOOL_TRUE) != 0) {
        log_error("Signing-key cache: could not age the row");
        goto done;
    }
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &third) != 0 || !third) {
        log_error("Signing-key cache: call after out-of-band update failed");
        goto done;
    }
    if (third->current_generated_at != first->current_generated_at - 1) {
        log_error("Signing-key cache: stale hit — expected generated_at %lld, got %lld",
                  (long long)(first->current_generated_at - 1),
                  (long long)third->current_generated_at);
        goto done;
    }
    log_info("  out-of-band timestamp change observed on the next call (OK)");

    /* 3. No row at all must route to the reload path, not serve a stale copy. */
    if (db_execute_direct(sdb, "DELETE FROM access_token_signing") != 0) {
        log_error("Signing-key cache: could not delete the row");
        goto done;
    }
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &fourth) != 0 || !fourth) {
        log_error("Signing-key cache: did not regenerate after the row was deleted");
        goto done;
    }
    if (!fourth->current_private_key ||
        strcmp(fourth->current_private_key, first->current_private_key) == 0) {
        log_error("Signing-key cache: served the deleted key");
        goto done;
    }
    log_info("  deleted row regenerates rather than serving a stale key (OK)");

    failed = 0;

done:
    signing_key_free(first);
    signing_key_free(second);
    signing_key_free(third);
    signing_key_free(fourth);
    signing_key_thread_cleanup();
    db_disconnect(sdb);

    if (!failed) {
        log_info("Signing-key cache tests passed!");
    }
    return failed;
}

/*
 * MFA-management gate — keyed on enrollment (has_mfa), not on the require_mfa
 * preference.
 *
 * The case that matters: a user who has enrolled a factor but not opted in to
 * "require". A gate reading the preference would pass their password-only
 * session -- and several gated endpoints end in a factor that session could then
 * present. The decision itself is oauth_session_mfa_pending(); what can silently
 * break it is the session lookup not carrying has_mfa, which would make the gate
 * read 0 and wave everyone through. So this drives the real lookup.
 *
 * Returns 0 on success.
 */
static int test_mfa_management_gate(const config_t *config) {
    log_info("\nMFA-management gate tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("MFA gate: could not open a test database");
        return 1;
    }

    int failed = 1;

    const unsigned char user_id[16] = {0x6d, 0x66, 0x61, 0x67, 0x61, 0x74, 0x65, 0x01,
                                       0x6d, 0x66, 0x61, 0x67, 0x61, 0x74, 0x65, 0x02};
    if (db_execute_direct(sdb,
            "INSERT INTO user_account (id) VALUES (x'6d666167617465016d66616761746502')") != 0) {
        log_error("MFA gate: could not insert user");
        goto done;
    }

    long long user_pin = 0;
    db_stmt_t *stmt = NULL;
    if (db_prepare(sdb, &stmt, "SELECT pin FROM user_account") != 0 || db_step(stmt) != DB_ROW) {
        log_error("MFA gate: could not read user pin");
        if (stmt) db_finalize(stmt);
        goto done;
    }
    user_pin = db_column_int64(stmt, 0);
    db_finalize(stmt);

    const char *token = "mfa-gate-test-session-token";
    unsigned char session_id[16];
    if (oauth_session_create(sdb, user_pin, user_id, token, "password",
                             NULL, NULL, 3600, session_id) != 0) {
        log_error("MFA gate: could not create session");
        goto done;
    }

    oauth_session_info_t s;

    /* 1. No factor enrolled: not gated. First enrollment has to be reachable. */
    if (oauth_session_get_by_token(sdb, token, &s) != 0) {
        log_error("MFA gate: session lookup failed");
        goto done;
    }
    if (s.user_has_mfa != 0 || oauth_session_mfa_pending(&s)) {
        log_error("MFA gate: unenrolled user gated (has_mfa=%d)", s.user_has_mfa);
        goto done;
    }
    log_info("  no factor enrolled: not gated (OK)");

    /* 2. Enrolled, require_mfa still 0, password-only session: gated. A gate
       reading require_mfa instead of has_mfa fails here. */
    if (db_execute_direct(sdb, "UPDATE user_account SET has_mfa = 1") != 0 ||
        oauth_session_get_by_token(sdb, token, &s) != 0) {
        log_error("MFA gate: could not mark user enrolled");
        goto done;
    }
    if (s.user_has_mfa != 1 || s.user_requires_mfa != 0 || !oauth_session_mfa_pending(&s)) {
        log_error("MFA gate: enrolled user with password-only session NOT gated "
                  "(has_mfa=%d require_mfa=%d mfa_completed=%d)",
                  s.user_has_mfa, s.user_requires_mfa, s.mfa_completed);
        goto done;
    }
    log_info("  enrolled, require off, password-only session: gated (OK)");

    /* 3. Once the session completes MFA, the gate opens. */
    if (oauth_session_set_mfa_completed(sdb, token) != 0 ||
        oauth_session_get_by_token(sdb, token, &s) != 0) {
        log_error("MFA gate: could not complete MFA on session");
        goto done;
    }
    if (oauth_session_mfa_pending(&s)) {
        log_error("MFA gate: still gated after MFA completion");
        goto done;
    }
    log_info("  after MFA completion: not gated (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("MFA-management gate tests passed!");
    }
    return failed;
}

/*
 * Token liveness after account deactivation.
 *
 * api/README says a deactivated user's tokens "will fail introspection" —
 * deactivation revokes nothing, so the check has to happen at use time, in every
 * liveness query. Pins both of them, and that a client_credentials token (no
 * user row) is not collateral damage of the user predicate.
 *
 * Returns 0 on success.
 */
static int test_deactivated_user_tokens(const config_t *config) {
    log_info("\nDeactivated-user token tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Deactivation: could not open a test database");
        return 1;
    }

    int failed = 1;

    /* One org, resource server, client and user; pins are all 1. */
    if (db_execute_direct(sdb,
            "INSERT INTO organization (id, code_name, display_name) "
            "  VALUES (x'00000000000000000000000000000001', 'org', 'Org');"
            "INSERT INTO resource_server (id, organization_pin, code_name, display_name, address) "
            "  VALUES (x'00000000000000000000000000000002', 1, 'rs', 'RS', 'https://rs.example');"
            "INSERT INTO client (id, organization_pin, code_name, client_type, grant_type, "
            "                    display_name, access_token_ttl_seconds) "
            "  VALUES (x'00000000000000000000000000000003', 1, 'cl', 'confidential', "
            "          'authorization_code', 'Client', 3600);"
            "INSERT INTO user_account (id) VALUES (x'00000000000000000000000000000004');") != 0) {
        log_error("Deactivation: could not insert fixtures");
        goto done;
    }

    unsigned char token_id[16];
    if (oauth_token_create_access(sdb, 1, 1, 1, NULL, NULL, "deact-user-token", "read",
                                  3600, token_id) != 0 ||
        oauth_token_create_access(sdb, 1, 1, 0, NULL, NULL, "deact-machine-token", "read",
                                  3600, token_id) != 0) {
        log_error("Deactivation: could not create access tokens");
        goto done;
    }

    int active = 0;

    /* 1. Baseline: both live while the account is active. */
    if (oauth_introspect_token(sdb, "deact-user-token", NULL, 1, &active,
                               NULL, NULL, NULL, NULL, NULL, NULL) != 0 || !active ||
        oauth_access_token_is_active(sdb, "deact-user-token") != 1) {
        log_error("Deactivation: user token not active before deactivation");
        goto done;
    }
    log_info("  active account: user token active (OK)");

    /* 2. Deactivate, and the user's token must be dead to both. */
    if (db_execute_direct(sdb, "UPDATE user_account SET is_active = 0") != 0) {
        log_error("Deactivation: could not deactivate user");
        goto done;
    }
    active = -1;
    if (oauth_introspect_token(sdb, "deact-user-token", NULL, 1, &active,
                               NULL, NULL, NULL, NULL, NULL, NULL) != 0 || active != 0) {
        log_error("Deactivation: introspection still reports the token active");
        goto done;
    }
    if (oauth_access_token_is_active(sdb, "deact-user-token") != 0) {
        log_error("Deactivation: oauth_access_token_is_active still reports it active");
        goto done;
    }
    log_info("  deactivated account: introspection and liveness both inactive (OK)");

    /* 3. A client_credentials token has no user; the predicate must not kill it. */
    active = 0;
    if (oauth_introspect_token(sdb, "deact-machine-token", NULL, 1, &active,
                               NULL, NULL, NULL, NULL, NULL, NULL) != 0 || !active ||
        oauth_access_token_is_active(sdb, "deact-machine-token") != 1) {
        log_error("Deactivation: client_credentials token wrongly inactive");
        goto done;
    }
    log_info("  client_credentials token unaffected (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Deactivated-user token tests passed!");
    }
    return failed;
}

/*
 * Authorization-scoped writes must report when they matched nothing.
 *
 * These statements carry their authorization in the WHERE clause, so "not
 * found / not yours / not confidential" is a statement that changes zero rows
 * and still completes. Reported as success, that becomes a 200 carrying a key_id
 * and secret for a client key that does not exist, or "Key revoked successfully"
 * for a key that stays live. Each zero-row case below must return 1.
 *
 * Runs under both auth modes (user 1 administers org 1; org key 1 belongs to
 * org 1), since each write has a separate SQL text per mode, and checks that a
 * revoked key and another org's key are refused. Returns 0 on success.
 */
static int test_zero_row_writes(const config_t *config) {
    log_info("\nZero-row write reporting tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Zero-row: could not open a test database");
        return 1;
    }

    int failed = 1;

    /* Org 1 (ours) and org 2 (not ours). In org 1: a confidential client (pin 1),
       a public client (pin 2), a resource server (pin 1). In org 2: a
       confidential client (pin 3) and a resource server (pin 2). Org keys: pin 1
       active in org 1, pin 2 revoked in org 1, pin 3 active in org 2. The key
       hashes are never verified at this layer -- the queries authorize by key
       pin and is_active -- so placeholders do. */
    if (db_execute_direct(sdb,
            "INSERT INTO organization (id, code_name, display_name) VALUES "
            "  (x'10000000000000000000000000000001', 'ours', 'Ours'),"
            "  (x'10000000000000000000000000000002', 'theirs', 'Theirs');"
            "INSERT INTO organization_key (id, organization_pin, salt, hash_iterations, "
            "                              secret_hash, is_active) VALUES "
            "  (x'70000000000000000000000000000001', 1, 's', 1, 'h', 1),"
            "  (x'70000000000000000000000000000002', 1, 's', 1, 'h', 0),"
            "  (x'70000000000000000000000000000003', 2, 's', 1, 'h', 1);") != 0) {
        log_error("Zero-row: could not insert organizations");
        goto done;
    }
    if (db_execute_direct(sdb,
            "INSERT INTO user_account (id) VALUES (x'20000000000000000000000000000001');"
            "INSERT INTO organization_admin (organization_pin, user_account_pin) VALUES (1, 1);"
            "INSERT INTO client (id, organization_pin, code_name, client_type, grant_type, "
            "                    display_name, access_token_ttl_seconds) VALUES "
            "  (x'30000000000000000000000000000001', 1, 'conf', 'confidential', 'client_credentials', 'C', 60),"
            "  (x'30000000000000000000000000000002', 1, 'pub', 'public', 'authorization_code', 'P', 60),"
            "  (x'30000000000000000000000000000003', 2, 'other', 'confidential', 'client_credentials', 'O', 60);"
            "INSERT INTO resource_server (id, organization_pin, code_name, display_name, address) VALUES "
            "  (x'40000000000000000000000000000001', 1, 'rs', 'RS', 'https://rs.ours'),"
            "  (x'40000000000000000000000000000002', 2, 'rs2', 'RS2', 'https://rs.theirs');") != 0) {
        log_error("Zero-row: could not insert fixtures");
        goto done;
    }

    const unsigned char conf_client[16]  = {0x30,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
    const unsigned char pub_client[16]   = {0x30,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02};
    const unsigned char other_client[16] = {0x30,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03};
    const unsigned char our_rs[16]       = {0x40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
    const unsigned char their_rs[16]     = {0x40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02};
    const unsigned char unknown[16]      = {0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,
                                            0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99};
    const char *secret = "zero-row-test-secret-value";
    unsigned char key_id[16];
    int rc;

#define EXPECT(call, want, what) \
    do { rc = (call); if (rc != (want)) { \
        log_error("Zero-row: %s returned %d, expected %d", (what), rc, (want)); \
        goto done; } } while (0)

    /* Every dual-auth write has one SQL text per auth mode, so the matrix runs
       once under each: session (admin of org 1) and org 1's active key. */
    const struct { long long user_pin, key_pin; const char *name; } auths[] = {
        {  1, -1, "session" },
        { -1,  1, "org key" },
    };

    for (size_t a = 0; a < sizeof(auths) / sizeof(auths[0]); a++) {
        const long long U = auths[a].user_pin, K = auths[a].key_pin;

        /* Client keys */
        EXPECT(client_key_create(sdb, U, K, pub_client, secret, NULL, key_id), 1,
               "client key for a public client");
        EXPECT(client_key_create(sdb, U, K, other_client, secret, NULL, key_id), 1,
               "client key for another org's client");
        EXPECT(client_key_create(sdb, U, K, conf_client, secret, NULL, key_id), 0,
               "client key for our confidential client");
        EXPECT(client_key_revoke(sdb, U, K, key_id), 0, "revoke our client key");
        EXPECT(client_key_revoke(sdb, U, K, key_id), 1, "revoke it again");
        EXPECT(client_key_revoke(sdb, U, K, unknown), 1, "revoke an unknown client key");

        /* Resource server keys */
        EXPECT(resource_server_key_create(sdb, U, K, their_rs, secret, NULL, key_id), 1,
               "RS key for another org's resource server");
        EXPECT(resource_server_key_create(sdb, U, K, our_rs, secret, NULL, key_id), 0,
               "RS key for our resource server");
        EXPECT(resource_server_key_revoke(sdb, U, K, unknown), 1, "revoke an unknown RS key");
        EXPECT(resource_server_key_revoke(sdb, U, K, key_id), 0, "revoke our RS key");

        /* Client-resource-server links: "already linked" stays a success */
        EXPECT(client_resource_server_create(sdb, U, K, conf_client, their_rs), 1,
               "link across organizations");
        EXPECT(client_resource_server_create(sdb, U, K, other_client, their_rs), 1,
               "link in an org we don't administer");
        EXPECT(client_resource_server_create(sdb, U, K, conf_client, our_rs), 0, "link ours");
        EXPECT(client_resource_server_create(sdb, U, K, conf_client, our_rs), 0,
               "link ours again (idempotent)");
        EXPECT(client_resource_server_delete(sdb, U, K, conf_client, our_rs), 0, "unlink ours");
        EXPECT(client_resource_server_delete(sdb, U, K, conf_client, our_rs), 1,
               "unlink it again");

        /* Redirect URIs */
        EXPECT(client_redirect_uri_create(sdb, U, K, other_client, "https://x.example/cb", NULL), 1,
               "redirect URI on another org's client");
        EXPECT(client_redirect_uri_create(sdb, U, K, pub_client, "https://x.example/cb", NULL), 0,
               "redirect URI on our client");
        EXPECT(client_redirect_uri_delete(sdb, U, K, pub_client, "https://x.example/cb"), 0,
               "delete our redirect URI");
        EXPECT(client_redirect_uri_delete(sdb, U, K, pub_client, "https://x.example/cb"), 1,
               "delete it again");

        log_info("  %s: keys, links and redirect URIs report zero-row outcomes (OK)",
                 auths[a].name);
    }

    /* A revoked org key and another org's key must be refused everywhere --
       including against objects that exist and that org 1 could change. Set up
       live ones with session auth, try each denied key, then check they are
       all still there to be removed by the rightful caller. */
    unsigned char live_client_key[16], live_rs_key[16];
    EXPECT(client_key_create(sdb, 1, -1, conf_client, secret, NULL, live_client_key), 0,
           "set up a live client key");
    EXPECT(resource_server_key_create(sdb, 1, -1, our_rs, secret, NULL, live_rs_key), 0,
           "set up a live RS key");
    EXPECT(client_resource_server_create(sdb, 1, -1, conf_client, our_rs), 0,
           "set up a live link");
    EXPECT(client_redirect_uri_create(sdb, 1, -1, pub_client, "https://live.example/cb", NULL), 0,
           "set up a live redirect URI");

    const struct { long long key_pin; const char *name; } denied[] = {
        { 2, "revoked org key" },
        { 3, "other org's key" },
    };

    for (size_t d = 0; d < sizeof(denied) / sizeof(denied[0]); d++) {
        const long long K = denied[d].key_pin;

        EXPECT(client_key_create(sdb, -1, K, conf_client, secret, NULL, key_id), 1,
               "denied: create client key");
        EXPECT(client_key_revoke(sdb, -1, K, live_client_key), 1, "denied: revoke client key");
        EXPECT(resource_server_key_create(sdb, -1, K, our_rs, secret, NULL, key_id), 1,
               "denied: create RS key");
        EXPECT(resource_server_key_revoke(sdb, -1, K, live_rs_key), 1, "denied: revoke RS key");
        EXPECT(client_resource_server_create(sdb, -1, K, conf_client, our_rs), 1,
               "denied: link (already linked, but not the caller's)");
        EXPECT(client_resource_server_delete(sdb, -1, K, conf_client, our_rs), 1,
               "denied: unlink");
        EXPECT(client_redirect_uri_create(sdb, -1, K, pub_client, "https://y.example/cb", NULL), 1,
               "denied: create redirect URI");
        EXPECT(client_redirect_uri_delete(sdb, -1, K, pub_client, "https://live.example/cb"), 1,
               "denied: delete redirect URI");

        log_info("  %s: refused on every write, live objects included (OK)", denied[d].name);
    }

    EXPECT(client_key_revoke(sdb, 1, -1, live_client_key), 0, "live client key survived");
    EXPECT(resource_server_key_revoke(sdb, 1, -1, live_rs_key), 0, "live RS key survived");
    EXPECT(client_resource_server_delete(sdb, 1, -1, conf_client, our_rs), 0, "live link survived");
    EXPECT(client_redirect_uri_delete(sdb, 1, -1, pub_client, "https://live.example/cb"), 0,
           "live redirect URI survived");
    log_info("  live objects untouched by denied callers (OK)");

    /* Organization keys (unscoped at this layer; the handler authorizes) */
    EXPECT(organization_key_create(sdb, "ours", secret, NULL, key_id), 0, "org key create");
    EXPECT(organization_key_revoke(sdb, key_id), 0, "revoke org key");
    EXPECT(organization_key_revoke(sdb, key_id), 0, "revoke org key again (idempotent)");
    EXPECT(organization_key_revoke(sdb, unknown), 1, "revoke an unknown org key");
    log_info("  organization key revoke reports an unknown id (OK)");

#undef EXPECT

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Zero-row write reporting tests passed!");
    }
    return failed;
}

int main(void) {
    log_init(LOG_INFO);
    log_info("Database Integration Test");

#ifdef DB_BACKEND_POSTGRESQL
    /* The connection below is only built for SQLite's db_path, and the tests
       above run on SQLite in memory. The PostgreSQL backend has no runtime
       tests; saying so beats failing to connect. */
    log_info("Skipped: test-db runs in the SQLite build only.");
    return 0;
#endif

    /* Load configuration */
    log_info("Loading configuration...");
    config_t *config = config_load("auth.conf");
    if (!config) {
        log_error("Failed to load configuration");
        return 1;
    }

    log_info("Configuration loaded:");
    log_info("  Server: %s:%d (workers=%d)", config->host, config->port, config->workers);
    log_info("  Database type: %s", config->db_type == DB_TYPE_SQLITE ? "SQLite" : "PostgreSQL");
    log_info("  Database path: %s", config->db_path ? config->db_path : "(none)");
    log_info("  Schema dir: %s", config->schema_dir);

    /* Connect to database */
    log_info("Connecting to database...");
    db_handle_t *db = NULL;
    const char *connection_string = config->db_type == DB_TYPE_SQLITE
        ? config->db_path
        : ""; /* PostgreSQL connection string not yet implemented */

    int result = db_connect(&db, config->db_type, connection_string);
    if (result != 0) {
        log_error("Failed to connect to database");
        config_free(config);
        return 1;
    }

    log_info("Connected successfully");

    /* Initialize schema */
    log_info("Initializing schema...");
    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    result = db_init_schema(db, config->db_type, config->schema_dir, owner_role);
    if (result < 0) {
        log_error("Failed to initialize schema");
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    int fresh_schema = (result == 0);
    log_info("Schema initialized (%s)", fresh_schema ? "created" : "already existed");

    /* Initialize history tables if enabled */
    if (config->enable_history_tables) {
        result = db_init_history_tables(db, config->db_type, fresh_schema);
        if (result != 0) {
            log_error("Failed to initialize history tables");
            db_disconnect(db);
            config_free(config);
            return 1;
        }
    } else {
        log_info("History tables disabled in configuration");
    }

    /* Test query: List all tables */
    log_info("Testing query...");
    db_result_t *query_result = NULL;
#ifdef DB_BACKEND_SQLITE
    result = db_query(db, &query_result, "SELECT name FROM sqlite_master WHERE type='table';");
#endif
#ifdef DB_BACKEND_POSTGRESQL
    result = db_query(db, &query_result,
        "SELECT table_schema || '.' || table_name "
        "FROM information_schema.tables "
        "WHERE table_schema IN ('keys','security','session','lookup','logging') "
        "ORDER BY table_schema, table_name;");
#endif
    if (result != 0) {
        log_error("Query failed: %s", db_error(db));
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    int row_count = db_result_row_count(query_result);
    int col_count = db_result_column_count(query_result);
    log_info("Query returned %d rows, %d columns", row_count, col_count);

    /* Print table names */
    log_info("Tables in database:");
    for (int i = 0; i < row_count; i++) {
        const char *table_name = db_result_get(query_result, i, 0);
        log_info("  - %s", table_name ? table_name : "(null)");
    }

    db_result_free(query_result);

    /* Test prepared statement: Query grant_type lookup table */
    log_info("\nTesting prepared statement API...");

    const char *sql =
        "SELECT grant_type, description "
        "FROM " TBL_GRANT_TYPE " "
        "WHERE grant_type = " P"1";

    db_stmt_t *stmt = NULL;
    result = db_prepare(db, &stmt, sql);
    if (result != 0) {
        log_error("Prepare failed: %s", db_error(db));
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    log_info("Statement prepared successfully");

    /* Test 1: Query for 'authorization_code' */
    db_bind_text(stmt, 1, "authorization_code", -1);

    result = db_step(stmt);
    if (result == DB_ROW) {
        const char *grant_type = db_column_text(stmt, 0);
        const char *description = db_column_text(stmt, 1);
        log_info("Found: %s - %s", grant_type, description);
    } else if (result == DB_DONE) {
        log_warn("No rows returned for 'authorization_code'");
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Test 2: Reset and query for 'client_credentials' */
    db_reset(stmt);
    db_bind_text(stmt, 1, "client_credentials", -1);

    result = db_step(stmt);
    if (result == DB_ROW) {
        const char *grant_type = db_column_text(stmt, 0);
        const char *description = db_column_text(stmt, 1);
        log_info("Found: %s - %s", grant_type, description);
    } else if (result == DB_DONE) {
        log_warn("No rows returned for 'client_credentials'");
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Test 3: Query for non-existent grant type */
    db_reset(stmt);
    db_bind_text(stmt, 1, "nonexistent_grant", -1);

    result = db_step(stmt);
    if (result == DB_DONE) {
        log_info("Correctly returned no rows for nonexistent grant type");
    } else if (result == DB_ROW) {
        log_error("Unexpectedly found row for nonexistent grant type");
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    } else {
        log_error("Step failed: %s", db_error(db));
        db_finalize(stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    db_finalize(stmt);
    log_info("Prepared statement tests passed!");

    /* Test bind/column for all parameter types via SELECT passthrough */
    log_info("\nTesting bind/column types...");

    const char *type_sql =
        "SELECT " P"1, " P"2, " P"3, " P"4";

    db_stmt_t *type_stmt = NULL;
    result = db_prepare(db, &type_stmt, type_sql);
    if (result != 0) {
        log_error("Prepare type test failed: %s", db_error(db));
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Bind: int, int64, blob, null */
    db_bind_int(type_stmt, 1, 7777777);
    db_bind_int64(type_stmt, 2, 631411200000LL);
    unsigned char test_blob[] = {0xDA, 0xDA};
    db_bind_blob(type_stmt, 3, test_blob, sizeof(test_blob));
    db_bind_null(type_stmt, 4);

    result = db_step(type_stmt);
    if (result != DB_ROW) {
        log_error("Type test: expected row, got %d", result);
        db_finalize(type_stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }

    /* Verify int */
    int int_val = db_column_int(type_stmt, 0);
    if (int_val != 7777777) {
        log_error("Type test: int expected 7777777, got %d", int_val);
        db_finalize(type_stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }
    log_info("  int:   %d (OK)", int_val);

    /* Verify int64 */
    long long int64_val = db_column_int64(type_stmt, 1);
    if (int64_val != 631411200000LL) {
        log_error("Type test: int64 expected 631411200000, got %lld", int64_val);
        db_finalize(type_stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }
    log_info("  int64: %lld (OK)", int64_val);

    /* Verify blob */
    const unsigned char *blob_val = db_column_blob(type_stmt, 2);
    int blob_len = db_column_bytes(type_stmt, 2);
    if (!blob_val || blob_len != 2 ||
        blob_val[0] != 0xDA || blob_val[1] != 0xDA) {
        log_error("Type test: blob mismatch (len=%d)", blob_len);
        db_finalize(type_stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }
    log_info("  blob:  0xDADA (%d bytes) (OK)", blob_len);

    /* Verify null */
    int null_type = db_column_type(type_stmt, 3);
    if (null_type != DB_NULL) {
        log_error("Type test: expected NULL type (%d), got %d", DB_NULL, null_type);
        db_finalize(type_stmt);
        db_disconnect(db);
        config_free(config);
        return 1;
    }
    log_info("  null:  (OK)");

    db_finalize(type_stmt);
    log_info("Bind/column type tests passed!");

    /* Disconnect */
    log_info("\nDisconnecting...");
    db_disconnect(db);

    if (test_signing_key_cache(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_mfa_management_gate(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_deactivated_user_tokens(config) != 0) {
        config_free(config);
        return 1;
    }

    /* Key creation hashes the secret, so the password module needs its config */
    if (crypto_password_init(config) != 0 || test_zero_row_writes(config) != 0) {
        config_free(config);
        return 1;
    }

    /* Cleanup */
    config_free(config);

    log_info("=== Database Integration Test Passed! ===");
    return 0;
}
