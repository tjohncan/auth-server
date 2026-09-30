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
#include "db/queries/mfa.h"
#include "crypto/password.h"
#include "crypto/encrypt.h"
#include "crypto/sha256.h"
#include "db/queries/user.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

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

/* Read the first column of a one-row query, raw, as stored. */
static int read_stored_value(db_handle_t *db, const char *sql, char *out, size_t out_size) {
    db_stmt_t *stmt = NULL;
    out[0] = '\0';
    if (db_prepare(db, &stmt, sql) != 0) return -1;
    int rc = db_step(stmt);
    const char *v = (rc == DB_ROW) ? db_column_text(stmt, 0) : NULL;
    if (v) snprintf(out, out_size, "%s", v);
    db_finalize(stmt);
    return (rc == DB_ROW && v) ? 0 : -1;
}

/* One organization, resource server and confidential client; pins are all 1. */
#define FIXTURE_ORG_RS_CLIENT \
    "INSERT INTO organization (id, code_name, display_name) " \
    "  VALUES (x'00000000000000000000000000000001', 'org', 'Org');" \
    "INSERT INTO resource_server (id, organization_pin, code_name, display_name, address) " \
    "  VALUES (x'00000000000000000000000000000002', 1, 'rs', 'RS', 'https://rs.example');" \
    "INSERT INTO client (id, organization_pin, code_name, client_type, grant_type, " \
    "                    display_name, access_token_ttl_seconds) " \
    "  VALUES (x'00000000000000000000000000000003', 1, 'cl', 'confidential', " \
    "          'authorization_code', 'Client', 3600);"

static const unsigned char FIXTURE_CLIENT_ID[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03};

/*
 * Part of what README.md promises about storage, checked against what lands in
 * the tables: a username is kept encrypted and found again through its blind
 * index, whatever its case; a password verifies as itself and nothing else; and
 * every bearer credential -- session, authorization code, refresh and access
 * token -- is kept as its SHA-256, never as issued. Emails and MFA secrets are
 * sealed the same way as usernames but are not checked here.
 *
 * Returns 0 on success.
 */
static int test_storage_at_rest(const config_t *config) {
    log_info("\nStorage-at-rest tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Storage: could not open a test database");
        return 1;
    }

    int failed = 1;
    char stored[512], opened[256], expected[SHA256_HEX_LENGTH];

    /* 1. The username is stored encrypted, and opens to what was given */
    unsigned char user_id[16];
    if (user_create(sdb, "Alice", NULL, "correct horse", user_id) != 0) {
        log_error("Storage: could not create a user");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT username FROM user_account", stored, sizeof(stored)) != 0 ||
        strcmp(stored, "Alice") == 0 ||
        decrypt_field(stored, opened, sizeof(opened)) != 0 || strcmp(opened, "Alice") != 0) {
        log_error("Storage: username is not stored encrypted");
        goto done;
    }
    log_info("  username encrypted at rest (OK)");

    /* 2. Login finds the user through the blind index, whatever the case, and
       the password verifies only as itself */
    long long user_pin = 0;
    if (user_verify_password(sdb, "alice", "correct horse", &user_pin, NULL) != 1 ||
        user_verify_password(sdb, "ALICE", "correct horse", NULL, NULL) != 1) {
        log_error("Storage: login by username failed");
        goto done;
    }
    if (user_verify_password(sdb, "Alice", "correct horsE", NULL, NULL) != 0 ||
        user_verify_password(sdb, "Alicia", "correct horse", NULL, NULL) != 0) {
        log_error("Storage: a wrong password or an unknown username verified");
        goto done;
    }
    log_info("  login by blind index, case-insensitive; wrong password refused (OK)");

    /* 3. Every bearer credential is stored as its SHA-256 */
    unsigned char code_id[16], id[16];
    if (db_execute_direct(sdb, FIXTURE_ORG_RS_CLIENT) != 0 ||
        oauth_session_create(sdb, user_pin, user_id, "raw-session-token", "password",
                             NULL, NULL, 3600, id) != 0 ||
        oauth_auth_code_create(sdb, 1, FIXTURE_CLIENT_ID, user_pin, user_id, "raw-auth-code",
                               NULL, NULL, 600, code_id) != 0 ||
        oauth_token_create_refresh(sdb, 1, user_pin, code_id, "raw-refresh-token", "read",
                                   3600, id) != 0 ||
        oauth_token_create_access(sdb, 1, 1, user_pin, code_id, NULL, "raw-access-token",
                                  "read", 3600, id) != 0) {
        log_error("Storage: could not issue credentials");
        goto done;
    }
    const struct { const char *sql, *issued; } creds[] = {
        { "SELECT session_token FROM browser",   "raw-session-token" },
        { "SELECT code FROM authorization_code", "raw-auth-code" },
        { "SELECT token FROM refresh_token",     "raw-refresh-token" },
        { "SELECT token FROM access_token",      "raw-access-token" },
    };
    for (size_t i = 0; i < sizeof(creds) / sizeof(creds[0]); i++) {
        if (crypto_sha256_hex(creds[i].issued, strlen(creds[i].issued),
                              expected, sizeof(expected)) != 0 ||
            read_stored_value(sdb, creds[i].sql, stored, sizeof(stored)) != 0 ||
            strcmp(stored, expected) != 0) {
            log_error("Storage: \"%s\" does not hold the SHA-256 of what was issued",
                      creds[i].sql);
            goto done;
        }
    }
    log_info("  session, code, refresh and access tokens stored as SHA-256 (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Storage-at-rest tests passed!");
    }
    return failed;
}

/*
 * A credential is good until it is used up, revoked, closed or expired: an
 * authorization code exchanges exactly once, a revoked or expired access token
 * is inactive, and a closed or expired session is not found. Deactivation, the
 * other way out, is test_deactivated_user_tokens.
 *
 * Returns 0 on success.
 */
static int test_credential_lifetimes(const config_t *config) {
    log_info("\nCredential lifetime tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Lifetimes: could not open a test database");
        return 1;
    }

    int failed = 1;

    if (db_execute_direct(sdb, FIXTURE_ORG_RS_CLIENT
            "INSERT INTO user_account (id) VALUES (x'00000000000000000000000000000004');") != 0) {
        log_error("Lifetimes: could not insert fixtures");
        goto done;
    }
    const unsigned char user_id[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x04};
    unsigned char id[16];

    /* Credential tables are keyed by id blobs. Below, rows are picked out by
       SQLite's rowid, which is insertion order: 1 stays good, 2 and 3 do not. */

    /* 1. An authorization code exchanges once, and the second try is reported
       as a replay; an expired one never exchanges */
    oauth_auth_code_data_t code;
    if (oauth_auth_code_create(sdb, 1, FIXTURE_CLIENT_ID, 1, user_id, "life-code",
                               NULL, NULL, 600, id) != 0 ||
        oauth_auth_code_create(sdb, 1, FIXTURE_CLIENT_ID, 1, user_id, "life-code-expired",
                               NULL, NULL, 600, id) != 0 ||
        db_execute_direct(sdb, "UPDATE authorization_code "
                               "SET expected_expiry = datetime('now', '-1 second') "
                               "WHERE rowid = 2") != 0) {
        log_error("Lifetimes: could not create authorization codes");
        goto done;
    }
    if (oauth_auth_code_consume(sdb, "life-code", &code) != 0 || code.user_account_pin != 1) {
        log_error("Lifetimes: a fresh authorization code did not exchange");
        goto done;
    }
    if (oauth_auth_code_consume(sdb, "life-code", &code) != 1) {
        log_error("Lifetimes: a used authorization code was not reported as a replay");
        goto done;
    }
    if (oauth_auth_code_consume(sdb, "life-code-expired", &code) != -1) {
        log_error("Lifetimes: an expired authorization code exchanged");
        goto done;
    }
    log_info("  authorization code: exchanges once, replay reported, expired refused (OK)");

    /* 2. Access tokens: revoked and expired are inactive to both liveness checks */
    const char *tokens[] = { "life-access", "life-access-revoked", "life-access-expired" };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (oauth_token_create_access(sdb, 1, 1, 1, NULL, NULL, tokens[i], "read",
                                      3600, id) != 0) {
            log_error("Lifetimes: could not create access tokens");
            goto done;
        }
    }
    if (db_execute_direct(sdb,
            "UPDATE access_token SET is_revoked = 1 WHERE rowid = 2;"
            "UPDATE access_token SET expected_expiry = datetime('now', '-1 second') "
            "WHERE rowid = 3;") != 0) {
        log_error("Lifetimes: could not revoke and expire access tokens");
        goto done;
    }
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        int want = (i == 0), active = -1;
        if (oauth_introspect_token(sdb, tokens[i], NULL, 1, &active,
                                   NULL, NULL, NULL, NULL, NULL, NULL) != 0 ||
            active != want || oauth_access_token_is_active(sdb, tokens[i]) != want) {
            log_error("Lifetimes: %s should be %s", tokens[i], want ? "active" : "inactive");
            goto done;
        }
    }
    log_info("  access token: revoked and expired are inactive (OK)");

    /* 3. Sessions: closed and expired are not found */
    const char *sessions[] = { "life-session", "life-session-closed", "life-session-expired" };
    for (size_t i = 0; i < sizeof(sessions) / sizeof(sessions[0]); i++) {
        if (oauth_session_create(sdb, 1, user_id, sessions[i], "password",
                                 NULL, NULL, 3600, id) != 0) {
            log_error("Lifetimes: could not create sessions");
            goto done;
        }
    }
    if (db_execute_direct(sdb,
            "UPDATE browser SET is_closed = 1 WHERE rowid = 2;"
            "UPDATE browser SET expected_expiry = datetime('now', '-1 second') "
            "WHERE rowid = 3;") != 0) {
        log_error("Lifetimes: could not close and expire sessions");
        goto done;
    }
    for (size_t i = 0; i < sizeof(sessions) / sizeof(sessions[0]); i++) {
        oauth_session_info_t s;
        int found = (oauth_session_get_by_token(sdb, sessions[i], &s) == 0);
        if (found != (i == 0)) {
            log_error("Lifetimes: %s should %sbe found", sessions[i], i == 0 ? "" : "not ");
            goto done;
        }
    }
    log_info("  session: closed and expired are not found (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Credential lifetime tests passed!");
    }
    return failed;
}

/*
 * Two guarantees the schema makes and the code leans on without checking:
 * foreign keys are enforced -- SQLite leaves them off unless each connection
 * asks, which db_connect does -- and require_mfa cannot be on without has_mfa,
 * which oauth_session_mfa_pending relies on to cover both flags.
 *
 * Returns 0 on success.
 */
static int test_schema_constraints(const config_t *config) {
    log_info("\nSchema constraint tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Schema: could not open a test database");
        return 1;
    }

    int failed = 1;

    if (db_execute_direct(sdb,
            "INSERT INTO user_account (id) VALUES (x'00000000000000000000000000000004');") != 0) {
        log_error("Schema: could not insert a user");
        goto done;
    }

    /* 1. A row pointing at a user that does not exist is refused */
    if (db_execute_direct(sdb,
            "INSERT INTO user_mfa (id, user_account_pin, mfa_method, display_name, secret) "
            "VALUES (x'00000000000000000000000000000005', 999, 'TOTP', 'x', 's');") == 0) {
        log_error("Schema: a row referencing a missing user was accepted; foreign keys are off");
        goto done;
    }
    log_info("  foreign keys enforced (OK)");

    /* 2. require_mfa is refused without has_mfa, and accepted with it */
    if (db_execute_direct(sdb, "UPDATE user_account SET require_mfa = 1;") == 0) {
        log_error("Schema: require_mfa was set without has_mfa");
        goto done;
    }
    if (db_execute_direct(sdb, "UPDATE user_account SET has_mfa = 1, require_mfa = 1;") != 0) {
        log_error("Schema: has_mfa with require_mfa was refused");
        goto done;
    }
    log_info("  require_mfa needs has_mfa (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Schema constraint tests passed!");
    }
    return failed;
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
 * Signing keys are encrypted at rest, and a key that will not open fails
 * rather than being replaced.
 *
 * The ES256 private key mints access tokens; storing it in plaintext would make
 * read access to the database enough to forge them. This pins: what is stored
 * (sealed private material, plaintext public key); that rotation carries the
 * sealed value into the prior columns intact; and the two ways a row can fail to
 * open -- plaintext format, or a different encryption_key -- both fail every load
 * and leave the row untouched instead of regenerating over it.
 *
 * Returns 0 on success.
 */
static int test_signing_key_encryption(const config_t *config) {
    log_info("\nSigning-key encryption tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Key encryption: could not open a test database");
        return 1;
    }

    int failed = 1;
    signing_key_t *es = NULL, *hmac = NULL, *rotated = NULL, *bad = NULL;
    char stored[1024], stored_before[1024];

    signing_key_thread_cleanup();

    /* 1. What lands in the table */
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &es) != 0 || !es ||
        signing_key_get_or_rotate(sdb, SIGNING_KEY_AUTH_REQUEST, &hmac) != 0 || !hmac) {
        log_error("Key encryption: could not generate keys");
        goto done;
    }
    if (strncmp(es->current_private_key, "-----BEGIN PRIVATE KEY-----", 27) != 0) {
        log_error("Key encryption: loaded private key is not a PEM");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT current_private_key FROM access_token_signing",
                        stored, sizeof(stored)) != 0 ||
        strncmp(stored, "e1:", 3) != 0 || strstr(stored, "PRIVATE KEY")) {
        log_error("Key encryption: private key stored unsealed: %.40s", stored);
        goto done;
    }
    if (read_stored_value(sdb, "SELECT current_secret FROM auth_request_signing",
                        stored, sizeof(stored)) != 0 ||
        strncmp(stored, "e1:", 3) != 0 || strcmp(stored + 3, hmac->current_secret) == 0) {
        log_error("Key encryption: HMAC secret stored unsealed");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT current_public_key FROM access_token_signing",
                        stored, sizeof(stored)) != 0 ||
        strncmp(stored, "-----BEGIN PUBLIC KEY-----", 26) != 0) {
        log_error("Key encryption: public key should stay plaintext");
        goto done;
    }
    log_info("  private material sealed at rest, public key plaintext (OK)");

    /* 2. Rotation moves the sealed value into prior, and it still opens */
    if (read_stored_value(sdb, "SELECT current_private_key FROM access_token_signing",
                        stored_before, sizeof(stored_before)) != 0 ||
        db_execute_direct(sdb,
            "UPDATE access_token_signing SET current_generated_at = "
            "datetime('now', '-61 days')") != 0 ||
        signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &rotated) != 0 || !rotated) {
        log_error("Key encryption: rotation failed");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT prior_private_key FROM access_token_signing",
                        stored, sizeof(stored)) != 0 ||
        strcmp(stored, stored_before) != 0 ||
        !rotated->prior_private_key ||
        strcmp(rotated->prior_private_key, es->current_private_key) != 0 ||
        strcmp(rotated->current_private_key, es->current_private_key) == 0) {
        log_error("Key encryption: rotation did not carry the sealed key into prior");
        goto done;
    }
    log_info("  rotation carries the sealed key into prior and it opens (OK)");

    /* 3. Pre-encryption plaintext row: every load fails, nothing is regenerated */
    if (db_execute_direct(sdb,
            "UPDATE auth_request_signing SET current_secret = 'legacy-plaintext-secret'") != 0) {
        log_error("Key encryption: could not plant a legacy row");
        goto done;
    }
    signing_key_thread_cleanup();  /* the cache is keyed on timestamps; force a reload */
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_AUTH_REQUEST, &bad) == 0) {
        log_error("Key encryption: a plaintext row was accepted");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT current_secret FROM auth_request_signing",
                        stored, sizeof(stored)) != 0 ||
        strcmp(stored, "legacy-plaintext-secret") != 0) {
        log_error("Key encryption: the legacy row was overwritten");
        goto done;
    }
    log_info("  plaintext legacy row fails and is left alone (OK)");

    /* 4. Different encryption_key: fails, row untouched; right key recovers */
    if (encrypt_init("not-the-key-that-sealed-these") != 0) {
        log_error("Key encryption: could not switch passphrase");
        goto done;
    }
    signing_key_thread_cleanup();
    int wrong_key_rc = signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &bad);
    if (encrypt_init(config->encryption_key) != 0) {
        log_error("Key encryption: could not restore passphrase");
        goto done;
    }
    if (wrong_key_rc == 0) {
        log_error("Key encryption: key opened under the wrong encryption_key");
        goto done;
    }
    signing_key_thread_cleanup();
    signing_key_free(rotated);
    rotated = NULL;
    if (signing_key_get_or_rotate(sdb, SIGNING_KEY_ACCESS_TOKEN, &rotated) != 0 || !rotated) {
        log_error("Key encryption: key did not open again under the right encryption_key");
        goto done;
    }
    log_info("  wrong encryption_key fails, right one recovers (OK)");

    failed = 0;

done:
    signing_key_free(es);
    signing_key_free(hmac);
    signing_key_free(rotated);
    signing_key_free(bad);
    signing_key_thread_cleanup();
    OPENSSL_cleanse(stored, sizeof(stored));
    OPENSSL_cleanse(stored_before, sizeof(stored_before));
    db_disconnect(sdb);
    if (!failed) {
        log_info("Signing-key encryption tests passed!");
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
 * The operator's MFA reset. User 1 has a confirmed method, an unconfirmed one, a
 * recovery-code set and require on, and a password-only session held at the
 * factor-management gate. After the reset no method remains, the recovery-code
 * set is revoked, both flags are clear, and that session is free of the gate:
 * first enrollment is open again. User 2's confirmed method is untouched, a
 * repeat succeeds, and an unknown id is reported.
 *
 * Returns 0 on success.
 */
static int test_mfa_reset(const config_t *config) {
    log_info("\nMFA reset tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("MFA reset: could not open a test database");
        return 1;
    }

    int failed = 1;
    char value[64];

    if (db_execute_direct(sdb,
            "INSERT INTO user_account (id) VALUES "
            "  (x'00000000000000000000000000000011'),"
            "  (x'00000000000000000000000000000012');") != 0) {
        log_error("MFA reset: could not insert users");
        goto done;
    }
    const unsigned char user1[16]   = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x11};
    const unsigned char unknown[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x99};

    unsigned char method_id[16], set_id[16];
    const char *codes[] = { "reset-code-one", "reset-code-two" };
    if (mfa_method_create(sdb, 1, "TOTP", "phone", "secret-1", method_id) != 0 ||
        mfa_method_confirm(sdb, method_id) != 0 ||
        mfa_method_create(sdb, 1, "TOTP", "spare", "secret-2", method_id) != 0 ||
        recovery_code_set_create(sdb, 1, codes, 2, set_id) != 0 ||
        mfa_update_require_mfa_flag(sdb, 1, 1) != 0 ||
        mfa_method_create(sdb, 2, "TOTP", "theirs", "secret-3", method_id) != 0 ||
        mfa_method_confirm(sdb, method_id) != 0) {
        log_error("MFA reset: could not set up MFA");
        goto done;
    }

    const char *token = "mfa-reset-test-session";
    unsigned char session_id[16];
    oauth_session_info_t s;
    if (oauth_session_create(sdb, 1, user1, token, "password", NULL, NULL, 3600, session_id) != 0 ||
        oauth_session_get_by_token(sdb, token, &s) != 0 || !oauth_session_mfa_pending(&s)) {
        log_error("MFA reset: the password-only session should start out gated");
        goto done;
    }

    /* 1. Reset user 1: everything of theirs goes, nothing of user 2's does */
    if (mfa_reset_user(sdb, user1) != 0) {
        log_error("MFA reset: the reset failed");
        goto done;
    }
    const struct { const char *sql, *want, *what; } after[] = {
        { "SELECT COUNT(*) FROM user_mfa WHERE user_account_pin = 1", "0",
          "user 1's methods" },
        { "SELECT COUNT(*) FROM recovery_code_set WHERE user_account_pin = 1 AND is_active = 1", "0",
          "user 1's active recovery-code sets" },
        { "SELECT COUNT(*) FROM recovery_code_set WHERE user_account_pin = 1 AND revoked_at IS NOT NULL", "1",
          "user 1's revoked recovery-code sets" },
        { "SELECT has_mfa || '/' || require_mfa FROM user_account WHERE pin = 1", "0/0",
          "user 1's has_mfa/require_mfa" },
        { "SELECT COUNT(*) FROM user_mfa WHERE user_account_pin = 2 AND is_confirmed = 1", "1",
          "user 2's confirmed methods" },
        { "SELECT has_mfa FROM user_account WHERE pin = 2", "1",
          "user 2's has_mfa" },
    };
    for (size_t i = 0; i < sizeof(after) / sizeof(after[0]); i++) {
        if (read_stored_value(sdb, after[i].sql, value, sizeof(value)) != 0 ||
            strcmp(value, after[i].want) != 0) {
            log_error("MFA reset: %s is '%s', expected '%s'", after[i].what, value, after[i].want);
            goto done;
        }
    }
    log_info("  methods deleted, recovery codes revoked, both flags clear (OK)");
    log_info("  another user's MFA untouched (OK)");

    if (oauth_session_get_by_token(sdb, token, &s) != 0 || oauth_session_mfa_pending(&s)) {
        log_error("MFA reset: the session is still held at the gate");
        goto done;
    }
    log_info("  the user's session is free of the gate, so enrollment is open again (OK)");

    /* 2. A repeat changes nothing and succeeds; an unknown id is reported */
    if (mfa_reset_user(sdb, user1) != 0 || mfa_reset_user(sdb, unknown) != 1) {
        log_error("MFA reset: a repeat, or an unknown id, was answered wrongly");
        goto done;
    }
    log_info("  repeat succeeds, unknown id reported (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("MFA reset tests passed!");
    }
    return failed;
}

/*
 * Token liveness after account deactivation.
 *
 * user_set_active revokes a user's tokens (test_deactivation_revokes), but every
 * liveness query also reads is_active at use time, for the tokens that sweep
 * misses: one issued while the deactivation was running, or anything an account
 * deactivated before the sweep existed still holds. So this flips is_active
 * directly, as such an account was left, and pins the use-time check in both
 * queries, and that a client_credentials token (no user row) is not collateral
 * damage of it. Deactivating the client's organization, or the token's resource
 * server, revokes nothing and is read the same way, for both kinds of token.
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

    /* 4. With the account active again, deactivating the client's organization
       kills both tokens, and reactivating it brings them back. The same for the
       tokens' resource server. */
    if (db_execute_direct(sdb, "UPDATE user_account SET is_active = 1") != 0) {
        log_error("Deactivation: could not reactivate the user");
        goto done;
    }
    const char *owners[] = { "organization", "resource_server" };
    const char *owned_tokens[] = { "deact-user-token", "deact-machine-token" };
    for (size_t o = 0; o < sizeof(owners) / sizeof(owners[0]); o++) {
        char sql[64];
        snprintf(sql, sizeof(sql), "UPDATE %s SET is_active = 0", owners[o]);
        if (db_execute_direct(sdb, sql) != 0) {
            log_error("Deactivation: could not deactivate the %s", owners[o]);
            goto done;
        }
        for (size_t i = 0; i < sizeof(owned_tokens) / sizeof(owned_tokens[0]); i++) {
            active = -1;
            if (oauth_introspect_token(sdb, owned_tokens[i], NULL, 1, &active,
                                       NULL, NULL, NULL, NULL, NULL, NULL) != 0 || active != 0 ||
                oauth_access_token_is_active(sdb, owned_tokens[i]) != 0) {
                log_error("Deactivation: %s still active after its %s was deactivated",
                          owned_tokens[i], owners[o]);
                goto done;
            }
        }
        snprintf(sql, sizeof(sql), "UPDATE %s SET is_active = 1", owners[o]);
        if (db_execute_direct(sdb, sql) != 0 ||
            oauth_access_token_is_active(sdb, "deact-user-token") != 1 ||
            oauth_access_token_is_active(sdb, "deact-machine-token") != 1) {
            log_error("Deactivation: tokens not active again after the %s was reactivated",
                      owners[o]);
            goto done;
        }
        log_info("  deactivated %s: both tokens inactive, active again after (OK)", owners[o]);
    }

    /* 5. A malformed user id must not degrade into "no user". A zero user id is
       how a client_credentials token looks, so a user token would introspect
       as active with no sub. It must read as inactive instead. */
    if (db_execute_direct(sdb,
            "UPDATE user_account SET is_active = 1, id = x'DEADBEEF'") != 0) {
        log_error("Deactivation: could not corrupt the user id");
        goto done;
    }
    active = -1;
    if (oauth_introspect_token(sdb, "deact-user-token", NULL, 1, &active,
                               NULL, NULL, NULL, NULL, NULL, NULL) != 0 || active != 0) {
        log_error("Deactivation: token with a malformed user id introspected as active");
        goto done;
    }
    log_info("  malformed user id: inactive, not a machine token (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Deactivated-user token tests passed!");
    }
    return failed;
}

/*
 * Deactivation revokes, so reactivation doesn't resurrect.
 *
 * The use-time checks read is_active, so an account that is only flagged
 * inactive gets every session and token back when it is reactivated: an
 * attacker's included, MFA-complete sessions and all, and every emailed link
 * still in date. user_set_active must close the sessions, revoke the refresh and
 * access tokens and void the password-reset, passwordless-login and invitation
 * links when it deactivates, leave another user's alone, and sweep an account an
 * older build flagged inactive without revoking anything.
 *
 * Returns 0 on success.
 */
static int test_deactivation_revokes(const config_t *config) {
    log_info("\nDeactivation revocation tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Revocation: could not open a test database");
        return 1;
    }

    int failed = 1;

    /* Two users, pins 1 and 2 */
    if (db_execute_direct(sdb, FIXTURE_ORG_RS_CLIENT
            "INSERT INTO user_account (id) VALUES (x'00000000000000000000000000000004');"
            "INSERT INTO user_account (id) VALUES (x'00000000000000000000000000000005');") != 0) {
        log_error("Revocation: could not insert fixtures");
        goto done;
    }
    const unsigned char user_ids[2][16] = {
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x04},
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x05},
    };

    /* Each user gets an MFA-complete session, a refresh token and an access token,
       and a password-reset, a passwordless-login and an invitation link. The
       emailed links are rows with a known token hash, which is all their
       redeem functions look at besides the account. */
    const char *sessions[] = { "revoke-session-1", "revoke-session-2" };
    const char *codes[]    = { "revoke-code-1", "revoke-code-2" };
    const char *refresh[]  = { "revoke-refresh-1", "revoke-refresh-2" };
    const char *access[]   = { "revoke-access-1", "revoke-access-2" };
    const char *resets[]   = { "revoke-reset-1", "revoke-reset-2" };
    const char *pwless[]   = { "revoke-pwless-1", "revoke-pwless-2" };
    char invites[2][64];
    for (int u = 0; u < 2; u++) {
        unsigned char id[16], code_id[16];
        if (oauth_session_create(sdb, u + 1, user_ids[u], sessions[u], "password",
                                 NULL, NULL, 3600, id) != 0 ||
            oauth_session_set_mfa_completed(sdb, sessions[u]) != 0 ||
            oauth_auth_code_create(sdb, 1, FIXTURE_CLIENT_ID, u + 1, user_ids[u], codes[u],
                                   NULL, NULL, 600, code_id) != 0 ||
            oauth_token_create_refresh(sdb, 1, u + 1, code_id, refresh[u], "read",
                                       3600, id) != 0 ||
            oauth_token_create_access(sdb, 1, 1, u + 1, NULL, NULL, access[u], "read",
                                      3600, id) != 0) {
            log_error("Revocation: could not create sessions and tokens");
            goto done;
        }

        char reset_hash[SHA256_HEX_LENGTH], pwless_hash[SHA256_HEX_LENGTH], sql[1024];
        if (crypto_sha256_hex(resets[u], strlen(resets[u]), reset_hash, sizeof(reset_hash)) != 0 ||
            crypto_sha256_hex(pwless[u], strlen(pwless[u]), pwless_hash, sizeof(pwless_hash)) != 0) {
            log_error("Revocation: could not hash the emailed-link tokens");
            goto done;
        }
        snprintf(sql, sizeof(sql),
            "UPDATE user_account SET allow_passwordless_login = 1 WHERE pin = %d;"
            "INSERT INTO password_reset_token (id, user_account_pin, token, issued_at, expected_expiry) "
            "  VALUES (randomblob(16), %d, '%s', datetime('now'), datetime('now', '+1 hour'));"
            "INSERT INTO passwordless_login_token "
            "  (id, user_account_pin, email_address, token, issued_at, expected_expiry) "
            "  VALUES (randomblob(16), %d, 'not-read', '%s', datetime('now'), "
            "          datetime('now', '+10 minutes'));",
            u + 1, u + 1, reset_hash, u + 1, pwless_hash);
        if (db_execute_direct(sdb, sql) != 0 ||
            user_create_invitation_token(sdb, u + 1, 0, 3600, NULL, invites[u]) != 0) {
            log_error("Revocation: could not create the emailed links");
            goto done;
        }
    }

    oauth_session_info_t session;
    char revoked[8];
    long long link_pin;
    unsigned char link_id[16];
    char return_to[64];

    /* 1. Deactivate user 1, then reactivate: none of theirs comes back */
    if (user_set_active(sdb, user_ids[0], 0) != 0 ||
        user_set_active(sdb, user_ids[0], 1) != 0) {
        log_error("Revocation: could not deactivate and reactivate");
        goto done;
    }
    if (oauth_session_get_by_token(sdb, sessions[0], &session) == 0) {
        log_error("Revocation: the session came back with the account");
        goto done;
    }
    if (read_stored_value(sdb, "SELECT is_revoked FROM refresh_token WHERE user_account_pin = 1",
                          revoked, sizeof(revoked)) != 0 || strcmp(revoked, "1") != 0) {
        log_error("Revocation: the refresh token came back with the account");
        goto done;
    }
    if (oauth_access_token_is_active(sdb, access[0]) != 0) {
        log_error("Revocation: the access token came back with the account");
        goto done;
    }
    if (user_consume_password_reset_token(sdb, resets[0], "a-new-password") != 1) {
        log_error("Revocation: the password-reset link came back with the account");
        goto done;
    }
    if (user_consume_passwordless_login_token(sdb, pwless[0], &link_pin, link_id,
                                               return_to, sizeof(return_to)) != 1) {
        log_error("Revocation: the passwordless-login link came back with the account");
        goto done;
    }
    if (user_consume_invitation_token(sdb, invites[0], "a-new-password") != 1) {
        log_error("Revocation: the invitation link came back with the account");
        goto done;
    }
    log_info("  deactivated then reactivated: session, tokens and emailed links stay dead (OK)");

    /* 2. User 2's are untouched */
    if (oauth_session_get_by_token(sdb, sessions[1], &session) != 0 ||
        read_stored_value(sdb, "SELECT is_revoked FROM refresh_token WHERE user_account_pin = 2",
                          revoked, sizeof(revoked)) != 0 || strcmp(revoked, "0") != 0 ||
        oauth_access_token_is_active(sdb, access[1]) != 1) {
        log_error("Revocation: another user's session or tokens were touched");
        goto done;
    }
    if (read_stored_value(sdb,
            "SELECT (SELECT COUNT(*) FROM password_reset_token "
            "        WHERE user_account_pin = 2 AND is_revoked = 0 AND is_used = 0)"
            "     + (SELECT COUNT(*) FROM passwordless_login_token "
            "        WHERE user_account_pin = 2 AND is_used = 0)"
            "     + (SELECT COUNT(*) FROM invitation_token "
            "        WHERE user_account_pin = 2 AND is_used = 0)",
            revoked, sizeof(revoked)) != 0 || strcmp(revoked, "3") != 0) {
        log_error("Revocation: another user's emailed links were touched");
        goto done;
    }
    log_info("  another user's session, tokens and emailed links untouched (OK)");

    /* 3. User 2 flagged inactive the old way, everything still open: deactivating
       again sweeps it, so reactivating brings nothing back */
    if (db_execute_direct(sdb, "UPDATE user_account SET is_active = 0 WHERE pin = 2") != 0 ||
        user_set_active(sdb, user_ids[1], 0) != 0 ||
        user_set_active(sdb, user_ids[1], 1) != 0) {
        log_error("Revocation: could not deactivate an already-inactive account");
        goto done;
    }
    if (oauth_session_get_by_token(sdb, sessions[1], &session) == 0 ||
        read_stored_value(sdb, "SELECT is_revoked FROM refresh_token WHERE user_account_pin = 2",
                          revoked, sizeof(revoked)) != 0 || strcmp(revoked, "1") != 0 ||
        oauth_access_token_is_active(sdb, access[1]) != 0 ||
        user_consume_password_reset_token(sdb, resets[1], "a-new-password") != 1 ||
        user_consume_passwordless_login_token(sdb, pwless[1], &link_pin, link_id,
                                              return_to, sizeof(return_to)) != 1 ||
        user_consume_invitation_token(sdb, invites[1], "a-new-password") != 1) {
        log_error("Revocation: deactivating an already-inactive account left something open");
        goto done;
    }
    log_info("  already inactive: deactivating again sweeps what it still held (OK)");

    /* 4. An unknown id is reported, not waved through */
    const unsigned char unknown_id[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    if (user_set_active(sdb, unknown_id, 0) != 1) {
        log_error("Revocation: an unknown id was not reported");
        goto done;
    }
    log_info("  unknown id reported (OK)");

    failed = 0;

done:
    db_disconnect(sdb);
    if (!failed) {
        log_info("Deactivation revocation tests passed!");
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

/*
 * A malformed 16-byte id must be refused, not copied.
 *
 * SQLite's `id blob not null` constrains nullability, not length. For a short
 * but non-empty blob sqlite3_column_blob returns a live pointer, so a NULL-only
 * guard copies 16 bytes out of a shorter value -- adjacent process memory, into
 * a response. The application never writes such an id; this plants one directly
 * and checks the MFA reads (one of the families fixed together) skip it.
 *
 * Returns 0 on success.
 */
static int test_short_id_blobs(const config_t *config) {
    log_info("\nShort id blob tests");

    db_handle_t *sdb = open_test_db(config);
    if (!sdb) {
        log_error("Short id: could not open a test database");
        return 1;
    }

    int failed = 1;
    mfa_method_t *methods = NULL;

    if (db_execute_direct(sdb,
            "INSERT INTO user_account (id) VALUES (x'50000000000000000000000000000001');"
            "INSERT INTO user_mfa (id, user_account_pin, mfa_method, display_name, secret) VALUES "
            "  (x'60000000000000000000000000000001', 1, 'TOTP', 'good', 's'),"
            "  (x'DEADBEEF', 1, 'TOTP', 'short', 's');") != 0) {
        log_error("Short id: could not insert fixtures");
        goto done;
    }

    int count = -1;
    if (mfa_method_list(sdb, 1, 0, &methods, &count) != 0) {
        log_error("Short id: mfa_method_list failed");
        goto done;
    }
    const unsigned char good_id[16] = {0x60,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
    if (count != 1 || memcmp(methods[0].id, good_id, 16) != 0) {
        log_error("Short id: list returned %d methods; the short-id row must be skipped", count);
        goto done;
    }
    log_info("  list skips a method whose id is 4 bytes (OK)");

    /* The guard must not reject the normal case. (A lookup BY a short id can't
       be driven from here -- get_by_id binds exactly 16 bytes -- so the list is
       the path that reaches the malformed row.) */
    mfa_method_t one;
    if (mfa_method_get_by_id(sdb, good_id, &one) != 0) {
        log_error("Short id: well-formed id no longer resolves");
        goto done;
    }
    log_info("  well-formed id still resolves (OK)");

    failed = 0;

done:
    free(methods);
    db_disconnect(sdb);
    if (!failed) {
        log_info("Short id blob tests passed!");
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

    /* Field encryption and password hashing, set up as main.c does: usernames and
       signing keys are sealed with the one, passwords and API keys hashed with
       the other */
    if (encrypt_init(config->encryption_key) != 0 || crypto_password_init(config) != 0) {
        log_error("Failed to initialize field encryption or password hashing");
        config_free(config);
        return 1;
    }

    if (test_storage_at_rest(config) != 0 ||
        test_credential_lifetimes(config) != 0 ||
        test_schema_constraints(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_signing_key_cache(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_signing_key_encryption(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_mfa_management_gate(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_mfa_reset(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_deactivated_user_tokens(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_deactivation_revokes(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_short_id_blobs(config) != 0) {
        config_free(config);
        return 1;
    }

    if (test_zero_row_writes(config) != 0) {
        config_free(config);
        return 1;
    }

    /* Cleanup */
    config_free(config);

    log_info("=== Database Integration Test Passed! ===");
    return 0;
}
