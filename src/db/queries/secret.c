#include "db/queries/secret.h"
#include "db/db_sql.h"
#include "util/log.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

int secret_rehash(db_handle_t *db, const char *table, long long pin, secret_kind_t kind,
                  const char *secret, const char *verified_hash) {
    if (!db || !table || !secret || !verified_hash) {
        log_error("Invalid arguments to secret_rehash");
        return -1;
    }

    char salt[PASSWORD_SALT_HEX_MAX_LENGTH], hash[PASSWORD_HASH_MAX_LENGTH];
    int iterations = 0;
    int rc = crypto_password_hash(kind, secret, strlen(secret), salt, sizeof(salt),
                                  &iterations, hash, sizeof(hash));
    if (rc != 0) {
        /* -2: the secret is outside the length limits set since it was stored */
        return rc == -2 ? 1 : -1;
    }

    /* The write is the check: it lands only on the hash that verified */
    char sql[256];
    snprintf(sql, sizeof(sql),
             "UPDATE %s SET salt = " P"1, hash_iterations = " P"2, secret_hash = " P"3, "
             "updated_at = " NOW " WHERE pin = " P"4 AND secret_hash = " P"5 RETURNING pin",
             table);
    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        OPENSSL_cleanse(hash, sizeof(hash));
        log_error("Failed to prepare the re-hash of %s pin %lld", table, pin);
        return -1;
    }
    db_bind_text(stmt, 1, salt, -1);
    db_bind_int(stmt, 2, iterations);
    db_bind_text(stmt, 3, hash, -1);
    db_bind_int64(stmt, 4, pin);
    db_bind_text(stmt, 5, verified_hash, -1);
    rc = db_step(stmt);
    db_finalize(stmt);
    OPENSSL_cleanse(hash, sizeof(hash));

    if (rc == DB_ROW) {
        log_info("Re-hashed %s pin %lld with %s", table, pin, crypto_password_method(kind));
        return 0;
    }
    if (rc == DB_DONE) return 1;
    log_error("Failed to re-hash %s pin %lld", table, pin);
    return -1;
}
