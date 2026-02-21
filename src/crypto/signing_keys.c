/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE  /* for timegm() */

#include "crypto/signing_keys.h"
#include "crypto/random.h"
#include "db/db.h"
#include "db/db_sql.h"
#include "util/log.h"
#include "util/str.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/*
 * Parse timestamp from SQLite/PostgreSQL datetime string
 * SQLite: "2026-01-21 15:30:00"
 * PostgreSQL: "2026-01-21 15:30:00" or with timezone
 */
static time_t parse_timestamp(const char *timestamp_str) {
    if (!timestamp_str) {
        return 0;
    }

    struct tm tm = {0};
    /* Parse ISO 8601 format: YYYY-MM-DD HH:MM:SS */
    if (sscanf(timestamp_str, "%d-%d-%d %d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        log_error("Failed to parse timestamp: %s", timestamp_str);
        return 0;
    }

    tm.tm_year -= 1900;  /* years since 1900 */
    tm.tm_mon -= 1;      /* months since January [0-11] */
    tm.tm_isdst = 0;     /* UTC has no DST */

    return timegm(&tm);  /* UTC — mktime would misinterpret as local time */
}

/*
 * Generate HMAC secret (32 random bytes, base64url-encoded)
 */
static char *generate_hmac_secret(void) {
    unsigned char random_bytes[32];
    if (crypto_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        log_error("Failed to generate random bytes for HMAC secret");
        return NULL;
    }

    char *secret = malloc(64);  /* 32 bytes -> ~44 chars + null */
    if (!secret) {
        log_error("Failed to allocate memory for HMAC secret");
        return NULL;
    }

    size_t encoded_len = crypto_base64url_encode(random_bytes, sizeof(random_bytes),
                                                  secret, 64);
    if (encoded_len == 0) {
        log_error("Failed to encode HMAC secret");
        free(secret);
        return NULL;
    }

    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));

    return secret;
}

/*
 * Export EVP_PKEY to PEM string (private or public)
 */
static char *export_key_to_pem(EVP_PKEY *pkey, int is_private) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        log_error("Failed to create BIO for PEM export");
        return NULL;
    }

    int success;
    if (is_private) {
        success = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    } else {
        success = PEM_write_bio_PUBKEY(bio, pkey);
    }

    if (!success) {
        log_error("Failed to write key to PEM format");
        BIO_free(bio);
        return NULL;
    }

    /* Get PEM data from BIO */
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    if (pem_len <= 0) {
        log_error("Failed to get PEM data from BIO");
        BIO_free(bio);
        return NULL;
    }

    /* Copy to null-terminated string */
    char *result = malloc(pem_len + 1);
    if (!result) {
        log_error("Failed to allocate memory for PEM string");
        BIO_free(bio);
        return NULL;
    }

    memcpy(result, pem_data, pem_len);
    result[pem_len] = '\0';

    BIO_free(bio);
    return result;
}

/*
 * Generate ES256 keypair (ECDSA P-256)
 * Returns keypair via out_private_pem and out_public_pem
 */
static int generate_es256_keypair(char **out_private_pem, char **out_public_pem) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int result = -1;

    /* Create context for key generation */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        log_error("Failed to create EVP_PKEY_CTX");
        goto cleanup;
    }

    /* Initialize keygen */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        log_error("Failed to initialize keygen");
        goto cleanup;
    }

    /* Set curve to P-256 (prime256v1 / secp256r1) */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        log_error("Failed to set EC curve to P-256");
        goto cleanup;
    }

    /* Generate keypair */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        log_error("Failed to generate EC keypair");
        goto cleanup;
    }

    /* Export to PEM format */
    *out_private_pem = export_key_to_pem(pkey, 1);
    *out_public_pem = export_key_to_pem(pkey, 0);

    if (!*out_private_pem || !*out_public_pem) {
        log_error("Failed to export keypair to PEM");
        free(*out_private_pem);
        free(*out_public_pem);
        *out_private_pem = NULL;
        *out_public_pem = NULL;
        goto cleanup;
    }

    result = 0;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

/* ============================================================================
 * Database Operations
 * ============================================================================ */

/*
 * Load key from database (returns NULL if not found, caller frees result)
 */
static signing_key_t *load_key_from_db(db_handle_t *db, signing_key_type_t type) {
    const char *table = (type == SIGNING_KEY_AUTH_REQUEST)
                        ? TBL_AUTH_REQUEST_SIGNING
                        : TBL_ACCESS_TOKEN_SIGNING;

    char sql[512];
    if (type == SIGNING_KEY_AUTH_REQUEST) {
        snprintf(sql, sizeof(sql),
                 "SELECT current_secret, prior_secret, current_generated_at, prior_generated_at "
                 "FROM %s WHERE singleton = " BOOL_TRUE, table);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT current_private_key, current_public_key, prior_private_key, "
                 "prior_public_key, current_generated_at, prior_generated_at "
                 "FROM %s WHERE singleton = " BOOL_TRUE, table);
    }

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        log_error("Failed to prepare load key statement");
        return NULL;
    }

    int rc = db_step(stmt);
    if (rc != DB_ROW) {
        db_finalize(stmt);
        return NULL;  /* Not found (not an error) */
    }

    /* Allocate key structure */
    signing_key_t *key = calloc(1, sizeof(signing_key_t));
    if (!key) {
        log_error("Failed to allocate memory for signing key");
        db_finalize(stmt);
        return NULL;
    }

    key->type = type;

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        /* HMAC keys */
        const char *current = (const char *)db_column_text(stmt, 0);
        const char *prior = (const char *)db_column_text(stmt, 1);

        key->current_secret = current ? str_dup(current) : NULL;
        key->prior_secret = (prior && db_column_type(stmt, 1) != DB_NULL) ? str_dup(prior) : NULL;

        const char *current_ts = (const char *)db_column_text(stmt, 2);
        const char *prior_ts = (const char *)db_column_text(stmt, 3);

        key->current_generated_at = parse_timestamp(current_ts);
        key->prior_generated_at = (prior_ts && db_column_type(stmt, 3) != DB_NULL)
                                   ? parse_timestamp(prior_ts) : 0;
    } else {
        /* ES256 keypairs */
        const char *current_priv = (const char *)db_column_text(stmt, 0);
        const char *current_pub = (const char *)db_column_text(stmt, 1);
        const char *prior_priv = (const char *)db_column_text(stmt, 2);
        const char *prior_pub = (const char *)db_column_text(stmt, 3);

        key->current_private_key = current_priv ? str_dup(current_priv) : NULL;
        key->current_public_key = current_pub ? str_dup(current_pub) : NULL;
        key->prior_private_key = (prior_priv && db_column_type(stmt, 2) != DB_NULL) ? str_dup(prior_priv) : NULL;
        key->prior_public_key = (prior_pub && db_column_type(stmt, 3) != DB_NULL) ? str_dup(prior_pub) : NULL;

        const char *current_ts = (const char *)db_column_text(stmt, 4);
        const char *prior_ts = (const char *)db_column_text(stmt, 5);

        key->current_generated_at = parse_timestamp(current_ts);
        key->prior_generated_at = (prior_ts && db_column_type(stmt, 5) != DB_NULL)
                                   ? parse_timestamp(prior_ts) : 0;
    }

    db_finalize(stmt);
    return key;
}

/*
 * Insert new key into database (first run)
 */
static int insert_new_key(db_handle_t *db, signing_key_type_t type,
                          const char *secret_or_priv, const char *public_key) {
    const char *table = (type == SIGNING_KEY_AUTH_REQUEST)
                        ? TBL_AUTH_REQUEST_SIGNING
                        : TBL_ACCESS_TOKEN_SIGNING;

    char sql[1024];
    db_stmt_t *stmt = NULL;

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s (singleton, current_secret, current_generated_at) "
                 "VALUES (" BOOL_TRUE ", " P"1, " NOW ")", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare insert HMAC key statement");
            return -1;
        }

        db_bind_text(stmt, 1, secret_or_priv, -1);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s (singleton, current_private_key, current_public_key, "
                 "current_generated_at) VALUES (" BOOL_TRUE ", " P"1, " P"2, " NOW ")", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare insert ES256 key statement");
            return -1;
        }

        db_bind_text(stmt, 1, secret_or_priv, -1);
        db_bind_text(stmt, 2, public_key, -1);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to insert new signing key");
        return -1;
    }

    log_info("Generated new %s signing key",
             type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing");
    return 0;
}

/*
 * Rotate key (move current -> prior, insert new -> current)
 */
static int rotate_key(db_handle_t *db, signing_key_type_t type,
                      const char *new_secret_or_priv, const char *new_public_key,
                      const char *old_secret_or_priv, const char *old_public_key) {
    const char *table = (type == SIGNING_KEY_AUTH_REQUEST)
                        ? TBL_AUTH_REQUEST_SIGNING
                        : TBL_ACCESS_TOKEN_SIGNING;

    char sql[1024];
    db_stmt_t *stmt = NULL;

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        snprintf(sql, sizeof(sql),
                 "UPDATE %s SET "
                 "prior_secret = " P"1, "
                 "prior_generated_at = current_generated_at, "
                 "current_secret = " P"2, "
                 "current_generated_at = " NOW " "
                 "WHERE singleton = " BOOL_TRUE, table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare rotate HMAC key statement");
            return -1;
        }

        db_bind_text(stmt, 1, old_secret_or_priv, -1);
        db_bind_text(stmt, 2, new_secret_or_priv, -1);
    } else {
        snprintf(sql, sizeof(sql),
                 "UPDATE %s SET "
                 "prior_private_key = " P"1, "
                 "prior_public_key = " P"2, "
                 "prior_generated_at = current_generated_at, "
                 "current_private_key = " P"3, "
                 "current_public_key = " P"4, "
                 "current_generated_at = " NOW " "
                 "WHERE singleton = " BOOL_TRUE, table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare rotate ES256 key statement");
            return -1;
        }

        db_bind_text(stmt, 1, old_secret_or_priv, -1);
        db_bind_text(stmt, 2, old_public_key, -1);
        db_bind_text(stmt, 3, new_secret_or_priv, -1);
        db_bind_text(stmt, 4, new_public_key, -1);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);

    if (rc != DB_DONE) {
        log_error("Failed to rotate signing key");
        return -1;
    }

    log_info("Rotated %s signing key",
             type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing");
    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int signing_key_get_or_rotate(db_handle_t *db, signing_key_type_t type,
                                signing_key_t **out_key) {
    if (!db || !out_key) {
        log_error("Invalid arguments to signing_key_get_or_rotate");
        return -1;
    }

    *out_key = NULL;

    /* Determine rotation interval */
    time_t rotation_interval = (type == SIGNING_KEY_AUTH_REQUEST)
                               ? AUTH_REQUEST_ROTATION_SECONDS
                               : ACCESS_TOKEN_ROTATION_SECONDS;

    /* Start transaction (prevents concurrent rotation) */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction for key rotation");
        return -1;
    }

    /* Load existing key */
    signing_key_t *key = load_key_from_db(db, type);

    if (!key) {
        /* First run: no key exists, generate and insert */
        log_info("No %s key found, generating initial key",
                 type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing");

        char *secret_or_priv = NULL;
        char *public_key = NULL;

        if (type == SIGNING_KEY_AUTH_REQUEST) {
            secret_or_priv = generate_hmac_secret();
            if (!secret_or_priv) {
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }
        } else {
            if (generate_es256_keypair(&secret_or_priv, &public_key) != 0) {
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }
        }

        if (insert_new_key(db, type, secret_or_priv, public_key) != 0) {
            free(secret_or_priv);
            free(public_key);
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        /* Commit and reload */
        if (db_execute_trusted(db, "COMMIT") != 0) {
            log_error("Failed to commit new key transaction");
            free(secret_or_priv);
            free(public_key);
            return -1;
        }

        free(secret_or_priv);
        free(public_key);

        /* Reload from DB to get timestamp */
        key = load_key_from_db(db, type);
        if (!key) {
            log_error("Failed to reload newly inserted key");
            return -1;
        }

        *out_key = key;
        return 0;
    }

    /* Check if rotation needed */
    time_t now = time(NULL);
    time_t age = now - key->current_generated_at;

    if (age >= rotation_interval) {
        /* Rotation needed */
        log_info("Rotating %s key (age: %ld seconds, threshold: %ld seconds)",
                 type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing",
                 (long)age, (long)rotation_interval);

        char *new_secret_or_priv = NULL;
        char *new_public_key = NULL;

        if (type == SIGNING_KEY_AUTH_REQUEST) {
            new_secret_or_priv = generate_hmac_secret();
            if (!new_secret_or_priv) {
                signing_key_free(key);
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }

            if (rotate_key(db, type, new_secret_or_priv, NULL,
                          key->current_secret, NULL) != 0) {
                free(new_secret_or_priv);
                signing_key_free(key);
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }
        } else {
            if (generate_es256_keypair(&new_secret_or_priv, &new_public_key) != 0) {
                signing_key_free(key);
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }

            if (rotate_key(db, type, new_secret_or_priv, new_public_key,
                          key->current_private_key, key->current_public_key) != 0) {
                free(new_secret_or_priv);
                free(new_public_key);
                signing_key_free(key);
                db_execute_trusted(db, "ROLLBACK");
                return -1;
            }
        }

        /* Commit rotation */
        if (db_execute_trusted(db, "COMMIT") != 0) {
            log_error("Failed to commit key rotation");
            free(new_secret_or_priv);
            free(new_public_key);
            signing_key_free(key);
            return -1;
        }

        free(new_secret_or_priv);
        free(new_public_key);

        /* Reload rotated key */
        signing_key_free(key);
        key = load_key_from_db(db, type);
        if (!key) {
            log_error("Failed to reload rotated key");
            return -1;
        }

        *out_key = key;
        return 0;
    }

    /* Key is fresh, just commit and return */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit key load transaction");
        signing_key_free(key);
        return -1;
    }

    *out_key = key;
    return 0;
}

const char *signing_key_active_private(const signing_key_t *key) {
    if (!key || key->type != SIGNING_KEY_ACCESS_TOKEN) {
        return NULL;
    }

    /* First run: no prior key, must use current */
    if (!key->prior_private_key) {
        return key->current_private_key;
    }

    /* Use prior key until activation delay has elapsed after rotation */
    time_t now = time(NULL);
    if (now < key->current_generated_at + JWKS_ACTIVATION_DELAY_SECONDS) {
        log_debug("Signing with prior key (activation delay: %ld seconds remaining)",
                  (long)(key->current_generated_at + JWKS_ACTIVATION_DELAY_SECONDS - now));
        return key->prior_private_key;
    }

    return key->current_private_key;
}

void signing_key_free(signing_key_t *key) {
    if (!key) {
        return;
    }

    /* Cleanse sensitive data before freeing (OPENSSL_cleanse resists compiler elimination) */
    if (key->current_secret) {
        OPENSSL_cleanse(key->current_secret, strlen(key->current_secret));
        free(key->current_secret);
    }
    if (key->prior_secret) {
        OPENSSL_cleanse(key->prior_secret, strlen(key->prior_secret));
        free(key->prior_secret);
    }
    if (key->current_private_key) {
        OPENSSL_cleanse(key->current_private_key, strlen(key->current_private_key));
        free(key->current_private_key);
    }
    if (key->current_public_key) {
        free(key->current_public_key);
    }
    if (key->prior_private_key) {
        OPENSSL_cleanse(key->prior_private_key, strlen(key->prior_private_key));
        free(key->prior_private_key);
    }
    if (key->prior_public_key) {
        free(key->prior_public_key);
    }

    free(key);
}
