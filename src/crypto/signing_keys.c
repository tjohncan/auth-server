/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE  /* for timegm() */

#include "crypto/signing_keys.h"
#include "crypto/random.h"
#include "crypto/encrypt.h"
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
/* Cleanse BIO internal buffer and free (for private key export) */
static void bio_cleanse_free(BIO *bio) {
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr && bptr->data && bptr->length > 0)
        OPENSSL_cleanse(bptr->data, bptr->length);
    BIO_free(bio);
}

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
        if (is_private) bio_cleanse_free(bio); else BIO_free(bio);
        return NULL;
    }

    /* Get PEM data from BIO */
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    if (pem_len <= 0) {
        log_error("Failed to get PEM data from BIO");
        if (is_private) bio_cleanse_free(bio); else BIO_free(bio);
        return NULL;
    }

    /* Copy to null-terminated string */
    char *result = malloc(pem_len + 1);
    if (!result) {
        log_error("Failed to allocate memory for PEM string");
        if (is_private) bio_cleanse_free(bio); else BIO_free(bio);
        return NULL;
    }

    memcpy(result, pem_data, pem_len);
    result[pem_len] = '\0';

    if (is_private) bio_cleanse_free(bio); else BIO_free(bio);
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
        if (*out_private_pem) OPENSSL_cleanse(*out_private_pem, strlen(*out_private_pem));
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
 * Encryption at rest
 * ============================================================================
 *
 * The HMAC secrets and ES256 private keys are stored encrypted with the same
 * AES-256-GCM field encryption as usernames, emails and MFA secrets. Public keys
 * stay plaintext: they are published at /.well-known/jwks.json anyway.
 *
 * Stored form: "e1:" + encrypt_field() output. The prefix cannot occur in either
 * plaintext form (base64url for HMAC secrets, "-----BEGIN" for PEM) or in
 * encrypt_field's own base64url output, so a stored value is unambiguous, and a
 * later format can take "e2:" without guessing.
 *
 * A value that will not open fails every operation that needs the key; nothing is
 * regenerated. The two ways to get there are a row in the older plaintext format
 * and an encryption_key that differs from the one that stored the row. Both are
 * fixed the same way, by an operator deleting the rows, which the log message says.
 *
 * Plaintext is refused rather than read, or sealed in place, so that there is one
 * stored format and no upgrade path to maintain. The refusal is hygiene, not a
 * defence against someone who can write the database: a sealed value is not bound
 * to its column, so any value sealed under the same key opens here.
 */

#define SIGNING_KEY_SEALED_PREFIX     "e1:"
#define SIGNING_KEY_SEALED_PREFIX_LEN 3
#define SIGNING_KEY_SEALED_MAX        512  /* prefix + base64url(12 + 256 + 16) + NUL */

static int seal_key_material(const char *plaintext, char *out, size_t out_size) {
    if (out_size <= SIGNING_KEY_SEALED_PREFIX_LEN) {
        return -1;
    }
    memcpy(out, SIGNING_KEY_SEALED_PREFIX, SIGNING_KEY_SEALED_PREFIX_LEN);
    if (encrypt_field(plaintext, out + SIGNING_KEY_SEALED_PREFIX_LEN,
                      out_size - SIGNING_KEY_SEALED_PREFIX_LEN) != 0) {
        log_error("Failed to encrypt signing key material");
        OPENSSL_cleanse(out, out_size);
        return -1;
    }
    return 0;
}

/* Returns a heap copy of the plaintext (caller cleanses and frees), or NULL. */
static char *open_key_material(const char *stored, const char *table, const char *column) {
    if (strncmp(stored, SIGNING_KEY_SEALED_PREFIX, SIGNING_KEY_SEALED_PREFIX_LEN) != 0) {
        log_error("Signing key %s.%s is stored unencrypted (written by a build before signing "
                  "keys were encrypted). Token issuance, /userinfo and JWKS will fail until it "
                  "is removed: delete the rows in %s and %s; new keys are generated on next use.",
                  table, column, TBL_ACCESS_TOKEN_SIGNING, TBL_AUTH_REQUEST_SIGNING);
        return NULL;
    }

    char plaintext[ENCRYPT_FIELD_MAX_LENGTH + 1];
    if (decrypt_field(stored + SIGNING_KEY_SEALED_PREFIX_LEN, plaintext, sizeof(plaintext)) != 0) {
        log_error("Signing key %s.%s cannot be decrypted: encryption_key is not the one that "
                  "stored it. Token issuance, /userinfo and JWKS will fail until the key is "
                  "restored or the rows in %s and %s are deleted (new keys are generated on "
                  "next use; outstanding access tokens then stop verifying against JWKS).",
                  table, column, TBL_ACCESS_TOKEN_SIGNING, TBL_AUTH_REQUEST_SIGNING);
        OPENSSL_cleanse(plaintext, sizeof(plaintext));
        return NULL;
    }

    char *copy = str_dup(plaintext);
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    if (!copy) {
        log_error("Failed to allocate memory for signing key material");
    }
    return copy;
}

/* ============================================================================
 * Database Operations
 * ============================================================================ */

/*
 * Load key from database
 *
 * Returns 0 with *out_key set, 1 if there is no row, -1 on error -- including a
 * row whose key material will not open. That distinction is load-bearing: the
 * caller treats "no row" as first run and generates a key, and an unreadable
 * row must never be mistaken for that.
 *
 * out_current_ts / out_prior_ts receive the generated_at columns as raw text,
 * caller frees. They come from this statement rather than a separate read so
 * the timestamps and the key material can never describe different generations
 * of the row; see the per-worker cache below for why that matters. Either may
 * be NULL on success: prior_generated_at when the column is NULL, or when a
 * copy could not be allocated.
 */
static int load_key_from_db(db_handle_t *db, signing_key_type_t type,
                            signing_key_t **out_key,
                            char **out_current_ts, char **out_prior_ts) {
    *out_key = NULL;
    *out_current_ts = NULL;
    *out_prior_ts = NULL;

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
        return -1;
    }

    int rc = db_step(stmt);
    if (rc == DB_DONE) {
        db_finalize(stmt);
        return 1;  /* No row: first run */
    }
    if (rc != DB_ROW) {
        db_finalize(stmt);
        log_error("Failed to load signing key");
        return -1;
    }

    /* Allocate key structure */
    signing_key_t *key = calloc(1, sizeof(signing_key_t));
    if (!key) {
        log_error("Failed to allocate memory for signing key");
        db_finalize(stmt);
        return -1;
    }

    key->type = type;

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        /* HMAC keys */
        const char *current = (const char *)db_column_text(stmt, 0);
        const char *prior = (const char *)db_column_text(stmt, 1);
        int has_prior = (prior && db_column_type(stmt, 1) != DB_NULL);

        key->current_secret = current
            ? open_key_material(current, table, "current_secret") : NULL;
        key->prior_secret = has_prior
            ? open_key_material(prior, table, "prior_secret") : NULL;

        if (!key->current_secret || (has_prior && !key->prior_secret)) {
            db_finalize(stmt);
            signing_key_free(key);
            return -1;
        }

        const char *current_ts = (const char *)db_column_text(stmt, 2);
        const char *prior_ts = (const char *)db_column_text(stmt, 3);

        key->current_generated_at = parse_timestamp(current_ts);
        key->prior_generated_at = (prior_ts && db_column_type(stmt, 3) != DB_NULL)
                                   ? parse_timestamp(prior_ts) : 0;

        if (current_ts) *out_current_ts = str_dup(current_ts);
        if (prior_ts && db_column_type(stmt, 3) != DB_NULL) *out_prior_ts = str_dup(prior_ts);
    } else {
        /* ES256 keypairs */
        const char *current_priv = (const char *)db_column_text(stmt, 0);
        const char *current_pub = (const char *)db_column_text(stmt, 1);
        const char *prior_priv = (const char *)db_column_text(stmt, 2);
        const char *prior_pub = (const char *)db_column_text(stmt, 3);

        int has_prior_priv = (prior_priv && db_column_type(stmt, 2) != DB_NULL);

        key->current_private_key = current_priv
            ? open_key_material(current_priv, table, "current_private_key") : NULL;
        key->prior_private_key = has_prior_priv
            ? open_key_material(prior_priv, table, "prior_private_key") : NULL;
        key->current_public_key = current_pub ? str_dup(current_pub) : NULL;
        key->prior_public_key = (prior_pub && db_column_type(stmt, 3) != DB_NULL) ? str_dup(prior_pub) : NULL;

        if (!key->current_private_key || (has_prior_priv && !key->prior_private_key)) {
            db_finalize(stmt);
            signing_key_free(key);
            return -1;
        }
        if (!key->current_public_key) {
            log_error("Failed to load signing key pair (missing or unallocatable public key)");
            db_finalize(stmt);
            signing_key_free(key);
            return -1;
        }

        const char *current_ts = (const char *)db_column_text(stmt, 4);
        const char *prior_ts = (const char *)db_column_text(stmt, 5);

        key->current_generated_at = parse_timestamp(current_ts);
        key->prior_generated_at = (prior_ts && db_column_type(stmt, 5) != DB_NULL)
                                   ? parse_timestamp(prior_ts) : 0;

        if (current_ts) *out_current_ts = str_dup(current_ts);
        if (prior_ts && db_column_type(stmt, 5) != DB_NULL) *out_prior_ts = str_dup(prior_ts);
    }

    db_finalize(stmt);
    *out_key = key;
    return 0;
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

    char sealed[SIGNING_KEY_SEALED_MAX];
    if (seal_key_material(secret_or_priv, sealed, sizeof(sealed)) != 0) {
        return -1;
    }

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s (singleton, current_secret, current_generated_at) "
                 "VALUES (" BOOL_TRUE ", " P"1, " NOW ")", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare insert HMAC key statement");
            OPENSSL_cleanse(sealed, sizeof(sealed));
            return -1;
        }

        db_bind_text(stmt, 1, sealed, -1);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s (singleton, current_private_key, current_public_key, "
                 "current_generated_at) VALUES (" BOOL_TRUE ", " P"1, " P"2, " NOW ")", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare insert ES256 key statement");
            OPENSSL_cleanse(sealed, sizeof(sealed));
            return -1;
        }

        db_bind_text(stmt, 1, sealed, -1);
        db_bind_text(stmt, 2, public_key, -1);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);
    OPENSSL_cleanse(sealed, sizeof(sealed));

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
 *
 * The prior columns are copied from the current ones inside the UPDATE, so the
 * stored (encrypted) value moves as-is and is never re-bound from memory.
 *
 * Optimistic concurrency is keyed on current_generated_at, compared as the raw
 * text load_key_from_db read: if another worker already rotated, that column has
 * moved on, zero rows match, and this harmlessly no-ops. The key value itself
 * cannot serve as the check for an encrypted column -- AES-GCM with a random IV
 * never reproduces the stored ciphertext. The timestamp is the same invariant the
 * per-worker cache relies on (it strictly increases across every write this file
 * performs).
 */
static int rotate_key(db_handle_t *db, signing_key_type_t type,
                      const char *new_secret_or_priv, const char *new_public_key,
                      const char *old_generated_at) {
    const char *table = (type == SIGNING_KEY_AUTH_REQUEST)
                        ? TBL_AUTH_REQUEST_SIGNING
                        : TBL_ACCESS_TOKEN_SIGNING;

    if (!old_generated_at) {
        log_error("Cannot rotate signing key without its current generated_at");
        return -1;
    }

    char sealed[SIGNING_KEY_SEALED_MAX];
    if (seal_key_material(new_secret_or_priv, sealed, sizeof(sealed)) != 0) {
        return -1;
    }

    char sql[1024];
    db_stmt_t *stmt = NULL;

    if (type == SIGNING_KEY_AUTH_REQUEST) {
        snprintf(sql, sizeof(sql),
                 "UPDATE %s SET "
                 "prior_secret = current_secret, "
                 "prior_generated_at = current_generated_at, "
                 "current_secret = " P"1, "
                 "current_generated_at = " NOW " "
                 "WHERE singleton = " BOOL_TRUE " "
                 "AND current_generated_at = " P"2 "
                 "RETURNING singleton", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare rotate HMAC key statement");
            OPENSSL_cleanse(sealed, sizeof(sealed));
            return -1;
        }

        db_bind_text(stmt, 1, sealed, -1);
        db_bind_text(stmt, 2, old_generated_at, -1);
    } else {
        snprintf(sql, sizeof(sql),
                 "UPDATE %s SET "
                 "prior_private_key = current_private_key, "
                 "prior_public_key = current_public_key, "
                 "prior_generated_at = current_generated_at, "
                 "current_private_key = " P"1, "
                 "current_public_key = " P"2, "
                 "current_generated_at = " NOW " "
                 "WHERE singleton = " BOOL_TRUE " "
                 "AND current_generated_at = " P"3 "
                 "RETURNING singleton", table);

        if (db_prepare(db, &stmt, sql) != 0) {
            log_error("Failed to prepare rotate ES256 key statement");
            OPENSSL_cleanse(sealed, sizeof(sealed));
            return -1;
        }

        db_bind_text(stmt, 1, sealed, -1);
        db_bind_text(stmt, 2, new_public_key, -1);
        db_bind_text(stmt, 3, old_generated_at, -1);
    }

    int rc = db_step(stmt);
    db_finalize(stmt);
    OPENSSL_cleanse(sealed, sizeof(sealed));

    if (rc == DB_ROW) {
        log_info("Rotated %s signing key",
                 type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing");
    } else if (rc != DB_DONE) {
        log_error("Failed to rotate signing key");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Per-worker key cache
 * ============================================================================
 *
 * signing_key_get_or_rotate() might rotate, and rotation needs BEGIN IMMEDIATE,
 * the database-wide write lock on SQLite. It almost never does rotate: once per
 * 24 hours for auth-request keys, once per 60 days for access-token keys. Taking
 * that lock on every call would declare write intent in order to run a SELECT,
 * which is the one thing WAL mode exists to make unnecessary. So the lock is
 * taken only on a cache miss.
 *
 * The cache below is validated against the database on every single use rather
 * than trusted for an interval. It holds the generated_at columns as raw text;
 * a bare SELECT of those same two columns either matches, in which case the
 * cached material is still the row, or it does not, in which case we take the
 * write lock and reload.
 *
 * The invariant that makes the pair sufficient is that current_generated_at
 * strictly increases across every write this code performs, and every one of
 * those writes rewrites prior_generated_at as well — rotate_key sets both in
 * either branch, insert_new_key starts them. So a rotation, a deletion or a
 * regeneration is picked up on the very next request. What the pair cannot see
 * is a hand-edit that swaps key material while leaving current_generated_at
 * inside the same one-second tick, datetime('now') being second-granular.
 * Against a TTL that is still no contest: a TTL is wrong for its entire
 * interval on every one of these, including the ones caught here immediately.
 *
 * Raw text and not the parsed time_t, which is not a stylistic preference:
 * parse_timestamp() returns 0 for anything it cannot read, so two different
 * malformed values would compare equal, and its "%d-%d-%d %d:%d:%d" discards
 * everything after the seconds field, so on PostgreSQL — where NOW() carries
 * sub-second precision — two writes inside the same second would compare equal.
 * Both are cache hits across a change that really happened, which is the only
 * direction that matters when the cached object is a signing key.
 */

typedef struct {
    signing_key_t *key;          /* the materialised row, owned here */
    char *current_generated_at;  /* raw column text, never parsed */
    char *prior_generated_at;    /* NULL when the column is NULL */
    int has_prior;               /* distinguishes a NULL column from empty text */
} signing_key_cache_t;

static _Thread_local signing_key_cache_t g_key_cache[2];  /* indexed by signing_key_type_t */

/*
 * Deep copy of a key structure.
 *
 * Callers own what signing_key_get_or_rotate() hands them and release it with
 * signing_key_free(), and the cache keeps the original, so the cache returns a
 * copy rather than changing that contract. Rewriting ownership semantics at
 * seven call sites on a branch that also changes token issuance is how a double
 * free ships; a calloc and a few str_dups is nothing against the write-lock
 * round trip being removed.
 */
static signing_key_t *clone_signing_key(const signing_key_t *src) {
    if (!src) {
        return NULL;
    }

    signing_key_t *copy = calloc(1, sizeof(signing_key_t));
    if (!copy) {
        return NULL;
    }

    copy->type = src->type;
    copy->current_generated_at = src->current_generated_at;
    copy->prior_generated_at = src->prior_generated_at;

    /* A failed str_dup leaves the copy partly populated; signing_key_free is
       per-field NULL-safe, so hand it the whole thing. */
    if ((src->current_secret      && !(copy->current_secret      = str_dup(src->current_secret)))      ||
        (src->prior_secret        && !(copy->prior_secret        = str_dup(src->prior_secret)))        ||
        (src->current_private_key && !(copy->current_private_key = str_dup(src->current_private_key))) ||
        (src->current_public_key  && !(copy->current_public_key  = str_dup(src->current_public_key)))  ||
        (src->prior_private_key   && !(copy->prior_private_key   = str_dup(src->prior_private_key)))   ||
        (src->prior_public_key    && !(copy->prior_public_key    = str_dup(src->prior_public_key)))) {
        log_error("Failed to allocate memory for signing key copy");
        signing_key_free(copy);
        return NULL;
    }

    return copy;
}

/*
 * Empty a cache entry, cleansing key material on the way out.
 */
static void cache_invalidate(signing_key_cache_t *entry) {
    signing_key_free(entry->key);
    free(entry->current_generated_at);
    free(entry->prior_generated_at);
    entry->key = NULL;
    entry->current_generated_at = NULL;
    entry->prior_generated_at = NULL;
    entry->has_prior = 0;
}

/*
 * Does the cached entry still describe the row in the database?
 *
 * A bare SELECT with no BEGIN: in WAL mode that takes a shared read lock, blocks
 * nothing, and is never blocked by a writer. It selects the same two columns raw,
 * exactly as load_key_from_db does. Rendering them differently here — through
 * UNIX_TS(), say — would compare epoch text against "YYYY-MM-DD HH:MM:SS", the
 * cache would never once hit, and the symptom would be that the change appeared
 * to do nothing rather than anything resembling a bug.
 *
 * Anything that is not a matching row is a miss, deliberately including no row
 * at all: a deleted row has to route to the reload path rather than fall through
 * on the strength of a copy of something that is gone.
 */
static int cache_matches_db(db_handle_t *db, signing_key_type_t type,
                            const signing_key_cache_t *entry) {
    const char *table = (type == SIGNING_KEY_AUTH_REQUEST)
                        ? TBL_AUTH_REQUEST_SIGNING
                        : TBL_ACCESS_TOKEN_SIGNING;

    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT current_generated_at, prior_generated_at "
             "FROM %s WHERE singleton = " BOOL_TRUE, table);

    db_stmt_t *stmt = NULL;
    if (db_prepare(db, &stmt, sql) != 0) {
        return 0;
    }

    if (db_step(stmt) != DB_ROW) {
        db_finalize(stmt);
        return 0;
    }

    /* Compared in place: the column pointers stay valid until finalize on both
       backends, so this neither copies nor risks truncating a long timestamp
       into a false match. */
    const char *current_ts = (const char *)db_column_text(stmt, 0);
    const char *prior_ts = (const char *)db_column_text(stmt, 1);
    int has_prior = (prior_ts && db_column_type(stmt, 1) != DB_NULL);

    int matches = current_ts
                  && strcmp(current_ts, entry->current_generated_at) == 0
                  && has_prior == entry->has_prior
                  && (!has_prior || strcmp(prior_ts, entry->prior_generated_at) == 0);

    db_finalize(stmt);
    return matches;
}

/*
 * Take ownership of a freshly loaded row and hand the caller its own copy.
 *
 * Cannot fail: if the copy or the timestamps are unavailable the entry is left
 * empty and the caller receives the original, which is precisely the uncached
 * behaviour this replaces.
 */
static void cache_store_and_return(signing_key_type_t type, signing_key_t *key,
                                   char *current_ts, char *prior_ts,
                                   signing_key_t **out_key) {
    signing_key_cache_t *entry = &g_key_cache[type];
    cache_invalidate(entry);

    signing_key_t *copy = current_ts ? clone_signing_key(key) : NULL;
    if (!copy) {
        free(current_ts);
        free(prior_ts);
        *out_key = key;
        return;
    }

    entry->key = key;
    entry->current_generated_at = current_ts;
    entry->prior_generated_at = prior_ts;
    entry->has_prior = (prior_ts != NULL);

    *out_key = copy;
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

    /*
     * Validate the cached row against the database before using it.
     * current_generated_at is read fresh on every call, so the rotation check
     * below fires exactly as promptly as it did when this function took the
     * write lock unconditionally.
     */
    signing_key_cache_t *entry = &g_key_cache[type];
    if (entry->key && cache_matches_db(db, type, entry)
        && time(NULL) - entry->key->current_generated_at < rotation_interval) {
        signing_key_t *copy = clone_signing_key(entry->key);
        if (copy) {
            *out_key = copy;
            return 0;
        }
        /* Could not copy: fall through and reload the slow way. */
    }

    /* Start transaction (prevents concurrent rotation) */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Failed to begin transaction for key rotation");
        return -1;
    }

    /* Load existing key. An unreadable row is an error, never "first run":
       generating over it would silently replace the deployment's key. */
    char *current_ts = NULL;
    char *prior_ts = NULL;
    signing_key_t *key = NULL;
    int load_rc = load_key_from_db(db, type, &key, &current_ts, &prior_ts);

    if (load_rc < 0) {
        db_execute_trusted(db, "ROLLBACK");
        return -1;
    }

    if (load_rc == 1) {
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
            OPENSSL_cleanse(secret_or_priv, strlen(secret_or_priv));
            free(secret_or_priv);
            free(public_key);
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        /* Commit and reload */
        if (db_execute_trusted(db, "COMMIT") != 0) {
            log_error("Failed to commit new key transaction");
            OPENSSL_cleanse(secret_or_priv, strlen(secret_or_priv));
            free(secret_or_priv);
            free(public_key);
            return -1;
        }

        OPENSSL_cleanse(secret_or_priv, strlen(secret_or_priv));
        free(secret_or_priv);
        free(public_key);

        /* Reload from DB to get timestamp */
        if (load_key_from_db(db, type, &key, &current_ts, &prior_ts) != 0) {
            log_error("Failed to reload newly inserted key");
            return -1;
        }

        cache_store_and_return(type, key, current_ts, prior_ts, out_key);
        return 0;
    }

    /* Check if rotation needed */
    time_t now = time(NULL);
    time_t age = now - key->current_generated_at;

    if (age >= rotation_interval) {
        /* The row is about to be replaced. current_ts is kept only as rotate_key's
           concurrency check and released below; prior_ts is dead already. */
        free(prior_ts);
        prior_ts = NULL;

        /* Rotation needed */
        log_info("Rotating %s key (age: %ld seconds, threshold: %ld seconds)",
                 type == SIGNING_KEY_AUTH_REQUEST ? "auth_request_signing" : "access_token_signing",
                 (long)age, (long)rotation_interval);

        char *new_secret_or_priv = NULL;
        char *new_public_key = NULL;

        if (type == SIGNING_KEY_AUTH_REQUEST) {
            new_secret_or_priv = generate_hmac_secret();
        } else if (generate_es256_keypair(&new_secret_or_priv, &new_public_key) != 0) {
            new_secret_or_priv = NULL;
        }

        if (!new_secret_or_priv ||
            rotate_key(db, type, new_secret_or_priv, new_public_key, current_ts) != 0) {
            if (new_secret_or_priv) {
                OPENSSL_cleanse(new_secret_or_priv, strlen(new_secret_or_priv));
            }
            free(new_secret_or_priv);
            free(new_public_key);
            free(current_ts);
            signing_key_free(key);
            db_execute_trusted(db, "ROLLBACK");
            return -1;
        }

        free(current_ts);
        current_ts = NULL;

        /* Commit and reload */
        if (db_execute_trusted(db, "COMMIT") != 0) {
            log_error("Failed to commit key rotation");
            OPENSSL_cleanse(new_secret_or_priv, strlen(new_secret_or_priv));
            free(new_secret_or_priv);
            free(new_public_key);
            signing_key_free(key);
            return -1;
        }

        OPENSSL_cleanse(new_secret_or_priv, strlen(new_secret_or_priv));
        free(new_secret_or_priv);
        free(new_public_key);

        signing_key_free(key);
        key = NULL;
        if (load_key_from_db(db, type, &key, &current_ts, &prior_ts) != 0) {
            log_error("Failed to reload rotated key");
            return -1;
        }

        cache_store_and_return(type, key, current_ts, prior_ts, out_key);
        return 0;
    }

    /* Key is fresh, just commit and return */
    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Failed to commit key load transaction");
        signing_key_free(key);
        free(current_ts);
        free(prior_ts);
        return -1;
    }

    cache_store_and_return(type, key, current_ts, prior_ts, out_key);
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

int signing_key_format_kid(time_t generated_at, char *out_kid, size_t kid_len) {
    if (!out_kid || kid_len == 0) {
        return -1;
    }

    int n = snprintf(out_kid, kid_len, "%lld", (long long)generated_at);
    if (n < 0 || (size_t)n >= kid_len) {
        log_error("Key ID buffer too small");
        return -1;
    }

    return 0;
}

int signing_key_active_kid(const signing_key_t *key, const char *active_private,
                           char *out_kid, size_t kid_len) {
    if (!key || key->type != SIGNING_KEY_ACCESS_TOKEN || !active_private) {
        return -1;
    }

    /*
     * Matched by pointer against the key set rather than by re-running the
     * activation-delay condition. Two evaluations of that condition would agree
     * everywhere except the instant it elapses, and naming the wrong key is
     * worse than naming none: a verifier would confidently select a key that did
     * not sign, where with no kid it would at least have to try both. This also
     * picks up the first-run case for free, since active_private is then the
     * current key and prior_private_key is NULL.
     */
    if (active_private == key->prior_private_key) {
        return signing_key_format_kid(key->prior_generated_at, out_kid, kid_len);
    }
    if (active_private == key->current_private_key) {
        return signing_key_format_kid(key->current_generated_at, out_kid, kid_len);
    }

    log_error("Signing key does not belong to this key set");
    return -1;
}

void signing_key_thread_cleanup(void) {
    for (int i = 0; i < 2; i++) {
        cache_invalidate(&g_key_cache[i]);
    }
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
