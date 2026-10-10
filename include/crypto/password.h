#ifndef CRYPTO_PASSWORD_H
#define CRYPTO_PASSWORD_H

#include "util/config.h"
#include <stddef.h>

/*
 * High-Level Password Hashing API
 *
 * Module-level wrapper that delegates to Argon2id or PBKDF2-SHA256.
 *
 * Usage:
 *   1. Call crypto_password_init(config) once at startup
 *   2. Call crypto_password_hash() / crypto_password_verify() from any thread
 *
 * Two kinds of secret, each with its own configured method and iteration range:
 *   - a person's: passwords (secret_hashing_algorithm,
 *     secret_hash_min/max_iterations)
 *   - a machine's: the secrets of client, resource-server and organization
 *     keys, generated or supplied, and recovery codes
 *     (machine_secret_hashing_algorithm and its range; unset, the person's)
 * Every secret of a kind is hashed with that kind's method: a method chosen per
 * secret would tell by time which secret was supplied.
 *
 * A stored hash names the method that made it, "<method>$<hex>": argon2id$...
 * or pbkdf2-sha256$.... Salt and iterations keep columns of their own:
 *   - salt (text)
 *   - hash_iterations (integer)
 *   - secret_hash (text)
 * A hash without a label fails verification, with an error saying so.
 */

typedef enum {
    SECRET_USER,
    SECRET_MACHINE
} secret_kind_t;

/* Buffer sizes: a salt in hex, and a stored hash with its label */
#define PASSWORD_SALT_HEX_MAX_LENGTH  65
#define PASSWORD_HASH_MAX_LENGTH      96

/* Maximum password/secret length (bytes) — rejects before hashing */
#define PASSWORD_MAX_LENGTH  1024

/*
 * Initialize password hashing module
 *
 * Stores each kind's method and iteration range from config. Must be called
 * once at startup before any hash/verify operations. Thread-safe after
 * initialization (settings are read-only).
 *
 * Returns: 0 on success, negative on error
 */
int crypto_password_init(const config_t *config);

/*
 * Hash a secret for storage, with its kind's method
 *
 * Generates a random salt, and an iteration count drawn from the kind's range.
 * out_hash gets the stored form, labeled with the method.
 *
 * Returns: 0 on success, -1 on error, -2 if the secret is longer than
 *          PASSWORD_MAX_LENGTH or shorter than password_min_length
 *
 * Example:
 *   char salt[PASSWORD_SALT_HEX_MAX_LENGTH];
 *   int iterations;
 *   char hash[PASSWORD_HASH_MAX_LENGTH];
 *
 *   crypto_password_hash(SECRET_USER, "password", 8, salt, sizeof(salt),
 *                        &iterations, hash, sizeof(hash));
 *
 *   // INSERT INTO user_account (salt, hash_iterations, secret_hash)
 *   // VALUES (?, ?, ?)
 */
int crypto_password_hash(secret_kind_t kind, const char *password, size_t password_len,
                         char *out_salt_hex, size_t salt_hex_len,
                         int *out_iterations,
                         char *out_hash, size_t hash_len);

/* Returns the configured minimum password length */
int crypto_password_min_length(void);

/*
 * Hash a secret with a given method, salt and iteration count (low-level)
 *
 * For recovery codes, which share one salt and iteration count per set, and
 * one method: a code is found by hashing what was submitted as its set's codes
 * were hashed, and comparing. out_hash gets the stored form, labeled.
 *
 * Returns: 0 on success, negative on error (an unknown method among them)
 */
int crypto_password_hash_with_salt(const char *method, const char *password,
                                   size_t password_len, const char *salt_hex,
                                   int iterations, char *out_hash, size_t hash_len);

/*
 * Verify a secret against its stored hash, with the method the hash names
 *
 * Uses timing-safe comparison. out_rehash (may be NULL) is set on a match made
 * under another method than the kind's configured one, or under an iteration
 * count outside the kind's range: the secret should be hashed again and stored
 * (secret_rehash in db/queries/secret.h), so a change of method rolls forward
 * as secrets are used.
 *
 * Returns: 1 if the secret matches, 0 if not,
 *          -1 on error, an unlabeled or unknown label among them (logged)
 */
int crypto_password_verify(secret_kind_t kind, const char *password, size_t password_len,
                           const char *salt_hex, int iterations,
                           const char *stored_hash, int *out_rehash);

/*
 * Verify a secret against nothing, at the cost of a real verification: the
 * kind's method, at an iteration count drawn the way crypto_password_hash draws
 * one. For an account or key that doesn't exist or can't be used, so its
 * answer takes as long as a wrong secret's would.
 *
 * For machine secrets only while that's cheap: PBKDF2 at up to 10,000
 * iterations, about a millisecond. An unknown key id costs its sender nothing,
 * so a dearer dummy (Argon2id, the password method an auth.conf without the
 * machine settings falls back to) would let anyone stall a worker with made-up
 * ids. Key ids are random 128-bit values, so what the dummy hides is only
 * whether an id someone already has is still active.
 */
void crypto_password_verify_dummy(secret_kind_t kind, const char *password,
                                  size_t password_len);

/* A kind's configured method ("argon2id" or "pbkdf2-sha256"), and the least
   iterations of its range (recovery codes are hashed at it) */
const char *crypto_password_method(secret_kind_t kind);
int crypto_password_min_iterations(secret_kind_t kind);

/*
 * The method a stored hash names, copied into out_method: 0, or -1 if it has
 * no label or an unknown one
 */
int crypto_password_hash_method(const char *stored_hash, char *out_method, size_t size);

#endif /* CRYPTO_PASSWORD_H */
