#ifndef CRYPTO_PBKDF2_H
#define CRYPTO_PBKDF2_H

#include <stddef.h>

/*
 * PBKDF2-SHA256 Password Hashing
 *
 * Traditional iterative key derivation function.
 * Uses SHA256 as the underlying hash function.
 *
 * Matches database schema:
 *   - salt (text)
 *   - hash_iterations (integer)
 *   - secret_hash (text)
 */

/* PBKDF2 parameters */
#define PBKDF2_SALT_LENGTH       16        /* Salt length in bytes */
#define PBKDF2_HASH_LENGTH       32        /* Hash output length in bytes (SHA256) */

/* Iteration bounds - OWASP 2023 recommends 600,000+ for PBKDF2-SHA256 */
#define PBKDF2_MIN_ITERATIONS    100000    /* Minimum iterations */
#define PBKDF2_MAX_ITERATIONS    600000    /* Maximum iterations */

/* Output string lengths (hex encoded: 2 chars per byte, plus null terminator) */
#define PBKDF2_SALT_HEX_LENGTH   ((PBKDF2_SALT_LENGTH * 2) + 1)   /* 33 bytes */
#define PBKDF2_HASH_HEX_LENGTH   ((PBKDF2_HASH_LENGTH * 2) + 1)   /* 65 bytes */

/*
 * Hash password with generated salt and random iterations
 *
 * Generates random salt and random iterations, hashes password.
 * Returns all three values for database storage.
 *
 * Parameters:
 *   password        - Plain text password
 *   password_len    - Length of password
 *   out_salt_hex    - Output buffer for salt (hex string)
 *   salt_hex_len    - Size of salt buffer (must be >= PBKDF2_SALT_HEX_LENGTH)
 *   out_iterations  - Output: random iterations used
 *   out_hash_hex    - Output buffer for hash (hex string)
 *   hash_hex_len    - Size of hash buffer (must be >= PBKDF2_HASH_HEX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 */
int crypto_pbkdf2_hash(const char *password, size_t password_len,
                      char *out_salt_hex, size_t salt_hex_len,
                      int *out_iterations,
                      char *out_hash_hex, size_t hash_hex_len);

/*
 * Hash password with provided salt and iterations (low-level)
 *
 * Use this for verification or when you control the parameters.
 *
 * Parameters:
 *   password        - Plain text password
 *   password_len    - Length of password
 *   salt_hex        - Salt as hex string (from database)
 *   iterations      - Number of iterations (from database)
 *   out_hash_hex    - Output buffer for hash (hex string)
 *   hash_hex_len    - Size of hash buffer (must be >= PBKDF2_HASH_HEX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 */
int crypto_pbkdf2_hash_with_salt(const char *password, size_t password_len,
                                 const char *salt_hex, int iterations,
                                 char *out_hash_hex, size_t hash_hex_len);

/*
 * Verify password against stored hash
 *
 * Hashes password with stored salt and iterations, compares with stored hash.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * Parameters:
 *   password        - Plain text password to verify
 *   password_len    - Length of password
 *   salt_hex        - Stored salt (hex string from database)
 *   iterations      - Stored iterations (from database)
 *   expected_hash_hex - Stored hash (hex string from database)
 *
 * Returns: 1 if password matches, 0 if mismatch, negative on error
 */
int crypto_pbkdf2_verify(const char *password, size_t password_len,
                        const char *salt_hex, int iterations,
                        const char *expected_hash_hex);

#endif /* CRYPTO_PBKDF2_H */
