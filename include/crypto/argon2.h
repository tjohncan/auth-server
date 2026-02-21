#ifndef CRYPTO_ARGON2_H
#define CRYPTO_ARGON2_H

#include <stddef.h>

/*
 * Argon2 Password Hashing
 *
 * Uses Argon2id variant (recommended for password storage).
 * Argon2id combines:
 *   - Argon2i: Resistant to side-channel attacks
 *   - Argon2d: Resistant to GPU cracking
 *
 * Matches database schema:
 *   - salt (text)
 *   - hash_iterations (integer)
 *   - secret_hash (text)
 */

/* Argon2 parameters */
#define ARGON2_SALT_LENGTH       16        /* Salt length in bytes */
#define ARGON2_HASH_LENGTH       32        /* Hash output length in bytes */
#define ARGON2_MEMORY_COST       (64*1024) /* Memory in KiB (64 MB) */
#define ARGON2_PARALLELISM       1         /* Number of threads */

/* Iteration bounds (time cost) - randomized per hash for added security */
#define ARGON2_MIN_ITERATIONS    3         /* Minimum iterations */
#define ARGON2_MAX_ITERATIONS    10        /* Maximum iterations */

/* Output string lengths (hex encoded: 2 chars per byte, plus null terminator) */
#define ARGON2_SALT_HEX_LENGTH   ((ARGON2_SALT_LENGTH * 2) + 1)   /* 33 bytes */
#define ARGON2_HASH_HEX_LENGTH   ((ARGON2_HASH_LENGTH * 2) + 1)   /* 65 bytes */

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
 *   salt_hex_len    - Size of salt buffer (must be >= ARGON2_SALT_HEX_LENGTH)
 *   out_iterations  - Output: random iterations used
 *   out_hash_hex    - Output buffer for hash (hex string)
 *   hash_hex_len    - Size of hash buffer (must be >= ARGON2_HASH_HEX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 *
 * Example:
 *   char salt[ARGON2_SALT_HEX_LENGTH];
 *   int iterations;
 *   char hash[ARGON2_HASH_HEX_LENGTH];
 *
 *   crypto_argon2_hash("password", 8, salt, sizeof(salt), &iterations, hash, sizeof(hash));
 *
 *   // Insert into database:
 *   // INSERT INTO user_account (salt, hash_iterations, secret_hash) VALUES (?, ?, ?)
 */
int crypto_argon2_hash(const char *password, size_t password_len,
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
 *   hash_hex_len    - Size of hash buffer (must be >= ARGON2_HASH_HEX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 */
int crypto_argon2_hash_with_salt(const char *password, size_t password_len,
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
 *
 * Example:
 *   // SELECT salt, hash_iterations, secret_hash FROM user_account WHERE username = ?
 *   int valid = crypto_argon2_verify(password, strlen(password),
 *                                    stored_salt, stored_iterations, stored_hash);
 *   if (valid == 1) {
 *       // Login success
 *   }
 */
int crypto_argon2_verify(const char *password, size_t password_len,
                        const char *salt_hex, int iterations,
                        const char *expected_hash_hex);

#endif /* CRYPTO_ARGON2_H */
