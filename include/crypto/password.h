#ifndef CRYPTO_PASSWORD_H
#define CRYPTO_PASSWORD_H

#include "util/config.h"
#include <stddef.h>

/*
 * High-Level Password Hashing API
 *
 * Module-level wrapper that delegates to Argon2id or PBKDF2-SHA256
 * based on initialization settings.
 *
 * Usage:
 *   1. Call crypto_password_init(config) once at startup
 *   2. Call crypto_password_hash() / crypto_password_verify() from any thread
 *
 * Module stores:
 *   - secret_hashing_algorithm (argon2id or pbkdf2-sha256)
 *   - secret_hash_min_iterations
 *   - secret_hash_max_iterations
 *
 * Outputs match database schema:
 *   - salt (text)
 *   - hash_iterations (integer)
 *   - secret_hash (text)
 */

/* Maximum buffer sizes (covers both Argon2 and PBKDF2) */
#define PASSWORD_SALT_HEX_MAX_LENGTH  65
#define PASSWORD_HASH_HEX_MAX_LENGTH  65

/*
 * Initialize password hashing module
 *
 * Stores algorithm and iteration range from config.
 * Must be called once at startup before any hash/verify operations.
 * Thread-safe after initialization (settings are read-only).
 *
 * Parameters:
 *   config - Configuration with algorithm and iteration settings
 *
 * Returns: 0 on success, negative on error
 */
int crypto_password_init(const config_t *config);

/*
 * Hash password for storage
 *
 * Generates random salt and random iterations based on initialized settings.
 * Delegates to Argon2id or PBKDF2 based on algorithm from crypto_password_init().
 *
 * Optimized: If min_iterations == max_iterations, skips random number generation.
 *
 * Parameters:
 *   password        - Plain text password
 *   password_len    - Length of password
 *   out_salt_hex    - Output buffer for salt (hex string)
 *   salt_hex_len    - Size of salt buffer (must be >= PASSWORD_SALT_HEX_MAX_LENGTH)
 *   out_iterations  - Output: iterations used (store in DB)
 *   out_hash_hex    - Output buffer for hash (hex string)
 *   hash_hex_len    - Size of hash buffer (must be >= PASSWORD_HASH_HEX_MAX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 *
 * Example:
 *   char salt[PASSWORD_SALT_HEX_MAX_LENGTH];
 *   int iterations;
 *   char hash[PASSWORD_HASH_HEX_MAX_LENGTH];
 *
 *   crypto_password_hash("password", 8, salt, sizeof(salt),
 *                       &iterations, hash, sizeof(hash));
 *
 *   // INSERT INTO user_account (salt, hash_iterations, secret_hash)
 *   // VALUES (?, ?, ?)
 */
int crypto_password_hash(const char *password, size_t password_len,
                        char *out_salt_hex, size_t salt_hex_len,
                        int *out_iterations,
                        char *out_hash_hex, size_t hash_hex_len);

/*
 * Hash password with provided salt and iterations (low-level)
 *
 * Use this when hashing multiple values against the same salt.
 * Delegates to Argon2id or PBKDF2 based on algorithm from crypto_password_init().
 *
 * Parameters:
 *   password        - Plain text password
 *   password_len    - Length of password
 *   salt_hex        - Salt as hex string
 *   iterations      - Number of iterations
 *   out_hash_hex    - Output buffer for hash (hex string)
 *   hash_hex_len    - Size of hash buffer (must be >= PASSWORD_HASH_HEX_MAX_LENGTH)
 *
 * Returns: 0 on success, negative on error
 */
int crypto_password_hash_with_salt(const char *password, size_t password_len,
                                   const char *salt_hex, int iterations,
                                   char *out_hash_hex, size_t hash_hex_len);

/*
 * Verify password against stored hash
 *
 * Delegates to Argon2id or PBKDF2 based on algorithm from crypto_password_init().
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * Parameters:
 *   password          - Plain text password to verify
 *   password_len      - Length of password
 *   salt_hex          - Stored salt (hex string from database)
 *   iterations        - Stored iterations (from database)
 *   expected_hash_hex - Stored hash (hex string from database)
 *
 * Returns: 1 if password matches, 0 if mismatch, negative on error
 *
 * Example:
 *   // SELECT salt, hash_iterations, secret_hash FROM user_account WHERE ...
 *   int valid = crypto_password_verify(password, strlen(password),
 *                                      stored_salt, stored_iterations, stored_hash);
 *   if (valid == 1) {
 *       // Authentication success
 *   }
 */
int crypto_password_verify(const char *password, size_t password_len,
                          const char *salt_hex, int iterations,
                          const char *expected_hash_hex);

/*
 * Get configured minimum iterations (for dummy verification on unknown users)
 */
int crypto_password_min_iterations(void);

#endif /* CRYPTO_PASSWORD_H */
