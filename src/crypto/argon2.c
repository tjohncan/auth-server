#include "crypto/argon2.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include <argon2.h>
#include <openssl/crypto.h>
#include <string.h>

/* ============================================================================
 * Public API
 * ============================================================================ */

int crypto_argon2_hash(const char *password, size_t password_len,
                      char *out_salt_hex, size_t salt_hex_len,
                      int *out_iterations,
                      char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !out_salt_hex || !out_iterations || !out_hash_hex) {
        log_error("Invalid arguments to crypto_argon2_hash");
        return -1;
    }

    if (salt_hex_len < ARGON2_SALT_HEX_LENGTH || hash_hex_len < ARGON2_HASH_HEX_LENGTH) {
        log_error("Output buffers too small for Argon2 hash");
        return -1;
    }

    /* Generate random salt */
    unsigned char salt[ARGON2_SALT_LENGTH];
    if (crypto_random_bytes(salt, sizeof(salt)) != 0) {
        log_error("Failed to generate salt for Argon2");
        return -1;
    }

    /* Generate random iterations in range [min, max] */
    int iterations = crypto_random_int_range(ARGON2_MIN_ITERATIONS, ARGON2_MAX_ITERATIONS);

    /* Hash password with Argon2id */
    unsigned char hash[ARGON2_HASH_LENGTH];
    int result = argon2id_hash_raw(
        iterations,
        ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM,
        password,
        password_len,
        salt,
        sizeof(salt),
        hash,
        sizeof(hash)
    );

    if (result != ARGON2_OK) {
        log_error("Argon2 hash failed: %s", argon2_error_message(result));
        return -1;
    }

    /* Convert to hex strings for database storage */
    bytes_to_hex(salt, sizeof(salt), out_salt_hex, salt_hex_len);
    bytes_to_hex(hash, sizeof(hash), out_hash_hex, hash_hex_len);
    *out_iterations = iterations;

    return 0;
}

int crypto_argon2_hash_with_salt(const char *password, size_t password_len,
                                 const char *salt_hex, int iterations,
                                 char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !salt_hex || !out_hash_hex) {
        log_error("Invalid arguments to crypto_argon2_hash_with_salt");
        return -1;
    }

    if (hash_hex_len < ARGON2_HASH_HEX_LENGTH) {
        log_error("Output buffer too small for Argon2 hash");
        return -1;
    }

    if (iterations < 1 || iterations > 20) {
        log_error("Invalid iteration count: %d", iterations);
        return -1;
    }

    /* Convert salt from hex to binary */
    unsigned char salt[ARGON2_SALT_LENGTH];
    if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0) {
        log_error("Invalid salt hex format");
        return -1;
    }

    /* Hash password with Argon2id */
    unsigned char hash[ARGON2_HASH_LENGTH];
    int result = argon2id_hash_raw(
        iterations,
        ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM,
        password,
        password_len,
        salt,
        sizeof(salt),
        hash,
        sizeof(hash)
    );

    if (result != ARGON2_OK) {
        log_error("Argon2 hash failed: %s", argon2_error_message(result));
        return -1;
    }

    /* Convert hash to hex string */
    bytes_to_hex(hash, sizeof(hash), out_hash_hex, hash_hex_len);

    return 0;
}

int crypto_argon2_verify(const char *password, size_t password_len,
                        const char *salt_hex, int iterations,
                        const char *expected_hash_hex) {
    if (!password || !salt_hex || !expected_hash_hex) {
        log_error("Invalid arguments to crypto_argon2_verify");
        return -1;
    }

    /* Hash password with stored salt and iterations */
    char computed_hash_hex[ARGON2_HASH_HEX_LENGTH];
    if (crypto_argon2_hash_with_salt(password, password_len, salt_hex, iterations,
                                    computed_hash_hex, sizeof(computed_hash_hex)) != 0) {
        return -1;
    }

    /* Timing-safe comparison to prevent timing attacks */
    size_t hash_len = strlen(expected_hash_hex);
    if (hash_len != strlen(computed_hash_hex)) {
        return 0;  /* Length mismatch = password doesn't match */
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(expected_hash_hex, computed_hash_hex, hash_len) == 0 ? 1 : 0;
}
