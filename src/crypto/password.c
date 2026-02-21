#include "crypto/password.h"
#include "crypto/argon2.h"
#include "crypto/pbkdf2.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include <argon2.h>
#include <openssl/evp.h>

/* Module-level state (initialized once at startup, read-only after init) */
static password_hash_algorithm_t g_algorithm;
static int g_min_iterations;
static int g_max_iterations;
static int g_initialized = 0;

int crypto_password_init(const config_t *config) {
    if (!config) {
        log_error("Invalid config to crypto_password_init");
        return -1;
    }

    if (g_initialized) {
        log_warn("crypto_password already initialized");
        return 0;
    }

    g_algorithm = config->secret_hashing_algorithm;
    g_min_iterations = config->secret_hash_min_iterations;
    g_max_iterations = config->secret_hash_max_iterations;
    g_initialized = 1;

    log_info("Initialized password hashing: algorithm=%s, iterations=%d-%d",
             g_algorithm == PASSWORD_HASH_ARGON2ID ? "argon2id" : "pbkdf2-sha256",
             g_min_iterations, g_max_iterations);

    return 0;
}

int crypto_password_hash(const char *password, size_t password_len,
                        char *out_salt_hex, size_t salt_hex_len,
                        int *out_iterations,
                        char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !out_salt_hex || !out_iterations || !out_hash_hex) {
        log_error("Invalid arguments to crypto_password_hash");
        return -1;
    }

    if (!g_initialized) {
        log_error("crypto_password module not initialized");
        return -1;
    }

    if (salt_hex_len < PASSWORD_SALT_HEX_MAX_LENGTH ||
        hash_hex_len < PASSWORD_HASH_HEX_MAX_LENGTH) {
        log_error("Output buffer too small for password hash");
        return -1;
    }

    /* Delegate to configured algorithm */
    switch (g_algorithm) {
        case PASSWORD_HASH_ARGON2ID: {
            /* Generate random salt */
            unsigned char salt[ARGON2_SALT_LENGTH];
            if (crypto_random_bytes(salt, sizeof(salt)) != 0) {
                log_error("Failed to generate salt");
                return -1;
            }

            /* Convert salt to hex */
            bytes_to_hex(salt, sizeof(salt), out_salt_hex, salt_hex_len);

            /* Get iterations (optimized if min==max) */
            int iterations = crypto_random_int_range(g_min_iterations, g_max_iterations);
            *out_iterations = iterations;

            /* Hash with Argon2id */
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

            if (result != 0) {
                log_error("Argon2 hash failed");
                return -1;
            }

            /* Convert hash to hex */
            bytes_to_hex(hash, sizeof(hash), out_hash_hex, hash_hex_len);

            return 0;
        }

        case PASSWORD_HASH_PBKDF2_SHA256: {
            /* Generate random salt */
            unsigned char salt[PBKDF2_SALT_LENGTH];
            if (crypto_random_bytes(salt, sizeof(salt)) != 0) {
                log_error("Failed to generate salt");
                return -1;
            }

            /* Get iterations (optimized if min==max) */
            int iterations = crypto_random_int_range(g_min_iterations, g_max_iterations);
            *out_iterations = iterations;

            /* Hash with PBKDF2 directly (optimal path) */
            unsigned char hash[PBKDF2_HASH_LENGTH];
            int result = PKCS5_PBKDF2_HMAC(
                password,
                (int)password_len,
                salt,
                sizeof(salt),
                iterations,
                EVP_sha256(),
                sizeof(hash),
                hash
            );

            if (result != 1) {
                log_error("PBKDF2 hash failed");
                return -1;
            }

            /* Convert to hex strings for database storage */
            bytes_to_hex(salt, sizeof(salt), out_salt_hex, salt_hex_len);
            bytes_to_hex(hash, sizeof(hash), out_hash_hex, hash_hex_len);

            return 0;
        }

        default:
            log_error("Unknown password hashing algorithm: %d", g_algorithm);
            return -1;
    }
}

int crypto_password_hash_with_salt(const char *password, size_t password_len,
                                   const char *salt_hex, int iterations,
                                   char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !salt_hex || !out_hash_hex) {
        log_error("Invalid arguments to crypto_password_hash_with_salt");
        return -1;
    }

    if (!g_initialized) {
        log_error("crypto_password module not initialized");
        return -1;
    }

    switch (g_algorithm) {
        case PASSWORD_HASH_ARGON2ID:
            return crypto_argon2_hash_with_salt(password, password_len, salt_hex,
                                               iterations, out_hash_hex, hash_hex_len);

        case PASSWORD_HASH_PBKDF2_SHA256:
            return crypto_pbkdf2_hash_with_salt(password, password_len, salt_hex,
                                               iterations, out_hash_hex, hash_hex_len);

        default:
            log_error("Unknown password hashing algorithm: %d", g_algorithm);
            return -1;
    }
}

int crypto_password_min_iterations(void) {
    return g_min_iterations;
}

int crypto_password_verify(const char *password, size_t password_len,
                          const char *salt_hex, int iterations,
                          const char *expected_hash_hex) {
    if (!password || !salt_hex || !expected_hash_hex) {
        log_error("Invalid arguments to crypto_password_verify");
        return -1;
    }

    if (!g_initialized) {
        log_error("crypto_password module not initialized");
        return -1;
    }

    /* Delegate to configured algorithm */
    switch (g_algorithm) {
        case PASSWORD_HASH_ARGON2ID:
            return crypto_argon2_verify(password, password_len, salt_hex,
                                       iterations, expected_hash_hex);

        case PASSWORD_HASH_PBKDF2_SHA256:
            return crypto_pbkdf2_verify(password, password_len, salt_hex,
                                       iterations, expected_hash_hex);

        default:
            log_error("Unknown password hashing algorithm: %d", g_algorithm);
            return -1;
    }
}
