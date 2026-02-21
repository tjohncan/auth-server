#include "crypto/pbkdf2.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

/* ============================================================================
 * Public API
 * ============================================================================ */

int crypto_pbkdf2_hash(const char *password, size_t password_len,
                      char *out_salt_hex, size_t salt_hex_len,
                      int *out_iterations,
                      char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !out_salt_hex || !out_iterations || !out_hash_hex) {
        log_error("Invalid arguments to crypto_pbkdf2_hash");
        return -1;
    }

    if (salt_hex_len < PBKDF2_SALT_HEX_LENGTH || hash_hex_len < PBKDF2_HASH_HEX_LENGTH) {
        log_error("Output buffers too small for PBKDF2 hash");
        return -1;
    }

    /* Generate random salt */
    unsigned char salt[PBKDF2_SALT_LENGTH];
    if (crypto_random_bytes(salt, sizeof(salt)) != 0) {
        log_error("Failed to generate salt for PBKDF2");
        return -1;
    }

    /* Generate random iterations in range [min, max] */
    int iterations = crypto_random_int_range(PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS);

    /* Derive key using PBKDF2-HMAC-SHA256 */
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
    *out_iterations = iterations;

    return 0;
}

int crypto_pbkdf2_hash_with_salt(const char *password, size_t password_len,
                                 const char *salt_hex, int iterations,
                                 char *out_hash_hex, size_t hash_hex_len) {
    if (!password || !salt_hex || !out_hash_hex) {
        log_error("Invalid arguments to crypto_pbkdf2_hash_with_salt");
        return -1;
    }

    if (hash_hex_len < PBKDF2_HASH_HEX_LENGTH) {
        log_error("Output buffer too small for PBKDF2 hash");
        return -1;
    }

    if (iterations < 1 || iterations > 10000000) {
        log_error("Invalid iteration count: %d", iterations);
        return -1;
    }

    /* Convert salt from hex to binary */
    unsigned char salt[PBKDF2_SALT_LENGTH];
    if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0) {
        log_error("Invalid salt hex format");
        return -1;
    }

    /* Derive key using PBKDF2-HMAC-SHA256 */
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

    /* Convert hash to hex string */
    bytes_to_hex(hash, sizeof(hash), out_hash_hex, hash_hex_len);

    return 0;
}

int crypto_pbkdf2_verify(const char *password, size_t password_len,
                        const char *salt_hex, int iterations,
                        const char *expected_hash_hex) {
    if (!password || !salt_hex || !expected_hash_hex) {
        log_error("Invalid arguments to crypto_pbkdf2_verify");
        return -1;
    }

    /* Hash password with stored salt and iterations */
    char computed_hash_hex[PBKDF2_HASH_HEX_LENGTH];
    if (crypto_pbkdf2_hash_with_salt(password, password_len, salt_hex, iterations,
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
