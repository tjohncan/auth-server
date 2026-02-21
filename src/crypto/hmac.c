#include "crypto/hmac.h"
#include "util/log.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>

int crypto_hmac_sha256(const unsigned char *key, size_t key_len,
                      const unsigned char *data, size_t data_len,
                      unsigned char *out_hmac, size_t hmac_len) {
    if (!key || !data || !out_hmac) {
        log_error("Invalid arguments to crypto_hmac_sha256");
        return -1;
    }

    if (hmac_len < HMAC_SHA256_LENGTH) {
        log_error("Output buffer too small for HMAC-SHA256 (need %d bytes)", HMAC_SHA256_LENGTH);
        return -1;
    }

    /* Compute HMAC-SHA256 using OpenSSL */
    unsigned int result_len = 0;
    unsigned char *result = HMAC(EVP_sha256(), key, (int)key_len,
                                data, data_len, out_hmac, &result_len);

    if (result == NULL || result_len != HMAC_SHA256_LENGTH) {
        log_error("HMAC-SHA256 computation failed");
        return -1;
    }

    return 0;
}

int crypto_hmac_sha256_hex(const unsigned char *key, size_t key_len,
                          const unsigned char *data, size_t data_len,
                          char *out_hmac_hex, size_t hmac_hex_len) {
    if (!key || !data || !out_hmac_hex) {
        log_error("Invalid arguments to crypto_hmac_sha256_hex");
        return -1;
    }

    if (hmac_hex_len < HMAC_SHA256_HEX_LENGTH) {
        log_error("Output buffer too small for HMAC-SHA256 hex (need %d bytes)", HMAC_SHA256_HEX_LENGTH);
        return -1;
    }

    /* Compute binary HMAC */
    unsigned char hmac_binary[HMAC_SHA256_LENGTH];
    if (crypto_hmac_sha256(key, key_len, data, data_len,
                          hmac_binary, sizeof(hmac_binary)) != 0) {
        return -1;
    }

    /* Convert to hex string */
    for (size_t i = 0; i < HMAC_SHA256_LENGTH; i++) {
        snprintf(out_hmac_hex + (i * 2), 3, "%02x", hmac_binary[i]);
    }
    out_hmac_hex[HMAC_SHA256_LENGTH * 2] = '\0';

    return 0;
}

int crypto_hmac_compare(const unsigned char *hmac1, const unsigned char *hmac2, size_t len) {
    if (!hmac1 || !hmac2) {
        log_error("Invalid arguments to crypto_hmac_compare");
        return 0;  /* Not equal on error */
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(hmac1, hmac2, len) == 0 ? 1 : 0;
}
