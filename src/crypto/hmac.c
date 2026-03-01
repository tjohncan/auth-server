#include "crypto/hmac.h"
#include "util/log.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>

/*
 * Compute HMAC using EVP_MAC API (OpenSSL 3.0+)
 * Internal helper — callers use crypto_hmac_sha256 / crypto_hmac_sha1
 */
static int hmac_compute(const char *digest,
                        const unsigned char *key, size_t key_len,
                        const unsigned char *data, size_t data_len,
                        unsigned char *out, size_t out_size, size_t *out_len) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0),
        OSSL_PARAM_construct_end()
    };

    int rc = -1;
    if (EVP_MAC_init(ctx, key, key_len, params) == 1 &&
        EVP_MAC_update(ctx, data, data_len) == 1 &&
        EVP_MAC_final(ctx, out, out_len, out_size) == 1) {
        rc = 0;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rc;
}

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

    size_t result_len = 0;
    if (hmac_compute("SHA256", key, key_len, data, data_len,
                     out_hmac, hmac_len, &result_len) != 0 ||
        result_len != HMAC_SHA256_LENGTH) {
        log_error("HMAC-SHA256 computation failed");
        return -1;
    }

    return 0;
}

int crypto_hmac_sha1(const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len,
                     unsigned char *out_hmac, size_t hmac_len) {
    if (!key || !data || !out_hmac) {
        log_error("Invalid arguments to crypto_hmac_sha1");
        return -1;
    }

    if (hmac_len < HMAC_SHA1_LENGTH) {
        log_error("Output buffer too small for HMAC-SHA1 (need %d bytes)", HMAC_SHA1_LENGTH);
        return -1;
    }

    size_t result_len = 0;
    if (hmac_compute("SHA1", key, key_len, data, data_len,
                     out_hmac, hmac_len, &result_len) != 0 ||
        result_len != HMAC_SHA1_LENGTH) {
        log_error("HMAC-SHA1 computation failed");
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
