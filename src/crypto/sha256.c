#define _POSIX_C_SOURCE 200809L

#include "crypto/sha256.h"
#include "util/log.h"
#include <openssl/evp.h>
#include <stdio.h>

int crypto_sha256_hex(const void *data, size_t data_len,
                      char *out_hex, size_t hex_len) {
    if (!data || !out_hex) {
        log_error("Invalid arguments to crypto_sha256_hex");
        return -1;
    }

    if (hex_len < SHA256_HEX_LENGTH) {
        log_error("Output buffer too small for SHA-256 hex (need %d bytes)",
                  SHA256_HEX_LENGTH);
        return -1;
    }

    /* Compute SHA-256 using OpenSSL EVP */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;

    if (EVP_Digest(data, data_len, hash, &hash_len, EVP_sha256(), NULL) != 1
        || hash_len != SHA256_DIGEST_LENGTH) {
        log_error("SHA-256 computation failed");
        return -1;
    }

    /* Convert to hex string */
    for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
    out_hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    return 0;
}
