#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <stddef.h>

/*
 * HMAC-SHA256 for JWT signatures and token validation
 *
 * Uses OpenSSL's HMAC implementation with SHA-256 hash function.
 * Thread-safe, no state stored between calls.
 */

/* SHA-256 produces 32-byte (256-bit) output */
#define HMAC_SHA256_LENGTH     32
#define HMAC_SHA256_HEX_LENGTH 65  /* 32 bytes * 2 + null terminator */

/*
 * Compute HMAC-SHA256 (binary output)
 *
 * Used for JWT signature generation where binary output is base64url-encoded.
 *
 * Parameters:
 *   key        - Secret key (arbitrary length)
 *   key_len    - Length of key in bytes
 *   data       - Data to authenticate
 *   data_len   - Length of data in bytes
 *   out_hmac   - Output buffer for HMAC (must be >= HMAC_SHA256_LENGTH bytes)
 *   hmac_len   - Size of output buffer
 *
 * Returns: 0 on success, negative on error
 *
 * Example (JWT signing):
 *   unsigned char signature[HMAC_SHA256_LENGTH];
 *   crypto_hmac_sha256(secret, secret_len, "header.payload",
 *                     strlen("header.payload"), signature, sizeof(signature));
 *   // Then base64url-encode signature
 */
int crypto_hmac_sha256(const unsigned char *key, size_t key_len,
                      const unsigned char *data, size_t data_len,
                      unsigned char *out_hmac, size_t hmac_len);

/*
 * Compute HMAC-SHA256 (hex output)
 *
 * Used for debugging and non-JWT HMAC use cases.
 *
 * Parameters:
 *   key         - Secret key (arbitrary length)
 *   key_len     - Length of key in bytes
 *   data        - Data to authenticate
 *   data_len    - Length of data in bytes
 *   out_hmac_hex - Output buffer for hex string (must be >= HMAC_SHA256_HEX_LENGTH)
 *   hmac_hex_len - Size of output buffer
 *
 * Returns: 0 on success, negative on error
 *
 * Example (webhook validation):
 *   char signature_hex[HMAC_SHA256_HEX_LENGTH];
 *   crypto_hmac_sha256_hex(webhook_secret, secret_len, payload, payload_len,
 *                         signature_hex, sizeof(signature_hex));
 */
int crypto_hmac_sha256_hex(const unsigned char *key, size_t key_len,
                          const unsigned char *data, size_t data_len,
                          char *out_hmac_hex, size_t hmac_hex_len);

/*
 * Timing-safe comparison of HMAC values
 *
 * Prevents timing attacks when validating HMAC signatures.
 * Use this instead of memcmp() for security-sensitive comparisons.
 *
 * Parameters:
 *   hmac1 - First HMAC value
 *   hmac2 - Second HMAC value
 *   len   - Length to compare (typically HMAC_SHA256_LENGTH)
 *
 * Returns: 1 if equal, 0 if not equal
 *
 * Example (JWT validation):
 *   unsigned char computed[HMAC_SHA256_LENGTH];
 *   unsigned char received[HMAC_SHA256_LENGTH];
 *   // ... compute and decode ...
 *   if (crypto_hmac_compare(computed, received, HMAC_SHA256_LENGTH)) {
 *       // Signature valid
 *   }
 */
int crypto_hmac_compare(const unsigned char *hmac1, const unsigned char *hmac2, size_t len);

#endif /* CRYPTO_HMAC_H */
