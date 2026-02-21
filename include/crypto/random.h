#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H

#include <stddef.h>

/*
 * Cryptographic Random Number Generation
 *
 * Provides cryptographically secure random bytes and tokens.
 * Uses getrandom() syscall (Linux 3.17+) for entropy.
 *
 * SECURITY NOTE: Never use rand(), srand(), or similar for crypto operations.
 */

/*
 * Fill buffer with cryptographically secure random bytes
 *
 * Parameters:
 *   buffer - Output buffer to fill
 *   length - Number of random bytes to generate
 *
 * Returns: 0 on success, negative on error
 */
int crypto_random_bytes(void *buffer, size_t length);

/*
 * Generate URL-safe base64 token (for OAuth2 tokens, codes, etc.)
 *
 * Creates random bytes and encodes as base64url (RFC 4648 Section 5):
 *   - Uses A-Z, a-z, 0-9, -, _ (no padding)
 *   - Safe for URLs and HTTP headers
 *
 * Parameters:
 *   output     - Output buffer (must be >= crypto_token_encoded_size(num_bytes))
 *   output_len - Size of output buffer
 *   num_bytes  - Number of random bytes (before encoding)
 *                Recommended: 32 bytes (256 bits) for most OAuth2 tokens
 *
 * Returns: Number of characters written (excluding null terminator), or negative on error
 *
 * Example:
 *   char token[64];
 *   crypto_random_token(token, sizeof(token), 32);  // 32 bytes = 43 chars base64url
 */
int crypto_random_token(char *output, size_t output_len, size_t num_bytes);

/*
 * Calculate required buffer size for base64url encoded token
 *
 * Returns: Number of bytes needed for output buffer (including null terminator)
 */
static inline size_t crypto_token_encoded_size(size_t num_bytes) {
    /* Base64 encoding: ceil(num_bytes * 4 / 3), plus null terminator */
    return ((num_bytes * 4 + 2) / 3) + 1;
}

/*
 * Base64url encode binary data (RFC 4648 Section 5)
 *
 * Encodes binary data as base64url (no padding).
 * Used for JWT header/payload encoding.
 *
 * Parameters:
 *   input      - Binary data to encode
 *   input_len  - Length of input data
 *   output     - Output buffer for encoded string
 *   output_len - Size of output buffer
 *
 * Returns: Number of characters written (excluding null), or 0 on error
 */
size_t crypto_base64url_encode(const unsigned char *input, size_t input_len,
                              char *output, size_t output_len);

/*
 * Base64url decode string to binary data (RFC 4648 Section 5)
 *
 * Decodes base64url string (no padding) to binary.
 * Used for JWT header/payload/signature decoding.
 *
 * Parameters:
 *   input      - Base64url string to decode
 *   input_len  - Length of input string
 *   output     - Output buffer for decoded bytes
 *   output_len - Size of output buffer
 *
 * Returns: Number of bytes written, or negative on error
 */
int crypto_base64url_decode(const char *input, size_t input_len,
                           unsigned char *output, size_t output_len);

/*
 * Generate cryptographically secure random integer in range [min, max]
 *
 * Uses crypto_random_bytes() for CSPRNG randomness.
 * Common use: random iteration counts for password hashing.
 *
 * Parameters:
 *   min - Minimum value (inclusive)
 *   max - Maximum value (inclusive)
 *
 * Returns: Random integer in range, or min on error
 *
 * Example:
 *   int iterations = crypto_random_int_range(100000, 600000);
 */
int crypto_random_int_range(int min, int max);

#endif /* CRYPTO_RANDOM_H */
