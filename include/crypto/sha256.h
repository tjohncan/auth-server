#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <stddef.h>

/*
 * SHA-256 hashing for token storage
 *
 * High-entropy tokens (session, refresh, access, auth codes) are hashed
 * with SHA-256 before database storage. A single hash is sufficient for
 * 256-bit CSPRNG tokens — key-stretching adds nothing when input entropy
 * already matches output size.
 */

/* SHA-256 produces 32-byte (256-bit) output */
#define SHA256_DIGEST_LENGTH  32
#define SHA256_HEX_LENGTH     65  /* 32 bytes * 2 + null terminator */

/*
 * Compute SHA-256 hash (hex output)
 *
 * Parameters:
 *   data     - Data to hash
 *   data_len - Length of data in bytes
 *   out_hex  - Output buffer for hex string (must be >= SHA256_HEX_LENGTH)
 *   hex_len  - Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 */
int crypto_sha256_hex(const void *data, size_t data_len,
                      char *out_hex, size_t hex_len);

#endif /* CRYPTO_SHA256_H */
