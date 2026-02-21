#ifndef UTIL_DATA_H
#define UTIL_DATA_H

#include <stddef.h>

/*
 * Data Conversion Utilities
 *
 * Common functions for hex encoding/decoding used across crypto modules.
 */

/*
 * Convert binary data to lowercase hex string
 *
 * Parameters:
 *   bytes    - Input binary data
 *   len      - Length of binary data
 *   out      - Output buffer for hex string
 *   out_size - Size of output buffer (must be >= len*2 + 1)
 *
 * Output is null-terminated lowercase hex string.
 * Example: {0xDE, 0xAD, 0xBE, 0xEF} -> "deadbeef"
 *
 * Returns: 0 on success, -1 if output buffer is too small
 */
int bytes_to_hex(const unsigned char *bytes, size_t len, char *out, size_t out_size);

/*
 * Convert hex string to binary data
 *
 * Accepts both lowercase and uppercase hex characters.
 * Hyphens are stripped (allows UUID format with dashes).
 *
 * Parameters:
 *   hex      - Input hex string (must have exactly byte_len*2 hex chars, hyphens ignored)
 *   bytes    - Output buffer for binary data
 *   byte_len - Expected length of output in bytes
 *
 * Returns: 0 on success, -1 on error (invalid hex length or characters)
 *
 * Examples:
 *   "deadbeef" -> {0xDE, 0xAD, 0xBE, 0xEF}
 *   "550e8400-e29b-41d4-a716-446655440000" -> 16 bytes (UUID)
 */
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t byte_len);

#endif /* UTIL_DATA_H */
