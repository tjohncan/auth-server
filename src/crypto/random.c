#include "crypto/random.h"
#include "util/log.h"
#include <openssl/crypto.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>

/* Base64url alphabet (RFC 4648 Section 5) - URL and filename safe */
static const char base64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* ============================================================================
 * Random Byte Generation
 * ============================================================================ */

int crypto_random_bytes(void *buffer, size_t length) {
    if (!buffer || length == 0) {
        log_error("Invalid arguments to crypto_random_bytes");
        return -1;
    }

    /* Use getrandom() syscall (Linux 3.17+, no file descriptors needed) */
    size_t offset = 0;
    while (offset < length) {
        ssize_t result = getrandom((char *)buffer + offset, length - offset, 0);

        if (result < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            log_error("getrandom() failed: %s", strerror(errno));
            return -1;
        }

        offset += result;
    }

    return 0;
}

/* ============================================================================
 * Base64url Encoding (RFC 4648 Section 5)
 * ============================================================================
 *
 * Standard base64 uses: A-Z, a-z, 0-9, +, /, =
 * Base64url uses:       A-Z, a-z, 0-9, -, _  (no padding)
 *
 * This is safe for URLs, HTTP headers, and filenames.
 */

size_t crypto_base64url_encode(const unsigned char *input, size_t input_len,
                              char *output, size_t output_len) {
    size_t output_pos = 0;

    /* Process 3-byte blocks */
    for (size_t i = 0; i < input_len; i += 3) {
        /* Need at least 4 bytes in output for each 3-byte input block */
        if (output_pos + 4 > output_len) {
            log_error("Base64url output buffer too small");
            return 0;
        }

        /* Read 3 bytes (or fewer for last block) */
        unsigned char b0 = input[i];
        unsigned char b1 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b2 = (i + 2 < input_len) ? input[i + 2] : 0;

        /* Encode into 4 base64 characters */
        output[output_pos++] = base64url_alphabet[b0 >> 2];
        output[output_pos++] = base64url_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];

        if (i + 1 < input_len) {
            output[output_pos++] = base64url_alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        }

        if (i + 2 < input_len) {
            output[output_pos++] = base64url_alphabet[b2 & 0x3F];
        }
    }

    /* No padding in base64url */
    output[output_pos] = '\0';
    return output_pos;
}

/*
 * Decode base64url character to 6-bit value
 * Returns: 0-63 on success, -1 on invalid character
 */
static int base64url_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;  /* Invalid character */
}

int crypto_base64url_decode(const char *input, size_t input_len,
                           unsigned char *output, size_t output_len) {
    if (!input || !output) {
        log_error("Invalid arguments to crypto_base64url_decode");
        return -1;
    }

    if (input_len == 0) {
        return 0;  /* Empty input produces empty output */
    }

    /*
     * Base64url without padding: valid lengths produce 1-3 bytes in final block
     * input_len % 4 == 0: full blocks, produces (input_len/4)*3 bytes
     * input_len % 4 == 2: final block produces 1 byte
     * input_len % 4 == 3: final block produces 2 bytes
     * input_len % 4 == 1: INVALID (cannot represent complete data)
     */
    if (input_len % 4 == 1) {
        log_error("Invalid base64url length: %zu (cannot be 4n+1)", input_len);
        return -1;
    }

    /* Calculate expected output length */
    size_t expected_output_len = (input_len / 4) * 3;
    size_t remainder = input_len % 4;
    if (remainder == 2) expected_output_len += 1;
    if (remainder == 3) expected_output_len += 2;

    if (output_len < expected_output_len) {
        log_error("Output buffer too small for base64url decode");
        return -1;
    }

    size_t output_pos = 0;

    /* Process 4-character blocks */
    for (size_t i = 0; i < input_len; i += 4) {
        /* Decode 4 base64 characters to 6-bit values */
        int v0 = base64url_decode_char(input[i]);
        int v1 = (i + 1 < input_len) ? base64url_decode_char(input[i + 1]) : 0;
        int v2 = (i + 2 < input_len) ? base64url_decode_char(input[i + 2]) : 0;
        int v3 = (i + 3 < input_len) ? base64url_decode_char(input[i + 3]) : 0;

        if (v0 < 0 || v1 < 0) {
            log_error("Invalid base64url character in input");
            return -1;
        }

        if ((i + 2 < input_len && v2 < 0) || (i + 3 < input_len && v3 < 0)) {
            log_error("Invalid base64url character in input");
            return -1;
        }

        /* Decode to 3 bytes */
        output[output_pos++] = (v0 << 2) | (v1 >> 4);

        if (i + 2 < input_len) {
            output[output_pos++] = (v1 << 4) | (v2 >> 2);
        }

        if (i + 3 < input_len) {
            output[output_pos++] = (v2 << 6) | v3;
        }
    }

    return (int)output_pos;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int crypto_random_int_range(int min, int max) {
    if (min == max) {
        return min;  /* Fast path: no randomization needed */
    }

    if (min > max) {
        log_error("Invalid range: min (%d) > max (%d)", min, max);
        return min;
    }

    /* Generate unbiased random in range [min, max]
     * Uses rejection sampling to eliminate modulo bias.
     * Based on OpenBSD arc4random_uniform approach. */
    unsigned int range = (unsigned int)(max - min + 1);
    unsigned int rand_val;

    /* Calculate rejection threshold to eliminate modulo bias.
     * threshold = 2^32 % range (using unsigned wraparound) */
    unsigned int threshold = (-range) % range;

    /* Retry until we get a value that won't cause bias */
    do {
        if (crypto_random_bytes(&rand_val, sizeof(rand_val)) != 0) {
            log_error("Failed to generate random int");
            return min;  /* Fallback to min on error */
        }
    } while (rand_val < threshold);

    return min + (int)(rand_val % range);
}

int crypto_random_token(char *output, size_t output_len, size_t num_bytes) {
    if (!output || output_len == 0 || num_bytes == 0) {
        log_error("Invalid arguments to crypto_random_token");
        return -1;
    }

    /* Check output buffer is large enough */
    size_t required_size = crypto_token_encoded_size(num_bytes);
    if (output_len < required_size) {
        log_error("Output buffer too small: need %zu, have %zu", required_size, output_len);
        return -1;
    }

    /* Generate random bytes */
    unsigned char random_bytes[256];  /* Support up to 256 bytes */
    if (num_bytes > sizeof(random_bytes)) {
        log_error("Requested token too large: %zu bytes (max %zu)", num_bytes, sizeof(random_bytes));
        return -1;
    }

    if (crypto_random_bytes(random_bytes, num_bytes) != 0) {
        log_error("Failed to generate random bytes");
        return -1;
    }

    /* Encode as base64url */
    size_t encoded_len = crypto_base64url_encode(random_bytes, num_bytes, output, output_len);
    if (encoded_len == 0) {
        log_error("Failed to encode token");
        return -1;
    }

    /* Zero out random bytes (defense in depth — OPENSSL_cleanse resists compiler elimination) */
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));

    return (int)encoded_len;
}
