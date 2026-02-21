#include "util/data.h"
#include <string.h>
#include <stdio.h>

int bytes_to_hex(const unsigned char *bytes, size_t len, char *out, size_t out_size) {
    /* Check buffer is large enough for hex output + null terminator */
    if (out_size < len * 2 + 1) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        snprintf(out + (i * 2), out_size - (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
    return 0;
}

int hex_to_bytes(const char *hex, unsigned char *bytes, size_t byte_len) {
    /* Largest expected input: 256-byte key = 512 hex chars + null */
    if (byte_len > 256) {
        return -1;  /* Unreasonably large */
    }

    /* Strip hyphens into fixed buffer (allows UUID format with dashes) */
    char stripped[513];
    size_t j = 0;

    for (size_t i = 0; hex[i] && j < byte_len * 2; i++) {
        if (hex[i] != '-') {
            stripped[j++] = hex[i];
        }
    }
    stripped[j] = '\0';

    /* Must have exactly byte_len * 2 hex characters after stripping hyphens */
    if (j != byte_len * 2) {
        return -1;  /* Invalid hex length */
    }

    /* Parse the stripped hex string */
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(stripped + (i * 2), "%2x", &byte_val) != 1) {
            return -1;  /* Invalid hex character */
        }
        bytes[i] = (unsigned char)byte_val;
    }

    return 0;
}
