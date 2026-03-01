#include "util/data.h"
#include <string.h>

static const char hex_table[] = "0123456789abcdef";

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int bytes_to_hex(const unsigned char *bytes, size_t len, char *out, size_t out_size) {
    /* Check buffer is large enough for hex output + null terminator */
    if (out_size < len * 2 + 1) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_table[bytes[i] >> 4];
        out[i * 2 + 1] = hex_table[bytes[i] & 0x0F];
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
        int hi = hex_nibble(stripped[i * 2]);
        int lo = hex_nibble(stripped[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;  /* Invalid hex character */
        }
        bytes[i] = (unsigned char)((hi << 4) | lo);
    }

    return 0;
}
