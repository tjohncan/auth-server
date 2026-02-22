#include "util/str.h"
#include <string.h>  /* for strlen */
#include <stdlib.h>  /* for malloc, free */
#include <ctype.h>   /* for tolower */

/* ============================================================================
 * str_copy - Copy a string to already-allocated memory
 * ============================================================================

"Safely" copy the first (`dst_size`-1) characters of string `src` to `dst`.

*/
size_t str_copy(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) { return 0; }
    if (!src) { dst[0] = '\0'; return 0; }

    /* Calculate how many bytes to copy */
    size_t src_len = strlen(src);
    size_t copy_len = (src_len >= dst_size) ? (dst_size - 1) : src_len;

    memcpy(dst, src, copy_len);  /* Copy the bytes (quickly!) */
    dst[copy_len] = '\0';  /* Terminate */
    return (copy_len + 1);
}

/*
 * ============================================================================
 * str_dup - Duplicate a string (allocating new memory)
 * ============================================================================

Create and return a new pointer with data copied from `src` string.

Memory ownership: The CALLER owns the returned pointer and must free it!

*/
char *str_dup(const char *src) {
    if (!src) return NULL;
    size_t bytes_needed = strlen(src) + 1;  /* Extra byte for null terminator */

    /* Allocate memory on the heap */
    char *copy = malloc(bytes_needed);

    /* Always check if malloc succeeded! */
    if (copy == NULL) {
        return NULL;  /* Out of memory - caller should check for this */
    }

    memcpy(copy, src, bytes_needed);
    return copy;
}

/*
 * ============================================================================
 * str_split - Split string by delimiter
 * ============================================================================

Given a string `str` and a single character `delim`, return an array of substrings.

Each output array element represents a portion of `src` "between delimiters", in order.
The input/output `count` parameter is updated after execution, reflecting the number of elements.

*/
char **str_split(const char *str, char delim, int *count) {
    /* Determine number of output elements */
    int num_parts = 1;  /* Always at least 1 part (even if empty string) */
    for (const char *p = str; *p != '\0'; p++) {
        if (*p == delim) {
            num_parts++;
        }
    }

    /* Allocate array of pointers (with room for NULL terminator) */
    char **result = malloc((num_parts + 1) * sizeof(char *));
    if (result == NULL) { return NULL; }  /* Out of memory */

    /* Extract each part */
    int part_index = 0;
    const char *start = str;  /* Start of current part */
    for (const char *p = str; ; p++) {
        if (*p == delim || *p == '\0') {
            size_t part_len = p - start;
            result[part_index] = malloc(part_len + 1);
            if (result[part_index] == NULL) {
                /* Out of memory! Clean up what we've allocated so far */
                for (int i = 0; i < part_index; i++) { free(result[i]); }
                free(result);
                return NULL;
            }

            memcpy(result[part_index], start, part_len);
            result[part_index][part_len] = '\0';
            part_index++;

            if (*p == '\0') { break; }

            start = p + 1;
        }
    }

    result[part_index] = NULL;  /* Null-terminate the array of pointers */
    *count = num_parts;  /* Set output parameter */

    return result;
}


/*******/

int str_url_encode(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0 || !src) {
        return -1;
    }

    size_t written = 0;
    const unsigned char *p = (const unsigned char *)src;

    while (*p && written < dst_size - 1) {
        /* Check if character is unreserved (RFC 3986: A-Z a-z 0-9 - _ . ~) */
        if ((*p >= 'A' && *p <= 'Z') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            /* Unreserved - copy as-is */
            dst[written++] = *p;
        } else {
            /* Reserved or special - percent-encode */
            if (written + 3 > dst_size - 1) {
                /* Not enough space for %XX */
                dst[written] = '\0';
                return -1;
            }
            dst[written++] = '%';
            dst[written++] = "0123456789ABCDEF"[*p >> 4];
            dst[written++] = "0123456789ABCDEF"[*p & 0x0F];
        }
        p++;
    }

    if (*p) {
        /* Source string didn't fit */
        dst[written] = '\0';
        return -1;
    }

    dst[written] = '\0';
    return (int)written;
}


/*******/

int str_url_decode(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0 || !src) {
        return -1;
    }

    size_t written = 0;
    const char *p = src;

    while (*p && written < dst_size - 1) {
        if (*p == '%' && p[1] && p[2]) {
            /* Decode %XX hex sequence */
            char hex[3] = {p[1], p[2], '\0'};
            char *end;
            long val = strtol(hex, &end, 16);

            if (end == hex + 2) {
                /* Reject NULL byte injection (%00) */
                if (val == 0) return -1;
                dst[written++] = (char)val;
                p += 3;
            } else {
                /* Invalid hex - copy literally */
                dst[written++] = *p++;
            }
        } else if (*p == '+') {
            /* Convert '+' to space (form encoding) */
            dst[written++] = ' ';
            p++;
        } else {
            /* Copy as-is */
            dst[written++] = *p++;
        }
    }

    if (*p) {
        /* Source string didn't fit */
        dst[written] = '\0';
        return -1;
    }

    dst[written] = '\0';
    return (int)written;
}


/*******/

void str_to_lower(char *dest, size_t dest_size, const char *src) {
    if (!dest || dest_size == 0) return;
    size_t i;
    for (i = 0; src[i] && i < dest_size - 1; i++) {
        dest[i] = (char)tolower((unsigned char)src[i]);
    }
    dest[i] = '\0';
}


/*******/

void *memmem_nocase(const void *haystack, size_t haystack_len,
                    const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (needle_len > haystack_len) return NULL;

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    size_t last_start = haystack_len - needle_len;
    for (size_t i = 0; i <= last_start; i++) {
        size_t j;
        for (j = 0; j < needle_len; j++) {
            unsigned char hc = h[i + j];
            unsigned char nc = n[j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
        }
        if (j == needle_len) return (void *)(h + i);
    }
    return NULL;
}
