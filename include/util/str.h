#ifndef STR_H
#define STR_H

#include <stddef.h>  /* for size_t */

/*
 * String Utilities - Safe string operations
 *
 * These functions prevent common C string bugs like buffer overflows.
 * They replace "dangerous" standard library functions like strcpy.
 */

/*
 * str_copy - Safely copy string to buffer
 *
 * Copies src to dst, ensuring dst is null-terminated.
 * Never writes past dst_size.
 * Avoid setting dst_size higher than the real reserved range length of input dst (not checked)!
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer (including space for null terminator)
 *   src      - Source string to copy
 *
 * Returns: Number of bytes written (INCLUDING null terminator)
 *
 * Example:
 *   char buf[8];
 *   size_t ret = str_copy(buf, sizeof(buf), "Hello World");
 *   printf("%zu: '%s'\n", ret, buf);  // Truncates to "Hello W"
 */
size_t str_copy(char *dst, size_t dst_size, const char *src);

/*
 * str_appendf - Append a formatted string to a fixed buffer, advancing an offset
 *
 * Replaces the unsafe idiom
 *
 *     pos += snprintf(buf + pos, sizeof(buf) - pos, ...);
 *
 * snprintf returns the length it WOULD have written, so one truncating call pushes pos
 * past the end of the buffer; the next then forms `buf + pos` out of bounds and
 * underflows `sizeof(buf) - pos` to a huge size_t, giving an unbounded write.
 *
 * On success returns 0 and advances *pos past the bytes written. On truncation or
 * encoding error returns -1, restores the terminator at *pos, and leaves *pos
 * unchanged — so the buffer holds exactly those appends that succeeded, and a caller
 * that ignores the return value still cannot walk off the end.
 *
 * Parameters:
 *   buf  - Destination buffer
 *   size - Total size of buf (including space for the null terminator)
 *   pos  - In/out: current offset into buf; advanced only on success
 *   fmt  - printf-style format string
 *
 * Returns: 0 on success, -1 on truncation, encoding error, or bad arguments
 *
 * Example:
 *   char buf[64];
 *   size_t pos = 0;
 *   if (str_appendf(buf, sizeof(buf), &pos, "id=%d", id) != 0)     return -1;
 *   if (str_appendf(buf, sizeof(buf), &pos, "&name=%s", name) != 0) return -1;
 */
int str_appendf(char *buf, size_t size, size_t *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/*
 * str_dup - Duplicate a string (allocates memory)
 *
 * Creates a copy of the string in heap memory.
 * Caller MUST free the returned pointer when done!
 *
 * Parameters:
 *   src - String to duplicate
 *
 * Returns: Pointer to newly allocated string, or NULL if malloc fails
 *
 * Example:
 *   char *copy = str_dup("Clone");
 *   if (copy == NULL) { printf("ERROR: OOM?\n"); }
 *   printf("At %p (%zu bytes): '%s'\n", (void*)copy, strlen(copy) + 1, copy);
 *   free(copy);  // MUST free when done!
 */
char *str_dup(const char *src);

/*
 * str_split - Split string by delimiter
 *
 * Splits a string into parts based on a delimiter character.
 * Allocates an array of strings (each part is also allocated).
 *
 * Parameters:
 *   str   - String to split
 *   delim - Delimiter character (e.g., ',' or ' ')
 *   count - Output parameter: receives number of parts
 *
 * Returns: Array of strings (NULL-terminated array), or NULL if malloc fails
 *
 * IMPORTANT: Caller must free BOTH the array AND each string!
 *
 * Example:
 *   int count;
 *   char **parts = str_split("typical,csv,header,row", ',', &count);
 *   if (parts == NULL) { printf("ERROR: OOM?\n"); }
 *   printf("At %p (%d parts):\n", (void*)parts, count);
 *   for (int i = 0; i < count; i++) {
 *       printf("  part %d: '%s' (at %p)\n", i, parts[i], (void*)parts[i]);
 *       free(parts[i]);  // Free each part
 *   }
 *   free(parts);  // Free the array itself
 */
char **str_split(const char *str, char delim, int *count);

/*
 * str_url_encode - URL-encode a string (percent-encoding per RFC 3986)
 *
 * Encodes special characters for safe use in URL query parameters.
 * Encodes everything except: A-Z a-z 0-9 - _ . ~
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer
 *   src      - Source string to encode
 *
 * Returns: Number of bytes written (excluding null terminator), or -1 if buffer too small
 *
 * Example:
 *   char buf[256];
 *   str_url_encode(buf, sizeof(buf), "/authorize?client_id=abc&state=xyz");
 *   // Result: "%2Fauthorize%3Fclient_id%3Dabc%26state%3Dxyz"
 */
int str_url_encode(char *dst, size_t dst_size, const char *src);

/*
 * str_url_decode - URL-decode a string (percent-decoding)
 *
 * Decodes percent-encoded characters (%XX) back to their original form.
 * Also converts '+' to space (form encoding compatibility).
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer
 *   src      - Source string to decode
 *
 * Returns: Number of bytes written (excluding null terminator), or -1 if buffer too small
 *
 * Example:
 *   char buf[256];
 *   str_url_decode(buf, sizeof(buf), "http%3A%2F%2Flocalhost%3A8080%2Fapi");
 *   // Result: "http://localhost:8080/api"
 */
int str_url_decode(char *dst, size_t dst_size, const char *src);

/*
 * str_to_lower - Convert string to lowercase
 *
 * Copies src to dest, converting each character to lowercase.
 * Result is always null-terminated.
 *
 * Parameters:
 *   dest      - Output buffer
 *   dest_size - Size of output buffer
 *   src       - Input string
 */
void str_to_lower(char *dest, size_t dest_size, const char *src);

/*
 * memmem_nocase - Case-insensitive search for byte pattern in memory
 *
 * Searches for the first occurrence of needle in haystack, comparing
 * alphabetic bytes (A-Z, a-z) case-insensitively. Non-alphabetic bytes
 * (including \r, \n, and punctuation) are compared exactly.
 *
 * Parameters:
 *   haystack      - Buffer to search in
 *   haystack_len  - Length of haystack in bytes
 *   needle        - Pattern to search for
 *   needle_len    - Length of needle in bytes
 *
 * Returns: Pointer to first match within haystack, or NULL if not found
 *
 * Example:
 *   // Finds "\r\ntransfer-encoding" regardless of casing
 *   void *pos = memmem_nocase(buf, buf_len, "\r\nTransfer-Encoding", 19);
 */
void *memmem_nocase(const void *haystack, size_t haystack_len,
                    const void *needle, size_t needle_len);

/*
 * str_html_escape - Escape a string for safe embedding in HTML
 *
 * Escapes &, <, >, ", ' — covers both element content and attribute values.
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer
 *   src      - Source string to escape
 *
 * Returns: Number of bytes written (excluding NUL), or 0 if buffer too small
 */
size_t str_html_escape(char *dst, size_t dst_size, const char *src);

#endif /* STR_H */
