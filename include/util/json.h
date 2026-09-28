#ifndef UTIL_JSON_H
#define UTIL_JSON_H

#include <stddef.h>

/*
 * JSON Utility Functions
 *
 * Simple JSON parsing helpers for request body processing.
 * Not a full JSON parser - handles basic {"key":"value"} format.
 */

/*
 * json_unescape - Unescape JSON string escape sequences in-place
 *
 * Processes: \", \\, \/, \t, \n, \r, \b, \f, and \uXXXX (decoded to UTF-8, surrogate
 * pairs joined). Modifies string in-place (always shrinks or stays same size).
 *
 * Parameters:
 *   str - String to unescape (modified in place)
 *
 * Returns: 0 on success; -1 on an escape that is invalid or refused (\u0000, a
 *          lone surrogate, a truncated or non-hex \u, an unknown escape letter).
 *          On -1 the string's contents are unspecified and must not be used.
 */
int json_unescape(char *str);

/*
 * json_escapes_valid - Does every string in this JSON text unescape cleanly?
 *
 * Applies json_unescape's rules to every string literal (keys included).
 * Checked once per request, before any field is read: json_get_string refuses
 * a bad value field by field, which for an OPTIONAL field is indistinguishable
 * from "not sent" and would let the rest of the request proceed without it.
 *
 * Returns: 1 if valid (or no strings at all), 0 on any refused escape
 */
int json_escapes_valid(const char *json);

/*
 * json_get_string - Extract string value from JSON body
 *
 * Very simple parser - only handles basic {"key":"value"} format.
 * Unescapes standard JSON escape sequences.
 *
 * Parameters:
 *   json - JSON string to parse
 *   key  - Key to search for
 *
 * Returns: Newly allocated string (caller must free), or NULL if not found or
 *          if the value contains an escape json_unescape refuses
 */
char *json_get_string(const char *json, const char *key);

/*
 * json_get_int - Extract integer value from JSON body
 *
 * Parameters:
 *   json      - JSON string to parse
 *   key       - Key to search for
 *   out_value - Output: parsed integer value
 *
 * Returns: 0 on success, -1 if key not found or value not an integer
 */
int json_get_int(const char *json, const char *key, int *out_value);

/*
 * json_get_bool - Extract boolean value from JSON body
 *
 * Parses true, false, or null values.
 *
 * Parameters:
 *   json      - JSON string to parse
 *   key       - Key to search for
 *   out_value - Output: 1 for true, 0 for false/null
 *
 * Returns: 0 on success, -1 if key not found or value not a boolean
 */
int json_get_bool(const char *json, const char *key, int *out_value);

/*
 * json_escape - Escape string for JSON output
 *
 * Escapes: " \ and control characters (0x00-0x1F) per RFC 8259.
 *
 * Parameters:
 *   dst      - Destination buffer
 *   dst_size - Size of destination buffer
 *   src      - Source string to escape
 *
 * Returns: Number of bytes written (excluding null terminator)
 */
size_t json_escape(char *dst, size_t dst_size, const char *src);

/*
 * json_escaped_len - Exact byte length of the JSON-escaped form of src
 *
 * Counts what json_escape() would write, excluding the null terminator, using
 * the same escape table. A buffer of json_escaped_len(src) + 1 bytes holds the
 * result exactly.
 *
 * Callers need this because json_escape() cannot report truncation: it clamps
 * to dst_size and its return value is therefore always < dst_size, so testing
 * that return against the buffer size detects nothing. Measure first, then
 * escape.
 *
 * Parameters:
 *   src - Source string to measure (NULL returns 0)
 *
 * Returns: Bytes the escaped form requires, excluding the null terminator
 */
size_t json_escaped_len(const char *src);

/* ============================================================================
 * JsonBuf - Dynamic JSON response builder
 *
 * Eliminates silent truncation from fixed-size snprintf buffers.
 * Grows automatically (doubling) up to JSONBUF_MAX_CAP.
 * Ownership transfer via jsonbuf_to_response avoids extra malloc+memcpy.
 * ============================================================================ */

#define JSONBUF_MAX_CAP (1024 * 1024)  /* 1MB safety cap */

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int error;  /* set if growth fails */
} JsonBuf;

/*
 * jsonbuf_new - Create a new JSON buffer with given initial capacity
 *
 * Use sensible hints: 2048 for single objects, 4096 + count * 512 for arrays.
 * Returns NULL on malloc failure.
 */
JsonBuf *jsonbuf_new(size_t initial_cap);

/*
 * jsonbuf_appendf - Append formatted text to the buffer
 *
 * Grows buffer automatically if needed. On growth failure, sets jb->error
 * and subsequent appends become no-ops (no crash, checked at to_response).
 */
void jsonbuf_appendf(JsonBuf *jb, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * jsonbuf_append_escaped - Append a JSON-escaped string value
 *
 * Escapes the string per RFC 8259 and appends directly into the buffer.
 * Uses the same escape table as json_escape().
 */
void jsonbuf_append_escaped(JsonBuf *jb, const char *src);

/*
 * jsonbuf_free - Free a JsonBuf without creating a response
 *
 * Use only for error paths where you need to abandon the buffer.
 */
void jsonbuf_free(JsonBuf *jb);

#endif /* UTIL_JSON_H */
