#include "util/json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <limits.h>

void json_unescape(char *str) {
    if (!str) return;

    const char *read = str;
    char *write = str;

    while (*read) {
        if (*read == '\\' && *(read + 1)) {
            /* Process escape sequence */
            read++;  /* Skip backslash */
            switch (*read) {
                case '"':  *write++ = '"';  break;
                case '\\': *write++ = '\\'; break;
                case 't':  *write++ = '\t'; break;
                case 'n':  *write++ = '\n'; break;
                case 'r':  *write++ = '\r'; break;
                case 'b':  *write++ = '\b'; break;
                case 'f':  *write++ = '\f'; break;
                case 'u': {
                    /* Decode \uXXXX: accept printable ASCII, skip everything else */
                    if (!read[1] || !read[2] || !read[3] || !read[4]) {
                        /* Truncated \uXXXX — advance to end of string */
                        while (read[1]) read++;
                        break;
                    }
                    unsigned int cp = 0;
                    int i;
                    for (i = 0; i < 4; i++) {
                        char c = read[1 + i];
                        if (c >= '0' && c <= '9')      cp = (cp << 4) | (c - '0');
                        else if (c >= 'a' && c <= 'f') cp = (cp << 4) | (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') cp = (cp << 4) | (c - 'A' + 10);
                        else { cp = 0; break; }  /* Malformed — drop it */
                    }
                    read += 4;  /* Skip the 4 hex digits */
                    if (cp >= 0x20 && cp <= 0x7E) {
                        *write++ = (char)cp;  /* Printable ASCII */
                    }
                    /* else: control chars, null, non-ASCII — silently dropped */
                    break;
                }
                default:
                    /* Unknown escape - keep backslash and char */
                    *write++ = '\\';
                    *write++ = *read;
                    break;
            }
            read++;
        } else {
            /* Regular character */
            *write++ = *read++;
        }
    }
    *write = '\0';
}

/*
 * Skip past a JSON string starting at the opening quote.
 * Correctly handles escaped quotes including \\\".
 * Returns pointer to character AFTER the closing quote, or NULL on error.
 */
static const char *skip_json_string(const char *p) {
    if (*p != '"') return NULL;
    p++;  /* Skip opening quote */

    while (*p) {
        if (*p == '\\') {
            if (!*(p + 1)) return NULL;  /* Trailing backslash, malformed */
            p += 2;  /* Skip escape sequence */
            continue;
        }
        if (*p == '"') return p + 1;  /* Past closing quote */
        p++;
    }
    return NULL;  /* Unterminated string */
}

/*
 * Find a JSON key at the top-level object only (depth 1).
 * Tracks brace/bracket depth so nested keys are ignored.
 * Returns pointer to the opening quote of the matched key, or NULL.
 */
static const char *find_json_key(const char *json, const char *key) {
    size_t key_len = strlen(key);
    const char *p = json;
    int depth = 0;

    while (*p) {
        if (*p == '"') {
            /* Only match keys at depth 1 (inside the top-level object) */
            if (depth == 1 &&
                strncmp(p + 1, key, key_len) == 0 && p[1 + key_len] == '"') {
                /* Verify a colon follows (skip whitespace) */
                const char *after = p + 1 + key_len + 1;
                while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
                if (*after == ':') return p;
            }
            /* Skip past this string (whether it matched or not) */
            p = skip_json_string(p);
            if (!p) return NULL;
        } else if (*p == '{' || *p == '[') {
            depth++;
            p++;
        } else if (*p == '}' || *p == ']') {
            depth--;
            p++;
        } else {
            p++;
        }
    }
    return NULL;
}

/*
 * Find end of a JSON string value starting at the opening quote.
 * Returns pointer to the closing quote, correctly handling escaped quotes.
 */
static const char *find_string_end(const char *start) {
    const char *p = start;
    while (*p) {
        if (*p == '\\') {
            if (!*(p + 1)) return NULL;  /* Trailing backslash, malformed */
            p += 2;  /* Skip escape sequence */
            continue;
        }
        if (*p == '"') return p;
        p++;
    }
    return NULL;
}

char *json_get_string(const char *json, const char *key) {
    if (!json || !key) return NULL;

    const char *key_pos = find_json_key(json, key);
    if (!key_pos) return NULL;

    /* Find the colon after the key */
    const char *colon = strchr(key_pos, ':');
    if (!colon) return NULL;

    /* Skip whitespace after colon */
    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n' || *value_start == '\r') {
        value_start++;
    }

    /* Check if value is a string (starts with ") */
    if (*value_start != '"') return NULL;
    value_start++;  /* Skip opening quote */

    /* Find closing quote (correctly handles escaped quotes) */
    const char *value_end = find_string_end(value_start);
    if (!value_end) return NULL;

    /* Extract the value */
    size_t len = value_end - value_start;
    char *value = malloc(len + 1);
    if (!value) return NULL;

    memcpy(value, value_start, len);
    value[len] = '\0';

    /* Unescape JSON escape sequences */
    json_unescape(value);

    return value;
}

int json_get_int(const char *json, const char *key, int *out_value) {
    if (!json || !key || !out_value) return -1;

    const char *key_pos = find_json_key(json, key);
    if (!key_pos) return -1;

    /* Find the colon after the key */
    const char *colon = strchr(key_pos, ':');
    if (!colon) return -1;

    /* Skip whitespace after colon */
    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n' || *value_start == '\r') {
        value_start++;
    }

    /* Parse integer */
    char *endptr;
    long val = strtol(value_start, &endptr, 10);
    if (endptr == value_start) return -1;  /* No digits found */

    if (val < INT_MIN || val > INT_MAX) return -1;  /* Overflow */
    *out_value = (int)val;
    return 0;
}

int json_get_bool(const char *json, const char *key, int *out_value) {
    if (!json || !key || !out_value) return -1;

    const char *key_pos = find_json_key(json, key);
    if (!key_pos) return -1;

    /* Find the colon after the key */
    const char *colon = strchr(key_pos, ':');
    if (!colon) return -1;

    /* Skip whitespace after colon */
    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n' || *value_start == '\r') {
        value_start++;
    }

    /* Check that character after a JSON keyword is a valid delimiter */
    #define IS_JSON_DELIM(c) ((c) == ',' || (c) == '}' || (c) == ']' || \
                              (c) == ' ' || (c) == '\t' || (c) == '\n' || \
                              (c) == '\r' || (c) == '\0')

    /* Parse boolean value */
    if (strncmp(value_start, "true", 4) == 0 && IS_JSON_DELIM(value_start[4])) {
        *out_value = 1;
        return 0;
    } else if (strncmp(value_start, "false", 5) == 0 && IS_JSON_DELIM(value_start[5])) {
        *out_value = 0;
        return 0;
    } else if (strncmp(value_start, "null", 4) == 0 && IS_JSON_DELIM(value_start[4])) {
        *out_value = 0;
        return 0;
    }

    #undef IS_JSON_DELIM

    return -1;  /* Not a valid boolean */
}

/* ============================================================================
 * json_escape - Escape string for JSON output
 *
 * Escapes: " \ and control characters (0x00-0x1F) per RFC 8259
 * Returns: Number of bytes written (excluding null terminator)
 * ============================================================================ */

/* Lookup table: maps byte -> escape sequence + length */
typedef struct {
    const char *seq;
    unsigned char len;
} EscapeEntry;

static const EscapeEntry JSON_ESCAPE_TABLE[256] = {
    [0x00] = {"\\u0000", 6}, [0x01] = {"\\u0001", 6}, [0x02] = {"\\u0002", 6},
    [0x03] = {"\\u0003", 6}, [0x04] = {"\\u0004", 6}, [0x05] = {"\\u0005", 6},
    [0x06] = {"\\u0006", 6}, [0x07] = {"\\u0007", 6}, [0x08] = {"\\b", 2},
    [0x09] = {"\\t", 2},     [0x0A] = {"\\n", 2},     [0x0B] = {"\\u000b", 6},
    [0x0C] = {"\\f", 2},     [0x0D] = {"\\r", 2},     [0x0E] = {"\\u000e", 6},
    [0x0F] = {"\\u000f", 6}, [0x10] = {"\\u0010", 6}, [0x11] = {"\\u0011", 6},
    [0x12] = {"\\u0012", 6}, [0x13] = {"\\u0013", 6}, [0x14] = {"\\u0014", 6},
    [0x15] = {"\\u0015", 6}, [0x16] = {"\\u0016", 6}, [0x17] = {"\\u0017", 6},
    [0x18] = {"\\u0018", 6}, [0x19] = {"\\u0019", 6}, [0x1A] = {"\\u001a", 6},
    [0x1B] = {"\\u001b", 6}, [0x1C] = {"\\u001c", 6}, [0x1D] = {"\\u001d", 6},
    [0x1E] = {"\\u001e", 6}, [0x1F] = {"\\u001f", 6},
    ['"']  = {"\\\"", 2},
    ['\\'] = {"\\\\", 2},
};

size_t json_escape(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) return 0;

    const unsigned char *p = (const unsigned char *)src;
    size_t src_len = strlen(src);

    /* Check if escaping needed */
    bool needs_escape = false;
    for (size_t i = 0; i < src_len; i++) {
        if (JSON_ESCAPE_TABLE[p[i]].seq != NULL) {
            needs_escape = true;
            break;
        }
    }

    if (!needs_escape) {
        /* No escaping - direct copy */
        if (src_len + 1 <= dst_size) {
            memcpy(dst, src, src_len + 1);
            return src_len;
        }
        memcpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
        return dst_size - 1;
    }

    /* Escape using lookup table */
    size_t written = 0;
    dst_size--;

    while (*p && written < dst_size) {
        const EscapeEntry *entry = &JSON_ESCAPE_TABLE[*p];

        if (entry->seq) {
            if (written + entry->len > dst_size) break;
            memcpy(dst + written, entry->seq, entry->len);
            written += entry->len;
        } else {
            dst[written++] = *p;
        }
        p++;
    }

    dst[written] = '\0';
    return written;
}

/* ============================================================================
 * JsonBuf - Dynamic JSON response builder
 * ============================================================================ */

static void jsonbuf_grow(JsonBuf *jb, size_t needed) {
    if (jb->error) return;

    size_t new_cap = jb->cap;
    while (new_cap < needed) {
        if (new_cap > JSONBUF_MAX_CAP / 2) {
            jb->error = 1;
            return;
        }
        new_cap *= 2;
    }

    if (new_cap > JSONBUF_MAX_CAP) {
        jb->error = 1;
        return;
    }

    char *new_buf = realloc(jb->buf, new_cap);
    if (!new_buf) {
        jb->error = 1;
        return;
    }

    jb->buf = new_buf;
    jb->cap = new_cap;
}

JsonBuf *jsonbuf_new(size_t initial_cap) {
    if (initial_cap < 256) initial_cap = 256;
    if (initial_cap > JSONBUF_MAX_CAP) initial_cap = JSONBUF_MAX_CAP;

    JsonBuf *jb = malloc(sizeof(JsonBuf));
    if (!jb) return NULL;

    jb->buf = malloc(initial_cap);
    if (!jb->buf) {
        free(jb);
        return NULL;
    }

    jb->cap = initial_cap;
    jb->len = 0;
    jb->buf[0] = '\0';
    jb->error = 0;
    return jb;
}

void jsonbuf_appendf(JsonBuf *jb, const char *fmt, ...) {
    if (!jb || jb->error) return;

    va_list ap;
    va_start(ap, fmt);
    size_t avail = jb->cap - jb->len;
    int n = vsnprintf(jb->buf + jb->len, avail, fmt, ap);
    va_end(ap);

    if (n < 0) {
        jb->error = 1;
        return;
    }

    if ((size_t)n >= avail) {
        /* Grow and retry */
        jsonbuf_grow(jb, jb->len + (size_t)n + 1);
        if (jb->error) return;

        va_start(ap, fmt);
        vsnprintf(jb->buf + jb->len, jb->cap - jb->len, fmt, ap);
        va_end(ap);
    }

    jb->len += (size_t)n;
}

void jsonbuf_append_escaped(JsonBuf *jb, const char *src) {
    if (!jb || jb->error || !src) return;

    size_t src_len = strlen(src);
    /* Worst case: every char becomes \uXXXX (6x) */
    size_t max_escaped = src_len * 6 + 1;
    size_t needed = jb->len + max_escaped;

    if (needed > jb->cap) {
        jsonbuf_grow(jb, needed);
        if (jb->error) return;
    }

    /* Write escaped content directly into buffer */
    size_t written = json_escape(jb->buf + jb->len, jb->cap - jb->len, src);
    jb->len += written;
}

void jsonbuf_free(JsonBuf *jb) {
    if (!jb) return;
    free(jb->buf);
    free(jb);
}
