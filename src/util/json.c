#include "util/json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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
                while (*after == ' ' || *after == '\t' || *after == '\n') after++;
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
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n') {
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
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n') {
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
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n') {
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
