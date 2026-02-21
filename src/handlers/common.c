#include "handlers.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/queries/org.h"
#include "util/data.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/*
 * Common response helpers for handlers
 *
 * These provide application-specific shortcuts (assuming JSON responses)
 * while keeping the HTTP layer generic.
 */

/*
 * json_escape - Escape string for JSON output
 *
 * Escapes: " \ and control characters (0x00-0x1F) per RFC 8259
 * Returns: Number of bytes written (excluding null terminator)
 */

/* Lookup table: maps byte → escape sequence + length */
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

HttpResponse *require_content_type(const HttpRequest *req, const char *expected) {
    const char *ct = http_request_get_header(req, "Content-Type");
    if (!ct || strncmp(ct, expected, strlen(expected)) != 0) {
        return response_json_error(415, "Unsupported Media Type");
    }
    return NULL;
}

HttpResponse *response_json_ok(const char *json) {
    HttpResponse *resp = http_response_new(200);
    if (resp) {
        http_response_set(resp, CONTENT_TYPE_JSON, json);
    }
    return resp;
}

HttpResponse *response_json_error(int status_code, const char *message) {
    HttpResponse *resp = http_response_new(status_code);
    if (resp) {
        char escaped[256];
        char json[512];

        /* Escape the message to prevent JSON injection */
        json_escape(escaped, sizeof(escaped), message);

        snprintf(json, sizeof(json), "{\"error\":\"%s\"}", escaped);
        http_response_set(resp, CONTENT_TYPE_JSON, json);
    }
    return resp;
}

char *http_query_get_param(const char *query_string, const char *key) {
    if (!query_string || !key) return NULL;

    size_t key_len = strlen(key);
    const char *p = query_string;

    /* Scan through query string looking for exact key matches */
    while (*p) {
        /* Check if current position matches key followed by '=' */
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            /* Verify we're at start or after '&' (exact parameter boundary) */
            if (p == query_string || *(p - 1) == '&') {
                /* Found exact match - extract value */
                const char *value_start = p + key_len + 1;  /* +1 to skip '=' */
                const char *value_end = strchr(value_start, '&');

                size_t len = value_end ? (size_t)(value_end - value_start) : strlen(value_start);

                char *value = malloc(len + 1);
                if (!value) return NULL;

                memcpy(value, value_start, len);
                value[len] = '\0';
                return value;
            }
        }

        /* Move to next parameter */
        p = strchr(p, '&');
        if (!p) break;
        p++;  /* Skip the '&' */
    }

    return NULL;
}

char *http_cookie_get_value(const char *cookie_header, const char *name) {
    if (!cookie_header || !name) return NULL;

    char search[128];
    snprintf(search, sizeof(search), "%s=", name);
    size_t search_len = strlen(search);

    const char *p = cookie_header;
    const char *cookie = NULL;

    /* Find exact cookie name match (not substring of another cookie name) */
    while ((p = strstr(p, search)) != NULL) {
        /* Verify we're at start of header or after "; " separator */
        if (p == cookie_header || (*(p - 1) == ' ' && p >= cookie_header + 2 && *(p - 2) == ';')) {
            cookie = p;
            break;
        }
        p += search_len;
    }

    if (!cookie) return NULL;

    const char *value_start = cookie + search_len;
    const char *value_end = strchr(value_start, ';');

    size_t len;
    if (value_end) {
        len = value_end - value_start;
    } else {
        len = strlen(value_start);
    }

    char *value = malloc(len + 1);
    if (!value) return NULL;

    memcpy(value, value_start, len);
    value[len] = '\0';

    return value;
}

int parse_query_int(const char *query_string, const char *param_name,
                   int default_value, int min_value, int max_value) {
    if (!query_string) return default_value;

    char *param_value = http_query_get_param(query_string, param_name);
    if (!param_value) return default_value;

    char *endptr;
    long parsed = strtol(param_value, &endptr, 10);
    int value = (endptr == param_value) ? default_value : (int)parsed;
    free(param_value);

    if (value < min_value) return min_value;
    if (value > max_value) return max_value;
    return value;
}

int parse_query_bool(const char *query_string, const char *param_name, int *out_value) {
    if (!query_string) return -1;

    char *param_value = http_query_get_param(query_string, param_name);
    if (!param_value) return -1;

    if (strcmp(param_value, "true") == 0 || strcmp(param_value, "1") == 0) {
        *out_value = 1;
    } else if (strcmp(param_value, "false") == 0 || strcmp(param_value, "0") == 0) {
        *out_value = 0;
    } else {
        free(param_value);
        return -1;
    }

    free(param_value);
    return 0;
}

int try_org_key_auth(const HttpRequest *req, long long *out_org_pin, long long *out_key_pin) {
    db_handle_t *db = db_pool_get_connection();
    if (!db) {
        log_error("Failed to get database connection for org key auth");
        return -1;
    }

    const char *key_id_hex = http_request_get_header(req, "X-Org-Key-Id");
    const char *key_secret = http_request_get_header(req, "X-Org-Key-Secret");

    if (!key_id_hex || !key_secret) {
        return -1;
    }

    unsigned char key_id[16];
    if (hex_to_bytes(key_id_hex, key_id, 16) != 0) {
        log_error("Invalid X-Org-Key-Id format");
        return -1;
    }

    long long org_pin, key_pin;
    if (organization_key_verify(db, key_id, key_secret, &org_pin, &key_pin) != 0) {
        log_error("Organization key verification failed");
        return -1;
    }

    *out_org_pin = org_pin;
    *out_key_pin = key_pin;
    return 0;
}
