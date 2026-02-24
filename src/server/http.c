#include "server/http.h"
#include "util/str.h"
#include <string.h>
#include <strings.h>  /* for strcasecmp */
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <arpa/inet.h>  /* for INET6_ADDRSTRLEN */

/* ============================================================================
 * HTTP Request Parsing - Zero-copy, fast, minimal
 * ============================================================================ */

/* HTTP version this server supports */
#define HTTP_VERSION "HTTP/1.0"

/*
 * Parse HTTP method from string
 */
static HttpMethod parse_method(const char *method_str) {
    if (strcmp(method_str, "GET") == 0)     return HTTP_GET;
    if (strcmp(method_str, "HEAD") == 0)    return HTTP_HEAD;
    if (strcmp(method_str, "POST") == 0)    return HTTP_POST;
    if (strcmp(method_str, "PUT") == 0)     return HTTP_PUT;
    if (strcmp(method_str, "DELETE") == 0)  return HTTP_DELETE;
    if (strcmp(method_str, "CONNECT") == 0) return HTTP_CONNECT;
    if (strcmp(method_str, "OPTIONS") == 0) return HTTP_OPTIONS;
    if (strcmp(method_str, "TRACE") == 0)   return HTTP_TRACE;
    if (strcmp(method_str, "PATCH") == 0)   return HTTP_PATCH;
    return HTTP_UNKNOWN;
}

/*
 * Find CRLF CRLF (\r\n\r\n) - marks end of headers
 *
 * Returns: Pointer to start of body, or NULL if not found
 */
static char *find_header_end(char *data, size_t length) {
    char *p = data;
    char *end = data + length;

    while (p < end - 3) {
        /* Jump to next \r using highly-optimized memchr */
        p = memchr(p, '\r', end - p - 3);
        if (!p) return NULL;
        if (p[2] == '\r' && p[1] == '\n' && p[3] == '\n') {
            return p + 4;
        }
        p++;
    }

    return NULL;
}

/*
 * Parse request line: "GET /path?query HTTP/1.0\r\n"
 *
 * Modifies buffer in place (inserts null terminators).
 */
static bool parse_request_line(char *line, HttpRequest *req) {
    /* Find first space (after method) */
    char *space1 = strchr(line, ' ');
    if (!space1) return false;
    *space1 = '\0';  /* Null-terminate method */
    req->method_str = line;
    req->method = parse_method(line);

    /* Find second space (after path) */
    char *path_start = space1 + 1;
    char *space2 = strchr(path_start, ' ');
    if (!space2) return false;
    *space2 = '\0';  /* Null-terminate path */

    /* Split path and query string */
    char *question = strchr(path_start, '?');
    if (question) {
        *question = '\0';
        req->path = path_start;
        req->query_string = question + 1;
    } else {
        req->path = path_start;
        req->query_string = NULL;
    }

    /* HTTP version - validate and discard */
    char *version_start = space2 + 1;
    char *crlf = strstr(version_start, "\r\n");
    /* crlf guaranteed to exist - find_header_end() already found \r\n\r\n */
    if (crlf) *crlf = '\0';

    /* Accept HTTP/1.0 or HTTP/1.1, but always respond with HTTP/1.0
     * HTTP/1.1 clients MUST accept HTTP/1.0 responses (RFC 7230)
     * We don't support chunked encoding or persistent connections anyway */
    if (strcmp(version_start, "HTTP/1.0") != 0 && strcmp(version_start, "HTTP/1.1") != 0) {
        return false;
    }

    return true;
}

/*
 * Parse a single header line: "Name: Value\r\n"
 *
 * Modifies buffer in place.
 */
static bool parse_header_line(char *line, HttpHeader *header) {
    /* Find colon */
    char *colon = strchr(line, ':');
    if (!colon) return false;

    *colon = '\0';  /* Null-terminate name */
    header->name = line;

    /* Skip whitespace after colon */
    char *value = colon + 1;
    while (*value == ' ' || *value == '\t') value++;

    /* Remove trailing CRLF */
    char *crlf = strstr(value, "\r\n");
    if (crlf) *crlf = '\0';

    header->value = value;
    return true;
}

/*
 * Main parser - zero-copy, modifies buffer in place
 */
HttpRequest http_request_parse(char *raw, size_t length) {
    HttpRequest req = {0};  /* Zero-initialize */
    req._raw_buffer = raw;

    if (length == 0) {
        req.method = HTTP_UNKNOWN;
        return req;
    }

    /* Find end of headers */
    char *body_start = find_header_end(raw, length);
    if (!body_start) {
        /* Incomplete request or malformed */
        req.method = HTTP_UNKNOWN;
        return req;
    }

    /* Count headers BEFORE modifying buffer */
    char *first_header = strstr(raw, "\r\n");
    if (!first_header) {
        req.method = HTTP_UNKNOWN;
        return req;
    }
    first_header += 2;

    char *scan = first_header;
    while (*scan != '\r' && *scan != '\0') {
        req.header_count++;
        scan = strstr(scan, "\r\n");
        if (!scan) break;
        scan += 2;
    }

    /* Protect resources from malicious/malformed high header counts */
    if (req.header_count > 50) {
        req.method = HTTP_UNKNOWN;
        return req;
    }

    /* NOW parse request line (modifies buffer) */
    if (!parse_request_line(raw, &req)) {
        req.method = HTTP_UNKNOWN;
        return req;
    }

    /* Allocate headers and save pointers BEFORE modifying buffer */
    if (req.header_count > 0) {
        req.headers = malloc(req.header_count * sizeof(HttpHeader));
        if (!req.headers) {
            req.method = HTTP_UNKNOWN;
            return req;
        }

        /* Save pointers to each header line (before parse_header_line modifies buffer) */
        char **header_lines = malloc(req.header_count * sizeof(char*));
        if (!header_lines) {
            free(req.headers);
            req.headers = NULL;  /* Prevent dangling pointer */
            req.method = HTTP_UNKNOWN;
            return req;
        }

        char *line_ptr = first_header;
        for (int i = 0; i < req.header_count; i++) {
            header_lines[i] = line_ptr;
            line_ptr = strstr(line_ptr, "\r\n");
            if (!line_ptr) break;
            line_ptr += 2;
        }

        /* NOW parse each header (modifies buffer) */
        for (int i = 0; i < req.header_count; i++) {
            parse_header_line(header_lines[i], &req.headers[i]);
        }

        free(header_lines);
    }

    /* Body (if present) */
    size_t body_offset = body_start - raw;
    if (body_offset < length) {
        req.body = body_start;
        req.body_length = length - body_offset;

        /* Check Content-Length header */
        const char *content_length_str = http_request_get_header(&req, "Content-Length");
        if (content_length_str) {
            char *endptr;
            long declared_length = strtol(content_length_str, &endptr, 10);

            /* Validate: at least one digit parsed, no junk after, non-negative */
            if (endptr > content_length_str && *endptr == '\0' && declared_length >= 0) {
                if (req.body_length > (size_t)declared_length) {
                    req.body_length = (size_t)declared_length;
                }
            }
            /* If parse failed, ignore Content-Length (use actual body_length) */
        }
    } else {
        req.body = NULL;
        req.body_length = 0;
    }

    return req;
}

void http_request_cleanup(HttpRequest *req) {
    if (req->headers) {
        free(req->headers);
        req->headers = NULL;
    }
    /* Note: We don't free _raw_buffer - caller owns it */
}

const char *http_request_get_header(const HttpRequest *req, const char *name) {
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0) {
            return req->headers[i].value;
        }
    }
    return NULL;
}

const char *http_request_get_client_ip(const HttpRequest *req, const char *socket_ip) {
    /* Check X-Real-IP first (single IP from trusted reverse proxy).
     * This server must sit behind a trusted reverse proxy in any real deployment, for TLS. */
    const char *real_ip = http_request_get_header(req, "X-Real-IP");
    if (real_ip && real_ip[0] != '\0') {
        return real_ip;
    }

    /* Check X-Forwarded-For (comma-separated chain from trusted reverse proxy)
     * Format: "client_ip, proxy1_ip, proxy2_ip"
     * Extract only the first IP (the original client) for consistency */
    const char *forwarded = http_request_get_header(req, "X-Forwarded-For");
    if (forwarded && forwarded[0] != '\0') {
        /* Thread-local buffer for extracted IP (one per thread, no contention) */
        static __thread char first_ip[INET6_ADDRSTRLEN];

        const char *comma = strchr(forwarded, ',');
        size_t len = comma ? (size_t)(comma - forwarded) : strlen(forwarded);

        /* Clamp to buffer size */
        if (len >= sizeof(first_ip)) {
            len = sizeof(first_ip) - 1;
        }

        memcpy(first_ip, forwarded, len);
        first_ip[len] = '\0';

        /* Trim trailing whitespace (leading space rare in first position) */
        while (len > 0 && (first_ip[len-1] == ' ' || first_ip[len-1] == '\t')) {
            first_ip[--len] = '\0';
        }

        return first_ip;
    }

    /* Fall back to socket IP (direct connection, always valid) */
    return socket_ip;
}

/* ============================================================================
 * HTTP Response Building
 * ============================================================================ */

/*
 * HTTP Status Codes
 * References: RFC 7231, RFC 6585, RFC 2518, RFC 4918, ...
 */
static const char *status_code_text(int code) {
    switch (code) {
        /* 1xx: Informational */
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 102: return "Processing";              /* WebDAV (RFC 2518) */
        case 103: return "Early Hints";             /* RFC 8297 */

        /* 2xx: Success */
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status";            /* WebDAV (RFC 4918) */
        case 208: return "Already Reported";        /* WebDAV (RFC 5842) */
        case 226: return "IM Used";                 /* RFC 3229 */

        /* 3xx: Redirection */
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";               /* Deprecated */
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";      /* RFC 7538 */

        /* 4xx: Client Error */
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";        /* Reserved */
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";            /* RFC 2324 (April Fools) */
        case 421: return "Misdirected Request";     /* RFC 7540 */
        case 422: return "Unprocessable Entity";    /* WebDAV (RFC 4918) */
        case 423: return "Locked";                  /* WebDAV (RFC 4918) */
        case 424: return "Failed Dependency";       /* WebDAV (RFC 4918) */
        case 425: return "Too Early";               /* RFC 8470 */
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";   /* RFC 6585 */
        case 429: return "Too Many Requests";       /* RFC 6585 */
        case 431: return "Request Header Fields Too Large";  /* RFC 6585 */
        case 451: return "Unavailable For Legal Reasons";    /* RFC 7725 */

        /* 5xx: Server Error */
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 506: return "Variant Also Negotiates";  /* RFC 2295 */
        case 507: return "Insufficient Storage";     /* WebDAV (RFC 4918) */
        case 508: return "Loop Detected";            /* WebDAV (RFC 5842) */
        case 510: return "Not Extended";             /* RFC 2774 */
        case 511: return "Network Authentication Required";  /* RFC 6585 */

        default:  return "Unknown Status";
    }
}

HttpResponse *http_response_new(int status_code) {
    HttpResponse *resp = malloc(sizeof(HttpResponse));
    if (!resp) return NULL;

    resp->status_code = status_code;
    resp->status_text = status_code_text(status_code);
    resp->headers = NULL;
    resp->header_count = 0;
    resp->header_capacity = 0;
    resp->body = NULL;
    resp->body_length = 0;

    return resp;
}

void http_response_free(HttpResponse *resp) {
    if (!resp) return;

    /* Free header names and values */
    for (int i = 0; i < resp->header_count; i++) {
        free(resp->headers[i].name);
        free(resp->headers[i].value);
    }
    free(resp->headers);

    /* Free body */
    free(resp->body);

    /* Free response itself */
    free(resp);
}

void http_response_set_header(HttpResponse *resp, const char *name, const char *value) {
    /* Check if header already exists (replace it) */
    for (int i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i].name, name) == 0) {
            char *new_value = str_dup(value);
            if (!new_value) return;  /* OOM - keep existing value */
            free(resp->headers[i].value);
            resp->headers[i].value = new_value;
            return;
        }
    }

    /* Add new header */
    if (resp->header_count >= resp->header_capacity) {
        int new_capacity = resp->header_capacity == 0 ? 8 : resp->header_capacity * 2;
        HttpHeader *new_headers = realloc(resp->headers, new_capacity * sizeof(HttpHeader));
        if (!new_headers) return;  /* Out of memory */
        resp->headers = new_headers;
        resp->header_capacity = new_capacity;
    }

    char *dup_name = str_dup(name);
    char *dup_value = str_dup(value);
    if (!dup_name || !dup_value) {
        free(dup_name);
        free(dup_value);
        return;  /* OOM - skip header */
    }
    resp->headers[resp->header_count].name = dup_name;
    resp->headers[resp->header_count].value = dup_value;
    resp->header_count++;
}

void http_response_set_body(HttpResponse *resp, const char *body, size_t length) {
    free(resp->body);
    resp->body = malloc(length);
    if (resp->body) {
        memcpy(resp->body, body, length);
        resp->body_length = length;

        /* Auto-set Content-Length */
        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%zu", length);
        http_response_set_header(resp, "Content-Length", content_length);
    } else {
        resp->body_length = 0;
    }
}

void http_response_set_body_str(HttpResponse *resp, const char *body) {
    http_response_set_body(resp, body, strlen(body));
}

void http_response_set(HttpResponse *resp, const char *content_type, const char *body) {
    http_response_set_header(resp, "Content-Type", content_type);
    http_response_set_body_str(resp, body);
}

char *http_response_serialize(const HttpResponse *resp, size_t *out_length) {
    /* Calculate total size needed */
    size_t size = 0;

    /* Status line: "HTTP/1.0 200 OK\r\n" */
    size += strlen(HTTP_VERSION " ") + 3 + 1 + strlen(resp->status_text) + 2;

    /* Headers: "Name: Value\r\n" */
    for (int i = 0; i < resp->header_count; i++) {
        size += strlen(resp->headers[i].name) + 2 + strlen(resp->headers[i].value) + 2;
    }

    /* Blank line */
    size += 2;

    /* Body */
    size += resp->body_length;

    /* Allocate buffer */
    char *buffer = malloc(size + 1);  /* +1 for safety null terminator */
    if (!buffer) return NULL;

    /* Build response */
    char *p = buffer;
    size_t remaining = size + 1;

    /* Status line */
    int written = snprintf(p, remaining, HTTP_VERSION " %d %s\r\n", resp->status_code, resp->status_text);
    p += written;
    remaining -= written;

    /* Headers */
    for (int i = 0; i < resp->header_count; i++) {
        written = snprintf(p, remaining, "%s: %s\r\n", resp->headers[i].name, resp->headers[i].value);
        p += written;
        remaining -= written;
    }

    /* Blank line */
    written = snprintf(p, remaining, "\r\n");
    p += written;

    /* Body */
    if (resp->body && resp->body_length > 0) {
        memcpy(p, resp->body, resp->body_length);
        p += resp->body_length;
    }

    *out_length = p - buffer;
    return buffer;
}
