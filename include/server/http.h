#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

/*
 * HTTP Parser and Response Builder
 *
 * Designed for HTTP/1.0 (simple, no chunked encoding, no keep-alive)
 * Fast, minimal, zero dependencies.
 */

/* ============================================================================
 * HTTP Methods
 * ============================================================================ */

/*
 * HTTP Methods
 * List of standard HTTP methods (RFC 7231, RFC 5789)
 */
typedef enum {
    HTTP_GET,      /* Retrieve resource */
    HTTP_HEAD,     /* Retrieve headers only */
    HTTP_POST,     /* Submit data, create resource */
    HTTP_PUT,      /* Replace resource */
    HTTP_DELETE,   /* Remove resource */
    HTTP_CONNECT,  /* Establish tunnel (for proxies) */
    HTTP_OPTIONS,  /* Query supported methods */
    HTTP_TRACE,    /* Echo request (debugging) */
    HTTP_PATCH,    /* Partial modification */
    HTTP_UNKNOWN   /* Unrecognized method */
} HttpMethod;

/* ============================================================================
 * HTTP Request
 * ============================================================================ */

/* Single HTTP header (name: value) */
typedef struct {
    char *name;   /* ex: "Content-Type" */
    char *value;  /* ex: "application/json; charset=utf-8" */
} HttpHeader;

/* Parsed HTTP request */
typedef struct {
    HttpMethod method;      /* GET, POST, etc. */
    char *method_str;       /* Original string (e.g., "GET") */
    char *path;             /* ex: "/health" or "/users/123" */
    char *query_string;     /* ex: "ex1=abc&ex2=def" (NULL if none) */

    HttpHeader *headers;    /* Array of headers */
    int header_count;       /* Number of headers */

    char *body;             /* Request body (NULL if none) */
    size_t body_length;     /* Length of body in bytes */

    char remote_ip[46];     /* Client socket IP (INET6_ADDRSTRLEN = 46) for localhost validation */

    /* Internal: points to original buffer (for zero-copy parsing) */
    char *_raw_buffer;      /* DO NOT FREE - this is caller's memory */
} HttpRequest;

/*
 * http_request_parse - Parse HTTP request from raw bytes
 *
 * This is a ZERO-COPY parser where possible - it modifies the input buffer
 * by inserting null terminators. The HttpRequest struct points INTO the buffer.
 *
 * IMPORTANT: The input buffer MUST remain valid for the lifetime of HttpRequest!
 *            Do NOT free the buffer while using the parsed request.
 *
 * Parameters:
 *   raw    - Raw HTTP request bytes (WILL BE MODIFIED!)
 *   length - Length of raw bytes
 *
 * Returns: HttpRequest struct (stack-allocated), or .method = HTTP_UNKNOWN on error
 *
 * Example:
 *   char buffer[4096];
 *   ssize_t n = read(socket, buffer, sizeof(buffer));
 *   HttpRequest req = http_request_parse(buffer, n);
 *   if (req.method == HTTP_UNKNOWN) {
 *       // Parse error
 *   }
 *   // Use req...
 *   http_request_cleanup(&req);
 *   free(buffer);
 */
HttpRequest http_request_parse(char *raw, size_t length);

/*
 * http_request_cleanup - Free dynamically allocated parts
 *
 * Call this when done with a parsed request.
 * Does NOT free the original buffer (caller owns it).
 */
void http_request_cleanup(HttpRequest *req);

/*
 * http_request_get_header - Find header by name (case-insensitive)
 *
 * Returns: Header value, or NULL if not found
 */
const char *http_request_get_header(const HttpRequest *req, const char *name);

/*
 * http_request_get_client_ip - Get real client IP from headers
 *
 * When behind a reverse proxy, the socket IP will be the proxy.
 * This extracts the real client IP from standard proxy headers.
 *
 * Standard proxy server headers (set by trusted reverse proxy):
 *   X-Real-IP: client_ip (single address, preferred)
 *   X-Forwarded-For: client_ip, proxy1_ip, proxy2_ip (comma-separated chain)
 *
 * Priority:
 *   1. X-Real-IP (single IP, clean)
 *   2. X-Forwarded-For (extracts first IP from comma-separated list)
 *   3. Falls back to socket_ip if neither present
 *
 * Returns a single IP address consistently across all paths.
 *
 * Parameters:
 *   req       - Parsed HTTP request
 *   socket_ip - IP from socket (fallback if no headers)
 *
 * Returns: Client IP string (thread-local or header value, don't free)
 */
const char *http_request_get_client_ip(const HttpRequest *req, const char *socket_ip);

/* ============================================================================
 * HTTP Response - Build responses to send
 * ============================================================================ */

typedef struct {
    int status_code;          /* ex: 200, 404, 500 */
    const char *status_text;  /* ex: "OK", "Not Found", "Internal Server Error" */

    HttpHeader *headers;    /* Array of headers */
    int header_count;       /* Number of headers */
    int header_capacity;    /* Allocated capacity */

    char *body;             /* Response body */
    size_t body_length;     /* Length of body */
} HttpResponse;

/*
 * http_response_new - Create a new response
 *
 * Caller must free with http_response_free().
 *
 * Returns: Pointer to new HttpResponse, or NULL if malloc fails
 */
HttpResponse *http_response_new(int status_code);

/*
 * http_response_free - Free a response and all its parts
 */
void http_response_free(HttpResponse *resp);

/*
 * http_response_set_header - Set a header (or replace if exists)
 */
void http_response_set_header(HttpResponse *resp, const char *name, const char *value);

/*
 * http_response_set_body - Set response body (copies data)
 */
void http_response_set_body(HttpResponse *resp, const char *body, size_t length);

/*
 * http_response_set_body_str - Set response body from null-terminated string
 */
void http_response_set_body_str(HttpResponse *resp, const char *body);

/*
 * http_response_set - Set Content-Type and body in one call
 *
 * Convenience wrapper for the common pattern of setting both.
 * For binary data or custom headers, use set_header() and set_body() directly.
 */
void http_response_set(HttpResponse *resp, const char *content_type, const char *body);

/*
 * http_response_serialize - Convert response to bytes for sending
 *
 * Allocates and returns serialized HTTP response.
 * Caller must free the returned buffer.
 *
 * Parameters:
 *   resp       - Response to serialize
 *   out_length - Receives total length of output (including body)
 *
 * Returns: Pointer to serialized bytes, or NULL if malloc fails
 */
char *http_response_serialize(const HttpResponse *resp, size_t *out_length);

#endif /* HTTP_H */
