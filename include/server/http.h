#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include "util/json.h"

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

    char *body;             /* The body Content-Length framed (NULL without one) */
    size_t body_length;     /* Length of body in bytes */

    char remote_ip[46];     /* Client socket IP (INET6_ADDRSTRLEN = 46) for localhost validation */
    int admin_listener;     /* Arrived on the loopback-only admin listener (admin_port), not
                               the public one: the only way to the localhost-only endpoints */

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
 *   raw    - Raw HTTP request bytes (WILL BE MODIFIED!). MUST be NUL-terminated at
 *            raw[length], so the allocation has to be length + 1 bytes. The parser's
 *            line walks rely on that terminator, and the body is terminated in place
 *            at its declared Content-Length.
 *   length - Length of raw bytes, not counting that terminator
 *
 * Returns: HttpRequest struct (stack-allocated), or .method = HTTP_UNKNOWN on error
 *
 * Example. Note the buffer must already hold a COMPLETE request — the server
 * accumulates across reads in event_loop.c and calls this once, so the single
 * read() below is illustration, not a usable framing strategy:
 *   char buffer[4096];
 *   ssize_t n = read(socket, buffer, sizeof(buffer) - 1);   // leave room for the NUL
 *   if (n < 0) { ... }
 *   buffer[n] = '\0';                                       // required, see `raw`
 *   HttpRequest req = http_request_parse(buffer, (size_t)n);
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
 * http_request_is_cross_origin - Did a browser send this from another origin?
 *
 * Sec-Fetch-Site decides when present, and every current browser sends it:
 * only "same-origin" and "none" (the user's own navigation) pass. A browser
 * too old to send it still sends Origin on a cross-origin POST, and that has
 * to match the Host the request was sent to. A request with neither header
 * isn't a browser's, or is from one too old to tell, and passes: this keeps
 * other sites from driving a user's browser, not clients from calling.
 *
 * Returns: 1 if another (or an opaque) origin sent it, 0 otherwise
 */
int http_request_is_cross_origin(const HttpRequest *req);

/*
 * http_set_client_ip_header - Which header carries the client's address
 *
 * Behind a reverse proxy the socket peer is the proxy, so the client's address
 * comes from a header the proxy sets. Only that header is trustworthy: one the
 * proxy passes through untouched is the client's to fill in, so there's no safe
 * order to try them in, and the deployer names the one their proxy sets.
 *   "x-real-ip"       X-Real-IP, which the shipped nginx overwrites (the default)
 *   "x-forwarded-for" the last X-Forwarded-For entry, the one the nearest proxy
 *                     appended (an AWS ALB in front of the server)
 *   "none"            no address
 * NULL means the default. Called once at startup, before any request.
 *
 * Returns: 0, or -1 for a name it doesn't know (nothing changed)
 */
int http_set_client_ip_header(const char *name);

/*
 * http_request_get_client_ip - The client's address, from the header
 * http_set_client_ip_header named
 *
 * Parameters:
 *   req       - Parsed HTTP request
 *   socket_ip - Returned when the header is absent, or holds something that
 *               isn't an IPv4 or IPv6 address (every caller passes NULL)
 *
 * Returns: Client IP string (thread-local or header value, don't free)
 */
const char *http_request_get_client_ip(const HttpRequest *req, const char *socket_ip);

/*
 * http_request_get_user_agent - The User-Agent header, fit for storing: at most
 * 512 bytes of well-formed UTF-8 (str_utf8_sanitize), or NULL if absent. The
 * copy is the calling thread's, good until its next call.
 */
const char *http_request_get_user_agent(const HttpRequest *req);

/*
 * http_find_header_end - Find the end of the header block, resumably
 *
 * Searches for CRLFCRLF and returns the offset just PAST it, or 0 if the header
 * block is not terminated yet. 0 is unambiguous: a terminated block is at least
 * four bytes, so a real answer is never 0.
 *
 * `already_scanned` is how many bytes were in the buffer the last time this
 * returned 0. The search restarts three bytes before that rather than at that
 * offset, because a CRLFCRLF can straddle the boundary between two reads — miss
 * that and the request never completes and never errors, it just hangs until the
 * idle timeout. Pass 0 to scan the whole buffer.
 *
 * Parameters:
 *   buffer          - Bytes received so far
 *   length          - How many of them are valid
 *   already_scanned - Buffer length at the previous unsuccessful call
 *
 * Returns: offset just past the delimiter, or 0 if not found
 */
size_t http_find_header_end(const char *buffer, size_t length, size_t already_scanned);

/*
 * http_scan_content_length - Read the Content-Length that frames a request
 *
 * The socket layer calls this once per request, on its read buffer, to learn how
 * many body bytes to wait for. That buffer is NOT NUL-terminated, so this reads only
 * within header_len. http_request_parse() applies the same value rule, so the two
 * layers can't disagree about where a body ends. Both refuse a header block with a
 * NUL in it (RFC 9110 §5.5): the parser reads header lines as C strings, and would
 * stop at it short of headers this reads.
 *
 * A value must be one or more digits, optionally surrounded by spaces or tabs.
 * Several Content-Length lines are accepted only if they agree.
 *
 * Parameters:
 *   headers    - Start of the request (request line, then header lines)
 *   header_len - Offset just past the CRLFCRLF, as http_find_header_end() returned
 *   out_length - Receives the length on success
 *
 * Returns: 0 found, 1 no Content-Length, -1 an invalid value,
 *          -2 Content-Length lines that disagree, -3 a NUL in the header block
 */
int http_scan_content_length(const char *headers, size_t header_len, size_t *out_length);

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
 * http_response_add_header - Append a header (no dedup)
 *
 * Use for headers that may appear multiple times (e.g., Set-Cookie).
 * Per RFC 6265, multiple Set-Cookie headers cannot be comma-joined.
 */
void http_response_add_header(HttpResponse *resp, const char *name, const char *value);

/*
 * http_response_set_body - Set response body (copies data)
 */
void http_response_set_body(HttpResponse *resp, const char *body, size_t length);

/*
 * http_response_set_body_owned - Set response body (takes ownership, no copy)
 *
 * Like set_body but assigns body pointer directly instead of malloc+memcpy.
 * The body will be freed by http_response_free(). Caller must NOT free it.
 */
void http_response_set_body_owned(HttpResponse *resp, char *body, size_t length);

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

/*
 * jsonbuf_to_response - Convert JsonBuf to HTTP response (ownership transfer)
 *
 * Creates an HttpResponse with the buffer as body. The buffer is transferred
 * (not copied) to the response. The JsonBuf struct is freed. Caller must NOT
 * use jb after this call.
 *
 * If jb->error is set, frees the buffer and returns a 500 error response.
 */
HttpResponse *jsonbuf_to_response(JsonBuf *jb, int status_code);

#endif /* HTTP_H */
