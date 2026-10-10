#include "server/router.h"
#include "handlers.h"
#include "util/str.h"
#include "util/log.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/crypto.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Hash table size - must be power of 2 for fast modulo
 * 64 buckets supports unlimited routes (routes share buckets via chaining)
 * With 20 routes: ~0-1 per bucket. With 100 routes: ~1-2 per bucket.
 */
#define HASH_TABLE_SIZE 64

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/*
 * Route - Single route entry (exact-match, stored in hash table)
 */
typedef struct {
    HttpMethod method;        /* HTTP method (GET, POST, etc.) */
    char *path_pattern;       /* Exact path (e.g., "/health") */
    RouteHandler handler;     /* Handler function */
} Route;

/*
 * RouteNode - Linked list for hash table chaining
 */
typedef struct RouteNode {
    Route route;
    struct RouteNode *next;
} RouteNode;

/*
 * Router - Hash table of routes
 */
struct Router {
    RouteNode *buckets[HASH_TABLE_SIZE];  /* Hash table buckets */
    int route_count;                       /* Total routes registered */
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * hash_path - FNV-1a hash for exact-match route lookup
 */
static uint32_t hash_path(const char *path) {
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    const char *p = path;

    while (*p) {
        hash ^= (uint8_t)*p++;
        hash *= 16777619;  /* FNV prime */
    }

    return hash % HASH_TABLE_SIZE;
}

/*
 * method_to_string - Convert HttpMethod enum to string
 */
static const char *method_to_string(HttpMethod method) {
    switch (method) {
        case HTTP_GET:     return "GET";
        case HTTP_HEAD:    return "HEAD";
        case HTTP_POST:    return "POST";
        case HTTP_PUT:     return "PUT";
        case HTTP_DELETE:  return "DELETE";
        case HTTP_CONNECT: return "CONNECT";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_TRACE:   return "TRACE";
        case HTTP_PATCH:   return "PATCH";
        default:           return "UNKNOWN";
    }
}

/* ============================================================================
 * Router Implementation
 * ============================================================================ */

Router *router_create(void) {
    Router *router = malloc(sizeof(Router));
    if (!router) {
        log_error("Failed to allocate router");
        return NULL;
    }

    /* Initialize hash table buckets to NULL */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        router->buckets[i] = NULL;
    }
    router->route_count = 0;

    return router;
}

void router_destroy(Router *router) {
    if (!router) return;

    /* Free all hash table buckets */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        RouteNode *node = router->buckets[i];
        while (node) {
            RouteNode *next = node->next;

            free(node->route.path_pattern);
            free(node);
            node = next;
        }
    }

    free(router);
}

void router_add(Router *router, HttpMethod method, const char *path, RouteHandler handler) {
    if (!router || !path || !handler) {
        log_error("Invalid router_add parameters");
        return;
    }

    /* router_dispatch answers OPTIONS centrally, from CORS_PUBLIC_PATHS, and
       returns before consulting the table. A route registered here for OPTIONS
       would therefore look registered and never run — the same silent-no-op that
       router_validate_cors_paths() exists to prevent, pointed the other way.
       Refuse it loudly instead. If OPTIONS routing is ever genuinely wanted, the
       preflight branch in router_dispatch is what has to change. */
    if (method == HTTP_OPTIONS) {
        log_error("OPTIONS is answered by the CORS preflight path and is not "
                  "dispatched from the route table; refusing to register %s", path);
        return;
    }

    /* Hash the path */
    uint32_t bucket_idx = hash_path(path);

    /* Check for duplicate route (same method + path pattern) */
    RouteNode *node = router->buckets[bucket_idx];
    while (node) {
        if (node->route.method == method && strcmp(node->route.path_pattern, path) == 0) {
            log_error("Duplicate route: %s %s", method_to_string(method), path);
            return;
        }
        node = node->next;
    }

    /* Create new route node */
    RouteNode *new_node = malloc(sizeof(RouteNode));
    if (!new_node) {
        log_error("Failed to allocate route node");
        return;
    }

    new_node->route.method = method;
    new_node->route.path_pattern = str_dup(path);
    new_node->route.handler = handler;

    /* Insert at head of bucket (fast) */
    new_node->next = router->buckets[bucket_idx];
    router->buckets[bucket_idx] = new_node;

    router->route_count++;

    log_info("  %-7s %s", method_to_string(method), path);
}

static HttpResponse *dispatch_route(Router *router, const HttpRequest *req) {
    log_debug("Dispatching: %s %s", req->method_str, req->path);

    /* Exact match in the path's hash bucket */
    uint32_t bucket_idx = hash_path(req->path);
    RouteNode *node = router->buckets[bucket_idx];

    while (node) {
        Route *route = &node->route;

        if (route->method == req->method && strcmp(route->path_pattern, req->path) == 0) {
            log_debug("Matched route: %s", route->path_pattern);

            HttpResponse *resp = route->handler(req);

            if (!resp) {
                log_error("Handler returned NULL for %s %s", req->method_str, req->path);
                return response_json_error(500, "Internal Server Error");
            }

            return resp;
        }

        node = node->next;
    }

    /* No route matched */
    log_debug("No route matched for %s %s", req->method_str, req->path);
    return response_json_error(404, "Not Found");
}

/* ============================================================================
 * CORS
 * ============================================================================ */

const char *const CORS_PUBLIC_PATHS[] = {
    "/token",
    "/revoke",
    "/userinfo",
    "/.well-known/jwks.json",
};

const int CORS_PUBLIC_PATH_COUNT =
    (int)(sizeof(CORS_PUBLIC_PATHS) / sizeof(CORS_PUBLIC_PATHS[0]));

int router_path_allows_cors(const char *path) {
    if (!path) {
        return 0;
    }

    for (int i = 0; i < CORS_PUBLIC_PATH_COUNT; i++) {
        if (strcmp(path, CORS_PUBLIC_PATHS[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * Is this path registered for any method?
 */
static bool router_has_path(const Router *router, const char *path) {
    RouteNode *node = router->buckets[hash_path(path)];

    while (node) {
        if (strcmp(node->route.path_pattern, path) == 0) {
            return true;
        }
        node = node->next;
    }

    return false;
}

int router_validate_cors_paths(const Router *router) {
    if (!router) {
        return -1;
    }

    int missing = 0;
    for (int i = 0; i < CORS_PUBLIC_PATH_COUNT; i++) {
        if (!router_has_path(router, CORS_PUBLIC_PATHS[i])) {
            log_error("CORS path '%s' is not a registered route", CORS_PUBLIC_PATHS[i]);
            missing++;
        }
    }

    return missing;
}

/*
 * Answer a CORS preflight
 *
 * Only /userinfo actually preflights — it sends Authorization, which is not on
 * the CORS safelist. /token and /revoke are form-encoded POSTs, which are simple
 * requests the browser sends without asking. All four are answered anyway, from
 * the same array, so the cross-origin surface has exactly one definition.
 *
 * No Access-Control-Max-Age: browsers then re-ask often, which is the cheap and
 * boring direction. A deployer who wants preflights cached can add it at the
 * edge without touching this.
 */
static HttpResponse *cors_preflight(const char *path) {
    if (!router_path_allows_cors(path)) {
        log_debug("OPTIONS for non-CORS path %s", path ? path : "(null)");
        return response_json_error(404, "Not Found");
    }

    HttpResponse *resp = http_response_new(204);
    if (!resp) {
        log_error("Failed to allocate preflight response");
        return response_json_error(500, "Internal Server Error");
    }

    http_response_set_header(resp, "Access-Control-Allow-Origin", "*");
    http_response_set_header(resp, "Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
    http_response_set_header(resp, "Access-Control-Allow-Headers", "Authorization, Content-Type");

    return resp;
}

HttpResponse *router_dispatch(Router *router, const HttpRequest *req) {
    if (!router || !req) {
        log_error("Invalid router_dispatch parameters");
        return response_json_error(500, "Internal Server Error");
    }

    /* Nothing registers OPTIONS, so a preflight would otherwise 404 — and a 404
       without CORS headers is unreadable to the browser regardless of what it
       says. Gated on the same array as the header below, never a second list. */
    if (req->method == HTTP_OPTIONS) {
        return cors_preflight(req->path);
    }

    /*
     * One whole-body check for JSON string escapes, before any handler reads a
     * field. json_get_string refuses a bad value per field, but a refused
     * OPTIONAL field looks exactly like an omitted one, so without this the
     * rest of the request would go through with that field silently skipped.
     * Form-encoded bodies are exempt: they carry no JSON strings, and any quote
     * or backslash in them is percent-encoded.
     *
     * And before that, that the body is UTF-8 at all, which RFC 8259 requires
     * of JSON. Raw bytes reach a handler as sent, and then the backends part
     * ways: SQLite stores an invalid sequence and echoes it into later JSON
     * responses, while PostgreSQL refuses it at INSERT and the handler answers
     * 500. Refused here, both answer 400.
     */
    HttpResponse *resp;
    const char *content_type = http_request_get_header(req, "Content-Type");
    int is_form = content_type &&
        strncasecmp(content_type, "application/x-www-form-urlencoded", 33) == 0;
    if (req->body && !is_form && !json_utf8_valid(req->body, req->body_length)) {
        resp = response_json_error(400, "Request body is not valid UTF-8");
    } else if (req->body && !is_form && !json_escapes_valid(req->body)) {
        resp = response_json_error(400, "Invalid JSON string escape");
    } else {
        resp = dispatch_route(router, req);
    }

    /*
     * HEAD: nothing registers it, so fall back to the GET route for the same
     * path. RFC 7231 4.3.2 wants the same headers GET would send, Content-Length
     * included, with only the body omitted.
     *
     * Deliberately NOT an early return the way OPTIONS is above. The CORS header
     * is attached below and is keyed on the path, so a HEAD that returned early
     * would silently lose it on the four public endpoints — and no test that
     * only checked GET would notice.
     */
    if (req->method == HTTP_HEAD && resp && resp->status_code == 404) {
        HttpRequest as_get = *req;
        as_get.method = HTTP_GET;

        HttpResponse *from_get = dispatch_route(router, &as_get);
        if (from_get) {
            http_response_free(resp);
            resp = from_get;
        }
    }

    /*
     * Drop the body, keep the headers. Freed by hand rather than through
     * http_response_set_body(resp, "", 0), which sets Content-Length as a side
     * effect and would rewrite it to 0 — a well-formed response with the wrong
     * length, which nothing would flag. Serialization guards the body on
     * body_length > 0 and Content-Length is a stored header, so zeroing one does
     * not touch the other.
     *
     * Cleansed first because http_response_free() would have, and /userinfo and
     * /api/user/profile are GET routes whose bodies carry user data.
     */
    if (req->method == HTTP_HEAD && resp && resp->body) {
        OPENSSL_cleanse(resp->body, resp->body_length);
        free(resp->body);
        resp->body = NULL;
        resp->body_length = 0;
    }

    /* Attached per path, never per client: the question is whether a browser at
       some origin may read this response, which is a property of the endpoint.
       Branching on the caller would make the same URL sometimes carry the header
       and sometimes not, needing Vary to cache correctly, and would buy nothing
       since a server-side client ignores it either way.

       Deliberately no Access-Control-Allow-Credentials. `*` plus credentials is
       refused by the Fetch standard, and that refusal is the entire reason `*`
       is safe here. */
    if (resp && router_path_allows_cors(req->path)) {
        http_response_set_header(resp, "Access-Control-Allow-Origin", "*");
    }

    return resp;
}
