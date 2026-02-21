#include "server/router.h"
#include "handlers.h"
#include "util/str.h"
#include "util/log.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Path parameter support - compile-time toggle
 * Set to 1 for "/users/:id" style routing (flexible)
 * Set to 0 for exact path matching only (fast, minimal)
 * Default: 0 (disabled)
 */
#ifndef ROUTER_USE_PATH_PARAMS
#define ROUTER_USE_PATH_PARAMS 0
#endif

/* Hash table size - must be power of 2 for fast modulo
 * 64 buckets supports unlimited routes (routes share buckets via chaining)
 * With 20 routes: ~0-1 per bucket. With 100 routes: ~1-2 per bucket.
 */
#define HASH_TABLE_SIZE 64

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/*
 * Route - Single route entry
 */
typedef struct {
    HttpMethod method;        /* HTTP method (GET, POST, etc.) */
    char *path_pattern;       /* Original pattern (e.g., "/users/:id") */
    char **segments;          /* Split by '/' for fast matching */
    int segment_count;        /* Number of segments */
    RouteHandler handler;     /* Handler function */
} Route;

/*
 * RouteList - Linked list for hash table chaining
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

/*
 * RouteParams - Extracted path parameters
 */
#define MAX_ROUTE_PARAMS 8

struct RouteParams {
    struct {
        char *name;           /* Parameter name (e.g., "id") */
        char *value;          /* Parameter value (e.g., "123") */
    } params[MAX_ROUTE_PARAMS];
    int count;                /* Number of parameters */
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * split_path - Split path by '/' into segments
 *
 * Example: "/users/123" → ["users", "123"]
 *
 * Returns: Array of segments (caller must free each segment and array)
 */
static char **split_path(const char *path, int *out_count) {
    /* Skip leading slash */
    if (path[0] == '/') {
        path++;
    }

    /* Empty path or just "/" */
    if (path[0] == '\0') {
        *out_count = 0;
        return NULL;
    }

    return str_split(path, '/', out_count);
}

/*
 * hash_path - FNV-1a hash function
 *
 * For path params, normalizes ":param" → "$" before hashing so:
 *   "/users/:id" and "/users/:email" hash to same value (caught as duplicate)
 *   "/users/123" hashes differently (lookup uses normalized version)
 */
static uint32_t hash_path(const char *path) {
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    const char *p = path;

    while (*p) {
#if ROUTER_USE_PATH_PARAMS
        if (*p == ':') {
            /* Normalize :param to $ */
            hash ^= (uint8_t)'$';
            hash *= 16777619;  /* FNV prime */
            /* Skip to next / or end */
            while (*p && *p != '/') p++;
            continue;
        }
#endif
        hash ^= (uint8_t)*p++;
        hash *= 16777619;
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

#if ROUTER_USE_PATH_PARAMS
/*
 * is_param_segment - Check if segment is a parameter (starts with ':')
 */
static bool is_param_segment(const char *segment) {
    return segment && segment[0] == ':';
}

/*
 * extract_param_name - Get parameter name from segment
 *
 * Example: ":id" → "id"
 */
static const char *extract_param_name(const char *segment) {
    if (is_param_segment(segment)) {
        return segment + 1;  /* Skip the ':' */
    }
    return NULL;
}
#endif /* ROUTER_USE_PATH_PARAMS */

#if ROUTER_USE_PATH_PARAMS
/*
 * route_params_create - Create empty params struct
 */
static RouteParams *route_params_create(void) {
    RouteParams *params = malloc(sizeof(RouteParams));
    if (!params) return NULL;

    memset(params, 0, sizeof(RouteParams));
    return params;
}

/*
 * route_params_destroy - Free params struct
 */
static void route_params_destroy(RouteParams *params) {
    if (!params) return;

    for (int i = 0; i < params->count; i++) {
        free(params->params[i].name);
        free(params->params[i].value);
    }
    free(params);
}

/*
 * route_params_add - Add a parameter
 */
static void route_params_add(RouteParams *params, const char *name, const char *value) {
    if (!params || params->count >= MAX_ROUTE_PARAMS) return;

    params->params[params->count].name = str_dup(name);
    params->params[params->count].value = str_dup(value);
    params->count++;
}
#endif /* ROUTER_USE_PATH_PARAMS */

/* ============================================================================
 * Route Matching
 * ============================================================================ */

/*
 * route_matches - Check if route matches request path
 *
 * Returns: RouteParams if match, NULL if no match
 */
static RouteParams *route_matches(const Route *route, const char *path) {
#if ROUTER_USE_PATH_PARAMS
    /* Split request path */
    int path_segment_count;
    char **path_segments = split_path(path, &path_segment_count);

    /* Segment count must match exactly */
    if (path_segment_count != route->segment_count) {
        if (path_segments) {
            for (int i = 0; i < path_segment_count; i++) {
                free(path_segments[i]);
            }
            free(path_segments);
        }
        return NULL;
    }

    /* Create params struct for extracted parameters */
    RouteParams *params = route_params_create();
    if (!params) {
        if (path_segments) {
            for (int i = 0; i < path_segment_count; i++) {
                free(path_segments[i]);
            }
            free(path_segments);
        }
        return NULL;
    }

    /* Match each segment */
    for (int i = 0; i < route->segment_count; i++) {
        const char *route_seg = route->segments[i];
        const char *path_seg = path_segments[i];

        if (is_param_segment(route_seg)) {
            /* This is a parameter - extract it */
            const char *param_name = extract_param_name(route_seg);
            route_params_add(params, param_name, path_seg);
        } else {
            /* Exact match required */
            if (strcmp(route_seg, path_seg) != 0) {
                /* No match */
                route_params_destroy(params);
                for (int j = 0; j < path_segment_count; j++) {
                    free(path_segments[j]);
                }
                free(path_segments);
                return NULL;
            }
        }
    }

    /* Match! */
    for (int i = 0; i < path_segment_count; i++) {
        free(path_segments[i]);
    }
    free(path_segments);

    return params;
#else
    /* Exact string matching only */
    static const RouteParams matched = {0};
    if (strcmp(route->path_pattern, path) == 0) {
        return (RouteParams *)&matched;
    }
    return NULL;
#endif
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

    /* Free all buckets */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        RouteNode *node = router->buckets[i];
        while (node) {
            RouteNode *next = node->next;

            free(node->route.path_pattern);

            /* Free segments */
            for (int j = 0; j < node->route.segment_count; j++) {
                free(node->route.segments[j]);
            }
            free(node->route.segments);

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
    new_node->route.segments = split_path(path, &new_node->route.segment_count);

    /* Insert at head of bucket (fast) */
    new_node->next = router->buckets[bucket_idx];
    router->buckets[bucket_idx] = new_node;

    router->route_count++;

    log_info("  %-7s %s", method_to_string(method), path);
}

HttpResponse *router_dispatch(Router *router, const HttpRequest *req) {
    if (!router || !req) {
        log_error("Invalid router_dispatch parameters");
        return response_json_error(500, "Internal Server Error");
    }

    log_debug("Dispatching: %s %s", req->method_str, req->path);

    /* Hash the request path to find bucket */
    uint32_t bucket_idx = hash_path(req->path);
    RouteNode *node = router->buckets[bucket_idx];

    /* Search bucket for matching route */
    while (node) {
        Route *route = &node->route;

        /* Check method */
        if (route->method == req->method) {
            /* Check path pattern */
            RouteParams *params = route_matches(route, req->path);
            if (params) {
                /* Match! Call handler */
                log_debug("Matched route: %s", route->path_pattern);

                HttpResponse *resp = route->handler(req, params);

#if ROUTER_USE_PATH_PARAMS
                route_params_destroy(params);
#endif

                if (!resp) {
                    log_error("Handler returned NULL for %s %s", req->method_str, req->path);
                    return response_json_error(500, "Internal Server Error");
                }

                return resp;
            }
        }

        node = node->next;
    }

    /* No route matched - 404 */
    log_debug("No route matched for %s %s", req->method_str, req->path);
    return response_json_error(404, "Not Found");
}

/* ============================================================================
 * Route Parameters API
 * ============================================================================ */

const char *route_params_get(const RouteParams *params, const char *name) {
    if (!params || !name) return NULL;

    for (int i = 0; i < params->count; i++) {
        if (strcmp(params->params[i].name, name) == 0) {
            return params->params[i].value;
        }
    }

    return NULL;
}
