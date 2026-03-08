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
 * Route - Single route entry (exact-match, stored in hash table)
 */
typedef struct {
    HttpMethod method;        /* HTTP method (GET, POST, etc.) */
    char *path_pattern;       /* Original path (e.g., "/health") */
    char **segments;          /* Split by '/' */
    int segment_count;        /* Number of segments */
    RouteHandler handler;     /* Handler function */
} Route;

/*
 * RouteNode - Linked list for hash table chaining
 */
typedef struct RouteNode {
    Route route;
    struct RouteNode *next;
} RouteNode;

#if ROUTER_USE_PATH_PARAMS
/*
 * ParamRoute - Parameterized route entry (stored in separate list)
 *
 * Parameterized routes bypass the hash table entirely. At dispatch time,
 * candidates are filtered by segment count and literal segment equality,
 * then disambiguated by literal position vectors.
 */
typedef struct {
    HttpMethod method;
    char *path_pattern;       /* Original pattern e.g. "/users/:id" */
    char **segments;          /* Split segments */
    int segment_count;
    int literal_count;        /* Number of non-param segments */
    int *literal_mask;        /* 1=literal, 0=param, per segment */
    RouteHandler handler;
} ParamRoute;

#define PARAM_ROUTES_INITIAL_CAPACITY 8
#endif

/*
 * Router - Hash table of routes with optional parameterized route list
 */
struct Router {
    RouteNode *buckets[HASH_TABLE_SIZE];  /* Hash table buckets */
    int route_count;                       /* Total routes registered */
#if ROUTER_USE_PATH_PARAMS
    ParamRoute *param_routes;              /* Parameterized routes (separate from hash table) */
    int param_route_count;
    int param_route_capacity;
#endif
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

#if ROUTER_USE_PATH_PARAMS
/*
 * is_param_segment - Check if segment is a parameter (starts with ':')
 */
static bool is_param_segment(const char *segment) {
    return segment && segment[0] == ':';
}

/*
 * extract_param_name - Get parameter name from ":name" segment
 */
static const char *extract_param_name(const char *segment) {
    if (is_param_segment(segment)) {
        return segment + 1;
    }
    return NULL;
}

/*
 * path_has_params - Check if path contains parameterized segments ("/:...")
 */
static bool path_has_params(const char *path) {
    return strstr(path, "/:") != NULL;
}

/*
 * paths_match_normalized - Check if two parameterized paths have identical
 *                          $-normalized forms (same literal structure)
 *
 * "/users/:id" and "/users/:email" → true  (both normalize to "/users/$")
 * "/users/:id" and "/posts/:id"   → false
 */
static bool paths_match_normalized(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return false;
        if (*a == '/' && *(a+1) == ':' && *(b+1) == ':') {
            a++; b++;
            while (*a && *a != '/') a++;
            while (*b && *b != '/') b++;
            continue;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

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
 * route_params_destroy - Free params struct and all contained strings
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
 * route_params_add - Add a named parameter
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
 * route_matches - Check if exact-match route matches request path
 *
 * Parameterized routes are matched separately via the param_routes list.
 */
static RouteParams *route_matches(const Route *route, const char *path) {
    static const RouteParams matched = {0};
    if (strcmp(route->path_pattern, path) == 0) {
        return (RouteParams *)&matched;
    }
    return NULL;
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

#if ROUTER_USE_PATH_PARAMS
    router->param_routes = NULL;
    router->param_route_count = 0;
    router->param_route_capacity = 0;
#endif

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

            for (int j = 0; j < node->route.segment_count; j++) {
                free(node->route.segments[j]);
            }
            free(node->route.segments);

            free(node);
            node = next;
        }
    }

#if ROUTER_USE_PATH_PARAMS
    for (int i = 0; i < router->param_route_count; i++) {
        free(router->param_routes[i].path_pattern);
        for (int j = 0; j < router->param_routes[i].segment_count; j++) {
            free(router->param_routes[i].segments[j]);
        }
        free(router->param_routes[i].segments);
        free(router->param_routes[i].literal_mask);
    }
    free(router->param_routes);
#endif

    free(router);
}

void router_add(Router *router, HttpMethod method, const char *path, RouteHandler handler) {
    if (!router || !path || !handler) {
        log_error("Invalid router_add parameters");
        return;
    }

#if ROUTER_USE_PATH_PARAMS
    /* Parameterized routes go into a separate list, not the hash table */
    if (path_has_params(path)) {
        /* Reject duplicate normalized forms (same method + same literal structure) */
        for (int i = 0; i < router->param_route_count; i++) {
            if (router->param_routes[i].method == method &&
                paths_match_normalized(router->param_routes[i].path_pattern, path)) {
                log_error("Duplicate parameterized route: %s %s (conflicts with %s)",
                         method_to_string(method), path,
                         router->param_routes[i].path_pattern);
                return;
            }
        }

        /* Grow array if needed */
        if (router->param_route_count >= router->param_route_capacity) {
            int new_cap = router->param_route_capacity
                        ? router->param_route_capacity * 2
                        : PARAM_ROUTES_INITIAL_CAPACITY;
            ParamRoute *grown = realloc(router->param_routes, new_cap * sizeof(ParamRoute));
            if (!grown) {
                log_error("Failed to allocate param route");
                return;
            }
            router->param_routes = grown;
            router->param_route_capacity = new_cap;
        }

        ParamRoute *pr = &router->param_routes[router->param_route_count];
        pr->method = method;
        pr->path_pattern = str_dup(path);
        pr->handler = handler;
        pr->segments = split_path(path, &pr->segment_count);

        /* Pre-compute literal mask and count for dispatch disambiguation */
        pr->literal_mask = malloc(pr->segment_count * sizeof(int));
        pr->literal_count = 0;
        for (int i = 0; i < pr->segment_count; i++) {
            if (is_param_segment(pr->segments[i])) {
                pr->literal_mask[i] = 0;
            } else {
                pr->literal_mask[i] = 1;
                pr->literal_count++;
            }
        }

        router->param_route_count++;
        router->route_count++;

        log_info("  %-7s %s (parameterized)", method_to_string(method), path);
        return;
    }
#endif

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

    /* Step 1: Exact hash match */
    uint32_t bucket_idx = hash_path(req->path);
    RouteNode *node = router->buckets[bucket_idx];

    while (node) {
        Route *route = &node->route;

        if (route->method == req->method) {
            RouteParams *params = route_matches(route, req->path);
            if (params) {
                log_debug("Matched route: %s", route->path_pattern);

                HttpResponse *resp = route->handler(req, params);

                if (!resp) {
                    log_error("Handler returned NULL for %s %s", req->method_str, req->path);
                    return response_json_error(500, "Internal Server Error");
                }

                return resp;
            }
        }

        node = node->next;
    }

#if ROUTER_USE_PATH_PARAMS
    /*
     * Step 2: Parameterized route matching (fallback after exact hash miss)
     *
     * Algorithm:
     *   1. Split request path into segments
     *   2. Filter to POSSIBLY VALID candidates:
     *      - Same HTTP method
     *      - Same segment count
     *      - All literal segments equal the corresponding request segments
     *   3. Among candidates, pick the winner by literal position vector:
     *      - Prefer higher literal_count (more specific route)
     *      - Break ties by leftmost literal positions (lexicographic comparison)
     *   4. Extract params from the single winner
     *
     * The winner is guaranteed unique: routes with identical $-normalized
     * forms are rejected at registration, so literal position vectors are
     * always distinct among same-segment-count candidates.
     */
    if (router->param_route_count > 0) {
        int req_seg_count;
        char **req_segments = split_path(req->path, &req_seg_count);

        int best = -1;
        int best_literal_count = -1;

        for (int i = 0; i < router->param_route_count; i++) {
            ParamRoute *pr = &router->param_routes[i];

            if (pr->method != req->method) continue;
            if (pr->segment_count != req_seg_count) continue;

            /* All literal segments must match the request */
            bool valid = true;
            for (int s = 0; s < pr->segment_count; s++) {
                if (pr->literal_mask[s] &&
                    strcmp(pr->segments[s], req_segments[s]) != 0) {
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;

            /* Candidate is POSSIBLY VALID — check if it beats current best */
            if (pr->literal_count > best_literal_count) {
                best = i;
                best_literal_count = pr->literal_count;
            } else if (pr->literal_count == best_literal_count && best >= 0) {
                /* Tie-break: compare literal position vectors left to right
                 * Prefer the route with a literal segment in an earlier position */
                ParamRoute *prev = &router->param_routes[best];
                for (int s = 0; s < pr->segment_count; s++) {
                    if (pr->literal_mask[s] > prev->literal_mask[s]) {
                        best = i;
                        break;
                    } else if (pr->literal_mask[s] < prev->literal_mask[s]) {
                        break;
                    }
                }
            }
        }

        if (best >= 0) {
            /* Winner found — extract params and dispatch */
            ParamRoute *pr = &router->param_routes[best];
            RouteParams *params = route_params_create();

            if (!params) {
                for (int s = 0; s < req_seg_count; s++)
                    free(req_segments[s]);
                free(req_segments);
                log_error("Failed to allocate route params");
                return response_json_error(500, "Internal Server Error");
            }

            for (int s = 0; s < pr->segment_count; s++) {
                if (!pr->literal_mask[s]) {
                    route_params_add(params,
                                    extract_param_name(pr->segments[s]),
                                    req_segments[s]);
                }
            }

            for (int s = 0; s < req_seg_count; s++) {
                free(req_segments[s]);
            }
            free(req_segments);

            log_debug("Matched parameterized route: %s", pr->path_pattern);
            HttpResponse *resp = pr->handler(req, params);
            route_params_destroy(params);

            if (!resp) {
                log_error("Handler returned NULL for %s %s", req->method_str, req->path);
                return response_json_error(500, "Internal Server Error");
            }
            return resp;
        }

        /* No parameterized match — clean up and fall through to 404 */
        if (req_segments) {
            for (int s = 0; s < req_seg_count; s++) {
                free(req_segments[s]);
            }
            free(req_segments);
        }
    }
#endif

    /* No route matched */
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
