#ifndef ROUTER_H
#define ROUTER_H

#include "http.h"

/*
 * Router - Maps HTTP requests to handler functions
 *
 * Supports:
 * - Exact path matching: "/health"
 * - Path parameters: "/users/:id" matches "/users/123" and captures id=123
 * - Method filtering: GET /health != POST /health
 * - 404 for unmatched routes
 *
 * Pattern matching rules:
 * - Segments starting with ':' are parameters (e.g., ":id", ":username")
 * - Segment count must match exactly (no wildcards)
 * - Case-sensitive matching
 *
 * Example:
 *   Router *r = router_create();
 *   router_add(r, HTTP_GET, "/health", health_handler);
 *   router_add(r, HTTP_GET, "/users/:id", get_user_handler);
 *   router_add(r, HTTP_POST, "/users", create_user_handler);
 *
 *   HttpResponse *resp = router_dispatch(r, request);
 */

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

typedef struct Router Router;
typedef struct RouteParams RouteParams;

/* ============================================================================
 * Handler Function Signature
 * ============================================================================ */

/*
 * Route handler - called when a route matches
 *
 * Parameters:
 *   req    - Parsed HTTP request
 *   params - Extracted path parameters (e.g., id=123 from /users/:id)
 *
 * Returns: HTTP response (caller must free with http_response_free)
 */
typedef HttpResponse *(*RouteHandler)(const HttpRequest *req, const RouteParams *params);

/* ============================================================================
 * Router API
 * ============================================================================ */

/*
 * router_create - Create a new router
 */
Router *router_create(void);

/*
 * router_destroy - Free router and all routes
 */
void router_destroy(Router *router);

/*
 * router_add - Register a route
 *
 * Parameters:
 *   router  - Router instance
 *   method  - HTTP method (HTTP_GET, HTTP_POST, etc.)
 *   path    - Path pattern (e.g., "/users/:id")
 *   handler - Handler function to call when route matches
 *
 * Example:
 *   router_add(r, HTTP_GET, "/health", health_handler);
 *   router_add(r, HTTP_GET, "/users/:id", get_user_handler);
 */
void router_add(Router *router, HttpMethod method, const char *path, RouteHandler handler);

/*
 * router_dispatch - Find matching route and call handler
 *
 * Parameters:
 *   router - Router instance
 *   req    - Parsed HTTP request
 *
 * Returns: HTTP response (never NULL - returns 404 if no route matches)
 *          Caller must free with http_response_free()
 */
HttpResponse *router_dispatch(Router *router, const HttpRequest *req);

/* ============================================================================
 * CORS
 * ============================================================================ */

/*
 * The paths a browser on another origin may read a response from
 *
 * This array is the entire cross-origin surface. It is deliberately a set of
 * paths rather than a helper a handler could call, because a handler that can
 * opt itself in is one plausible line away from being added to a
 * cookie-authenticated endpoint. Adding an endpoint here means editing one
 * greppable array and the test that pins it.
 *
 * All four authenticate by PKCE, by bearer token, or by a client secret in the
 * request body. None reads a cookie, which is the thing `*` would be dangerous
 * with — and the Fetch standard refuses a `*` response to any request made with
 * credentials, so this cannot expose cookie-authenticated data even by mistake.
 */
extern const char *const CORS_PUBLIC_PATHS[];
extern const int CORS_PUBLIC_PATH_COUNT;

/*
 * Is this exact path in the CORS set?
 *
 * Returns: 1 if it is, 0 otherwise
 */
int router_path_allows_cors(const char *path);

/*
 * Check every CORS path is a registered route
 *
 * Call once after registration. A typo in CORS_PUBLIC_PATHS otherwise fails
 * open into silently sending no header, which presents as "the browser client
 * still does not work" and costs an afternoon to trace back to here.
 *
 * Returns: 0 if all are registered, otherwise how many are missing (each logged)
 */
int router_validate_cors_paths(const Router *router);

/* ============================================================================
 * Route Parameters API
 * ============================================================================ */

/*
 * route_params_get - Get a path parameter by name
 *
 * Example:
 *   // Route pattern: "/users/:id"
 *   // Request path:   "/users/123"
 *   const char *user_id = route_params_get(params, "id");  // Returns "123"
 *
 * Returns: Parameter value, or NULL if not found
 */
const char *route_params_get(const RouteParams *params, const char *name);

#endif /* ROUTER_H */
