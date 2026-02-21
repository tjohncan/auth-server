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
