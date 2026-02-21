#include "handlers.h"

/*
 * GET /health
 *
 * Health check endpoint - returns 200 OK with status.
 * Used by load balancers, Kubernetes probes, monitoring systems.
 */
HttpResponse *health_handler(const HttpRequest *req, const RouteParams *params) {
    (void)req;     /* Unused */
    (void)params;  /* Unused */

    return response_json_ok("{\"status\":\"ok\"}");
}
