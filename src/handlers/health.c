#include "handlers.h"

/*
 * GET /health
 *
 * Health check endpoint - returns 200 OK with status.
 * Used by load balancers, Kubernetes probes, monitoring systems.
 */
HttpResponse *health_handler(const HttpRequest *req) {
    (void)req;     /* Unused */

    return response_json_ok("{\"status\":\"ok\"}");
}
