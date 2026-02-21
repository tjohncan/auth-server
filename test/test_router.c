#include "server/router.h"
#include "handlers.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ============================================================================
 * Handler Functions (examples)
 * ============================================================================ */

HttpResponse *health_handler(const HttpRequest *req, const RouteParams *params) {
    (void)req;     /* Unused */
    (void)params;  /* Unused */

    return response_json_ok("{\"status\":\"ok\"}");
}

HttpResponse *get_user_handler(const HttpRequest *req, const RouteParams *params) {
    (void)req;  /* Unused */

    const char *user_id = route_params_get(params, "id");
    if (!user_id) {
        return response_json_error(400, "Missing user ID");
    }

    /* Build response with user ID */
    char json[256];
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\",\"name\":\"Test User\"}", user_id);

    return response_json_ok(json);
}

HttpResponse *create_user_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;  /* Unused */

    /* Just log the body for now */
    printf("Creating user with body: %.*s\n", (int)req->body_length,
           req->body ? req->body : "(no body)");

    return response_json_ok("{\"status\":\"created\",\"id\":\"123\"}");
}

HttpResponse *get_post_handler(const HttpRequest *req, const RouteParams *params) {
    (void)req;  /* Unused */

    const char *user_id = route_params_get(params, "user_id");
    const char *post_id = route_params_get(params, "post_id");

    if (!user_id || !post_id) {
        return response_json_error(400, "Missing parameters");
    }

    char json[256];
    snprintf(json, sizeof(json),
             "{\"user_id\":\"%s\",\"post_id\":\"%s\",\"title\":\"Test Post\"}",
             user_id, post_id);

    return response_json_ok(json);
}

/* ============================================================================
 * Test Cases
 * ============================================================================ */

void test_exact_match(Router *router) {
    printf("\n=== Test: Exact Match ===\n");

    /* Create request */
    char req_str[] = "GET /health HTTP/1.0\r\n\r\n";
    HttpRequest req = http_request_parse(req_str, strlen(req_str));

    /* Dispatch */
    HttpResponse *resp = router_dispatch(router, &req);
    assert(resp != NULL);
    assert(resp->status_code == 200);

    printf("✓ /health matched and returned 200\n");

    http_response_free(resp);
    http_request_cleanup(&req);
}

#if ROUTER_USE_PATH_PARAMS
void test_path_params(Router *router) {
    printf("\n=== Test: Path Parameters ===\n");

    /* Create request */
    char req_str[] = "GET /users/456 HTTP/1.0\r\n\r\n";
    HttpRequest req = http_request_parse(req_str, strlen(req_str));

    /* Dispatch */
    HttpResponse *resp = router_dispatch(router, &req);
    assert(resp != NULL);
    assert(resp->status_code == 200);

    /* Serialize to check body contains "456" */
    size_t resp_len;
    char *serialized = http_response_serialize(resp, &resp_len);
    assert(strstr(serialized, "456") != NULL);

    printf("✓ /users/:id matched, extracted id=456\n");

    free(serialized);
    http_response_free(resp);
    http_request_cleanup(&req);
}

void test_multiple_params(Router *router) {
    printf("\n=== Test: Multiple Path Parameters ===\n");

    /* Create request */
    char req_str[] = "GET /users/42/posts/99 HTTP/1.0\r\n\r\n";
    HttpRequest req = http_request_parse(req_str, strlen(req_str));

    /* Dispatch */
    HttpResponse *resp = router_dispatch(router, &req);
    assert(resp != NULL);
    assert(resp->status_code == 200);

    /* Check response contains both IDs */
    size_t resp_len;
    char *serialized = http_response_serialize(resp, &resp_len);
    assert(strstr(serialized, "42") != NULL);
    assert(strstr(serialized, "99") != NULL);

    printf("✓ Multiple params extracted: user_id=42, post_id=99\n");

    free(serialized);
    http_response_free(resp);
    http_request_cleanup(&req);
}

void test_method_filtering(Router *router) {
    printf("\n=== Test: Method Filtering ===\n");

    /* Test GET /users/123 - should match get_user_handler */
    char req1_str[] = "GET /users/123 HTTP/1.0\r\n\r\n";
    HttpRequest req1 = http_request_parse(req1_str, strlen(req1_str));
    HttpResponse *resp1 = router_dispatch(router, &req1);
    assert(resp1->status_code == 200);
    http_response_free(resp1);
    http_request_cleanup(&req1);

    /* Test POST /users - should match create_user_handler */
    char req2_str[] = "POST /users HTTP/1.0\r\nContent-Length: 0\r\n\r\n";
    HttpRequest req2 = http_request_parse(req2_str, strlen(req2_str));
    HttpResponse *resp2 = router_dispatch(router, &req2);
    assert(resp2->status_code == 200);
    http_response_free(resp2);
    http_request_cleanup(&req2);

    printf("✓ GET and POST handled separately\n");
}

void test_segment_count_mismatch(Router *router) {
    printf("\n=== Test: Segment Count Mismatch ===\n");

    /* Too many segments */
    char req1_str[] = "GET /users/123/extra HTTP/1.0\r\n\r\n";
    HttpRequest req1 = http_request_parse(req1_str, strlen(req1_str));
    HttpResponse *resp1 = router_dispatch(router, &req1);
    assert(resp1->status_code == 404);
    http_response_free(resp1);
    http_request_cleanup(&req1);

    /* Too few segments */
    char req2_str[] = "GET /users HTTP/1.0\r\n\r\n";
    HttpRequest req2 = http_request_parse(req2_str, strlen(req2_str));
    HttpResponse *resp2 = router_dispatch(router, &req2);
    assert(resp2->status_code == 404);
    http_response_free(resp2);
    http_request_cleanup(&req2);

    printf("✓ Segment count mismatch correctly returns 404\n");
}
#endif /* ROUTER_USE_PATH_PARAMS */

void test_404(Router *router) {
    printf("\n=== Test: 404 Not Found ===\n");

    /* Request non-existent route */
    char req_str[] = "GET /nonexistent HTTP/1.0\r\n\r\n";
    HttpRequest req = http_request_parse(req_str, strlen(req_str));

    HttpResponse *resp = router_dispatch(router, &req);
    assert(resp != NULL);
    assert(resp->status_code == 404);

    printf("✓ Unmatched route returned 404\n");

    http_response_free(resp);
    http_request_cleanup(&req);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    log_init(LOG_INFO);
    log_info("Router Test Suite");

    /* Set up router with all routes */
    printf("\n--- Setting up router ---\n");
    Router *router = router_create();
    router_add(router, HTTP_GET, "/health", health_handler);
#if ROUTER_USE_PATH_PARAMS
    router_add(router, HTTP_GET, "/users/:id", get_user_handler);
    router_add(router, HTTP_GET, "/users/:user_id/posts/:post_id", get_post_handler);
    router_add(router, HTTP_POST, "/users", create_user_handler);
#endif

    /* Run tests */
    test_exact_match(router);
    test_404(router);
#if ROUTER_USE_PATH_PARAMS
    test_path_params(router);
    test_multiple_params(router);
    test_method_filtering(router);
    test_segment_count_mismatch(router);
#else
    printf("\n=== Path parameter tests skipped (ROUTER_USE_PATH_PARAMS=0) ===\n");
#endif

    router_destroy(router);
    printf("\n=== All Router Tests Passed! ===\n\n");

    return 0;
}
