#include "server/router.h"
#include "handlers.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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


/* ============================================================================
 * CORS
 * ============================================================================ */

static const char *header_value(const HttpResponse *resp, const char *name) {
    for (int i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i].name, name) == 0) {
            return resp->headers[i].value;
        }
    }
    return NULL;
}

static HttpResponse *request(Router *router, const char *raw) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", raw);
    HttpRequest req = http_request_parse(buf, strlen(buf));
    HttpResponse *resp = router_dispatch(router, &req);
    http_request_cleanup(&req);
    return resp;
}

/*
 * A JSON body with a refused string escape is answered 400 before any handler
 * runs, whichever field carries it. Per-field refusal alone would let a bad
 * OPTIONAL field pass as omitted. Form-encoded bodies are not JSON-checked.
 */
void test_json_body_escape_check(Router *router) {
    printf("\n=== Test: Whole-body JSON escape check ===\n");

    HttpResponse *resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"
        "{\"display_name\":\"X\",\"note\":\"a\\ud800\"}");
    assert(resp && resp->status_code == 400);
    printf("✓ bad escape in an optional field: %d\n", resp->status_code);
    http_response_free(resp);

    resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"
        "{\"display_name\":\"Caf\\u00e9\"}");
    assert(resp && resp->status_code == 200);
    printf("✓ valid escapes reach the handler: %d\n", resp->status_code);
    http_response_free(resp);

    resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        "token=\"a\\qb\"");
    assert(resp && resp->status_code == 200);
    printf("✓ form-encoded body is not JSON-checked: %d\n", resp->status_code);
    http_response_free(resp);
}

/*
 * A body that isn't UTF-8 is answered 400 before any handler runs, so SQLite and
 * PostgreSQL treat it alike. Raw UTF-8 passes, and form-encoded bodies are exempt.
 */
void test_json_body_utf8_check(Router *router) {
    printf("\n=== Test: Whole-body UTF-8 check ===\n");

    HttpResponse *resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"
        "{\"display_name\":\"X\",\"note\":\"a\xff\"}");
    assert(resp && resp->status_code == 400);
    assert(resp->body && strstr(resp->body, "not valid UTF-8"));
    printf("✓ invalid byte in an optional field: %d\n", resp->status_code);
    http_response_free(resp);

    resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"
        "{\"note\":\"\xed\xa0\x80\"}");
    assert(resp && resp->status_code == 400);
    printf("✓ an encoded surrogate: %d\n", resp->status_code);
    http_response_free(resp);

    resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"
        "{\"display_name\":\"Caf\xc3\xa9\"}");
    assert(resp && resp->status_code == 200);
    printf("✓ raw UTF-8 reaches the handler: %d\n", resp->status_code);
    http_response_free(resp);

    resp = request(router,
        "POST /revoke HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        "token=a\xff");
    assert(resp && resp->status_code == 200);
    printf("✓ form-encoded body is not UTF-8-checked: %d\n", resp->status_code);
    http_response_free(resp);
}

/*
 * Pin the set. Adding a fifth path has to fail here first, which forces somebody
 * to look at the endpoint rather than discover it in production.
 */
void test_cors_set_is_pinned(void) {
    printf("\n=== Test: CORS path set is pinned ===\n");

    static const char *const expected[] = {
        "/token",
        "/revoke",
        "/userinfo",
        "/.well-known/jwks.json",
    };
    const int expected_count = (int)(sizeof(expected) / sizeof(expected[0]));

    assert(CORS_PUBLIC_PATH_COUNT == expected_count);
    for (int i = 0; i < expected_count; i++) {
        assert(strcmp(CORS_PUBLIC_PATHS[i], expected[i]) == 0);
    }

    /* A pinned list alone would not catch a future cookie-authenticated endpoint
       whose name nobody thought to add here, so keep a prefix check as a second
       belt. Neither guard subsumes the other. */
    static const char *const forbidden_prefixes[] = {
        "/api/user", "/api/admin", "/api/rs", "/login",
    };
    for (int i = 0; i < CORS_PUBLIC_PATH_COUNT; i++) {
        for (size_t p = 0; p < sizeof(forbidden_prefixes) / sizeof(forbidden_prefixes[0]); p++) {
            assert(strncmp(CORS_PUBLIC_PATHS[i], forbidden_prefixes[p],
                           strlen(forbidden_prefixes[p])) != 0);
        }
    }

    assert(router_path_allows_cors("/token") == 1);
    assert(router_path_allows_cors("/userinfo") == 1);
    assert(router_path_allows_cors("/login") == 0);
    assert(router_path_allows_cors("/api/user/profile") == 0);
    assert(router_path_allows_cors("/authorize") == 0);
    assert(router_path_allows_cors("/token/extra") == 0);   /* exact match only */
    assert(router_path_allows_cors(NULL) == 0);

    printf("✓ exactly 4 paths, none cookie-authenticated, exact match only\n");
}

void test_cors_header_on_public_paths(Router *router) {
    printf("\n=== Test: CORS header only on the public paths ===\n");

    HttpResponse *resp = request(router, "GET /userinfo HTTP/1.0\r\n\r\n");
    assert(resp);
    assert(header_value(resp, "Access-Control-Allow-Origin") != NULL);
    assert(strcmp(header_value(resp, "Access-Control-Allow-Origin"), "*") == 0);
    /* `*` is only safe because credentials are never allowed alongside it. */
    assert(header_value(resp, "Access-Control-Allow-Credentials") == NULL);
    http_response_free(resp);

    resp = request(router, "GET /health HTTP/1.0\r\n\r\n");
    assert(resp);
    assert(header_value(resp, "Access-Control-Allow-Origin") == NULL);
    http_response_free(resp);

    /* A 404 on a CORS path still carries it — the browser has to be able to read
       the error, which is the whole failure mode this item is about. */
    resp = request(router, "POST /token HTTP/1.0\r\n\r\n");
    assert(resp);
    assert(header_value(resp, "Access-Control-Allow-Origin") != NULL);
    http_response_free(resp);

    printf("✓ header present on /userinfo and /token, absent on /health\n");
    printf("✓ no Access-Control-Allow-Credentials anywhere\n");
}

void test_cors_preflight(Router *router) {
    printf("\n=== Test: OPTIONS preflight ===\n");

    HttpResponse *resp = request(router, "OPTIONS /userinfo HTTP/1.0\r\n\r\n");
    assert(resp);
    assert(resp->status_code == 204);
    assert(resp->body == NULL || resp->body_length == 0);
    assert(strcmp(header_value(resp, "Access-Control-Allow-Origin"), "*") == 0);
    /* Every method the router will actually answer on these paths must be listed,
     * or a browser refuses the preflight for the one that is missing. HEAD is
     * CORS-safelisted so no browser preflights it today, but leaving it out would
     * be an internal disagreement between this list and what the router does. */
    assert(strstr(header_value(resp, "Access-Control-Allow-Methods"), "GET") != NULL);
    assert(strstr(header_value(resp, "Access-Control-Allow-Methods"), "HEAD") != NULL);
    assert(strstr(header_value(resp, "Access-Control-Allow-Methods"), "POST") != NULL);
    assert(strstr(header_value(resp, "Access-Control-Allow-Methods"), "OPTIONS") != NULL);
    assert(strstr(header_value(resp, "Access-Control-Allow-Headers"), "Authorization") != NULL);
    assert(strstr(header_value(resp, "Access-Control-Allow-Headers"), "Content-Type") != NULL);
    assert(header_value(resp, "Access-Control-Allow-Credentials") == NULL);
    http_response_free(resp);

    /* Gated on the same array as the header, so a path outside it is still a 404. */
    resp = request(router, "OPTIONS /login HTTP/1.0\r\n\r\n");
    assert(resp);
    assert(resp->status_code == 404);
    assert(header_value(resp, "Access-Control-Allow-Origin") == NULL);
    http_response_free(resp);

    printf("✓ 204 with allow-methods and allow-headers on /userinfo\n");
    printf("✓ 404 and no header for OPTIONS on a non-CORS path\n");
}

void test_cors_boot_validation(void) {
    printf("\n=== Test: boot validation catches a missing route ===\n");

    Router *empty = router_create();
    assert(router_validate_cors_paths(empty) == CORS_PUBLIC_PATH_COUNT);
    router_destroy(empty);

    Router *full = router_create();
    for (int i = 0; i < CORS_PUBLIC_PATH_COUNT; i++) {
        router_add(full, HTTP_GET, CORS_PUBLIC_PATHS[i], health_handler);
    }
    assert(router_validate_cors_paths(full) == 0);
    router_destroy(full);

    assert(router_validate_cors_paths(NULL) == -1);

    printf("✓ reports every unregistered CORS path, 0 when all present\n");

    /* An OPTIONS route would never be dispatched — router_dispatch answers
     * OPTIONS from the CORS array and returns before consulting the table — so
     * registration refuses it rather than letting it look registered. */
    Router *opts = router_create();
    router_add(opts, HTTP_OPTIONS, "/whatever", health_handler);
    assert(router_validate_cors_paths(opts) == CORS_PUBLIC_PATH_COUNT);

    HttpRequest req = http_request_parse((char[]){"OPTIONS /whatever HTTP/1.0\r\n\r\n"},
                                         strlen("OPTIONS /whatever HTTP/1.0\r\n\r\n"));
    HttpResponse *resp = router_dispatch(opts, &req);
    assert(resp && resp->status_code == 404);
    http_response_free(resp);
    http_request_cleanup(&req);
    router_destroy(opts);

    printf("✓ registering an OPTIONS route is refused, not silently shadowed\n");
}


/* ============================================================================
 * HEAD
 * ============================================================================ */

void test_head_requests(Router *router) {
    printf("\n=== Test: HEAD falls back to the GET route ===\n");

    HttpResponse *get = request(router, "GET /health HTTP/1.0\r\n\r\n");
    assert(get);
    assert(get->status_code == 200);
    assert(get->body && get->body_length > 0);
    const char *get_len = header_value(get, "Content-Length");
    assert(get_len != NULL);
    char expected_len[32];
    snprintf(expected_len, sizeof(expected_len), "%s", get_len);

    HttpResponse *head = request(router, "HEAD /health HTTP/1.0\r\n\r\n");
    assert(head);
    assert(head->status_code == 200);

    /* RFC 7231 4.3.2: same headers as GET, no body. Content-Length in particular
     * must be what GET would have sent, not 0 — that is what makes a HEAD useful
     * to whatever is probing with it. */
    assert(head->body == NULL);
    assert(head->body_length == 0);
    assert(header_value(head, "Content-Length") != NULL);
    assert(strcmp(header_value(head, "Content-Length"), expected_len) == 0);

    /* And the headers really are the same set, not a subset. */
    assert(head->header_count == get->header_count);

    http_response_free(get);
    http_response_free(head);
    printf("✓ HEAD /health: 200, no body, Content-Length still %s\n", expected_len);

    /* Serialization must emit the headers and stop at the blank line. */
    head = request(router, "HEAD /health HTTP/1.0\r\n\r\n");
    size_t out_len = 0;
    char *wire = http_response_serialize(head, &out_len);
    assert(wire);
    assert(strstr(wire, "Content-Length:") != NULL);
    assert(out_len >= 4 && memcmp(wire + out_len - 4, "\r\n\r\n", 4) == 0);
    free(wire);
    http_response_free(head);
    printf("✓ serialized HEAD response ends at the blank line\n");

    /* An unrouted path is still a 404 under HEAD. */
    head = request(router, "HEAD /nope HTTP/1.0\r\n\r\n");
    assert(head);
    assert(head->status_code == 404);
    assert(head->body == NULL);
    http_response_free(head);
    printf("✓ HEAD on an unrouted path is 404 with no body\n");

    /*
     * The regression this commit could cause. HEAD is handled after
     * dispatch_route and before the CORS attachment, precisely so that a HEAD on
     * a public endpoint keeps the header commit 5 added. Handling it as an early
     * return, the way OPTIONS is, would silently drop it here.
     */
    head = request(router, "HEAD /userinfo HTTP/1.0\r\n\r\n");
    assert(head);
    assert(header_value(head, "Access-Control-Allow-Origin") != NULL);
    assert(strcmp(header_value(head, "Access-Control-Allow-Origin"), "*") == 0);
    assert(head->body == NULL);
    http_response_free(head);

    head = request(router, "HEAD /health HTTP/1.0\r\n\r\n");
    assert(head);
    assert(header_value(head, "Access-Control-Allow-Origin") == NULL);
    http_response_free(head);
    printf("✓ HEAD keeps CORS on /userinfo and still has none on /health\n");
}

/*
 * Every response carries the server's own security headers, including the
 * anti-framing pair. They are set in http_response_new so no handler can
 * forget them; this pins that for a routed response and for the router's 404,
 * which never touches a handler. Without them, a deployment with no nginx in
 * front (the documented load-balancer topology) serves framable pages.
 */
void test_default_security_headers(Router *router) {
    printf("\n=== Test: Default security headers on every response ===\n");

    const char *raws[] = {
        "GET /health HTTP/1.0\r\n\r\n",
        "GET /no-such-path HTTP/1.0\r\n\r\n",
    };

    for (size_t i = 0; i < sizeof(raws) / sizeof(raws[0]); i++) {
        HttpResponse *resp = request(router, raws[i]);
        assert(resp);

        const char *nosniff = header_value(resp, "X-Content-Type-Options");
        const char *xfo = header_value(resp, "X-Frame-Options");
        const char *csp = header_value(resp, "Content-Security-Policy");

        assert(nosniff && strcmp(nosniff, "nosniff") == 0);
        assert(xfo && strcmp(xfo, "SAMEORIGIN") == 0);
        assert(csp && strcmp(csp, "frame-ancestors 'self'") == 0);

        printf("✓ %d response: nosniff, X-Frame-Options, frame-ancestors present\n",
               resp->status_code);
        http_response_free(resp);
    }
}

int main(void) {
    log_init(LOG_INFO);
    log_info("Router Test Suite");

    /* Set up router with all routes */
    printf("\n--- Setting up router ---\n");
    Router *router = router_create();
    router_add(router, HTTP_GET, "/health", health_handler);
    router_add(router, HTTP_GET, "/userinfo", health_handler);
    router_add(router, HTTP_POST, "/revoke", health_handler);
    router_add(router, HTTP_GET, "/.well-known/jwks.json", health_handler);
    /* /token is deliberately NOT registered here: a CORS path with no matching
       route must still get the header on its 404, or the browser cannot read the
       error either. */
#if ROUTER_USE_PATH_PARAMS
    router_add(router, HTTP_GET, "/users/:id", get_user_handler);
    router_add(router, HTTP_GET, "/users/:user_id/posts/:post_id", get_post_handler);
    router_add(router, HTTP_POST, "/users", create_user_handler);
#endif

    /* Run tests */
    test_exact_match(router);
    test_404(router);
    test_json_body_escape_check(router);
    test_json_body_utf8_check(router);
    test_cors_set_is_pinned();
    test_cors_header_on_public_paths(router);
    test_cors_preflight(router);
    test_cors_boot_validation();
    test_head_requests(router);
    test_default_security_headers(router);
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
