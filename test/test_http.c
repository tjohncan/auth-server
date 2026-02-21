#include "server/http.h"
#include "handlers.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void test_request_parsing(void) {
    printf("\n=== Testing HTTP Request Parsing ===\n\n");

    /* Test 1: Simple GET request */
    char req1[] =
        "GET /health HTTP/1.0\r\n"
        "Host: localhost:8080\r\n"
        "User-Agent: curl/7.68.0\r\n"
        "\r\n";

    HttpRequest parsed1 = http_request_parse(req1, strlen(req1));

    assert(parsed1.method == HTTP_GET);
    assert(strcmp(parsed1.method_str, "GET") == 0);
    assert(strcmp(parsed1.path, "/health") == 0);
    assert(parsed1.query_string == NULL);
    assert(parsed1.header_count == 2);
    assert(strcmp(http_request_get_header(&parsed1, "Host"), "localhost:8080") == 0);
    assert(strcmp(http_request_get_header(&parsed1, "User-Agent"), "curl/7.68.0") == 0);
    assert(parsed1.body == NULL);
    assert(parsed1.body_length == 0);

    printf("✓ Simple GET request parsed correctly\n");
    http_request_cleanup(&parsed1);

    /* Test 2: GET with query string */
    char req2[] =
        "GET /users?id=123&name=test HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "\r\n";

    HttpRequest parsed2 = http_request_parse(req2, strlen(req2));

    assert(parsed2.method == HTTP_GET);
    assert(strcmp(parsed2.path, "/users") == 0);
    assert(strcmp(parsed2.query_string, "id=123&name=test") == 0);

    printf("✓ GET with query string parsed correctly\n");
    http_request_cleanup(&parsed2);

    /* Test 3: POST with body */
    char req3[] =
        "POST /api/login HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 27\r\n"
        "\r\n"
        "{\"user\":\"test\",\"pass\":\"123\"}";

    HttpRequest parsed3 = http_request_parse(req3, strlen(req3));

    assert(parsed3.method == HTTP_POST);
    assert(strcmp(parsed3.path, "/api/login") == 0);
    assert(parsed3.body != NULL);
    assert(parsed3.body_length == 27);
    assert(strncmp(parsed3.body, "{\"user\":\"test\"", 14) == 0);
    assert(strcmp(http_request_get_header(&parsed3, "Content-Type"), "application/json") == 0);

    printf("✓ POST with JSON body parsed correctly\n");

    /* Test 4: Case-insensitive header lookup (before cleanup!) */
    assert(strcmp(http_request_get_header(&parsed3, "content-type"), "application/json") == 0);
    assert(strcmp(http_request_get_header(&parsed3, "CONTENT-TYPE"), "application/json") == 0);

    printf("✓ Case-insensitive header lookup works\n");

    http_request_cleanup(&parsed3);
}

void test_response_building(void) {
    printf("\n=== Testing HTTP Response Building ===\n\n");

    /* Test 1: Simple JSON response */
    HttpResponse *resp1 = response_json_ok("{\"status\":\"ok\"}");
    assert(resp1 != NULL);
    assert(resp1->status_code == 200);
    assert(strcmp(resp1->status_text, "OK") == 0);

    size_t len1;
    char *serialized1 = http_response_serialize(resp1, &len1);
    assert(serialized1 != NULL);

    printf("Response 1 (%zu bytes):\n%.*s\n", len1, (int)len1, serialized1);

    /* Verify it contains expected parts */
    assert(strstr(serialized1, "HTTP/1.0 200 OK") != NULL);
    assert(strstr(serialized1, "Content-Type: application/json") != NULL);
    assert(strstr(serialized1, "Content-Length: 15") != NULL);
    assert(strstr(serialized1, "{\"status\":\"ok\"}") != NULL);

    printf("✓ JSON response built correctly\n");

    free(serialized1);
    http_response_free(resp1);

    /* Test 2: Error response */
    HttpResponse *resp2 = response_json_error(404, "Not Found");
    assert(resp2->status_code == 404);
    assert(strcmp(resp2->status_text, "Not Found") == 0);

    size_t len2;
    char *serialized2 = http_response_serialize(resp2, &len2);

    printf("\nResponse 2 (%zu bytes):\n%.*s\n", len2, (int)len2, serialized2);

    assert(strstr(serialized2, "HTTP/1.0 404 Not Found") != NULL);
    assert(strstr(serialized2, "{\"error\":\"Not Found\"}") != NULL);

    printf("✓ Error response built correctly\n");

    free(serialized2);
    http_response_free(resp2);

    /* Test 3: Custom headers */
    HttpResponse *resp3 = http_response_new(200);
    http_response_set_header(resp3, "X-Custom-Header", "test-value");
    http_response_set_header(resp3, "X-Another", "foo");
    http_response_set_body_str(resp3, "Hello World");

    size_t len3;
    char *serialized3 = http_response_serialize(resp3, &len3);

    printf("\nResponse 3 (%zu bytes):\n%.*s\n", len3, (int)len3, serialized3);

    assert(strstr(serialized3, "X-Custom-Header: test-value") != NULL);
    assert(strstr(serialized3, "X-Another: foo") != NULL);
    assert(strstr(serialized3, "Hello World") != NULL);

    printf("✓ Custom headers work correctly\n");

    free(serialized3);
    http_response_free(resp3);
}

void test_real_world_request(void) {
    printf("\n=== Testing Real-World Request (from curl) ===\n\n");

    /* We accept both HTTP/1.0 and HTTP/1.1, but respond with HTTP/1.0 */
    char real_request[] =
        "GET /health HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "User-Agent: curl/8.8.0\r\n"
        "Accept: */*\r\n"
        "\r\n";

    printf("Parsing:\n%s", real_request);

    HttpRequest req = http_request_parse(real_request, strlen(real_request));

    assert(req.method == HTTP_GET);
    printf("✓ Method: %s\n", req.method_str);
    printf("✓ Path: %s\n", req.path);
    printf("✓ Headers (%d):\n", req.header_count);

    for (int i = 0; i < req.header_count; i++) {
        printf("    %s: %s\n", req.headers[i].name, req.headers[i].value);
    }

    http_request_cleanup(&req);
}

int main(void) {
    log_init(LOG_INFO);
    log_info("HTTP Parser Test Suite");

    test_request_parsing();
    test_response_building();
    test_real_world_request();

    printf("\n=== All Tests Passed! ===\n\n");

    return 0;
}
