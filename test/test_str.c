#include "util/str.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void test_str_copy(void) {
    printf("\n=== Testing str_copy ===\n\n");

    char buffer[10];

    char *input, *output, *expected;
    size_t written;

    /* Normal copy (fits) */
    input = "Short";
    output = buffer;
    expected = "Short";
    written = str_copy(output, 10, input);
    assert(strcmp(output, expected) == 0);
    printf("Copied '%s' to buffer[10]: '%s' (%zu bytes incl. term.)\n", input, output, written);

    /* Truncation (doesn't fit) */
    input = "Too loooooong";
    output = buffer;
    expected = "Too loooo";
    written = str_copy(output, 10, input);
    assert(strcmp(output, expected) == 0);
    printf("Copied '%s' to buffer[10]: '%s' (%zu bytes incl. term.)\n", input, output, written);
}

void test_str_dup(void) {
    printf("\n=== Testing str_dup ===\n\n");

    char *copy = str_dup("Copy this");
    assert(copy != NULL);
    printf("At %p (%zu bytes): '%s' (from literal)\n", (void*)copy, strlen(copy) + 1, copy);
    free(copy);

    const char *original = "Copy that";
    char *second = str_dup(original);
    assert(second != NULL);
    assert(strcmp(original, second) == 0);
    printf("At %p (%zu bytes): '%s' (from %p)\n", (void*)second, strlen(second) + 1, second, (void*)original);
    free(second);
}

void test_str_split(void) {
    printf("\n=== Testing str_split ===\n\n");

    char *to_split = "typical,csv,header,row";
    char splitter = ',';

    printf("Split '%s' by '%c' ->\n", to_split, splitter);

    int count;
    char **parts = str_split(to_split, splitter, &count);
    assert(parts != NULL);
    printf("At %p (%d parts):\n", (void*)parts, count);
    for (int i = 0; i < count; i++) {
        printf("  part %d: '%s' (at %p)\n", i, parts[i], (void*)parts[i]);
        free(parts[i]);  // Free each part
    }
    free(parts);  // Free the array of parts

    /* Test edge cases */
    printf("\n--- Edge cases ---\n");

    /* Empty parts */
    to_split = "1||3"; splitter = '|';
    parts = str_split(to_split, splitter, &count);
    printf("Split '%s' by '%c' -> %d parts: ", to_split, splitter, count);
    for (int i = 0; i < count; i++) {
        printf("'%s'%s", parts[i], (i < count - 1) ? ", " : "\n");
        free(parts[i]);
    }
    free(parts);

    /* No delimiter */
    to_split = "whole"; splitter = '?';
    parts = str_split(to_split, splitter, &count);
    printf("Split '%s' by '%c' -> %d parts: ", to_split, splitter, count);
    for (int i = 0; i < count; i++) {
        printf("'%s'%s", parts[i], (i < count - 1) ? ", " : "\n");
        free(parts[i]);
    }
    free(parts);
}

void test_memmem_nocase(void) {
    printf("\n=== Testing memmem_nocase ===\n\n");

    const char *req = "POST /api HTTP/1.1\r\nHost: localhost\r\ntransfer-encOding: chunked\r\n\r\n";
    void *pos = memmem_nocase(req, strlen(req), "\r\nTransfer-Encoding", 19);
    assert(pos != NULL);
    printf("Case-insensitive match for '\\r\\nTransfer-Encoding' found at offset %td\n", (char *)pos - req);
}

int main(void) {
    log_init(LOG_INFO);
    log_info("TESTING - String Utilities");

    test_str_copy();
    test_str_dup();
    test_str_split();
    test_memmem_nocase();

    printf("\n=== All tests complete ===\n");

    return 0;
}
