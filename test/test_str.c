#include "util/str.h"
#include "util/json.h"
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

void test_str_appendf(void) {
    printf("\n=== Testing str_appendf ===\n\n");

    char buf[16];
    size_t pos;

    /* Normal accumulation */
    pos = 0; buf[0] = '\0';
    assert(str_appendf(buf, sizeof(buf), &pos, "a=%d", 1) == 0);
    assert(str_appendf(buf, sizeof(buf), &pos, "&b=%s", "xy") == 0);
    assert(strcmp(buf, "a=1&b=xy") == 0);
    assert(pos == strlen(buf));
    printf("Accumulated '%s' (pos=%zu)\n", buf, pos);

    /* Truncation leaves pos where it was and keeps only whole appends */
    size_t before = pos;
    assert(str_appendf(buf, sizeof(buf), &pos, "&c=%s", "0123456789") == -1);
    assert(pos == before);
    assert(strcmp(buf, "a=1&b=xy") == 0);
    printf("Refused an overlong append; buffer intact: '%s' (pos=%zu)\n", buf, pos);

    /* ...so a later, smaller append still lands from the unchanged offset */
    assert(str_appendf(buf, sizeof(buf), &pos, "&c=%d", 7) == 0);
    assert(strcmp(buf, "a=1&b=xy&c=7") == 0);
    printf("Smaller append still fits: '%s'\n", buf);

    /* Exact fit: 15 bytes plus NUL into buf[16] */
    pos = 0; buf[0] = '\0';
    assert(str_appendf(buf, sizeof(buf), &pos, "%s", "123456789012345") == 0);
    assert(pos == 15 && strlen(buf) == 15);
    printf("Exact fit (15 into buf[16]): '%s'\n", buf);

    /* One byte past exact fit */
    pos = 0; buf[0] = '\0';
    assert(str_appendf(buf, sizeof(buf), &pos, "%s", "1234567890123456") == -1);
    assert(pos == 0 && buf[0] == '\0');
    printf("One byte over refused; buffer emptied\n");

    /* The whole point. `pos += snprintf(buf + pos, sizeof(buf) - pos, ...)` would put
     * pos far past sizeof(buf) on the first of these, and the second would then form
     * buf + pos out of bounds with sizeof(buf) - pos underflowed to a huge size_t.
     * Here pos cannot move at all, so a hundred of them are still harmless. */
    pos = 0; buf[0] = '\0';
    for (int i = 0; i < 100; i++) {
        str_appendf(buf, sizeof(buf), &pos, "%s", "aaaaaaaaaaaaaaaaaaaaaaaa");
    }
    assert(pos == 0);
    assert(pos < sizeof(buf));
    printf("100 overlong appends: pos still %zu, never past %zu\n", pos, sizeof(buf));

    /* Entry guard: a caller that advanced pos itself still cannot make us write out
     * of bounds. str_appendf's own invariant keeps pos < size, so this is unreachable
     * from the calls above — which is exactly why it is worth pinning, since it is
     * what makes the header's "cannot walk off the end" promise true for a caller
     * that manipulates pos directly. */
    pos = sizeof(buf);
    assert(str_appendf(buf, sizeof(buf), &pos, "x") == -1);
    assert(pos == sizeof(buf));
    pos = sizeof(buf) + 100;
    assert(str_appendf(buf, sizeof(buf), &pos, "x") == -1);
    assert(pos == sizeof(buf) + 100);
    printf("Entry guard holds for pos at and past the end of the buffer\n");

    /* Bad arguments */
    pos = 0;
    assert(str_appendf(NULL, sizeof(buf), &pos, "x") == -1);
    assert(str_appendf(buf, 0, &pos, "x") == -1);
    assert(str_appendf(buf, sizeof(buf), NULL, "x") == -1);
    printf("NULL and zero-size arguments refused\n");
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

void test_str_url_encode_decode(void) {
    printf("\n=== Testing str_url_encode / str_url_decode ===\n\n");

    char encoded[256];
    char decoded[256];

    /* Encode: reserved symbols become %XX, unreserved (A-Z a-z 0-9 - _ . ~) pass through */
    const char *input = "a=1&b=2 c+d@e:f/g?h#i";
    int enc_len = str_url_encode(encoded, sizeof(encoded), input);
    assert(enc_len > 0);
    printf("Encode '%s' -> '%s' (%d bytes)\n", input, encoded, enc_len);

    /* Decode: round-trip back to original */
    int dec_len = str_url_decode(decoded, sizeof(decoded), encoded);
    assert(dec_len > 0);
    assert(strcmp(decoded, input) == 0);
    printf("Decode '%s' -> '%s' (%d bytes)\n", encoded, decoded, dec_len);
}

void test_str_html_escape(void) {
    printf("\n=== Testing str_html_escape ===\n\n");

    char buf[256];
    size_t written;

    /* All five entity escapes */
    written = str_html_escape(buf, sizeof(buf), "&<>\"'");
    assert(written > 0);
    assert(strcmp(buf, "&amp;&lt;&gt;&quot;&#39;") == 0);
    printf("Escaped '&<>\"\\'' -> '%s' (%zu bytes)\n", buf, written);

    /* Safe text passes through unchanged */
    written = str_html_escape(buf, sizeof(buf), "Hello World 123");
    assert(written > 0);
    assert(strcmp(buf, "Hello World 123") == 0);
    printf("Escaped 'Hello World 123' -> '%s'\n", buf);

    /* Mixed content */
    written = str_html_escape(buf, sizeof(buf), "<script>alert('xss')</script>");
    assert(written > 0);
    assert(strcmp(buf, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;") == 0);
    printf("Escaped XSS payload -> '%s'\n", buf);

    /* Buffer too small returns 0 and null-terminates */
    written = str_html_escape(buf, 5, "&<>");
    assert(written == 0);
    assert(buf[0] == '\0');
    printf("Buffer too small (first char): returned %zu, null-terminated\n", written);

    /* Partial write then truncation: 'a' fits, '&' doesn't */
    written = str_html_escape(buf, 4, "a&b");
    assert(written == 0);
    assert(buf[0] == 'a');
    assert(buf[1] == '\0');
    printf("Buffer too small (mid-string): partial 'a' + null-terminated\n");

    /* Empty string */
    written = str_html_escape(buf, sizeof(buf), "");
    assert(strcmp(buf, "") == 0);
    printf("Empty string: '%s' (%zu bytes)\n", buf, written);
}

void test_json_escape(void) {
    printf("\n=== Testing json_escape ===\n\n");

    char buf[256];
    size_t written;

    /* Quotes and backslash */
    written = json_escape(buf, sizeof(buf), "say \"hello\\world\"");
    assert(written > 0);
    assert(strcmp(buf, "say \\\"hello\\\\world\\\"") == 0);
    printf("Escaped quotes/backslash -> '%s'\n", buf);

    /* Control characters */
    written = json_escape(buf, sizeof(buf), "line1\tline2\nline3");
    assert(written > 0);
    assert(strcmp(buf, "line1\\tline2\\nline3") == 0);
    printf("Escaped control chars -> '%s'\n", buf);

    /* Low control char (0x01) gets \u0001 */
    written = json_escape(buf, sizeof(buf), "\x01");
    assert(written > 0);
    assert(strcmp(buf, "\\u0001") == 0);
    printf("Escaped 0x01 -> '%s'\n", buf);

    /* Safe text passes through */
    written = json_escape(buf, sizeof(buf), "abc 123");
    assert(written > 0);
    assert(strcmp(buf, "abc 123") == 0);
    printf("Safe text unchanged: '%s'\n", buf);
}

void test_json_escaped_len(void) {
    printf("\n=== Testing json_escaped_len ===\n\n");

    char buf[256];
    size_t written, need;

    assert(json_escaped_len("") == 0);
    assert(json_escaped_len(NULL) == 0);
    assert(json_escaped_len("abc 123") == 7);       /* nothing escapes */
    assert(json_escaped_len("say \"hi\"") == 10);   /* two quotes, +1 each */
    assert(json_escaped_len("\t") == 2);            /* \t */
    assert(json_escaped_len("\x01") == 6);          /* escapes to six bytes */
    printf("Measured plain, quoted, \\t and \\u0001 forms\n");

    /* Agreement with json_escape() given room to work */
    const char *mixed = "line\t\"one\"\x01";
    need = json_escaped_len(mixed);
    written = json_escape(buf, sizeof(buf), mixed);
    assert(need == written);
    printf("Measured %zu, json_escape wrote %zu -> '%s'\n", need, written, buf);

    /* The check json_escape() cannot make for you. Given a destination that is
     * too small it truncates, yet still reports a count below dst_size — so the
     * natural-looking `written < dst_size` test is true for every input, which is
     * exactly why the guard in jwt.c's json_escape_string() never fired. */
    const char *needs_room = "\x01\x01\x01";        /* three six-byte escapes = 18 bytes */
    char small[8];
    need = json_escaped_len(needs_room);
    written = json_escape(small, sizeof(small), needs_room);
    assert(need == 18);
    assert(written < sizeof(small));                /* old test: reports success */
    assert(need >= sizeof(small));                  /* truth: it did not fit */
    printf("Truncated into buf[%zu]: wrote %zu, actually needed %zu\n",
           sizeof(small), written, need);

    /* Exact fit: json_escaped_len() + 1 is enough, and not a byte more */
    char exact[19];
    written = json_escape(exact, sizeof(exact), needs_room);
    assert(written == 18);
    assert(strcmp(exact, "\\u0001\\u0001\\u0001") == 0);
    printf("Exact fit into buf[%zu]: '%s'\n", sizeof(exact), exact);
}

void test_json_unescape(void) {
    printf("\n=== Testing json_unescape ===\n\n");

    char buf[256];

    /* Standard escapes */
    strcpy(buf, "say \\\"hello\\\\world\\\"");
    json_unescape(buf);
    assert(strcmp(buf, "say \"hello\\world\"") == 0);
    printf("Unescaped quotes/backslash -> '%s'\n", buf);

    /* Tab and newline */
    strcpy(buf, "col1\\tcol2\\nrow2");
    json_unescape(buf);
    assert(strcmp(buf, "col1\tcol2\nrow2") == 0);
    printf("Unescaped \\t and \\n -> (contains tab and newline)\n");

    /* \\uXXXX for printable ASCII */
    strcpy(buf, "\\u003Cscript\\u003E");
    json_unescape(buf);
    assert(strcmp(buf, "<script>") == 0);
    printf("Unescaped \\u003C/\\u003E -> '%s'\n", buf);

    /* Round-trip: escape then unescape */
    char escaped[256];
    json_escape(escaped, sizeof(escaped), "He said \"hi\" & <bye>");
    strcpy(buf, escaped);
    json_unescape(buf);
    assert(strcmp(buf, "He said \"hi\" & <bye>") == 0);
    printf("Round-trip: '%s' -> escape -> unescape -> '%s'\n",
           "He said \"hi\" & <bye>", buf);
}

int main(void) {
    log_init(LOG_INFO);
    log_info("TESTING - String Utilities");

    test_str_copy();
    test_str_appendf();
    test_str_dup();
    test_str_split();
    test_str_url_encode_decode();
    test_memmem_nocase();
    test_str_html_escape();
    test_json_escape();
    test_json_escaped_len();
    test_json_unescape();

    printf("\n=== All tests complete ===\n");

    return 0;
}
