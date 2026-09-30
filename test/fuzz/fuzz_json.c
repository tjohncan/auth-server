/*
 * Fuzz harness for the JSON request-body helpers in src/util/json.c.
 * See test/fuzz/README.md for how to build and run.
 *
 * Mirrors the request path. router_dispatch runs json_utf8_valid and
 * json_escapes_valid over every body that isn't form-encoded, and handlers then
 * read fields with json_get_string, json_get_int and json_get_bool. The body is a
 * NUL-terminated copy, as the HTTP parser leaves it.
 *
 * Not crashing is the floor. Two properties are checked too, and a violation
 * aborts, which libFuzzer reports like a crash:
 *   - json_unescape works in place, so it must never lengthen a string;
 *   - once a body has passed both whole-body checks, every string a handler can
 *     read from it is well-formed UTF-8: escapes decode to UTF-8, and the raw
 *     bytes were checked before any field was read.
 */
#include "util/json.h"
#include "util/log.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Keys handlers read, so lookups hit as well as miss. "" probes the edge. */
static const char *KEYS[] = {
    "username", "password", "email", "user_id", "display_name", "note",
    "enabled", "limit", "",
};

/* The helpers log on some rejects; mute them so a sanitizer trace isn't buried. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    log_init((LogLevel)(LOG_ERROR + 1));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *body = malloc(size + 1);
    if (!body) return 0;
    memcpy(body, data, size);
    body[size] = '\0';

    int checked = json_utf8_valid(body, size) && json_escapes_valid(body);

    for (size_t k = 0; k < sizeof(KEYS) / sizeof(KEYS[0]); k++) {
        char *value = json_get_string(body, KEYS[k]);
        if (value) {
            if (checked && !json_utf8_valid(value, strlen(value))) abort();
            free(value);
        }
        int n, b;
        json_get_int(body, KEYS[k], &n);
        json_get_bool(body, KEYS[k], &b);
    }

    /* And json_unescape directly, on the whole input as one string */
    size_t before = strlen(body);
    if (json_unescape(body) == 0 && strlen(body) > before) abort();

    free(body);
    return 0;
}

#ifdef FUZZ_STANDALONE
/* Replay mode: run one input from a file (or stdin) under ASan/UBSan. No clang
 * needed — this is what `make fuzz-regress` uses to replay the saved seeds. */
#include <stdio.h>
int main(int argc, char **argv) {
    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) { perror("open"); return 1; }
    static unsigned char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (f != stdin) fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
#endif
