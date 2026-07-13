/*
 * Fuzz harness for the HTTP request path (http_request_parse + its accessors).
 * See test/fuzz/README.md for how to build and run.
 *
 * The harness models src/main.c:router_request_handler() byte for byte: same
 * private NUL-terminated copy of the socket bytes, same parse call, same
 * accessors on the way out. If it diverges from that, it is fuzzing fiction.
 */
#include "server/http.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The parser mutates its buffer in place, so hand it a private, exactly-sized,
     * NUL-terminated copy — byte-for-byte how the real server does it (src/main.c). */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    HttpRequest req = http_request_parse(buf, size);

    /* A rejected request is answered with a 400 and never touched again, so the
     * accessors below are only reachable on a request that parsed. Gating on that
     * keeps the harness honest rather than fuzzing states production can't reach. */
    if (req.method != HTTP_UNKNOWN) {
        /* Header lookup: walks every parsed header and strcasecmp()s the names. */
        http_request_get_header(&req, "Content-Type");
        http_request_get_header(&req, "Content-Length");

        /* Client IP: memcpy()s an attacker-controlled X-Forwarded-For / X-Real-IP
         * value into a fixed 46-byte buffer. Every production caller passes NULL
         * for the socket_ip fallback, so we do too. */
        http_request_get_client_ip(&req, NULL);
    }

    http_request_cleanup(&req);

    free(buf);
    return 0;
}

#ifdef FUZZ_STANDALONE
/* Replay mode: run one input from a file (or stdin) under ASan/UBSan. No clang
 * needed — this is what `make fuzz-regress` uses to replay the saved crash seeds
 * on a plain gcc box. Generates nothing; runs exactly the input you hand it. */
#include <stdio.h>
int main(int argc, char **argv) {
    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) { perror("open"); return 1; }
    static unsigned char buf[1 << 20];  /* 1 MB — matches DEFAULT_MAX_REQUEST_SIZE */
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (f != stdin) fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
#endif
