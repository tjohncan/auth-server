/*
 * Fuzz harness for the authorization-code JWT decoder (jwt_decode_auth_request).
 * See test/fuzz/README.md for how to build and run.
 *
 * The decoder verifies the HMAC signature BEFORE it parses the payload, so a token
 * with a random or absent signature is rejected at the gate and never reaches the
 * hand-rolled JSON parsing, hex decoding, and base64url decoding that are the point
 * of fuzzing this. Handing raw bytes straight in would fuzz nothing but the reject
 * path and report a hollow "clean".
 *
 * So the harness signs for the fuzzer: it owns a fixed secret, lets the fuzzer author
 * the PAYLOAD, then base64url-encodes and HMAC-signs a well-formed token around it.
 * Every token clears the gate by construction, so every execution reaches the parsers.
 * This is the standard shape for fuzzing behind a signature check — the point is the
 * code past the gate, and only the holder of the secret can get bytes there, which in
 * production is this server verifying codes it minted itself.
 */
#include "crypto/jwt.h"
#include "crypto/hmac.h"
#include "crypto/random.h"
#include "util/log.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Fixed test secret, base64url of 32 bytes. Value is irrelevant — it only has to be
 * the same one the decoder is handed below, so signatures verify. */
static const char *SECRET_B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";

#define JWT_HDR "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

/* The decoder logs an error on every rejected token — millions of lines at fuzzing
 * speed, which buries the one line that matters (a sanitizer trace). Raise the log
 * floor above LOG_ERROR once at startup to mute it. Runs before the first input. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    log_init((LogLevel)(LOG_ERROR + 1));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Cap the payload so the assembled token stays under JWT_MAX_TOKEN_LENGTH (2048).
     * base64url is 4/3 overhead; 1200 bytes of payload leaves room for header,
     * signature, and the two dots. Longer inputs are truncated, not skipped. */
    if (size > 1200) size = 1200;

    unsigned char secret[256];
    int secret_len = crypto_base64url_decode(SECRET_B64, strlen(SECRET_B64),
                                             secret, sizeof(secret));
    if (secret_len <= 0) return 0;

    /* The fuzzer's bytes ARE the payload. It gets to invent the JSON: missing keys,
     * duplicate keys, unbalanced quotes, bad UTF-8, absurd escapes, huge numbers —
     * exactly the input the parsers past the gate must survive. */
    char header_b64[128];
    char payload_b64[2048];
    size_t header_b64_len = crypto_base64url_encode(
        (const unsigned char *)JWT_HDR, strlen(JWT_HDR), header_b64, sizeof(header_b64));
    size_t payload_b64_len = crypto_base64url_encode(
        data, size, payload_b64, sizeof(payload_b64));
    if (header_b64_len == 0 || payload_b64_len == 0) return 0;

    /* Sign header.payload with our secret, exactly as jwt_encode_auth_request does. */
    char signing_input[2560];
    int signing_len = snprintf(signing_input, sizeof(signing_input),
                               "%s.%s", header_b64, payload_b64);
    if (signing_len < 0 || (size_t)signing_len >= sizeof(signing_input)) return 0;

    unsigned char sig[HMAC_SHA256_LENGTH];
    if (crypto_hmac_sha256(secret, secret_len,
                           (const unsigned char *)signing_input, signing_len,
                           sig, sizeof(sig)) != 0) return 0;

    char sig_b64[128];
    size_t sig_b64_len = crypto_base64url_encode(sig, sizeof(sig), sig_b64, sizeof(sig_b64));
    if (sig_b64_len == 0) return 0;

    char token[JWT_MAX_TOKEN_LENGTH];
    int token_len = snprintf(token, sizeof(token), "%s.%s", signing_input, sig_b64);
    if (token_len < 0 || (size_t)token_len >= sizeof(token)) return 0;

    /* Now decode the validly-signed token. Reaches every parser past the gate. */
    auth_request_claims_t claims;
    jwt_decode_auth_request(token, SECRET_B64, NULL, &claims);

    return 0;
}

#ifdef FUZZ_STANDALONE
/* Replay mode: run one input from a file (or stdin) under ASan/UBSan. No clang
 * needed — this is what `make fuzz-regress` uses to replay the saved crash seeds. */
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
