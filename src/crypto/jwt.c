#include "crypto/jwt.h"
#include "crypto/random.h"
#include "crypto/hmac.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Clock skew tolerance for JWT expiration checks (seconds) */
static int jwt_clock_skew_seconds = 0;  /* Default: strict validation */

void jwt_set_clock_skew_seconds(int seconds) {
    jwt_clock_skew_seconds = seconds;
}

/* Fixed JWT header for HS256 */
#define JWT_HEADER "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

/* Helper: Escape JSON string (quotes and backslashes) */
static int json_escape_string(const char *input, char *output, size_t output_len) {
    size_t out_pos = 0;

    for (const char *p = input; *p != '\0'; p++) {
        /* Need space for escaped char + null terminator */
        if (out_pos + 3 >= output_len) {
            return -1;  /* Buffer too small */
        }

        if (*p == '"' || *p == '\\') {
            output[out_pos++] = '\\';
            output[out_pos++] = *p;
        } else if (*p == '\n') {
            output[out_pos++] = '\\';
            output[out_pos++] = 'n';
        } else if (*p == '\r') {
            output[out_pos++] = '\\';
            output[out_pos++] = 'r';
        } else if (*p == '\t') {
            output[out_pos++] = '\\';
            output[out_pos++] = 't';
        } else if ((unsigned char)*p < 32) {
            /* Control characters (shouldn't appear in OAuth2 claims) */
            return -1;  /* Reject invalid characters */
        } else {
            output[out_pos++] = *p;
        }
    }

    output[out_pos] = '\0';
    return 0;
}

/* Helper: Unescape JSON string */
static int json_unescape_string(const char *input, char *output, size_t output_len) {
    size_t out_pos = 0;

    for (const char *p = input; *p != '\0'; p++) {
        if (out_pos + 1 >= output_len) {
            return -1;  /* Buffer too small */
        }

        if (*p == '\\' && *(p + 1) != '\0') {
            p++;  /* Skip backslash */
            if (*p == '"' || *p == '\\' || *p == '/') {
                output[out_pos++] = *p;
            } else if (*p == 'n') {
                output[out_pos++] = '\n';
            } else if (*p == 'r') {
                output[out_pos++] = '\r';
            } else if (*p == 't') {
                output[out_pos++] = '\t';
            } else {
                /* Unknown escape sequence */
                return -1;
            }
        } else {
            output[out_pos++] = *p;
        }
    }

    output[out_pos] = '\0';
    return 0;
}

/* Helper: Build JSON payload from claims */
static int build_payload_json(const jwt_claims_t *claims, char *json, size_t json_len) {
    /* Escape all string claims */
    char esc_iss[JWT_MAX_CLAIM_VALUE_LENGTH * 2];
    char esc_sub[JWT_MAX_CLAIM_VALUE_LENGTH * 2];
    char esc_aud[JWT_MAX_CLAIM_VALUE_LENGTH * 2];
    char esc_scope[JWT_MAX_CLAIM_VALUE_LENGTH * 2];
    char esc_client_id[JWT_MAX_CLAIM_VALUE_LENGTH * 2];

    if (json_escape_string(claims->iss, esc_iss, sizeof(esc_iss)) != 0 ||
        json_escape_string(claims->sub, esc_sub, sizeof(esc_sub)) != 0 ||
        json_escape_string(claims->aud, esc_aud, sizeof(esc_aud)) != 0 ||
        json_escape_string(claims->scope, esc_scope, sizeof(esc_scope)) != 0 ||
        json_escape_string(claims->client_id, esc_client_id, sizeof(esc_client_id)) != 0) {
        log_error("Failed to escape JWT claim values");
        return -1;
    }

    /* Build JSON with escaped values */
    int written = snprintf(json, json_len,
        "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\","
        "\"exp\":%ld,\"iat\":%ld,\"scope\":\"%s\",\"client_id\":\"%s\"}",
        esc_iss, esc_sub, esc_aud,
        (long)claims->exp, (long)claims->iat,
        esc_scope, esc_client_id);

    if (written < 0 || (size_t)written >= json_len) {
        log_error("Payload JSON buffer too small");
        return -1;
    }

    return 0;
}

/* Helper: Parse JSON field (simple parser for known structure) */
static int parse_json_string(const char *json, const char *key, char *out, size_t out_len) {
    /* Find key in JSON */
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);

    const char *start = strstr(json, search);
    if (!start) {
        return -1;  /* Key not found */
    }

    start += strlen(search);

    /* Find end quote (account for escaped quotes) */
    const char *end = start;
    while (*end != '\0') {
        if (*end == '\\' && *(end + 1) != '\0') {
            end += 2;  /* Skip escaped character */
        } else if (*end == '"') {
            break;  /* Found unescaped end quote */
        } else {
            end++;
        }
    }

    if (*end != '"') {
        return -1;  /* Malformed JSON */
    }

    size_t len = end - start;
    if (len >= out_len) {
        return -1;  /* Value too long */
    }

    /* Copy escaped string and unescape it */
    char escaped[JWT_MAX_CLAIM_VALUE_LENGTH];
    if (len >= sizeof(escaped)) {
        return -1;  /* Value too long for temp buffer */
    }

    memcpy(escaped, start, len);
    escaped[len] = '\0';

    if (json_unescape_string(escaped, out, out_len) != 0) {
        return -1;  /* Unescape failed */
    }

    return 0;
}

static int parse_json_long(const char *json, const char *key, long *out) {
    /* Find key in JSON */
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char *start = strstr(json, search);
    if (!start) {
        return -1;  /* Key not found */
    }

    start += strlen(search);
    while (*start == ' ') start++;

    char *endptr;
    long val = strtol(start, &endptr, 10);
    if (endptr == start) {
        return -1;  /* No digits found */
    }

    *out = val;
    return 0;
}

int jwt_encode(const jwt_claims_t *claims,
              const unsigned char *secret, size_t secret_len,
              char *out_token, size_t token_len) {
    if (!claims || !secret || !out_token) {
        log_error("Invalid arguments to jwt_encode");
        return -1;
    }

    if (token_len < JWT_MAX_TOKEN_LENGTH) {
        log_error("Token buffer too small");
        return -1;
    }

    /* Build payload JSON */
    char payload_json[1024];
    if (build_payload_json(claims, payload_json, sizeof(payload_json)) != 0) {
        return -1;
    }

    /* Base64url encode header */
    char header_b64[256];
    size_t header_b64_len = crypto_base64url_encode(
        (unsigned char *)JWT_HEADER, strlen(JWT_HEADER),
        header_b64, sizeof(header_b64));
    if (header_b64_len == 0) {
        log_error("Failed to encode JWT header");
        return -1;
    }

    /* Base64url encode payload */
    char payload_b64[2048];
    size_t payload_b64_len = crypto_base64url_encode(
        (unsigned char *)payload_json, strlen(payload_json),
        payload_b64, sizeof(payload_b64));
    if (payload_b64_len == 0) {
        log_error("Failed to encode JWT payload");
        return -1;
    }

    /* Build signing input: header.payload */
    char signing_input[3072];
    int signing_len = snprintf(signing_input, sizeof(signing_input),
                              "%s.%s", header_b64, payload_b64);
    if (signing_len < 0 || (size_t)signing_len >= sizeof(signing_input)) {
        log_error("JWT signing input buffer overflow");
        return -1;
    }

    /* Compute HMAC-SHA256 signature */
    unsigned char signature[HMAC_SHA256_LENGTH];
    if (crypto_hmac_sha256(secret, secret_len,
                          (unsigned char *)signing_input, signing_len,
                          signature, sizeof(signature)) != 0) {
        log_error("Failed to compute JWT signature");
        return -1;
    }

    /* Base64url encode signature */
    char signature_b64[128];
    size_t signature_b64_len = crypto_base64url_encode(
        signature, sizeof(signature),
        signature_b64, sizeof(signature_b64));
    if (signature_b64_len == 0) {
        log_error("Failed to encode JWT signature");
        return -1;
    }

    /* Build final token: header.payload.signature */
    int token_written = snprintf(out_token, token_len,
                                "%s.%s.%s",
                                header_b64, payload_b64, signature_b64);
    if (token_written < 0 || (size_t)token_written >= token_len) {
        log_error("JWT token buffer overflow");
        return -1;
    }

    return 0;
}

int jwt_decode(const char *token,
              const unsigned char *secret, size_t secret_len,
              jwt_claims_t *out_claims) {
    if (!token || !secret || !out_claims) {
        log_error("Invalid arguments to jwt_decode");
        return -1;
    }

    /* Find separators (header.payload.signature) */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        log_error("Invalid JWT format: missing first dot");
        return -1;
    }

    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        log_error("Invalid JWT format: missing second dot");
        return -1;
    }

    /* Extract parts */
    size_t header_len = dot1 - token;
    size_t payload_len = dot2 - (dot1 + 1);
    size_t signature_len = strlen(dot2 + 1);

    /* Verify signature */
    char signing_input[3072];
    int signing_len = snprintf(signing_input, sizeof(signing_input),
                              "%.*s.%.*s",
                              (int)header_len, token,
                              (int)payload_len, dot1 + 1);

    unsigned char computed_signature[HMAC_SHA256_LENGTH];
    if (crypto_hmac_sha256(secret, secret_len,
                          (unsigned char *)signing_input, signing_len,
                          computed_signature, sizeof(computed_signature)) != 0) {
        log_error("Failed to compute JWT signature for verification");
        return -1;
    }

    /* Decode received signature */
    unsigned char received_signature[HMAC_SHA256_LENGTH];
    int decoded_sig_len = crypto_base64url_decode(
        dot2 + 1, signature_len,
        received_signature, sizeof(received_signature));
    if (decoded_sig_len != HMAC_SHA256_LENGTH) {
        log_error("Invalid JWT signature length");
        return -1;
    }

    /* Timing-safe signature comparison */
    if (!crypto_hmac_compare(computed_signature, received_signature, HMAC_SHA256_LENGTH)) {
        log_error("JWT signature verification failed");
        return -1;
    }

    /* Decode payload */
    unsigned char payload_json[2048];
    int payload_json_len = crypto_base64url_decode(
        dot1 + 1, payload_len,
        payload_json, sizeof(payload_json) - 1);
    if (payload_json_len < 0) {
        log_error("Failed to decode JWT payload");
        return -1;
    }
    payload_json[payload_json_len] = '\0';

    /* Parse claims from JSON */
    memset(out_claims, 0, sizeof(jwt_claims_t));

    if (parse_json_string((char *)payload_json, "iss", out_claims->iss, sizeof(out_claims->iss)) != 0 ||
        parse_json_string((char *)payload_json, "sub", out_claims->sub, sizeof(out_claims->sub)) != 0 ||
        parse_json_string((char *)payload_json, "aud", out_claims->aud, sizeof(out_claims->aud)) != 0 ||
        parse_json_string((char *)payload_json, "scope", out_claims->scope, sizeof(out_claims->scope)) != 0 ||
        parse_json_string((char *)payload_json, "client_id", out_claims->client_id, sizeof(out_claims->client_id)) != 0) {
        log_error("Failed to parse JWT claims");
        return -1;
    }

    long exp, iat;
    if (parse_json_long((char *)payload_json, "exp", &exp) != 0 ||
        parse_json_long((char *)payload_json, "iat", &iat) != 0) {
        log_error("Failed to parse JWT timestamps");
        return -1;
    }
    out_claims->exp = (time_t)exp;
    out_claims->iat = (time_t)iat;

    /* Check expiration */
    time_t now = time(NULL);
    if (now >= out_claims->exp + jwt_clock_skew_seconds) {
        log_error("JWT token expired (exp=%ld, now=%ld)", (long)out_claims->exp, (long)now);
        return -1;
    }

    return 0;
}

int jwt_validate(const char *token,
                const unsigned char *secret, size_t secret_len) {
    jwt_claims_t claims;
    return (jwt_decode(token, secret, secret_len, &claims) == 0) ? 1 : 0;
}

/* ============================================================================
 * ES256 (ECDSA P-256) JWT Implementation
 * ============================================================================ */

/* Fixed JWT header for ES256 */
#define JWT_HEADER_ES256 "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

/*
 * Load private key from PEM string
 */
static EVP_PKEY *load_private_key_pem(const char *pem_string) {
    BIO *bio = BIO_new_mem_buf(pem_string, -1);
    if (!bio) {
        log_error("Failed to create BIO for private key");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        log_error("Failed to parse private key PEM");
        return NULL;
    }

    return pkey;
}

/*
 * Load public key from PEM string
 */
static EVP_PKEY *load_public_key_pem(const char *pem_string) {
    BIO *bio = BIO_new_mem_buf(pem_string, -1);
    if (!bio) {
        log_error("Failed to create BIO for public key");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        log_error("Failed to parse public key PEM");
        return NULL;
    }

    return pkey;
}

/*
 * Sign data with ECDSA private key
 * Returns signature length on success, -1 on error
 */
/*
 * Convert DER-encoded ECDSA signature to raw R||S (RFC 7518 Section 3.4).
 * P-256: R and S are each 32 bytes, zero-padded to fixed width.
 * Returns 64 on success, -1 on error.
 */
static int ecdsa_der_to_raw(const unsigned char *der_sig, size_t der_len,
                             unsigned char *raw_sig) {
    const unsigned char *p = der_sig;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (!sig) {
        log_error("Failed to parse DER ECDSA signature");
        return -1;
    }

    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    /* Zero-pad R and S to 32 bytes each */
    memset(raw_sig, 0, 64);
    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);
    BN_bn2bin(r, raw_sig + (32 - r_len));
    BN_bn2bin(s, raw_sig + 32 + (32 - s_len));

    ECDSA_SIG_free(sig);
    return 64;
}

/*
 * Convert raw R||S signature to DER-encoded ECDSA signature.
 * Returns DER length on success, -1 on error.
 */
static int ecdsa_raw_to_der(const unsigned char *raw_sig, size_t raw_len,
                             unsigned char *der_sig, size_t der_size) {
    if (raw_len != 64) {
        log_error("Invalid raw ES256 signature length: %zu", raw_len);
        return -1;
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) return -1;

    BIGNUM *r = BN_bin2bn(raw_sig, 32, NULL);
    BIGNUM *s = BN_bin2bn(raw_sig + 32, 32, NULL);
    if (!r || !s || ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -1;
    }
    /* r and s now owned by sig — do not free separately */

    int der_len = i2d_ECDSA_SIG(sig, NULL);
    if (der_len < 0 || (size_t)der_len > der_size) {
        ECDSA_SIG_free(sig);
        return -1;
    }

    unsigned char *out = der_sig;
    i2d_ECDSA_SIG(sig, &out);
    ECDSA_SIG_free(sig);
    return der_len;
}

static int ecdsa_sign(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                       unsigned char *out_sig, size_t *out_sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        log_error("Failed to create EVP_MD_CTX");
        return -1;
    }

    /* Initialize signing context */
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        log_error("Failed to initialize digest sign");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Sign data */
    if (EVP_DigestSign(mdctx, out_sig, out_sig_len, data, data_len) <= 0) {
        log_error("Failed to sign data");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

/*
 * Verify ECDSA signature
 * Returns 1 if valid, 0 if invalid, -1 on error
 */
static int ecdsa_verify(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                         const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        log_error("Failed to create EVP_MD_CTX for verification");
        return -1;
    }

    /* Initialize verification context */
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        log_error("Failed to initialize digest verify");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Verify signature */
    int result = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(mdctx);

    if (result == 1) {
        return 1;  /* Valid signature */
    } else if (result == 0) {
        return 0;  /* Invalid signature (not an error, just doesn't match) */
    } else {
        log_error("Error during signature verification");
        return -1;  /* Error */
    }
}

int jwt_encode_es256(const jwt_claims_t *claims,
                     const char *private_key_pem,
                     char *out_token, size_t token_len) {
    if (!claims || !private_key_pem || !out_token) {
        log_error("Invalid arguments to jwt_encode_es256");
        return -1;
    }

    if (token_len < JWT_MAX_TOKEN_LENGTH) {
        log_error("Token buffer too small");
        return -1;
    }

    /* Load private key */
    EVP_PKEY *pkey = load_private_key_pem(private_key_pem);
    if (!pkey) {
        return -1;
    }

    /* Build payload JSON */
    char payload_json[1024];
    if (build_payload_json(claims, payload_json, sizeof(payload_json)) != 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Base64url encode header */
    char header_b64[256];
    size_t header_b64_len = crypto_base64url_encode(
        (unsigned char *)JWT_HEADER_ES256, strlen(JWT_HEADER_ES256),
        header_b64, sizeof(header_b64));
    if (header_b64_len == 0) {
        log_error("Failed to encode JWT header");
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Base64url encode payload */
    char payload_b64[2048];
    size_t payload_b64_len = crypto_base64url_encode(
        (unsigned char *)payload_json, strlen(payload_json),
        payload_b64, sizeof(payload_b64));
    if (payload_b64_len == 0) {
        log_error("Failed to encode JWT payload");
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Build signing input: header.payload */
    char signing_input[3072];
    int signing_len = snprintf(signing_input, sizeof(signing_input),
                              "%s.%s", header_b64, payload_b64);
    if (signing_len < 0 || (size_t)signing_len >= sizeof(signing_input)) {
        log_error("JWT signing input buffer overflow");
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Sign with ECDSA (produces DER-encoded signature) */
    unsigned char der_signature[256];
    size_t der_sig_len = sizeof(der_signature);
    if (ecdsa_sign(pkey, (unsigned char *)signing_input, signing_len,
                   der_signature, &der_sig_len) != 0) {
        log_error("Failed to sign JWT with ES256");
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_free(pkey);

    /* Convert DER to raw R||S per RFC 7518 Section 3.4 */
    unsigned char signature[64];
    if (ecdsa_der_to_raw(der_signature, der_sig_len, signature) != 64) {
        log_error("Failed to convert ECDSA signature to raw R||S");
        return -1;
    }

    /* Base64url encode signature */
    char signature_b64[256];
    size_t signature_b64_len = crypto_base64url_encode(
        signature, 64,
        signature_b64, sizeof(signature_b64));
    if (signature_b64_len == 0) {
        log_error("Failed to encode JWT signature");
        return -1;
    }

    /* Build final token: header.payload.signature */
    int token_written = snprintf(out_token, token_len,
                                "%s.%s.%s",
                                header_b64, payload_b64, signature_b64);
    if (token_written < 0 || (size_t)token_written >= token_len) {
        log_error("JWT token buffer overflow");
        return -1;
    }

    return 0;
}

int jwt_decode_es256(const char *token,
                     const char *current_public_pem,
                     const char *prior_public_pem,
                     jwt_claims_t *out_claims) {
    if (!token || !current_public_pem || !out_claims) {
        log_error("Invalid arguments to jwt_decode_es256");
        return -1;
    }

    /* Find separators (header.payload.signature) */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        log_error("Invalid JWT format: missing first dot");
        return -1;
    }

    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        log_error("Invalid JWT format: missing second dot");
        return -1;
    }

    /* Extract parts */
    size_t header_len = dot1 - token;
    size_t payload_len = dot2 - (dot1 + 1);
    size_t signature_len = strlen(dot2 + 1);

    /* Build signing input for verification */
    char signing_input[3072];
    int signing_len = snprintf(signing_input, sizeof(signing_input),
                              "%.*s.%.*s",
                              (int)header_len, token,
                              (int)payload_len, dot1 + 1);

    /* Decode raw R||S signature (RFC 7518: always 64 bytes for P-256) */
    unsigned char raw_signature[64];
    int decoded_sig_len = crypto_base64url_decode(
        dot2 + 1, signature_len,
        raw_signature, sizeof(raw_signature));
    if (decoded_sig_len != 64) {
        log_error("Invalid ES256 signature length: expected 64, got %d", decoded_sig_len);
        return -1;
    }

    /* Convert raw R||S to DER for OpenSSL verification */
    unsigned char der_signature[256];
    int der_sig_len = ecdsa_raw_to_der(raw_signature, 64, der_signature, sizeof(der_signature));
    if (der_sig_len < 0) {
        log_error("Failed to convert raw R||S to DER");
        return -1;
    }

    /* Try current public key first */
    EVP_PKEY *pkey = load_public_key_pem(current_public_pem);
    if (!pkey) {
        return -1;
    }

    int valid = ecdsa_verify(pkey, (unsigned char *)signing_input, signing_len,
                            der_signature, der_sig_len);
    EVP_PKEY_free(pkey);

    /* If current key fails and prior key exists, try prior key */
    if (valid != 1 && prior_public_pem) {
        log_debug("Current ES256 public key failed, trying prior key");
        pkey = load_public_key_pem(prior_public_pem);
        if (!pkey) {
            return -1;
        }

        valid = ecdsa_verify(pkey, (unsigned char *)signing_input, signing_len,
                            der_signature, der_sig_len);
        EVP_PKEY_free(pkey);
    }

    if (valid != 1) {
        log_error("JWT ES256 signature verification failed");
        return -1;
    }

    /* Decode payload */
    unsigned char payload_json[2048];
    int payload_json_len = crypto_base64url_decode(
        dot1 + 1, payload_len,
        payload_json, sizeof(payload_json) - 1);
    if (payload_json_len < 0) {
        log_error("Failed to decode JWT payload");
        return -1;
    }
    payload_json[payload_json_len] = '\0';

    /* Parse claims from JSON */
    memset(out_claims, 0, sizeof(jwt_claims_t));

    if (parse_json_string((char *)payload_json, "iss", out_claims->iss, sizeof(out_claims->iss)) != 0 ||
        parse_json_string((char *)payload_json, "sub", out_claims->sub, sizeof(out_claims->sub)) != 0 ||
        parse_json_string((char *)payload_json, "aud", out_claims->aud, sizeof(out_claims->aud)) != 0 ||
        parse_json_string((char *)payload_json, "scope", out_claims->scope, sizeof(out_claims->scope)) != 0 ||
        parse_json_string((char *)payload_json, "client_id", out_claims->client_id, sizeof(out_claims->client_id)) != 0) {
        log_error("Failed to parse JWT claims");
        return -1;
    }

    long exp, iat;
    if (parse_json_long((char *)payload_json, "exp", &exp) != 0 ||
        parse_json_long((char *)payload_json, "iat", &iat) != 0) {
        log_error("Failed to parse JWT timestamps");
        return -1;
    }
    out_claims->exp = (time_t)exp;
    out_claims->iat = (time_t)iat;

    /* Check expiration */
    time_t now = time(NULL);
    if (now >= out_claims->exp + jwt_clock_skew_seconds) {
        log_error("JWT token expired (exp=%ld, now=%ld)", (long)out_claims->exp, (long)now);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Authorization Request JWTs (Stateless Authorization Codes)
 * ============================================================================ */

/* Forward declaration */
static int jwt_decode_auth_request_with_secret(const char *token,
                                                 const char *secret_b64,
                                                 auth_request_claims_t *out_claims);

/* Helper: Build JSON payload for auth request */
static int build_auth_request_payload_json(const auth_request_claims_t *claims,
                                            char *json, size_t json_len) {
    /* Convert UUIDs to hex strings */
    char client_id_hex[33];
    char user_id_hex[33];
    bytes_to_hex(claims->client_id, 16, client_id_hex, sizeof(client_id_hex));
    bytes_to_hex(claims->user_account_id, 16, user_id_hex, sizeof(user_id_hex));

    /* Escape string fields */
    char esc_redirect_uri[1024];
    char esc_scope[JWT_MAX_CLAIM_VALUE_LENGTH * 2];
    char esc_code_challenge[256];
    char esc_code_challenge_method[32];
    char esc_nonce[64];

    if (json_escape_string(claims->redirect_uri, esc_redirect_uri, sizeof(esc_redirect_uri)) != 0 ||
        json_escape_string(claims->scope, esc_scope, sizeof(esc_scope)) != 0 ||
        json_escape_string(claims->code_challenge, esc_code_challenge, sizeof(esc_code_challenge)) != 0 ||
        json_escape_string(claims->code_challenge_method, esc_code_challenge_method, sizeof(esc_code_challenge_method)) != 0 ||
        json_escape_string(claims->nonce, esc_nonce, sizeof(esc_nonce)) != 0) {
        log_error("Failed to escape auth request claim values");
        return -1;
    }

    /* Build JSON with all fields */
    int written = snprintf(json, json_len,
        "{\"client_id\":\"%s\",\"user_id\":\"%s\",\"redirect_uri\":\"%s\","
        "\"scope\":\"%s\",\"code_challenge\":\"%s\",\"code_challenge_method\":\"%s\","
        "\"iat\":%ld,\"exp\":%ld,\"nonce\":\"%s\"}",
        client_id_hex, user_id_hex, esc_redirect_uri,
        esc_scope, esc_code_challenge, esc_code_challenge_method,
        (long)claims->iat, (long)claims->exp, esc_nonce);

    if (written < 0 || (size_t)written >= json_len) {
        log_error("Auth request payload JSON buffer too small");
        return -1;
    }

    return 0;
}

int jwt_encode_auth_request(const auth_request_claims_t *claims,
                             const unsigned char *secret, size_t secret_len,
                             char *out_token, size_t token_len) {
    if (!claims || !secret || !out_token) {
        log_error("Invalid arguments to jwt_encode_auth_request");
        return -1;
    }

    if (token_len < JWT_MAX_TOKEN_LENGTH) {
        log_error("Token buffer too small");
        return -1;
    }

    /* Build payload JSON */
    char payload_json[2048];
    if (build_auth_request_payload_json(claims, payload_json, sizeof(payload_json)) != 0) {
        return -1;
    }

    /* Encode using HS256 (reuse existing jwt_encode logic) */
    /* Base64url encode header */
    char header_b64[256];
    size_t header_b64_len = crypto_base64url_encode(
        (const unsigned char *)JWT_HEADER, strlen(JWT_HEADER),
        header_b64, sizeof(header_b64));

    if (header_b64_len == 0) {
        log_error("Failed to encode JWT header");
        return -1;
    }

    /* Base64url encode payload */
    char payload_b64[4096];
    size_t payload_b64_len = crypto_base64url_encode(
        (const unsigned char *)payload_json, strlen(payload_json),
        payload_b64, sizeof(payload_b64));

    if (payload_b64_len == 0) {
        log_error("Failed to encode JWT payload");
        return -1;
    }

    /* Build data to sign: header.payload */
    char to_sign[5000];
    int to_sign_len = snprintf(to_sign, sizeof(to_sign), "%s.%s", header_b64, payload_b64);

    if (to_sign_len < 0 || (size_t)to_sign_len >= sizeof(to_sign)) {
        log_error("JWT signing data buffer too small");
        return -1;
    }

    /* Compute HMAC-SHA256 signature */
    unsigned char signature[32];
    if (crypto_hmac_sha256(secret, secret_len,
                           (const unsigned char *)to_sign, to_sign_len,
                           signature, sizeof(signature)) != 0) {
        log_error("Failed to compute HMAC for JWT");
        return -1;
    }

    /* Base64url encode signature */
    char signature_b64[64];
    size_t signature_b64_len = crypto_base64url_encode(
        signature, sizeof(signature),
        signature_b64, sizeof(signature_b64));

    if (signature_b64_len == 0) {
        log_error("Failed to encode JWT signature");
        return -1;
    }

    /* Build final JWT: header.payload.signature */
    int final_len = snprintf(out_token, token_len, "%s.%s.%s",
                              header_b64, payload_b64, signature_b64);

    if (final_len < 0 || (size_t)final_len >= token_len) {
        log_error("JWT output buffer too small");
        return -1;
    }

    return 0;
}

int jwt_decode_auth_request(const char *token,
                             const char *current_secret,
                             const char *prior_secret,
                             auth_request_claims_t *out_claims) {
    if (!token || !current_secret || !out_claims) {
        log_error("Invalid arguments to jwt_decode_auth_request");
        return -1;
    }

    /* Try current secret first */
    if (jwt_decode_auth_request_with_secret(token, current_secret, out_claims) == 0) {
        return 0;
    }

    /* Fallback to prior secret if available (key rotation support) */
    if (prior_secret && jwt_decode_auth_request_with_secret(token, prior_secret, out_claims) == 0) {
        log_debug("Auth request JWT validated with prior secret (key rotation)");
        return 0;
    }

    log_error("Auth request JWT validation failed with both current and prior secrets");
    return -1;
}

/* Helper: Decode auth request JWT with a specific secret */
static int jwt_decode_auth_request_with_secret(const char *token,
                                                 const char *secret_b64,
                                                 auth_request_claims_t *out_claims) {
    /* Decode base64url secret */
    unsigned char secret[256];
    int secret_len = crypto_base64url_decode(secret_b64, strlen(secret_b64),
                                              secret, sizeof(secret));
    if (secret_len <= 0) {
        log_error("Failed to decode secret for auth request JWT");
        return -1;
    }

    /* Split token into header.payload.signature */
    char token_copy[JWT_MAX_TOKEN_LENGTH];
    str_copy(token_copy, sizeof(token_copy), token);

    char *header_b64 = token_copy;
    char *payload_b64 = strchr(header_b64, '.');
    if (!payload_b64) {
        log_error("Malformed JWT (missing first dot)");
        return -1;
    }
    *payload_b64 = '\0';
    payload_b64++;

    char *signature_b64 = strchr(payload_b64, '.');
    if (!signature_b64) {
        log_error("Malformed JWT (missing second dot)");
        return -1;
    }
    *signature_b64 = '\0';
    signature_b64++;

    /* Rebuild data that was signed: header.payload */
    char to_verify[5000];
    int to_verify_len = snprintf(to_verify, sizeof(to_verify), "%s.%s",
                                  header_b64, payload_b64);

    if (to_verify_len < 0 || (size_t)to_verify_len >= sizeof(to_verify)) {
        log_error("JWT verification data buffer too small");
        return -1;
    }

    /* Compute expected HMAC */
    unsigned char expected_signature[32];
    if (crypto_hmac_sha256(secret, secret_len,
                           (const unsigned char *)to_verify, to_verify_len,
                           expected_signature, sizeof(expected_signature)) != 0) {
        log_error("Failed to compute HMAC for JWT verification");
        return -1;
    }

    /* Decode provided signature */
    unsigned char provided_signature[32];
    int provided_sig_len = crypto_base64url_decode(signature_b64, strlen(signature_b64),
                                                    provided_signature, sizeof(provided_signature));

    if (provided_sig_len != 32) {
        log_error("Invalid JWT signature length: %d", provided_sig_len);
        return -1;
    }

    /* Verify signature (timing-safe comparison) */
    if (!crypto_hmac_compare(expected_signature, provided_signature, 32)) {
        log_error("JWT signature verification failed");
        return -1;
    }

    /* Decode payload */
    unsigned char payload_json[2048];
    int payload_json_len = crypto_base64url_decode(payload_b64, strlen(payload_b64),
                                                    payload_json, sizeof(payload_json) - 1);

    if (payload_json_len <= 0) {
        log_error("Failed to decode JWT payload");
        return -1;
    }

    payload_json[payload_json_len] = '\0';

    /* Parse JSON fields */
    char client_id_hex[65];
    char user_id_hex[65];
    long iat_long, exp_long;

    if (parse_json_string((const char *)payload_json, "client_id", client_id_hex, sizeof(client_id_hex)) != 0 ||
        parse_json_string((const char *)payload_json, "user_id", user_id_hex, sizeof(user_id_hex)) != 0 ||
        parse_json_string((const char *)payload_json, "redirect_uri", out_claims->redirect_uri, sizeof(out_claims->redirect_uri)) != 0 ||
        parse_json_string((const char *)payload_json, "scope", out_claims->scope, sizeof(out_claims->scope)) != 0 ||
        parse_json_string((const char *)payload_json, "nonce", out_claims->nonce, sizeof(out_claims->nonce)) != 0 ||
        parse_json_long((const char *)payload_json, "iat", &iat_long) != 0 ||
        parse_json_long((const char *)payload_json, "exp", &exp_long) != 0) {
        log_error("Failed to parse required auth request JWT claims");
        return -1;
    }

    out_claims->iat = (time_t)iat_long;
    out_claims->exp = (time_t)exp_long;

    /* Parse optional PKCE fields (empty string if not present) */
    if (parse_json_string((const char *)payload_json, "code_challenge",
                           out_claims->code_challenge, sizeof(out_claims->code_challenge)) != 0) {
        out_claims->code_challenge[0] = '\0';
    }

    if (parse_json_string((const char *)payload_json, "code_challenge_method",
                           out_claims->code_challenge_method, sizeof(out_claims->code_challenge_method)) != 0) {
        out_claims->code_challenge_method[0] = '\0';
    }

    /* Convert hex UUIDs back to bytes */
    if (hex_to_bytes(client_id_hex, out_claims->client_id, 16) != 0) {
        log_error("Invalid client_id hex in auth request JWT");
        return -1;
    }

    if (hex_to_bytes(user_id_hex, out_claims->user_account_id, 16) != 0) {
        log_error("Invalid user_id hex in auth request JWT");
        return -1;
    }

    /* Check expiration */
    time_t now = time(NULL);
    if (now >= out_claims->exp + jwt_clock_skew_seconds) {
        log_error("Auth request JWT expired (exp=%ld, now=%ld)",
                 (long)out_claims->exp, (long)now);
        return -1;
    }

    return 0;
}
