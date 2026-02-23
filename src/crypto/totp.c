#include "crypto/totp.h"
#include "crypto/hmac.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/str.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Base32 alphabet (RFC 4648) */
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* HMAC-SHA1 produces 20-byte (160-bit) output */
#define HMAC_SHA1_LENGTH 20

/* ============================================================================
 * Base32 Encoding (RFC 4648)
 * ============================================================================ */

/*
 * Encode binary data to base32 string
 * Returns: number of characters written (excluding null terminator), or 0 on error
 */
static size_t base32_encode(const unsigned char *input, size_t input_len,
                            char *output, size_t output_len) {
    if (!input || !output || input_len == 0) {
        return 0;
    }

    /* Calculate required output size: ceil(input_len * 8 / 5) */
    size_t required_len = ((input_len * 8 + 4) / 5);
    if (output_len < required_len + 1) {  /* +1 for null terminator */
        log_error("Base32 output buffer too small");
        return 0;
    }

    size_t output_pos = 0;
    unsigned int buffer = 0;
    int bits_in_buffer = 0;

    for (size_t i = 0; i < input_len; i++) {
        buffer = (buffer << 8) | input[i];
        bits_in_buffer += 8;

        while (bits_in_buffer >= 5) {
            bits_in_buffer -= 5;
            output[output_pos++] = base32_alphabet[(buffer >> bits_in_buffer) & 0x1F];
        }
    }

    /* Flush remaining bits */
    if (bits_in_buffer > 0) {
        output[output_pos++] = base32_alphabet[(buffer << (5 - bits_in_buffer)) & 0x1F];
    }

    output[output_pos] = '\0';
    return output_pos;
}

/*
 * Decode base32 string to binary
 * Returns: number of bytes written, or -1 on error
 */
static int base32_decode(const char *input, unsigned char *output, size_t output_len) {
    if (!input || !output) {
        log_error("Invalid arguments to base32_decode");
        return -1;
    }

    size_t input_len = strlen(input);
    if (input_len == 0) {
        return 0;
    }

    /* Calculate output size: floor(input_len * 5 / 8) */
    size_t expected_output_len = (input_len * 5) / 8;
    if (output_len < expected_output_len) {
        log_error("Base32 decode output buffer too small");
        return -1;
    }

    size_t output_pos = 0;
    unsigned int buffer = 0;
    int bits_in_buffer = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = toupper(input[i]);

        /* Decode base32 character to 5-bit value */
        int value;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= '2' && c <= '7') {
            value = c - '2' + 26;
        } else {
            log_error("Invalid base32 character: %c", c);
            return -1;
        }

        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            output[output_pos++] = (buffer >> bits_in_buffer) & 0xFF;
        }
    }

    return (int)output_pos;
}

/* ============================================================================
 * TOTP Secret Generation
 * ============================================================================ */

int crypto_totp_generate_secret(char *out_secret, size_t secret_size) {
    if (!out_secret || secret_size < TOTP_SECRET_BASE32_LEN + 1) {
        log_error("Invalid arguments to crypto_totp_generate_secret");
        return -1;
    }

    /* Generate 20 random bytes (160 bits) */
    unsigned char random_bytes[TOTP_SECRET_BYTES];
    if (crypto_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        log_error("Failed to generate random bytes for TOTP secret");
        return -1;
    }

    /* Encode to base32 */
    size_t encoded_len = base32_encode(random_bytes, sizeof(random_bytes),
                                      out_secret, secret_size);
    if (encoded_len == 0) {
        log_error("Failed to encode TOTP secret to base32");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * TOTP Code Generation
 * ============================================================================ */

/*
 * Generate TOTP code using HMAC-SHA1
 * Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)
 */
static int totp_generate_code_internal(const unsigned char *secret, size_t secret_len,
                                       uint64_t time_counter, char *out_code) {
    /* Convert time counter to big-endian 8-byte array */
    unsigned char counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = (unsigned char)(time_counter & 0xFF);
        time_counter >>= 8;
    }

    /* Compute HMAC-SHA1(secret, counter) */
    unsigned char hmac[HMAC_SHA1_LENGTH];
    unsigned int hmac_len = 0;

    if (HMAC(EVP_sha1(), secret, (int)secret_len, counter_bytes, sizeof(counter_bytes),
             hmac, &hmac_len) == NULL || hmac_len != HMAC_SHA1_LENGTH) {
        log_error("HMAC-SHA1 computation failed for TOTP");
        return -1;
    }

    /* Dynamic truncation (RFC 4226 Section 5.3) */
    int offset = hmac[HMAC_SHA1_LENGTH - 1] & 0x0F;
    uint32_t binary_code = ((hmac[offset] & 0x7F) << 24)
                         | ((hmac[offset + 1] & 0xFF) << 16)
                         | ((hmac[offset + 2] & 0xFF) << 8)
                         | (hmac[offset + 3] & 0xFF);

    /* Generate 6-digit code */
    uint32_t code = binary_code % 1000000;
    snprintf(out_code, TOTP_CODE_DIGITS + 1, "%06u", code);

    return 0;
}

int crypto_totp_generate_code(const char *secret, time_t timestamp,
                               char *out_code, size_t code_size) {
    if (!secret || !out_code || code_size < TOTP_CODE_DIGITS + 1) {
        log_error("Invalid arguments to crypto_totp_generate_code");
        return -1;
    }

    /* Decode base32 secret */
    unsigned char secret_bytes[256];
    int secret_len = base32_decode(secret, secret_bytes, sizeof(secret_bytes));
    if (secret_len < 0) {
        log_error("Failed to decode TOTP secret");
        return -1;
    }

    /* Calculate time counter */
    uint64_t time_counter = (uint64_t)timestamp / TOTP_TIME_STEP;

    /* Generate code */
    int rc = totp_generate_code_internal(secret_bytes, (size_t)secret_len, time_counter, out_code);
    OPENSSL_cleanse(secret_bytes, sizeof(secret_bytes));
    return rc;
}

/* ============================================================================
 * TOTP Code Verification
 * ============================================================================ */

int crypto_totp_verify(const char *secret, const char *code, time_t current_time) {
    if (!secret || !code) {
        log_error("Invalid arguments to crypto_totp_verify");
        return -1;
    }

    /* Validate code format (6 digits) */
    if (strlen(code) != TOTP_CODE_DIGITS) {
        log_debug("Invalid TOTP code length: %zu (expected %d)", strlen(code), TOTP_CODE_DIGITS);
        return 0;  /* Invalid code */
    }

    for (int i = 0; i < TOTP_CODE_DIGITS; i++) {
        if (!isdigit(code[i])) {
            log_debug("Invalid TOTP code: non-digit character");
            return 0;  /* Invalid code */
        }
    }

    /* Decode secret */
    unsigned char secret_bytes[256];
    int secret_len = base32_decode(secret, secret_bytes, sizeof(secret_bytes));
    if (secret_len < 0) {
        log_error("Failed to decode TOTP secret for verification");
        return -1;
    }

    /* Calculate current time counter */
    uint64_t current_counter = (uint64_t)current_time / TOTP_TIME_STEP;

    /* Try current time window and ± TOTP_TIME_WINDOW steps (accounts for clock drift) */
    int result = 0;
    for (int offset = -TOTP_TIME_WINDOW; offset <= TOTP_TIME_WINDOW; offset++) {
        uint64_t test_counter = current_counter + offset;
        char expected_code[TOTP_CODE_DIGITS + 1];

        if (totp_generate_code_internal(secret_bytes, (size_t)secret_len,
                                       test_counter, expected_code) != 0) {
            log_error("Failed to generate TOTP code for verification");
            result = -1;
            goto cleanup;
        }

        if (crypto_hmac_compare((const unsigned char *)code, (const unsigned char *)expected_code, TOTP_CODE_DIGITS)) {
            log_debug("TOTP code verified successfully (offset: %d)", offset);
            result = 1;
            goto cleanup;
        }
    }

    log_debug("TOTP code verification failed: no match in time window");

cleanup:
    OPENSSL_cleanse(secret_bytes, sizeof(secret_bytes));
    return result;
}

/* ============================================================================
 * QR Code URL Generation
 * ============================================================================ */

int crypto_totp_generate_qr_url(const char *secret, const char *username,
                                 const char *issuer, char *out_url, size_t url_size) {
    if (!secret || !username || !issuer || !out_url) {
        log_error("Invalid arguments to crypto_totp_generate_qr_url");
        return -1;
    }

    /* URL-encode username and issuer for safe otpauth:// URI construction */
    char encoded_username[256];
    char encoded_issuer[256];
    if (str_url_encode(encoded_username, sizeof(encoded_username), username) < 0) {
        log_error("Failed to URL-encode username for TOTP QR URL");
        return -1;
    }
    if (str_url_encode(encoded_issuer, sizeof(encoded_issuer), issuer) < 0) {
        log_error("Failed to URL-encode issuer for TOTP QR URL");
        return -1;
    }

    /* Format: otpauth://totp/Issuer:username?secret=SECRET&issuer=Issuer */
    int written = snprintf(out_url, url_size,
                          "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                          encoded_issuer, encoded_username, secret, encoded_issuer);

    if (written < 0 || (size_t)written >= url_size) {
        log_error("TOTP QR URL buffer too small");
        return -1;
    }

    return 0;
}
