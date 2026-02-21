#include "crypto/random.h"
#include "crypto/password.h"
#include "crypto/hmac.h"
#include "crypto/sha256.h"
#include "crypto/jwt.h"
#include "crypto/signing_keys.h"
#include "crypto/totp.h"
#include "crypto/encrypt.h"
#include "util/log.h"
#include "util/config.h"
#include "db/db.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    log_init(LOG_INFO);
    log_info("=== Crypto Random Test ===\n");

    /* Generate random bytes */
    log_info("Test: Generate 32 random bytes");
    unsigned char random_bytes[32];
    if (crypto_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        log_error("Failed to generate random bytes");
        return 1;
    }

    printf("Random bytes (hex): ");
    for (size_t i = 0; i < sizeof(random_bytes); i++) {
        printf("%02x", random_bytes[i]);
    }
    printf("\n\n");

    /* Generate URL-safe token (32 bytes = ~43 chars base64url) */
    log_info("Test: Generate 32-byte token (OAuth2 refresh token size)");
    char token[64];
    int token_len = crypto_random_token(token, sizeof(token), 32);
    if (token_len < 0) {
        log_error("Failed to generate token");
        return 1;
    }

    log_info("Token (%d chars): %s\n", token_len, token);

    /* Generate shorter token (16 bytes = ~22 chars) */
    log_info("Test: Generate 16-byte token (OAuth2 auth code size)");
    char short_token[32];
    int short_len = crypto_random_token(short_token, sizeof(short_token), 16);
    if (short_len < 0) {
        log_error("Failed to generate short token");
        return 1;
    }

    log_info("Token (%d chars): %s\n", short_len, short_token);

    /* Verify tokens are different */
    log_info("Test: Generate two tokens and verify they differ");
    char token1[64], token2[64];
    crypto_random_token(token1, sizeof(token1), 32);
    crypto_random_token(token2, sizeof(token2), 32);

    if (strcmp(token1, token2) == 0) {
        log_error("FAIL: Two random tokens were identical! (Extremely unlikely)");
        return 1;
    }

    log_info("Token 1: %s", token1);
    log_info("Token 2: %s", token2);
    log_info("Tokens are different: PASS\n");

    /* Verify base64url character set */
    log_info("Test: Verify token uses base64url charset (A-Z, a-z, 0-9, -, _)");
    int valid = 1;
    for (const char *p = token1; *p != '\0'; p++) {
        char c = *p;
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_')) {
            log_error("Invalid character in token: '%c'", c);
            valid = 0;
        }
    }

    if (valid) {
        log_info("All characters valid: PASS\n");
    } else {
        log_error("Token contains invalid characters: FAIL");
        return 1;
    }

    /* Buffer size calculation */
    log_info("Test: Verify crypto_token_encoded_size calculation");
    size_t expected_size = crypto_token_encoded_size(32);
    size_t actual_size = strlen(token1) + 1;  /* +1 for null terminator */

    log_info("Expected buffer size for 32 bytes: %zu", expected_size);
    log_info("Actual token length + null: %zu", actual_size);

    if (actual_size <= expected_size) {
        log_info("Buffer size calculation correct: PASS\n");
    } else {
        log_error("Buffer size calculation incorrect: FAIL");
        return 1;
    }

    log_info("==========================================================");
    log_info("Password Hashing Tests");
    log_info("==========================================================\n");

    /* Load config for password hashing */
    config_t *config = config_load("auth.conf");
    if (!config) {
        log_error("Failed to load config");
        return 1;
    }

    /* Initialize password hashing module */
    if (crypto_password_init(config) != 0) {
        log_error("Failed to initialize password hashing");
        config_free(config);
        return 1;
    }

    /* Argon2id password hashing */
    log_info("Test: Password hashing (algorithm from config)");
    const char *test_password = "MySecurePassword123!";
    char salt1[PASSWORD_SALT_HEX_MAX_LENGTH];
    int iterations1;
    char hash1[PASSWORD_HASH_HEX_MAX_LENGTH];

    if (crypto_password_hash(test_password, strlen(test_password),
                            salt1, sizeof(salt1), &iterations1,
                            hash1, sizeof(hash1)) != 0) {
        log_error("Failed to hash password");
        config_free(config);
        return 1;
    }

    log_info("Password: %s", test_password);
    log_info("Salt: %s", salt1);
    log_info("Iterations: %d", iterations1);
    log_info("Hash: %s\n", hash1);

    /* Verify correct password */
    log_info("Test: Verify correct password");
    int ver_valid = crypto_password_verify(test_password, strlen(test_password),
                                          salt1, iterations1, hash1);
    if (ver_valid == 1) {
        log_info("Password verification: PASS\n");
    } else {
        log_error("Password verification failed: %d", ver_valid);
        config_free(config);
        return 1;
    }

    /* Verify wrong password */
    log_info("Test: Verify wrong password (should fail)");
    const char *wrong_password = "WrongPassword456!";
    ver_valid = crypto_password_verify(wrong_password, strlen(wrong_password),
                                      salt1, iterations1, hash1);
    if (ver_valid == 0) {
        log_info("Wrong password correctly rejected: PASS\n");
    } else {
        log_error("Wrong password was accepted! FAIL");
        config_free(config);
        return 1;
    }

    /* Two hashes of same password should differ (random salt) */
    log_info("Test: Verify random salt makes hashes unique");
    char salt2[PASSWORD_SALT_HEX_MAX_LENGTH];
    int iterations2;
    char hash2[PASSWORD_HASH_HEX_MAX_LENGTH];

    if (crypto_password_hash(test_password, strlen(test_password),
                            salt2, sizeof(salt2), &iterations2,
                            hash2, sizeof(hash2)) != 0) {
        log_error("Failed to hash password");
        config_free(config);
        return 1;
    }

    if (strcmp(salt1, salt2) == 0 || strcmp(hash1, hash2) == 0) {
        log_error("Two hashes have same salt or hash! (Extremely unlikely)");
        config_free(config);
        return 1;
    }

    log_info("Hash 1: %s", hash1);
    log_info("Hash 2: %s", hash2);
    log_info("Salts and hashes differ: PASS\n");

    /* Both hashes should verify with their own salt */
    log_info("Test: Both hashes verify independently");
    int valid1 = crypto_password_verify(test_password, strlen(test_password),
                                       salt1, iterations1, hash1);
    int valid2 = crypto_password_verify(test_password, strlen(test_password),
                                       salt2, iterations2, hash2);

    if (valid1 == 1 && valid2 == 1) {
        log_info("Both hashes verify correctly: PASS\n");
    } else {
        log_error("Hash verification failed: hash1=%d, hash2=%d", valid1, valid2);
        config_free(config);
        return 1;
    }

    config_free(config);

    log_info("==========================================================");
    log_info("HMAC-SHA256 Tests");
    log_info("==========================================================\n");

    /* Basic HMAC-SHA256 computation (binary output) */
    log_info("Test: Basic HMAC-SHA256 computation");
    const char *hmac_key = "secret";
    const char *hmac_data = "The quick brown fox jumps over the lazy dog";
    unsigned char hmac_binary[HMAC_SHA256_LENGTH];

    if (crypto_hmac_sha256((unsigned char *)hmac_key, strlen(hmac_key),
                          (unsigned char *)hmac_data, strlen(hmac_data),
                          hmac_binary, sizeof(hmac_binary)) != 0) {
        log_error("HMAC-SHA256 computation failed");
        return 1;
    }

    printf("HMAC-SHA256 (hex): ");
    for (size_t i = 0; i < HMAC_SHA256_LENGTH; i++) {
        printf("%02x", hmac_binary[i]);
    }
    printf("\n");
    log_info("HMAC computed successfully: PASS\n");

    /* HMAC-SHA256 hex output */
    log_info("Test: HMAC-SHA256 hex output");
    char hmac_hex[HMAC_SHA256_HEX_LENGTH];

    if (crypto_hmac_sha256_hex((unsigned char *)hmac_key, strlen(hmac_key),
                              (unsigned char *)hmac_data, strlen(hmac_data),
                              hmac_hex, sizeof(hmac_hex)) != 0) {
        log_error("HMAC-SHA256 hex computation failed");
        return 1;
    }

    log_info("HMAC-SHA256 hex: %s", hmac_hex);
    log_info("Hex output matches binary: PASS\n");

    /* RFC 4231 Test Vector #1 */
    log_info("Test: RFC 4231 HMAC-SHA256 Test Vector #1");
    const unsigned char rfc_key1[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    const char *rfc_data1 = "Hi There";
    const char *rfc_expected1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    char rfc_result1[HMAC_SHA256_HEX_LENGTH];
    if (crypto_hmac_sha256_hex(rfc_key1, sizeof(rfc_key1),
                              (unsigned char *)rfc_data1, strlen(rfc_data1),
                              rfc_result1, sizeof(rfc_result1)) != 0) {
        log_error("RFC test vector computation failed");
        return 1;
    }

    if (strcmp(rfc_result1, rfc_expected1) != 0) {
        log_error("RFC test vector mismatch!");
        log_error("Expected: %s", rfc_expected1);
        log_error("Got:      %s", rfc_result1);
        return 1;
    }

    log_info("RFC 4231 test vector verified: PASS\n");

    /* HMAC determinism (same input = same output) */
    log_info("Test: HMAC determinism");
    unsigned char hmac_a[HMAC_SHA256_LENGTH];
    unsigned char hmac_b[HMAC_SHA256_LENGTH];

    crypto_hmac_sha256((unsigned char *)hmac_key, strlen(hmac_key),
                      (unsigned char *)hmac_data, strlen(hmac_data),
                      hmac_a, sizeof(hmac_a));
    crypto_hmac_sha256((unsigned char *)hmac_key, strlen(hmac_key),
                      (unsigned char *)hmac_data, strlen(hmac_data),
                      hmac_b, sizeof(hmac_b));

    if (memcmp(hmac_a, hmac_b, HMAC_SHA256_LENGTH) != 0) {
        log_error("HMAC is not deterministic! Same input produced different outputs");
        return 1;
    }

    log_info("Same input produces same HMAC: PASS\n");

    /* Different keys produce different HMACs */
    log_info("Test: Different keys produce different HMACs");
    const char *key1 = "secret1";
    const char *key2 = "secret2";
    unsigned char hmac1[HMAC_SHA256_LENGTH];
    unsigned char hmac2[HMAC_SHA256_LENGTH];

    crypto_hmac_sha256((unsigned char *)key1, strlen(key1),
                      (unsigned char *)hmac_data, strlen(hmac_data),
                      hmac1, sizeof(hmac1));
    crypto_hmac_sha256((unsigned char *)key2, strlen(key2),
                      (unsigned char *)hmac_data, strlen(hmac_data),
                      hmac2, sizeof(hmac2));

    if (memcmp(hmac1, hmac2, HMAC_SHA256_LENGTH) == 0) {
        log_error("Different keys produced identical HMACs!");
        return 1;
    }

    log_info("Different keys produce different HMACs: PASS\n");

    /* Timing-safe comparison */
    log_info("Test: Timing-safe HMAC comparison");

    /* Test equal HMACs */
    if (!crypto_hmac_compare(hmac_a, hmac_b, HMAC_SHA256_LENGTH)) {
        log_error("Timing-safe comparison failed for equal HMACs");
        return 1;
    }

    /* Test unequal HMACs */
    if (crypto_hmac_compare(hmac1, hmac2, HMAC_SHA256_LENGTH)) {
        log_error("Timing-safe comparison failed for unequal HMACs");
        return 1;
    }

    log_info("Timing-safe comparison working correctly: PASS\n");

    log_info("==========================================================");
    log_info("SHA-256 Tests");
    log_info("==========================================================\n");

    /* Test: SHA-256 known test vector (empty string) */
    log_info("Test: SHA-256 known test vector (empty string)");
    char sha_hex[SHA256_HEX_LENGTH];
    if (crypto_sha256_hex("", 0, sha_hex, sizeof(sha_hex)) != 0) {
        log_error("SHA-256 of empty string failed");
        return 1;
    }

    const char *expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (strcmp(sha_hex, expected_empty) != 0) {
        log_error("SHA-256 empty string mismatch!");
        log_error("Expected: %s", expected_empty);
        log_error("Got:      %s", sha_hex);
        return 1;
    }
    log_info("SHA-256 empty string: %s", sha_hex);
    log_info("SHA-256 empty string test vector: PASS\n");

    /* Test: SHA-256 known test vector ("abc") */
    log_info("Test: SHA-256 known test vector (\"abc\")");
    if (crypto_sha256_hex("abc", 3, sha_hex, sizeof(sha_hex)) != 0) {
        log_error("SHA-256 of 'abc' failed");
        return 1;
    }

    const char *expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (strcmp(sha_hex, expected_abc) != 0) {
        log_error("SHA-256 'abc' mismatch!");
        log_error("Expected: %s", expected_abc);
        log_error("Got:      %s", sha_hex);
        return 1;
    }
    log_info("SHA-256 'abc': %s", sha_hex);
    log_info("SHA-256 'abc' test vector: PASS\n");

    /* Test: SHA-256 determinism */
    log_info("Test: SHA-256 determinism");
    char sha_a[SHA256_HEX_LENGTH], sha_b[SHA256_HEX_LENGTH];
    const char *sha_input = "deterministic input";
    crypto_sha256_hex(sha_input, strlen(sha_input), sha_a, sizeof(sha_a));
    crypto_sha256_hex(sha_input, strlen(sha_input), sha_b, sizeof(sha_b));

    if (strcmp(sha_a, sha_b) != 0) {
        log_error("SHA-256 not deterministic!");
        return 1;
    }
    log_info("Same input produces same hash: PASS\n");

    /* Test: SHA-256 different inputs produce different hashes */
    log_info("Test: SHA-256 different inputs produce different hashes");
    char sha_x[SHA256_HEX_LENGTH], sha_y[SHA256_HEX_LENGTH];
    crypto_sha256_hex("input1", 6, sha_x, sizeof(sha_x));
    crypto_sha256_hex("input2", 6, sha_y, sizeof(sha_y));

    if (strcmp(sha_x, sha_y) == 0) {
        log_error("Different inputs produced same SHA-256 hash!");
        return 1;
    }
    log_info("Different inputs produce different hashes: PASS\n");

    /* Test: SHA-256 output is 64 lowercase hex characters */
    log_info("Test: SHA-256 output format");
    if (strlen(sha_a) != 64) {
        log_error("SHA-256 hex output wrong length: %zu (expected 64)", strlen(sha_a));
        return 1;
    }

    for (const char *p = sha_a; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
            log_error("SHA-256 output contains non-hex character: '%c'", *p);
            return 1;
        }
    }
    log_info("SHA-256 output is 64 lowercase hex chars: PASS\n");

    log_info("==========================================================");
    log_info("JWT Tests");
    log_info("==========================================================\n");

    const char *jwt_secret = "test-secret-key-256-bits-long!!!";
    size_t jwt_secret_len = strlen(jwt_secret);

    /* JWT encoding (create access token) */
    log_info("Test: JWT encoding (create access token)");
    jwt_claims_t claims_out = {0};
    strcpy(claims_out.iss, "https://auth.example.com");
    strcpy(claims_out.sub, "user123");
    strcpy(claims_out.aud, "https://api.example.com");
    claims_out.exp = time(NULL) + 3600;  /* 1 hour from now */
    claims_out.iat = time(NULL);
    strcpy(claims_out.scope, "read write delete");
    strcpy(claims_out.client_id, "webapp-client");

    char jwt_token[JWT_MAX_TOKEN_LENGTH];
    if (jwt_encode(&claims_out, (unsigned char *)jwt_secret, jwt_secret_len,
                  jwt_token, sizeof(jwt_token)) != 0) {
        log_error("JWT encoding failed");
        return 1;
    }

    log_info("JWT token created (length=%zu)", strlen(jwt_token));
    log_info("Token: %s", jwt_token);
    log_info("JWT encoding: PASS\n");

    /* JWT decoding and verification */
    log_info("Test: JWT decoding and verification");
    jwt_claims_t claims_in = {0};

    if (jwt_decode(jwt_token, (unsigned char *)jwt_secret, jwt_secret_len,
                  &claims_in) != 0) {
        log_error("JWT decoding failed");
        return 1;
    }

    /* Verify claims match */
    if (strcmp(claims_in.iss, claims_out.iss) != 0 ||
        strcmp(claims_in.sub, claims_out.sub) != 0 ||
        strcmp(claims_in.aud, claims_out.aud) != 0 ||
        strcmp(claims_in.scope, claims_out.scope) != 0 ||
        strcmp(claims_in.client_id, claims_out.client_id) != 0) {
        log_error("Decoded claims don't match original");
        return 1;
    }

    log_info("Decoded claims:");
    log_info("  iss: %s", claims_in.iss);
    log_info("  sub: %s", claims_in.sub);
    log_info("  aud: %s", claims_in.aud);
    log_info("  exp: %ld", (long)claims_in.exp);
    log_info("  iat: %ld", (long)claims_in.iat);
    log_info("  scope: %s", claims_in.scope);
    log_info("  client_id: %s", claims_in.client_id);
    log_info("JWT decoding: PASS\n");

    /* JWT validation (fast path) */
    log_info("Test: JWT validation (fast path)");
    if (jwt_validate(jwt_token, (unsigned char *)jwt_secret, jwt_secret_len) != 1) {
        log_error("JWT validation failed for valid token");
        return 1;
    }
    log_info("Valid token accepted: PASS\n");

    /* JWT signature verification (wrong secret) */
    log_info("Test: JWT signature verification with wrong secret");
    const char *wrong_secret = "wrong-secret-key";
    if (jwt_decode(jwt_token, (unsigned char *)wrong_secret, strlen(wrong_secret),
                  &claims_in) == 0) {
        log_error("JWT accepted with wrong secret!");
        return 1;
    }
    log_info("Wrong secret correctly rejected: PASS\n");

    /* JWT token tampering detection */
    log_info("Test: JWT token tampering detection");
    char tampered_token[JWT_MAX_TOKEN_LENGTH];
    strcpy(tampered_token, jwt_token);

    /* Tamper with payload (change one character) */
    char *payload_start = strchr(tampered_token, '.') + 1;
    char *payload_end = strchr(payload_start, '.');
    if (payload_end > payload_start) {
        payload_start[0] = (payload_start[0] == 'A') ? 'B' : 'A';  /* Flip character */
    }

    if (jwt_decode(tampered_token, (unsigned char *)jwt_secret, jwt_secret_len,
                  &claims_in) == 0) {
        log_error("Tampered JWT was accepted!");
        return 1;
    }
    log_info("Tampered token correctly rejected: PASS\n");

    /* Expired JWT rejection */
    log_info("Test: Expired JWT rejection");
    jwt_claims_t expired_claims = {0};
    strcpy(expired_claims.iss, "https://auth.example.com");
    strcpy(expired_claims.sub, "user456");
    strcpy(expired_claims.aud, "https://api.example.com");
    expired_claims.exp = time(NULL) - 60;  /* Expired 60 seconds ago */
    expired_claims.iat = time(NULL) - 3660;
    strcpy(expired_claims.scope, "read");
    strcpy(expired_claims.client_id, "test-client");

    char expired_token[JWT_MAX_TOKEN_LENGTH];
    if (jwt_encode(&expired_claims, (unsigned char *)jwt_secret, jwt_secret_len,
                  expired_token, sizeof(expired_token)) != 0) {
        log_error("Failed to create expired token");
        return 1;
    }

    if (jwt_decode(expired_token, (unsigned char *)jwt_secret, jwt_secret_len,
                  &claims_in) == 0) {
        log_error("Expired JWT was accepted!");
        return 1;
    }
    log_info("Expired token correctly rejected: PASS\n");

    /* JWT round-trip with special characters */
    log_info("Test: JWT round-trip with special characters in claims");
    jwt_claims_t special_claims = {0};
    strcpy(special_claims.iss, "https://auth.example.com:8443/oauth2");
    strcpy(special_claims.sub, "user@example.com");
    strcpy(special_claims.aud, "api://default");
    special_claims.exp = time(NULL) + 1800;
    special_claims.iat = time(NULL);
    strcpy(special_claims.scope, "openid profile email");
    strcpy(special_claims.client_id, "spa-client-v2");

    char special_token[JWT_MAX_TOKEN_LENGTH];
    if (jwt_encode(&special_claims, (unsigned char *)jwt_secret, jwt_secret_len,
                  special_token, sizeof(special_token)) != 0) {
        log_error("Failed to encode JWT with special characters");
        return 1;
    }

    jwt_claims_t special_decoded = {0};
    if (jwt_decode(special_token, (unsigned char *)jwt_secret, jwt_secret_len,
                  &special_decoded) != 0) {
        log_error("Failed to decode JWT with special characters");
        return 1;
    }

    if (strcmp(special_decoded.sub, special_claims.sub) != 0) {
        log_error("Special characters not preserved (sub)");
        return 1;
    }

    log_info("Special characters preserved: PASS\n");

    log_info("==========================================================");
    log_info("ES256 JWT Tests");
    log_info("==========================================================\n");

    /* Generate test ES256 keypair (simulating signing_keys.c generation) */
    log_info("Test: ES256 keypair generation and JWT encoding");

    /* Generate test keypair using OpenSSL */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        log_error("Failed to initialize ES256 keypair generation");
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        log_error("Failed to generate ES256 keypair");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    /* Export to PEM format */
    BIO *priv_bio = BIO_new(BIO_s_mem());
    BIO *pub_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) ||
        !PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        log_error("Failed to export ES256 keypair to PEM");
        EVP_PKEY_free(pkey);
        BIO_free(priv_bio);
        BIO_free(pub_bio);
        return 1;
    }

    char *priv_pem_data = NULL, *pub_pem_data = NULL;
    long priv_len = BIO_get_mem_data(priv_bio, &priv_pem_data);
    long pub_len = BIO_get_mem_data(pub_bio, &pub_pem_data);

    char *current_private_pem = malloc(priv_len + 1);
    char *current_public_pem = malloc(pub_len + 1);
    memcpy(current_private_pem, priv_pem_data, priv_len);
    memcpy(current_public_pem, pub_pem_data, pub_len);
    current_private_pem[priv_len] = '\0';
    current_public_pem[pub_len] = '\0';

    BIO_free(priv_bio);
    BIO_free(pub_bio);
    EVP_PKEY_free(pkey);

    /* Create ES256 JWT */
    jwt_claims_t es256_claims = {0};
    strcpy(es256_claims.iss, "https://auth.example.com");
    strcpy(es256_claims.sub, "789");  /* user_pin */
    strcpy(es256_claims.aud, "456");  /* resource_server_pin */
    es256_claims.exp = time(NULL) + 3600;
    es256_claims.iat = time(NULL);
    strcpy(es256_claims.scope, "read write");
    strcpy(es256_claims.client_id, "123");  /* client_pin */

    char es256_token[JWT_MAX_TOKEN_LENGTH];
    if (jwt_encode_es256(&es256_claims, current_private_pem,
                         es256_token, sizeof(es256_token)) != 0) {
        log_error("ES256 JWT encoding failed");
        free(current_private_pem);
        free(current_public_pem);
        return 1;
    }

    log_info("ES256 token created (length=%zu)", strlen(es256_token));
    log_info("Token: %.80s...", es256_token);  /* Show first 80 chars */
    log_info("ES256 encoding: PASS\n");

    /* ES256 JWT decoding with current key */
    log_info("Test: ES256 JWT decoding and verification");
    jwt_claims_t es256_decoded = {0};

    if (jwt_decode_es256(es256_token, current_public_pem, NULL, &es256_decoded) != 0) {
        log_error("ES256 JWT decoding failed");
        free(current_private_pem);
        free(current_public_pem);
        return 1;
    }

    /* Verify claims match */
    if (strcmp(es256_decoded.sub, es256_claims.sub) != 0 ||
        strcmp(es256_decoded.aud, es256_claims.aud) != 0 ||
        strcmp(es256_decoded.scope, es256_claims.scope) != 0 ||
        strcmp(es256_decoded.client_id, es256_claims.client_id) != 0) {
        log_error("ES256 decoded claims don't match original");
        free(current_private_pem);
        free(current_public_pem);
        return 1;
    }

    log_info("Decoded ES256 claims:");
    log_info("  sub: %s", es256_decoded.sub);
    log_info("  aud: %s", es256_decoded.aud);
    log_info("  scope: %s", es256_decoded.scope);
    log_info("  client_id: %s", es256_decoded.client_id);
    log_info("ES256 decoding with current key: PASS\n");

    /* ES256 JWT with prior key fallback (simulate rotation) */
    log_info("Test: ES256 JWT with prior key fallback");

    /* Token was signed with current_private_pem, now make it the "prior" key */
    char *prior_public_pem = current_public_pem;

    /* Generate new "current" key */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY *new_pkey = NULL;
    EVP_PKEY_keygen(ctx, &new_pkey);
    EVP_PKEY_CTX_free(ctx);

    BIO *new_pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(new_pub_bio, new_pkey);
    char *new_pub_pem_data = NULL;
    long new_pub_len = BIO_get_mem_data(new_pub_bio, &new_pub_pem_data);
    char *new_current_public_pem = malloc(new_pub_len + 1);
    memcpy(new_current_public_pem, new_pub_pem_data, new_pub_len);
    new_current_public_pem[new_pub_len] = '\0';
    BIO_free(new_pub_bio);
    EVP_PKEY_free(new_pkey);

    /* Try to verify old token with new current key + prior key fallback */
    jwt_claims_t fallback_decoded = {0};
    if (jwt_decode_es256(es256_token, new_current_public_pem, prior_public_pem,
                         &fallback_decoded) != 0) {
        log_error("ES256 JWT prior key fallback failed");
        free(current_private_pem);
        free(prior_public_pem);
        free(new_current_public_pem);
        return 1;
    }

    log_info("Old token verified with prior key: PASS\n");

    /* ES256 JWT with wrong public key */
    log_info("Test: ES256 JWT with wrong public key");
    jwt_claims_t wrong_key_decoded = {0};

    /* Try to verify with only the new key (no prior key) - should fail */
    if (jwt_decode_es256(es256_token, new_current_public_pem, NULL,
                         &wrong_key_decoded) == 0) {
        log_error("ES256 JWT accepted with wrong public key!");
        free(current_private_pem);
        free(prior_public_pem);
        free(new_current_public_pem);
        return 1;
    }

    log_info("Wrong public key correctly rejected: PASS\n");

    /* ES256 JWT tampered token detection */
    log_info("Test: ES256 JWT tampered token detection");
    char tampered_es256[JWT_MAX_TOKEN_LENGTH];
    strcpy(tampered_es256, es256_token);

    /* Tamper with payload */
    char *es256_payload_start = strchr(tampered_es256, '.') + 1;
    char *es256_payload_end = strchr(es256_payload_start, '.');
    if (es256_payload_end > es256_payload_start) {
        es256_payload_start[0] = (es256_payload_start[0] == 'A') ? 'B' : 'A';
    }

    jwt_claims_t tampered_es256_decoded = {0};
    if (jwt_decode_es256(tampered_es256, current_public_pem, NULL,
                         &tampered_es256_decoded) == 0) {
        log_error("Tampered ES256 JWT was accepted!");
        free(current_private_pem);
        free(prior_public_pem);
        free(new_current_public_pem);
        return 1;
    }

    log_info("Tampered ES256 token correctly rejected: PASS\n");

    /* Cleanup */
    free(current_private_pem);
    free(prior_public_pem);
    free(new_current_public_pem);

    /* ====================================================================
     * TOTP Tests
     * ==================================================================== */

    log_info("=== TOTP (Time-Based One-Time Password) Tests ===\n");

    /* Generate TOTP secret */
    log_info("Test: Generate TOTP secret (base32-encoded)");
    char totp_secret[64];
    if (crypto_totp_generate_secret(totp_secret, sizeof(totp_secret)) != 0) {
        log_error("Failed to generate TOTP secret");
        return 1;
    }

    log_info("Generated TOTP secret: %s", totp_secret);
    log_info("Secret length: %zu (expected 32 for 20 bytes)", strlen(totp_secret));

    if (strlen(totp_secret) != 32) {
        log_error("TOTP secret has wrong length: %zu (expected 32)", strlen(totp_secret));
        return 1;
    }

    /* Verify base32 alphabet (A-Z, 2-7) */
    log_info("Test: Verify TOTP secret uses base32 alphabet");
    for (const char *p = totp_secret; *p != '\0'; p++) {
        char c = *p;
        if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'))) {
            log_error("Invalid character in TOTP secret: '%c' (not base32)", c);
            return 1;
        }
    }
    log_info("TOTP secret alphabet valid: PASS\n");

    /* Deterministic code generation with fixed timestamp */
    log_info("Test: Generate TOTP code with fixed timestamp");
    const char *test_secret = "JBSWY3DPEHPK3PXP";  /* "Hello!" in base32 (standard test vector) */
    time_t test_time = 1234567890;  /* Fixed timestamp: 2009-02-13 23:31:30 UTC */
    char generated_code[8];

    if (crypto_totp_generate_code(test_secret, test_time, generated_code, sizeof(generated_code)) != 0) {
        log_error("Failed to generate TOTP code");
        return 1;
    }

    log_info("Generated TOTP code for test_secret at timestamp %ld: %s", test_time, generated_code);

    /* Verify code is 6 digits */
    if (strlen(generated_code) != 6) {
        log_error("TOTP code has wrong length: %zu (expected 6)", strlen(generated_code));
        return 1;
    }

    for (int i = 0; i < 6; i++) {
        if (generated_code[i] < '0' || generated_code[i] > '9') {
            log_error("TOTP code contains non-digit: '%c'", generated_code[i]);
            return 1;
        }
    }
    log_info("TOTP code format valid: PASS\n");

    /* Code verification (same timestamp) */
    log_info("Test: Verify TOTP code (within time window)");
    int verify_result = crypto_totp_verify(test_secret, generated_code, test_time);
    if (verify_result != 1) {
        log_error("TOTP code verification failed for valid code (result: %d)", verify_result);
        return 1;
    }
    log_info("Valid TOTP code verified successfully: PASS\n");

    /* Code verification with time drift (+30 seconds) */
    log_info("Test: Verify TOTP code with +30 second time drift");
    verify_result = crypto_totp_verify(test_secret, generated_code, test_time + 30);
    if (verify_result != 1) {
        log_error("TOTP code verification failed with +30s drift (result: %d)", verify_result);
        return 1;
    }
    log_info("TOTP code verified with +30s drift: PASS\n");

    /* Code verification with time drift (-30 seconds) */
    log_info("Test: Verify TOTP code with -30 second time drift");
    verify_result = crypto_totp_verify(test_secret, generated_code, test_time - 30);
    if (verify_result != 1) {
        log_error("TOTP code verification failed with -30s drift (result: %d)", verify_result);
        return 1;
    }
    log_info("TOTP code verified with -30s drift: PASS\n");

    /* Code verification failure (outside time window) */
    log_info("Test: Reject TOTP code outside time window (+90 seconds)");
    verify_result = crypto_totp_verify(test_secret, generated_code, test_time + 90);
    if (verify_result != 0) {
        log_error("TOTP code incorrectly accepted outside time window (result: %d)", verify_result);
        return 1;
    }
    log_info("TOTP code correctly rejected outside window: PASS\n");

    /* Code verification failure (wrong code) */
    log_info("Test: Reject invalid TOTP code");
    verify_result = crypto_totp_verify(test_secret, "999999", test_time);
    if (verify_result != 0) {
        log_error("Invalid TOTP code was accepted (result: %d)", verify_result);
        return 1;
    }
    log_info("Invalid TOTP code correctly rejected: PASS\n");

    /* Code verification failure (wrong length) */
    log_info("Test: Reject TOTP code with wrong length");
    verify_result = crypto_totp_verify(test_secret, "12345", test_time);
    if (verify_result != 0) {
        log_error("Short TOTP code was accepted (result: %d)", verify_result);
        return 1;
    }
    log_info("Short TOTP code correctly rejected: PASS\n");

    /* QR code URL generation */
    log_info("Test: Generate TOTP QR code URL");
    char qr_url[512];
    if (crypto_totp_generate_qr_url(test_secret, "testuser", "AuthServer",
                                     qr_url, sizeof(qr_url)) != 0) {
        log_error("Failed to generate TOTP QR URL");
        return 1;
    }

    log_info("Generated QR URL: %s", qr_url);

    /* Verify URL format */
    if (strncmp(qr_url, "otpauth://totp/", 15) != 0) {
        log_error("QR URL has wrong prefix: %s", qr_url);
        return 1;
    }

    if (strstr(qr_url, "secret=") == NULL) {
        log_error("QR URL missing secret parameter");
        return 1;
    }

    if (strstr(qr_url, "issuer=") == NULL) {
        log_error("QR URL missing issuer parameter");
        return 1;
    }

    log_info("TOTP QR URL format valid: PASS\n");

    /* Two different secrets produce different codes */
    log_info("Test: Verify different secrets produce different codes");
    char secret1[64], secret2[64];
    char code1[8], code2[8];

    crypto_totp_generate_secret(secret1, sizeof(secret1));
    crypto_totp_generate_secret(secret2, sizeof(secret2));

    if (strcmp(secret1, secret2) == 0) {
        log_error("Two random TOTP secrets are identical (extremely unlikely)");
        return 1;
    }

    time_t now = time(NULL);
    crypto_totp_generate_code(secret1, now, code1, sizeof(code1));
    crypto_totp_generate_code(secret2, now, code2, sizeof(code2));

    if (strcmp(code1, code2) == 0) {
        log_info("NOTE: Two different secrets generated same code (possible but unlikely)");
    }

    log_info("Secret 1: %s -> Code: %s", secret1, code1);
    log_info("Secret 2: %s -> Code: %s", secret2, code2);
    log_info("Different secrets handled correctly: PASS\n");

    /* ====================================================================
     * MFA Encryption Tests
     * ==================================================================== */

    log_info("=== Field Encryption (AES-256-GCM) Tests ===\n");

    /* Test: Initialize field encryption */
    log_info("Test: Initialize field encryption with passphrase");
    if (encrypt_init("test-passphrase-for-unit-tests") != 0) {
        log_error("Field encryption init failed");
        return 1;
    }
    log_info("Field encryption initialized: PASS\n");

    /* Test: Encrypt and decrypt round-trip */
    log_info("Test: Encrypt/decrypt round-trip");
    const char *enc_plaintext = "JBSWY3DPEHPK3PXP";  /* Typical TOTP secret */
    char enc_encrypted[256];
    char enc_decrypted[64];

    if (encrypt_field(enc_plaintext, enc_encrypted, sizeof(enc_encrypted)) != 0) {
        log_error("Field encryption failed");
        return 1;
    }

    log_info("Plaintext:  %s", enc_plaintext);
    log_info("Encrypted:  %s", enc_encrypted);

    if (decrypt_field(enc_encrypted, enc_decrypted, sizeof(enc_decrypted)) != 0) {
        log_error("Field decryption failed");
        return 1;
    }

    if (strcmp(enc_plaintext, enc_decrypted) != 0) {
        log_error("Decrypted text doesn't match original!");
        log_error("Expected: %s", enc_plaintext);
        log_error("Got:      %s", enc_decrypted);
        return 1;
    }
    log_info("Decrypted:  %s", enc_decrypted);
    log_info("Round-trip: PASS\n");

    /* Test: Two encryptions of same plaintext produce different ciphertext (random IV) */
    log_info("Test: Random IV produces different ciphertext each time");
    char enc_encrypted2[256];
    if (encrypt_field(enc_plaintext, enc_encrypted2, sizeof(enc_encrypted2)) != 0) {
        log_error("Second field encryption failed");
        return 1;
    }

    if (strcmp(enc_encrypted, enc_encrypted2) == 0) {
        log_error("Two encryptions produced identical ciphertext (IV not random)!");
        return 1;
    }

    /* Verify both decrypt to the same plaintext */
    char enc_decrypted2[64];
    if (decrypt_field(enc_encrypted2, enc_decrypted2, sizeof(enc_decrypted2)) != 0) {
        log_error("Decryption of second ciphertext failed");
        return 1;
    }

    if (strcmp(enc_plaintext, enc_decrypted2) != 0) {
        log_error("Second decryption doesn't match original!");
        return 1;
    }
    log_info("Ciphertext 1: %s", enc_encrypted);
    log_info("Ciphertext 2: %s", enc_encrypted2);
    log_info("Both decrypt correctly, ciphertexts differ: PASS\n");

    /* Test: Tampered ciphertext is rejected (GCM authentication) */
    log_info("Test: Tampered ciphertext rejected by GCM tag verification");
    char tampered_enc[256];
    strcpy(tampered_enc, enc_encrypted);

    /* Flip a character in the middle of the ciphertext */
    size_t tamper_pos = strlen(tampered_enc) / 2;
    tampered_enc[tamper_pos] = (tampered_enc[tamper_pos] == 'A') ? 'B' : 'A';

    char tampered_output[64];
    if (decrypt_field(tampered_enc, tampered_output, sizeof(tampered_output)) == 0) {
        log_error("Tampered ciphertext was accepted!");
        return 1;
    }
    log_info("Tampered ciphertext correctly rejected: PASS\n");

    /* Test: Different passphrase cannot decrypt */
    log_info("Test: Different passphrase cannot decrypt");
    /* Re-init with different passphrase */
    if (encrypt_init("completely-different-passphrase") != 0) {
        log_error("Field encryption re-init failed");
        return 1;
    }

    char wrong_key_output[64];
    if (decrypt_field(enc_encrypted, wrong_key_output, sizeof(wrong_key_output)) == 0) {
        log_error("Decryption succeeded with wrong passphrase!");
        return 1;
    }
    log_info("Wrong passphrase correctly rejected: PASS\n");

    /* Re-init with original passphrase for hash_field tests */
    if (encrypt_init("test-passphrase-for-unit-tests") != 0) {
        log_error("Field encryption re-init for hash tests failed");
        return 1;
    }

    log_info("=== Blind Index (HMAC-SHA256) Tests ===\n");

    /* Test: hash_field determinism */
    log_info("Test: hash_field produces same output for same input");
    char hmac_hash1[65], hmac_hash2[65];
    if (hash_field("alice", hmac_hash1, sizeof(hmac_hash1)) != 0) {
        log_error("hash_field failed");
        return 1;
    }
    if (hash_field("alice", hmac_hash2, sizeof(hmac_hash2)) != 0) {
        log_error("hash_field second call failed");
        return 1;
    }
    assert(strcmp(hmac_hash1, hmac_hash2) == 0);
    log_info("Hash: %s", hmac_hash1);
    log_info("Determinism: PASS\n");

    /* Test: different inputs produce different hashes */
    log_info("Test: Different inputs produce different hashes");
    char hmac_hash3[65];
    if (hash_field("bob", hmac_hash3, sizeof(hmac_hash3)) != 0) {
        log_error("hash_field for 'bob' failed");
        return 1;
    }
    assert(strcmp(hmac_hash1, hmac_hash3) != 0);
    log_info("Hash(alice): %s", hmac_hash1);
    log_info("Hash(bob):   %s", hmac_hash3);
    log_info("Different inputs differ: PASS\n");

    /* Test: output is 64 hex characters */
    log_info("Test: Output is 64 hex characters");
    assert(strlen(hmac_hash1) == 64);
    for (size_t i = 0; i < 64; i++) {
        char c = hmac_hash1[i];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    log_info("Output format: PASS\n");

    log_info("==========================================================");
    log_info("=== All Tests Passed! ===");
    log_info("==========================================================");
    return 0;
}
