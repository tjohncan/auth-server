#ifndef CRYPTO_JWT_H
#define CRYPTO_JWT_H

#include <stddef.h>
#include <time.h>

/*
 * JWT (JSON Web Token) for OAuth2 Access Tokens
 *
 * Implements HS256 (HMAC-SHA256) signed JWTs for OAuth2 access tokens.
 * Format: base64url(header).base64url(payload).base64url(signature)
 *
 * Fixed header: {"alg":"HS256","typ":"JWT"}
 * Payload contains OAuth2 claims (sub, aud, exp, iat, scope, client_id)
 */

/* Maximum sizes for JWT components */
#define JWT_MAX_CLAIM_VALUE_LENGTH 256
#define JWT_MAX_TOKEN_LENGTH       2048

/*
 * Set clock skew tolerance for JWT expiration checks
 * Must be called during initialization before any JWT operations
 * Default: 0 seconds (strict validation)
 */
void jwt_set_clock_skew_seconds(int seconds);

/* JWT claims structure for OAuth2 access tokens */
typedef struct {
    /* Standard JWT claims */
    char iss[JWT_MAX_CLAIM_VALUE_LENGTH];      /* Issuer (your auth server URL) */
    char sub[JWT_MAX_CLAIM_VALUE_LENGTH];      /* Subject (user ID) */
    char aud[JWT_MAX_CLAIM_VALUE_LENGTH];      /* Audience (resource server) */
    time_t exp;                                /* Expiration time (unix timestamp) */
    time_t iat;                                /* Issued at (unix timestamp) */

    /* OAuth2-specific claims */
    char scope[JWT_MAX_CLAIM_VALUE_LENGTH];    /* OAuth2 scopes (space-separated) */
    char client_id[JWT_MAX_CLAIM_VALUE_LENGTH]; /* OAuth2 client ID */
} jwt_claims_t;

/*
 * Create and sign a JWT access token
 *
 * Generates a JWT with HS256 signature using provided claims and secret.
 * Sets iat (issued at) to current time if not already set.
 *
 * Parameters:
 *   claims      - JWT claims (sub, aud, exp, scope, client_id, etc.)
 *   secret      - Secret key for HMAC signature
 *   secret_len  - Length of secret key
 *   out_token   - Output buffer for JWT string
 *   token_len   - Size of output buffer (must be >= JWT_MAX_TOKEN_LENGTH)
 *
 * Returns: 0 on success, negative on error
 *
 * Example:
 *   jwt_claims_t claims = {0};
 *   snprintf(claims.iss, sizeof(claims.iss), "https://auth.example.com");
 *   snprintf(claims.sub, sizeof(claims.sub), "user123");
 *   snprintf(claims.aud, sizeof(claims.aud), "https://api.example.com");
 *   claims.exp = time(NULL) + 3600;  // 1 hour from now
 *   snprintf(claims.scope, sizeof(claims.scope), "read write");
 *   snprintf(claims.client_id, sizeof(claims.client_id), "webapp");
 *
 *   char token[JWT_MAX_TOKEN_LENGTH];
 *   jwt_encode(&claims, secret, secret_len, token, sizeof(token));
 */
int jwt_encode(const jwt_claims_t *claims,
              const unsigned char *secret, size_t secret_len,
              char *out_token, size_t token_len);

/*
 * Decode and verify a JWT access token
 *
 * Parses JWT, validates signature, checks expiration, and extracts claims.
 * Returns error if signature invalid or token expired.
 *
 * Parameters:
 *   token       - JWT string to decode
 *   secret      - Secret key for signature verification
 *   secret_len  - Length of secret key
 *   out_claims  - Output buffer for decoded claims
 *
 * Returns: 0 on success (token valid), negative on error/invalid/expired
 *
 * Example:
 *   jwt_claims_t claims;
 *   if (jwt_decode(token, secret, secret_len, &claims) == 0) {
 *       // Token valid, use claims.sub, claims.scope, etc.
 *   } else {
 *       // Token invalid or expired
 *   }
 */
int jwt_decode(const char *token,
              const unsigned char *secret, size_t secret_len,
              jwt_claims_t *out_claims);

/*
 * Validate JWT without full decode (fast path)
 *
 * Checks signature and expiration without parsing all claims.
 * Useful for quick token validation before expensive operations.
 *
 * Parameters:
 *   token       - JWT string to validate
 *   secret      - Secret key for signature verification
 *   secret_len  - Length of secret key
 *
 * Returns: 1 if valid, 0 if invalid/expired, negative on error
 */
int jwt_validate(const char *token,
                const unsigned char *secret, size_t secret_len);

/*
 * Create and sign a JWT access token with ES256 (ECDSA P-256)
 *
 * Generates a JWT with ES256 signature using provided claims and private key.
 * This is used for OAuth2 access tokens that resource servers will verify.
 *
 * Parameters:
 *   claims          - JWT claims (sub, aud, exp, scope, client_id, etc.)
 *   private_key_pem - Private key in PEM format (ECDSA P-256)
 *   out_token       - Output buffer for JWT string
 *   token_len       - Size of output buffer (must be >= JWT_MAX_TOKEN_LENGTH)
 *
 * Returns: 0 on success, negative on error
 *
 * Example:
 *   jwt_claims_t claims = {0};
 *   snprintf(claims.sub, sizeof(claims.sub), "a1b2c3...");  // user UUID hex
 *   snprintf(claims.aud, sizeof(claims.aud), "d4e5f6...");  // resource server UUID hex
 *   claims.exp = time(NULL) + 3600;
 *   snprintf(claims.scope, sizeof(claims.scope), "read write");
 *
 *   char token[JWT_MAX_TOKEN_LENGTH];
 *   jwt_encode_es256(&claims, private_key_pem, token, sizeof(token));
 */
int jwt_encode_es256(const jwt_claims_t *claims,
                     const char *private_key_pem,
                     char *out_token, size_t token_len);

/*
 * Decode and verify a JWT access token with ES256 (ECDSA P-256)
 *
 * Parses JWT, validates ES256 signature, checks expiration, extracts claims.
 * Tries current public key first, falls back to prior key if signature fails.
 *
 * Parameters:
 *   token               - JWT string to decode
 *   current_public_pem  - Current public key in PEM format
 *   prior_public_pem    - Prior public key in PEM format (NULL if none)
 *   out_claims          - Output buffer for decoded claims
 *
 * Returns: 0 on success (token valid), negative on error/invalid/expired
 *
 * Example:
 *   jwt_claims_t claims;
 *   if (jwt_decode_es256(token, current_pub, prior_pub, &claims) == 0) {
 *       // Token valid, use claims.sub, claims.scope, etc.
 *   }
 */
int jwt_decode_es256(const char *token,
                     const char *current_public_pem,
                     const char *prior_public_pem,
                     jwt_claims_t *out_claims);

/* ============================================================================
 * Authorization Request JWTs (Stateless Authorization Codes)
 * ============================================================================ */

/*
 * JWT claims structure for OAuth2 authorization requests
 *
 * Authorization codes are stateless JWTs signed with HMAC-SHA256.
 * They contain all the state needed to exchange for tokens without DB storage.
 * Short-lived (60 seconds) to prevent reuse and minimize DoS attack window.
 *
 * Uses UUIDs (not PINs) for external communication - immutable, opaque identifiers.
 */
typedef struct {
    /* Core authorization data (UUIDs for external use) */
    unsigned char client_id[16];                /* Client UUID */
    unsigned char user_account_id[16];          /* User account UUID */
    char redirect_uri[512];                     /* Validated redirect URI */
    char scope[JWT_MAX_CLAIM_VALUE_LENGTH];     /* Granted scopes (space-separated) */

    /* PKCE challenge (optional) */
    char code_challenge[128];                   /* PKCE challenge (empty string if not used) */
    char code_challenge_method[16];             /* "plain" or "S256" (empty string if not used) */

    /* Metadata */
    time_t iat;                                 /* Issued at (unix timestamp) */
    time_t exp;                                 /* Expiration time (unix timestamp) */
    char nonce[32];                             /* Random nonce to prevent reuse */
} auth_request_claims_t;

/*
 * Create and sign authorization request JWT
 *
 * Generates a stateless authorization code as a signed JWT.
 * This replaces database storage for authorization codes (DoS prevention).
 *
 * Parameters:
 *   claims      - Authorization request claims
 *   secret      - HMAC secret key (from auth_request_signing table)
 *   secret_len  - Length of secret key
 *   out_token   - Output buffer for JWT string (the authorization code)
 *   token_len   - Size of output buffer (must be >= JWT_MAX_TOKEN_LENGTH)
 *
 * Returns: 0 on success, -1 on error
 *
 * Example:
 *   auth_request_claims_t claims = {0};
 *   memcpy(claims.client_id, client_uuid, 16);
 *   memcpy(claims.user_account_id, user_uuid, 16);
 *   snprintf(claims.redirect_uri, sizeof(claims.redirect_uri), "https://app.example.com/callback");
 *   snprintf(claims.scope, sizeof(claims.scope), "read write");
 *   snprintf(claims.code_challenge, sizeof(claims.code_challenge), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
 *   snprintf(claims.code_challenge_method, sizeof(claims.code_challenge_method), "S256");
 *   claims.iat = time(NULL);
 *   claims.exp = claims.iat + 60;  // 60 second TTL
 *
 *   char code[JWT_MAX_TOKEN_LENGTH];
 *   jwt_encode_auth_request(&claims, secret, secret_len, code, sizeof(code));
 */
int jwt_encode_auth_request(const auth_request_claims_t *claims,
                             const unsigned char *secret, size_t secret_len,
                             char *out_token, size_t token_len);

/*
 * Decode and verify authorization request JWT
 *
 * Parses authorization code JWT, validates signature, checks expiration.
 * Tries current secret first, falls back to prior secret if signature fails
 * (supports graceful key rotation).
 *
 * Parameters:
 *   token          - Authorization code JWT string
 *   current_secret - Current HMAC secret (base64url-encoded)
 *   prior_secret   - Prior HMAC secret (NULL if no prior key)
 *   out_claims     - Output buffer for decoded claims
 *
 * Returns: 0 on success (code valid), -1 on error/invalid/expired
 *
 * Example:
 *   auth_request_claims_t claims;
 *   if (jwt_decode_auth_request(code, current_secret, prior_secret, &claims) == 0) {
 *       // Validate redirect_uri matches request
 *       // Validate PKCE if present
 *   } else {
 *       // Code invalid or expired
 *   }
 */
int jwt_decode_auth_request(const char *token,
                             const char *current_secret,
                             const char *prior_secret,
                             auth_request_claims_t *out_claims);

#endif /* CRYPTO_JWT_H */
