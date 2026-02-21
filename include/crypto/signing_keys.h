#ifndef CRYPTO_SIGNING_KEYS_H
#define CRYPTO_SIGNING_KEYS_H

#include "db/db.h"
#include <stddef.h>
#include <time.h>

/*
 * Signing Key Management
 *
 * Manages cryptographic signing keys for JWTs:
 * - Auth Request Signing: HMAC-SHA256 keys (internal authorization requests)
 * - Access Token Signing: ES256 keypairs (OAuth2 access tokens)
 *
 * Features:
 * - Automatic key generation on first use
 * - Passive rotation (checks staleness on every get, rotates if needed)
 * - Graceful key rollover (prior keys retained for validation)
 */

/* Maximum key sizes */
#define SIGNING_KEY_HMAC_SECRET_MAX      128   /* Base64url-encoded HMAC secret */
#define SIGNING_KEY_PEM_MAX              2048  /* PEM-encoded ECDSA keys */

/* Rotation intervals (hardcoded for security) */
#define AUTH_REQUEST_ROTATION_SECONDS    (24 * 3600)        /* 24 hours */
#define ACCESS_TOKEN_ROTATION_SECONDS    (60 * 24 * 3600)   /* 60 days */

/* JWKS endpoint caching and key activation delay
 *
 * After rotation, the new key is published in JWKS immediately but not used
 * for signing until the activation delay has elapsed. This guarantees all
 * JWKS caches (server-side and client-side) have the new key before any
 * token is signed with it — zero verification failures during rotation.
 *
 * Constraint: activation delay >= cache TTL + Cache-Control max-age
 */
#define JWKS_CACHE_TTL_SECONDS         300   /* 5 minutes — server-side cache per worker */
#define JWKS_CACHE_CONTROL_SECONDS     1800  /* 30 minutes — HTTP Cache-Control max-age */
#define JWKS_ACTIVATION_DELAY_SECONDS  2700  /* 45 minutes — sign with prior key until elapsed */

/*
 * Signing key types
 */
typedef enum {
    SIGNING_KEY_AUTH_REQUEST,    /* HMAC-SHA256 for internal auth requests */
    SIGNING_KEY_ACCESS_TOKEN     /* ES256 (ECDSA P-256) for OAuth2 access tokens */
} signing_key_type_t;

/*
 * Signing key data structure
 *
 * Contains either HMAC secrets OR ECDSA keypairs (not both).
 * Check 'type' field to determine which fields are populated.
 */
typedef struct {
    signing_key_type_t type;

    /* HMAC type (auth_request) */
    char *current_secret;               /* Base64url-encoded (32 bytes -> ~44 chars) */
    char *prior_secret;                 /* NULL if no prior key */

    /* ES256 type (access_token) */
    char *current_private_key;          /* PEM format */
    char *current_public_key;           /* PEM format */
    char *prior_private_key;            /* NULL if no prior key */
    char *prior_public_key;             /* NULL if no prior key */

    /* Common */
    time_t current_generated_at;
    time_t prior_generated_at;          /* 0 if no prior key */
} signing_key_t;

/*
 * Get signing key (auto-initializes or rotates if needed)
 *
 * This is the main entry point for all signing key operations.
 * Automatically handles:
 * - First run: Generates and inserts new key if table is empty
 * - Stale key: Rotates if current_generated_at + rotation_interval < now
 * - Fresh key: Returns current key immediately
 *
 * Parameters:
 *   db       - Database handle
 *   type     - Key type (auth_request or access_token)
 *   out_key  - Output buffer for key data (caller must free with signing_key_free)
 *
 * Returns: 0 on success, -1 on error
 *
 * Thread safety: Uses transaction (BEGIN IMMEDIATE) to prevent concurrent rotation
 *
 * Example:
 *   signing_key_t *key = NULL;
 *   if (signing_key_get_or_rotate(db, SIGNING_KEY_AUTH_REQUEST, &key) == 0) {
 *       // Use key->current_secret for HMAC signing
 *       signing_key_free(key);
 *   }
 */
int signing_key_get_or_rotate(db_handle_t *db, signing_key_type_t type,
                                signing_key_t **out_key);

/*
 * Free signing key structure
 *
 * Securely zeros out key material before freeing memory.
 *
 * Parameters:
 *   key - Key structure to free (NULL-safe)
 */
void signing_key_free(signing_key_t *key);

/*
 * Get the active private key for ES256 signing
 *
 * After key rotation, returns the PRIOR private key until the activation
 * delay has elapsed, giving JWKS caches time to propagate the new key.
 * Falls back to current key if no prior key exists (first run).
 *
 * Parameters:
 *   key - Signing key structure (must be SIGNING_KEY_ACCESS_TOKEN type)
 *
 * Returns: PEM private key string to use for signing (do not free)
 */
const char *signing_key_active_private(const signing_key_t *key);

#endif /* CRYPTO_SIGNING_KEYS_H */
