#ifndef CRYPTO_ENCRYPT_H
#define CRYPTO_ENCRYPT_H

#include <stddef.h>

/* Maximum plaintext length accepted by encrypt_field (bytes) */
#define ENCRYPT_FIELD_MAX_LENGTH 256

/*
 * Field Encryption (AES-256-GCM)
 *
 * Encrypts sensitive fields (usernames, emails, MFA secrets) before
 * database storage. Protects against database-level compromise (backup theft,
 * insider access, leaked dumps).
 *
 * Key derivation, once at startup: the passphrase is stretched with the method,
 * iterations and salt the database records (encryption_params), then
 * HKDF-SHA256 derives the AES key and the blind index's HMAC key from it. A
 * database without that record derives them from the passphrase with HKDF
 * alone, until it's re-keyed (--rekey).
 * Encryption: AES-256-GCM with random 12-byte IV per field.
 * Storage format: base64url(IV || ciphertext || 16-byte tag) in TEXT column.
 */

/* Field keys: AES-256-GCM, and the HMAC key behind the blind indexes */
typedef struct {
    unsigned char aes[32];
    unsigned char hmac[32];
} encrypt_keys_t;

/* How a database stretches its passphrase (its encryption_params row) */
typedef struct {
    char method[24];   /* "argon2id" or "pbkdf2-sha256" */
    int iterations;
    char salt[33];     /* 16 bytes, hex */
} encrypt_params_t;

/*
 * encrypt_params_new - Fresh stretching parameters: the method and iterations
 * given, and a random salt. Returns 0, or -1 for an unknown method or no
 * randomness.
 */
int encrypt_params_new(const char *method, int iterations, encrypt_params_t *out);

/*
 * encrypt_derive_keys - Field keys from a passphrase: stretched by params, then
 * HKDF; or with params NULL, HKDF alone. Costs one hash under the method, so
 * once per process (and once more per key in a re-key).
 *
 * Returns: 0, or -1 (an empty passphrase, a bad method or salt)
 */
int encrypt_derive_keys(const char *passphrase, const encrypt_params_t *params,
                        encrypt_keys_t *out);

/*
 * encrypt_init_keys - Make these the process's field keys, which encrypt_field,
 * decrypt_field and hash_field use. Copied; the caller cleanses its own.
 */
void encrypt_init_keys(const encrypt_keys_t *keys);

/*
 * Initialize encryption with passphrase from config, by HKDF alone (no
 * stretching). For tests and tools that need the keys of a database without
 * encryption_params; the server derives with encrypt_derive_keys.
 *
 * Returns: 0 on success, -1 on error
 */
int encrypt_init(const char *passphrase);

/*
 * Encrypt a field for database storage
 *
 * Parameters:
 *   plaintext  - Value to encrypt
 *   out_buf    - Output buffer for base64url(IV || ciphertext || tag)
 *   buf_size   - Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 */
int encrypt_field(const char *plaintext, char *out_buf, size_t buf_size);

/*
 * Decrypt a field from database storage
 *
 * Parameters:
 *   encrypted      - base64url(IV || ciphertext || tag) from database
 *   out_plaintext  - Output buffer for decrypted value
 *   plaintext_size - Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 */
int decrypt_field(const char *encrypted, char *out_plaintext, size_t plaintext_size);

/*
 * Compute HMAC-SHA256 blind index for database lookups
 *
 * Produces a deterministic hash for WHERE-clause matching on encrypted fields.
 * Caller must normalize input (e.g., lowercase) before calling.
 *
 * Parameters:
 *   plaintext  - Value to hash (e.g., lowercased username)
 *   out_hex    - Output buffer for 64-char hex string (+ null terminator)
 *   hex_size   - Size of output buffer (must be >= 65)
 *
 * Returns: 0 on success, -1 on error
 */
int hash_field(const char *plaintext, char *out_hex, size_t hex_size);

/* The same three under keys of the caller's, for a re-key holding two sets */
int encrypt_field_with(const encrypt_keys_t *keys, const char *plaintext,
                       char *out_buf, size_t buf_size);
int decrypt_field_with(const encrypt_keys_t *keys, const char *encrypted,
                       char *out_plaintext, size_t plaintext_size);
int hash_field_with(const encrypt_keys_t *keys, const char *plaintext,
                    char *out_hex, size_t hex_size);

/*
 * Cleanse derived keys from memory at shutdown
 */
void encrypt_cleanup(void);

#endif /* CRYPTO_ENCRYPT_H */
