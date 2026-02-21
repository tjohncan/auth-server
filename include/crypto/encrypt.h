#ifndef CRYPTO_ENCRYPT_H
#define CRYPTO_ENCRYPT_H

#include <stddef.h>

/*
 * Field Encryption (AES-256-GCM)
 *
 * Encrypts sensitive fields (usernames, emails, MFA secrets) before
 * database storage. Protects against database-level compromise (backup theft,
 * insider access, leaked dumps).
 *
 * Key derivation: HKDF-SHA256 from config passphrase (derived once at startup).
 * Encryption: AES-256-GCM with random 12-byte IV per field.
 * Storage format: base64url(IV || ciphertext || 16-byte tag) in TEXT column.
 */

/*
 * Initialize encryption with passphrase from config
 *
 * Derives AES-256 and HMAC-SHA256 keys via HKDF and stores in static memory.
 * Must be called once at startup before any encrypt/decrypt/hash operations.
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

/*
 * Cleanse derived keys from memory at shutdown
 */
void encrypt_cleanup(void);

#endif /* CRYPTO_ENCRYPT_H */
