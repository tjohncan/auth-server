#ifndef CRYPTO_TOTP_H
#define CRYPTO_TOTP_H

#include <stddef.h>
#include <time.h>

/* TOTP standard parameters */
#define TOTP_SECRET_BYTES 20        /* 160 bits (standard) */
#define TOTP_SECRET_BASE32_LEN 32   /* 20 bytes -> 32 base32 chars */
#define TOTP_CODE_DIGITS 6          /* Standard 6-digit codes */
#define TOTP_TIME_STEP 30           /* 30-second time step */
#define TOTP_TIME_WINDOW 1          /* ±1 time step (±30 seconds) */

/* ============================================================================
 * TOTP Secret Generation
 * ============================================================================ */

/* Generate random TOTP secret (base32-encoded)
 * Returns: 0 on success, -1 on error
 * Output: out_secret contains null-terminated base32 string */
int crypto_totp_generate_secret(char *out_secret, size_t secret_size);

/* ============================================================================
 * TOTP Code Generation and Verification
 * ============================================================================ */

/* Generate TOTP code for given secret at specific time
 * Used primarily for testing with fixed timestamps
 * Returns: 0 on success, -1 on error */
int crypto_totp_generate_code(const char *secret, time_t timestamp,
                               char *out_code, size_t code_size);

/* Verify TOTP code against secret with time window
 * Checks current time ± TOTP_TIME_WINDOW steps (±30 seconds)
 * Returns: 1 if valid, 0 if invalid, -1 on error */
int crypto_totp_verify(const char *secret, const char *code, time_t current_time);

/* ============================================================================
 * QR Code URL Generation
 * ============================================================================ */

/* Generate otpauth:// URL for QR code enrollment
 * Format: otpauth://totp/Issuer:username?secret=XXX&issuer=Issuer
 * Returns: 0 on success, -1 on error */
int crypto_totp_generate_qr_url(const char *secret, const char *username,
                                 const char *issuer, char *out_url, size_t url_size);

#endif /* CRYPTO_TOTP_H */
