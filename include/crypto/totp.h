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
 * Returns: 1 if valid, 0 if invalid, -1 on error
 *
 * DESIGN DECISION: codes are not single-use within their window.
 *
 * RFC 6238 Section 5.2 suggests recording the last accepted time step and
 * rejecting any code at or below it. We deliberately do not. A code is valid
 * for its full window and presenting it twice succeeds twice: if two parties
 * can both prove possession of the secret, we admit both.
 *
 * Single-use enforcement buys less than it appears to, and costs more:
 *
 *   - It does not stop an attacker who holds the secret. They wait 30 seconds.
 *   - It does not stop real-time relay phishing, the attack it looks like it
 *     should stop. There the attacker's bot always beats the human it is
 *     proxying, so the attacker gets in either way — and with single-use the
 *     *victim* is then rejected, for reasons they can neither see nor fix. We
 *     would break the honest party's login without stopping the dishonest one.
 *   - What it genuinely blocks is narrow: delayed replay of an observed code,
 *     inside its window, by someone who does not hold the secret.
 *
 * The cost, by contrast, is unconditional: any two legitimate holders of the
 * same seed (an authenticator on two devices, a second tab, a retry after a
 * flaky request) race each other, and the loser gets an opaque failure. We are
 * not willing to adjudicate that footrace every 30 seconds to close a window
 * this narrow.
 *
 * Accepted: an observed code can be replayed until its window closes.
 * Bounded by: guessing (as opposed to observing) is capped by per-method rate
 * limiting — see is_rate_limited in db/queries/mfa.c.
 *
 * Revisit if: we must certify against RFC 6238 §5.2, or delayed-replay attacks
 * appear against a real deployment. The change is small — persist the highest
 * accepted counter per method and reject <= it.
 */
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
