#ifndef HANDLERS_MFA_H
#define HANDLERS_MFA_H

#include "db/db.h"
#include <stddef.h>

/*
 * MFA Handler Functions
 *
 * Business logic layer for MFA enrollment, verification, and management.
 * All handlers perform authorization checks (method ownership) before operations.
 *
 * Note: Internal PINs in result structs must not be serialized to API responses.
 */

#define MFA_RECOVERY_CODE_COUNT   10
#define MFA_RECOVERY_CODE_LENGTH  20    /* hex chars (10 random bytes) */

/*
 * Begin TOTP enrollment
 *
 * Generates TOTP secret, creates unconfirmed method, returns QR URL for scanning.
 * Must be confirmed with mfa_totp_confirm before the method becomes active.
 *
 * Parameters:
 *   db               - Database handle
 *   user_account_pin - User performing setup
 *   display_name     - User-chosen name (e.g., "My Phone")
 *   issuer           - Service name for authenticator app
 *   username         - Username for authenticator label
 *   out_method_id    - Output: UUID of created method
 *   out_secret       - Output buffer for base32 secret (manual entry fallback)
 *   secret_size      - Size of out_secret buffer
 *   out_qr_url       - Output buffer for otpauth:// URL
 *   qr_url_size      - Size of out_qr_url buffer
 *
 * Returns: 0 on success, -1 on error
 */
int mfa_totp_setup(db_handle_t *db,
                   long long user_account_pin,
                   const char *display_name,
                   const char *issuer,
                   const char *username,
                   unsigned char *out_method_id,
                   char *out_secret, size_t secret_size,
                   char *out_qr_url, size_t qr_url_size);

/*
 * Confirm TOTP enrollment
 *
 * Verifies TOTP code against unconfirmed method. On success, confirms the method
 * and generates recovery codes if this is the first confirmed method.
 *
 * Parameters:
 *   db                  - Database handle
 *   user_account_pin    - Must match method owner
 *   method_id           - UUID of unconfirmed method
 *   totp_code           - 6-digit code from authenticator app
 *   out_recovery_codes  - Output: array of plaintext recovery codes, or NULL
 *   out_recovery_count  - Output: number of codes, or 0
 *
 * Returns: 0 on success, 1 if code invalid, -1 on error
 * Note: If out_recovery_codes is set, caller must free each string and the array
 */
int mfa_totp_confirm(db_handle_t *db,
                     long long user_account_pin,
                     const unsigned char *method_id,
                     const char *totp_code,
                     char ***out_recovery_codes,
                     int *out_recovery_count);

/*
 * Verify TOTP code during authentication
 *
 * Verifies the method belongs to the user, code is valid, and logs the attempt.
 *
 * Parameters:
 *   db               - Database handle
 *   user_account_pin - Must match method owner
 *   method_id        - UUID of confirmed method
 *   totp_code        - 6-digit code from authenticator app
 *   source_ip        - Client IP for audit log (optional)
 *   user_agent       - Client user agent for audit log (optional)
 *
 * Returns: 1 if valid, 0 if invalid, -1 on error
 */
int mfa_verify(db_handle_t *db,
               long long user_account_pin,
               const unsigned char *method_id,
               const char *totp_code,
               const char *source_ip,
               const char *user_agent);

/*
 * Verify recovery code during authentication
 *
 * Parameters:
 *   db               - Database handle
 *   user_account_pin - User attempting recovery
 *   recovery_code    - Plaintext recovery code
 *
 * Returns: 1 if valid, 0 if invalid, -1 on error
 */
int mfa_recover(db_handle_t *db,
                long long user_account_pin,
                const char *recovery_code);

/*
 * Delete MFA method
 *
 * Verifies method belongs to user before deleting.
 *
 * Returns: 0 on success, -1 on error
 */
int mfa_delete_method(db_handle_t *db,
                      long long user_account_pin,
                      const unsigned char *method_id);

/*
 * Regenerate recovery codes
 *
 * Revokes existing set and creates new one.
 * Requires at least one confirmed MFA method.
 *
 * Returns: 0 on success, -1 on error
 * Note: Caller must free each string and the array
 */
int mfa_regenerate_recovery_codes(db_handle_t *db,
                                   long long user_account_pin,
                                   char ***out_recovery_codes,
                                   int *out_count);

#endif /* HANDLERS_MFA_H */
