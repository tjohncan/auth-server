#ifndef DB_QUERIES_MFA_H
#define DB_QUERIES_MFA_H

#include "db/db.h"
#include <time.h>

/* ============================================================================
 * MFA Method Data Structure
 * ========================================================================== */

typedef struct {
    unsigned char id[16];           /* UUID */
    long long pin;                  /* Internal PK */
    long long user_account_pin;
    char mfa_method[16];            /* "TOTP", "SMS" */
    char display_name[128];         /* User-chosen name: "My Phone", "Work Laptop", etc. */
    char secret[256];               /* Base32-encoded for TOTP, phone number for SMS */
    int is_confirmed;
    char confirmed_at[32];
} mfa_method_t;

/* ============================================================================
 * MFA Method Management
 * ========================================================================== */

/* Create new MFA method (always unconfirmed initially)
 * For TOTP: secret is base32-encoded random bytes
 * For SMS: secret is phone number
 * Returns: 0 on success, -1 on error */
int mfa_method_create(db_handle_t *db,
                      long long user_account_pin,
                      const char *mfa_method,
                      const char *display_name,
                      const char *secret,
                      unsigned char *out_method_id);

/* Confirm MFA method (mark is_confirmed = 1, set confirmed_at)
 * Used by both TOTP and SMS flows
 * Returns: 0 on success, -1 on error */
int mfa_method_confirm(db_handle_t *db, const unsigned char *method_id);

/* Get single method by ID
 * Returns: 0 on success, -1 on error */
int mfa_method_get_by_id(db_handle_t *db,
                         const unsigned char *method_id,
                         mfa_method_t *out_method);

/* List all methods for user
 * filter_confirmed: if 1, only return confirmed methods; if 0, return all
 * Returns: 0 on success, -1 on error
 * Caller must free *out_methods with free() */
int mfa_method_list(db_handle_t *db,
                    long long user_account_pin,
                    int filter_confirmed,
                    mfa_method_t **out_methods,
                    int *out_count);

/* Delete method (hard delete)
 * Returns: 0 on success, -1 on error */
int mfa_method_delete(db_handle_t *db, const unsigned char *method_id);

/* Count confirmed methods for user
 * Returns: 0 on success, -1 on error */
int mfa_method_count_confirmed(db_handle_t *db,
                                long long user_account_pin,
                                int *out_count);

/* ============================================================================
 * Recovery Code Management
 * ========================================================================== */

typedef struct {
    unsigned char id[16];           /* UUID */
    long long user_account_pin;
    char salt[256];
    int hash_iterations;
    int is_active;
    char generated_at[32];
} recovery_code_set_t;

/* Create recovery code set with hashed codes
 * plaintext_codes: array of plaintext recovery codes (will be hashed)
 * code_count: number of codes in array
 * Returns: 0 on success, -1 on error */
int recovery_code_set_create(db_handle_t *db,
                              long long user_account_pin,
                              const char **plaintext_codes,
                              int code_count,
                              unsigned char *out_set_id);

/* Get active recovery code set for user
 * Returns: 0 on success, -1 on error, 1 if no active set found */
int recovery_code_set_get_active(db_handle_t *db,
                                  long long user_account_pin,
                                  recovery_code_set_t *out_set);

/* Verify recovery code (marks as used if valid)
 * Returns: 1 if valid, 0 if invalid, -1 on error */
int recovery_code_verify(db_handle_t *db,
                         long long user_account_pin,
                         const char *code);

/* Revoke recovery code set (set is_active = 0)
 * Returns: 0 on success, -1 on error */
int recovery_code_set_revoke(db_handle_t *db,
                              const unsigned char *set_id);

/* Get masked recovery codes (last 4 chars visible)
 * Returns: 0 on success, -1 on error
 * Caller must free *out_masked_codes and each string with free() */
int recovery_code_get_masked_list(db_handle_t *db,
                                   long long user_account_pin,
                                   char ***out_masked_codes,
                                   int *out_count);

/* ============================================================================
 * User Flag Management
 * ========================================================================== */

/* Update user.require_mfa flag (user preference)
 * Returns: 0 on success, -1 on error */
int mfa_update_require_mfa_flag(db_handle_t *db,
                                 long long user_account_pin,
                                 int require_mfa);

/* ============================================================================
 * Logging
 * ========================================================================== */

/* Log MFA authentication attempt
 * user_mfa_pin: which method was used
 * success: 1 if code was valid, 0 if invalid
 * Returns: 0 on success, -1 on error */
int mfa_log_usage(db_handle_t *db,
                  long long user_mfa_pin,
                  int success,
                  const char *source_ip,
                  const char *user_agent);

#endif /* DB_QUERIES_MFA_H */
