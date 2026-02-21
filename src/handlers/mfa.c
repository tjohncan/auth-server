#define _POSIX_C_SOURCE 200809L

#include "handlers/mfa.h"
#include "db/queries/mfa.h"
#include "crypto/totp.h"
#include "crypto/random.h"
#include "crypto/encrypt.h"
#include "util/log.h"
#include "util/data.h"
#include "util/str.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>

static int generate_recovery_codes(char ***out_codes) {
    char **codes = malloc(MFA_RECOVERY_CODE_COUNT * sizeof(char *));
    if (!codes) {
        log_error("Failed to allocate recovery codes array");
        return -1;
    }

    for (int i = 0; i < MFA_RECOVERY_CODE_COUNT; i++) {
        unsigned char rand_bytes[MFA_RECOVERY_CODE_LENGTH / 2];
        if (crypto_random_bytes(rand_bytes, sizeof(rand_bytes)) != 0) {
            log_error("Failed to generate random bytes for recovery code");
            for (int j = 0; j < i; j++) free(codes[j]);
            free(codes);
            return -1;
        }

        codes[i] = malloc(MFA_RECOVERY_CODE_LENGTH + 1);
        if (!codes[i]) {
            log_error("Failed to allocate recovery code string");
            for (int j = 0; j < i; j++) free(codes[j]);
            free(codes);
            return -1;
        }

        bytes_to_hex(rand_bytes, sizeof(rand_bytes), codes[i], MFA_RECOVERY_CODE_LENGTH + 1);
    }

    *out_codes = codes;
    return 0;
}

int mfa_totp_setup(db_handle_t *db,
                   long long user_account_pin,
                   const char *display_name,
                   const char *issuer,
                   const char *username,
                   unsigned char *out_method_id,
                   char *out_secret, size_t secret_size,
                   char *out_qr_url, size_t qr_url_size) {
    if (!db || !display_name || !issuer || !username ||
        !out_method_id || !out_secret || !out_qr_url) {
        log_error("Invalid arguments to mfa_totp_setup");
        return -1;
    }

    /* Generate TOTP secret */
    char secret[TOTP_SECRET_BASE32_LEN + 1];
    if (crypto_totp_generate_secret(secret, sizeof(secret)) != 0) {
        log_error("Failed to generate TOTP secret");
        return -1;
    }

    /* Encrypt secret for database storage */
    char encrypted_secret[256];
    if (encrypt_field(secret, encrypted_secret, sizeof(encrypted_secret)) != 0) {
        OPENSSL_cleanse(secret, sizeof(secret));
        log_error("Failed to encrypt MFA secret");
        return -1;
    }

    /* Create unconfirmed MFA method */
    unsigned char method_id[16];
    if (mfa_method_create(db, user_account_pin, "TOTP", display_name,
                          encrypted_secret, method_id) != 0) {
        OPENSSL_cleanse(secret, sizeof(secret));
        log_error("Failed to create MFA method");
        return -1;
    }

    /* Generate QR URL */
    if (crypto_totp_generate_qr_url(secret, username, issuer,
                                     out_qr_url, qr_url_size) != 0) {
        OPENSSL_cleanse(secret, sizeof(secret));
        log_error("Failed to generate TOTP QR URL");
        return -1;
    }

    memcpy(out_method_id, method_id, 16);
    str_copy(out_secret, secret_size, secret);
    OPENSSL_cleanse(secret, sizeof(secret));

    log_info("TOTP setup initiated");
    return 0;
}

int mfa_totp_confirm(db_handle_t *db,
                     long long user_account_pin,
                     const unsigned char *method_id,
                     const char *totp_code,
                     char ***out_recovery_codes,
                     int *out_recovery_count) {
    if (!db || !method_id || !totp_code || !out_recovery_codes || !out_recovery_count) {
        log_error("Invalid arguments to mfa_totp_confirm");
        return -1;
    }

    *out_recovery_codes = NULL;
    *out_recovery_count = 0;

    /* Get method and verify ownership */
    mfa_method_t method;
    if (mfa_method_get_by_id(db, method_id, &method) != 0) {
        log_error("MFA method not found");
        return -1;
    }

    if (method.user_account_pin != user_account_pin) {
        log_error("MFA method does not belong to this user");
        return -1;
    }

    if (method.is_confirmed) {
        log_error("MFA method is already confirmed");
        return -1;
    }

    /* Decrypt secret from database */
    char decrypted_secret[TOTP_SECRET_BASE32_LEN + 1];
    if (decrypt_field(method.secret, decrypted_secret, sizeof(decrypted_secret)) != 0) {
        log_error("Failed to decrypt MFA secret");
        return -1;
    }

    /* Verify TOTP code against the unconfirmed method's secret */
    int valid = crypto_totp_verify(decrypted_secret, totp_code, time(NULL));
    OPENSSL_cleanse(decrypted_secret, sizeof(decrypted_secret));
    if (valid != 1) {
        if (valid == 0) {
            log_info("TOTP confirm failed: invalid code");
            return 1;  /* Invalid code */
        }
        log_error("Error verifying TOTP code during confirm");
        return -1;
    }

    /* Confirm the method */
    if (mfa_method_confirm(db, method_id) != 0) {
        log_error("Failed to confirm MFA method");
        return -1;
    }

    /* Generate recovery codes if this is the first confirmed method */
    int confirmed_count = 0;
    if (mfa_method_count_confirmed(db, user_account_pin, &confirmed_count) != 0) {
        log_error("Failed to count confirmed MFA methods");
        return -1;
    }

    if (confirmed_count == 1) {
        char **codes = NULL;
        if (generate_recovery_codes(&codes) != 0) {
            log_error("Failed to generate recovery codes");
            return -1;
        }

        unsigned char set_id[16];
        const char *code_ptrs[MFA_RECOVERY_CODE_COUNT];
        for (int i = 0; i < MFA_RECOVERY_CODE_COUNT; i++) {
            code_ptrs[i] = codes[i];
        }

        if (recovery_code_set_create(db, user_account_pin,
                                     code_ptrs, MFA_RECOVERY_CODE_COUNT,
                                     set_id) != 0) {
            log_error("Failed to store recovery codes");
            for (int i = 0; i < MFA_RECOVERY_CODE_COUNT; i++) free(codes[i]);
            free(codes);
            return -1;
        }

        *out_recovery_codes = codes;
        *out_recovery_count = MFA_RECOVERY_CODE_COUNT;
    }

    log_info("Confirmed MFA method");
    return 0;
}

int mfa_verify(db_handle_t *db,
               long long user_account_pin,
               const unsigned char *method_id,
               const char *totp_code,
               const char *source_ip,
               const char *user_agent) {
    if (!db || !method_id || !totp_code) {
        log_error("Invalid arguments to mfa_verify");
        return -1;
    }

    /* Get method, verify ownership and confirmed status */
    mfa_method_t method;
    if (mfa_method_get_by_id(db, method_id, &method) != 0) {
        log_debug("MFA method not found");
        return 0;  /* Treat as invalid */
    }

    if (method.user_account_pin != user_account_pin) {
        log_error("MFA method does not belong to this user");
        return 0;  /* Treat as invalid */
    }

    if (!method.is_confirmed) {
        log_error("MFA method is not confirmed");
        return 0;  /* Treat as invalid */
    }

    /* Decrypt secret from database */
    char decrypted_secret[TOTP_SECRET_BASE32_LEN + 1];
    if (decrypt_field(method.secret, decrypted_secret, sizeof(decrypted_secret)) != 0) {
        log_error("Failed to decrypt MFA secret");
        return -1;
    }

    /* Verify code directly using the decrypted secret */
    int valid = crypto_totp_verify(decrypted_secret, totp_code, time(NULL));
    OPENSSL_cleanse(decrypted_secret, sizeof(decrypted_secret));

    /* Log the attempt */
    if (mfa_log_usage(db, method.pin, valid == 1 ? 1 : 0,
                      source_ip, user_agent) != 0) {
        log_error("Failed to log MFA usage (non-fatal)");
    }

    if (valid == 1) {
        log_info("MFA verified");
        return 1;
    } else if (valid == 0) {
        log_info("MFA verification failed");
        return 0;
    } else {
        log_error("Error during MFA verification");
        return -1;
    }
}

int mfa_recover(db_handle_t *db,
                long long user_account_pin,
                const char *recovery_code) {
    if (!db || !recovery_code) {
        log_error("Invalid arguments to mfa_recover");
        return -1;
    }

    int result = recovery_code_verify(db, user_account_pin, recovery_code);

    if (result == 1) {
        log_info("Recovery code used");
    } else if (result == 0) {
        log_info("Invalid recovery code");
    }

    return result;
}

int mfa_delete_method(db_handle_t *db,
                      long long user_account_pin,
                      const unsigned char *method_id) {
    if (!db || !method_id) {
        log_error("Invalid arguments to mfa_delete_method");
        return -1;
    }

    /* Verify ownership before deleting */
    mfa_method_t method;
    if (mfa_method_get_by_id(db, method_id, &method) != 0) {
        log_error("MFA method not found");
        return -1;
    }

    if (method.user_account_pin != user_account_pin) {
        log_error("MFA method does not belong to this user");
        return -1;
    }

    return mfa_method_delete(db, method_id);
}

int mfa_regenerate_recovery_codes(db_handle_t *db,
                                   long long user_account_pin,
                                   char ***out_recovery_codes,
                                   int *out_count) {
    if (!db || !out_recovery_codes || !out_count) {
        log_error("Invalid arguments to mfa_regenerate_recovery_codes");
        return -1;
    }

    /* Must have at least one confirmed method */
    int confirmed_count = 0;
    if (mfa_method_count_confirmed(db, user_account_pin, &confirmed_count) != 0) {
        log_error("Failed to count confirmed MFA methods");
        return -1;
    }

    if (confirmed_count == 0) {
        log_error("Cannot generate recovery codes without a confirmed MFA method");
        return -1;
    }

    /* Generate plaintext codes */
    char **codes = NULL;
    if (generate_recovery_codes(&codes) != 0) {
        return -1;
    }

    /* Store (revokes existing set atomically) */
    unsigned char set_id[16];
    const char *code_ptrs[MFA_RECOVERY_CODE_COUNT];
    for (int i = 0; i < MFA_RECOVERY_CODE_COUNT; i++) {
        code_ptrs[i] = codes[i];
    }

    if (recovery_code_set_create(db, user_account_pin,
                                 code_ptrs, MFA_RECOVERY_CODE_COUNT,
                                 set_id) != 0) {
        log_error("Failed to store recovery codes");
        for (int i = 0; i < MFA_RECOVERY_CODE_COUNT; i++) free(codes[i]);
        free(codes);
        return -1;
    }

    *out_recovery_codes = codes;
    *out_count = MFA_RECOVERY_CODE_COUNT;

    log_info("Regenerated recovery codes");
    return 0;
}
