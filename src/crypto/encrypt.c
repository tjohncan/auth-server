#define _POSIX_C_SOURCE 200809L

#include "crypto/encrypt.h"
#include "crypto/hmac.h"
#include "crypto/random.h"
#include "util/log.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

/* AES-256-GCM parameters */
#define AES_KEY_LENGTH   32
#define GCM_IV_LENGTH    12
#define GCM_TAG_LENGTH   16

/* HKDF application-specific constants */
static const unsigned char HKDF_SALT[] = "auth-server-encryption-v1";
static const unsigned char HKDF_INFO_AES[] = "aes256gcm";
static const unsigned char HKDF_INFO_HMAC[] = "hmac-sha256";

/* Derived keys held in static memory after init */
static unsigned char derived_key[AES_KEY_LENGTH];
static unsigned char hmac_key[AES_KEY_LENGTH];
static int key_initialized = 0;

/* Derive a 32-byte key via HKDF-SHA256 (extract + expand) */
static int hkdf_derive(const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out_key, size_t key_len) {
    (void)key_len;  /* Always AES_KEY_LENGTH (32) = one HMAC block */
    unsigned char expand_input[64 + 1];  /* info + counter byte */
    if (info_len > 64) {
        log_error("HKDF info too long");
        return -1;
    }
    memcpy(expand_input, info, info_len);
    expand_input[info_len] = 0x01;

    if (crypto_hmac_sha256(prk, prk_len,
                           expand_input, info_len + 1,
                           out_key, AES_KEY_LENGTH) != 0) {
        return -1;
    }
    return 0;
}

int encrypt_init(const char *passphrase) {
    if (!passphrase || !*passphrase) {
        log_error("Encryption passphrase is empty");
        return -1;
    }

    /* HKDF-Extract: PRK = HMAC-SHA256(salt, passphrase) */
    unsigned char prk[HMAC_SHA256_LENGTH];
    if (crypto_hmac_sha256(HKDF_SALT, sizeof(HKDF_SALT) - 1,
                           (const unsigned char *)passphrase, strlen(passphrase),
                           prk, sizeof(prk)) != 0) {
        log_error("HKDF extract failed");
        return -1;
    }

    /* HKDF-Expand: derive AES key */
    if (hkdf_derive(prk, sizeof(prk),
                    HKDF_INFO_AES, sizeof(HKDF_INFO_AES) - 1,
                    derived_key, sizeof(derived_key)) != 0) {
        OPENSSL_cleanse(prk, sizeof(prk));
        log_error("HKDF expand (AES) failed");
        return -1;
    }

    /* HKDF-Expand: derive HMAC key */
    if (hkdf_derive(prk, sizeof(prk),
                    HKDF_INFO_HMAC, sizeof(HKDF_INFO_HMAC) - 1,
                    hmac_key, sizeof(hmac_key)) != 0) {
        OPENSSL_cleanse(prk, sizeof(prk));
        OPENSSL_cleanse(derived_key, sizeof(derived_key));
        log_error("HKDF expand (HMAC) failed");
        return -1;
    }

    OPENSSL_cleanse(prk, sizeof(prk));
    key_initialized = 1;
    log_info("Field encryption initialized");
    return 0;
}

void encrypt_cleanup(void) {
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    OPENSSL_cleanse(hmac_key, sizeof(hmac_key));
    key_initialized = 0;
}

int encrypt_field(const char *plaintext, char *out_buf, size_t buf_size) {
    if (!plaintext || !out_buf) {
        log_error("Invalid arguments to encrypt_field");
        return -1;
    }

    if (!key_initialized) {
        log_error("Encryption not initialized");
        return -1;
    }

    size_t plaintext_len = strlen(plaintext);
    if (plaintext_len > ENCRYPT_FIELD_MAX_LENGTH) {
        log_error("Plaintext too long for encryption (%zu bytes, max %d)",
                  plaintext_len, ENCRYPT_FIELD_MAX_LENGTH);
        return -1;
    }

    /* Generate random IV */
    unsigned char iv[GCM_IV_LENGTH];
    if (crypto_random_bytes(iv, sizeof(iv)) != 0) {
        log_error("Failed to generate IV for encryption");
        return -1;
    }

    /* Encrypt with AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create cipher context");
        return -1;
    }

    int ret = -1;
    unsigned char ciphertext[256];
    unsigned char tag[GCM_TAG_LENGTH];
    int ciphertext_len = 0;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        log_error("EVP_EncryptInit_ex failed");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LENGTH, NULL) != 1) {
        log_error("Failed to set GCM IV length");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, derived_key, iv) != 1) {
        log_error("EVP_EncryptInit_ex (key/iv) failed");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          (const unsigned char *)plaintext, (int)plaintext_len) != 1) {
        log_error("EVP_EncryptUpdate failed");
        goto cleanup;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        log_error("EVP_EncryptFinal_ex failed");
        goto cleanup;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LENGTH, tag) != 1) {
        log_error("Failed to get GCM tag");
        goto cleanup;
    }

    /* Pack IV || ciphertext || tag into a single buffer */
    size_t packed_len = GCM_IV_LENGTH + (size_t)ciphertext_len + GCM_TAG_LENGTH;
    unsigned char packed[512];
    if (packed_len > sizeof(packed)) {
        log_error("Packed ciphertext too large");
        goto cleanup;
    }

    memcpy(packed, iv, GCM_IV_LENGTH);
    memcpy(packed + GCM_IV_LENGTH, ciphertext, (size_t)ciphertext_len);
    memcpy(packed + GCM_IV_LENGTH + ciphertext_len, tag, GCM_TAG_LENGTH);

    /* Base64url encode */
    size_t encoded_len = crypto_base64url_encode(packed, packed_len, out_buf, buf_size);
    if (encoded_len == 0) {
        log_error("Failed to base64url encode encrypted field");
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(packed, sizeof(packed));
    return ret;
}

int decrypt_field(const char *encrypted, char *out_plaintext, size_t plaintext_size) {
    if (!encrypted || !out_plaintext) {
        log_error("Invalid arguments to decrypt_field");
        return -1;
    }

    if (!key_initialized) {
        log_error("Encryption not initialized");
        return -1;
    }

    /* Base64url decode */
    size_t encrypted_len = strlen(encrypted);
    unsigned char packed[512];
    int packed_len = crypto_base64url_decode(encrypted, encrypted_len,
                                            packed, sizeof(packed));
    if (packed_len < 0) {
        log_error("Failed to base64url decode encrypted field");
        return -1;
    }

    /* Minimum size: IV + tag (no ciphertext = empty plaintext) */
    if ((size_t)packed_len < GCM_IV_LENGTH + GCM_TAG_LENGTH) {
        log_error("Encrypted field too short");
        return -1;
    }

    /* Unpack IV || ciphertext || tag */
    const unsigned char *iv = packed;
    size_t ciphertext_len = (size_t)packed_len - GCM_IV_LENGTH - GCM_TAG_LENGTH;
    const unsigned char *ciphertext = packed + GCM_IV_LENGTH;
    const unsigned char *tag = packed + GCM_IV_LENGTH + ciphertext_len;

    if (ciphertext_len + 1 > plaintext_size) {
        log_error("Output buffer too small for decrypted field");
        return -1;
    }

    /* Decrypt with AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create cipher context");
        return -1;
    }

    int ret = -1;
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        log_error("EVP_DecryptInit_ex failed");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LENGTH, NULL) != 1) {
        log_error("Failed to set GCM IV length");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, derived_key, iv) != 1) {
        log_error("EVP_DecryptInit_ex (key/iv) failed");
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, (unsigned char *)out_plaintext, &len,
                          ciphertext, (int)ciphertext_len) != 1) {
        log_error("EVP_DecryptUpdate failed");
        goto cleanup;
    }
    plaintext_len = len;

    /* Set expected tag for verification */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH,
                            (void *)tag) != 1) {
        log_error("Failed to set GCM tag for verification");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)out_plaintext + len, &len) != 1) {
        log_error("GCM tag verification failed (wrong key or tampered data)");
        OPENSSL_cleanse(out_plaintext, plaintext_size);
        goto cleanup;
    }
    plaintext_len += len;

    out_plaintext[plaintext_len] = '\0';
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(packed, sizeof(packed));
    if (ret != 0) {
        OPENSSL_cleanse(out_plaintext, plaintext_size);
    }
    return ret;
}

int hash_field(const char *plaintext, char *out_hex, size_t hex_size) {
    if (!plaintext || !out_hex) {
        log_error("Invalid arguments to hash_field");
        return -1;
    }

    if (!key_initialized) {
        log_error("Encryption not initialized");
        return -1;
    }

    if (hex_size < HMAC_SHA256_HEX_LENGTH) {
        log_error("Output buffer too small for hash_field (need %d, got %zu)",
                  HMAC_SHA256_HEX_LENGTH, hex_size);
        return -1;
    }

    return crypto_hmac_sha256_hex(hmac_key, sizeof(hmac_key),
                                  (const unsigned char *)plaintext, strlen(plaintext),
                                  out_hex, hex_size);
}
