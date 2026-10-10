#include "crypto/password.h"
#include "crypto/argon2.h"
#include "crypto/pbkdf2.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/data.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

/* Module-level state (initialized once at startup, read-only after init):
   each kind's method and iteration range */
typedef struct {
    password_hash_algorithm_t algorithm;
    int min_iterations;
    int max_iterations;
} kind_settings_t;

static kind_settings_t g_kinds[2];
static int g_password_min_length;
static int g_machine_dummy;  /* unknown key ids get a dummy verification */
static int g_initialized = 0;

/* The most PBKDF2 iterations a machine-secret dummy may cost: about a
   millisecond. An unknown key id costs whoever sends one nothing, so a dummy
   any dearer would let anyone make a worker spend it. */
#define MACHINE_DUMMY_MAX_PBKDF2_ITERATIONS 10000

/* The name a method is stored and configured under; NULL for none */
static const char *method_name(password_hash_algorithm_t algorithm) {
    switch (algorithm) {
    case PASSWORD_HASH_ARGON2ID:      return "argon2id";
    case PASSWORD_HASH_PBKDF2_SHA256: return "pbkdf2-sha256";
    default:                          return NULL;
    }
}

/* The method a label names, or PASSWORD_HASH_UNSET */
static password_hash_algorithm_t method_from_name(const char *name, size_t len) {
    if (len == 8 && strncmp(name, "argon2id", 8) == 0) return PASSWORD_HASH_ARGON2ID;
    if (len == 13 && strncmp(name, "pbkdf2-sha256", 13) == 0) return PASSWORD_HASH_PBKDF2_SHA256;
    return PASSWORD_HASH_UNSET;
}

int crypto_password_init(const config_t *config) {
    if (!config) {
        log_error("Invalid config to crypto_password_init");
        return -1;
    }

    if (g_initialized) {
        log_warn("crypto_password already initialized");
        return 0;
    }

    g_kinds[SECRET_USER] = (kind_settings_t){
        config->secret_hashing_algorithm,
        config->secret_hash_min_iterations,
        config->secret_hash_max_iterations,
    };
    g_kinds[SECRET_MACHINE] = (kind_settings_t){
        config->machine_secret_hashing_algorithm,
        config->machine_secret_hash_min_iterations,
        config->machine_secret_hash_max_iterations,
    };

    /* config_load fills every setting in; one missing here would store hashes
       under no method, or fail every one, so it stops the start instead */
    for (int kind = SECRET_USER; kind <= SECRET_MACHINE; kind++) {
        const kind_settings_t *k = &g_kinds[kind];
        if (!method_name(k->algorithm) || k->min_iterations < 1 ||
            k->max_iterations < k->min_iterations) {
            log_error("No hashing method or iterations for %s",
                      kind == SECRET_USER ? "passwords" : "machine secrets");
            return -1;
        }
    }

    const kind_settings_t *machine = &g_kinds[SECRET_MACHINE];
    g_machine_dummy = machine->algorithm == PASSWORD_HASH_PBKDF2_SHA256 &&
                      machine->max_iterations <= MACHINE_DUMMY_MAX_PBKDF2_ITERATIONS;
    g_password_min_length = config->password_min_length;
    g_initialized = 1;

    log_info("Initialized password hashing: passwords %s, iterations=%d-%d; "
             "machine secrets %s, iterations=%d-%d",
             method_name(g_kinds[SECRET_USER].algorithm),
             g_kinds[SECRET_USER].min_iterations, g_kinds[SECRET_USER].max_iterations,
             method_name(machine->algorithm), machine->min_iterations, machine->max_iterations);
    if (!g_machine_dummy) {
        log_warn("Machine secrets are hashed with %s at up to %d iterations: every client, "
                 "resource-server and org key check stalls a worker for a password hash, and "
                 "unknown key ids answer at once rather than let anyone spend that. "
                 "auth.conf.example sets machine_secret_hashing_algorithm = pbkdf2-sha256 at 777.",
                 method_name(machine->algorithm), machine->max_iterations);
    }

    return 0;
}

int crypto_password_min_length(void) {
    return g_password_min_length;
}

const char *crypto_password_method(secret_kind_t kind) {
    return method_name(g_kinds[kind].algorithm);
}

int crypto_password_min_iterations(secret_kind_t kind) {
    return g_kinds[kind].min_iterations;
}

int crypto_password_hash_method(const char *stored_hash, char *out_method, size_t size) {
    const char *sep = stored_hash ? strchr(stored_hash, '$') : NULL;
    if (!sep || method_from_name(stored_hash, (size_t)(sep - stored_hash)) == PASSWORD_HASH_UNSET ||
        (size_t)(sep - stored_hash) >= size) {
        return -1;
    }
    memcpy(out_method, stored_hash, (size_t)(sep - stored_hash));
    out_method[sep - stored_hash] = '\0';
    return 0;
}

/* The stored form: "<method>$<hex>" */
static int label(password_hash_algorithm_t algorithm, const char *hex, char *out, size_t size) {
    const char *name = method_name(algorithm);
    if (!name) return -1;
    int n = snprintf(out, size, "%s$%s", name, hex);
    return (n < 0 || (size_t)n >= size) ? -1 : 0;
}

/* Hash with a given method, salt and iterations, into the stored form */
static int hash_labeled(password_hash_algorithm_t algorithm, const char *password,
                        size_t password_len, const char *salt_hex, int iterations,
                        char *out_hash, size_t hash_len) {
    char hex[ARGON2_HASH_HEX_LENGTH > PBKDF2_HASH_HEX_LENGTH
             ? ARGON2_HASH_HEX_LENGTH : PBKDF2_HASH_HEX_LENGTH];
    int rc;
    switch (algorithm) {
    case PASSWORD_HASH_ARGON2ID:
        rc = crypto_argon2_hash_with_salt(password, password_len, salt_hex, iterations,
                                          hex, sizeof(hex));
        break;
    case PASSWORD_HASH_PBKDF2_SHA256:
        rc = crypto_pbkdf2_hash_with_salt(password, password_len, salt_hex, iterations,
                                          hex, sizeof(hex));
        break;
    default:
        return -1;
    }
    if (rc == 0) rc = label(algorithm, hex, out_hash, hash_len);
    OPENSSL_cleanse(hex, sizeof(hex));
    return rc;
}

int crypto_password_hash(secret_kind_t kind, const char *password, size_t password_len,
                         char *out_salt_hex, size_t salt_hex_len,
                         int *out_iterations,
                         char *out_hash, size_t hash_len) {
    if (!password || !out_salt_hex || !out_iterations || !out_hash) {
        log_error("Invalid arguments to crypto_password_hash");
        return -1;
    }

    if (!g_initialized) {
        log_error("crypto_password module not initialized");
        return -1;
    }

    if (salt_hex_len < PASSWORD_SALT_HEX_MAX_LENGTH || hash_len < PASSWORD_HASH_MAX_LENGTH) {
        log_error("Output buffer too small for password hash");
        return -1;
    }

    if (password_len > PASSWORD_MAX_LENGTH) {
        log_info("Password rejected: length %zu exceeds maximum %d",
                 password_len, PASSWORD_MAX_LENGTH);
        return -2;
    }

    if ((int)password_len < g_password_min_length) {
        log_info("Password rejected: length %zu below minimum %d",
                 password_len, g_password_min_length);
        return -2;
    }

    const kind_settings_t *k = &g_kinds[kind];
    unsigned char salt[ARGON2_SALT_LENGTH];  /* the same length for both methods */
    if (crypto_random_bytes(salt, sizeof(salt)) != 0) {
        log_error("Failed to generate salt");
        return -1;
    }
    bytes_to_hex(salt, sizeof(salt), out_salt_hex, salt_hex_len);
    OPENSSL_cleanse(salt, sizeof(salt));

    /* Drawn from the range (no draw when min == max) */
    *out_iterations = crypto_random_int_range(k->min_iterations, k->max_iterations);

    if (hash_labeled(k->algorithm, password, password_len, out_salt_hex, *out_iterations,
                     out_hash, hash_len) != 0) {
        log_error("%s hash failed", method_name(k->algorithm));
        return -1;
    }
    return 0;
}

int crypto_password_hash_with_salt(const char *method, const char *password,
                                   size_t password_len, const char *salt_hex,
                                   int iterations, char *out_hash, size_t hash_len) {
    if (!method || !password || !salt_hex || !out_hash) {
        log_error("Invalid arguments to crypto_password_hash_with_salt");
        return -1;
    }
    password_hash_algorithm_t algorithm = method_from_name(method, strlen(method));
    if (algorithm == PASSWORD_HASH_UNSET) {
        log_error("Unknown hashing method '%s'", method);
        return -1;
    }
    return hash_labeled(algorithm, password, password_len, salt_hex, iterations,
                        out_hash, hash_len);
}

void crypto_password_verify_dummy(secret_kind_t kind, const char *password,
                                  size_t password_len) {
    /* An unknown key id costs nothing to send: its dummy is spent only while the
     * machine method is cheap (crypto_password_init says when it isn't) */
    if (kind == SECRET_MACHINE && !g_machine_dummy) return;

    /* Drawn like a real hash's, not pinned to the minimum: with a range
     * configured, real hashes average its middle, and a cheaper dummy would
     * tell an existing account from a missing one by time */
    const kind_settings_t *k = &g_kinds[kind];
    char stored[PASSWORD_HASH_MAX_LENGTH];
    if (label(k->algorithm, "0000000000000000000000000000000000000000000000000000000000000000",
              stored, sizeof(stored)) != 0) {
        return;
    }
    crypto_password_verify(kind, password, password_len, "00000000000000000000000000000000",
                           crypto_random_int_range(k->min_iterations, k->max_iterations),
                           stored, NULL);
}

int crypto_password_verify(secret_kind_t kind, const char *password, size_t password_len,
                           const char *salt_hex, int iterations,
                           const char *stored_hash, int *out_rehash) {
    if (out_rehash) *out_rehash = 0;
    if (!password || !salt_hex || !stored_hash) {
        log_error("Invalid arguments to crypto_password_verify");
        return -1;
    }

    if (!g_initialized) {
        log_error("crypto_password module not initialized");
        return -1;
    }

    /* The method the hash names */
    const char *sep = strchr(stored_hash, '$');
    password_hash_algorithm_t algorithm = sep
        ? method_from_name(stored_hash, (size_t)(sep - stored_hash)) : PASSWORD_HASH_UNSET;
    if (algorithm == PASSWORD_HASH_UNSET) {
        log_error("A stored secret hash doesn't start with the method that made it "
                  "(argon2id$ or pbkdf2-sha256$), so it can't be checked");
        return -1;
    }

    if (password_len > PASSWORD_MAX_LENGTH) {
        return 0;  /* Oversized input cannot match any stored hash */
    }

    int valid = algorithm == PASSWORD_HASH_ARGON2ID
        ? crypto_argon2_verify(password, password_len, salt_hex, iterations, sep + 1)
        : crypto_pbkdf2_verify(password, password_len, salt_hex, iterations, sep + 1);

    const kind_settings_t *k = &g_kinds[kind];
    if (valid == 1 && out_rehash) {
        *out_rehash = algorithm != k->algorithm ||
                      iterations < k->min_iterations || iterations > k->max_iterations;
    }
    return valid;
}
