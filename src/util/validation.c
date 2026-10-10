#include "util/validation.h"
#include "util/json.h"
#include "util/log.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

/* Well-formed UTF-8, so what's stored can always be sent back as JSON */
static int utf8_ok(const char *value, const char *what, char *error_msg, size_t error_len) {
    if (json_utf8_valid(value, strlen(value))) return 1;
    if (error_msg && error_len > 0) {
        snprintf(error_msg, error_len, "%s is not valid UTF-8", what);
    }
    return 0;
}

int validate_username(const char *username, char *error_msg, size_t error_len) {
    if (!username) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Username is NULL");
        }
        return -1;
    }

    /* Check for empty string */
    if (username[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Username cannot be empty");
        }
        return -1;
    }

    /* Check length (must fit within HTML escape buffers and encryption limit) */
    if (strlen(username) > 100) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Username must be 100 characters or fewer");
        }
        return -1;
    }

    /* Check for spaces, @ symbol, and control characters */
    for (const char *p = username; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Username contains invalid control character (0x%02X)", c);
            }
            return -1;
        }
        if (*p == ' ') {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Username cannot contain spaces");
            }
            return -1;
        }
        if (*p == '@') {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Username cannot contain @ symbol");
            }
            return -1;
        }
    }

    if (!utf8_ok(username, "Username", error_msg, error_len)) return -1;

    return 0;  /* Valid */
}

int validate_email(const char *email, char *error_msg, size_t error_len) {
    if (!email) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email is NULL");
        }
        return -1;
    }

    /* Check for empty string */
    if (email[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email cannot be empty");
        }
        return -1;
    }

    /* Check length (must fit within field encryption limit; also RFC 5321 max) */
    if (strlen(email) > 254) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email must be 254 characters or fewer");
        }
        return -1;
    }

    /* Find @ symbol, check for spaces and control characters */
    const char *at_pos = NULL;
    int at_count = 0;

    for (const char *p = email; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Email contains invalid control character (0x%02X)", c);
            }
            return -1;
        }
        if (*p == ' ') {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Email cannot contain spaces");
            }
            return -1;
        }
        if (*p == '@') {
            at_count++;
            at_pos = p;
        }
    }

    /* Check for exactly one @ */
    if (at_count == 0) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email must contain @ symbol");
        }
        return -1;
    }
    if (at_count > 1) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email cannot contain multiple @ symbols");
        }
        return -1;
    }

    /* Check for at least one char before @ */
    if (at_pos == email) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email must have at least one character before @");
        }
        return -1;
    }

    /* Check for at least one char after @ */
    if (*(at_pos + 1) == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email must have at least one character after @");
        }
        return -1;
    }

    if (!utf8_ok(email, "Email", error_msg, error_len)) return -1;

    return 0;  /* Valid */
}

int validate_code_name(const char *code_name, char *error_msg, size_t error_len) {
    if (!code_name) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Code name is NULL");
        }
        return -1;
    }

    /* Check for empty string */
    if (code_name[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Code name cannot be empty");
        }
        return -1;
    }

    /* Check for leading whitespace */
    if (isspace((unsigned char)code_name[0])) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Code name cannot have leading whitespace");
        }
        return -1;
    }

    /* Check for trailing whitespace */
    size_t len = strlen(code_name);
    if (len > 0 && isspace((unsigned char)code_name[len - 1])) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Code name cannot have trailing whitespace");
        }
        return -1;
    }

    /* Check length limit */
    if (len > 100) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Code name cannot exceed 100 characters");
        }
        return -1;
    }

    /* Check for control characters */
    for (const char *p = code_name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Code name contains invalid control character (0x%02X)", c);
            }
            return -1;
        }
    }

    if (!utf8_ok(code_name, "Code name", error_msg, error_len)) return -1;

    return 0;  /* Valid */
}

int validate_display_name(const char *display_name, char *error_msg, size_t error_len) {
    if (!display_name) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Display name is NULL");
        }
        return -1;
    }

    if (display_name[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Display name cannot be empty");
        }
        return -1;
    }

    if (strlen(display_name) > 200) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Display name cannot exceed 200 characters");
        }
        return -1;
    }

    /* Check for control characters */
    for (const char *p = display_name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Display name contains invalid control character (0x%02X)", c);
            }
            return -1;
        }
    }

    if (!utf8_ok(display_name, "Display name", error_msg, error_len)) return -1;

    return 0;
}

int validate_note(const char *note, char *error_msg, size_t error_len) {
    if (!note) {
        return 0;  /* NULL is allowed */
    }

    if (strlen(note) > 2000) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Note cannot exceed 2000 characters");
        }
        return -1;
    }

    /* Check for control characters (allow \n and \t in notes) */
    for (const char *p = note; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 && c != '\n' && c != '\t') {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Note contains invalid control character (0x%02X)", c);
            }
            return -1;
        }
        if (c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "Note contains invalid control character (0x7F)");
            }
            return -1;
        }
    }

    if (!utf8_ok(note, "Note", error_msg, error_len)) return -1;

    return 0;
}

int validate_url_field(const char *url, const char *field_name,
                       char *error_msg, size_t error_len) {
    const char *name = field_name ? field_name : "URL";

    if (!url) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "%s is required", name);
        }
        return -1;
    }

    if (url[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "%s cannot be empty", name);
        }
        return -1;
    }

    if (strlen(url) > 2000) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "%s cannot exceed 2000 characters", name);
        }
        return -1;
    }

    /* Reject control characters (prevents header injection) */
    for (const char *p = url; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "%s contains invalid control character (0x%02X)", name, c);
            }
            return -1;
        }
    }

    return 0;
}

int validate_scope(const char *scope, char *error_msg, size_t error_len) {
    if (!scope) {
        return 0;  /* NULL means "no scope requested" - allowed */
    }

    if (scope[0] == '\0') {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Scope cannot be empty string");
        }
        return -1;
    }

    size_t len = strlen(scope);
    if (len > 250) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Scope cannot exceed 250 characters");
        }
        return -1;
    }

    /*
     * RFC 6749 Section 3.3:
     *   scope       = scope-token *( SP scope-token )
     *   scope-token = 1*NQCHAR
     *   NQCHAR      = %x21 / %x23-5B / %x5D-7E
     *
     * This explicitly excludes: space (0x20, separator only), " (0x22),
     * \ (0x5C), control characters (0x00-0x1F), and DEL/high bytes (0x7F+).
     */
    int in_token = 0;
    for (const char *p = scope; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == ' ') {
            if (!in_token) {
                /* Leading space or consecutive spaces */
                if (error_msg && error_len > 0) {
                    snprintf(error_msg, error_len,
                             "Scope has invalid whitespace (leading, trailing, or consecutive spaces)");
                }
                return -1;
            }
            in_token = 0;
        } else if (c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)) {
            /* Valid NQCHAR */
            in_token = 1;
        } else {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len,
                         "Scope contains invalid character (0x%02X); "
                         "only printable ASCII except '\"' and '\\' are allowed", c);
            }
            return -1;
        }
    }

    if (!in_token) {
        /* Trailing space */
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len,
                     "Scope has invalid whitespace (leading, trailing, or consecutive spaces)");
        }
        return -1;
    }

    return 0;  /* Valid */
}

int validate_redirect_uri(const char *uri, char *error_msg, size_t error_len) {
    if (validate_url_field(uri, "Redirect URI", error_msg, error_len) != 0) {
        return -1;
    }

    /* Stricter length limit than generic URLs: the redirect URI is carried inside the
     * stateless authorization code, so it must fit auth_request_claims_t.redirect_uri
     * (char[512], include/crypto/jwt.h). 500 leaves room for the NUL and a little slack.
     * The 2000-byte ck_client_redirect_uri_len constraint in the schema is a backstop
     * behind this, not the operative limit. */
    if (strlen(uri) > 500) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Redirect URI cannot exceed 500 characters");
        }
        return -1;
    }

    if (strncasecmp(uri, "http://", 7) != 0 &&
        strncasecmp(uri, "https://", 8) != 0) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len,
                     "Redirect URI must use http or https scheme");
        }
        return -1;
    }

    /* RFC 6749 3.1.2: no fragment. The code is appended as a query, and after a
     * '#' it would land inside the fragment instead. */
    if (strchr(uri, '#')) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Redirect URI must not contain a fragment (#)");
        }
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Patterns, for values created or set
 * ========================================================================== */

/* The defaults when a pattern isn't set. An address takes one conservative
 * real-world shape: letters, digits and . _ + - before the @, with no dot
 * leading, trailing or doubled; then dotted labels of letters, digits and inner
 * hyphens, ending in an alphabetic or an xn-- top-level domain. A username or
 * code name takes the shape of that local part ("whatever is valid in an email,
 * except the @"). Passwords and machine secrets have none. */
#define NAME_DEFAULT "[A-Za-z0-9_+-]+(\\.[A-Za-z0-9_+-]+)*"
#define LABEL "[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
#define EMAIL_DEFAULT NAME_DEFAULT "@" LABEL "(\\." LABEL ")*\\.([A-Za-z]{2,}|xn--[A-Za-z0-9-]+)"

typedef enum {
    PATTERN_USERNAME, PATTERN_EMAIL, PATTERN_CODE_NAME, PATTERN_PASSWORD,
    PATTERN_MACHINE_SECRET, PATTERN_COUNT
} pattern_t;

static struct {
    const char *setting;       /* its auth.conf key */
    const char *what;          /* the value, in messages */
    const char *fallback;      /* the default pattern, or NULL for none */
    const char *fallback_rule; /* what the default asks for, when it refuses */
    regex_t re;
    int active;                /* a pattern applies */
    int is_default;            /* ... and it's the fallback */
} g_patterns[PATTERN_COUNT] = {
    [PATTERN_USERNAME] = { "username_pattern", "Username", NAME_DEFAULT,
        "Username may contain only letters, digits and . _ + -, with no dot first, last or doubled" },
    [PATTERN_EMAIL] = { "email_pattern", "Email", EMAIL_DEFAULT,
        "Email must look like name@example.com: letters, digits and . _ + - before the @, "
        "and a domain after it" },
    [PATTERN_CODE_NAME] = { "code_name_pattern", "Code name", NAME_DEFAULT,
        "Code name may contain only letters, digits and . _ + -, with no dot first, last or doubled" },
    [PATTERN_PASSWORD] = { "password_pattern", "Password", NULL, NULL },
    [PATTERN_MACHINE_SECRET] = { "machine_secret_pattern", "Secret", NULL, NULL },
};

static int g_patterns_ready = 0;

void validation_cleanup(void) {
    for (int i = 0; i < PATTERN_COUNT; i++) {
        if (g_patterns[i].active) regfree(&g_patterns[i].re);
        g_patterns[i].active = 0;
        g_patterns[i].is_default = 0;
    }
    g_patterns_ready = 0;
}

int validation_init(const validation_patterns_t *patterns) {
    validation_cleanup();
    const char *configured[PATTERN_COUNT] = {
        patterns ? patterns->username : NULL,
        patterns ? patterns->email : NULL,
        patterns ? patterns->code_name : NULL,
        patterns ? patterns->password : NULL,
        patterns ? patterns->machine_secret : NULL,
    };

    for (int i = 0; i < PATTERN_COUNT; i++) {
        const char *pattern = configured[i] ? configured[i] : g_patterns[i].fallback;
        if (!pattern || pattern[0] == '\0') continue;  /* none */

        /* The whole value has to match, not some part of it */
        size_t size = strlen(pattern) + 5;
        char *anchored = malloc(size);
        if (!anchored) {
            log_error("Out of memory compiling %s", g_patterns[i].setting);
            validation_cleanup();
            return -1;
        }
        snprintf(anchored, size, "^(%s)$", pattern);
        int rc = regcomp(&g_patterns[i].re, anchored, REG_EXTENDED | REG_NOSUB);
        free(anchored);
        if (rc != 0) {
            char reason[128];
            regerror(rc, &g_patterns[i].re, reason, sizeof(reason));
            log_error("%s is not a valid pattern (POSIX extended): %s", g_patterns[i].setting, reason);
            validation_cleanup();
            return -1;
        }
        g_patterns[i].active = 1;
        g_patterns[i].is_default = !configured[i];
    }

    g_patterns_ready = 1;
    return 0;
}

/* The pattern for this kind of value, if one applies */
static int pattern_ok(pattern_t which, const char *value, char *error_msg, size_t error_len) {
    if (!g_patterns_ready) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Validation patterns are not initialized");
        }
        log_error("validate_new_* called before validation_init");
        return 0;
    }
    if (!g_patterns[which].active || regexec(&g_patterns[which].re, value, 0, NULL, 0) == 0) {
        return 1;
    }
    if (error_msg && error_len > 0) {
        if (g_patterns[which].is_default) {
            snprintf(error_msg, error_len, "%s", g_patterns[which].fallback_rule);
        } else {
            snprintf(error_msg, error_len, "%s doesn't match this server's %s",
                     g_patterns[which].what, g_patterns[which].setting);
        }
    }
    return 0;
}

/* No C1 control characters (U+0080 to U+009F, C2 80 to C2 9F in UTF-8) in a
 * new value, whatever the pattern lets through: invisible, and nothing types them */
static int no_c1(const char *value, const char *what, char *error_msg, size_t error_len) {
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (p[0] == 0xC2 && p[1] >= 0x80 && p[1] <= 0x9F) {
            if (error_msg && error_len > 0) {
                snprintf(error_msg, error_len, "%s contains a control character (U+%04X)",
                         what, (unsigned)p[1]);
            }
            return 0;
        }
    }
    return 1;
}

int validate_new_username(const char *username, char *error_msg, size_t error_len) {
    if (validate_username(username, error_msg, error_len) != 0) return -1;
    if (!no_c1(username, "Username", error_msg, error_len)) return -1;
    return pattern_ok(PATTERN_USERNAME, username, error_msg, error_len) ? 0 : -1;
}

int validate_new_email(const char *email, char *error_msg, size_t error_len) {
    if (validate_email(email, error_msg, error_len) != 0) return -1;
    if (!no_c1(email, "Email", error_msg, error_len)) return -1;
    if (!pattern_ok(PATTERN_EMAIL, email, error_msg, error_len)) return -1;

    /* The default's shape stops short of RFC 5321's limit on the local part */
    if (g_patterns[PATTERN_EMAIL].is_default && strchr(email, '@') - email > 64) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Email can have at most 64 characters before the @");
        }
        return -1;
    }
    return 0;
}

int validate_new_code_name(const char *code_name, char *error_msg, size_t error_len) {
    if (validate_code_name(code_name, error_msg, error_len) != 0) return -1;
    if (!no_c1(code_name, "Code name", error_msg, error_len)) return -1;
    return pattern_ok(PATTERN_CODE_NAME, code_name, error_msg, error_len) ? 0 : -1;
}

int validate_new_password(const char *password, char *error_msg, size_t error_len) {
    if (!password) {
        if (error_msg && error_len > 0) snprintf(error_msg, error_len, "Password is required");
        return -1;
    }
    return pattern_ok(PATTERN_PASSWORD, password, error_msg, error_len) ? 0 : -1;
}

int validate_new_machine_secret(const char *secret, char *error_msg, size_t error_len) {
    if (!secret) {
        if (error_msg && error_len > 0) snprintf(error_msg, error_len, "Secret is required");
        return -1;
    }
    return pattern_ok(PATTERN_MACHINE_SECRET, secret, error_msg, error_len) ? 0 : -1;
}
