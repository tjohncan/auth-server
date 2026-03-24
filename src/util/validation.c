#include "util/validation.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

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

    /* Check for spaces and @ symbol */
    for (const char *p = username; *p; p++) {
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

    /* Find @ symbol and check for spaces */
    const char *at_pos = NULL;
    int at_count = 0;

    for (const char *p = email; *p; p++) {
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
    if (len > 1000) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len, "Scope cannot exceed 1000 characters");
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

    if (strncasecmp(uri, "http://", 7) != 0 &&
        strncasecmp(uri, "https://", 8) != 0) {
        if (error_msg && error_len > 0) {
            snprintf(error_msg, error_len,
                     "Redirect URI must use http or https scheme");
        }
        return -1;
    }

    return 0;
}
