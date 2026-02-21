#include "util/validation.h"
#include <string.h>
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

    return 0;  /* Valid */
}
