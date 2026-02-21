#ifndef VALIDATION_H
#define VALIDATION_H

#include <stddef.h>

/*
 * validate_username - Validate username format
 *
 * Rules:
 *   - Not empty string
 *   - No spaces
 *   - No @ symbol
 *
 * Parameters:
 *   username   - Username to validate
 *   error_msg  - Output buffer for error message (if validation fails)
 *   error_len  - Size of error_msg buffer
 *
 * Returns:
 *   0 on success (valid username)
 *   -1 on failure (invalid username, error_msg populated)
 */
int validate_username(const char *username, char *error_msg, size_t error_len);

/*
 * validate_email - Validate email format
 *
 * Rules:
 *   - Exactly one @ symbol
 *   - At least one character before @
 *   - At least one character after @
 *   - No spaces
 *
 * Parameters:
 *   email      - Email address to validate
 *   error_msg  - Output buffer for error message (if validation fails)
 *   error_len  - Size of error_msg buffer
 *
 * Returns:
 *   0 on success (valid email)
 *   -1 on failure (invalid email, error_msg populated)
 */
int validate_email(const char *email, char *error_msg, size_t error_len);

/*
 * validate_code_name - Validate code_name format
 *
 * Rules:
 *   - Not empty string
 *   - No leading or trailing whitespace
 *
 * Parameters:
 *   code_name  - Code name to validate
 *   error_msg  - Output buffer for error message (if validation fails)
 *   error_len  - Size of error_msg buffer
 *
 * Returns:
 *   0 on success (valid code_name)
 *   -1 on failure (invalid code_name, error_msg populated)
 */
int validate_code_name(const char *code_name, char *error_msg, size_t error_len);

#endif /* VALIDATION_H */
