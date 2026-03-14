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
 *   - Length <= 100 characters
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

/*
 * validate_display_name - Validate display_name format
 *
 * Rules:
 *   - Not empty string
 *   - Length <= 200 characters
 */
int validate_display_name(const char *display_name, char *error_msg, size_t error_len);

/*
 * validate_note - Validate note format
 *
 * Rules:
 *   - NULL is allowed (returns 0)
 *   - If non-NULL, length <= 2000 characters
 */
int validate_note(const char *note, char *error_msg, size_t error_len);

/*
 * validate_url_field - Validate URL field (address, redirect_uri)
 *
 * Rules:
 *   - Not empty string
 *   - Length <= 2000 characters
 *
 * Parameters:
 *   url        - URL to validate
 *   field_name - Field name for error messages (e.g., "Address", "Redirect URI")
 *   error_msg  - Output buffer for error message
 *   error_len  - Size of error_msg buffer
 */
int validate_url_field(const char *url, const char *field_name,
                       char *error_msg, size_t error_len);

/*
 * validate_redirect_uri - Validate OAuth2 redirect URI
 *
 * Rules:
 *   - All validate_url_field rules apply
 *   - Scheme must be http:// or https://
 */
int validate_redirect_uri(const char *uri, char *error_msg, size_t error_len);

#endif /* VALIDATION_H */
