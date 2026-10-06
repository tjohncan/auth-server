#ifndef VALIDATION_H
#define VALIDATION_H

#include <stddef.h>

/*
 * Two kinds of check for usernames, email addresses and code names:
 *
 * - validate_username, validate_email, validate_code_name: the fixed rules
 *   (length, no control characters, well-formed UTF-8, the shape below). They
 *   run wherever such a value arrives, including values that are only looked
 *   up: an address to send a reset link to, a username to make an org admin.
 *   A value stored before a stricter pattern was set still passes them, so its
 *   account keeps working.
 *
 * - validate_new_username, validate_new_email, validate_new_code_name: the
 *   fixed rules, then the configured pattern (validation_init). Only where a
 *   value is created or set, since patterns never apply to rows already
 *   stored. validate_new_password and validate_new_machine_secret are the same
 *   for secrets, which are only ever set.
 */

/*
 * The patterns a value created or set must match: auth.conf's username_pattern,
 * email_pattern, code_name_pattern, password_pattern and machine_secret_pattern.
 *
 * Each is POSIX extended syntax, matched against the whole value. NULL means the
 * default: the shape of a real email address for addresses (validate_new_email),
 * its local part for usernames and code names, and none for passwords and
 * machine secrets. An empty string means none.
 */
typedef struct {
    const char *username;
    const char *email;
    const char *code_name;
    const char *password;
    const char *machine_secret;
} validation_patterns_t;

/*
 * validation_init - Compile the patterns, once, at startup
 *
 * Every validate_new_* refuses until this has succeeded, so a server that
 * forgot to call it fails loudly instead of skipping the patterns.
 *
 * Returns: 0, or -1 if a pattern won't compile (logged, naming the setting)
 */
int validation_init(const validation_patterns_t *patterns);

/* validation_cleanup - Free the compiled patterns */
void validation_cleanup(void);

/*
 * validate_username - Fixed rules for a username
 *
 * Rules:
 *   - Not empty, at most 100 bytes
 *   - No control characters, spaces or @
 *   - Well-formed UTF-8
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
 * validate_email - Fixed rules for an email address
 *
 * Rules:
 *   - Not empty, at most 254 bytes (RFC 5321)
 *   - Exactly one @, with at least one character before and after it
 *   - No control characters or spaces
 *   - Well-formed UTF-8
 *
 * Returns: 0 if valid, -1 with error_msg populated
 */
int validate_email(const char *email, char *error_msg, size_t error_len);

/*
 * validate_code_name - Fixed rules for a code name
 *
 * Rules:
 *   - Not empty, at most 100 bytes
 *   - No leading or trailing whitespace, no control characters
 *   - Well-formed UTF-8
 *
 * Returns: 0 if valid, -1 with error_msg populated
 */
int validate_code_name(const char *code_name, char *error_msg, size_t error_len);

/*
 * validate_new_username, validate_new_email, validate_new_code_name - For a
 * value being created or set: the fixed rules, no C1 control characters
 * (U+0080 to U+009F), and the configured pattern. An address under the default
 * pattern also has at most 64 bytes before the @ (RFC 5321).
 *
 * Returns: 0 if valid, -1 with error_msg populated
 */
int validate_new_username(const char *username, char *error_msg, size_t error_len);
int validate_new_email(const char *email, char *error_msg, size_t error_len);
int validate_new_code_name(const char *code_name, char *error_msg, size_t error_len);

/*
 * validate_new_password, validate_new_machine_secret - The configured pattern
 * for a password, or for a secret a caller supplies for a client, resource
 * server or organization key. Nothing else: their lengths are checked where
 * they're hashed, and a secret's characters are its owner's business.
 *
 * Returns: 0 if valid (or no pattern is set), -1 with error_msg populated
 */
int validate_new_password(const char *password, char *error_msg, size_t error_len);
int validate_new_machine_secret(const char *secret, char *error_msg, size_t error_len);

/*
 * validate_display_name - Validate display_name format
 *
 * Rules:
 *   - Not empty string
 *   - Length <= 200 characters
 *   - No control characters; well-formed UTF-8
 */
int validate_display_name(const char *display_name, char *error_msg, size_t error_len);

/*
 * validate_note - Validate note format
 *
 * Rules:
 *   - NULL is allowed (returns 0)
 *   - If non-NULL, length <= 2000 characters
 *   - No control characters but newline and tab; well-formed UTF-8
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
 *   - Length <= 500 characters (must fit in JWT claim buffer)
 */
int validate_redirect_uri(const char *uri, char *error_msg, size_t error_len);

/*
 * validate_scope - Validate OAuth2 scope string (RFC 6749 Section 3.3)
 *
 * Rules:
 *   - NULL is allowed (returns 0, means "no scope requested")
 *   - Empty string is not allowed
 *   - Space-separated tokens, each 1+ characters
 *   - Allowed characters per token: %x21 / %x23-5B / %x5D-7E (NQCHAR)
 *     (printable ASCII except space, double-quote, and backslash)
 *   - No leading, trailing, or consecutive spaces
 *   - Total length <= 250 characters (must fit in JWT claim buffer)
 */
int validate_scope(const char *scope, char *error_msg, size_t error_len);

#endif /* VALIDATION_H */
