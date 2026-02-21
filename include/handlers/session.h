#ifndef HANDLERS_SESSION_H
#define HANDLERS_SESSION_H

#include "db/db.h"

/*
 * Session Handler Functions
 *
 * Business logic layer for authentication and session management.
 * These handlers coordinate user authentication and browser session lifecycle.
 *
 * All handlers:
 * - Perform input validation
 * - Coordinate multiple query operations
 * - Return 0 on success, -1 on error
 *
 * Note: HTTP layer (JSON parsing, cookie handling) is separate.
 */

/*
 * Authenticate user and create session
 *
 * Validates username/password, creates browser session, generates session token.
 * Session token should be set as HTTP-only cookie by HTTP layer.
 *
 * Parameters:
 *   db                  - Database handle
 *   username            - Username (required)
 *   password            - Password (plaintext, required)
 *   source_ip           - Client IP (optional, can be NULL)
 *   user_agent          - Browser user agent (optional, can be NULL)
 *   session_ttl_seconds - Session lifetime in seconds
 *   out_session_token   - Output: Session token for cookie (caller must free)
 *   out_user_pin        - Output: User PIN (for response/logging)
 *
 * Returns: 0 on success (credentials valid, session created),
 *          -1 on error or invalid credentials
 */
int session_authenticate_and_create(db_handle_t *db,
                                     const char *username,
                                     const char *password,
                                     const char *source_ip,
                                     const char *user_agent,
                                     int session_ttl_seconds,
                                     char **out_session_token,
                                     long long *out_user_pin);

#endif /* HANDLERS_SESSION_H */
