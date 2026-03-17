#ifndef HANDLERS_RS_H
#define HANDLERS_RS_H

#include "db/db.h"
#include "db/queries/user.h"
#include "db/queries/resource_server.h"

/*
 * Resource Server Provisioning Handler Functions
 *
 * Business logic layer for RS user provisioning API.
 * These handlers coordinate identity matching, user creation,
 * invitation tokens, and client-user link management.
 *
 * All endpoints require RS key authentication (handled by HTTP layer)
 * and allow_user_provisioning=1 on the resource server.
 *
 * Note: HTTP layer (JSON parsing, response formatting, email sending)
 * is separate.
 */

/* User info returned by provision and lookup operations */
typedef struct {
    unsigned char user_id[16];
    char username[256];
    int is_active;
    user_email_t *emails;       /* Array (caller must free) */
    int email_count;
    int was_created;            /* 1 if user was newly created */
    char invitation_token[44];  /* Token string (empty if not created) */
} rs_user_info_t;

/*
 * Free dynamic fields in rs_user_info_t
 */
void rs_user_info_free(rs_user_info_t *info);

/*
 * Find-or-create user + generate invitation
 *
 * If user exists (by username or verified email): returns user info.
 * If user doesn't exist: creates user (no password), creates invitation token.
 * At least one of username or email required.
 *
 * Parameters:
 *   db             - Database handle
 *   rs_pin         - Authenticated resource server PIN
 *   username       - Username (can be NULL if email provided)
 *   email          - Email address (can be NULL if username provided)
 *   invitation_ttl - Invitation token TTL in seconds
 *   source_ip      - Client IP for audit trail
 *   out_info       - Output: user info (caller must call rs_user_info_free)
 *
 * Returns: 0 success, 1 provisioning not allowed, 2 ambiguous match, -1 error
 */
int rs_handler_provision_user(db_handle_t *db, long long rs_pin,
                               const char *username, const char *email,
                               int invitation_ttl, const char *source_ip,
                               rs_user_info_t *out_info);

/*
 * Look up user without creating
 *
 * Preferred: lookup by user_id. Fallback: username and/or email.
 * At least one identifier required.
 *
 * Parameters:
 *   db       - Database handle
 *   rs_pin   - Authenticated resource server PIN
 *   user_id  - User UUID (16 bytes, can be NULL)
 *   username - Username (can be NULL)
 *   email    - Email address (can be NULL)
 *   out_info - Output: user info (caller must call rs_user_info_free)
 *
 * Returns: 0 found, 1 not found, 2 ambiguous, 3 not allowed, -1 error
 */
int rs_handler_lookup_user(db_handle_t *db, long long rs_pin,
                            const unsigned char *user_id,
                            const char *username, const char *email,
                            rs_user_info_t *out_info);

/*
 * Link user to client (idempotent)
 *
 * Scope: client must be linked to this RS via client_resource_server.
 *
 * Returns: 0 success, 1 not allowed, 2 client not in scope, 3 user not found, -1 error
 */
int rs_handler_link_client_user(db_handle_t *db, long long rs_pin,
                                 const unsigned char *client_id,
                                 const unsigned char *user_id);

/*
 * Unlink user from client (idempotent)
 *
 * Scope: client must be linked to this RS via client_resource_server.
 *
 * Returns: 0 success, 1 not allowed, 2 client not in scope, -1 error
 */
int rs_handler_unlink_client_user(db_handle_t *db, long long rs_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *user_id);

/*
 * List users linked to client
 *
 * Scope: client must be linked to this RS via client_resource_server.
 *
 * Returns: 0 success, 1 not allowed, 2 client not in scope, -1 error
 */
int rs_handler_list_client_users(db_handle_t *db, long long rs_pin,
                                  const unsigned char *client_id,
                                  int limit, int offset,
                                  rs_client_user_t **out_users,
                                  int *out_count, int *out_total);

#endif /* HANDLERS_RS_H */
