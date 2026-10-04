#include "handlers/rs.h"
#include "util/log.h"

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

void rs_user_info_free(rs_user_info_t *info) {
    if (!info) return;
    if (info->emails) {
        free(info->emails);
        info->emails = NULL;
    }
    OPENSSL_cleanse(info->invitation_token, sizeof(info->invitation_token));
}

/* Populate rs_user_info_t from user_identity_t + fetch emails */
static int populate_user_info(db_handle_t *db, const user_identity_t *match,
                               rs_user_info_t *out) {
    memcpy(out->user_id, match->user_id, 16);
    snprintf(out->username, sizeof(out->username), "%s", match->username);
    out->is_active = match->is_active;

    if (user_get_emails(db, match->user_account_pin, 100, 0,
                         &out->emails, &out->email_count, NULL) != 0) {
        log_error("Failed to get emails for user");
        return -1;
    }

    return 0;
}

int rs_handler_provision_user(db_handle_t *db, long long rs_pin,
                               const char *username, const char *email,
                               int invitation_ttl, const char *source_ip,
                               rs_user_info_t *out_info) {
    if (!db || (!username && !email) || !out_info) {
        log_error("Invalid arguments to rs_handler_provision_user");
        return -1;
    }

    int allowed = resource_server_provisioning_allowed(db, rs_pin);
    if (allowed != 1) {
        if (allowed == 0) log_info("User provisioning not enabled for resource server");
        return (allowed == 0) ? 1 : -1;
    }

    memset(out_info, 0, sizeof(*out_info));

    /* Find existing user by identity */
    user_identity_t match;
    int rc = user_find_by_identity(db, username, email, &match);
    if (rc == -1) return -1;
    if (rc == 2) return 2;  /* ambiguous */

    /* An account provisioned for this address that hasn't accepted its
     * invitation holds the address unverified, which the match above doesn't
     * look at. By email alone, that account is the person; with a username,
     * it's them if the username found it too. Either way they're invited again,
     * rather than a second account made for the same address. */
    long long pending_email_pin = 0;
    int invite_again = 0;
    if (email) {
        user_identity_t pending;
        int pending_rc = user_find_pending_by_email(db, email, &pending, &pending_email_pin);
        if (pending_rc == -1) return -1;
        if (pending_rc == 0 && rc == 1 && !username) {
            match = pending;
            rc = 0;
            invite_again = 1;
        } else if (pending_rc == 0 && rc == 0 &&
                   pending.user_account_pin == match.user_account_pin) {
            invite_again = 1;
        }
    }

    if (rc == 0) {
        /* User found — return info, and a fresh invitation if still pending */
        out_info->was_created = 0;
        if (populate_user_info(db, &match, out_info) != 0) return -1;

        /* Not for a deactivated account: nothing a resource server does brings
           one back. A 1 is the hourly limit, and means no invitation this time. */
        if (invite_again && match.is_active &&
            user_create_invitation_token(db, match.user_account_pin, pending_email_pin,
                                         invitation_ttl, source_ip,
                                         out_info->invitation_token) == -1) {
            return -1;
        }
        return 0;
    }

    /* User not found — create without password */
    long long user_pin = 0;
    unsigned char user_id[16];
    long long email_pin = 0;

    if (user_create_no_password(db, username, email,
                                 &user_pin, user_id, &email_pin) != 0) {
        log_error("Failed to create user for RS provisioning");
        return -1;
    }

    memcpy(out_info->user_id, user_id, 16);
    if (username)
        snprintf(out_info->username, sizeof(out_info->username), "%s", username);
    out_info->is_active = 1;
    out_info->was_created = 1;

    /* Create invitation token */
    if (user_create_invitation_token(db, user_pin, email_pin,
                                      invitation_ttl, source_ip,
                                      out_info->invitation_token) != 0) {
        log_error("Failed to create invitation token for new user");
        return -1;
    }

    /* Fetch emails for newly created user */
    if (email) {
        if (user_get_emails(db, user_pin, 100, 0,
                             &out_info->emails, &out_info->email_count, NULL) != 0) {
            log_error("Failed to get emails for new user");
            return -1;
        }
    }

    return 0;
}

int rs_handler_lookup_user(db_handle_t *db, long long rs_pin,
                            const unsigned char *user_id,
                            const char *username, const char *email,
                            rs_user_info_t *out_info) {
    if (!db || (!user_id && !username && !email) || !out_info) {
        log_error("Invalid arguments to rs_handler_lookup_user");
        return -1;
    }

    int allowed = resource_server_provisioning_allowed(db, rs_pin);
    if (allowed != 1) {
        if (allowed == 0) log_info("User provisioning not enabled for resource server");
        return (allowed == 0) ? 3 : -1;
    }

    memset(out_info, 0, sizeof(*out_info));

    user_identity_t match;

    if (user_id) {
        int rc = user_get_by_id(db, user_id, &match);
        if (rc == 1) return 1;  /* not found */
        if (rc != 0) return -1;
    } else {
        int rc = user_find_by_identity(db, username, email, &match);
        if (rc == 1) return 1;  /* not found */
        if (rc == 2) return 2;  /* ambiguous */
        if (rc != 0) return -1;
    }

    return populate_user_info(db, &match, out_info);
}

/* Shared provisioning + client scope check for client-user operations */
static int check_provisioning_and_scope(db_handle_t *db, long long rs_pin,
                                         const unsigned char *client_id,
                                         long long *out_client_pin) {
    int allowed = resource_server_provisioning_allowed(db, rs_pin);
    if (allowed != 1) {
        if (allowed == 0) log_info("User provisioning not enabled for resource server");
        return (allowed == 0) ? 1 : -1;
    }

    int rc = rs_resolve_client(db, rs_pin, client_id, out_client_pin);
    if (rc == 1) {
        log_info("Client not linked to resource server");
        return 2;
    }
    if (rc != 0) return -1;

    return 0;
}

int rs_handler_link_client_user(db_handle_t *db, long long rs_pin,
                                 const unsigned char *client_id,
                                 const unsigned char *user_id) {
    if (!db || !client_id || !user_id) {
        log_error("Invalid arguments to rs_handler_link_client_user");
        return -1;
    }

    long long client_pin;
    int rc = check_provisioning_and_scope(db, rs_pin, client_id, &client_pin);
    if (rc != 0) return rc;

    rc = rs_client_user_link(db, client_pin, user_id);
    if (rc == 1) return 3;  /* user not found */
    return rc;
}

int rs_handler_unlink_client_user(db_handle_t *db, long long rs_pin,
                                   const unsigned char *client_id,
                                   const unsigned char *user_id) {
    if (!db || !client_id || !user_id) {
        log_error("Invalid arguments to rs_handler_unlink_client_user");
        return -1;
    }

    long long client_pin;
    int rc = check_provisioning_and_scope(db, rs_pin, client_id, &client_pin);
    if (rc != 0) return rc;

    return rs_client_user_unlink(db, client_pin, user_id);
}

int rs_handler_list_client_users(db_handle_t *db, long long rs_pin,
                                  const unsigned char *client_id,
                                  int limit, int offset,
                                  rs_client_user_t **out_users,
                                  int *out_count, int *out_total) {
    if (!db || !client_id || !out_users || !out_count) {
        log_error("Invalid arguments to rs_handler_list_client_users");
        return -1;
    }

    long long client_pin;
    int rc = check_provisioning_and_scope(db, rs_pin, client_id, &client_pin);
    if (rc != 0) return rc;

    return rs_client_user_list(db, client_pin, limit, offset,
                                out_users, out_count, out_total);
}
