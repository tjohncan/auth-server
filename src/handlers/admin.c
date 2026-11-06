#include "handlers/admin.h"
#include "db/db_sql.h"
#include "db/queries/org.h"
#include "db/queries/client.h"
#include "db/queries/resource_server.h"
#include "db/queries/user.h"
#include "util/log.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * BOOTSTRAP
 * ========================================================================== */

int admin_bootstrap(db_handle_t *db,
                   const config_t *config,
                   const char *org_code_name,
                   const char *org_display_name,
                   const char *username,
                   const char *password) {
    if (!db || !config || !org_code_name || !org_display_name ||
        !username || !password) {
        log_error("Invalid arguments to admin_bootstrap");
        return -1;
    }

    /* Pre-flight check: organization must not exist */
    int org_ex = org_exists(db, org_code_name);
    if (org_ex < 0) {
        return -1;
    } else if (org_ex == 1) {
        log_error("Bootstrap failed: organization '%s' already exists", org_code_name);
        return -1;
    }

    /* Pre-flight check: username must not exist */
    int user_ex = user_username_exists(db, username);
    if (user_ex < 0) {
        return -1;
    } else if (user_ex == 1) {
        log_error("Bootstrap failed: the username already exists");
        return -1;
    }

    /* Management API address and redirect URI, at the server's public address */
    char mgmt_api_address[256];
    char mgmt_ui_redirect[256];
    snprintf(mgmt_api_address, sizeof(mgmt_api_address), "%s/api", config->public_base_url);
    snprintf(mgmt_ui_redirect, sizeof(mgmt_ui_redirect), "%s/callback", config->public_base_url);

    /* Every write or none. A failure part-way would leave an organization behind,
       and a retry would answer "Organization already exists" until it was removed
       by hand. None of the steps opens a transaction of its own: user_create does
       only for an email address, and bootstrap gives none. The admin password is
       hashed inside, once per bootstrap. */
    if (db_execute_trusted(db, BEGIN_WRITE) != 0) {
        log_error("Bootstrap failed: could not begin a transaction");
        return -1;
    }

    /* Create organization */
    long long org_pin;
    if (org_create(db, org_code_name, org_display_name, "Management API + UI", &org_pin, NULL) != 0) {
        log_error("Bootstrap failed: could not create organization");
        goto rollback;
    }

    /* Create management API resource server */
    long long mgmt_api_pin;
    if (resource_server_create_bootstrap(db, org_code_name, "management_api",
                                          "Management API", mgmt_api_address,
                                          "OAuth2 resource server for management operations",
                                          &mgmt_api_pin) != 0) {
        log_error("Bootstrap failed: could not create management API resource server");
        goto rollback;
    }

    /* Create management UI client (public, universal, authorization_code) */
    unsigned char mgmt_ui_id[16];
    long long mgmt_ui_pin;
    if (client_create_bootstrap(db, org_code_name, "management_ui",
                                 "Management UI", "public", "authorization_code",
                                 "Universal public client for management interface",
                                 0,      /* require_mfa = false */
                                 3600,   /* access_token_ttl_seconds = 1 hour */
                                 1,      /* issue_refresh_tokens = true */
                                 86400,  /* refresh_token_ttl_seconds = 24 hours */
                                 -1,     /* maximum_session_seconds = NULL (no limit) */
                                 -1,     /* secret_rotation_seconds = NULL (not applicable for public) */
                                 1,      /* is_universal = true */
                                 mgmt_ui_id, &mgmt_ui_pin) != 0) {
        log_error("Bootstrap failed: could not create management UI client");
        goto rollback;
    }

    /* Add redirect URI for management UI */
    if (admin_add_client_redirect_uri_bootstrap(db, mgmt_ui_id, mgmt_ui_redirect, "Default callback") != 0) {
        log_error("Bootstrap failed: could not add redirect URI");
        goto rollback;
    }

    /* Link management UI client to management API resource server */
    if (admin_link_client_resource_server_bootstrap(db, org_code_name, mgmt_ui_id, mgmt_api_address) != 0) {
        log_error("Bootstrap failed: could not link client to resource server");
        goto rollback;
    }

    /* Create first admin user (email can be added later via user profile) */
    unsigned char user_id[16];
    if (user_create(db, username, NULL, password, user_id) != 0) {
        log_error("Bootstrap failed: could not create admin user");
        goto rollback;
    }

    /* Make user admin of organization */
    if (user_make_org_admin(db, user_id, org_code_name) != 0) {
        log_error("Bootstrap failed: could not grant org admin privileges");
        goto rollback;
    }

    if (db_execute_trusted(db, "COMMIT") != 0) {
        log_error("Bootstrap failed: could not commit");
        goto rollback;
    }

    log_info("Bootstrap complete: org='%s', user='%s'", org_code_name, username);
    return 0;

rollback:
    db_execute_trusted(db, "ROLLBACK");
    return -1;
}

/* ============================================================================
 * ORGANIZATION OPERATIONS
 * ========================================================================== */

int admin_create_organization(db_handle_t *db,
                              const char *code_name,
                              const char *display_name,
                              const char *note,
                              unsigned char *out_id) {
    if (!db || !code_name || !display_name) {
        log_error("Invalid arguments to admin_create_organization");
        return -1;
    }

    /* Check if organization already exists */
    int exists = org_exists(db, code_name);
    if (exists < 0) {
        return -1;
    } else if (exists == 1) {
        log_info("Organization already exists: code_name='%s'", code_name);
        return -1;
    }

    /* Create organization */
    long long org_pin;
    if (org_create(db, code_name, display_name, note, &org_pin, out_id) != 0) {
        log_error("Failed to create organization");
        return -1;
    }

    return 0;
}

int admin_list_organizations(db_handle_t *db, long long user_account_pin,
                             long long organization_key_pin,
                             int limit, int offset,
                             const int *filter_is_active,
                             admin_organization_t **out_orgs, int *out_count,
                             int *out_total) {
    if (!db || !out_orgs || !out_count) {
        log_error("Invalid arguments to admin_list_organizations");
        return -1;
    }

    /* Call query layer */
    org_data_t *orgs = NULL;
    int count = 0;

    if (org_list_all(db, user_account_pin, organization_key_pin, limit, offset, filter_is_active, &orgs, &count, out_total) != 0) {
        return -1;
    }

    *out_orgs = orgs;
    *out_count = count;

    return 0;
}

int admin_get_organization(db_handle_t *db, long long user_account_pin,
                           long long organization_key_pin,
                           const unsigned char *org_id,
                           admin_organization_t *out_org) {
    if (!db || !org_id || !out_org) {
        log_error("Invalid arguments to admin_get_organization");
        return -1;
    }

    /* Call query layer */
    org_data_t org;
    if (org_get_by_id(db, org_id, user_account_pin, organization_key_pin, &org) != 0) {
        return -1;
    }

    /* org_data_t and admin_organization_t have identical layout */
    memcpy(out_org, &org, sizeof(org));

    return 0;
}

int admin_update_organization(db_handle_t *db, long long user_account_pin,
                              long long organization_key_pin,
                              const unsigned char *org_id,
                              const char *display_name,
                              const char *note,
                              const int *is_active) {
    if (!db || !org_id) {
        log_error("Invalid arguments to admin_update_organization");
        return -1;
    }

    /* At least one field must be updated */
    if (!display_name && !note && !is_active) {
        log_error("No fields to update in admin_update_organization");
        return -1;
    }

    /* Verify organization exists and caller is authorized */
    admin_organization_t existing;
    if (admin_get_organization(db, user_account_pin, organization_key_pin, org_id, &existing) != 0) {
        return -1;
    }

    /* Call query layer */
    if (org_update(db, org_id, user_account_pin, organization_key_pin, display_name, note, is_active) != 0) {
        return -1;
    }

    return 0;
}

int admin_list_resource_servers(db_handle_t *db, long long user_account_pin,
                                 long long organization_key_pin,
                                 const unsigned char *organization_id,
                                 int limit, int offset,
                                 const int *filter_is_active,
                                 admin_resource_server_t **out_servers,
                                 int *out_count,
                                 int *out_total) {
    if (!db || !organization_id || !out_servers || !out_count) {
        log_error("Invalid arguments to admin_list_resource_servers");
        return -1;
    }

    resource_server_data_t *servers = NULL;
    int count = 0;

    if (resource_server_list_all(db, user_account_pin, organization_key_pin, organization_id, limit, offset, filter_is_active, &servers, &count, out_total) != 0) {
        return -1;
    }

    *out_servers = servers;
    *out_count = count;

    return 0;
}

int admin_get_resource_server(db_handle_t *db, long long user_account_pin,
                               long long organization_key_pin,
                               const unsigned char *server_id,
                               admin_resource_server_t *out_server) {
    if (!db || !server_id || !out_server) {
        log_error("Invalid arguments to admin_get_resource_server");
        return -1;
    }

    resource_server_data_t server;
    if (resource_server_get_by_id(db, server_id, user_account_pin, organization_key_pin, &server) != 0) {
        return -1;
    }

    memcpy(out_server, &server, sizeof(server));

    return 0;
}

int admin_update_resource_server(db_handle_t *db, long long user_account_pin,
                                  long long organization_key_pin,
                                  const unsigned char *server_id,
                                  const char *display_name,
                                  const char *address,
                                  const char *note,
                                  const int *is_active,
                                  const int *allow_user_provisioning) {
    if (!db || !server_id) {
        log_error("Invalid arguments to admin_update_resource_server");
        return -1;
    }

    if (!display_name && !address && !note && !is_active && !allow_user_provisioning) {
        log_error("No fields to update in admin_update_resource_server");
        return -1;
    }

    /* Verify resource server exists and caller is authorized */
    admin_resource_server_t existing;
    if (admin_get_resource_server(db, user_account_pin, organization_key_pin, server_id, &existing) != 0) {
        return -1;
    }

    /* One active server per address and per code name in an organization.
       Checked here, against the row as it stands, so a clash is answered and
       the update isn't sent. Only a server becoming active, or an active one
       moving to another address, can clash: a deactivated server keeps an
       address an active one has taken, and its other edits still save. */
    int will_be_active = is_active ? (*is_active != 0) : existing.is_active;
    const char *will_have_address = address ? address : existing.address;
    if (will_be_active &&
        (!existing.is_active || strcmp(will_have_address, existing.address) != 0)) {
        int clash = resource_server_active_clash(db, existing.organization_pin, existing.pin,
                                                 will_have_address, existing.code_name);
        if (clash != 0) {
            if (clash > 0) {
                log_info("Resource server update refused: another active server has its %s",
                         clash == 1 ? "address" : "code name");
            }
            return clash;
        }
    }

    if (resource_server_update(db, server_id, user_account_pin, organization_key_pin, display_name, address, note, is_active, allow_user_provisioning) != 0) {
        return -1;
    }

    return 0;
}

int admin_list_clients(db_handle_t *db, long long user_account_pin,
                       long long organization_key_pin,
                       const unsigned char *organization_id,
                       int limit, int offset,
                       const int *filter_is_active,
                       admin_client_t **out_clients,
                       int *out_count,
                       int *out_total) {
    if (!db || !organization_id || !out_clients || !out_count) {
        log_error("Invalid arguments to admin_list_clients");
        return -1;
    }

    client_data_t *clients = NULL;
    int count = 0;

    if (client_list_all(db, user_account_pin, organization_key_pin, organization_id, limit, offset, filter_is_active, &clients, &count, out_total) != 0) {
        return -1;
    }

    *out_clients = clients;
    *out_count = count;

    return 0;
}

int admin_create_resource_server(db_handle_t *db, long long user_account_pin,
                                   long long organization_key_pin,
                                   const unsigned char *organization_id,
                                   const char *code_name,
                                   const char *display_name,
                                   const char *address,
                                   const char *note,
                                   unsigned char *out_id) {
    if (!db || !organization_id || !code_name || !display_name || !address || !out_id) {
        log_error("Invalid arguments to admin_create_resource_server");
        return -1;
    }

    /* Checked here, so a refusal is answered and the INSERT isn't sent: the
       organization, which the caller must administer, and one active server per
       address and per code name in it */
    org_data_t org;
    int found = org_get_by_id(db, organization_id, user_account_pin, organization_key_pin, &org);
    if (found != 0) {
        if (found > 0) {
            log_info("Resource server creation refused: organization not found, or not the caller's");
            return 3;
        }
        return -1;
    }
    int clash = resource_server_active_clash(db, org.pin, -1, address, code_name);
    if (clash != 0) {
        if (clash > 0) {
            log_info("Resource server creation refused: an active server has its %s",
                     clash == 1 ? "address" : "code name");
        }
        return clash;
    }

    return resource_server_create(db, user_account_pin, organization_key_pin,
                                   organization_id, code_name, display_name, address, note,
                                   out_id);
}

int admin_create_client(db_handle_t *db, long long user_account_pin,
                         long long organization_key_pin,
                         const unsigned char *organization_id,
                         const char *code_name,
                         const char *display_name,
                         const char *client_type,
                         const char *grant_type,
                         const char *note,
                         int require_mfa,
                         int access_token_ttl_seconds,
                         int issue_refresh_tokens,
                         int refresh_token_ttl_seconds,
                         int maximum_session_seconds,
                         int secret_rotation_seconds,
                         unsigned char *out_id) {
    if (!db || !organization_id || !code_name || !display_name ||
        !client_type || !grant_type || !out_id) {
        log_error("Invalid arguments to admin_create_client");
        return -1;
    }

    /* Checked here, so a refusal is answered and the INSERT isn't sent: the
       organization, which the caller must administer, and one active client per
       code name in it */
    org_data_t org;
    int found = org_get_by_id(db, organization_id, user_account_pin, organization_key_pin, &org);
    if (found != 0) {
        if (found > 0) {
            log_info("Client creation refused: organization not found, or not the caller's");
            return 2;
        }
        return -1;
    }
    int taken = client_active_code_name_taken(db, org.pin, -1, code_name);
    if (taken != 0) {
        if (taken > 0) {
            log_info("Client creation refused: an active client has its code name");
        }
        return taken;
    }

    return client_create(db, user_account_pin, organization_key_pin,
                          organization_id, code_name, display_name, client_type, grant_type, note,
                          require_mfa, access_token_ttl_seconds,
                          issue_refresh_tokens, refresh_token_ttl_seconds,
                          maximum_session_seconds, secret_rotation_seconds,
                          out_id);
}

int admin_get_client(db_handle_t *db, long long user_account_pin,
                     long long organization_key_pin,
                     const unsigned char *client_id,
                     admin_client_t *out_client) {
    if (!db || !client_id || !out_client) {
        log_error("Invalid arguments to admin_get_client");
        return -1;
    }

    client_data_t client;
    if (client_get_by_id(db, client_id, user_account_pin, organization_key_pin, &client) != 0) {
        return -1;
    }

    memcpy(out_client, &client, sizeof(client));

    return 0;
}

int admin_update_client(db_handle_t *db, long long user_account_pin,
                        long long organization_key_pin,
                        const unsigned char *client_id,
                        const char *display_name,
                        const char *note,
                        const int *require_mfa,
                        const int *access_token_ttl_seconds,
                        const int *issue_refresh_tokens,
                        const int *refresh_token_ttl_seconds,
                        const int *maximum_session_seconds,
                        const int *secret_rotation_seconds,
                        const int *is_active) {
    if (!db || !client_id) {
        log_error("Invalid arguments to admin_update_client");
        return -1;
    }

    if (!display_name && !note && !require_mfa && !access_token_ttl_seconds &&
        !issue_refresh_tokens && !refresh_token_ttl_seconds &&
        !maximum_session_seconds && !secret_rotation_seconds && !is_active) {
        log_error("No fields to update in admin_update_client");
        return -1;
    }

    /* Verify client exists and caller is authorized */
    admin_client_t existing;
    if (admin_get_client(db, user_account_pin, organization_key_pin, client_id, &existing) != 0) {
        return -1;
    }

    /* One active client per code name in an organization. A client's code name
       doesn't change, so only reactivating one can clash; checked here, so the
       clash is answered and the update isn't sent. */
    if (is_active && *is_active && !existing.is_active) {
        int taken = client_active_code_name_taken(db, existing.organization_pin, existing.pin,
                                                  existing.code_name);
        if (taken != 0) {
            if (taken > 0) {
                log_info("Client update refused: another active client has its code name");
            }
            return taken;
        }
    }

    if (client_update(db, client_id, user_account_pin, organization_key_pin, display_name, note,
                      require_mfa, access_token_ttl_seconds, issue_refresh_tokens,
                      refresh_token_ttl_seconds, maximum_session_seconds,
                      secret_rotation_seconds, is_active) != 0) {
        return -1;
    }

    return 0;
}

int admin_list_client_redirect_uris(db_handle_t *db, long long user_account_pin,
                                     long long organization_key_pin,
                                     const unsigned char *client_id,
                                     int limit, int offset,
                                     admin_client_redirect_uri_t **out_uris,
                                     int *out_count,
                                     int *out_total) {
    if (!db || !client_id || !out_uris || !out_count) {
        log_error("Invalid arguments to admin_list_client_redirect_uris");
        return -1;
    }

    client_redirect_uri_data_t *uris = NULL;
    int count = 0;

    if (client_redirect_uri_list(db, user_account_pin, organization_key_pin, client_id, limit, offset, &uris, &count, out_total) != 0) {
        return -1;
    }

    *out_uris = uris;
    *out_count = count;

    return 0;
}

int admin_create_client_redirect_uri(db_handle_t *db, long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *client_id,
                                      const char *redirect_uri,
                                      const char *note) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to admin_create_client_redirect_uri");
        return -1;
    }

    return client_redirect_uri_create(db, user_account_pin, organization_key_pin, client_id, redirect_uri, note);
}

int admin_delete_client_redirect_uri(db_handle_t *db, long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *client_id,
                                      const char *redirect_uri) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to admin_delete_client_redirect_uri");
        return -1;
    }

    return client_redirect_uri_delete(db, user_account_pin, organization_key_pin, client_id, redirect_uri);
}

int admin_list_client_resource_servers(db_handle_t *db, long long user_account_pin,
                                        long long organization_key_pin,
                                        const unsigned char *client_id,
                                        int limit, int offset,
                                        admin_client_resource_server_t **out_links,
                                        int *out_count,
                                        int *out_total) {
    if (!db || !client_id || !out_links || !out_count) {
        log_error("Invalid arguments to admin_list_client_resource_servers");
        return -1;
    }

    client_resource_server_data_t *links = NULL;
    int count = 0;

    if (client_resource_server_list(db, user_account_pin, organization_key_pin, client_id, limit, offset, &links, &count, out_total) != 0) {
        return -1;
    }

    *out_links = links;
    *out_count = count;

    return 0;
}

int admin_list_resource_server_clients(db_handle_t *db, long long user_account_pin,
                                        long long organization_key_pin,
                                        const unsigned char *resource_server_id,
                                        int limit, int offset,
                                        admin_resource_server_client_t **out_links,
                                        int *out_count,
                                        int *out_total) {
    if (!db || !resource_server_id || !out_links || !out_count) {
        log_error("Invalid arguments to admin_list_resource_server_clients");
        return -1;
    }

    resource_server_client_data_t *links = NULL;
    int count = 0;

    if (resource_server_client_list(db, user_account_pin, organization_key_pin, resource_server_id, limit, offset, &links, &count, out_total) != 0) {
        return -1;
    }

    *out_links = links;
    *out_count = count;

    return 0;
}

int admin_create_client_resource_server_link(db_handle_t *db, long long user_account_pin,
                                              long long organization_key_pin,
                                              const unsigned char *client_id,
                                              const unsigned char *resource_server_id) {
    if (!db || !client_id || !resource_server_id) {
        log_error("Invalid arguments to admin_create_client_resource_server_link");
        return -1;
    }

    return client_resource_server_create(db, user_account_pin, organization_key_pin, client_id, resource_server_id);
}

int admin_delete_client_resource_server_link(db_handle_t *db, long long user_account_pin,
                                              long long organization_key_pin,
                                              const unsigned char *client_id,
                                              const unsigned char *resource_server_id) {
    if (!db || !client_id || !resource_server_id) {
        log_error("Invalid arguments to admin_delete_client_resource_server_link");
        return -1;
    }

    return client_resource_server_delete(db, user_account_pin, organization_key_pin,
                                         client_id, resource_server_id);
}

/* ============================================================================
 * RESOURCE SERVER KEY OPERATIONS
 * ========================================================================== */

int admin_create_resource_server_key(db_handle_t *db,
                                      long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *resource_server_id,
                                      const char *secret,
                                      const char *note,
                                      unsigned char *out_key_id) {
    if (!db || !resource_server_id || !secret || !out_key_id) {
        log_error("Invalid arguments to admin_create_resource_server_key");
        return -1;
    }

    int rc = resource_server_key_create(db, user_account_pin, organization_key_pin,
                                    resource_server_id, secret, note, out_key_id);
    if (rc != 0) return rc;

    return 0;
}

int admin_list_resource_server_keys(db_handle_t *db,
                                     long long user_account_pin,
                                     long long organization_key_pin,
                                     const unsigned char *resource_server_id,
                                     int limit, int offset,
                                     const int *filter_is_active,
                                     admin_resource_server_key_t **out_keys,
                                     int *out_count,
                                     int *out_total) {
    if (!db || !resource_server_id || !out_keys || !out_count) {
        log_error("Invalid arguments to admin_list_resource_server_keys");
        return -1;
    }

    resource_server_key_data_t *keys = NULL;
    int count = 0;

    if (resource_server_key_list(db, user_account_pin, organization_key_pin,
                                  resource_server_id, limit, offset, filter_is_active, &keys, &count, out_total) != 0) {
        return -1;
    }

    *out_keys = keys;
    *out_count = count;

    return 0;
}

int admin_revoke_resource_server_key(db_handle_t *db,
                                      long long user_account_pin,
                                      long long organization_key_pin,
                                      const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to admin_revoke_resource_server_key");
        return -1;
    }

    return resource_server_key_revoke(db, user_account_pin, organization_key_pin, key_id);
}

/* ============================================================================
 * CLIENT KEY OPERATIONS
 * ========================================================================== */

int admin_create_client_key(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *client_id,
                             const char *secret,
                             const char *note,
                             unsigned char *out_key_id) {
    if (!db || !client_id || !secret || !out_key_id) {
        log_error("Invalid arguments to admin_create_client_key");
        return -1;
    }

    int rc = client_key_create(db, user_account_pin, organization_key_pin,
                          client_id, secret, note, out_key_id);
    if (rc != 0) return rc;

    return 0;
}

int admin_list_client_keys(db_handle_t *db,
                            long long user_account_pin,
                            long long organization_key_pin,
                            const unsigned char *client_id,
                            int limit, int offset,
                            const int *filter_is_active,
                            admin_client_key_t **out_keys,
                            int *out_count,
                            int *out_total) {
    if (!db || !client_id || !out_keys || !out_count) {
        log_error("Invalid arguments to admin_list_client_keys");
        return -1;
    }

    client_key_data_t *keys = NULL;
    int count = 0;

    if (client_key_list(db, user_account_pin, organization_key_pin,
                        client_id, limit, offset, filter_is_active, &keys, &count, out_total) != 0) {
        return -1;
    }

    *out_keys = keys;
    *out_count = count;

    return 0;
}

int admin_revoke_client_key(db_handle_t *db,
                             long long user_account_pin,
                             long long organization_key_pin,
                             const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to admin_revoke_client_key");
        return -1;
    }

    return client_key_revoke(db, user_account_pin, organization_key_pin, key_id);
}

/* ============================================================================
 * CLIENT OPERATIONS
 * ========================================================================== */

int admin_add_client_redirect_uri_bootstrap(db_handle_t *db,
                                            const unsigned char *client_id,
                                            const char *redirect_uri,
                                            const char *note) {
    if (!db || !client_id || !redirect_uri) {
        log_error("Invalid arguments to admin_add_client_redirect_uri_bootstrap");
        return -1;
    }

    /* Add redirect URI (query function validates client exists) */
    if (client_add_redirect_uri_bootstrap(db, client_id, redirect_uri, note) != 0) {
        log_error("Failed to add client redirect URI");
        return -1;
    }

    return 0;
}

int admin_link_client_resource_server_bootstrap(db_handle_t *db,
                                                const char *org_code_name,
                                                const unsigned char *client_id,
                                                const char *resource_server_address) {
    if (!db || !org_code_name || !client_id || !resource_server_address) {
        log_error("Invalid arguments to admin_link_client_resource_server_bootstrap");
        return -1;
    }

    /* Link client to resource server (query validates both exist in org) */
    if (client_link_resource_server_bootstrap(db, org_code_name, client_id, resource_server_address) != 0) {
        log_error("Failed to link client to resource server");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * USER OPERATIONS
 * ========================================================================== */

int admin_create_user(db_handle_t *db,
                     const char *username,
                     const char *email,
                     const char *password,
                     unsigned char *out_user_id) {
    if (!db || !password || !out_user_id) {
        log_error("Invalid arguments to admin_create_user");
        return -1;
    }

    /* A username is what the account signs in with: an address goes on unverified */
    if (!username) {
        log_error("A username is required");
        return -1;
    }

    /* Check if username already exists */
    int username_taken = user_username_exists(db, username);
    if (username_taken < 0) {
        return -1;
    } else if (username_taken == 1) {
        log_info("Username already exists");
        return -1;
    }

    /* Check if email already exists */
    if (email) {
        int exists = user_email_exists(db, email, -1);
        if (exists < 0) {
            return -1;
        } else if (exists == 1) {
            log_info("Email already exists");
            return -1;
        }
    }

    /* Create user */
    if (user_create(db, username, email, password, out_user_id) != 0) {
        log_error("Failed to create user");
        return -1;
    }

    return 0;
}

int admin_make_org_admin(db_handle_t *db,
                        const unsigned char *user_id,
                        const char *org_code_name) {
    if (!db || !user_id || !org_code_name) {
        log_error("Invalid arguments to admin_make_org_admin");
        return -1;
    }

    /* Validate user exists */
    int user_ex = user_id_exists(db, user_id);
    if (user_ex < 0) {
        return -1;
    } else if (user_ex == 0) {
        log_info("User does not exist");
        return -1;
    }

    /* Validate organization exists */
    int org_ex = org_exists(db, org_code_name);
    if (org_ex < 0) {
        return -1;
    } else if (org_ex == 0) {
        log_info("Organization does not exist: code_name='%s'", org_code_name);
        return -1;
    }

    /* Make user org admin (idempotent) */
    if (user_make_org_admin(db, user_id, org_code_name) != 0) {
        log_error("Failed to make user org admin");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * ORGANIZATION KEY OPERATIONS
 * ========================================================================== */

int admin_list_organization_keys(db_handle_t *db,
                                  long long organization_pin,
                                  int limit, int offset,
                                  const int *filter_is_active,
                                  admin_organization_key_t **out_keys,
                                  int *out_count,
                                  int *out_total) {
    if (!db || !out_keys || !out_count) {
        log_error("Invalid arguments to admin_list_organization_keys");
        return -1;
    }

    organization_key_data_t *keys = NULL;
    int count = 0;

    if (organization_key_list(db, organization_pin, limit, offset, filter_is_active, &keys, &count, out_total) != 0) {
        return -1;
    }

    *out_keys = keys;
    *out_count = count;

    return 0;
}

int admin_revoke_organization_key(db_handle_t *db,
                                   const unsigned char *key_id) {
    if (!db || !key_id) {
        log_error("Invalid arguments to admin_revoke_organization_key");
        return -1;
    }

    return organization_key_revoke(db, key_id);
}
