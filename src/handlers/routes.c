#include "handlers.h"
#include "server/router.h"

/*
 * The server's route table: every endpoint, by method and exact path.
 *
 * Kept apart from main.c so test-handlers dispatches through the same table the
 * server does, rather than a copy that could drift from it.
 */
void register_routes(Router *router) {
    router_add(router, HTTP_GET, "/", index_handler);
    router_add(router, HTTP_GET, "/health", health_handler);
    router_add(router, HTTP_POST, "/api/admin/bootstrap", admin_bootstrap_handler);
    router_add(router, HTTP_POST, "/api/admin/organizations", admin_create_organization_handler);
    router_add(router, HTTP_POST, "/api/admin/users", admin_create_user_handler);
    router_add(router, HTTP_POST, "/api/admin/org-admins", admin_make_org_admin_handler);
    router_add(router, HTTP_GET, "/api/admin/list-all-organizations", admin_list_all_organizations_handler);
    router_add(router, HTTP_POST, "/api/admin/organization-keys", admin_create_organization_key_handler);

    /* Dual-auth endpoints (localhost OR org key) */
    router_add(router, HTTP_GET, "/api/admin/organization-keys", admin_list_organization_keys_handler);
    router_add(router, HTTP_DELETE, "/api/admin/organization-keys", admin_revoke_organization_key_handler);

    /* Authenticated org-admin endpoints */
    router_add(router, HTTP_GET, "/api/admin/organizations", admin_get_organizations_handler);
    router_add(router, HTTP_PUT, "/api/admin/organizations", admin_update_organization_handler);
    router_add(router, HTTP_GET, "/api/admin/resource-servers", admin_get_resource_servers_handler);
    router_add(router, HTTP_POST, "/api/admin/resource-servers", admin_create_resource_server_handler);
    router_add(router, HTTP_PUT, "/api/admin/resource-servers", admin_update_resource_server_handler);
    router_add(router, HTTP_GET, "/api/admin/clients", admin_get_clients_handler);
    router_add(router, HTTP_POST, "/api/admin/clients", admin_create_client_handler);
    router_add(router, HTTP_PUT, "/api/admin/clients", admin_update_client_handler);
    router_add(router, HTTP_GET, "/api/admin/client-redirect-uris", admin_get_client_redirect_uris_handler);
    router_add(router, HTTP_POST, "/api/admin/client-redirect-uris", admin_create_client_redirect_uri_handler);
    router_add(router, HTTP_DELETE, "/api/admin/client-redirect-uris", admin_delete_client_redirect_uri_handler);
    router_add(router, HTTP_GET, "/api/admin/client-resource-servers", admin_get_client_resource_servers_handler);
    router_add(router, HTTP_GET, "/api/admin/resource-server-clients", admin_get_resource_server_clients_handler);
    router_add(router, HTTP_POST, "/api/admin/client-resource-servers", admin_create_client_resource_server_link_handler);
    router_add(router, HTTP_DELETE, "/api/admin/client-resource-servers", admin_delete_client_resource_server_link_handler);
    router_add(router, HTTP_POST, "/api/admin/resource-server-keys", admin_create_resource_server_key_handler);
    router_add(router, HTTP_GET, "/api/admin/resource-server-keys", admin_get_resource_server_keys_handler);
    router_add(router, HTTP_DELETE, "/api/admin/resource-server-keys", admin_delete_resource_server_key_handler);
    router_add(router, HTTP_POST, "/api/admin/client-keys", admin_create_client_key_handler);
    router_add(router, HTTP_GET, "/api/admin/client-keys", admin_get_client_keys_handler);
    router_add(router, HTTP_DELETE, "/api/admin/client-keys", admin_delete_client_key_handler);

    /* User activate/deactivate, MFA reset, password and addresses (localhost-only) */
    router_add(router, HTTP_POST, "/api/admin/users/activate", server_activate_user_handler);
    router_add(router, HTTP_POST, "/api/admin/users/deactivate", server_deactivate_user_handler);
    router_add(router, HTTP_POST, "/api/admin/users/reset-mfa", server_reset_user_mfa_handler);
    router_add(router, HTTP_POST, "/api/admin/users/set-password", server_set_user_password_handler);
    router_add(router, HTTP_GET, "/api/admin/users/emails", server_list_user_emails_handler);
    router_add(router, HTTP_DELETE, "/api/admin/users/emails", server_delete_user_email_handler);

    router_add(router, HTTP_POST, "/login", login_handler);
    router_add(router, HTTP_GET, "/api/user/management-setups", management_setups_handler);
    router_add(router, HTTP_GET, "/api/user/profile", profile_handler);
    router_add(router, HTTP_GET, "/api/user/emails", emails_handler);
    router_add(router, HTTP_POST, "/api/user/emails", add_email_handler);
    router_add(router, HTTP_DELETE, "/api/user/emails", delete_email_handler);
    router_add(router, HTTP_POST, "/api/user/emails/set-primary", set_primary_email_handler);
#ifdef EMAIL_SUPPORT
    router_add(router, HTTP_POST, "/email-verification-token", create_email_verification_token_handler);
    router_add(router, HTTP_GET, "/verify-email", verify_email_page_handler);
    router_add(router, HTTP_POST, "/verify-email", verify_email_handler);
    router_add(router, HTTP_GET, "/request-password-reset", request_password_reset_page_handler);
    router_add(router, HTTP_POST, "/request-password-reset", request_password_reset_handler);
    router_add(router, HTTP_GET, "/reset-password", reset_password_page_handler);
    router_add(router, HTTP_POST, "/reset-password", reset_password_handler);
    router_add(router, HTTP_GET, "/request-passwordless-login", request_passwordless_login_page_handler);
    router_add(router, HTTP_POST, "/request-passwordless-login", request_passwordless_login_handler);
    router_add(router, HTTP_GET, "/passwordless-login", passwordless_login_page_handler);
    router_add(router, HTTP_POST, "/passwordless-login", passwordless_login_handler);
    router_add(router, HTTP_POST, "/api/user/passwordless-login", passwordless_login_toggle_handler);
#endif
    router_add(router, HTTP_POST, "/api/user/password", change_password_handler);
    router_add(router, HTTP_POST, "/api/user/username", change_username_handler);
    router_add(router, HTTP_POST, "/logout", logout_handler);

    /* MFA endpoints */
    router_add(router, HTTP_POST, "/api/user/mfa/totp/setup", mfa_totp_setup_handler);
    router_add(router, HTTP_POST, "/api/user/mfa/totp/confirm", mfa_totp_confirm_handler);
    router_add(router, HTTP_POST, "/api/user/mfa/verify", mfa_verify_handler);
    router_add(router, HTTP_POST, "/api/user/mfa/recover", mfa_recover_handler);
    router_add(router, HTTP_GET, "/api/user/mfa/methods", mfa_list_methods_handler);
    router_add(router, HTTP_DELETE, "/api/user/mfa/methods", mfa_delete_method_handler);
    router_add(router, HTTP_POST, "/api/user/mfa/recovery-codes/regenerate", mfa_regenerate_recovery_codes_handler);
    router_add(router, HTTP_POST, "/api/user/mfa/require", mfa_set_require_handler);
    router_add(router, HTTP_GET, "/authorize", authorize_handler);
    router_add(router, HTTP_POST, "/token", token_handler);
    router_add(router, HTTP_POST, "/revoke", revoke_handler);
    router_add(router, HTTP_POST, "/introspect", introspect_handler);
    router_add(router, HTTP_GET, "/.well-known/jwks.json", jwks_handler);
    router_add(router, HTTP_GET, "/userinfo", userinfo_handler);

    /* Invitation endpoints */
    router_add(router, HTTP_GET, "/accept-invitation", accept_invitation_page_handler);
    router_add(router, HTTP_POST, "/accept-invitation", accept_invitation_handler);

    /* RS user provisioning API */
    router_add(router, HTTP_POST, "/api/rs/users", rs_provision_user_handler);
    router_add(router, HTTP_GET, "/api/rs/users", rs_lookup_user_handler);
    router_add(router, HTTP_POST, "/api/rs/client-users", rs_link_client_user_handler);
    router_add(router, HTTP_DELETE, "/api/rs/client-users", rs_unlink_client_user_handler);
    router_add(router, HTTP_GET, "/api/rs/client-users", rs_list_client_users_handler);

    /* POST aliases for GET endpoints (browsers cannot send GET with JSON body) */
    router_add(router, HTTP_POST, "/api/rs/users/lookup", rs_lookup_user_handler);
    router_add(router, HTTP_POST, "/api/rs/client-users/list", rs_list_client_users_handler);
}
