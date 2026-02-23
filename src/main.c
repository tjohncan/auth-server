/* Define POSIX features before including headers */
#define _POSIX_C_SOURCE 200809L

#include "util/log.h"
#include "util/config.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/cleaner.h"
#include "db/init/db_init.h"
#include "db/init/db_history.h"
#include "crypto/password.h"
#include "crypto/jwt.h"
#include "crypto/encrypt.h"
#include "server/event_loop.h"
#include "server/router.h"
#include "server/http.h"
#include "handlers.h"
#include "util/str.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

/* Global shutdown flag for signal handling */
static volatile sig_atomic_t shutdown_requested = 0;
static EventLoopPool *global_pool = NULL;
static pthread_t cleaner_thread = 0;

/* Global context for HTTP handlers */
const config_t *g_config = NULL;

/*
 * Signal handler for graceful shutdown
 *
 * IMPORTANT: Signal handlers must only call async-signal-safe functions.
 * event_loop_pool_stop_signal_safe() is safe - it only sets boolean flags.
 */
static void signal_handler(int signum) {
    (void)signum;
    shutdown_requested = 1;

    /* Stop workers by setting their running flags to false */
    if (global_pool) {
        event_loop_pool_stop_signal_safe(global_pool);
    }
}

/*
 * Install signal handlers for graceful shutdown
 */
static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        log_warn("Failed to install SIGINT handler");
    }

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        log_warn("Failed to install SIGTERM handler");
    }

    /* Ignore SIGPIPE (broken pipe on write) */
    signal(SIGPIPE, SIG_IGN);
}

/*
 * Router-based HTTP request handler
 */
static int router_request_handler(Connection *conn,
                                   const char *request_data, size_t request_len,
                                   char **out_response, size_t *out_len)
{
    Router *router = (Router *)conn->userdata;
    if (!router) {
        log_error("No router in connection context");
        return -1;
    }

    log_debug("[Connection %lu] Received %zu bytes from %s",
             conn->connection_id, request_len, conn->remote_ip);

    /* Parse HTTP request (needs mutable copy) */
    char *request_copy = malloc(request_len + 1);
    if (!request_copy) {
        log_error("Failed to allocate request copy");
        return -1;
    }
    memcpy(request_copy, request_data, request_len);
    request_copy[request_len] = '\0';

    HttpRequest req = http_request_parse(request_copy, request_len);

    /* Copy remote IP from connection for localhost validation */
    str_copy(req.remote_ip, sizeof(req.remote_ip), conn->remote_ip);

    if (req.method == HTTP_UNKNOWN) {
        log_warn("[Connection %lu] Failed to parse HTTP request", conn->connection_id);
        free(request_copy);

        HttpResponse *error_resp = response_json_error(400, "Bad Request");
        if (!error_resp) {
            log_error("Failed to create error response");
            return -1;
        }
        *out_response = http_response_serialize(error_resp, out_len);
        http_response_free(error_resp);
        return *out_response ? 0 : -1;
    }

    log_info("[Connection %lu] %s %s", conn->connection_id, req.method_str, req.path);

    /* Dispatch to router */
    HttpResponse *resp = router_dispatch(router, &req);

    http_request_cleanup(&req);
    free(request_copy);

    if (!resp) {
        log_error("[Connection %lu] Router returned NULL", conn->connection_id);
        return -1;
    }

    int status_code = resp->status_code;

    /* Serialize response */
    *out_response = http_response_serialize(resp, out_len);
    http_response_free(resp);

    if (!*out_response) {
        log_error("[Connection %lu] Failed to serialize response", conn->connection_id);
        return -1;
    }

    log_info("[Connection %lu] Sending %d response (%zu bytes)",
             conn->connection_id, status_code, *out_len);

    return 0;
}

int main(void) {
    log_init(LOG_INFO);
    log_info("=== Auth Server Starting ===");

    /* Install signal handlers */
    setup_signal_handlers();
    log_info("Signal handlers installed");

    /* Load configuration */
    log_info("Loading configuration...");
    config_t *config = config_load("auth.conf");
    if (!config) {
        log_error("Failed to load configuration");
        return 1;
    }

    /* Apply configured log level (parsed from config file / env var) */
    log_init(config->log_level);

    log_info("Configuration loaded:");
    log_info("  Server: %s:%d (workers=%d)", config->host, config->port, config->workers);
    log_info("  Database: %s", config->db_type == DB_TYPE_SQLITE ? "SQLite" : "PostgreSQL");
    if (config->db_type == DB_TYPE_SQLITE) {
        log_info("  DB Path: %s", config->db_path);
    }

    /* Initialize password hashing module */
    log_info("Initializing password hashing...");
    if (crypto_password_init(config) != 0) {
        log_error("Failed to initialize password hashing");
        config_free(config);
        return 1;
    }

    /* Initialize JWT clock skew tolerance */
    jwt_set_clock_skew_seconds(config->jwt_clock_skew_seconds);
    log_info("JWT clock skew tolerance: %d seconds", config->jwt_clock_skew_seconds);

    /* Initialize field encryption */
    if (strcmp(config->encryption_key, "customize_me") == 0) {
        log_warn("Using default encryption key — set encryption_key in auth.conf or AUTH_ENCRYPTION_KEY env");
    }
    if (encrypt_init(config->encryption_key) != 0) {
        log_error("Failed to initialize MFA encryption");
        config_free(config);
        return 1;
    }

    /* Determine number of workers (auto-detect if config specifies 0) */
    int num_workers = config->workers;
    if (num_workers <= 0) {
        #ifdef _SC_NPROCESSORS_ONLN
        num_workers = sysconf(_SC_NPROCESSORS_ONLN);
        if (num_workers <= 0) num_workers = 4;
        #else
        num_workers = 4;
        #endif
        log_info("Auto-detected %d CPU cores for workers", num_workers);
    }

    /* Initialize database pool */
    log_info("Initializing database pool...");
    char pg_conn_str[512];
    const char *connection_string;
    if (config->db_type == DB_TYPE_SQLITE) {
        connection_string = config->db_path;
    } else {
        snprintf(pg_conn_str, sizeof(pg_conn_str),
                 "host=%s port=%d dbname=%s user=%s password=%s",
                 config->db_host, config->db_port, config->db_name,
                 config->db_user, config->db_password);
        connection_string = pg_conn_str;
    }

    if (db_pool_init(num_workers, config->db_type, connection_string) != 0) {
        log_error("Failed to initialize database pool");
        config_free(config);
        return 1;
    }

    /* Initialize schema using first connection */
    log_info("Initializing database schema...");
    db_handle_t *setup_db = db_pool_get_connection_by_index(0);
    if (!setup_db) {
        log_error("Failed to get setup database connection");
        db_pool_shutdown();
        config_free(config);
        return 1;
    }

    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    int schema_rc = db_init_schema(setup_db, config->db_type, config->schema_dir, owner_role);
    if (schema_rc < 0) {
        log_error("Failed to initialize schema");
        db_pool_shutdown();
        config_free(config);
        return 1;
    }

    /* Initialize history tables if enabled */
    if (config->enable_history_tables) {
        if (db_init_history_tables(setup_db, config->db_type, schema_rc == 0) != 0) {
            log_error("Failed to initialize history tables");
            db_pool_shutdown();
            config_free(config);
            return 1;
        }
    } else {
        log_info("History tables disabled in configuration");
    }

    /* Start cleaner thread */
    cleaner_config_t cleaner_cfg;
    cleaner_config_from_main_config(&cleaner_cfg, config);
    cleaner_cfg.connection_string = connection_string;
    if (cleaner_start(&cleaner_cfg, &cleaner_thread) != 0) {
        log_error("Failed to start cleaner thread");
        db_pool_shutdown();
        config_free(config);
        return 1;
    }

    /* Set global context for HTTP handlers */
    g_config = config;

    /* Create router and register routes */
    log_info("Initializing router...");
    Router *router = router_create();
    if (!router) {
        log_error("Failed to create router");
        db_pool_shutdown();
        config_free(config);
        return 1;
    }

    /* Register API routes */
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

    router_add(router, HTTP_POST, "/login", login_handler);
    router_add(router, HTTP_GET, "/api/user/management-setups", management_setups_handler);
    router_add(router, HTTP_GET, "/api/user/profile", profile_handler);
    router_add(router, HTTP_GET, "/api/user/emails", emails_handler);
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

    /* Register static files from ./static/ directory */
    register_static_files(router);

    /* Configure event loop (use resolved num_workers) */
    EventLoopConfig event_config = {
        .num_workers = num_workers,
        .port = config->port,
        .backlog = 128,
        .max_request_size = 1024 * 1024,
        .connection_timeout_ms = 30000,
        .max_connections_per_worker = 1024,
        .handler = router_request_handler,
        .handler_context = router
    };

    /* Create event loop pool */
    log_info("Creating event loop pool...");
    EventLoopPool *pool = event_loop_pool_create(&event_config);
    if (!pool) {
        log_error("Failed to create event loop pool");
        router_destroy(router);
        db_pool_shutdown();
        config_free(config);
        return 1;
    }

    log_info("=======================================================");
    log_info("Server ready on port %d!", config->port);
    log_info("Workers: %d", num_workers);
    log_info("Database: %s", config->db_type == DB_TYPE_SQLITE ? config->db_path : "PostgreSQL");
    log_info("Press Ctrl+C to stop");
    log_info("=======================================================");

    /* Set global pool for signal handler */
    global_pool = pool;

    /* Start event loop (blocks until shutdown signal) */
    event_loop_pool_start(pool);

    /* Cleanup */
    log_info("Shutting down...");
    global_pool = NULL;
    event_loop_pool_destroy(pool);
    router_destroy(router);

    /* Stop cleaner thread (if it was started) */
    if (cleaner_thread) {
        cleaner_request_stop();
        pthread_join(cleaner_thread, NULL);
        log_info("Cleaner thread stopped");
    }

    db_pool_shutdown();
    encrypt_cleanup();
    config_free(config);

    log_info("=== Auth Server Stopped ===");
    return 0;
}
