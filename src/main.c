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
#include "crypto/signing_keys.h"
#include "crypto/encrypt.h"
#include "crypto/hmac.h"
#include "server/event_loop.h"
#include "server/router.h"
#include "server/http.h"
#include "handlers.h"
#include "util/str.h"
#include "util/template.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <openssl/crypto.h>

static void worker_thread_cleanup(void) {
    crypto_jwt_thread_cleanup();
    signing_key_thread_cleanup();
}

static EventLoopPool * volatile global_pool = NULL;
static pthread_t cleaner_thread;
static bool cleaner_started = false;

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

    /* Stop workers by setting their running flags to false */
    if (global_pool) {
        event_loop_pool_stop_signal_safe((EventLoopPool *)global_pool);
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

#ifdef EMAIL_SUPPORT
    /* Auto-reap child processes (email delivery forks without waitpid) */
    signal(SIGCHLD, SIG_IGN);
#endif
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

    /* Copy remote IP and listener from connection for localhost validation */
    str_copy(req.remote_ip, sizeof(req.remote_ip), conn->remote_ip);
    req.admin_listener = conn->admin_listener;

    if (req.method == HTTP_UNKNOWN) {
        log_warn("[Connection %lu] Failed to parse HTTP request", conn->connection_id);
        /* A rejected parse can still have allocated (and freed) headers on the way
         * out. cleanup() is idempotent and NULL-safe, so call it on every path
         * rather than relying on the parser to leave nothing behind when it fails. */
        http_request_cleanup(&req);
        OPENSSL_cleanse(request_copy, request_len);
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
    OPENSSL_cleanse(request_copy, request_len);
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

    /* An access token must stay verifiable for its whole life. Signing keeps the
     * current and prior ES256 keys; after a rotation the old key still signs for
     * the activation delay and is dropped at the next rotation, one interval
     * later. So only a TTL of at most (interval - delay) is guaranteed to verify
     * until exp. Anything longer can fail verification early, before its own
     * expiry, with no error anywhere to explain it. */
    const int max_verifiable_ttl = ACCESS_TOKEN_ROTATION_SECONDS - JWKS_ACTIVATION_DELAY_SECONDS;
    if (config->max_access_token_ttl_seconds > max_verifiable_ttl) {
        log_warn("max_access_token_ttl_seconds %d exceeds signing-key retention; using %d",
                 config->max_access_token_ttl_seconds, max_verifiable_ttl);
        config->max_access_token_ttl_seconds = max_verifiable_ttl;
    }

    log_info("Configuration loaded:");
    log_info("  Server: %s:%d (workers=%d)", config->host, config->port, config->workers);

    /* The admin API listens on loopback alone, on a port of its own. Sharing the
       public one, loopback traffic to the public port (a proxy on the same host,
       say) would land on the admin listener. */
    if (config->admin_port == config->port) {
        log_error("admin_port and server_port are both %d: the admin API needs a port of its own",
                  config->port);
        config_free(config);
        return 1;
    }
    log_info("  Admin API: 127.0.0.1:%d (and [::1] where present), loopback only",
             config->admin_port);
    log_info("  Database: %s", config->db_type == DB_TYPE_SQLITE ? "SQLite" : "PostgreSQL");
    if (config->db_type == DB_TYPE_SQLITE) {
        log_info("  DB Path: %s", config->db_path);
    }

    /* Where the client's address comes from. A typo refuses to start rather than
       quietly falling back, which behind a load balancer would record whatever
       address each client chose to send. */
    if (http_set_client_ip_header(config->client_ip_header) != 0) {
        log_error("Unknown client_ip_header '%s': use x-real-ip, x-forwarded-for or none",
                  config->client_ip_header);
        config_free(config);
        return 1;
    }
    log_info("  Client address from: %s",
             config->client_ip_header ? config->client_ip_header : "x-real-ip");

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

    /* DESIGN DECISION: the default encryption key warns; it does not refuse to boot.
     * Field encryption's threat model is bounded and stated — keep PII out of plain
     * view of whoever is reading the database — not defeat an attacker holding the
     * database *and* the config. The default key is public on purpose: a fresh clone
     * has to build and run, or nobody gets far enough to evaluate the project. Taxing
     * every newcomer to protect a deployer who ignored both a startup warning and a
     * documented config line is the wrong trade. The same philosophy governs the other
     * permissive defaults, notably password_min_length (ships at 1). Policy is the
     * deployer's call; this server ships ready to run, not ready to ship. Revisit if
     * we add a strict/production mode that refuses known-default secrets. */
    if (strcmp(config->encryption_key, "customize_me") == 0) {
        log_warn("Using default encryption key — set encryption_key in auth.conf or AUTH_ENCRYPTION_KEY env");
    }
    if (encrypt_init(config->encryption_key) != 0) {
        log_error("Failed to initialize MFA encryption");
        config_free(config);
        return 1;
    }
    OPENSSL_cleanse(config->encryption_key, strlen(config->encryption_key));

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
        if (!config->db_host || !config->db_name || !config->db_user || !config->db_password) {
            log_error("PostgreSQL requires db_host, db_name, db_user, and db_password");
            encrypt_cleanup();
            config_free(config);
            return 1;
        }
        if (config_build_pg_connection_string(config, pg_conn_str, sizeof(pg_conn_str)) != 0) {
            log_error("PostgreSQL connection string too long");
            encrypt_cleanup();
            config_free(config);
            return 1;
        }
        connection_string = pg_conn_str;
    }

    if (db_pool_init(num_workers, config->db_type, connection_string) != 0) {
        log_error("Failed to initialize database pool");
        encrypt_cleanup();
        config_free(config);
        return 1;
    }
    if (config->db_password) {
        OPENSSL_cleanse(config->db_password, strlen(config->db_password));
    }

    /* Initialize schema using first connection */
    log_info("Initializing database schema...");
    db_handle_t *setup_db = db_pool_get_connection_by_index(0);
    if (!setup_db) {
        log_error("Failed to get setup database connection");
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    int schema_rc = db_init_schema(setup_db, config->db_type, config->schema_dir, owner_role);
    if (schema_rc < 0) {
        log_error("Failed to initialize schema");
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    /* Initialize history tables if enabled */
    if (config->enable_history_tables) {
        if (db_init_history_tables(setup_db, config->db_type, schema_rc == 0) != 0) {
            log_error("Failed to initialize history tables");
            db_pool_shutdown();
            encrypt_cleanup();
            config_free(config);
            return 1;
        }
    } else {
        log_info("History tables disabled in configuration");
    }

    /* The wrong encryption_key, or signing keys sealed under another, stops the
       server here, rather than showing up as failed sign-ins and token issuance
       once it's serving */
    int key_check = signing_key_check_encryption_key(setup_db);
    if (key_check != 0) {
        log_error(key_check == -2
                  ? "Refusing to start: the stored signing keys don't open under encryption_key"
                  : "Refusing to start: encryption_key does not match the database");
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    /* Start cleaner thread */
    cleaner_config_t cleaner_cfg;
    cleaner_config_from_main_config(&cleaner_cfg, config);
    cleaner_cfg.connection_string = connection_string;
    if (cleaner_start(&cleaner_cfg, &cleaner_thread) != 0) {
        log_error("Failed to start cleaner thread");
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }
    cleaner_started = cleaner_cfg.enabled;

    /* Connection string no longer needed — cleanse credentials from stack */
    if (config->db_type != DB_TYPE_SQLITE) {
        OPENSSL_cleanse(pg_conn_str, sizeof(pg_conn_str));
    }

    /* Set global context for HTTP handlers */
    g_config = config;

    /* Create router and register routes */
    log_info("Initializing router...");
    Router *router = router_create();
    if (!router) {
        log_error("Failed to create router");
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    /* Register API routes */
    register_routes(router);

    /* Every CORS path must be a route, or the header silently never appears */
    if (router_validate_cors_paths(router) != 0) {
        log_error("CORS path set does not match the registered routes");
        router_destroy(router);
        db_pool_shutdown();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    /* Register static files from ./static/ directory */
    register_static_files(router, config);

    /* Load templates from ./templates/ directory */
    template_init("./templates");

    /* Configure event loop (use resolved num_workers) */
    EventLoopConfig event_config = {
        .num_workers = num_workers,
        .port = config->port,
        .admin_port = config->admin_port,
        .backlog = 128,
        .max_request_size = 1024 * 1024,
        .connection_timeout_ms = 30000,
        .max_connections_per_worker = 1024,
        .handler = router_request_handler,
        .handler_context = router,
        .on_worker_exit = worker_thread_cleanup
    };

    /* Create event loop pool */
    log_info("Creating event loop pool...");
    EventLoopPool *pool = event_loop_pool_create(&event_config);
    if (!pool) {
        log_error("Failed to create event loop pool");
        router_destroy(router);
        db_pool_shutdown();
        encrypt_cleanup();
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
    if (cleaner_started) {
        cleaner_request_stop();
        pthread_join(cleaner_thread, NULL);
        log_info("Cleaner thread stopped");
    }

    static_files_cleanup();
    template_cleanup();
    db_pool_shutdown();
    encrypt_cleanup();
    crypto_hmac_cleanup();
    config_free(config);

    log_info("=== Auth Server Stopped ===");
    return 0;
}
