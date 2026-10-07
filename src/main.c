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
#include "util/validation.h"
#include "db/instance_lock.h"
#include "db/maintenance.h"
#include "db/encryption_params.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

static void worker_thread_cleanup(void) {
    crypto_jwt_thread_cleanup();
    signing_key_thread_cleanup();
}

static EventLoopPool * volatile global_pool = NULL;
static pthread_t cleaner_thread;
static bool cleaner_started = false;

/* ============================================================================
 * The instance lock (db/instance_lock.h): held shared while the server runs
 * ============================================================================ */

static int g_lock_fd = -1;               /* SQLite: the lock file */
static atomic_bool g_lock_lost = false;  /* a maintenance run took it: exit 1 */

/* How the database stretched encryption_key when this process derived its field
   keys (init_field_keys): encryption_params_get_or_make's answer, and the row.
   Set before any worker or the cleaner starts. */
static bool g_keys_derived = false;
static int g_keys_have;
static encrypt_params_t g_keys_params;

/* Are two statements on this connection served by one PostgreSQL backend? A
   transaction-pooling proxy may hand each to another, where this session's
   lock isn't. It can miss a proxy that happens to repeat a backend, never a
   direct connection. 1, 0, or -1 on error. */
static int same_backend(db_handle_t *db) {
    db_result_t *a = NULL, *b = NULL;
    int rc = -1;
    if (db_query(db, &a, "%s", "SELECT pg_backend_pid()") == 0 &&
        db_query(db, &b, "%s", "SELECT pg_backend_pid()") == 0 &&
        db_result_row_count(a) == 1 && db_result_row_count(b) == 1) {
        const char *pa = db_result_get(a, 0, 0), *pb = db_result_get(b, 0, 0);
        rc = pa && pb && strcmp(pa, pb) == 0;
    }
    db_result_free(a);
    db_result_free(b);
    return rc;
}

/*
 * The shared lock on a PostgreSQL connection that serves, as its session hook
 * (db_set_session_hook): taken when it connects, and again after every
 * reconnect before it runs anything else, since PostgreSQL drops a session's
 * lock with the session (a restart, say). So no connection serves without it,
 * and a maintenance run can't start while one does. One that finds a run
 * holding it stops the instance: what it would serve with is being replaced.
 */
static int hold_instance_lock(db_handle_t *db) {
    int rc = instance_lock_pg(db, 0);
    if (rc == 1) {
        log_error("A maintenance run holds the database: this instance stops, since what it "
                  "serves with is being replaced. Start it after the run.");
        atomic_store(&g_lock_lost, true);
        if (global_pool) event_loop_pool_stop((EventLoopPool *)global_pool);
        return 1;
    }
    if (rc != 0) return -1;
    if (same_backend(db) != 1) {
        log_error("This connection's statements don't reach one PostgreSQL session (a "
                  "transaction-pooling proxy?), so it can't hold the instance lock: connect "
                  "the server to PostgreSQL directly");
        return -1;
    }
    /* A run that came and went while this connection's session was gone (a
       PostgreSQL restart, say) left the lock free, so taking it shows nothing. A
       re-key leaves the encryption_params row changed, and then the field keys
       this instance holds are the old ones. */
    if (g_keys_derived) {
        int same = encryption_params_unchanged(db, g_keys_have, &g_keys_params);
        if (same == 0) {
            log_error("The database was re-keyed while this instance's connections were down "
                      "(after a PostgreSQL restart, say): this instance stops, since its field "
                      "keys are the old ones. Start it with the new encryption_key.");
            atomic_store(&g_lock_lost, true);
            if (global_pool) event_loop_pool_stop((EventLoopPool *)global_pool);
            return 1;
        }
        if (same != 1) return -1;
    }
    return 0;
}

/* SQLite: take the shared lock before the database is touched. Returns 0; 1 if
   a maintenance run holds it (logged); -1 on error. (PostgreSQL connections
   take theirs as they connect: hold_instance_lock.) */
static int instance_lock_take_shared(const config_t *config) {
    char path[1100];
    if (instance_lock_path(config->db_path, path, sizeof(path)) != 0) return 0;  /* in memory */
    int rc = instance_lock_file(path, 0, &g_lock_fd);
    if (rc == 1) {
        log_error("A maintenance run holds %s: start after it finishes", path);
    }
    return rc;
}

static void instance_lock_release_all(void) {
    instance_lock_file_release(g_lock_fd);
    g_lock_fd = -1;
}

/* ============================================================================
 * Maintenance modes
 * ============================================================================ */

/*
 * A maintenance run's connection, with every instance stopped, which the
 * exclusive instance lock makes sure of. Returns 0, or 1 (logged).
 */
static int open_for_maintenance(const config_t *config, const char *connection_string,
                                db_handle_t **db, int *lock_fd) {
    *db = NULL;
    *lock_fd = -1;

    if (config->db_type == DB_TYPE_SQLITE) {
        char path[1100];
        if (instance_lock_path(config->db_path, path, sizeof(path)) != 0 ||
            access(config->db_path, F_OK) != 0) {
            log_error("No database at %s", config->db_path);
            return 1;
        }
        int rc = instance_lock_file(path, 1, lock_fd);
        if (rc != 0) {
            if (rc == 1) {
                log_error("An instance is running on this database, or another maintenance "
                          "run is: stop every instance first");
            }
            return 1;
        }
    }

    if (db_connect(db, config->db_type, connection_string) != 0) {
        log_error("Can't connect to the database");
        instance_lock_file_release(*lock_fd);
        *lock_fd = -1;
        return 1;
    }

    if (config->db_type != DB_TYPE_SQLITE) {
        int rc = instance_lock_pg(*db, 1);
        if (rc != 0) {
            if (rc == 1) {
                log_error("An instance is running on this database, or another maintenance "
                          "run is: stop every instance first");
            }
            db_disconnect(*db);
            *db = NULL;
            return 1;
        }
    }
    return 0;
}

static void close_after_maintenance(db_handle_t *db, int lock_fd) {
    db_disconnect(db);
    instance_lock_file_release(lock_fd);
}

/* ./auth-server --drophistory (db/maintenance.h) */
static int run_drophistory(const config_t *config, const char *connection_string) {
    db_handle_t *db;
    int lock_fd;
    if (open_for_maintenance(config, connection_string, &db, &lock_fd) != 0) return 1;

    drophistory_report_t report;
    int rc = maintenance_drop_history(db, config->db_type, config->enable_history_tables, &report);
    if (rc != -1) {
        printf("Dropped %d history table%s and %d %s that filled them.\n",
               report.tables_dropped, report.tables_dropped == 1 ? "" : "s",
               report.triggers_dropped,
               config->db_type == DB_TYPE_SQLITE ? "triggers" : "trigger functions");
        printf(report.rebuilt
               ? "enable_history_tables is on: empty history tables and triggers were made again.\n"
               : "enable_history_tables is off: no history was made again.\n");
        printf("WAL archives, replicas and backups still hold what history held.\n");
    }

    close_after_maintenance(db, lock_fd);
    return rc == 0 ? 0 : 1;
}

/* The method new stretching parameters use: the one user secrets are hashed with */
static const char *stretch_method(const config_t *config) {
    return config->secret_hashing_algorithm == PASSWORD_HASH_PBKDF2_SHA256
           ? "pbkdf2-sha256" : "argon2id";
}

/*
 * ./auth-server --rekey (db/maintenance.h): everything sealed under
 * encryption_key_previous, as the database stretches it now, is sealed again
 * under encryption_key, stretched with the configured method and a fresh salt.
 * The same passphrase in both re-keys too: that's how a database made before
 * stretching gets it, or a new method or iteration count takes effect.
 */
static int run_rekey(const config_t *config, const char *connection_string) {
    if (!config->encryption_key_previous || !*config->encryption_key_previous) {
        log_error("--rekey needs the passphrase the data is sealed under now, in "
                  "encryption_key_previous (or AUTH_ENCRYPTION_KEY_PREVIOUS), and the new one in "
                  "encryption_key. To keep the passphrase and change only how it's stretched, "
                  "give the same one in both.");
        return 1;
    }
    if (strcmp(config->encryption_key, "customize_me") == 0) {
        log_warn("encryption_key is the shipped default: this re-seals everything under a "
                 "published key");
    }

    db_handle_t *db;
    int lock_fd;
    if (open_for_maintenance(config, connection_string, &db, &lock_fd) != 0) return 1;

    int status = 1;
    encrypt_params_t old_params, new_params;
    encrypt_keys_t old_keys, new_keys;
    memset(&old_keys, 0, sizeof(old_keys));
    memset(&new_keys, 0, sizeof(new_keys));

    /* The new stretch is recorded in the database, so its table must be there */
    int exists = encryption_params_table_exists(db);
    if (exists != 1) {
        if (exists == 0) {
            log_error("No encryption_params table: add it first, as sql/README.md shows under "
                      "--rekey");
        }
        goto done;
    }

    /* The keys the data is sealed under: the previous passphrase, as the database
       stretches it (HKDF alone without a row) */
    int have = encryption_params_load(db, &old_params);
    if (have == -1 ||
        encrypt_derive_keys(config->encryption_key_previous, have == 0 ? &old_params : NULL,
                            &old_keys) != 0) {
        goto done;
    }

    if (encrypt_params_new(stretch_method(config), config->secret_hash_max_iterations,
                           &new_params) != 0 ||
        encrypt_derive_keys(config->encryption_key, &new_params, &new_keys) != 0) {
        goto done;
    }

    rekey_report_t report;
    int rc = maintenance_rekey(db, config->db_type, &old_keys, &new_keys, &new_params, &report);
    if (rc != -1) {
        printf("Re-sealed under encryption_key, stretched with %s (%d iteration%s):\n",
               new_params.method, new_params.iterations, new_params.iterations == 1 ? "" : "s");
        printf("  %d username%s, %d address%s, %d passwordless sign-in link%s, "
               "%d TOTP secret%s, %d signing key%s\n",
               report.usernames, report.usernames == 1 ? "" : "s",
               report.addresses, report.addresses == 1 ? "" : "es",
               report.passwordless, report.passwordless == 1 ? "" : "s",
               report.mfa_secrets, report.mfa_secrets == 1 ? "" : "s",
               report.signing_keys, report.signing_keys == 1 ? "" : "s");
        if (report.history_tables > 0) {
            printf("History made before the re-key is still sealed under the old key, in %d "
                   "table%s: run ./auth-server --drophistory next to remove it.\n",
                   report.history_tables, report.history_tables == 1 ? "" : "s");
        }
        if (rc == -2) {
            printf("NOT SCRUBBED: the replaced values are still in the database's files (the "
                   "error above says how to finish it).\n");
        }
        printf("Backups, WAL archives and replicas made before this still hold the old-key "
               "values.\n");
        printf("Start every instance with the new encryption_key, and remove "
               "encryption_key_previous.\n");
    }
    status = rc == 0 ? 0 : 1;

done:
    OPENSSL_cleanse(&old_keys, sizeof(old_keys));
    OPENSSL_cleanse(&new_keys, sizeof(new_keys));
    close_after_maintenance(db, lock_fd);
    return status;
}

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

/*
 * The process's field keys: encryption_key stretched as the database's
 * encryption_params row says, then HKDF. A database with nothing sealed yet gets
 * its row now, with the method user secrets are hashed with and their most
 * iterations, so it's stretched from the start. One whose values were sealed
 * before the row existed keeps HKDF alone until --rekey adds the stretch.
 * Returns 0, or -1 (logged).
 */
static int init_field_keys(db_handle_t *db, const config_t *config) {
    encrypt_params_t params;
    int have = encryption_params_get_or_make(db, stretch_method(config),
                                             config->secret_hash_max_iterations, &params);
    if (have == -1) return -1;

    encrypt_keys_t keys;
    if (encrypt_derive_keys(config->encryption_key, have == 0 ? &params : NULL, &keys) != 0) {
        log_error("Failed to derive the field keys from encryption_key");
        return -1;
    }
    encrypt_init_keys(&keys);
    OPENSSL_cleanse(&keys, sizeof(keys));
    g_keys_have = have;
    if (have == 0) g_keys_params = params;
    g_keys_derived = true;

    if (have == 0) {
        log_info("Field encryption initialized (encryption_key stretched with %s, %d iterations)",
                 params.method, params.iterations);
    } else {
        log_warn("encryption_key is used without stretching (no encryption_params row): with "
                 "every instance stopped, ./auth-server --rekey adds it (sql/README.md)");
    }
    return 0;
}

/*
 * The connection string db_connect takes: the SQLite path, or one built for
 * PostgreSQL in pg_buf. Returns 0, or -1 (logged).
 */
static int connection_string_for(const config_t *config, char *pg_buf, size_t pg_size,
                                 const char **out) {
    if (config->db_type == DB_TYPE_SQLITE) {
        *out = config->db_path;
        return 0;
    }
    if (!config->db_host || !config->db_name || !config->db_user || !config->db_password) {
        log_error("PostgreSQL requires db_host, db_name, db_user, and db_password");
        return -1;
    }
    if (config_build_pg_connection_string(config, pg_buf, pg_size) != 0) {
        log_error("PostgreSQL connection string too long");
        return -1;
    }
    *out = pg_buf;
    return 0;
}

/* The admin socket auth.conf names, or NULL for none */
static const char *admin_socket_of(const config_t *config) {
    return config->admin_socket && config->admin_socket[0] ? config->admin_socket : NULL;
}

/*
 * ./auth-server --admin METHOD PATH [BODY | -]: one call to this server's admin
 * API, on the admin socket auth.conf names, else its admin_port, printing the
 * answer's body. BODY is JSON; "-" reads it from standard input, which keeps a
 * password out of the process list. Exits 0 for a 2xx answer, 1 for any other
 * (its status on standard error), 2 if the call couldn't be made.
 */
static int run_admin_client(const config_t *config, const char *method, const char *path,
                            const char *body_arg) {
    for (const char *c = method; *c; c++) {
        if (*c < 'A' || *c > 'Z') {
            fprintf(stderr, "--admin: the method is a word like GET or POST\n");
            return 2;
        }
    }
    for (const char *c = path; *c; c++) {
        if ((unsigned char)*c <= ' ' || *c == 0x7f) {
            fprintf(stderr, "--admin: the path can't hold spaces or control characters\n");
            return 2;
        }
    }
    if (path[0] != '/') {
        fprintf(stderr, "--admin: the path starts with /, as in /api/admin/bootstrap\n");
        return 2;
    }

    /* The body: the argument, or standard input for "-" */
    char *body = NULL;
    size_t body_len = 0;
    if (body_arg && strcmp(body_arg, "-") == 0) {
        size_t capacity = 4096;
        body = malloc(capacity);
        size_t n;
        while (body && (n = fread(body + body_len, 1, capacity - body_len, stdin)) > 0) {
            body_len += n;
            if (body_len == capacity) {
                if (capacity >= 1024 * 1024) {
                    fprintf(stderr, "--admin: the body is over 1 MiB\n");
                    OPENSSL_cleanse(body, body_len);
                    free(body);
                    return 2;
                }
                char *grown = realloc(body, capacity * 2);
                if (!grown) break;
                body = grown;
                capacity *= 2;
            }
        }
        if (!body) {
            fprintf(stderr, "--admin: out of memory\n");
            return 2;
        }
    } else if (body_arg) {
        body_len = strlen(body_arg);
        body = malloc(body_len + 1);
        if (!body) return 2;
        memcpy(body, body_arg, body_len);
    }

    /* The admin socket, else loopback TCP on admin_port */
    const char *socket_path = admin_socket_of(config);
    int fd = -1;
    if (socket_path) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(socket_path) < sizeof(addr.sun_path)) {
            memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
            fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                fprintf(stderr, "--admin: can't connect to %s: %s\n", socket_path, strerror(errno));
                close(fd);
                fd = -1;
            }
        }
    } else if (config->admin_port > 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)config->admin_port);
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            fprintf(stderr, "--admin: can't connect to 127.0.0.1:%d: %s\n", config->admin_port,
                    strerror(errno));
            close(fd);
            fd = -1;
        }
    } else {
        fprintf(stderr, "--admin: auth.conf has no admin_socket and no admin_port\n");
    }
    if (fd < 0) {
        if (body) OPENSSL_cleanse(body, body_len);
        free(body);
        return 2;
    }
    struct timeval timeout = { .tv_sec = 35, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    /* One HTTP/1.0 request, as the admin listener takes it */
    char head[1024];
    int head_len = body
        ? snprintf(head, sizeof(head), "%s %s HTTP/1.0\r\nHost: localhost\r\n"
                   "User-Agent: auth-server --admin\r\nContent-Type: application/json\r\n"
                   "Content-Length: %zu\r\n\r\n", method, path, body_len)
        : snprintf(head, sizeof(head), "%s %s HTTP/1.0\r\nHost: localhost\r\n"
                   "User-Agent: auth-server --admin\r\n\r\n", method, path);
    int sent = head_len > 0 && (size_t)head_len < sizeof(head) &&
               send(fd, head, (size_t)head_len, MSG_NOSIGNAL) == head_len;
    for (size_t off = 0; sent && off < body_len; ) {
        ssize_t n = send(fd, body + off, body_len - off, MSG_NOSIGNAL);
        if (n <= 0) sent = 0;
        else off += (size_t)n;
    }
    if (body) OPENSSL_cleanse(body, body_len);
    free(body);
    if (!sent) {
        fprintf(stderr, "--admin: sending the request failed: %s\n", strerror(errno));
        close(fd);
        return 2;
    }

    /* The answer, to the end: the server closes after one */
    size_t capacity = 16384, len = 0;
    char *answer = malloc(capacity + 1);
    ssize_t n;
    while (answer && (n = recv(fd, answer + len, capacity - len, 0)) > 0) {
        len += (size_t)n;
        if (len == capacity) {
            char *grown = realloc(answer, capacity * 2 + 1);
            if (!grown) break;
            answer = grown;
            capacity *= 2;
        }
    }
    close(fd);
    if (!answer) return 2;
    answer[len] = '\0';

    int status = 0;
    const char *body_start = strstr(answer, "\r\n\r\n");
    if (sscanf(answer, "HTTP/1.%*d %d", &status) != 1 || !body_start) {
        fprintf(stderr, "--admin: no answer from the server\n");
        free(answer);
        return 2;
    }
    body_start += 4;
    fputs(body_start, stdout);
    if (*body_start && body_start[strlen(body_start) - 1] != '\n') fputc('\n', stdout);
    free(answer);
    if (status < 200 || status > 299) {
        fprintf(stderr, "HTTP %d\n", status);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* No arguments serves. One maintenance mode runs once and exits, and so does
       one admin call. */
    const char *mode = argc == 2 ? argv[1] : NULL;
    bool drophistory = mode && strcmp(mode, "--drophistory") == 0;
    bool rekey = mode && strcmp(mode, "--rekey") == 0;
    bool admin = (argc == 4 || argc == 5) && strcmp(argv[1], "--admin") == 0;
    if (argc > 1 && !drophistory && !rekey && !admin) {
        fprintf(stderr, "Usage: %s [--drophistory | --rekey | --admin METHOD PATH [BODY | -]]\n"
                        "  (no argument)    serve, configured by ./auth.conf\n"
                        "  --drophistory    remove every history table and its triggers, making\n"
                        "                   them again if enable_history_tables is on\n"
                        "  --rekey          seal everything sealed under encryption_key_previous\n"
                        "                   again under encryption_key\n"
                        "  Every instance must be stopped before either.\n"
                        "  --admin          call this server's admin API (its admin_socket, else\n"
                        "                   admin_port) and print the answer; BODY is JSON, and\n"
                        "                   - reads it from standard input\n",
                argv[0]);
        return 2;
    }

    /* An admin call prints the answer alone: only warnings and errors are logged */
    if (admin) {
        log_init(LOG_WARN);
        config_t *config = config_load("auth.conf");
        if (!config) return 2;
        int rc = run_admin_client(config, argv[2], argv[3], argc == 5 ? argv[4] : NULL);
        config_free(config);
        return rc;
    }

    log_init(LOG_INFO);
    log_info(drophistory ? "=== Auth Server: --drophistory ===" :
             rekey ? "=== Auth Server: --rekey ===" : "=== Auth Server Starting ===");

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

    if (drophistory || rekey) {
        char pg_buf[512];
        const char *connection_string;
        int rc = connection_string_for(config, pg_buf, sizeof(pg_buf), &connection_string) != 0 ? 1
                 : drophistory ? run_drophistory(config, connection_string)
                 : run_rekey(config, connection_string);
        OPENSSL_cleanse(pg_buf, sizeof(pg_buf));
        config_free(config);
        return rc;
    }

    /* Only --rekey reads it: a server has no use for the old passphrase */
    if (config->encryption_key_previous) {
        log_warn("encryption_key_previous is set, and only --rekey reads it: remove it once "
                 "the re-key is done");
        OPENSSL_cleanse(config->encryption_key_previous, strlen(config->encryption_key_previous));
    }

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

    /* The admin API: on a Unix socket, which only who its mode lets in can open,
       and on loopback TCP too where admin_port asks for it. A port of its own:
       sharing the public one, loopback traffic to the public port (a proxy on
       the same host, say) would land on the admin listener. */
    if (config->admin_port > 0 && config->admin_port == config->port) {
        log_error("admin_port and server_port are both %d: the admin API needs a port of its own",
                  config->port);
        config_free(config);
        return 1;
    }
    if (admin_socket_of(config)) {
        log_info("  Admin API: %s (mode %04o)", config->admin_socket, config->admin_socket_mode);
    }
    if (config->admin_port > 0) {
        log_info("  Admin API: 127.0.0.1:%d (and [::1] where present), loopback only",
                 config->admin_port);
    }
    if (!admin_socket_of(config) && config->admin_port <= 0) {
        log_info("  Admin API: off (no admin_socket, no admin_port)");
    }
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

    /* The patterns new usernames, addresses, code names and secrets must match.
       One that won't compile refuses to start, naming the setting. */
    validation_patterns_t patterns = {
        .username = config->username_pattern,
        .email = config->email_pattern,
        .code_name = config->code_name_pattern,
        .password = config->password_pattern,
        .machine_secret = config->machine_secret_pattern,
    };
    if (validation_init(&patterns) != 0) {
        config_free(config);
        return 1;
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
    /* The field keys themselves are derived once the database is open: how the
       key is stretched is recorded there (init_field_keys) */

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
    if (connection_string_for(config, pg_conn_str, sizeof(pg_conn_str), &connection_string) != 0) {
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    /* The instance lock, held shared until exit, before anything touches the
       database: a maintenance run in progress refuses this start. SQLite: the
       lock file, now. PostgreSQL: every pool connection, as soon as it's made. */
    if (config->db_type == DB_TYPE_SQLITE && instance_lock_take_shared(config) != 0) {
        instance_lock_release_all();
        encrypt_cleanup();
        config_free(config);
        return 1;
    }

    if (db_pool_init(num_workers, config->db_type, connection_string) != 0) {
        log_error("Failed to initialize database pool");
        encrypt_cleanup();
        config_free(config);
        return 1;
    }
    if (config->db_type != DB_TYPE_SQLITE) {
        for (int i = 0; i < num_workers; i++) {
            int rc = db_set_session_hook(db_pool_get_connection_by_index(i), hold_instance_lock);
            if (rc != 0) {
                if (rc == 1) log_error("A maintenance run holds the database: start after it finishes");
                db_pool_shutdown();
                encrypt_cleanup();
                config_free(config);
                return 1;
            }
        }
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

    /* The field keys, from encryption_key as the database stretches it */
    int keys_rc = init_field_keys(setup_db, config);
    OPENSSL_cleanse(config->encryption_key, strlen(config->encryption_key));
    if (keys_rc != 0) {
        db_pool_shutdown();
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
    if (config->db_type != DB_TYPE_SQLITE) cleaner_cfg.session_hook = hold_instance_lock;
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
        .admin_socket = admin_socket_of(config),
        .admin_socket_mode = config->admin_socket_mode,
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
    int serve_rc = event_loop_pool_start(pool);

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
    validation_cleanup();
    db_pool_shutdown();
    instance_lock_release_all();
    encrypt_cleanup();
    crypto_hmac_cleanup();
    config_free(config);

    log_info("=== Auth Server Stopped ===");
    return (serve_rc != 0 || atomic_load(&g_lock_lost)) ? 1 : 0;
}
