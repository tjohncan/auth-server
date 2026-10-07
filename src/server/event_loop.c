/* Define _GNU_SOURCE for SO_REUSEPORT and accept4 */
#define _GNU_SOURCE

#include "server/event_loop.h"
#include "server/http.h"
#include "util/log.h"
#include "util/str.h"
#include "db/db_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/crypto.h>

/* ============================================================================
 * Constants and Defaults
 * ============================================================================ */

#define DEFAULT_BACKLOG 128
#define DEFAULT_MAX_REQUEST_SIZE (1 * 1024 * 1024)  /* 1MB */
#define DEFAULT_CONNECTION_TIMEOUT_MS 30000         /* 30 seconds */
#define INITIAL_READ_BUFFER_SIZE 4096               /* 4KB initial buffer */

/* Ceiling on the header block: the CRLFCRLF that ends it has to fall within the
 * first MAX_HEADER_BYTES bytes, or the request is refused. That is the header-block
 * total nginx allows by default — large_client_header_buffers is `4 8k`, four
 * buffers of 8 KB each, with any single line capped at 8 KB — so this is not a
 * guess at what is generous, it is the ceiling the edge in front of us already
 * enforces. The rule is on where the block ends, not on how many bytes have arrived
 * when a check runs, so a request passes or fails the same way however the network
 * splits it into reads. The read buffer doubles (4, 8, 16, 32 KB), so this is also
 * the most an unterminated block can occupy.
 * Without it a client can make every connection buffer max_request_size of headers
 * that will never be parsed. That bounds memory, not time: the idle timeout can't
 * close such a connection, because last_activity is refreshed on every recv, so
 * close_idle_connections also gives a request a deadline from the connection's
 * opening. Applies only before the delimiter is found; after it the body is entitled
 * to grow to max_request_size, which is what that limit is for. */
#define MAX_HEADER_BYTES 32768
#define MAX_EPOLL_EVENTS 1024                       /* Process up to 1024 events per epoll_wait */

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/* Connection IDs come from one counter for the whole process, not one per worker:
 * the ID is how log lines from the same request are tied together, and with a
 * counter per worker every worker hands out the same numbers at once. One
 * uncontended atomic increment per accepted connection. */
static atomic_uint_fast64_t g_next_connection_id = 1;

/*
 * EventLoop - One epoll instance, runs on one thread
 */
struct EventLoop {
    int epoll_fd;                 /* epoll file descriptor */
    atomic_bool running;          /* Set to false to stop the loop */
    EventLoopConfig config;       /* Configuration (copied) */
    int worker_index;             /* Index of this worker (for DB connection binding) */
    struct EventLoopPool *pool;   /* Its pool, stopped if this loop can't run */

    /* Listening sockets, opened by the pool before any worker starts: this
       worker's public one (-1: none), and the process's admin ones, shared */
    int public_fd;
    int admin_fds[3];
    int admin_fd_count;

    /* Doubly-linked list of all active connections (for timeout enforcement) */
    Connection *connections_head;
    Connection *connections_tail;
    int active_connections;        /* Current count of active connections */
};

/*
 * Listener - One listening socket. Its epoll event carries a pointer to this,
 * which is how its events are told from a connection's.
 */
typedef struct {
    int fd;
    int admin;                    /* The loopback admin listener, not the public one */

    /* accept4() failed for want of descriptors or memory, with connections maybe
     * still queued: retried on every pass of the loop until it succeeds */
    bool accept_failing;
} Listener;

/*
 * EventLoopPool - Manages multiple worker threads
 */
struct EventLoopPool {
    EventLoopConfig config;       /* Configuration */
    int num_workers;              /* Number of worker threads */
    pthread_t *worker_threads;    /* Array of worker thread handles */
    EventLoop **event_loops;      /* One EventLoop per worker */
    atomic_bool running;          /* Set to false to stop all workers */
    atomic_bool failed;           /* A worker's loop couldn't run */
    int admin_fds[3];             /* The admin listener's sockets: a Unix one, and loopback
                                     TCP per family */
    int admin_fd_count;
    char *admin_socket_path;      /* The Unix socket this process made, removed at the end */
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * create_listen_socket - Create dual-stack TCP socket (IPv4 + IPv6)
 *
 * Uses SO_REUSEPORT so multiple threads can accept on the same port.
 * Creates IPv6 socket with IPV6_V6ONLY=0 to accept both IPv4 and IPv6.
 * IPv4 connections appear as IPv4-mapped IPv6 addresses (::ffff:192.0.2.1).
 *
 * Every descriptor the event loop opens -- this one, each accepted connection,
 * each epoll instance -- is non-blocking (blocking I/O would hang the loop) and
 * close-on-exec, both set atomically at creation. Close-on-exec keeps them out of
 * the email command (util/email.c), which would otherwise hold a client's
 * connection open after the worker closed it, and could keep a listening socket
 * in SO_REUSEPORT's group past a restart, where connections queue unaccepted.
 */
static int create_listen_socket(int port, int backlog) {
    /* Create IPv6 socket (supports both IPv4 and IPv6 when IPV6_V6ONLY=0) */
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("socket(AF_INET6) failed: %s", strerror(errno));
        return -1;
    }

    /* Disable IPV6_V6ONLY to accept both IPv4 and IPv6 (dual-stack) */
    int opt = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(IPV6_V6ONLY) failed: %s - IPv4 may not work", strerror(errno));
    }

    /* SO_REUSEADDR: Allow reusing port immediately after restart */
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }

    /* SO_REUSEPORT: Allow multiple threads to bind to same port (Linux 3.9+)
     * Kernel distributes incoming connections across all listening sockets.
     * This is the magic that makes multi-threaded accept work! */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        log_error("setsockopt(SO_REUSEPORT) failed: %s", strerror(errno));
        log_error("Multi-threaded accept requires Linux 3.9+ with SO_REUSEPORT support");
        close(fd);
        return -1;
    }

    /* Bind to :: (IPv6 any address, includes 0.0.0.0 when IPV6_V6ONLY=0) */
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;  /* :: (includes 0.0.0.0 for IPv4) */
    addr.sin6_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("bind() failed on port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }

    /* Listen */
    if (listen(fd, backlog) < 0) {
        log_error("listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_info("Created dual-stack listen socket on port %d (IPv4+IPv6, fd=%d)", port, fd);
    return fd;
}

/*
 * claim_public_port - Is the public port free of every other process?
 *
 * The public listener is a group of SO_REUSEPORT sockets, one per worker, and
 * Linux lets any process running as the same user join that group: a second
 * deployment on the same port would share it, and the kernel would split
 * connections between the two databases. A socket without SO_REUSEPORT can't
 * bind a port anyone listens on, so one is bound and closed first, and a port
 * held refuses the start. SO_REUSEADDR still lets a restart past its
 * predecessor's connections in TIME_WAIT.
 *
 * Returns: 0, or -1 (logged)
 */
static int claim_public_port(int port) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("socket(AF_INET6) failed: %s", strerror(errno));
        return -1;
    }
    int opt = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(IPV6_V6ONLY) failed: %s - IPv4 may not work", strerror(errno));
    }
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(fd);
    if (rc == 0) return 0;
    if (err == EADDRINUSE) {
        log_error("server_port %d is in use: another program, or another deployment of this "
                  "server, holds it. Each deployment on a host needs a server_port of its own "
                  "(auth.conf, or AUTH_SERVER_PORT).", port);
    } else {
        log_error("bind() failed on port %d: %s", port, strerror(err));
    }
    return -1;
}

/*
 * create_loopback_listen_socket - One loopback address only, for the admin listener
 *
 * Loopback has no dual-stack form: a socket on ::1 doesn't take connections to
 * 127.0.0.1. So the admin listener is one socket per family: 127.0.0.1 always,
 * and ::1 where the host has it. A container without IPv6 may have no ::1 at
 * all (EADDRNOTAVAIL), or no IPv6 sockets (EAFNOSUPPORT); either way the admin
 * listener goes on without it. CLOEXEC and non-blocking, as for the public socket.
 *
 * Not SO_REUSEPORT: each socket is opened once per process and shared by its
 * workers, so a port another process holds refuses this one at startup. With
 * SO_REUSEPORT, two deployments on one host under one user would share the
 * port, and the kernel would split admin calls between their databases.
 *
 * Returns: the descriptor, -2 for an IPv6 loopback this host doesn't have, -1 on error
 */
static int create_loopback_listen_socket(int family, int port, int backlog) {
    const char *name = family == AF_INET ? "127.0.0.1" : "[::1]";

    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (family == AF_INET6 && errno == EAFNOSUPPORT) return -2;
        log_error("socket() for the admin listener on %s failed: %s", name, strerror(errno));
        return -1;
    }

    int opt = 1;
    if (family == AF_INET6 &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(IPV6_V6ONLY) on the admin listener failed: %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }

    int rc;
    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;
        addr.sin6_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    }
    if (rc < 0) {
        int err = errno;
        close(fd);
        if (family == AF_INET6 && err == EADDRNOTAVAIL) return -2;
        if (err == EADDRINUSE) {
            log_error("admin_port %d is in use on %s: another program, or another deployment of "
                      "this server, holds it. Each deployment on a host needs an admin_port of "
                      "its own (auth.conf, or AUTH_ADMIN_PORT).", port, name);
        } else {
            log_error("bind() failed for the admin listener on %s:%d: %s", name, port,
                      strerror(err));
        }
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        log_error("listen() failed on the admin listener: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_info("Created admin listen socket on %s:%d (loopback only, fd=%d)", name, port, fd);
    return fd;
}


/* The first directory on path, from / down, that every user can write: into
   found, 1; 0 if there's none. Missing ones are skipped. */
static int world_writable_dir_on(const char *path, char *found, size_t size) {
    char prefix[PATH_MAX];
    size_t len = strlen(path);
    for (size_t i = 0; i <= len; i++) {
        if (i < len && path[i] != '/') continue;
        size_t n = i == 0 ? 1 : i;  /* the root, then each directory below it */
        if (n >= sizeof(prefix)) return 0;
        memcpy(prefix, path, n);
        prefix[n] = '\0';
        struct stat st;
        if (stat(prefix, &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & S_IWOTH)) {
            snprintf(found, size, "%s", prefix);
            return 1;
        }
    }
    return 0;
}

int admin_socket_dir_private(const char *path, int owner_too, char *reason, size_t size) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        snprintf(dir, sizeof(dir), ".");
    } else if (slash == dir) {
        dir[1] = '\0';
    } else {
        *slash = '\0';
    }

    /* Every directory on the way, as written and as it resolves: one every user
       can write lets anyone make or swap what's below it */
    char absolute[PATH_MAX], resolved[PATH_MAX], found[PATH_MAX];
    if (dir[0] == '/') {
        snprintf(absolute, sizeof(absolute), "%s", dir);
    } else if (!getcwd(resolved, sizeof(resolved)) ||
               snprintf(absolute, sizeof(absolute), "%s/%s", resolved, dir) >= (int)sizeof(absolute)) {
        absolute[0] = '\0';
    }
    if ((absolute[0] && world_writable_dir_on(absolute, found, sizeof(found))) ||
        (realpath(dir, resolved) && world_writable_dir_on(resolved, found, sizeof(found)))) {
        snprintf(reason, size, "%s, on its path, is writable by every user", found);
        return 0;
    }

    struct stat st;
    if (stat(dir, &st) != 0) return 1;  /* not there yet: the server makes it, 0700 */
    if (owner_too && st.st_uid != geteuid() && st.st_uid != 0) {
        snprintf(reason, size, "its directory %s belongs to another user (uid %u)", dir,
                 (unsigned)st.st_uid);
        return 0;
    }
    return 1;
}

/*
 * create_unix_listen_socket - The admin listener on a Unix socket at path
 *
 * Who may connect is the file's mode: 0600 lets only the server's own user (and
 * root) in, 0660 its group too. It's set before listen(), so no connection is
 * ever taken under a looser one. Who may replace it is its directory's: one
 * every user can write, or another user's, is refused (admin_socket_dir_private).
 * A file already at the path is left alone unless it's a socket that refuses
 * connections, one a server left when it stopped: a live one is another
 * server's, one this user may not connect to may be another user's, and
 * anything else isn't ours to remove. The directory is made (0700) if it's
 * missing, one level, as ./data may be on PostgreSQL.
 *
 * Returns: the descriptor, or -1 (logged)
 */
static int create_unix_listen_socket(const char *path, int mode, int backlog) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        log_error("admin_socket %s is too long: a Unix socket path takes at most %zu bytes",
                  path, sizeof(addr.sun_path) - 1);
        return -1;
    }
    memcpy(addr.sun_path, path, strlen(path) + 1);

    char reason[1100];
    if (!admin_socket_dir_private(path, 1, reason, sizeof(reason))) {
        log_error("admin_socket %s can't be used: %s, so someone else could put a directory or "
                  "a socket of their own on the path and receive the operator's calls. Put it "
                  "where no directory up to / is writable by every user, as /tmp is (./data, the "
                  "default, is such a place in the usual layouts).", path, reason);
        return -1;
    }

    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            log_error("admin_socket %s exists and isn't a socket: not replacing it", path);
            return -1;
        }
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe < 0) {
            log_error("socket(AF_UNIX) to try admin_socket %s failed: %s", path, strerror(errno));
            return -1;
        }
        int rc = connect(probe, (struct sockaddr *)&addr, sizeof(addr));
        int err = errno;
        close(probe);
        if (rc == 0) {
            log_error("admin_socket %s is in use: another server answers on it. Each deployment "
                      "needs an admin_socket of its own.", path);
            return -1;
        }
        if (err != ECONNREFUSED && err != ENOENT) {
            log_error("admin_socket %s is there, and this server can't try it (%s): it may be "
                      "another user's server's, so it isn't replaced.", path, strerror(err));
            return -1;
        }
        if (err == ECONNREFUSED && unlink(path) != 0 && errno != ENOENT) {
            log_error("admin_socket %s was left by a server that stopped, and can't be removed: %s",
                      path, strerror(errno));
            return -1;
        }
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("socket(AF_UNIX) for the admin listener failed: %s", strerror(errno));
        return -1;
    }
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno == ENOENT) {
        /* The directory isn't there: make it, one level, and try again */
        char dir[sizeof(addr.sun_path)];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) {
            *slash = '\0';
            if (mkdir(dir, 0700) == 0) {
                log_info("Made %s for the admin socket", dir);
                rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
            }
        }
    }
    if (rc < 0) {
        log_error("bind() failed for the admin socket %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (chmod(path, (mode_t)mode) != 0) {
        log_error("chmod(%04o) failed for the admin socket %s: %s", mode, path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        log_error("listen() failed on the admin socket: %s", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    log_info("Created admin listen socket at %s (mode %04o, fd=%d)", path, mode, fd);
    return fd;
}

/* ============================================================================
 * Connection Management
 * ============================================================================ */

/*
 * connection_create - Allocate and initialize a new connection
 */
static Connection *connection_create(int fd, const char *remote_ip, uint64_t connection_id,
                                     int admin_listener) {
    Connection *conn = malloc(sizeof(Connection));
    if (!conn) {
        log_error("Failed to allocate connection");
        return NULL;
    }

    memset(conn, 0, sizeof(Connection));
    conn->fd = fd;
    conn->admin_listener = admin_listener;
    conn->state = CONN_STATE_READING_HEADERS;
    conn->connection_id = connection_id;
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    conn->opened_at = conn->last_activity;

    /* Allocate initial read buffer */
    conn->read_buffer = malloc(INITIAL_READ_BUFFER_SIZE);
    if (!conn->read_buffer) {
        log_error("Failed to allocate read buffer");
        free(conn);
        return NULL;
    }
    conn->read_buffer_size = INITIAL_READ_BUFFER_SIZE;
    conn->bytes_read = 0;
    conn->header_end = 0;
    conn->total_needed = 0;

    /* Copy remote IP */
    str_copy(conn->remote_ip, sizeof(conn->remote_ip), remote_ip);

    /* Linked list pointers initialized to NULL by memset */

    log_debug("Created connection %lu from %s (fd=%d)", connection_id, remote_ip, fd);
    return conn;
}

/*
 * list_add_connection - Add connection to event loop's linked list
 */
static void list_add_connection(EventLoop *loop, Connection *conn) {
    conn->next = NULL;
    conn->prev = loop->connections_tail;

    if (loop->connections_tail) {
        loop->connections_tail->next = conn;
    } else {
        loop->connections_head = conn;  /* First connection */
    }

    loop->connections_tail = conn;
    loop->active_connections++;
}

/*
 * list_remove_connection - Remove connection from event loop's linked list
 */
static void list_remove_connection(EventLoop *loop, Connection *conn) {
    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        loop->connections_head = conn->next;  /* Was head */
    }

    if (conn->next) {
        conn->next->prev = conn->prev;
    } else {
        loop->connections_tail = conn->prev;  /* Was tail */
    }

    conn->next = NULL;
    conn->prev = NULL;
    loop->active_connections--;
}

/*
 * connection_destroy - Free connection and all its resources
 */
static void connection_destroy(Connection *conn) {
    if (!conn) return;

    log_debug("Destroying connection %lu (fd=%d)", conn->connection_id, conn->fd);

    if (conn->fd >= 0) {
        close(conn->fd);
    }

    if (conn->read_buffer)
        OPENSSL_cleanse(conn->read_buffer, conn->read_buffer_size);
    free(conn->read_buffer);
    if (conn->write_buffer)
        OPENSSL_cleanse(conn->write_buffer, conn->write_buffer_size);
    free(conn->write_buffer);
    /* Note: userdata points to shared context (router), not connection-owned memory */
    free(conn);
}

/* ============================================================================
 * Event Loop Core
 * ============================================================================ */

/*
 * event_loop_create - Create a new event loop (one epoll instance)
 */
EventLoop *event_loop_create(void) {
    EventLoop *loop = malloc(sizeof(EventLoop));
    if (!loop) {
        log_error("Failed to allocate EventLoop");
        return NULL;
    }

    memset(loop, 0, sizeof(EventLoop));

    /* Create epoll instance (close-on-exec: see create_listen_socket) */
    loop->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epoll_fd < 0) {
        log_error("epoll_create1() failed: %s", strerror(errno));
        free(loop);
        return NULL;
    }

    loop->running = false;
    loop->connections_head = NULL;
    loop->connections_tail = NULL;
    loop->public_fd = -1;

    log_debug("Created event loop (epoll_fd=%d)", loop->epoll_fd);
    return loop;
}

/*
 * event_loop_destroy - Free event loop resources
 */
void event_loop_destroy(EventLoop *loop) {
    if (!loop) return;

    /* Free all active connections */
    Connection *conn = loop->connections_head;
    while (conn) {
        Connection *next = conn->next;
        connection_destroy(conn);
        conn = next;
    }

    if (loop->epoll_fd >= 0) {
        close(loop->epoll_fd);
    }
    if (loop->public_fd >= 0) {
        close(loop->public_fd);
    }

    free(loop);
}

/*
 * handle_accept - Accept new connections and add to epoll
 *
 * IMPORTANT: With edge-triggered epoll, we must accept ALL pending connections
 * in a loop until EAGAIN. Otherwise queued connections won't trigger notifications.
 *
 * Supports both IPv4 and IPv6 connections (dual-stack).
 */
static void handle_accept(EventLoop *loop, Listener *listener) {
    /* Loop until no more connections to accept */
    while (1) {
        struct sockaddr_storage client_addr;  /* Large enough for both IPv4 and IPv6 */
        socklen_t client_len = sizeof(client_addr);

        /* Accept new connection (non-blocking, may return EAGAIN). The connection
         * itself comes back non-blocking and close-on-exec: see create_listen_socket. */
        int client_fd = accept4(listener->fd, (struct sockaddr *)&client_addr, &client_len,
                                SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No more connections to accept right now - this is normal */
                return;
            }

            /* That connection failed before we took it (accept(2) passes a new
             * socket's pending network errors this way): the next may be fine */
            if (errno == EINTR || errno == ECONNABORTED || errno == EPROTO ||
                errno == ENETDOWN || errno == ENOPROTOOPT || errno == EHOSTDOWN ||
                errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH
#ifdef ENONET
                || errno == ENONET
#endif
                ) {
                continue;
            }

            /* Out of descriptors or memory (EMFILE, ENFILE, ENOBUFS, ENOMEM). The
             * listening socket is edge-triggered, so connections still queued won't
             * be announced again until another arrives: the loop retries on its
             * next pass instead, at least once a second. Logged once until it
             * clears, since every retry fails the same way. */
            if (!listener->accept_failing) {
                log_error("accept4() failed: %s; retrying until it clears", strerror(errno));
            }
            listener->accept_failing = true;
            return;
        }

        if (listener->accept_failing) {
            log_info("accept4() is accepting connections again");
            listener->accept_failing = false;
        }

        /* Reject if at connection limit. Not on the admin listener: only the host
         * can reach it, and a flood on the public port mustn't lock the operator
         * out of the admin API, which is how they'd respond to one. */
        if (!listener->admin && loop->config.max_connections_per_worker > 0 &&
            loop->active_connections >= loop->config.max_connections_per_worker) {
            close(client_fd);
            log_warn("Connection limit reached (%d), rejecting new connection",
                    loop->active_connections);
            continue;
        }

        /* Get client IP (handle both IPv4 and IPv6) */
        char remote_ip[INET6_ADDRSTRLEN];
        if (client_addr.ss_family == AF_INET) {
            /* IPv4 connection */
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, remote_ip, sizeof(remote_ip));
        } else if (client_addr.ss_family == AF_INET6) {
            /* IPv6 connection (or IPv4-mapped IPv6) */
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, remote_ip, sizeof(remote_ip));
        } else if (client_addr.ss_family == AF_UNIX) {
            /* The admin socket: no address, but the kernel says who connected */
            snprintf(remote_ip, sizeof(remote_ip), "local");
            struct ucred cred;
            socklen_t cred_len = sizeof(cred);
            if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0) {
                log_info("Admin socket connection from uid %u (pid %d)",
                         (unsigned)cred.uid, (int)cred.pid);
            }
        } else {
            /* Unknown address family */
            snprintf(remote_ip, sizeof(remote_ip), "unknown");
        }

        /* Create connection object */
        Connection *conn = connection_create(client_fd, remote_ip,
                                             atomic_fetch_add(&g_next_connection_id, 1),
                                             listener->admin);
        if (!conn) {
            close(client_fd);
            continue;  /* Try next connection */
        }

        /* Add to epoll (edge-triggered, watch for reads) */
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;  /* Edge-triggered: only notified once per state change */
        ev.data.ptr = conn;             /* Store connection pointer in event */

        if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            log_error("epoll_ctl(ADD) failed: %s", strerror(errno));
            connection_destroy(conn);
            continue;  /* Try next connection */
        }

        /* Add to connection list for timeout tracking */
        list_add_connection(loop, conn);

        log_info("Accepted connection %lu from %s (fd=%d)%s", conn->connection_id, remote_ip,
                 client_fd, listener->admin ? " on the admin listener" : "");
    }  /* End of while(1) loop */
}

/*
 * handle_read - Read data from connection
 *
 * Returns: 0 if more data expected, 1 if request complete, -1 on error/close
 */
static int handle_read(Connection *conn, size_t max_request_size) {
    while (1) {
        /* Grow buffer if needed */
        if (conn->bytes_read >= conn->read_buffer_size) {
            if (conn->read_buffer_size >= max_request_size) {
                log_warn("Request too large from connection %lu", conn->connection_id);
                return -1;  /* Request too big */
            }

            size_t new_size = conn->read_buffer_size * 2;
            if (new_size > max_request_size) {
                new_size = max_request_size;
            }

            char *new_buffer = realloc(conn->read_buffer, new_size);
            if (!new_buffer) {
                log_error("Failed to grow read buffer");
                return -1;
            }

            conn->read_buffer = new_buffer;
            conn->read_buffer_size = new_size;
        }

        /* Read into buffer */
        ssize_t n = recv(conn->fd, conn->read_buffer + conn->bytes_read,
                        conn->read_buffer_size - conn->bytes_read, 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No more data available right now (edge-triggered) */
                return 0;
            }
            log_error("recv() failed on connection %lu: %s", conn->connection_id, strerror(errno));
            return -1;
        }

        if (n == 0) {
            /* Client closed connection */
            log_debug("Client closed connection %lu", conn->connection_id);
            return -1;
        }

        size_t scanned_before = conn->bytes_read;
        conn->bytes_read += n;
        clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);

        /* Locate the end of the header block ONCE. Resuming rather than
         * restarting is what keeps this linear: a header block that never
         * terminates otherwise rescans everything received so far on every
         * single byte. */
        if (!conn->header_end) {
            conn->header_end = http_find_header_end(conn->read_buffer, conn->bytes_read,
                                                    scanned_before);

            /* Judged by where the block ends: past the limit, or not ended
             * anywhere within it, whichever read the bytes came in */
            if (conn->header_end > MAX_HEADER_BYTES ||
                (!conn->header_end && conn->bytes_read >= MAX_HEADER_BYTES)) {
                log_warn("Header block exceeds %d bytes on connection %lu, closing",
                         MAX_HEADER_BYTES, conn->connection_id);
                return -1;
            }

            if (!conn->header_end) {
                continue;  /* headers still incomplete */
            }

            /* Everything below reads the header block, so it runs once per
             * request rather than once per chunk. */
            size_t content_length = 0;
            int cl_result = http_scan_content_length(conn->read_buffer, conn->header_end,
                                                     &content_length);

            if (cl_result == -3) {
                /* The parser would stop reading header lines at the NUL, short of
                 * what framed the request here */
                log_warn("Rejecting request with a NUL in its header block from connection %lu",
                        conn->connection_id);
                return -1;
            }

            if (cl_result == -2) {
                /* Multiple/conflicting Content-Length headers (request smuggling attack) */
                log_warn("Rejecting request with conflicting Content-Length headers from connection %lu",
                        conn->connection_id);
                return -1;
            }

            if (cl_result == -1) {
                /* Not 1*DIGIT: the framing is invalid (RFC 7230 §3.3.3), so there is
                 * no right number of body bytes to wait for */
                log_warn("Rejecting request with an invalid Content-Length from connection %lu",
                        conn->connection_id);
                return -1;
            }

            /* Reject Transfer-Encoding (chunked, etc.) - this server does not
             * support chunked transfer coding. If behind a reverse proxy,
             * it should reassemble chunks and forward with Content-Length.
             * A direct request with Transfer-Encoding is either a misconfigured
             * client or a request smuggling attempt. */
            if (memmem_nocase(conn->read_buffer, conn->header_end,
                       "\r\nTransfer-Encoding", 19) != NULL) {
                log_warn("Rejecting request with Transfer-Encoding header from connection %lu",
                        conn->connection_id);
                return -1;
            }

            if (cl_result != 0) {
                /* No Content-Length (cl_result == 1), request is complete (GET/HEAD/etc.) */
                log_debug("Received complete request (%zu bytes) from connection %lu",
                         conn->bytes_read, conn->connection_id);
                return 1;
            }

            conn->total_needed = conn->header_end + content_length;

            if (conn->total_needed > max_request_size) {
                log_warn("Request body too large (%zu bytes) from connection %lu",
                        content_length, conn->connection_id);
                return -1;
            }
        }

        if (conn->bytes_read >= conn->total_needed) {
            /* Have complete request including body */
            log_debug("Received complete request with body (%zu bytes) from connection %lu",
                     conn->bytes_read, conn->connection_id);
            return 1;
        }

        /* Need more bytes for body - keep reading */
    }
}

/*
 * handle_write - Write response data to connection
 *
 * Returns: 0 if more data to write, 1 if write complete, -1 on error
 */
static int handle_write(Connection *conn) {
    while (conn->bytes_written < conn->write_buffer_size) {
        ssize_t n = send(conn->fd,
                        conn->write_buffer + conn->bytes_written,
                        conn->write_buffer_size - conn->bytes_written,
                        0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Socket buffer full, try again later */
                return 0;
            }
            log_error("send() failed on connection %lu: %s", conn->connection_id, strerror(errno));
            return -1;
        }

        conn->bytes_written += n;
        clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    }

    /* All data written */
    log_debug("Wrote complete response (%zu bytes) to connection %lu",
             conn->write_buffer_size, conn->connection_id);
    return 1;
}

/*
 * close_connection - Remove from epoll, list, and free
 */
static void close_connection(EventLoop *loop, Connection *conn) {
    epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    list_remove_connection(loop, conn);
    connection_destroy(conn);
}

/*
 * handle_connection_event - Process epoll event for a connection
 */
static void handle_connection_event(EventLoop *loop, Connection *conn, uint32_t events) {
    /* Check for errors or hangup */
    if (events & (EPOLLERR | EPOLLHUP)) {
        log_debug("Connection %lu error/hangup", conn->connection_id);
        close_connection(loop, conn);
        return;
    }

    /* Readable event */
    if (events & EPOLLIN) {
        int result = handle_read(conn, loop->config.max_request_size);

        if (result < 0) {
            /* Error or close */
            close_connection(loop, conn);
            return;
        }

        if (result == 1) {
            /* Request complete - call handler */
            char *response = NULL;
            size_t response_len = 0;

            /* Pass handler context through connection userdata */
            conn->userdata = loop->config.handler_context;

            int handler_result = loop->config.handler(conn,
                                                     conn->read_buffer, conn->bytes_read,
                                                     &response, &response_len);

            if (handler_result < 0 || !response) {
                log_error("Handler failed for connection %lu", conn->connection_id);
                close_connection(loop, conn);
                return;
            }

            /* Store response for writing */
            conn->write_buffer = response;
            conn->write_buffer_size = response_len;
            conn->bytes_written = 0;
            conn->state = CONN_STATE_WRITING_RESPONSE;

            /* Modify epoll to watch for writes */
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.ptr = conn;
            if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) == -1) {
                log_error("[Connection %lu] epoll_ctl(EPOLL_CTL_MOD) failed: %s",
                         conn->connection_id, strerror(errno));
                close_connection(loop, conn);
                return;
            }
        }
    }

    /* Writable event */
    if (events & EPOLLOUT) {
        int result = handle_write(conn);

        if (result < 0) {
            /* Write error */
            close_connection(loop, conn);
            return;
        }

        if (result == 1) {
            /* Write complete - close connection (HTTP/1.0 no keep-alive) */
            close_connection(loop, conn);
        }
    }
}

/*
 * close_idle_connections - Check for and close timed-out connections
 *
 * Idle is measured from the last byte either way, so a client trickling a byte
 * every few seconds is never idle: one every 29 s held a connection through a
 * 32 KB header block for about eleven days. So a request also has to arrive
 * whole within the same timeout of its connection opening, however steadily it
 * trickles. One request per connection (HTTP/1.0, closed after the response),
 * so the connection's age is the request's.
 */
static void close_idle_connections(EventLoop *loop) {
    if (loop->config.connection_timeout_ms <= 0) return;  /* Timeout disabled */

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    Connection *conn = loop->connections_head;
    while (conn) {
        Connection *next = conn->next;  /* Save next before potential free */

        long idle_ms = (now.tv_sec - conn->last_activity.tv_sec) * 1000
                     + (now.tv_nsec - conn->last_activity.tv_nsec) / 1000000;
        long age_ms = (now.tv_sec - conn->opened_at.tv_sec) * 1000
                    + (now.tv_nsec - conn->opened_at.tv_nsec) / 1000000;
        if (idle_ms >= loop->config.connection_timeout_ms) {
            log_info("Closing idle connection %lu (idle for %ldms)",
                    conn->connection_id, idle_ms);
            close_connection(loop, conn);
        } else if (conn->state == CONN_STATE_READING_HEADERS &&
                   age_ms >= loop->config.connection_timeout_ms) {
            log_info("Closing connection %lu: its request didn't arrive within %dms",
                    conn->connection_id, loop->config.connection_timeout_ms);
            close_connection(loop, conn);
        }

        conn = next;
    }
}

/*
 * event_loop_run - Run the event loop (main loop)
 *
 * This is the heart of the event loop:
 * 1. Call epoll_wait() - blocks until events arrive
 * 2. Process each event (accept, read, write)
 * 3. Repeat forever until stopped
 */
int event_loop_run(EventLoop *loop, RequestHandler handler, void *context) {
    if (!loop || !handler) return -1;

    loop->config.handler = handler;
    loop->config.handler_context = context;
    loop->running = true;

    /* Listening sockets, which the pool opened before the server said it was
     * ready: this worker's public one on every interface, then the admin
     * listener's on loopback only, which every worker shares (an accept that
     * loses the race to another worker gets EAGAIN, and waits for the next) */
    if (loop->public_fd < 0) {
        log_error("Event loop %d has no listening socket", loop->worker_index);
        return -1;
    }
    Listener listeners[4];
    int listener_count = 0;
    listeners[listener_count++] = (Listener){ .fd = loop->public_fd, .admin = 0 };
    for (int i = 0; i < loop->admin_fd_count; i++) {
        listeners[listener_count++] = (Listener){ .fd = loop->admin_fds[i], .admin = 1 };
    }

    /* Each listening socket's events carry a pointer to its Listener */
    for (int i = 0; i < listener_count; i++) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.ptr = &listeners[i];

        if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, listeners[i].fd, &ev) < 0) {
            log_error("epoll_ctl(ADD listen) failed: %s", strerror(errno));
            return -1;
        }
    }

    log_info("Event loop running on port %d, admin port %d", loop->config.port,
             loop->config.admin_port);

    /* Event array for epoll_wait */
    struct epoll_event events[MAX_EPOLL_EVENTS];

    /* Track last timeout check to avoid excessive scanning under load */
    time_t last_timeout_check = time(NULL);

    /* Main loop */
    while (loop->running) {
        /* Wait for events (timeout: 1 second) */
        int n = epoll_wait(loop->epoll_fd, events, MAX_EPOLL_EVENTS, 1000);

        if (n < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal (e.g., Ctrl+C) - check running flag */
                continue;
            }
            log_error("epoll_wait() failed: %s", strerror(errno));
            break;
        }

        /* Process each event */
        for (int i = 0; i < n; i++) {
            Listener *listener = NULL;
            for (int j = 0; j < listener_count && !listener; j++) {
                if (events[i].data.ptr == &listeners[j]) listener = &listeners[j];
            }
            if (listener) {
                /* New connection on a listening socket */
                handle_accept(loop, listener);
            } else {
                /* Event on existing connection */
                Connection *conn = (Connection *)events[i].data.ptr;
                handle_connection_event(loop, conn, events[i].events);
            }
        }

        /* Connections left queued by a failed accept: closing others above may
         * have freed what it lacked */
        for (int j = 0; j < listener_count; j++) {
            if (listeners[j].accept_failing) {
                handle_accept(loop, &listeners[j]);
            }
        }

        /* Check for idle connections every 5 seconds (wall-clock time)
         * This ensures timeouts are enforced even under sustained load */
        time_t now = time(NULL);
        if (now - last_timeout_check >= 5) {
            close_idle_connections(loop);
            last_timeout_check = now;
        }
    }

    log_info("Event loop stopped");
    return 0;
}

/*
 * event_loop_stop - Signal the loop to stop
 */
void event_loop_stop(EventLoop *loop) {
    if (loop) {
        loop->running = false;
    }
}

/* ============================================================================
 * Worker Thread
 * ============================================================================ */

/*
 * Worker thread function - each worker runs its own event loop
 */
static void *worker_thread_func(void *arg) {
    EventLoop *loop = (EventLoop *)arg;

    log_info("Worker thread %d started (tid=%lu)", loop->worker_index, (unsigned long)pthread_self());

    /* Bind database connection to this thread */
    db_handle_t *db = db_pool_get_connection_by_index(loop->worker_index);
    if (db) {
        db_pool_set_connection(db);
        log_debug("Worker %d bound to database connection", loop->worker_index);
    } else {
        log_warn("Worker %d: No database connection available", loop->worker_index);
    }

    /* Run event loop (blocks until stopped). One that can't run stops every
       worker, and the server exits failing, rather than serving on fewer */
    if (event_loop_run(loop, loop->config.handler, loop->config.handler_context) != 0 &&
        loop->pool) {
        log_error("Worker %d couldn't run its event loop: stopping the server", loop->worker_index);
        atomic_store(&loop->pool->failed, true);
        event_loop_pool_stop_signal_safe(loop->pool);
    }

    if (loop->config.on_worker_exit)
        loop->config.on_worker_exit();

    log_info("Worker thread %d stopped (tid=%lu)", loop->worker_index, (unsigned long)pthread_self());
    return NULL;
}

/* ============================================================================
 * Event Loop Pool (Multi-Threaded)
 * ============================================================================ */

/*
 * event_loop_pool_create - Create pool of worker threads
 */
EventLoopPool *event_loop_pool_create(EventLoopConfig *config) {
    if (!config || !config->handler) {
        log_error("Invalid EventLoopConfig");
        return NULL;
    }

    EventLoopPool *pool = malloc(sizeof(EventLoopPool));
    if (!pool) {
        log_error("Failed to allocate EventLoopPool");
        return NULL;
    }

    memset(pool, 0, sizeof(EventLoopPool));

    /* Copy config */
    memcpy(&pool->config, config, sizeof(EventLoopConfig));

    pool->num_workers = config->num_workers;

    /* Set defaults */
    if (pool->config.backlog <= 0) pool->config.backlog = DEFAULT_BACKLOG;
    if (pool->config.max_request_size <= 0) pool->config.max_request_size = DEFAULT_MAX_REQUEST_SIZE;
    if (pool->config.connection_timeout_ms <= 0) pool->config.connection_timeout_ms = DEFAULT_CONNECTION_TIMEOUT_MS;

    log_info("Creating event loop pool with %d workers", pool->num_workers);

    /* Allocate worker arrays */
    pool->worker_threads = malloc(pool->num_workers * sizeof(pthread_t));
    pool->event_loops = malloc(pool->num_workers * sizeof(EventLoop *));

    if (!pool->worker_threads || !pool->event_loops) {
        log_error("Failed to allocate worker arrays");
        free(pool->worker_threads);
        free(pool->event_loops);
        free(pool);
        return NULL;
    }

    /* Create event loops (one per worker) */
    for (int i = 0; i < pool->num_workers; i++) {
        pool->event_loops[i] = event_loop_create();
        if (!pool->event_loops[i]) {
            /* Cleanup on error */
            for (int j = 0; j < i; j++) {
                event_loop_destroy(pool->event_loops[j]);
            }
            free(pool->worker_threads);
            free(pool->event_loops);
            free(pool);
            return NULL;
        }

        /* Copy config to each loop */
        memcpy(&pool->event_loops[i]->config, &pool->config, sizeof(EventLoopConfig));

        /* Set worker index for DB connection binding */
        pool->event_loops[i]->worker_index = i;
        pool->event_loops[i]->pool = pool;
    }

    /* Every listening socket, before the server says it's ready, so a port
       that can't be had stops the start: the admin listener's once for the
       process (127.0.0.1, and ::1 where the host has it), then each worker's
       public one, once no other process holds its port */
    int failed = 0;
    if (pool->config.admin_socket) {
        int fd = create_unix_listen_socket(pool->config.admin_socket,
                                           pool->config.admin_socket_mode, pool->config.backlog);
        pool->admin_socket_path = fd >= 0 ? strdup(pool->config.admin_socket) : NULL;
        if (fd < 0 || !pool->admin_socket_path) {
            if (fd >= 0) close(fd);
            failed = 1;
        } else {
            pool->admin_fds[pool->admin_fd_count++] = fd;
        }
    }
    if (pool->config.admin_port > 0 && !failed) {
        static const int families[] = { AF_INET, AF_INET6 };
        for (size_t f = 0; f < sizeof(families) / sizeof(families[0]) && !failed; f++) {
            int fd = create_loopback_listen_socket(families[f], pool->config.admin_port,
                                                   pool->config.backlog);
            if (fd == -2) {
                log_info("No IPv6 loopback here: the admin listener is on 127.0.0.1 only");
            } else if (fd < 0) {
                failed = 1;
            } else {
                pool->admin_fds[pool->admin_fd_count++] = fd;
            }
        }
    }
    if (!failed && claim_public_port(pool->config.port) != 0) {
        failed = 1;
    }
    for (int i = 0; i < pool->num_workers && !failed; i++) {
        EventLoop *loop = pool->event_loops[i];
        loop->public_fd = create_listen_socket(pool->config.port, pool->config.backlog);
        failed = loop->public_fd < 0;
        memcpy(loop->admin_fds, pool->admin_fds, sizeof(loop->admin_fds));
        loop->admin_fd_count = pool->admin_fd_count;
    }
    if (failed) {
        event_loop_pool_destroy(pool);
        return NULL;
    }

    pool->running = false;
    return pool;
}

/*
 * event_loop_pool_start - Start all workers
 */
int event_loop_pool_start(EventLoopPool *pool) {
    if (!pool) return -1;

    pool->running = true;

    log_info("Starting %d worker threads...", pool->num_workers);

    /* Start worker threads */
    for (int i = 0; i < pool->num_workers; i++) {
        if (pthread_create(&pool->worker_threads[i], NULL, worker_thread_func, pool->event_loops[i]) != 0) {
            log_error("Failed to create worker thread %d: %s", i, strerror(errno));

            /* Stop already-started threads */
            pool->running = false;
            for (int j = 0; j < i; j++) {
                event_loop_stop(pool->event_loops[j]);
            }

            /* Wait for them to finish */
            for (int j = 0; j < i; j++) {
                pthread_join(pool->worker_threads[j], NULL);
            }

            return -1;
        }
    }

    log_info("All workers started, listening on port %d", pool->config.port);

    /* Wait for all workers to finish */
    for (int i = 0; i < pool->num_workers; i++) {
        pthread_join(pool->worker_threads[i], NULL);
    }

    log_info("All workers stopped");
    return atomic_load(&pool->failed) ? -1 : 0;
}

/*
 * event_loop_pool_stop_signal_safe - Stop all workers (async-signal-safe)
 *
 * This version does NO logging and can be called from signal handlers.
 * It only sets boolean flags.
 */
void event_loop_pool_stop_signal_safe(EventLoopPool *pool) {
    if (!pool) return;

    pool->running = 0;

    /* Signal each event loop to stop */
    for (int i = 0; i < pool->num_workers; i++) {
        if (pool->event_loops[i]) {
            pool->event_loops[i]->running = 0;
        }
    }
}

/*
 * event_loop_pool_stop - Stop all workers
 */
void event_loop_pool_stop(EventLoopPool *pool) {
    if (!pool) return;

    log_info("Stopping event loop pool...");
    event_loop_pool_stop_signal_safe(pool);
}

/*
 * event_loop_pool_destroy - Cleanup
 */
void event_loop_pool_destroy(EventLoopPool *pool) {
    if (!pool) return;

    for (int i = 0; i < pool->num_workers; i++) {
        event_loop_destroy(pool->event_loops[i]);
    }
    for (int i = 0; i < pool->admin_fd_count; i++) {
        close(pool->admin_fds[i]);
    }
    if (pool->admin_socket_path) {
        unlink(pool->admin_socket_path);
        free(pool->admin_socket_path);
    }

    free(pool->worker_threads);
    free(pool->event_loops);
    free(pool);
}
