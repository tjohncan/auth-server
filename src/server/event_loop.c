/* Define _GNU_SOURCE for SO_REUSEPORT and memmem */
#define _GNU_SOURCE

#include "server/event_loop.h"
#include "util/log.h"
#include "util/str.h"
#include "db/db_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* ============================================================================
 * Constants and Defaults
 * ============================================================================ */

#define DEFAULT_BACKLOG 128
#define DEFAULT_MAX_REQUEST_SIZE (1 * 1024 * 1024)  /* 1MB */
#define DEFAULT_CONNECTION_TIMEOUT_MS 30000         /* 30 seconds */
#define INITIAL_READ_BUFFER_SIZE 4096               /* 4KB initial buffer */
#define MAX_EPOLL_EVENTS 1024                       /* Process up to 1024 events per epoll_wait */

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/*
 * EventLoop - One epoll instance, runs on one thread
 */
struct EventLoop {
    int epoll_fd;                 /* epoll file descriptor */
    atomic_bool running;          /* Set to false to stop the loop */
    uint64_t next_connection_id;  /* Monotonic counter for connection IDs */
    EventLoopConfig config;       /* Configuration (copied) */
    int worker_index;             /* Index of this worker (for DB connection binding) */

    /* Doubly-linked list of all active connections (for timeout enforcement) */
    Connection *connections_head;
    Connection *connections_tail;
    int active_connections;        /* Current count of active connections */
};

/*
 * EventLoopPool - Manages multiple worker threads
 */
struct EventLoopPool {
    EventLoopConfig config;       /* Configuration */
    int listen_fd;                /* Shared listen socket (SO_REUSEPORT) */
    int num_workers;              /* Number of worker threads */
    pthread_t *worker_threads;    /* Array of worker thread handles */
    EventLoop **event_loops;      /* One EventLoop per worker */
    atomic_bool running;          /* Set to false to stop all workers */
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * set_nonblocking - Make a socket non-blocking
 *
 * This is CRITICAL for event loops. Blocking I/O would hang the entire loop.
 */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_error("fcntl(F_GETFL) failed: %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_error("fcntl(F_SETFL) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * create_listen_socket - Create dual-stack TCP socket (IPv4 + IPv6)
 *
 * Uses SO_REUSEPORT so multiple threads can accept on the same port.
 * Creates IPv6 socket with IPV6_V6ONLY=0 to accept both IPv4 and IPv6.
 * IPv4 connections appear as IPv4-mapped IPv6 addresses (::ffff:192.0.2.1).
 */
static int create_listen_socket(int port, int backlog) {
    /* Create IPv6 socket (supports both IPv4 and IPv6 when IPV6_V6ONLY=0) */
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
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

    /* Make non-blocking */
    if (set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }

    log_info("Created dual-stack listen socket on port %d (IPv4+IPv6, fd=%d)", port, fd);
    return fd;
}

/*
 * get_cpu_count - Detect number of CPU cores
 */
static int get_cpu_count(void) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) {
        log_warn("Could not detect CPU count, defaulting to 1");
        return 1;
    }
    return (int)nprocs;
}

/* ============================================================================
 * Connection Management
 * ============================================================================ */

/*
 * connection_create - Allocate and initialize a new connection
 */
static Connection *connection_create(int fd, const char *remote_ip, uint64_t connection_id) {
    Connection *conn = malloc(sizeof(Connection));
    if (!conn) {
        log_error("Failed to allocate connection");
        return NULL;
    }

    memset(conn, 0, sizeof(Connection));
    conn->fd = fd;
    conn->state = CONN_STATE_READING_HEADERS;
    conn->connection_id = connection_id;
    conn->last_activity = time(NULL);  /* Track connection start time */

    /* Allocate initial read buffer */
    conn->read_buffer = malloc(INITIAL_READ_BUFFER_SIZE);
    if (!conn->read_buffer) {
        log_error("Failed to allocate read buffer");
        free(conn);
        return NULL;
    }
    conn->read_buffer_size = INITIAL_READ_BUFFER_SIZE;
    conn->bytes_read = 0;

    /* Copy remote IP */
    snprintf(conn->remote_ip, sizeof(conn->remote_ip), "%s", remote_ip);

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

    free(conn->read_buffer);
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

    /* Create epoll instance */
    loop->epoll_fd = epoll_create1(0);
    if (loop->epoll_fd < 0) {
        log_error("epoll_create1() failed: %s", strerror(errno));
        free(loop);
        return NULL;
    }

    loop->running = false;
    loop->next_connection_id = 1;
    loop->connections_head = NULL;
    loop->connections_tail = NULL;

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
static void handle_accept(EventLoop *loop, int listen_fd) {
    /* Loop until no more connections to accept */
    while (1) {
        struct sockaddr_storage client_addr;  /* Large enough for both IPv4 and IPv6 */
        socklen_t client_len = sizeof(client_addr);

        /* Accept new connection (non-blocking, may return EAGAIN) */
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No more connections to accept right now - this is normal */
                return;
            }
            log_error("accept() failed: %s", strerror(errno));
            return;
        }

        /* Reject if at connection limit */
        if (loop->config.max_connections_per_worker > 0 &&
            loop->active_connections >= loop->config.max_connections_per_worker) {
            close(client_fd);
            log_warn("Connection limit reached (%d), rejecting new connection",
                    loop->active_connections);
            continue;
        }

        /* Make client socket non-blocking */
        if (set_nonblocking(client_fd) < 0) {
            close(client_fd);
            continue;  /* Try next connection */
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
        } else {
            /* Unknown address family */
            snprintf(remote_ip, sizeof(remote_ip), "unknown");
        }

        /* Create connection object */
        Connection *conn = connection_create(client_fd, remote_ip, loop->next_connection_id++);
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

        log_info("Accepted connection %lu from %s (fd=%d)", conn->connection_id, remote_ip, client_fd);
    }  /* End of while(1) loop */
}

/*
 * extract_content_length - Quick scan for Content-Length header value
 *
 * Scans for "Content-Length: 123" without full HTTP parsing.
 * Used to determine if we need to read request body.
 *
 * SECURITY: Detects multiple Content-Length headers (request smuggling attack).
 * Per RFC 7230 Section 3.3.2: Multiple Content-Length with different values = REJECT.
 *
 * Returns: 0 if found (sets *out_length), -1 if not found, -2 if multiple/conflicting
 */
static int extract_content_length(const char *buffer, size_t buffer_len, size_t *out_length) {
    /* Look for "Content-Length:" (case-insensitive) */
    const char *p = buffer;
    const char *end = buffer + buffer_len;
    bool found = false;
    size_t first_value = 0;

    while (p < end) {
        /* Find next line */
        const char *line_start = p;
        const char *line_end = memmem(p, end - p, "\r\n", 2);
        if (!line_end) break;

        size_t line_len = line_end - line_start;

        /* Check if this line starts with "Content-Length:" (case-insensitive) */
        if (line_len > 15 && strncasecmp(line_start, "Content-Length:", 15) == 0) {
            /* Found it! Extract the number */
            const char *value_start = line_start + 15;

            /* Skip whitespace */
            while (value_start < line_end && (*value_start == ' ' || *value_start == '\t')) {
                value_start++;
            }

            /* Parse number */
            char *endptr;
            long length = strtol(value_start, &endptr, 10);

            /* Validate: at least one digit parsed, non-negative */
            if (endptr > value_start && length >= 0) {
                if (!found) {
                    /* First Content-Length header */
                    first_value = (size_t)length;
                    found = true;
                } else {
                    /* Multiple Content-Length headers! */
                    if (first_value != (size_t)length) {
                        /* Different values = request smuggling attack */
                        log_warn("Multiple Content-Length headers with different values detected");
                        return -2;
                    }
                    /* Same value = accept (redundant but harmless) */
                }
            }
        }

        /* Next line */
        p = line_end + 2;
    }

    if (found) {
        *out_length = first_value;
        return 0;  /* Success */
    }

    return -1;  /* Not found */
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

        conn->bytes_read += n;
        conn->last_activity = time(NULL);  /* Update activity timestamp */

        /* Check if we have complete HTTP headers (ends with \r\n\r\n) */
        if (conn->bytes_read >= 4) {
            char *end = memmem(conn->read_buffer, conn->bytes_read, "\r\n\r\n", 4);
            if (end) {
                /* Found end of headers! */
                size_t header_end_offset = (end - conn->read_buffer) + 4;

                /* Check for Content-Length to see if there's a body */
                size_t content_length = 0;
                int cl_result = extract_content_length(conn->read_buffer, header_end_offset, &content_length);

                if (cl_result == -2) {
                    /* Multiple/conflicting Content-Length headers (request smuggling attack) */
                    log_warn("Rejecting request with conflicting Content-Length headers from connection %lu",
                            conn->connection_id);
                    return -1;
                }

                /* Reject Transfer-Encoding (chunked, etc.) - this server does not
                 * support chunked transfer coding. If behind a reverse proxy,
                 * it should reassemble chunks and forward with Content-Length.
                 * A direct request with Transfer-Encoding is either a misconfigured
                 * client or a request smuggling attempt. */
                if (memmem_nocase(conn->read_buffer, header_end_offset,
                           "\r\nTransfer-Encoding", 19) != NULL) {
                    log_warn("Rejecting request with Transfer-Encoding header from connection %lu",
                            conn->connection_id);
                    return -1;
                }

                if (cl_result == 0) {
                    /* Request has a body - need header_end + content_length bytes total */
                    size_t total_needed = header_end_offset + content_length;

                    if (total_needed > max_request_size) {
                        log_warn("Request body too large (%zu bytes) from connection %lu",
                                content_length, conn->connection_id);
                        return -1;
                    }

                    if (conn->bytes_read >= total_needed) {
                        /* Have complete request including body */
                        log_debug("Received complete request with body (%zu bytes) from connection %lu",
                                 conn->bytes_read, conn->connection_id);
                        return 1;
                    }

                    /* Need more bytes for body - keep reading */
                } else {
                    /* No Content-Length (cl_result == -1), request is complete (GET/HEAD/etc.) */
                    log_debug("Received complete request (%zu bytes) from connection %lu",
                             conn->bytes_read, conn->connection_id);
                    return 1;
                }
            }
        }
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
        conn->last_activity = time(NULL);  /* Update activity timestamp */
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
 */
static void close_idle_connections(EventLoop *loop) {
    if (loop->config.connection_timeout_ms <= 0) return;  /* Timeout disabled */

    time_t now = time(NULL);
    time_t timeout_seconds = loop->config.connection_timeout_ms / 1000;

    Connection *conn = loop->connections_head;
    while (conn) {
        Connection *next = conn->next;  /* Save next before potential free */

        time_t idle_time = now - conn->last_activity;
        if (idle_time >= timeout_seconds) {
            log_info("Closing idle connection %lu (idle for %ld seconds)",
                    conn->connection_id, idle_time);
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

    /* Create listen socket */
    int listen_fd = create_listen_socket(loop->config.port,
                                         loop->config.backlog > 0 ? loop->config.backlog : DEFAULT_BACKLOG);
    if (listen_fd < 0) {
        return -1;
    }

    /* Add listen socket to epoll (watch for new connections)
     * Use sentinel pointer to distinguish from Connection pointers */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = &listen_fd;  /* Sentinel: address of listen_fd variable */

    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        log_error("epoll_ctl(ADD listen) failed: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    log_info("Event loop running on port %d", loop->config.port);

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
            if (events[i].data.ptr == &listen_fd) {
                /* New connection on listen socket (sentinel pointer) */
                handle_accept(loop, listen_fd);
            } else {
                /* Event on existing connection */
                Connection *conn = (Connection *)events[i].data.ptr;
                handle_connection_event(loop, conn, events[i].events);
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
    close(listen_fd);
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

    log_info("Worker thread %d started (tid=%lu)", loop->worker_index, pthread_self());

    /* Bind database connection to this thread */
    db_handle_t *db = db_pool_get_connection_by_index(loop->worker_index);
    if (db) {
        db_pool_set_connection(db);
        log_debug("Worker %d bound to database connection", loop->worker_index);
    } else {
        log_warn("Worker %d: No database connection available", loop->worker_index);
    }

    /* Run event loop (blocks until stopped) */
    event_loop_run(loop, loop->config.handler, loop->config.handler_context);

    log_info("Worker thread %d stopped (tid=%lu)", loop->worker_index, pthread_self());
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

    /* Auto-detect number of workers if not specified */
    if (config->num_workers <= 0) {
        pool->num_workers = get_cpu_count();
    } else {
        pool->num_workers = config->num_workers;
    }

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
    return 0;
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

    free(pool->worker_threads);
    free(pool->event_loops);
    free(pool);
}
