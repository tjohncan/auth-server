#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>  /* For INET6_ADDRSTRLEN */

/*
 * High-Performance Multi-Threaded Event Loop
 *
 * Architecture:
 * - N worker threads (default: number of CPU cores)
 * - Each worker runs its own epoll instance (no shared state)
 * - Kernel distributes connections via SO_REUSEPORT
 * - Non-blocking I/O with edge-triggered epoll
 * - Handles 10k+ concurrent connections per core
 *
 * Benefits of this approach:
 * - Scales linearly with CPU cores
 * - No locks or shared state between workers
 * - No context switching within each worker thread
 * - Kernel handles load balancing automatically
 */

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

typedef struct EventLoop EventLoop;
typedef struct EventLoopPool EventLoopPool;

/* ============================================================================
 * Connection State Machine
 * ============================================================================ */

/*
 * Each connection goes through these states:
 * READING_HEADERS → READING_BODY → PROCESSING → WRITING_RESPONSE → CLOSED
 */
typedef enum {
    CONN_STATE_READING_HEADERS,   /* Reading HTTP request line + headers */
    CONN_STATE_READING_BODY,      /* Reading request body (if Content-Length > 0) */
    CONN_STATE_PROCESSING,        /* Calling handler, building response */
    CONN_STATE_WRITING_RESPONSE,  /* Writing response back to client */
    CONN_STATE_CLOSED             /* Connection finished, ready for cleanup */
} ConnectionState;

/*
 * Connection context - one per client connection
 * Allocated when connection accepted, freed when closed
 */
typedef struct Connection {
    int fd;                       /* Socket file descriptor */
    ConnectionState state;        /* Current state in the state machine */

    char *read_buffer;            /* Buffer for incoming data */
    size_t read_buffer_size;      /* Allocated size of read buffer */
    size_t bytes_read;            /* How much data we've read so far */

    char *write_buffer;           /* Serialized HTTP response */
    size_t write_buffer_size;     /* Total size of response */
    size_t bytes_written;         /* How much we've written so far */

    char remote_ip[INET6_ADDRSTRLEN];  /* Client IP address (IPv4 or IPv6, for logging) */
    uint64_t connection_id;       /* Unique ID for logging/debugging */
    time_t last_activity;         /* Last read/write time (for timeout detection) */

    void *userdata;               /* Shared context from handler_context (not owned by connection) */

    /* Linked list for tracking all connections (for timeout enforcement) */
    struct Connection *next;
    struct Connection *prev;
} Connection;

/* ============================================================================
 * Request Handler Callback
 * ============================================================================ */

/*
 * Handler function signature
 *
 * Called when a complete HTTP request has been received.
 * Handler should parse request, build response, and return serialized bytes.
 *
 * Parameters:
 *   conn         - Connection context
 *   request_data - Raw HTTP request bytes
 *   request_len  - Length of request
 *   out_response - Handler sets this to response bytes (malloc'd, we'll free it)
 *   out_len      - Handler sets this to response length
 *
 * Returns: 0 on success, -1 on error (we'll close connection)
 */
typedef int (*RequestHandler)(Connection *conn,
                              const char *request_data, size_t request_len,
                              char **out_response, size_t *out_len);

/* ============================================================================
 * Event Loop Configuration
 * ============================================================================ */

typedef struct {
    int num_workers;              /* Number of worker threads (0 = auto-detect cores) */
    int port;                     /* Port to listen on */
    int backlog;                  /* Listen queue size (default: 128) */
    size_t max_request_size;      /* Max request size in bytes (default: 1MB) */
    int connection_timeout_ms;    /* Close idle connections after this (default: 30s) */
    int max_connections_per_worker; /* Max concurrent connections per worker (0 = unlimited) */
    RequestHandler handler;       /* Application request handler */
    void *handler_context;        /* Passed to handler (e.g., router) */
} EventLoopConfig;

/* ============================================================================
 * Event Loop Pool API (Multi-Threaded)
 * ============================================================================ */

/*
 * event_loop_pool_create - Create a pool of worker threads
 *
 * Each worker runs its own epoll event loop.
 * Connections are distributed by the kernel via SO_REUSEPORT.
 *
 * Returns: EventLoopPool pointer, or NULL on error
 */
EventLoopPool *event_loop_pool_create(EventLoopConfig *config);

/*
 * event_loop_pool_start - Start all worker threads and begin accepting connections
 *
 * This blocks until the server is shut down (e.g., SIGINT).
 * Workers run in background threads, main thread waits.
 *
 * Returns: 0 on clean shutdown, -1 on error
 */
int event_loop_pool_start(EventLoopPool *pool);

/*
 * event_loop_pool_stop_signal_safe - Signal all workers to stop (async-signal-safe)
 *
 * Safe to call from signal handlers. Sets running flags only, no logging.
 * Workers will finish current requests and shut down gracefully.
 */
void event_loop_pool_stop_signal_safe(EventLoopPool *pool);

/*
 * event_loop_pool_stop - Signal all workers to stop
 *
 * Sets running flags and logs. NOT signal-safe (uses logging).
 * Workers will finish current requests and shut down gracefully.
 */
void event_loop_pool_stop(EventLoopPool *pool);

/*
 * event_loop_pool_destroy - Free all resources
 *
 * Call after event_loop_pool_start returns.
 */
void event_loop_pool_destroy(EventLoopPool *pool);

/* ============================================================================
 * Single Event Loop API (Low-Level)
 * ============================================================================ */

/*
 * These are the internal primitives, typically not used directly (reference EventLoopPool, instead).
 * They're exposed for testing and advanced use cases.
 */

/*
 * event_loop_create - Create a single event loop (one epoll instance)
 */
EventLoop *event_loop_create(void);

/*
 * event_loop_add_connection - Add a new connection to the event loop
 *
 * Registers the socket with epoll, sets non-blocking mode.
 */
int event_loop_add_connection(EventLoop *loop, int fd, const char *remote_ip);

/*
 * event_loop_run - Run the event loop (blocks until stopped)
 *
 * Calls epoll_wait in a loop, handling events as they arrive.
 *
 * Parameters:
 *   loop    - Event loop instance
 *   handler - Request handler function
 *   context - Passed to handler
 *
 * Returns: 0 on clean exit, -1 on error
 */
int event_loop_run(EventLoop *loop, RequestHandler handler, void *context);

/*
 * event_loop_stop - Stop the event loop
 */
void event_loop_stop(EventLoop *loop);

/*
 * event_loop_destroy - Free event loop resources
 */
void event_loop_destroy(EventLoop *loop);

#endif /* EVENT_LOOP_H */
