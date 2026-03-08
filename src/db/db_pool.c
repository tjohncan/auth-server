#include "db/db_pool.h"
#include "util/log.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * Connection pool state
 */
static struct {
    db_handle_t **connections;  /* Array of connection handles */
    size_t num_connections;
    pthread_key_t thread_key;   /* Thread-local storage key */
    pthread_mutex_t mutex;      /* Protects pool state */
    int initialized;
} pool = {
    .connections = NULL,
    .num_connections = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .initialized = 0
};

/*
 * Thread-local destructor (called when thread exits)
 */
static void thread_connection_destructor(void *arg) {
    (void)arg;  /* Connection cleanup handled in db_pool_shutdown */
}

int db_pool_init(size_t num_workers, db_type_t type, const char *connection_string) {
    pthread_mutex_lock(&pool.mutex);

    if (pool.initialized) {
        pthread_mutex_unlock(&pool.mutex);
        log_warn("Connection pool already initialized");
        return 0;
    }

    if (num_workers == 0) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Cannot initialize pool with 0 workers");
        return -1;
    }

    if (!connection_string) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Connection string is NULL");
        return -1;
    }

    log_info("Initializing connection pool: %zu workers, type=%s",
            num_workers, type == DB_TYPE_SQLITE ? "SQLite" : "PostgreSQL");

    /* Create thread-local storage key */
    if (pthread_key_create(&pool.thread_key, thread_connection_destructor) != 0) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Failed to create thread-local storage key");
        return -1;
    }

    /* Allocate connection array */
    pool.connections = calloc(num_workers, sizeof(db_handle_t *));
    if (!pool.connections) {
        pthread_key_delete(pool.thread_key);
        pthread_mutex_unlock(&pool.mutex);
        log_error("Failed to allocate connection array");
        return -1;
    }

    pool.num_connections = num_workers;

    /* Create connections */
    for (size_t i = 0; i < num_workers; i++) {
        int result = db_connect(&pool.connections[i], type, connection_string);
        if (result != 0) {
            log_error("Failed to create connection %zu/%zu", i + 1, num_workers);

            /* Cleanup already-created connections */
            for (size_t j = 0; j < i; j++) {
                db_disconnect(pool.connections[j]);
            }
            free(pool.connections);
            pool.connections = NULL;
            pool.num_connections = 0;
            pthread_key_delete(pool.thread_key);
            pthread_mutex_unlock(&pool.mutex);
            return -1;
        }
    }

    pool.initialized = 1;
    pthread_mutex_unlock(&pool.mutex);
    log_info("Connection pool initialized successfully");
    return 0;
}

db_handle_t *db_pool_get_connection(void) {
    /* Workers are created after pool init and joined before shutdown,
     * so no locking needed — just read the thread-local connection. */
    db_handle_t *db = (db_handle_t *)pthread_getspecific(pool.thread_key);

    if (!db) {
        log_error("No connection bound to current thread");
        return NULL;
    }

    return db;
}

void db_pool_set_connection(db_handle_t *db) {
    if (!db) {
        log_error("Cannot set NULL connection");
        return;
    }

    if (pthread_setspecific(pool.thread_key, db) != 0) {
        log_error("Failed to set thread-local connection");
    }
}

db_handle_t *db_pool_get_connection_by_index(size_t index) {
    if (index >= pool.num_connections) {
        log_error("Connection index %zu out of bounds (max: %zu)", index, pool.num_connections);
        return NULL;
    }

    return pool.connections[index];
}

void db_pool_shutdown(void) {
    pthread_mutex_lock(&pool.mutex);

    if (!pool.initialized) {
        pthread_mutex_unlock(&pool.mutex);
        return;
    }

    log_info("Shutting down connection pool");

    /* Close all connections */
    for (size_t i = 0; i < pool.num_connections; i++) {
        if (pool.connections[i]) {
            db_disconnect(pool.connections[i]);
            pool.connections[i] = NULL;
        }
    }

    /* Free connection array */
    free(pool.connections);
    pool.connections = NULL;
    pool.num_connections = 0;

    /* Delete thread-local storage key */
    pthread_key_delete(pool.thread_key);

    pool.initialized = 0;

    pthread_mutex_unlock(&pool.mutex);
    log_info("Connection pool shutdown complete");
}
