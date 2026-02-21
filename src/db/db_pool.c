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
    int shutting_down;          /* Prevents new access during shutdown */
} pool = {
    .connections = NULL,
    .num_connections = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .initialized = 0,
    .shutting_down = 0
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
    pthread_mutex_lock(&pool.mutex);

    if (!pool.initialized || pool.shutting_down) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Connection pool not available");
        return NULL;
    }

    pthread_mutex_unlock(&pool.mutex);

    /* Get connection from thread-local storage (no lock needed) */
    db_handle_t *db = (db_handle_t *)pthread_getspecific(pool.thread_key);

    if (!db) {
        log_error("No connection bound to current thread");
        return NULL;
    }

    return db;
}

void db_pool_set_connection(db_handle_t *db) {
    pthread_mutex_lock(&pool.mutex);

    if (!pool.initialized || pool.shutting_down) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Connection pool not available");
        return;
    }

    if (!db) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Cannot set NULL connection");
        return;
    }

    pthread_key_t key = pool.thread_key;
    pthread_mutex_unlock(&pool.mutex);

    /* Store connection in thread-local storage (no lock needed) */
    if (pthread_setspecific(key, db) != 0) {
        log_error("Failed to set thread-local connection");
    }
}

db_handle_t *db_pool_get_connection_by_index(size_t index) {
    pthread_mutex_lock(&pool.mutex);

    if (!pool.initialized || pool.shutting_down) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Connection pool not available");
        return NULL;
    }

    if (index >= pool.num_connections) {
        pthread_mutex_unlock(&pool.mutex);
        log_error("Connection index %zu out of bounds (max: %zu)", index, pool.num_connections);
        return NULL;
    }

    db_handle_t *db = pool.connections[index];
    pthread_mutex_unlock(&pool.mutex);

    return db;
}

void db_pool_shutdown(void) {
    pthread_mutex_lock(&pool.mutex);

    if (!pool.initialized) {
        pthread_mutex_unlock(&pool.mutex);
        return;
    }

    /* Set shutting_down flag to prevent new accesses */
    pool.shutting_down = 1;

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
    pool.shutting_down = 0;

    pthread_mutex_unlock(&pool.mutex);
    log_info("Connection pool shutdown complete");
}
