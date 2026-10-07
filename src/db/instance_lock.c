/* flock, O_CLOEXEC */
#define _GNU_SOURCE

#include "db/instance_lock.h"
#include "util/log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* The advisory lock's two keys: "AUTH", and which of the server's locks */
#define INSTANCE_LOCK_CLASS 1096111176
#define INSTANCE_LOCK_ID    1

int instance_lock_path(const char *db_path, char *out, size_t out_size) {
    if (!db_path || !out || strcmp(db_path, ":memory:") == 0 ||
        strncmp(db_path, "file::memory:", 13) == 0) {
        return -1;
    }
    int n = snprintf(out, out_size, "%s.lock", db_path);
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

int instance_lock_file(const char *lock_path, int exclusive, int *out_fd) {
    if (!lock_path || !out_fd) return -1;

    /* Close-on-exec, so the email command doesn't inherit the lock */
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_error("Can't open the instance lock %s: %s", lock_path, strerror(errno));
        return -1;
    }
    if (flock(fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
        int err = errno;
        close(fd);
        if (err == EWOULDBLOCK) return 1;
        log_error("Can't lock %s: %s", lock_path, strerror(err));
        return -1;
    }
    *out_fd = fd;
    return 0;
}

void instance_lock_file_release(int fd) {
    if (fd >= 0) close(fd);
}

/* One boolean a query returns, as 1 or 0; -1 on error */
static int query_bool(db_handle_t *db, const char *sql) {
    db_result_t *result = NULL;
    if (db_query(db, &result, "%s", sql) != 0) return -1;
    const char *v = db_result_row_count(result) == 1 ? db_result_get(result, 0, 0) : NULL;
    int rc = !v ? -1 : (v[0] == 't' || v[0] == '1');
    db_result_free(result);
    return rc;
}

int instance_lock_pg(db_handle_t *db, int exclusive) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s(%d, %d)",
             exclusive ? "pg_try_advisory_lock" : "pg_try_advisory_lock_shared",
             INSTANCE_LOCK_CLASS, INSTANCE_LOCK_ID);
    int taken = query_bool(db, sql);
    return taken < 0 ? -1 : !taken;
}

