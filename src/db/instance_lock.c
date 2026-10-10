/* flock, O_CLOEXEC */
#define _GNU_SOURCE

#include "db/instance_lock.h"
#include "util/log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
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

int instance_lock_file_user(const char *path, char *who, size_t who_size) {
    struct stat target;
    if (stat(path, &target) != 0) return 0;
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    /* Every descriptor of every process this user may look into; each is a link
       to what it has open, and stat follows it to that file */
    long self = (long)getpid(), found = 0;
    struct dirent *entry;
    while (!found && (entry = readdir(proc))) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end || pid <= 0 || pid == self) continue;
        char fd_dir[64];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%ld/fd", pid);
        DIR *fds = opendir(fd_dir);
        if (!fds) continue;  /* another user's, or gone */
        struct dirent *fd;
        while ((fd = readdir(fds))) {
            char link[sizeof(fd_dir) + 1 + sizeof(fd->d_name)];
            struct stat st;
            snprintf(link, sizeof(link), "%s/%s", fd_dir, fd->d_name);
            if (fd->d_name[0] != '.' && stat(link, &st) == 0 &&
                st.st_dev == target.st_dev && st.st_ino == target.st_ino) {
                found = pid;
                break;
            }
        }
        closedir(fds);
    }
    closedir(proc);

    if (found && who && who_size > 0) {
        char comm_path[64], name[32] = "";
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", found);
        FILE *comm = fopen(comm_path, "r");
        if (comm) {
            if (fgets(name, sizeof(name), comm)) name[strcspn(name, "\n")] = '\0';
            fclose(comm);
        }
        snprintf(who, who_size, name[0] ? "process %ld (%s)" : "process %ld", found, name);
    }
    return (int)found;
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

