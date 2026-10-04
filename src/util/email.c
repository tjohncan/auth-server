#define _GNU_SOURCE  /* syscall() */
#include "util/email.h"
#include "util/json.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <openssl/crypto.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <errno.h>

#define EMAIL_TIMEOUT_SECONDS 30

/* Close every descriptor above stderr, in the forked child before it makes its
 * pipe. A plain fork() copies every descriptor the server has, close-on-exec or
 * not: listening sockets, epoll instances, other clients' connections, the very
 * connection that asked for this email. Whatever this child or the command keeps
 * holds those open, so a client connection doesn't close when its worker closes
 * it. close_range where the kernel has it (5.9+), otherwise one close() per
 * possible descriptor. Only async-signal-safe calls: this runs after fork() in a
 * multi-threaded process. */
static void close_inherited_fds(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0) return;
#endif
    struct rlimit rl;
    long max = (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
        ? (long)rl.rlim_cur : 65536;
    for (long fd = 3; fd < max; fd++) {
        close((int)fd);
    }
}

/* Write a message to stderr without locks (safe after fork in multi-threaded process).
 * log_* functions use flockfile(stderr) which can deadlock if another thread held
 * the lock at the time of fork(). */
static void sub_log(const char *msg) {
    if (write(STDERR_FILENO, msg, strlen(msg)) < 0
        || write(STDERR_FILENO, "\n", 1) < 0)
        _exit(1);
}

int email_send(const config_t *config,
               const char *to,
               const char *subject,
               const char *body_text,
               const char *body_html) {

    if (!config || !config->email_command || !config->email_command[0]) {
        log_error("Email command not configured");
        return -1;
    }

    if (!to || !to[0]) {
        log_error("Email recipient is empty");
        return -1;
    }

    /* Build JSON payload with proper RFC 8259 escaping */
    JsonBuf *jb = jsonbuf_new(2048);
    if (!jb) {
        log_error("Failed to allocate email JSON buffer");
        return -1;
    }

    jsonbuf_appendf(jb, "{\"to\":\"");
    jsonbuf_append_escaped(jb, to);
    jsonbuf_appendf(jb, "\",\"from\":\"");
    jsonbuf_append_escaped(jb, config->email_from ? config->email_from : "");
    jsonbuf_appendf(jb, "\",\"from_name\":\"");
    jsonbuf_append_escaped(jb, config->email_from_name ? config->email_from_name : "");
    jsonbuf_appendf(jb, "\",\"subject\":\"");
    jsonbuf_append_escaped(jb, subject ? subject : "");
    jsonbuf_appendf(jb, "\",\"body_text\":\"");
    jsonbuf_append_escaped(jb, body_text ? body_text : "");
    jsonbuf_appendf(jb, "\",\"body_html\":\"");
    jsonbuf_append_escaped(jb, body_html ? body_html : "");
    jsonbuf_appendf(jb, "\"}");

    if (jb->error) {
        log_error("Failed to build email JSON payload");
        jsonbuf_free(jb);
        return -1;
    }

    /* Fork a child process to handle delivery without blocking the worker.
     * Parent returns immediately. Child manages the email command lifecycle
     * with a timeout to prevent runaway processes. SIGCHLD = SIG_IGN in
     * main.c ensures the child is auto-reaped by the kernel. */
    pid_t pid = fork();
    if (pid < 0) {
        log_error("Failed to fork for email command");
        OPENSSL_cleanse(jb->buf, jb->len);
        jsonbuf_free(jb);
        return -1;
    }

    if (pid != 0) {
        /* Parent: cleanse and free payload (may contain tokens in email body) */
        OPENSSL_cleanse(jb->buf, jb->len);
        jsonbuf_free(jb);
        return 0;
    }

    /* ---- Child process (independent, can block freely) ---- */

    /* Reset SIGCHLD so our waitpid works on the grandchild */
    signal(SIGCHLD, SIG_DFL);

    /* Hold nothing of the server's: only stdin, stdout and stderr stay */
    close_inherited_fds();

    /* Create pipe for email command's stdin */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        _exit(1);
    }

    pid_t email_pid = fork();
    if (email_pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        _exit(1);
    }

    if (email_pid == 0) {
        /* Grandchild: exec email command, as the leader of its own process group
         * so a timeout can kill whatever the command starts, not just the shell */
        setpgid(0, 0);
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[0]);
        execl("/bin/sh", "sh", "-c", config->email_command, (char *)NULL);
        _exit(127);
    }

    /* Child: set the group here too, so it exists whichever process runs first */
    setpgid(email_pid, email_pid);

    /* Child: write payload to grandchild's stdin */
    close(pipefd[0]);
    size_t written = 0;
    while (written < jb->len) {
        ssize_t n = write(pipefd[1], jb->buf + written, jb->len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            sub_log("[WARN] Failed to write email payload to pipe");
            break;
        }
        written += (size_t)n;
    }
    close(pipefd[1]);

    /* Cleanse payload — skip free() to avoid potential deadlock after fork()
     * (malloc mutex may be held by another thread). _exit() reclaims all memory. */
    OPENSSL_cleanse(jb->buf, jb->len);

    /* Wait for grandchild with timeout */
    time_t deadline = time(NULL) + EMAIL_TIMEOUT_SECONDS;
    int status;
    pid_t result;

    for (;;) {
        result = waitpid(email_pid, &status, WNOHANG);
        if (result != 0) break;
        if (time(NULL) >= deadline) break;
        struct timespec ts = {0, 100000000};
        nanosleep(&ts, NULL);
    }

    if (result == 0) {
        /* Timed out — kill the email command and everything it started */
        if (kill(-email_pid, SIGKILL) != 0) {
            kill(email_pid, SIGKILL);
        }
        waitpid(email_pid, &status, 0);
        sub_log("[WARN] Email command timed out");
    } else if (result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        sub_log("[INFO] Email sent");
    } else if (result > 0 && WIFEXITED(status)) {
        sub_log("[WARN] Email command exited with non-zero status");
    } else if (result > 0) {
        sub_log("[WARN] Email command terminated abnormally");
    } else {
        sub_log("[WARN] Failed to wait for email command");
    }

    _exit(0);
}
