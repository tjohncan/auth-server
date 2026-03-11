#include "util/email.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/*
 * Escape a string for JSON output.
 * Writes escaped result to dst, returns chars written (excluding NUL).
 * Returns -1 if dst_size is insufficient.
 */
static int json_escape(char *dst, size_t dst_size, const char *src) {
    size_t i = 0;
    for (; *src; src++) {
        const char *esc;
        switch (*src) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:   esc = NULL;   break;
        }
        if (esc) {
            size_t len = strlen(esc);
            if (i + len >= dst_size) return -1;
            memcpy(dst + i, esc, len);
            i += len;
        } else {
            if (i + 1 >= dst_size) return -1;
            dst[i++] = *src;
        }
    }
    if (i >= dst_size) return -1;
    dst[i] = '\0';
    return (int)i;
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

    /* JSON-escape all string fields */
    char esc_to[512];
    char esc_from[512];
    char esc_from_name[512];
    char esc_subject[1024];
    char esc_body_text[8192];
    char esc_body_html[16384];

    if (json_escape(esc_to, sizeof(esc_to), to) < 0 ||
        json_escape(esc_from, sizeof(esc_from), config->email_from ? config->email_from : "") < 0 ||
        json_escape(esc_from_name, sizeof(esc_from_name), config->email_from_name ? config->email_from_name : "") < 0 ||
        json_escape(esc_subject, sizeof(esc_subject), subject ? subject : "") < 0 ||
        json_escape(esc_body_text, sizeof(esc_body_text), body_text ? body_text : "") < 0 ||
        json_escape(esc_body_html, sizeof(esc_body_html), body_html ? body_html : "") < 0) {
        log_error("Email content too large for buffer");
        return -1;
    }

    /* Build JSON payload */
    char payload[32768];
    int n = snprintf(payload, sizeof(payload),
        "{\"to\":\"%s\",\"from\":\"%s\",\"from_name\":\"%s\","
        "\"subject\":\"%s\",\"body_text\":\"%s\",\"body_html\":\"%s\"}",
        esc_to, esc_from, esc_from_name,
        esc_subject, esc_body_text, esc_body_html);

    if (n < 0 || (size_t)n >= sizeof(payload)) {
        log_error("Email JSON payload too large");
        return -1;
    }

    /* Create pipe for stdin */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        log_error("Failed to create pipe for email command");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_error("Failed to fork for email command");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: redirect stdin from pipe read end */
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[0]);

        /* exec the configured command via shell */
        execl("/bin/sh", "sh", "-c", config->email_command, (char *)NULL);
        _exit(127);
    }

    /* Parent: write payload to pipe write end */
    close(pipefd[0]);

    size_t payload_len = (size_t)n;
    ssize_t written = write(pipefd[1], payload, payload_len);
    close(pipefd[1]);

    if (written < 0 || (size_t)written != payload_len) {
        log_warn("Failed to write full payload to email command (wrote %zd of %zu)",
                 written, payload_len);
    }

    /* Wait for child */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_warn("Failed to wait for email command");
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        log_info("Email sent to %s: %s", to, subject ? subject : "(no subject)");
        return 0;
    }

    if (WIFEXITED(status)) {
        log_warn("Email command exited with status %d (to: %s)", WEXITSTATUS(status), to);
    } else {
        log_warn("Email command terminated abnormally (to: %s)", to);
    }

    return -1;
}
