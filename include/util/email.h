#ifndef EMAIL_H
#define EMAIL_H

#include "util/config.h"

/*
 * Email Delivery (Command-Based)
 *
 * Sends email by forking/exec-ing a configured external command.
 * The command receives a JSON payload on stdin and signals success
 * via exit code 0.
 *
 * The auth server is completely ignorant of email providers.
 * The command is a deployment artifact.
 */

/*
 * Send an email via the configured email command.
 *
 * Forks a child process, pipes JSON to its stdin, and checks exit code.
 * Fire-and-forget: logs warning on failure but does not propagate errors
 * to the caller's HTTP response.
 *
 * Returns: 0 on success, -1 on failure (command not configured, fork failed,
 *          command exited non-zero)
 */
int email_send(const config_t *config,
               const char *to,
               const char *subject,
               const char *body_text,
               const char *body_html);

#endif /* EMAIL_H */
