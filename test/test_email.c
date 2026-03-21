#include "util/config.h"
#include "util/email.h"
#include "util/log.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    const char *recipient = argc > 1 ? argv[1] : NULL;
    const char *config_file = argc > 2 ? argv[2] : "auth.conf";

    log_init(LOG_DEBUG);

    config_t *config = config_load(config_file);
    if (!config) {
        fprintf(stderr, "Failed to load config from '%s'\n", config_file);
        return 1;
    }

    if (!config->email_command || !config->email_command[0]) {
        fprintf(stderr, "Email not configured. Set 'email_command' in %s\n", config_file);
        config_free(config);
        return 1;
    }

    if (!recipient) {
        fprintf(stderr, "Usage: test-email <recipient_email> [config_file]\n");
        config_free(config);
        return 1;
    }

    printf("Sending test email to %s via: %s\n", recipient, config->email_command);

    int result = email_send(config, recipient,
        "Auth Server Test Email",
        "This is a test email from the auth server email delivery system.",
        "<p>This is a <strong>test email</strong> from the auth server email delivery system.</p>");

    if (result == 0) {
        printf("Success — email command exited 0\n");
    } else {
        printf("Failed — email command returned non-zero or could not be executed\n");
    }

    config_free(config);
    return result;
}
