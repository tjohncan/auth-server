/* Define _POSIX_C_SOURCE for gmtime_r */
#define _POSIX_C_SOURCE 200809L

#include "util/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

static LogLevel current_min_level = LOG_INFO;

/*
 * Initialize the logging system
 */
void log_init(LogLevel min_level) {
    current_min_level = min_level;
}

/*
 * Helper function to get current timestamp as a string
 * Format: [2025-12-27 19:30:45]
 */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm tm_info;
    gmtime_r(&now, &tm_info);  /* Thread-safe, UTC — consistent with database timestamps */
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_info);
}

/*
 * Helper function to get the string name of a log level
 */
static const char* level_to_string(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        default:        return "?????";
    }
}

/*
 * Core logging function - all the log_* functions use this internally
 *
 * The message is formatted whole, then written as printable ASCII, every other
 * byte but tab as \xNN. A caller may pass text that came from a request, decoded
 * or not, and a line feed in it would start a forged record of its own; so would
 * NEL or U+2028 to a reader that splits lines on them, and a C1 control or a
 * bidirectional override can rewrite what a terminal shows. This way every
 * record is one line, shown as written, whatever any caller passes.
 */
static void log_message(LogLevel level, const char *fmt, va_list args) {
    /* Skip if this message is below our minimum level */
    if (level < current_min_level) {
        return;
    }

    /* Get current timestamp */
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Format the message: on the stack, or on the heap when it's longer */
    char stack[1024];
    char *message = stack;
    va_list again;
    va_copy(again, args);
    int length = vsnprintf(stack, sizeof(stack), fmt, args);
    if (length < 0) {
        snprintf(stack, sizeof(stack), "(a log message that couldn't be formatted)");
    } else if ((size_t)length >= sizeof(stack)) {
        char *heap = malloc((size_t)length + 1);
        if (heap) {
            vsnprintf(heap, (size_t)length + 1, fmt, again);
            message = heap;
        }
    }
    va_end(again);

    /* Lock stderr so multi-threaded output doesn't interleave */
    flockfile(stderr);

    /* Print: [timestamp] LEVEL: message */
    fprintf(stderr, "[%s] %s: ", timestamp, level_to_string(level));
    for (const unsigned char *c = (const unsigned char *)message; *c; c++) {
        if ((*c < 0x20 && *c != '\t') || *c >= 0x7f) {
            fprintf(stderr, "\\x%02x", *c);
        } else {
            putc_unlocked(*c, stderr);
        }
    }
    putc_unlocked('\n', stderr);

    /* Flush to make sure it appears immediately (useful for crashes) */
    fflush(stderr);

    funlockfile(stderr);

    if (message != stack) {
        free(message);
    }
}

/*
 * Public API functions - these are what users call
 */

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_DEBUG, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_INFO, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_WARN, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_ERROR, fmt, args);
    va_end(args);
}
