/* Define _POSIX_C_SOURCE for localtime_r */
#define _POSIX_C_SOURCE 200112L

#include "util/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/*
 * Static variable - this keeps its value between function calls.
 * It's like a "global" but only visible within this file.
 * Starts at LOG_INFO by default.
 */
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
    localtime_r(&now, &tm_info);  /* Thread-safe version */
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
 * The "..." (variadic arguments) let us do printf-style formatting.
 * We use va_list to handle them.
 */
static void log_message(LogLevel level, const char *fmt, va_list args) {
    /* Skip if this message is below our minimum level */
    if (level < current_min_level) {
        return;
    }

    /* Get current timestamp */
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Lock stderr so multi-threaded output doesn't interleave */
    flockfile(stderr);

    /* Print: [timestamp] LEVEL: message */
    fprintf(stderr, "[%s] %s: ", timestamp, level_to_string(level));

    /* Print the actual message with user's formatting */
    vfprintf(stderr, fmt, args);

    /* End with newline */
    fprintf(stderr, "\n");

    /* Flush to make sure it appears immediately (useful for crashes) */
    fflush(stderr);

    funlockfile(stderr);
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
