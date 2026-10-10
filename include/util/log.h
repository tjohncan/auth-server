#ifndef LOG_H
#define LOG_H

/*
 * Logging module - provides timestamped logging at different severity levels
 *
 * Each record is one line of printable ASCII on stderr: every other byte in a
 * message, but tab, is written as \xNN. So text a caller passes on from a request
 * can't start a record of its own, by a line feed or a Unicode line separator,
 * nor carry a control character or a bidirectional override to a terminal.
 *
 * Usage:
 *   log_init(LOG_INFO);  // Initialize with minimum level
 *   log_info("Server started on port %d", 8080);
 *   log_error("Failed to open file: %s", filename);
 */

typedef enum {
    LOG_DEBUG,   // Detailed debugging information
    LOG_INFO,    // General informational messages
    LOG_WARN,    // Warning messages
    LOG_ERROR    // Error messages
} LogLevel;

/*
 * Initialize the logging system with a minimum log level.
 * Messages below this level will be ignored.
 */
void log_init(LogLevel min_level);

/*
 * Log messages at different levels (printf-style formatting)
 */
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* LOG_H */
