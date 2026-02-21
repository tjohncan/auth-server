#ifndef LOG_H
#define LOG_H

/*
 * Logging module - provides timestamped logging at different severity levels
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
void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif /* LOG_H */
