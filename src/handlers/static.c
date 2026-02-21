#include "handlers.h"
#include "util/log.h"
#include "server/router.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

/* MIME type detection based on file extension */
static const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";

    ext++; /* Skip the dot */

    /* Text formats */
    if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, "css") == 0) return "text/css; charset=utf-8";
    if (strcmp(ext, "js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(ext, "json") == 0) return "application/json; charset=utf-8";
    if (strcmp(ext, "txt") == 0) return "text/plain; charset=utf-8";
    if (strcmp(ext, "xml") == 0) return "application/xml; charset=utf-8";

    /* Images */
    if (strcmp(ext, "png") == 0) return "image/png";
    if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, "gif") == 0) return "image/gif";
    if (strcmp(ext, "svg") == 0) return "image/svg+xml";
    if (strcmp(ext, "ico") == 0) return "image/x-icon";
    if (strcmp(ext, "webp") == 0) return "image/webp";

    /* Fonts */
    if (strcmp(ext, "woff") == 0) return "font/woff";
    if (strcmp(ext, "woff2") == 0) return "font/woff2";
    if (strcmp(ext, "ttf") == 0) return "font/ttf";
    if (strcmp(ext, "otf") == 0) return "font/otf";

    return "application/octet-stream";
}

/*
 * GET /static/...
 *
 * Serves static files from the /static directory.
 * Returns 404 if file doesn't exist or path contains directory traversal.
 */
HttpResponse *static_file_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    /* Get the requested path (e.g., /static/css/main.css) */
    const char *request_path = req->path;
    if (!request_path) {
        log_error("static_file_handler: NULL request path");
        return response_json_error(400, "Bad Request");
    }

    /* Security: Block directory traversal attempts */
    if (strstr(request_path, "..") != NULL) {
        log_warn("static_file_handler: Directory traversal attempt blocked: %s", request_path);
        return response_json_error(403, "Forbidden");
    }

    /* Build file path: ./static/login.html from /login.html */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "./static%s", request_path);

    /* Check if file exists and is readable */
    struct stat st;
    if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        log_debug("static_file_handler: File not found: %s", file_path);
        return response_json_error(404, "Not Found");
    }

    /* Read file into memory */
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        log_error("static_file_handler: Failed to open file: %s", file_path);
        return response_json_error(500, "Internal Server Error");
    }

    /* Allocate buffer for file contents */
    char *content = malloc(st.st_size + 1);
    if (!content) {
        log_error("static_file_handler: Failed to allocate memory for file: %s", file_path);
        fclose(file);
        return response_json_error(500, "Internal Server Error");
    }

    /* Read file contents */
    size_t bytes_read = fread(content, 1, st.st_size, file);
    fclose(file);

    if (bytes_read != (size_t)st.st_size) {
        log_error("static_file_handler: Failed to read file: %s", file_path);
        free(content);
        return response_json_error(500, "Internal Server Error");
    }

    content[bytes_read] = '\0';

    /* Create response */
    HttpResponse *resp = http_response_new(200);
    if (!resp) {
        log_error("static_file_handler: Failed to create response");
        free(content);
        return response_json_error(500, "Internal Server Error");
    }

    /* Set Content-Type based on file extension */
    const char *mime_type = get_mime_type(file_path);
    http_response_set(resp, mime_type, content);

    /* Add caching headers for static assets (1 hour) */
    http_response_set_header(resp, "Cache-Control", "public, max-age=3600");

    free(content);
    log_debug("static_file_handler: Served %s (%zu bytes, %s)", file_path, bytes_read, mime_type);

    return resp;
}

/*
 * Handler for extensionless HTML file aliases (e.g., /login -> /login.html)
 */
HttpResponse *static_html_alias_handler(const HttpRequest *req, const RouteParams *params) {
    /* Add .html extension to the request path */
    char path_with_html[512];
    snprintf(path_with_html, sizeof(path_with_html), "%s.html", req->path);

    HttpRequest modified_req = *req;
    modified_req.path = path_with_html;

    return static_file_handler(&modified_req, params);
}

/*
 * GET /
 *
 * Serves index.html as the root page.
 */
HttpResponse *index_handler(const HttpRequest *req, const RouteParams *params) {
    /* Reuse static file handler by creating a modified request */
    HttpRequest index_req = *req;
    index_req.path = "/index.html";

    return static_file_handler(&index_req, params);
}

/*
 * Recursively scan directory and register static file routes
 * Returns: Number of files registered
 */
static int scan_and_register(Router *router, const char *dir_path, const char *url_prefix) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_debug("Could not open directory: %s", dir_path);
        return 0;
    }

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full filesystem path */
        char fs_path[512];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", dir_path, entry->d_name);

        /* Build URL path (route) */
        char url_path[512];
        snprintf(url_path, sizeof(url_path), "%s/%s", url_prefix, entry->d_name);

        struct stat st;
        if (stat(fs_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* Recursively scan subdirectory */
            count += scan_and_register(router, fs_path, url_path);
        } else if (S_ISREG(st.st_mode)) {
            /* Register route for this file */
            router_add(router, HTTP_GET, url_path, static_file_handler);
            log_debug("Registered static file: %s -> %s", url_path, fs_path);
            count++;

            /* For .html files, also register extensionless alias */
            size_t url_len = strlen(url_path);
            if (url_len > 5 && strcmp(url_path + url_len - 5, ".html") == 0) {
                char alias[512];
                size_t alias_len = url_len - 5;
                memcpy(alias, url_path, alias_len);
                alias[alias_len] = '\0';
                router_add(router, HTTP_GET, alias, static_html_alias_handler);
                log_debug("Registered static file alias: %s -> %s", alias, fs_path);
                count++;
            }
        }
    }

    closedir(dir);
    return count;
}

/*
 * Register all static files from ./static/ directory
 *
 * Scans ./static/ recursively and registers routes for each file.
 * Files are served without the /static prefix in the URL.
 *
 * Example:
 *   ./static/login.html -> GET /login.html
 *   ./static/css/main.css -> GET /css/main.css
 */
void register_static_files(Router *router) {
    if (!router) {
        log_error("Invalid router in register_static_files");
        return;
    }

    log_info("Scanning ./static/ for files to register...");
    int count = scan_and_register(router, "./static", "");
    log_info("Registered %d static file%s", count, count == 1 ? "" : "s");
}
