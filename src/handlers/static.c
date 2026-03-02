#include "handlers.h"
#include "util/log.h"
#include "util/str.h"
#include "server/router.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strncasecmp */
#include <sys/stat.h>
#include <dirent.h>

/* --------------------------------------------------------------------
 * In-memory static file cache
 *
 * All files under ./static/ are read into memory at startup.
 * Template replacements (login placeholder, mothership link) are
 * applied once at load time.  Requests are served directly from
 * the cached buffers — no per-request file I/O.
 * -------------------------------------------------------------------- */

typedef struct {
    char    path[256];      /* URL path, e.g. "/login.html" */
    char   *content;        /* heap-allocated file content   */
    size_t  length;         /* content length in bytes       */
    const char *mime_type;  /* static string, never freed    */
} StaticFile;

#define MAX_STATIC_FILES 128

static StaticFile static_files[MAX_STATIC_FILES];
static int static_file_count = 0;

/* -------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------- */

static StaticFile *find_static_file(const char *path) {
    for (int i = 0; i < static_file_count; i++) {
        if (strcmp(static_files[i].path, path) == 0)
            return &static_files[i];
    }
    return NULL;
}

/*
 * Replace first occurrence of `needle` in a cached file's content.
 * Reallocates the buffer to fit the replacement.
 */
static void template_replace(StaticFile *sf,
                             const char *needle,
                             const char *replacement) {
    char *pos = strstr(sf->content, needle);
    if (!pos) return;

    size_t needle_len = strlen(needle);
    size_t replace_len = strlen(replacement);
    size_t new_len = sf->length - needle_len + replace_len;

    char *buf = malloc(new_len + 1);
    if (!buf) {
        log_error("Failed to allocate for template replacement");
        return;
    }

    size_t prefix = (size_t)(pos - sf->content);
    memcpy(buf, sf->content, prefix);
    memcpy(buf + prefix, replacement, replace_len);
    memcpy(buf + prefix + replace_len, pos + needle_len,
           sf->length - prefix - needle_len);
    buf[new_len] = '\0';

    free(sf->content);
    sf->content = buf;
    sf->length = new_len;
}

/* -------------------------------------------------------------------- */

/*
 * GET /static/...
 *
 * Serves files from the in-memory cache.
 */
HttpResponse *static_file_handler(const HttpRequest *req, const RouteParams *params) {
    (void)params;

    const char *request_path = req->path;
    if (!request_path) {
        log_error("static_file_handler: NULL request path");
        return response_json_error(400, "Bad Request");
    }

    /* Security: block directory traversal */
    if (strstr(request_path, "..") != NULL) {
        log_warn("static_file_handler: Directory traversal attempt blocked: %s", request_path);
        return response_json_error(403, "Forbidden");
    }

    StaticFile *sf = find_static_file(request_path);
    if (!sf) {
        log_debug("static_file_handler: Not cached: %s", request_path);
        return response_json_error(404, "Not Found");
    }

    HttpResponse *resp = http_response_new(200);
    if (!resp) {
        log_error("static_file_handler: Failed to create response");
        return response_json_error(500, "Internal Server Error");
    }

    http_response_set_header(resp, "Content-Type", sf->mime_type);
    http_response_set_body(resp, sf->content, sf->length);
    http_response_set_header(resp, "Cache-Control", "public, max-age=3600");

    return resp;
}

/*
 * Handler for extensionless HTML file aliases (e.g., /login -> /login.html)
 */
HttpResponse *static_html_alias_handler(const HttpRequest *req, const RouteParams *params) {
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
    HttpRequest index_req = *req;
    index_req.path = "/index.html";

    return static_file_handler(&index_req, params);
}

/* -------------------------------------------------------------------- */

/*
 * Read a single file into the static file cache.
 * Returns 0 on success, -1 on failure.
 */
static int cache_file(const char *fs_path, const char *url_path) {
    if (static_file_count >= MAX_STATIC_FILES) {
        log_error("Static file cache full (%d files)", MAX_STATIC_FILES);
        return -1;
    }

    struct stat st;
    if (stat(fs_path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;

    FILE *file = fopen(fs_path, "rb");
    if (!file) {
        log_error("Failed to open static file: %s", fs_path);
        return -1;
    }

    char *content = malloc(st.st_size + 1);
    if (!content) {
        log_error("Failed to allocate memory for static file: %s", fs_path);
        fclose(file);
        return -1;
    }

    size_t bytes_read = fread(content, 1, st.st_size, file);
    fclose(file);

    if (bytes_read != (size_t)st.st_size) {
        log_error("Failed to read static file: %s", fs_path);
        free(content);
        return -1;
    }
    content[bytes_read] = '\0';

    StaticFile *sf = &static_files[static_file_count++];
    str_copy(sf->path, sizeof(sf->path), url_path);
    sf->content = content;
    sf->length = bytes_read;
    sf->mime_type = get_mime_type(fs_path);

    return 0;
}

/*
 * Recursively scan directory, cache files, and register routes.
 * Returns number of routes registered.
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
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fs_path[512];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", dir_path, entry->d_name);

        char url_path[512];
        snprintf(url_path, sizeof(url_path), "%s/%s", url_prefix, entry->d_name);

        struct stat st;
        if (stat(fs_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            count += scan_and_register(router, fs_path, url_path);
        } else if (S_ISREG(st.st_mode)) {
            if (cache_file(fs_path, url_path) != 0)
                continue;

            router_add(router, HTTP_GET, url_path, static_file_handler);
            log_debug("Registered static file: %s (%zu bytes)", url_path,
                      static_files[static_file_count - 1].length);
            count++;

            /* For .html files, also register extensionless alias */
            size_t url_len = strlen(url_path);
            if (url_len > 5 && strcmp(url_path + url_len - 5, ".html") == 0) {
                char alias[512];
                size_t alias_len = url_len - 5;
                memcpy(alias, url_path, alias_len);
                alias[alias_len] = '\0';
                router_add(router, HTTP_GET, alias, static_html_alias_handler);
                log_debug("Registered static file alias: %s", alias);
                count++;
            }
        }
    }

    closedir(dir);
    return count;
}

/* -------------------------------------------------------------------- */

/*
 * Apply template replacements to cached files.
 *
 * Login placeholder: controlled by build flag (compile-time).
 * Mothership link:   controlled by config (runtime).
 */
static void apply_templates(const config_t *config) {
    /* Login placeholder — replace "Email or Username" with the
       appropriate text based on build configuration */
#ifndef EMAIL_SUPPORT
    StaticFile *login = find_static_file("/login.html");
    if (login)
        template_replace(login, "placeholder=\"Email or Username\"",
                                 "placeholder=\"Username\"");
#endif

    /* Mothership link — only when configured */
    if (config->mothership_url && config->mothership_url[0] != '\0') {
        StaticFile *index = find_static_file("/index.html");
        if (index) {
            /* Strip scheme for display text */
            const char *display = config->mothership_url;
            if (strncasecmp(display, "https://", 8) == 0) display += 8;
            else if (strncasecmp(display, "http://", 7) == 0) display += 7;

            /* Strip trailing slash */
            char display_clean[256];
            str_copy(display_clean, sizeof(display_clean), display);
            size_t display_len = strlen(display_clean);
            if (display_len > 0 && display_clean[display_len - 1] == '/')
                display_clean[display_len - 1] = '\0';

            /* Build footer HTML */
            char mothership_html[1024];
            snprintf(mothership_html, sizeof(mothership_html),
                "<div style=\"margin-top:40px;padding-top:16px;"
                "border-top:1px solid #333;font-size:14px;\">"
                "<a href=\"%s\" style=\"color:#aa66aa;text-decoration:none;\">"
                "&#8627; %s</a></div>",
                config->mothership_url, display_clean);

            template_replace(index, "<!-- MOTHERSHIP -->", mothership_html);
        }
    } else {
        /* No mothership configured — remove the comment */
        StaticFile *index = find_static_file("/index.html");
        if (index)
            template_replace(index, "<!-- MOTHERSHIP -->", "");
    }
}

/* -------------------------------------------------------------------- */

/*
 * Register all static files from ./static/ directory.
 *
 * Reads every file into memory, applies template replacements,
 * and registers routes.  Files are served from memory thereafter.
 */
void register_static_files(Router *router, const config_t *config) {
    if (!router) {
        log_error("Invalid router in register_static_files");
        return;
    }

    log_info("Scanning ./static/ for files to register...");
    int count = scan_and_register(router, "./static", "");

    /* Apply template replacements after all files are cached */
    apply_templates(config);

    size_t total_bytes = 0;
    for (int i = 0; i < static_file_count; i++)
        total_bytes += static_files[i].length;

    log_info("Registered %d static file%s (%zu bytes cached)",
             count, count == 1 ? "" : "s", total_bytes);
}

/*
 * Free all cached static file buffers.
 */
void static_files_cleanup(void) {
    for (int i = 0; i < static_file_count; i++)
        free(static_files[i].content);
    static_file_count = 0;
}
