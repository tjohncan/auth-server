#include "util/template.h"
#include "util/log.h"
#include "util/str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdint.h>

/* --------------------------------------------------------------------
 * In-memory template cache
 *
 * All files under ./templates/ are read into memory at startup.
 * Templates are never modified — each render clones and substitutes.
 * -------------------------------------------------------------------- */

typedef struct {
    char    name[256];      /* e.g. "emails/verify.html"  */
    char   *content;        /* heap-allocated file content */
    size_t  length;         /* content length in bytes     */
    int     hash_next;      /* chaining index, -1 = end    */
} Template;

#define MAX_TEMPLATES    64
#define TEMPLATE_HASH_SIZE 32

static Template templates[MAX_TEMPLATES];
static int template_count = 0;
static int template_hash_buckets[TEMPLATE_HASH_SIZE];

/* -------------------------------------------------------------------- */

static uint32_t template_hash(const char *name) {
    uint32_t h = 2166136261u;
    while (*name) {
        h ^= (uint8_t)*name++;
        h *= 16777619;
    }
    return h % TEMPLATE_HASH_SIZE;
}

static Template *find_template(const char *name) {
    int idx = template_hash_buckets[template_hash(name)];
    while (idx >= 0) {
        if (strcmp(templates[idx].name, name) == 0)
            return &templates[idx];
        idx = templates[idx].hash_next;
    }
    return NULL;
}

/* -------------------------------------------------------------------- */

static int cache_template(const char *fs_path, const char *name) {
    if (template_count >= MAX_TEMPLATES) {
        log_error("Template cache full (%d templates)", MAX_TEMPLATES);
        return -1;
    }

    struct stat st;
    if (stat(fs_path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;

    FILE *file = fopen(fs_path, "rb");
    if (!file) {
        log_error("Failed to open template: %s", fs_path);
        return -1;
    }

    char *content = malloc(st.st_size + 1);
    if (!content) {
        log_error("Failed to allocate memory for template: %s", fs_path);
        fclose(file);
        return -1;
    }

    size_t bytes_read = fread(content, 1, st.st_size, file);
    fclose(file);

    if (bytes_read != (size_t)st.st_size) {
        log_error("Failed to read template: %s", fs_path);
        free(content);
        return -1;
    }
    content[bytes_read] = '\0';

    int idx = template_count++;
    Template *t = &templates[idx];
    str_copy(t->name, sizeof(t->name), name);
    t->content = content;
    t->length = bytes_read;

    uint32_t bucket = template_hash(name);
    t->hash_next = template_hash_buckets[bucket];
    template_hash_buckets[bucket] = idx;

    return 0;
}

/* -------------------------------------------------------------------- */

static int scan_templates(const char *dir_path, const char *prefix) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_debug("Could not open template directory: %s", dir_path);
        return 0;
    }

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fs_path[512];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", dir_path, entry->d_name);

        char name[512];
        if (prefix[0])
            snprintf(name, sizeof(name), "%s/%s", prefix, entry->d_name);
        else
            str_copy(name, sizeof(name), entry->d_name);

        struct stat st;
        if (stat(fs_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            count += scan_templates(fs_path, name);
        } else if (S_ISREG(st.st_mode)) {
            if (cache_template(fs_path, name) == 0) {
                log_debug("Cached template: %s (%zu bytes)", name,
                          templates[template_count - 1].length);
                count++;
            }
        }
    }

    closedir(dir);
    return count;
}

/* -------------------------------------------------------------------- */

int template_init(const char *templates_dir) {
    memset(template_hash_buckets, -1, sizeof(template_hash_buckets));

    log_info("Scanning %s for templates...", templates_dir);
    int count = scan_templates(templates_dir, "");

    size_t total_bytes = 0;
    for (int i = 0; i < template_count; i++)
        total_bytes += templates[i].length;

    log_info("Cached %d template%s (%zu bytes)",
             count, count == 1 ? "" : "s", total_bytes);
    return 0;
}

/* -------------------------------------------------------------------- */

char *template_render_pairs(const char *name,
                             const char **keys, const char **vals, int count) {
    Template *t = find_template(name);
    if (!t) {
        log_error("Template not found: %s", name);
        return NULL;
    }

    /* Build substitution table with precomputed lengths */
    struct { const char *key; const char *val; size_t klen; size_t vlen; } subs[MAX_TEMPLATE_SUBS];
    if (count > MAX_TEMPLATE_SUBS) {
        log_warn("Template '%s': %d substitutions exceeds limit of %d", name, count, MAX_TEMPLATE_SUBS);
        count = MAX_TEMPLATE_SUBS;
    }
    int nsubs = count;

    for (int i = 0; i < nsubs; i++) {
        subs[i].key = keys[i];
        subs[i].val = vals[i];
        subs[i].klen = strlen(keys[i]);
        subs[i].vlen = strlen(vals[i]);
    }

    /* Pass 1: calculate output size */
    size_t out_size = 0;
    const char *p = t->content;
    const char *end = t->content + t->length;

    while (p < end) {
        if (p[0] == '{' && p + 1 < end && p[1] == '{') {
            const char *close = strstr(p + 2, "}}");
            if (close && close < end) {
                size_t klen = (size_t)(close - (p + 2));
                int found = 0;
                for (int i = 0; i < nsubs; i++) {
                    if (klen == subs[i].klen &&
                        memcmp(p + 2, subs[i].key, klen) == 0) {
                        out_size += subs[i].vlen;
                        found = 1;
                        break;
                    }
                }
                if (!found)
                    out_size += klen + 4; /* keep {{KEY}} as-is */
                p = close + 2;
                continue;
            }
        }
        out_size++;
        p++;
    }

    /* Pass 2: build output */
    char *result = malloc(out_size + 1);
    if (!result) {
        log_error("Failed to allocate template render buffer");
        return NULL;
    }

    char *w = result;
    p = t->content;

    while (p < end) {
        if (p[0] == '{' && p + 1 < end && p[1] == '{') {
            const char *close = strstr(p + 2, "}}");
            if (close && close < end) {
                size_t klen = (size_t)(close - (p + 2));
                int found = 0;
                for (int i = 0; i < nsubs; i++) {
                    if (klen == subs[i].klen &&
                        memcmp(p + 2, subs[i].key, klen) == 0) {
                        memcpy(w, subs[i].val, subs[i].vlen);
                        w += subs[i].vlen;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    size_t orig = klen + 4;
                    memcpy(w, p, orig);
                    w += orig;
                }
                p = close + 2;
                continue;
            }
        }
        *w++ = *p++;
    }
    *w = '\0';

    return result;
}

char *template_render(const char *name, ...) {
    const char *keys[MAX_TEMPLATE_SUBS], *vals[MAX_TEMPLATE_SUBS];
    int n = 0;

    va_list args;
    va_start(args, name);
    const char *key;
    while ((key = va_arg(args, const char *)) != NULL && n < MAX_TEMPLATE_SUBS) {
        const char *val = va_arg(args, const char *);
        if (!val) break;
        keys[n] = key;
        vals[n] = val;
        n++;
    }
    va_end(args);

    return template_render_pairs(name, keys, vals, n);
}

/* -------------------------------------------------------------------- */

void template_cleanup(void) {
    for (int i = 0; i < template_count; i++)
        free(templates[i].content);
    template_count = 0;
    memset(template_hash_buckets, -1, sizeof(template_hash_buckets));
}
