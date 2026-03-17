#ifndef UTIL_TEMPLATE_H
#define UTIL_TEMPLATE_H

/*
 * In-memory template engine
 *
 * Loads template files from ./templates/ at startup.
 * Renders with {{PLACEHOLDER}} substitution at request time.
 * Returns heap-allocated strings — caller frees.
 */

/*
 * Load all template files from directory into memory.
 * Called once at startup before forking workers.
 *
 * Returns: 0 on success, -1 on error
 */
int template_init(const char *templates_dir);

/*
 * Render a template with placeholder substitutions.
 *
 * Substitutions are key-value pairs terminated by NULL sentinel.
 * Placeholders in template files use {{KEY}} syntax.
 *
 * WARNING: Values are inserted verbatim (no escaping).
 * Callers MUST html-escape any user-influenced values before passing them
 * (e.g., via str_html_escape) to prevent XSS in rendered HTML.
 *
 * Returns: heap-allocated string (caller frees), NULL on error.
 *
 * Example:
 *   char *html = template_render("pages/verify-email.html",
 *                                "EMAIL", escaped_email,
 *                                "TOKEN", token,
 *                                NULL);
 *   // use html...
 *   free(html);
 */
char *template_render(const char *name, ...);

/*
 * Free all cached template buffers.
 */
void template_cleanup(void);

#endif /* UTIL_TEMPLATE_H */
