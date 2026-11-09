/* strndup */
#define _POSIX_C_SOURCE 200809L

/*
 * Handler-level tests: raw requests through the server's own route table,
 * router and handlers, against a database of the suite's own (scratch_db.h), one
 * flow per test. Its raw SQL is written for both backends, with db_sql.h's
 * macros and scratch_db.h's.
 *
 * test-db pins the query functions underneath; this pins what the handlers add
 * on top -- authentication, the MFA gates, status codes -- along the flows the
 * README promises. Keep it to flows: what a single query returns belongs in
 * test-db.
 */
#include "handlers.h"
#include "server/router.h"
#include "server/http.h"
#include "util/config.h"
#include "util/log.h"
#include "util/str.h"
#include "util/json.h"
#include "db/db.h"
#include "db/db_pool.h"
#include "db/db_sql.h"
#include "db/init/db_init.h"
#include "db/init/db_history.h"
#include "db/queries/user.h"
#include "crypto/encrypt.h"
#include "crypto/password.h"
#include "crypto/random.h"
#include "crypto/sha256.h"
#include "crypto/totp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "util/template.h"
#include "util/validation.h"
#include "scratch_db.h"
#ifdef EMAIL_SUPPORT
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#endif

/* main.c's, read by the handlers */
const config_t *g_config = NULL;

static Router *g_router;

/* Set while a request goes to the admin listener (the admin socket or
   admin_port), where the localhost-only endpoints are served; otherwise it's the
   public one */
static int g_on_admin_port;

/* The address a request arrives from: loopback, or the admin socket's "local" */
static const char *g_remote_ip = "127.0.0.1";

/* ============================================================================
 * Requests
 * ============================================================================ */

/* What a client sees of a response */
typedef struct {
    int status;
    char *location;
    char *cookie;      /* "__Host-session=..." from Set-Cookie, if any */
    char *body;
} Reply;

static void reply_free(Reply *r) {
    free(r->location);
    free(r->cookie);
    free(r->body);
    memset(r, 0, sizeof(*r));
}

/* One request, handled the way main.c's router_request_handler does it: a
 * private NUL-terminated copy, parsed, arriving from 127.0.0.1, dispatched. */
static Reply send_raw(const char *raw) {
    Reply r = {0};
    size_t len = strlen(raw);
    char *copy = malloc(len + 1);
    memcpy(copy, raw, len + 1);

    HttpRequest req = http_request_parse(copy, len);
    str_copy(req.remote_ip, sizeof(req.remote_ip), g_remote_ip);
    req.admin_listener = g_on_admin_port;
    HttpResponse *resp = req.method == HTTP_UNKNOWN
        ? response_json_error(400, "Bad Request")
        : router_dispatch(g_router, &req);
    http_request_cleanup(&req);
    free(copy);

    r.status = resp->status_code;
    for (int i = 0; i < resp->header_count; i++) {
        const char *name = resp->headers[i].name, *value = resp->headers[i].value;
        if (!r.location && strcasecmp(name, "Location") == 0) {
            r.location = str_dup(value);
        }
        if (!r.cookie && strcasecmp(name, "Set-Cookie") == 0) {
            const char *semi = strchr(value, ';');
            r.cookie = semi ? strndup(value, (size_t)(semi - value)) : str_dup(value);
        }
    }
    r.body = resp->body ? strndup(resp->body, resp->body_length) : str_dup("");
    http_response_free(resp);
    return r;
}

/* extra_headers: zero or more complete "Name: value\r\n" lines */
static Reply request(const char *method, const char *target, const char *cookie,
                     const char *extra_headers, const char *content_type,
                     const char *body) {
    static char raw[16384];
    int n = snprintf(raw, sizeof(raw), "%s %s HTTP/1.0\r\n", method, target);
    if (cookie) n += snprintf(raw + n, sizeof(raw) - n, "Cookie: %s\r\n", cookie);
    if (extra_headers) n += snprintf(raw + n, sizeof(raw) - n, "%s", extra_headers);
    if (content_type) n += snprintf(raw + n, sizeof(raw) - n, "Content-Type: %s\r\n", content_type);
    if (body) {
        snprintf(raw + n, sizeof(raw) - n, "Content-Length: %zu\r\n\r\n%s", strlen(body), body);
    } else {
        snprintf(raw + n, sizeof(raw) - n, "\r\n");
    }
    return send_raw(raw);
}

static Reply post_json(const char *path, const char *cookie, const char *json) {
    return request("POST", path, cookie, NULL, "application/json", json);
}

static Reply post_form(const char *path, const char *form) {
    return request("POST", path, NULL, NULL, "application/x-www-form-urlencoded", form);
}

/* A request on the admin listener, as the operator's curl sends one: no cookie,
   a JSON body if any */
static Reply admin_port(const char *method, const char *target, const char *extra_headers,
                        const char *json) {
    g_on_admin_port = 1;
    Reply r = request(method, target, NULL, extra_headers, json ? "application/json" : NULL, json);
    g_on_admin_port = 0;
    return r;
}

/* A string field of a JSON reply, copied into out */
static int field(const Reply *r, const char *key, char *out, size_t out_size) {
    char *v = json_get_string(r->body, key);
    if (!v) return -1;
    snprintf(out, out_size, "%s", v);
    free(v);
    return 0;
}

/* The strings of a JSON array of plain strings, as the server writes one (no spaces,
   no escapes), at most max of them: the count, or -1 if there's no such array */
static int string_array(const char *body, const char *key, char out[][32], int max) {
    char start[64];
    snprintf(start, sizeof(start), "\"%s\":[", key);
    const char *p = strstr(body, start);
    if (!p) return -1;
    p += strlen(start);
    int n = 0;
    while (*p == '"') {
        const char *end = strchr(p + 1, '"');
        if (!end || n == max || end - p - 1 >= 32) return -1;
        snprintf(out[n++], 32, "%.*s", (int)(end - p - 1), p + 1);
        p = end + 1;
        if (*p == ',') p++;
    }
    return *p == ']' ? n : -1;
}

/* First column of a one-row query, as text */
static int query_text(const char *sql, char *out, size_t out_size) {
    db_stmt_t *stmt = NULL;
    out[0] = '\0';
    if (db_prepare(db_pool_get_connection(), &stmt, sql) != 0) return -1;
    int rc = db_step(stmt);
    const char *v = rc == DB_ROW ? db_column_text(stmt, 0) : NULL;
    if (v) snprintf(out, out_size, "%s", v);
    db_finalize(stmt);
    return v ? 0 : -1;
}

/* A JWT's payload, decoded, for reading its claims; the caller frees it */
static char *token_payload(const char *jwt) {
    const char *payload = strchr(jwt, '.');
    const char *end = payload ? strchr(payload + 1, '.') : NULL;
    if (!end) return NULL;
    size_t len = (size_t)(end - payload - 1);
    unsigned char *json = malloc(len + 1);
    int n = json ? crypto_base64url_decode(payload + 1, len, json, len) : -1;
    if (n <= 0) {
        free(json);
        return NULL;
    }
    json[n] = '\0';
    return (char *)json;
}

#define FAIL(...) do { printf("✗ "); printf(__VA_ARGS__); printf("\n"); return 1; } while (0)

/* ============================================================================
 * Mail, in a build with email support
 * ============================================================================ */

#ifdef EMAIL_SUPPORT
/* The email command saves what it's given here, one JSON file per message */
static char g_outbox[64];

/* A message waiting in the outbox, read and removed; -1 if none came within
   wait_ms (the email command runs in a child process, so it can lag) */
static int mail_take(int wait_ms, char *json, size_t size) {
    for (int waited = 0; waited <= wait_ms; waited += 20) {
        DIR *dir = opendir(g_outbox);
        struct dirent *e;
        char path[128] = "";
        while (dir && !path[0] && (e = readdir(dir))) {
            size_t n = strlen(e->d_name);
            if (n > 5 && strcmp(e->d_name + n - 5, ".json") == 0) {
                snprintf(path, sizeof(path), "%s/%s", g_outbox, e->d_name);
            }
        }
        if (dir) closedir(dir);
        if (path[0]) {
            FILE *f = fopen(path, "r");
            size_t len = f ? fread(json, 1, size - 1, f) : 0;
            if (f) fclose(f);
            unlink(path);
            json[len] = '\0';
            return 0;
        }
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return -1;
}

/* The token in the link of the one message just sent, which must be to `to` */
static int mail_token(const char *to, char *token, size_t size) {
    char json[8192];
    if (mail_take(5000, json, sizeof(json)) != 0) return -1;
    char *rcpt = json_get_string(json, "to");
    char *text = json_get_string(json, "body_text");
    const char *t = text ? strstr(text, "token=") : NULL;
    int ok = rcpt && strcmp(rcpt, to) == 0 && t;
    if (ok) snprintf(token, size, "%.*s", (int)strcspn(t + 6, " \r\n"), t + 6);
    free(rcpt);
    free(text);
    return ok ? 0 : -1;
}

/* Nothing was sent: no message turns up in a while */
static int mail_none(void) {
    char json[8192];
    return mail_take(300, json, sizeof(json)) != 0;
}
#endif

/* ============================================================================
 * Shared state: the bootstrap admin and their organization
 * ============================================================================ */

static char g_admin_cookie[256];
static char g_org_id[33];

static int login(const char *username, const char *password, char *cookie, size_t size) {
    char body[1200];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    Reply r = post_json("/login", NULL, body);
    int ok = r.status == 200 && r.cookie;
    if (ok) snprintf(cookie, size, "%s", r.cookie);
    reply_free(&r);
    return ok ? 0 : -1;
}

static int setup(void) {
    Reply r = admin_port("POST", "/api/admin/bootstrap", NULL,
                        "{\"username\":\"admin\",\"password\":\"correct horse battery\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("bootstrap answered %d", status);
    if (login("admin", "correct horse battery", g_admin_cookie, sizeof(g_admin_cookie)) != 0) {
        FAIL("the bootstrap admin can't sign in");
    }
    if (query_text("SELECT " ID_HEX("id") " FROM " TBL_ORGANIZATION " WHERE code_name = 'system'",
                   g_org_id, sizeof(g_org_id)) != 0) {
        FAIL("no bootstrap organization");
    }
    return 0;
}

/* ============================================================================
 * Logout
 * ============================================================================ */

/*
 * Logging out closes the session, so its cookie is refused even if the browser
 * kept it. Logging out again with that cookie also answers 200, since nothing
 * is left open, and both answers clear the cookie.
 */
static int test_logout(void) {
    printf("\n=== Logout ===\n");

    char cookie[256];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"leaving\",\"password\":\"leaving password\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 200 || login("leaving", "leaving password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }

    for (int i = 1; i <= 2; i++) {
        r = request("POST", "/logout", cookie, NULL, NULL, "");
        status = r.status;
        int cleared = r.cookie && strcmp(r.cookie, SESSION_COOKIE_NAME "=") == 0;
        reply_free(&r);
        if (status != 200 || !cleared) {
            FAIL("logout %d answered %d, %s", i, status,
                 cleared ? "clearing the cookie" : "leaving the cookie");
        }
    }
    r = request("GET", "/api/user/profile", cookie, NULL, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (status != 401) FAIL("the closed session's cookie got %d", status);
    printf("✓ logout clears the cookie, a second time too, and the closed session is refused\n");

    return 0;
}

/* ============================================================================
 * Authorization code with PKCE, and refresh-token rotation
 * ============================================================================ */

/* RFC 7636 Appendix B's verifier and its S256 challenge */
#define PKCE_VERIFIER  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
#define PKCE_CHALLENGE "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

static char g_ui_client[33];
static char g_redirect_enc[128];

/* /authorize as the admin, through the console's client, with this challenge */
static Reply authorize_with(const char *challenge) {
    char target[512];
    snprintf(target, sizeof(target),
             "/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=st8"
             "&code_challenge=%s&code_challenge_method=S256",
             g_ui_client, g_redirect_enc, challenge);
    return request("GET", target, g_admin_cookie, NULL, NULL, NULL);
}

/* The same with the verifier's challenge; the code from the redirect */
static int authorize(char *code, size_t size) {
    Reply r = authorize_with(PKCE_CHALLENGE);
    const char *q = r.location ? strchr(r.location, '?') : NULL;
    char *c = q ? http_query_get_param(q + 1, "code") : NULL;
    char *state = q ? http_query_get_param(q + 1, "state") : NULL;
    int ok = r.status == 302 && c && state && strcmp(state, "st8") == 0;
    if (ok) snprintf(code, size, "%s", c);
    free(c);
    free(state);
    reply_free(&r);
    return ok ? 0 : -1;
}

static Reply exchange(const char *code, const char *verifier) {
    char form[4096];
    snprintf(form, sizeof(form),
             "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
             code, g_redirect_enc, g_ui_client, verifier);
    return post_form("/token", form);
}

static Reply refresh(const char *refresh_token) {
    char form[1024];
    snprintf(form, sizeof(form), "grant_type=refresh_token&refresh_token=%s&client_id=%s",
             refresh_token, g_ui_client);
    return post_form("/token", form);
}

static int userinfo_status(const char *access_token) {
    char header[4096];
    snprintf(header, sizeof(header), "Authorization: Bearer %s\r\n", access_token);
    Reply r = request("GET", "/userinfo", NULL, header, NULL, NULL);
    int status = r.status;
    reply_free(&r);
    return status;
}

/*
 * A code exchanges once, and only with its PKCE verifier. Presenting it again
 * is treated as theft: the tokens the first exchange issued are revoked. A
 * refresh token rotates, and replaying a rotated one revokes its whole chain.
 */
static int test_authorization_code_flow(void) {
    printf("\n=== Authorization code, PKCE and refresh rotation ===\n");

    if (query_text("SELECT " ID_HEX("id") " FROM " TBL_CLIENT " WHERE code_name = 'management_ui'",
                   g_ui_client, sizeof(g_ui_client)) != 0) {
        FAIL("no management UI client");
    }
    char redirect[256];
    snprintf(redirect, sizeof(redirect), "%s/callback", g_config->public_base_url);
    str_url_encode(g_redirect_enc, sizeof(g_redirect_enc), redirect);

    char code[2048], access[2048], rt[256], rt2[256];

    /* 0. A challenge that can't be an S256 one is refused, no code made: a byte
          short, and characters a challenge doesn't have */
    static const char *not_s256[] = {
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c", "%C3%A9" };
    for (size_t i = 0; i < sizeof(not_s256) / sizeof(not_s256[0]); i++) {
        Reply r = authorize_with(not_s256[i]);
        int refused = r.status == 302 && r.location &&
                      strstr(r.location, "error=invalid_request") && !strstr(r.location, "code=");
        reply_free(&r);
        if (!refused) FAIL("/authorize took the challenge '%s'", not_s256[i]);
    }
    printf("✓ a challenge that can't be S256's is refused before a code is made\n");

    /* Parameters that don't decode to text never reach a handler, which on PostgreSQL
       would hand them to the database and answer 500 */
    Reply bad = authorize_with("%FF%FE");
    int status = bad.status;
    reply_free(&bad);
    if (status != 400) FAIL("/authorize with %%FF%%FE in a parameter answered %d, not 400", status);
    bad = post_form("/token", "grant_type=refresh_token&refresh_token=x&client_id=x&resource=%FF");
    status = bad.status;
    int said = strstr(bad.body, "not valid UTF-8 text") != NULL;
    reply_free(&bad);
    if (status != 400 || !said) FAIL("/token with resource=%%FF answered %d", status);
    printf("✓ a parameter that doesn't decode to text is refused, on a query or a form\n");

    /* The one-time link forms read a body as a form, so another type would pass it by that
       check, and an invitation would take a password no sign-in can send */
    static const char *const link_forms[] = {
        "/accept-invitation",
#ifdef EMAIL_SUPPORT
        "/verify-email", "/reset-password", "/passwordless-login",
#endif
    };
    for (size_t i = 0; i < sizeof(link_forms) / sizeof(link_forms[0]); i++) {
        static const char *const types[] = { "text/plain", NULL };
        for (size_t t = 0; t < 2; t++) {
            bad = request("POST", link_forms[i], NULL, NULL, types[t],
                          "token=nosuch&password=%FF%FE%FDlongenoughpassword");
            status = bad.status;
            reply_free(&bad);
            if (status != 415) {
                FAIL("%s sent as %s answered %d, not 415", link_forms[i],
                     types[t] ? types[t] : "no type", status);
            }
        }
    }
    printf("✓ the one-time link forms take form-encoded bodies alone\n");

    /* 1. The wrong verifier is refused and the right one exchanges, so the
          refusal was PKCE's (it's checked before the code is spent) */
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    Reply r = exchange(code, "wrong-verifier-wrong-verifier-wrong-verifier-x");
    if (r.status != 400) FAIL("an exchange with the wrong PKCE verifier answered %d", r.status);
    reply_free(&r);
    r = exchange(code, PKCE_VERIFIER);
    if (r.status != 200 || field(&r, "access_token", access, sizeof(access)) != 0 ||
        field(&r, "refresh_token", rt, sizeof(rt)) != 0) {
        FAIL("the code exchange answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    if (userinfo_status(access) != 200) FAIL("a fresh access token is refused at /userinfo");
    printf("✓ a code exchanges only with its PKCE verifier\n");

    /* 2. The same code again: refused, and the tokens it issued are revoked */
    r = exchange(code, PKCE_VERIFIER);
    if (r.status != 400) FAIL("a replayed code answered %d", r.status);
    reply_free(&r);
    if (userinfo_status(access) != 401) FAIL("the replay left the first access token live");
    r = refresh(rt);
    if (r.status != 400) FAIL("the replay left the first refresh token live");
    reply_free(&r);
    printf("✓ a code exchanges once; replaying it revokes what it issued\n");

    /* 3. Rotation: a refresh token works once; replaying it kills its successor */
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    r = exchange(code, PKCE_VERIFIER);
    if (r.status != 200 || field(&r, "refresh_token", rt, sizeof(rt)) != 0) {
        FAIL("the code exchange answered %d", r.status);
    }
    reply_free(&r);
    r = refresh(rt);
    if (r.status != 200 || field(&r, "refresh_token", rt2, sizeof(rt2)) != 0 ||
        field(&r, "access_token", access, sizeof(access)) != 0) {
        FAIL("rotating a refresh token answered %d", r.status);
    }
    reply_free(&r);
    r = refresh(rt);
    if (r.status != 400) FAIL("a rotated refresh token was accepted again");
    reply_free(&r);
    r = refresh(rt2);
    if (r.status != 400) FAIL("replaying a rotated token left its successor live");
    reply_free(&r);
    if (userinfo_status(access) != 401) FAIL("replay left the chain's access token live");
    printf("✓ a refresh token rotates once; replaying it revokes the chain\n");

    /* 4. Logging out after two rotations: revoking the newest refresh token
          revokes every access token of the grant, the exchange's included */
    char at[3][2048], rt3[256];
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    r = exchange(code, PKCE_VERIFIER);
    if (r.status != 200 || field(&r, "access_token", at[0], sizeof(at[0])) != 0 ||
        field(&r, "refresh_token", rt, sizeof(rt)) != 0) {
        FAIL("the code exchange answered %d", r.status);
    }
    reply_free(&r);
    for (int i = 1; i < 3; i++) {
        r = refresh(rt);
        if (r.status != 200 || field(&r, "access_token", at[i], sizeof(at[i])) != 0 ||
            field(&r, "refresh_token", rt3, sizeof(rt3)) != 0) {
            FAIL("rotation %d answered %d", i, r.status);
        }
        reply_free(&r);
        snprintf(rt, sizeof(rt), "%s", rt3);
    }
    char form[512];
    snprintf(form, sizeof(form), "token=%s&client_id=%s", rt, g_ui_client);
    r = post_form("/revoke", form);
    if (r.status != 200) FAIL("/revoke answered %d", r.status);
    reply_free(&r);
    for (int i = 0; i < 3; i++) {
        if (userinfo_status(at[i]) != 401) FAIL("after logout, access token %d is still live", i);
    }
    printf("✓ revoking the newest refresh token revokes every access token of the grant\n");

    /* 5. An earlier refresh token of a grant revokes the newest too */
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    r = exchange(code, PKCE_VERIFIER);
    if (r.status != 200 || field(&r, "refresh_token", rt, sizeof(rt)) != 0) {
        FAIL("the code exchange answered %d", r.status);
    }
    reply_free(&r);
    r = refresh(rt);
    if (r.status != 200 || field(&r, "refresh_token", rt2, sizeof(rt2)) != 0 ||
        field(&r, "access_token", access, sizeof(access)) != 0) {
        FAIL("rotating a refresh token answered %d", r.status);
    }
    reply_free(&r);
    snprintf(form, sizeof(form), "token=%s&client_id=%s", rt, g_ui_client);
    r = post_form("/revoke", form);
    if (r.status != 200) FAIL("/revoke answered %d", r.status);
    reply_free(&r);
    r = refresh(rt2);
    if (r.status != 400 || userinfo_status(access) != 401) {
        FAIL("revoking a grant's earlier refresh token left its newest live (%d)", r.status);
    }
    reply_free(&r);
    printf("✓ an earlier refresh token of the grant revokes it all\n");

    /* 6. A client that issues no refresh tokens: replaying its code still
          revokes the access token the first exchange issued */
    if (db_execute_direct(db_pool_get_connection(),
                          "UPDATE " TBL_CLIENT " SET issue_refresh_tokens = " BOOL_FALSE " "
                          "WHERE code_name = 'management_ui'") != 0) {
        FAIL("could not turn refresh tokens off");
    }
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    r = exchange(code, PKCE_VERIFIER);
    int ok = r.status == 200 && field(&r, "access_token", access, sizeof(access)) == 0 &&
             !strstr(r.body, "refresh_token");
    reply_free(&r);
    r = exchange(code, PKCE_VERIFIER);
    int replay = r.status;
    reply_free(&r);
    int live = userinfo_status(access);
    if (db_execute_direct(db_pool_get_connection(),
                          "UPDATE " TBL_CLIENT " SET issue_refresh_tokens = " BOOL_TRUE " "
                          "WHERE code_name = 'management_ui'") != 0) {
        FAIL("could not turn refresh tokens back on");
    }
    if (!ok) FAIL("without refresh tokens, the code exchange went wrong");
    if (replay != 400 || live != 401) {
        FAIL("without refresh tokens, a replayed code answered %d and left /userinfo at %d",
             replay, live);
    }
    printf("✓ with no refresh tokens, replaying a code still revokes its access token\n");

    /* 7. A client that needs a user link: unlinked while the code is outstanding,
          the exchange is refused. Linked again, the same code exchanges, so the
          refusal was the link's and it didn't spend the code */
    db_handle_t *db = db_pool_get_connection();
    const char *link =
        "INSERT INTO " TBL_CLIENT_USER " (client_pin, user_account_pin) "
        "SELECT C.pin, A.user_account_pin FROM " TBL_CLIENT " C, " TBL_ORGANIZATION_ADMIN " A "
        "WHERE C.code_name = 'management_ui'";
    const char *unlink =
        "DELETE FROM " TBL_CLIENT_USER " WHERE client_pin = "
        "(SELECT pin FROM " TBL_CLIENT " WHERE code_name = 'management_ui')";
    if (db_execute_direct(db, "UPDATE " TBL_CLIENT " SET is_universal = " BOOL_FALSE " "
                              "WHERE code_name = 'management_ui'") != 0 ||
        db_execute_direct(db, link) != 0) {
        FAIL("could not make the client need a link");
    }
    int authorized = authorize(code, sizeof(code)) == 0;
    db_execute_direct(db, unlink);
    r = exchange(code, PKCE_VERIFIER);
    int unlinked = r.status;
    reply_free(&r);
    db_execute_direct(db, link);
    r = exchange(code, PKCE_VERIFIER);
    int relinked = r.status;
    reply_free(&r);
    if (db_execute_direct(db, unlink) != 0 ||
        db_execute_direct(db, "UPDATE " TBL_CLIENT " SET is_universal = " BOOL_TRUE " "
                              "WHERE code_name = 'management_ui'") != 0) {
        FAIL("could not make the client universal again");
    }
    if (!authorized) FAIL("/authorize refused a linked user");
    if (unlinked != 400 || relinked != 200) {
        FAIL("a code exchanged after its user was unlinked answered %d (linked again, %d)",
             unlinked, relinked);
    }
    printf("✓ a code doesn't exchange once its user is unlinked from the client\n");

    return 0;
}

/* ============================================================================
 * Redirect URIs
 * ============================================================================ */

/*
 * A redirect URI never has a fragment, which the code would land inside. Plain
 * http is the client deployer's call, to any host. Adding one the client has
 * already is a success that changes nothing.
 */
static int test_redirect_uris(void) {
    printf("\n=== Redirect URIs ===\n");

    static const struct { const char *uri; int status; } cases[] = {
        { "https://app.example.com/callback", 200 },
        { "http://localhost:3000/callback", 200 },
        { "http://app.example.com/callback", 200 },
        { "HTTPS://app.example.com/upper", 200 },
        { "https://app.example.com/cb#x", 400 },
        { "http://localhost/cb#x", 400 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[256];
        snprintf(json, sizeof(json), "{\"client_id\":\"%s\",\"redirect_uri\":\"%s\"}",
                 g_ui_client, cases[i].uri);
        Reply r = post_json("/api/admin/client-redirect-uris", g_admin_cookie, json);
        int status = r.status;
        reply_free(&r);
        if (status != cases[i].status) {
            FAIL("registering %s answered %d, not %d", cases[i].uri, status, cases[i].status);
        }
    }
    printf("✓ a redirect URI with a fragment is refused\n");

    /* The first one again, with a note: 200 saying nothing changed, and still one
       of it, its note as it was */
    char json[256], target[128];
    snprintf(json, sizeof(json), "{\"client_id\":\"%s\",\"redirect_uri\":\"%s\","
             "\"note\":\"a second note\"}", g_ui_client, cases[0].uri);
    Reply r = post_json("/api/admin/client-redirect-uris", g_admin_cookie, json);
    int status = r.status;
    int said = status == 200 && strstr(r.body, "already registered") != NULL;
    reply_free(&r);
    snprintf(target, sizeof(target), "/api/admin/client-redirect-uris?client_id=%s&limit=100",
             g_ui_client);
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    const char *first = r.status == 200 ? strstr(r.body, cases[0].uri) : NULL;
    int kept = first && !strstr(first + 1, cases[0].uri) && !strstr(r.body, "a second note");
    reply_free(&r);
    if (!said || !kept) {
        FAIL("adding a redirect URI the client has answered %d%s", status,
             said ? ", and changed what's stored" : ", not 200 saying nothing changed");
    }
    printf("✓ adding a redirect URI the client has answers 200, and changes nothing\n");

    return 0;
}

/* ============================================================================
 * The issuer
 * ============================================================================ */

/*
 * Access tokens name the server's public address as their issuer, and resource
 * servers pin it: https:// and server_host behind the proxy, with no port.
 */
static int test_issuer(void) {
    printf("\n=== The issuer ===\n");

    /* 1. A token names the address the server was configured with */
    char code[2048], access[2048];
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    Reply r = exchange(code, PKCE_VERIFIER);
    int issued = r.status == 200 && field(&r, "access_token", access, sizeof(access)) == 0;
    reply_free(&r);
    if (!issued) FAIL("the code exchange failed");
    char *payload = token_payload(access);
    char *iss = payload ? json_get_string(payload, "iss") : NULL;
    int same = iss && strcmp(iss, g_config->public_base_url) == 0;
    if (!same) {
        printf("✗ a token names '%s' as its issuer, not '%s'\n",
               iss ? iss : "(none)", g_config->public_base_url);
    }
    free(iss);
    free(payload);
    if (!same) return 1;

    /* 2. Named, it's https:// and the name, as the proxy in front serves it */
    const char *host_env = g_config->server_host_env ? g_config->server_host_env
                                                     : "AUTH_SERVER_HOST";
    setenv(host_env, "auth.example.com", 1);
    config_t *named = config_load("auth.conf");
    unsetenv(host_env);
    int ok = named && strcmp(named->public_base_url, "https://auth.example.com") == 0;
    config_free(named);
    if (!ok) FAIL("a server named auth.example.com doesn't call itself https://auth.example.com");

    printf("✓ access tokens name the server's public address as their issuer\n");
    return 0;
}

/* ============================================================================
 * Client credentials, introspection, revocation, and the TTL cap
 * ============================================================================ */

/* POST a JSON body as the admin and return a string field of the reply */
static int admin_create(const char *path, const char *json, const char *key,
                        char *out, size_t size) {
    Reply r = post_json(path, g_admin_cookie, json);
    int ok = r.status == 200 && field(&r, key, out, size) == 0;
    if (!ok) printf("  %s answered %d: %s\n", path, r.status, r.body);
    reply_free(&r);
    return ok ? 0 : -1;
}

/* A table the server can't find, and its return: a failed read, where a test
   needs one. One at a time. On one connection, SQLite fails at the query's prepare
   and PostgreSQL at its step. legacy_alter_table: SQLite otherwise checks the rename
   against every view and trigger, and renaming a table some of them name fails. */
#ifdef DB_BACKEND_POSTGRESQL
#define HIDE_TABLE(schema, table) "ALTER TABLE " schema table " RENAME TO zz_hidden"
#define SHOW_TABLE(schema, table) "ALTER TABLE " schema "zz_hidden RENAME TO " table
#else
#define HIDE_TABLE(schema, table) \
    "PRAGMA legacy_alter_table = ON; ALTER TABLE " schema table " RENAME TO zz_hidden"
#define SHOW_TABLE(schema, table) "ALTER TABLE " schema "zz_hidden RENAME TO " table
#endif

/* 1 active, 0 inactive, -1 no answer about the token */
static int introspect_active(const char *token, const char *rs, const char *key,
                             const char *secret) {
    char form[4096];
    snprintf(form, sizeof(form),
             "token=%s&resource_server_id=%s&resource_server_key_id=%s&resource_server_secret=%s",
             token, rs, key, secret);
    Reply r = post_form("/introspect", form);
    int active = r.status == 200 ? (strstr(r.body, "\"active\":true") != NULL) : -1;
    reply_free(&r);
    return active;
}

/*
 * A confidential client authenticates with its key and gets a token for the
 * resource server it's linked to. Introspection answers only that server, a
 * revoked token is inactive, and the server's access-token TTL cap applies even
 * to a client stored above it.
 */
static int test_client_credentials(void) {
    printf("\n=== Client credentials, introspection, revocation ===\n");

    char json[512], rs_a[33], rs_b[33], svc[33];
    char ck[33], cs[128], ka[33], sa[128], kb[33], sb[128];

    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"rs_a\","
             "\"display_name\":\"RS A\",\"address\":\"https://a.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", rs_a, sizeof(rs_a)) != 0) return 1;
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"rs_b\","
             "\"display_name\":\"RS B\",\"address\":\"https://b.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", rs_b, sizeof(rs_b)) != 0) return 1;
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"svc\","
             "\"display_name\":\"Service\",\"client_type\":\"confidential\","
             "\"grant_type\":\"client_credentials\",\"access_token_ttl_seconds\":600}", g_org_id);
    if (admin_create("/api/admin/clients", json, "id", svc, sizeof(svc)) != 0) return 1;

    snprintf(json, sizeof(json), "{\"client_id\":\"%s\",\"resource_server_id\":\"%s\"}", svc, rs_a);
    Reply r = post_json("/api/admin/client-resource-servers", g_admin_cookie, json);
    if (r.status != 200) FAIL("linking the client to RS A answered %d", r.status);
    reply_free(&r);

    snprintf(json, sizeof(json), "{\"client_id\":\"%s\"}", svc);
    r = post_json("/api/admin/client-keys", g_admin_cookie, json);
    if (field(&r, "key_id", ck, sizeof(ck)) != 0 || field(&r, "secret", cs, sizeof(cs)) != 0) {
        FAIL("client key create answered %d", r.status);
    }
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"resource_server_id\":\"%s\"}", rs_a);
    r = post_json("/api/admin/resource-server-keys", g_admin_cookie, json);
    if (field(&r, "key_id", ka, sizeof(ka)) != 0 || field(&r, "secret", sa, sizeof(sa)) != 0) {
        FAIL("RS A key create answered %d", r.status);
    }
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"resource_server_id\":\"%s\"}", rs_b);
    r = post_json("/api/admin/resource-server-keys", g_admin_cookie, json);
    if (field(&r, "key_id", kb, sizeof(kb)) != 0 || field(&r, "secret", sb, sizeof(sb)) != 0) {
        FAIL("RS B key create answered %d", r.status);
    }
    reply_free(&r);

    /* 1. A token for RS A; introspection answers RS A and no one else */
    char form[4096], token[2048];
    snprintf(form, sizeof(form), "grant_type=client_credentials&client_id=%s&client_key_id=%s"
             "&client_secret=%s", svc, ck, cs);
    r = post_form("/token", form);
    if (r.status != 200 || field(&r, "access_token", token, sizeof(token)) != 0) {
        FAIL("client_credentials answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    if (introspect_active(token, rs_a, ka, sa) != 1) FAIL("RS A sees its own token inactive");
    if (introspect_active(token, rs_b, kb, sb) != 0) FAIL("RS B can see RS A's token");
    printf("✓ a client_credentials token introspects active for its server only\n");

    /* A check that fails says nothing about the token: no answer, not "inactive" */
    db_handle_t *conn = db_pool_get_connection();
    if (db_execute_direct(conn, HIDE_TABLE(SESSION_, "access_token")) != 0) {
        FAIL("could not hide the access tokens");
    }
    int seen = introspect_active(token, rs_a, ka, sa);
    if (db_execute_direct(conn, SHOW_TABLE(SESSION_, "access_token")) != 0) {
        FAIL("could not show the access tokens");
    }
    if (seen != -1) FAIL("a live token, the check failing, introspected as %d", seen);
    if (introspect_active(token, rs_a, ka, sa) != 1) {
        FAIL("the same token, once the database worked, isn't active");
    }
    printf("✓ an introspection the database fails gives no answer about the token\n");

    /* 2. Revoked by its client: inactive */
    snprintf(form, sizeof(form), "token=%s&client_id=%s&client_key_id=%s&client_secret=%s",
             token, svc, ck, cs);
    r = post_form("/revoke", form);
    if (r.status != 200) FAIL("/revoke answered %d", r.status);
    reply_free(&r);
    if (introspect_active(token, rs_a, ka, sa) != 0) FAIL("a revoked token still introspects active");
    printf("✓ a revoked token introspects inactive\n");

    /* 3. A client stored above the TTL cap gets tokens at the cap: in expires_in,
          and in the exp that a resource server verifying the JWT itself trusts */
    int cap = g_config->max_access_token_ttl_seconds;
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE " TBL_CLIENT " SET access_token_ttl_seconds = %d "
             "WHERE id = " ID_FROM_HEX("%s"), cap + 3600, svc);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not raise the TTL");
    snprintf(form, sizeof(form), "grant_type=client_credentials&client_id=%s&client_key_id=%s"
             "&client_secret=%s", svc, ck, cs);
    r = post_form("/token", form);
    int expires_in = 0, exp = 0, iat = 0;
    if (r.status != 200 || json_get_int(r.body, "expires_in", &expires_in) != 0 ||
        field(&r, "access_token", token, sizeof(token)) != 0) {
        FAIL("client_credentials over the cap answered %d", r.status);
    }
    reply_free(&r);
    char *payload = token_payload(token);
    int decoded = payload && json_get_int(payload, "exp", &exp) == 0 &&
                  json_get_int(payload, "iat", &iat) == 0;
    free(payload);
    if (!decoded || expires_in != cap || exp - iat != cap) {
        FAIL("a client stored over the cap got expires_in %d and exp - iat %d, not %d",
             expires_in, exp - iat, cap);
    }

    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"too_long\","
             "\"display_name\":\"Too long\",\"client_type\":\"confidential\","
             "\"grant_type\":\"client_credentials\",\"access_token_ttl_seconds\":%d}",
             g_org_id, cap + 1);
    r = post_json("/api/admin/clients", g_admin_cookie, json);
    if (r.status != 400) FAIL("creating a client over the TTL cap answered %d", r.status);
    reply_free(&r);
    printf("✓ the TTL cap holds at issuance and at client create\n");

    /* 4. A key for a public client: refused, and no secret in the answer */
    char pub[33];
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"pub\","
             "\"display_name\":\"Public\",\"client_type\":\"public\","
             "\"grant_type\":\"authorization_code\",\"access_token_ttl_seconds\":600}", g_org_id);
    if (admin_create("/api/admin/clients", json, "id", pub, sizeof(pub)) != 0) return 1;
    snprintf(json, sizeof(json), "{\"client_id\":\"%s\"}", pub);
    r = post_json("/api/admin/client-keys", g_admin_cookie, json);
    if (r.status != 409 || strstr(r.body, "secret\":")) {
        FAIL("a key for a public client answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    r = request("DELETE", "/api/admin/client-keys?id=99999999999999999999999999999999",
                g_admin_cookie, NULL, NULL, NULL);
    if (r.status != 404) FAIL("revoking an unknown key answered %d", r.status);
    reply_free(&r);
    printf("✓ writes that match nothing answer 409/404, with no secret\n");

    return 0;
}

/*
 * A field sent as another kind of value ("3600" in quotes, 12345 for a name) is
 * refused, naming the field: a client's on create and on update, and the admin
 * listener's alike. Taken as left out, it would give the client no key-age
 * limit, or no MFA, or keep its old name, and answer 200 for whatever else the
 * body changed. A flag sent as null counts as left out: read as false, an update
 * that doesn't mean to touch MFA would switch it off.
 */
static int test_field_kinds(void) {
    printf("\n=== A field of the wrong kind ===\n");

    /* 1. Create: refused, and nothing made, so the code name is still free */
    const char *sent[2][2] = {
        { "secret_rotation_seconds", "\"3600\"" },
        { "require_mfa", "\"true\"" },
    };
    char json[512], id[33];
    for (size_t i = 0; i < 2; i++) {
        snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"kinds\","
                 "\"display_name\":\"Kinds\",\"client_type\":\"confidential\","
                 "\"grant_type\":\"authorization_code\",\"access_token_ttl_seconds\":600,"
                 "\"%s\":%s}", g_org_id, sent[i][0], sent[i][1]);
        Reply r = post_json("/api/admin/clients", g_admin_cookie, json);
        int refused = r.status == 400 && strstr(r.body, sent[i][0]);
        if (!refused) FAIL("creating a client with %s %s answered %d: %s",
                           sent[i][0], sent[i][1], r.status, r.body);
        reply_free(&r);
    }
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"kinds\","
             "\"display_name\":\"Kinds\",\"client_type\":\"confidential\","
             "\"grant_type\":\"authorization_code\",\"access_token_ttl_seconds\":600,"
             "\"secret_rotation_seconds\":3600,\"require_mfa\":true}", g_org_id);
    if (admin_create("/api/admin/clients", json, "id", id, sizeof(id)) != 0) return 1;

    /* 2. Update: refused beside a good field, and nothing changes */
    char target[128], name[64];
    snprintf(target, sizeof(target), "/api/admin/clients?id=%s", id);
    Reply r = request("PUT", target, g_admin_cookie, NULL, "application/json",
                      "{\"display_name\":\"Renamed\",\"secret_rotation_seconds\":\"60\"}");
    int refused = r.status == 400 && strstr(r.body, "secret_rotation_seconds");
    if (!refused) FAIL("an update with a key age in quotes answered %d: %s", r.status, r.body);
    reply_free(&r);
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    int age = 0;
    int kept = r.status == 200 && json_get_int(r.body, "secret_rotation_seconds", &age) == 0 &&
               age == 3600 && field(&r, "display_name", name, sizeof(name)) == 0 &&
               strcmp(name, "Kinds") == 0;
    reply_free(&r);
    if (!kept) FAIL("a refused update changed the client (key age %d)", age);

    /* 3. A flag sent as null beside a good field: the flag is left as it is */
    r = request("PUT", target, g_admin_cookie, NULL, "application/json",
                "{\"display_name\":\"Renamed\",\"require_mfa\":null}");
    int applied = r.status == 200;
    reply_free(&r);
    if (!applied) FAIL("an update with require_mfa null beside a display name was refused");
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    int mfa = 0;
    int left = r.status == 200 && json_get_bool(r.body, "require_mfa", &mfa) == 0 && mfa == 1 &&
               field(&r, "display_name", name, sizeof(name)) == 0 && strcmp(name, "Renamed") == 0;
    reply_free(&r);
    if (!left) FAIL("require_mfa null turned MFA off, or the display name wasn't applied");

    /* 4. Text of another kind beside a good field: refused, and nothing changes */
    r = request("PUT", target, g_admin_cookie, NULL, "application/json",
                "{\"display_name\":12345,\"require_mfa\":false}");
    refused = r.status == 400 && strstr(r.body, "display_name");
    reply_free(&r);
    if (!refused) FAIL("an update with display_name 12345 wasn't refused naming it");
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    mfa = 0;
    kept = r.status == 200 && json_get_bool(r.body, "require_mfa", &mfa) == 0 && mfa == 1 &&
           field(&r, "display_name", name, sizeof(name)) == 0 && strcmp(name, "Renamed") == 0;
    reply_free(&r);
    if (!kept) FAIL("a refused update with display_name 12345 changed the client");

    /* 5. The admin listener's bodies too: an organization key's secret as a number,
          which a generated secret would otherwise stand in for */
    r = admin_port("POST", "/api/admin/organization-keys", NULL,
                   "{\"organization_code_name\":\"system\",\"secret\":12345678}");
    refused = r.status == 400 && strstr(r.body, "secret must be text");
    reply_free(&r);
    if (!refused) FAIL("an organization key with a numeric secret wasn't refused naming it");

    printf("✓ a field of the wrong kind is refused, and null leaves one as it is\n");
    return 0;
}

/* ============================================================================
 * One active holder per address and code name
 * ============================================================================ */

/* PUT a JSON body as the admin: whether it answered want, naming what's given */
static int put_answers(const char *target, const char *json, int want, const char *naming) {
    Reply r = request("PUT", target, g_admin_cookie, NULL, "application/json", json);
    int ok = r.status == want && (!naming || strstr(r.body, naming));
    if (!ok) printf("  PUT %s %s answered %d: %s\n", target, json, r.status, r.body);
    reply_free(&r);
    return ok;
}

/* A POST with the given session answers want, naming the text if given */
static int post_answers(const char *path, const char *cookie, const char *json, int want,
                        const char *naming) {
    Reply r = post_json(path, cookie, json);
    int ok = r.status == want && (!naming || strstr(r.body, naming));
    if (!ok) printf("  POST %s %s answered %d: %s\n", path, json, r.status, r.body);
    reply_free(&r);
    return ok;
}

/* A server's or client's is_active as GET answers it, with a text field of it
   when key is given; -1 if either can't be read */
static int active_with(const char *target, const char *key, char *out, size_t size) {
    Reply r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    int active = -1;
    if (r.status != 200 || json_get_bool(r.body, "is_active", &active) != 0 ||
        (key && field(&r, key, out, size) != 0)) {
        active = -1;
    }
    reply_free(&r);
    return active;
}

/*
 * In an organization, one active resource server has a given address and a given
 * code name, and one active client a given code name. An update that would break
 * that answers 409 naming which, and changes nothing. A deactivated server keeps
 * an address an active one has taken, and its edits still save, though the
 * console sends the address with every edit. Creating one that would break it
 * answers 409 naming which too, and creating one in an organization that isn't
 * there, or isn't the caller's, answers 404.
 */
static int test_active_clashes(void) {
    printf("\n=== One active holder per address and code name ===\n");

    char json[512], a[33], b[33], c[33], cl[33], twin[33], text[64];
    char ta[128], tb[128], tc[128], tcl[128];

    /* A server, deactivated, and another made at its address */
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"clash_a\","
             "\"display_name\":\"A\",\"address\":\"https://clash.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", a, sizeof(a)) != 0) return 1;
    snprintf(ta, sizeof(ta), "/api/admin/resource-servers?id=%s", a);
    if (!put_answers(ta, "{\"is_active\":false}", 200, NULL)) return 1;
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"clash_b\","
             "\"display_name\":\"B\",\"address\":\"https://clash.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", b, sizeof(b)) != 0) return 1;
    snprintf(tb, sizeof(tb), "/api/admin/resource-servers?id=%s", b);

    /* 1. The deactivated one's edit, sent as the console sends it: saved */
    if (!put_answers(ta, "{\"display_name\":\"A\",\"address\":\"https://clash.example\","
                     "\"note\":\"kept\",\"is_active\":false,\"allow_user_provisioning\":false}",
                     200, NULL) ||
        active_with(ta, "note", text, sizeof(text)) != 0 || strcmp(text, "kept") != 0) {
        FAIL("an edit to a deactivated server whose address an active one has wasn't saved");
    }

    /* 2. Reactivating it at that address: refused, and it stays deactivated */
    if (!put_answers(ta, "{\"is_active\":true}", 409, "address") ||
        active_with(ta, NULL, NULL, 0) != 0) {
        FAIL("reactivating a server at a taken address wasn't refused, or changed it");
    }

    /* 3. Reactivating it at a free address: done */
    if (!put_answers(ta, "{\"is_active\":true,\"address\":\"https://clash-a.example\"}",
                     200, NULL) ||
        active_with(ta, "address", text, sizeof(text)) != 1 ||
        strcmp(text, "https://clash-a.example") != 0) {
        FAIL("reactivating a server at a free address didn't take");
    }

    /* 4. An active server moving to a taken address: refused, and its address
          kept. An update that changes nothing is a success. */
    if (!put_answers(tb, "{\"address\":\"https://clash-a.example\"}", 409, "address") ||
        active_with(tb, "address", text, sizeof(text)) != 1 ||
        strcmp(text, "https://clash.example") != 0) {
        FAIL("moving an active server to a taken address wasn't refused, or changed it");
    }
    if (!put_answers(tb, "{\"display_name\":\"B\"}", 200, NULL)) {
        FAIL("an update that changes nothing wasn't a success");
    }

    /* 5. A server reactivated while another active one has its code name */
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"clash_c\","
             "\"display_name\":\"C\",\"address\":\"https://c1.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", c, sizeof(c)) != 0) return 1;
    snprintf(tc, sizeof(tc), "/api/admin/resource-servers?id=%s", c);
    if (!put_answers(tc, "{\"is_active\":false}", 200, NULL)) return 1;
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"clash_c\","
             "\"display_name\":\"C\",\"address\":\"https://c2.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", twin, sizeof(twin)) != 0) return 1;
    if (!put_answers(tc, "{\"is_active\":true}", 409, "code name") ||
        active_with(tc, NULL, NULL, 0) != 0) {
        FAIL("reactivating a server whose code name is taken wasn't refused, or changed it");
    }

    /* 6. The same for a client */
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"clash_d\","
             "\"display_name\":\"D\",\"client_type\":\"public\","
             "\"grant_type\":\"authorization_code\",\"access_token_ttl_seconds\":600}", g_org_id);
    if (admin_create("/api/admin/clients", json, "id", cl, sizeof(cl)) != 0) return 1;
    snprintf(tcl, sizeof(tcl), "/api/admin/clients?id=%s", cl);
    if (!put_answers(tcl, "{\"is_active\":false}", 200, NULL)) return 1;
    if (admin_create("/api/admin/clients", json, "id", twin, sizeof(twin)) != 0) return 1;
    if (!put_answers(tcl, "{\"is_active\":true}", 409, "code name") ||
        active_with(tcl, NULL, NULL, 0) != 0) {
        FAIL("reactivating a client whose code name is taken wasn't refused, or changed it");
    }

    /* 7. Creating one that would break the rule, or in an organization that isn't
          there or isn't the caller's: refused, naming why */
    const char *nowhere = "0123456789abcdef0123456789abcdef";
    char outsider[256];
    Reply u = admin_port("POST", "/api/admin/users", NULL,
                         "{\"username\":\"outsider\",\"password\":\"outsider password\"}");
    int made_user = u.status == 200;
    reply_free(&u);
    if (!made_user || login("outsider", "outsider password", outsider, sizeof(outsider)) != 0) {
        FAIL("could not create and sign in a user who administers nothing");
    }
    const struct { const char *org, *code_name, *address; int as_outsider, want;
                   const char *naming; } servers[] = {
        { g_org_id, "clash_b", "https://free.example", 0, 409, "code name" },
        { g_org_id, "clash_free", "https://clash.example", 0, 409, "address" },
        { nowhere, "clash_free", "https://free.example", 0, 404, NULL },
        { g_org_id, "clash_free", "https://free.example", 1, 404, NULL },
    };
    for (size_t i = 0; i < sizeof(servers) / sizeof(servers[0]); i++) {
        snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"%s\","
                 "\"display_name\":\"X\",\"address\":\"%s\"}", servers[i].org,
                 servers[i].code_name, servers[i].address);
        if (!post_answers("/api/admin/resource-servers",
                          servers[i].as_outsider ? outsider : g_admin_cookie, json,
                          servers[i].want, servers[i].naming)) {
            FAIL("creating a resource server wasn't refused with %d%s%s", servers[i].want,
                 servers[i].naming ? " naming its " : "",
                 servers[i].naming ? servers[i].naming : "");
        }
    }
    const struct { const char *org, *code_name; int as_outsider, want;
                   const char *naming; } clients[] = {
        { g_org_id, "clash_d", 0, 409, "code name" },
        { nowhere, "clash_free", 0, 404, NULL },
        { g_org_id, "clash_free", 1, 404, NULL },
    };
    for (size_t i = 0; i < sizeof(clients) / sizeof(clients[0]); i++) {
        snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"%s\","
                 "\"display_name\":\"X\",\"client_type\":\"public\","
                 "\"grant_type\":\"authorization_code\",\"access_token_ttl_seconds\":600}",
                 clients[i].org, clients[i].code_name);
        if (!post_answers("/api/admin/clients",
                          clients[i].as_outsider ? outsider : g_admin_cookie, json,
                          clients[i].want, clients[i].naming)) {
            FAIL("creating a client wasn't refused with %d%s%s", clients[i].want,
                 clients[i].naming ? " naming its " : "",
                 clients[i].naming ? clients[i].naming : "");
        }
    }

    printf("✓ one active holder per address and code name, and a deactivated server's "
           "edits save; a create that would clash answers 409 naming which, and one in an "
           "organization not the caller's 404\n");
    return 0;
}

/* ============================================================================
 * MFA gates
 * ============================================================================ */

static int totp_now(const char *secret, char *code, size_t size) {
    return crypto_totp_generate_code(secret, time(NULL), code, size);
}

/*
 * Once a user has a factor, managing factors takes that factor, whatever the
 * require preference says, so a password alone can't add, remove or replace
 * one, or list its recovery codes. With require on, the user's own endpoints
 * and the admin API refuse a session that hasn't completed MFA.
 */
static int test_mfa_gates(void) {
    printf("\n=== MFA gates ===\n");

    /* A second user, an org admin, so the admin API can be checked too */
    char user_id[33];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"mfa-user\",\"password\":\"mfa user password\"}");
    if (r.status != 200 || field(&r, "user_id", user_id, sizeof(user_id)) != 0) {
        FAIL("creating the MFA user answered %d", r.status);
    }
    reply_free(&r);
    r = admin_port("POST", "/api/admin/org-admins", NULL,
                  "{\"username\":\"mfa-user\",\"org_code_name\":\"system\"}");
    if (r.status != 200) FAIL("making them an org admin answered %d", r.status);
    reply_free(&r);

    char first[256], second[256], method[33], secret[64], code[16], json[256];
    if (login("mfa-user", "mfa user password", first, sizeof(first)) != 0) FAIL("first sign-in");

    /* Enroll: setup, then confirm with a code from the new secret */
    r = post_json("/api/user/mfa/totp/setup", first, "{\"display_name\":\"phone\"}");
    if (r.status != 200 || field(&r, "method_id", method, sizeof(method)) != 0 ||
        field(&r, "secret", secret, sizeof(secret)) != 0) {
        FAIL("TOTP setup answered %d", r.status);
    }
    reply_free(&r);
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    r = post_json("/api/user/mfa/totp/confirm", first, json);
    if (r.status != 200) FAIL("TOTP confirm answered %d", r.status);
    /* The recovery codes a first method gives, for step 6 */
    char codes[16][32];
    int code_count = string_array(r.body, "recovery_codes", codes, 16);
    reply_free(&r);
    if (code_count <= 0) FAIL("the first method's confirm gave no recovery codes");

    /* 1. Enrolled, require off, a password-only session: every factor-management
          endpoint wants the factor first */
    if (login("mfa-user", "mfa user password", second, sizeof(second)) != 0) FAIL("second sign-in");
    char target[128];
    snprintf(target, sizeof(target), "/api/user/mfa/methods?id=%s", method);
    Reply gated[6] = {
        post_json("/api/user/mfa/totp/setup", second, "{\"display_name\":\"other\"}"),
        post_json("/api/user/mfa/totp/confirm", second, json),
        request("DELETE", target, second, NULL, NULL, NULL),
        post_json("/api/user/mfa/recovery-codes/regenerate", second, "{}"),
        request("GET", "/api/user/mfa/recovery-codes", second, NULL, NULL, NULL),
        post_json("/api/user/mfa/require", second, "{\"enabled\":true}"),
    };
    const char *names[6] = { "setup", "confirm", "delete", "regenerate", "recovery codes",
                             "require" };
    for (int i = 0; i < 6; i++) {
        int bad = gated[i].status != 403;
        if (bad) printf("✗ %s answered %d to a password-only session\n", names[i], gated[i].status);
        reply_free(&gated[i]);
        if (bad) return 1;
    }
    printf("✓ the six factor-management endpoints refuse a password-only session\n");

    /* Their own profile and the admin API are another rule: those ask for the
       factor only once the user requires it */
    r = request("GET", "/api/user/profile", second, NULL, NULL, NULL);
    int open_profile = r.status;
    reply_free(&r);
    r = request("GET", "/api/admin/organizations", second, NULL, NULL, NULL);
    int open_admin = r.status;
    reply_free(&r);
    if (open_profile != 200 || open_admin != 200) {
        FAIL("with require off, a password-only session got profile %d, admin %d",
             open_profile, open_admin);
    }
    printf("✓ while require is off, the same session reaches its profile and the admin API\n");

    /* 2. The same session verifies the factor and is let through */
    r = post_json("/api/user/mfa/verify", second, json);
    if (r.status != 200) FAIL("verify answered %d", r.status);
    reply_free(&r);
    r = post_json("/api/user/mfa/require", second, "{\"enabled\":true}");
    if (r.status != 200) FAIL("require answered %d after verifying", r.status);
    reply_free(&r);
    printf("✓ after the MFA step, factor management opens\n");

    /* 3. Require on: a password-only session is refused by the user and admin APIs */
    char third[256];
    if (login("mfa-user", "mfa user password", third, sizeof(third)) != 0) FAIL("third sign-in");
    r = request("GET", "/api/user/profile", third, NULL, NULL, NULL);
    int profile = r.status;
    reply_free(&r);
    r = request("GET", "/api/admin/organizations", third, NULL, NULL, NULL);
    int admin = r.status;
    reply_free(&r);
    if (profile != 403 || admin != 403) {
        FAIL("with require on, a password-only session got profile %d, admin %d", profile, admin);
    }
    printf("✓ with require on, a password-only session is refused (403)\n");

    /* 4. A new password closes the session left waiting on MFA, which could
          still submit codes against the daily cap, and not the signed-in one:
          changed by the user, by a reset link, or by the operator */
    char sql[512], reset_hash[SHA256_HEX_LENGTH], set_json[160], pending_cookie[256];
    if (crypto_sha256_hex("mfa-reset", 9, reset_hash, sizeof(reset_hash)) != 0) FAIL("sha256");
    snprintf(sql, sizeof(sql),
             "INSERT INTO " TBL_PASSWORD_RESET_TOKEN " (id, user_account_pin, token, issued_at, "
             "expected_expiry) SELECT " NEW_ID ", pin, '%s', " NOW ", " INTERVAL_SECONDS("3600") " "
             "FROM " TBL_USER_ACCOUNT " WHERE id = " ID_FROM_HEX("%s"), reset_hash, user_id);
    snprintf(set_json, sizeof(set_json),
             "{\"user_id\":\"%s\",\"password\":\"mfa user password 4\"}", user_id);
    static const char *ways[3] = { "a change", "a reset", "set-password" };
    static const char *passwords[3] = {
        "mfa user password", "mfa user password 2", "mfa user password 3" };
    for (int i = 0; i < 3; i++) {
        /* The session waiting on MFA: step 3's, then one opened with the current password */
        if (i == 0) {
            snprintf(pending_cookie, sizeof(pending_cookie), "%s", third);
        } else if (login("mfa-user", passwords[i], pending_cookie, sizeof(pending_cookie)) != 0) {
            FAIL("could not open a session waiting on MFA");
        }
        int changed;
        if (i == 0) {
            r = post_json("/api/user/password", second,
                          "{\"current_password\":\"mfa user password\","
                          "\"new_password\":\"mfa user password 2\"}");
        } else if (i == 1) {
            changed = db_execute_direct(db_pool_get_connection(), sql) == 0 &&
                      user_consume_password_reset_token(db_pool_get_connection(), "mfa-reset",
                                                        "mfa user password 3") == 0;
        } else {
            r = admin_port("POST", "/api/admin/users/set-password", NULL, set_json);
        }
        if (i != 1) {
            changed = r.status == 200;
            reply_free(&r);
        }
        if (!changed) FAIL("the password wasn't set by %s", ways[i]);
        r = post_json("/api/user/mfa/verify", pending_cookie, json);
        int pending = r.status;
        reply_free(&r);
        r = request("GET", "/api/user/profile", second, NULL, NULL, NULL);
        int signed_in = r.status;
        reply_free(&r);
        if (pending != 401 || signed_in != 200) {
            FAIL("after %s, the pending session's verify got %d, the signed-in session's "
                 "profile %d", ways[i], pending, signed_in);
        }
    }
    printf("✓ a new password, however set, closes the session waiting on MFA; the signed-in "
           "one stays\n");

    /* 5. A refused MFA request answers 404 or 409, not 500. Another user's method
          answers as an unknown one does, so method ids can't be told apart. The
          bootstrap admin, who has no MFA method, is the other user. */
    static const char unknown_id[] = "0123456789abcdef0123456789abcdef";
    char mine[96], unknown[96], unknown_target[96];
    snprintf(mine, sizeof(mine), "{\"method_id\":\"%s\",\"code\":\"000000\"}", method);
    snprintf(unknown, sizeof(unknown), "{\"method_id\":\"%s\",\"code\":\"000000\"}", unknown_id);
    snprintf(unknown_target, sizeof(unknown_target), "/api/user/mfa/methods?id=%s", unknown_id);
    static const char *const refusals[6] = {
        "confirming another user's method", "confirming an unknown method",
        "deleting another user's method", "deleting an unknown method",
        "confirming a confirmed method, still there", "recovery codes without a confirmed method",
    };
    static const int want[6] = { 404, 404, 404, 404, 409, 409 };
    int got[6];
    r = post_json("/api/user/mfa/totp/confirm", g_admin_cookie, mine);
    got[0] = r.status;
    reply_free(&r);
    r = post_json("/api/user/mfa/totp/confirm", second, unknown);
    got[1] = r.status;
    reply_free(&r);
    r = request("DELETE", target, g_admin_cookie, NULL, NULL, NULL);
    got[2] = r.status;
    reply_free(&r);
    r = request("DELETE", unknown_target, second, NULL, NULL, NULL);
    got[3] = r.status;
    reply_free(&r);
    r = post_json("/api/user/mfa/totp/confirm", second, mine);
    got[4] = r.status;
    reply_free(&r);
    r = post_json("/api/user/mfa/recovery-codes/regenerate", g_admin_cookie, "{}");
    got[5] = r.status;
    reply_free(&r);
    for (int i = 0; i < 6; i++) {
        if (got[i] != want[i]) FAIL("%s answered %d, not %d", refusals[i], got[i], want[i]);
    }
    printf("✓ a refused MFA request answers 404 or 409, and another user's method is unknown\n");

    /* 6. The caller's own recovery codes, masked: the last four characters of
          each code the first method gave, in order, none used, and nothing more.
          The request names no account, so the admin, who has no codes, gets an
          empty list rather than anyone else's. */
    char expected[1024];
    int at = snprintf(expected, sizeof(expected), "{\"recovery_codes\":[");
    for (int i = 0; i < code_count; i++) {
        at += snprintf(expected + at, sizeof(expected) - (size_t)at,
                       "%s{\"last4\":\"%s\",\"used\":false}", i > 0 ? "," : "",
                       codes[i] + strlen(codes[i]) - 4);
    }
    snprintf(expected + at, sizeof(expected) - (size_t)at, "]}");
    r = request("GET", "/api/user/mfa/recovery-codes", second, NULL, NULL, NULL);
    int own = r.status == 200 && strcmp(r.body, expected) == 0;
    if (!own) printf("  listed %d: %s\n  wanted: %s\n", r.status, r.body, expected);
    reply_free(&r);
    r = request("GET", "/api/user/mfa/recovery-codes", g_admin_cookie, NULL, NULL, NULL);
    int none = r.status == 200 && strcmp(r.body, "{\"recovery_codes\":[]}") == 0;
    reply_free(&r);
    if (!own || !none) FAIL("the masked recovery codes weren't the caller's own, or only theirs");
    printf("✓ a user lists their own recovery codes, masked, and no one else's\n");

    return 0;
}

/* A row's address in its table, to pick one of several alike; and a trigger
   that makes every insert into the MFA attempt log fail, and its removal */
#ifdef DB_BACKEND_POSTGRESQL
#define ROW_ADDRESS "ctid"
#define REFUSE_MFA_USAGE \
    "CREATE FUNCTION refuse_mfa_usage() RETURNS trigger LANGUAGE plpgsql " \
    "AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; " \
    "CREATE TRIGGER refuse_mfa_usage BEFORE INSERT ON " TBL_USER_MFA_USAGE " " \
    "FOR EACH ROW EXECUTE FUNCTION refuse_mfa_usage()"
#define ALLOW_MFA_USAGE "DROP FUNCTION refuse_mfa_usage() CASCADE"
#else
#define ROW_ADDRESS "rowid"
#define REFUSE_MFA_USAGE \
    "CREATE TRIGGER refuse_mfa_usage BEFORE INSERT ON " TBL_USER_MFA_USAGE " " \
    "BEGIN SELECT RAISE(FAIL, 'refused'); END"
#define ALLOW_MFA_USAGE "DROP TRIGGER refuse_mfa_usage"
#endif

/*
 * Ten failed codes in a day, across the user's methods, refuse even a right
 * code; failures older than a day don't count. (The per-minute limit is
 * avoided by dating the failures hours back.)
 */
static int test_mfa_daily_cap(void) {
    printf("\n=== MFA daily cap ===\n");

    char cookie[256], method[33], secret[64], code[16], json[256], sql[512];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"capped\",\"password\":\"capped password\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 200 || login("capped", "capped password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }
    r = post_json("/api/user/mfa/totp/setup", cookie, "{\"display_name\":\"phone\"}");
    if (r.status != 200 || field(&r, "method_id", method, sizeof(method)) != 0 ||
        field(&r, "secret", secret, sizeof(secret)) != 0) {
        FAIL("TOTP setup answered %d", r.status);
    }
    reply_free(&r);
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    r = post_json("/api/user/mfa/totp/confirm", cookie, json);
    status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("TOTP confirm answered %d", status);

    /* 1. Ten failures two hours ago: a right code is refused */
    snprintf(sql, sizeof(sql),
             "INSERT INTO " TBL_USER_MFA_USAGE " (user_mfa_pin, submitted_at, success) "
             "SELECT pin, " SECONDS_AGO("7200") ", " BOOL_FALSE " FROM " TBL_USER_MFA " "
             "WHERE id = " ID_FROM_HEX("%s"), method);
    for (int i = 0; i < 10; i++) {
        if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not plant failures");
    }
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    r = post_json("/api/user/mfa/verify", cookie, json);
    status = r.status;
    reply_free(&r);
    if (status != 429) FAIL("after ten failures in a day, a right code answered %d", status);

    /* 2. Nine: the right code works */
    snprintf(sql, sizeof(sql),
             "DELETE FROM " TBL_USER_MFA_USAGE " WHERE " ROW_ADDRESS " = (SELECT " ROW_ADDRESS " "
             "FROM " TBL_USER_MFA_USAGE " WHERE success = " BOOL_FALSE " AND user_mfa_pin = "
             "(SELECT pin FROM " TBL_USER_MFA " WHERE id = " ID_FROM_HEX("%s") ") "
             "ORDER BY submitted_at DESC LIMIT 1)", method);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not remove a failure");
    r = post_json("/api/user/mfa/verify", cookie, json);
    int nine = r.status == 200 && strstr(r.body, "\"valid\":true") != NULL;
    reply_free(&r);
    if (!nine) FAIL("after nine failures in a day, a right code was refused");
    printf("✓ ten failed codes in a day refuse even a right one; nine don't\n");

    /* 3. Failures older than a day don't count */
    snprintf(sql, sizeof(sql),
             "UPDATE " TBL_USER_MFA_USAGE " SET submitted_at = " SECONDS_AGO("90000") " "
             "WHERE success = " BOOL_FALSE " AND user_mfa_pin = (SELECT pin FROM " TBL_USER_MFA " "
             "WHERE id = " ID_FROM_HEX("%s") ")", method);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not age the failures");
    snprintf(sql, sizeof(sql),
             "INSERT INTO " TBL_USER_MFA_USAGE " (user_mfa_pin, submitted_at, success) "
             "SELECT pin, " SECONDS_AGO("90000") ", " BOOL_FALSE " FROM " TBL_USER_MFA " "
             "WHERE id = " ID_FROM_HEX("%s"), method);
    for (int i = 0; i < 5; i++) {
        if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not plant failures");
    }
    r = post_json("/api/user/mfa/verify", cookie, json);
    int aged = r.status == 200 && strstr(r.body, "\"valid\":true") != NULL;
    reply_free(&r);
    if (!aged) FAIL("fourteen failures more than a day old still refused a right code");
    printf("✓ failures more than a day old don't count\n");

    /* 4. The limits count recorded attempts, so one that can't be recorded gets
          no verdict: right code or wrong, the same 503 */
    db_handle_t *conn = db_pool_get_connection();
    if (db_execute_direct(conn, REFUSE_MFA_USAGE) != 0) {
        FAIL("could not make the attempt log refuse");
    }
    r = post_json("/api/user/mfa/verify", cookie, json);
    int right = r.status;
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method,
             strcmp(code, "000000") == 0 ? "111111" : "000000");
    r = post_json("/api/user/mfa/verify", cookie, json);
    int wrong = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_MFA_USAGE) != 0) FAIL("could not drop the trigger");
    if (right != 503 || wrong != 503) {
        FAIL("an attempt that couldn't be recorded answered %d (right code), %d (wrong)", right, wrong);
    }
    r = post_json("/api/user/mfa/verify", cookie, json);
    int recorded = r.status == 200 && strstr(r.body, "\"valid\":false") != NULL;
    reply_free(&r);
    if (!recorded) FAIL("with the log back, a wrong code wasn't answered as wrong");
    printf("✓ an attempt that can't be recorded gets no verdict, right code or wrong\n");

    /* 5. A client whose User-Agent isn't UTF-8, which PostgreSQL won't store: its
          attempt is recorded with the header cleaned, and answered */
    char agent[64];
    r = request("POST", "/api/user/mfa/verify", cookie, "User-Agent: odd \xff agent\r\n",
                "application/json", json);
    int answered = r.status == 200 && strstr(r.body, "\"valid\":false") != NULL;
    reply_free(&r);
    if (!answered) FAIL("an attempt with an ill-formed User-Agent wasn't answered");
    if (query_text("SELECT user_agent FROM " TBL_USER_MFA_USAGE " WHERE user_agent LIKE 'odd %'",
                   agent, sizeof(agent)) != 0 || strcmp(agent, "odd ? agent") != 0) {
        FAIL("the attempt's User-Agent was stored as '%s'", agent);
    }
    printf("✓ an attempt with an ill-formed User-Agent is recorded, the header cleaned\n");

    return 0;
}

/* ============================================================================
 * Localhost only
 * ============================================================================ */

static int list_orgs_status(const char *headers) {
    Reply r = admin_port("GET", "/api/admin/list-all-organizations", headers, NULL);
    int status = r.status;
    reply_free(&r);
    return status;
}

/* The admin socket's caller ("local"), on the admin listener and, as can't
   happen, on the public one: the listener is what decides */
static int test_admin_socket_caller(void) {
    printf("\n=== Admin socket caller ===\n");
    g_remote_ip = "local";
    int on_admin = list_orgs_status(NULL);
    Reply r = request("GET", "/api/admin/list-all-organizations", NULL, NULL, NULL, NULL);
    int on_public = r.status;
    reply_free(&r);
    g_remote_ip = "127.0.0.1";
    if (on_admin != 200) FAIL("the admin socket's caller answered %d on the admin listener", on_admin);
    if (on_public != 403) FAIL("the admin socket's caller answered %d on the public listener", on_public);
    printf("✓ the admin socket's caller is let in on the admin listener, refused on the public one\n");

    /* The public port refuses with 403 whatever the request: a body that isn't
       JSON doesn't get the 415 first */
    r = request("POST", "/api/admin/bootstrap", NULL, NULL, "text/plain", "not json");
    int plain = r.status;
    reply_free(&r);
    if (plain != 403) FAIL("a non-JSON request to the public port answered %d", plain);
    printf("✓ the public port answers 403 before looking at the body\n");
    return 0;
}

/*
 * The localhost-only endpoints are served on the admin listener alone: on the
 * public one they're refused however local the request looks. And a browser
 * that can reach the admin port over loopback is not the operator: a web page
 * rebinding its own name to 127.0.0.1 sends its name as Host, and Origin and
 * Sec-Fetch-* besides. Any one of them is refused; curl's requests pass.
 */
static int test_localhost_only(void) {
    printf("\n=== Localhost only ===\n");

    /* Every route that serves the operator: refused on the public listener (403,
       or for org keys, which that one takes, 401), and on the admin listener not.
       There, made-up ids and empty bodies get the handlers' own 400s and 404s. */
    static const struct { const char *method, *target; } operator_routes[] = {
        { "POST", "/api/admin/bootstrap" },
        { "POST", "/api/admin/organizations" },
        { "POST", "/api/admin/org-admins" },
        { "GET", "/api/admin/list-all-organizations" },
        { "POST", "/api/admin/users" },
        { "POST", "/api/admin/users/activate" },
        { "POST", "/api/admin/users/deactivate" },
        { "POST", "/api/admin/users/reset-mfa" },
        { "POST", "/api/admin/users/set-password" },
        { "GET", "/api/admin/users/emails" },
        { "DELETE", "/api/admin/users/emails" },
        { "POST", "/api/admin/organization-keys" },
        { "GET", "/api/admin/organization-keys" },
        { "DELETE", "/api/admin/organization-keys?id=ffffffffffffffffffffffffffffffff" },
    };
    for (size_t i = 0; i < sizeof(operator_routes) / sizeof(operator_routes[0]); i++) {
        const char *method = operator_routes[i].method, *target = operator_routes[i].target;
        Reply pub = request(method, target, NULL, NULL, "application/json", "{}");
        Reply adm = admin_port(method, target, NULL, "{}");
        int refused = pub.status == 403 || pub.status == 401;
        int served = adm.status != 401 && adm.status != 403 && adm.status < 500;
        int pub_status = pub.status, adm_status = adm.status;
        reply_free(&pub);
        reply_free(&adm);
        if (!refused || !served) {
            FAIL("%s %s answered %d on the public listener and %d on the admin one",
                 method, target, pub_status, adm_status);
        }
    }
    printf("✓ every operator endpoint is refused on the public listener, served on the admin one\n");

    /* A key for an organization that isn't there is refused, not failed */
    Reply nokey = admin_port("POST", "/api/admin/organization-keys", NULL,
                             "{\"organization_code_name\":\"nosuchorg\"}");
    int nokey_status = nokey.status;
    reply_free(&nokey);
    if (nokey_status != 404) FAIL("a key for an unknown organization answered %d", nokey_status);
    printf("✓ a key for an unknown organization answers 404\n");

    static const char *const browser[] = {
        "Host: rebind.attacker.example:8080\r\n"
        "Origin: http://rebind.attacker.example:8080\r\n"
        "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\n",
        "Host: rebind.attacker.example:8080\r\n",
        "Host: localhost:8080\r\nOrigin: http://localhost:3000\r\n",
        "Host: localhost:8080\r\nSec-Fetch-Mode: navigate\r\n",
    };
    for (size_t i = 0; i < sizeof(browser) / sizeof(browser[0]); i++) {
        int status = list_orgs_status(browser[i]);
        if (status != 403) FAIL("a browser-made request (case %zu) answered %d", i + 1, status);
    }
    Reply r = admin_port("POST", "/api/admin/users/set-password", browser[0],
                         "{\"user_id\":\"ffffffffffffffffffffffffffffffff\","
                         "\"password\":\"attacker chose this\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 403) FAIL("a rebound set-password answered %d", status);
    printf("✓ a foreign Host, an Origin or a Sec-Fetch-* header is refused (403)\n");

    static const char *const local[] = {
        NULL, "Host: localhost:8080\r\n", "Host: LOCALHOST\r\n",
        "Host: 127.0.0.1:8080\r\n", "Host: [::1]:8080\r\n",
    };
    for (size_t i = 0; i < sizeof(local) / sizeof(local[0]); i++) {
        status = list_orgs_status(local[i]);
        if (status != 200) FAIL("a local request (case %zu) answered %d", i + 1, status);
    }
    printf("✓ no Host, or a loopback one with any port, is local\n");

    return 0;
}

/* ============================================================================
 * Account recovery
 * ============================================================================ */

static int post_status(const char *path, const char *json) {
    Reply r = admin_port("POST", path, NULL, json);
    int status = r.status;
    reply_free(&r);
    return status;
}

/*
 * The operator sets a password, whether or not the account is active. After a
 * compromise: deactivate, set a new password, reactivate, and the old password
 * works at no point in between. An invitation outstanding can't set another.
 */
static int test_account_recovery(void) {
    printf("\n=== Account recovery ===\n");

    char user_id[33], json[256], cookie[256], sql[128], pin[24], invite[64];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"recovered\",\"password\":\"the old password\"}");
    int status = r.status;
    int created = status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    if (!created) FAIL("creating the user answered %d", status);

    /* 1. Active, with an invitation and a reset link outstanding: the new password
          signs in, the old one doesn't, and neither link can set another. The
          session the old one opened stays: deactivation is what evicts */
    char reset_hash[SHA256_HEX_LENGTH], insert[512], before[256];
    if (login("recovered", "the old password", before, sizeof(before)) != 0) FAIL("could not sign in");
    snprintf(sql, sizeof(sql), "SELECT pin FROM " TBL_USER_ACCOUNT " WHERE id = " ID_FROM_HEX("%s"),
             user_id);
    if (query_text(sql, pin, sizeof(pin)) != 0 ||
        user_create_invitation_token(db_pool_get_connection(), atoll(pin), 0, 3600, NULL,
                                     invite) != 0 ||
        crypto_sha256_hex("recovery-reset", 14, reset_hash, sizeof(reset_hash)) != 0) {
        FAIL("could not plant an invitation");
    }
    /* A reset link is a row with a known token hash: all its redemption reads */
    snprintf(insert, sizeof(insert),
             "INSERT INTO " TBL_PASSWORD_RESET_TOKEN " (id, user_account_pin, token, issued_at, "
             "expected_expiry) VALUES (" NEW_ID ", %s, '%s', " NOW ", " INTERVAL_SECONDS("3600") ")",
             pin, reset_hash);
    if (db_execute_direct(db_pool_get_connection(), insert) != 0) FAIL("could not plant a reset link");
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\",\"password\":\"the new password\"}", user_id);
    status = post_status("/api/admin/users/set-password", json);
    if (status != 200) FAIL("set-password answered %d", status);
    if (login("recovered", "the new password", cookie, sizeof(cookie)) != 0 ||
        login("recovered", "the old password", cookie, sizeof(cookie)) == 0) {
        FAIL("after set-password, the new password doesn't sign in, or the old one does");
    }
    if (user_consume_invitation_token(db_pool_get_connection(), invite, "an invited password") != 1) {
        FAIL("an invitation outstanding when the password was set can still set another");
    }
    if (user_consume_password_reset_token(db_pool_get_connection(), "recovery-reset",
                                          "a reset password") != 1) {
        FAIL("a reset link outstanding when the password was set can still set another");
    }
    r = request("GET", "/api/user/profile", before, NULL, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("set-password closed a session of a user without MFA (%d)", status);
    printf("✓ the operator sets a password, no outstanding link can override it, and sessions stay\n");

    /* 2. The recovery order: deactivate, set, reactivate. Nothing signs in until
          reactivation, and then only the password set */
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    status = post_status("/api/admin/users/deactivate", json);
    if (status != 200) FAIL("deactivating answered %d", status);
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\",\"password\":\"the recovered password\"}",
             user_id);
    status = post_status("/api/admin/users/set-password", json);
    if (status != 200) FAIL("set-password on a deactivated account answered %d", status);
    if (login("recovered", "the recovered password", cookie, sizeof(cookie)) == 0 ||
        login("recovered", "the new password", cookie, sizeof(cookie)) == 0) {
        FAIL("a deactivated account signed in");
    }
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    status = post_status("/api/admin/users/activate", json);
    if (status != 200) FAIL("reactivating answered %d", status);
    if (login("recovered", "the recovered password", cookie, sizeof(cookie)) != 0 ||
        login("recovered", "the new password", cookie, sizeof(cookie)) == 0) {
        FAIL("after reactivation, the password set doesn't sign in, or the one before it does");
    }
    printf("✓ deactivate, set, reactivate: nothing signs in until then, and only the new password\n");

    /* 3. An unknown user is 404, and the minimum length applies */
    status = post_status("/api/admin/users/set-password",
                         "{\"user_id\":\"ffffffffffffffffffffffffffffffff\",\"password\":\"whatever\"}");
    if (status != 404) FAIL("set-password for an unknown user answered %d", status);
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\",\"password\":\"\"}", user_id);
    status = post_status("/api/admin/users/set-password", json);
    if (status != 400) FAIL("set-password with an empty password answered %d", status);
    printf("✓ an unknown user is 404, and the minimum length applies\n");

    return 0;
}

/*
 * A deactivated account keeps its username, as the unique index has it: the
 * account can be reactivated, and apps know it by that name. So the name is
 * taken for a new user and for a new organization's admin, and that bootstrap
 * makes nothing. The username change takes a name no other account holds, and
 * the caller's own in another case.
 */
static int test_usernames(void) {
    printf("\n=== Usernames ===\n");

    char user_id[33], json[256], found[8], cookie[256];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"dormant\",\"password\":\"dormant password\"}");
    int created = r.status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    if (!created || post_status("/api/admin/users/deactivate", json) != 200) {
        FAIL("could not create and deactivate the user");
    }

    /* 1. Its name, in another case, for a new user and a new organization's admin */
    int status = post_status("/api/admin/users",
                             "{\"username\":\"Dormant\",\"password\":\"another password\"}");
    if (status != 409) FAIL("a new user with a deactivated account's name answered %d", status);
    status = post_status("/api/admin/bootstrap", "{\"org_code_name\":\"second\","
                         "\"username\":\"Dormant\",\"password\":\"correct horse battery\"}");
    int made = query_text("SELECT 1 FROM " TBL_ORGANIZATION " WHERE code_name = 'second'",
                          found, sizeof(found)) == 0;
    if (status != 409 || made) {
        FAIL("a bootstrap with a deactivated account's name answered %d%s", status,
             made ? ", and made the organization" : "");
    }
    printf("✓ a deactivated account's name is taken for a new user and a bootstrap\n");

    /* 2. The username change */
    r = admin_port("POST", "/api/admin/users", NULL,
                   "{\"username\":\"renamer\",\"password\":\"renamer password\"}");
    status = r.status;
    reply_free(&r);
    if (status != 200 || login("renamer", "renamer password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }
    const struct { const char *name; int want; } changes[] = {
        { "Dormant", 409 },  /* a deactivated account's */
        { "admin", 409 },    /* an active account's */
        { "Renamer", 200 },  /* the caller's own, in another case */
    };
    for (size_t i = 0; i < sizeof(changes) / sizeof(changes[0]); i++) {
        snprintf(json, sizeof(json), "{\"new_username\":\"%s\"}", changes[i].name);
        r = post_json("/api/user/username", cookie, json);
        status = r.status;
        reply_free(&r);
        if (status != changes[i].want) {
            FAIL("changing the username to %s answered %d, not %d", changes[i].name, status,
                 changes[i].want);
        }
    }
    printf("✓ the username change refuses another account's name with 409, and takes its own\n");

    return 0;
}

/* A trigger that makes every insert into a table fail, and its removal: a
   database failure, where a test needs one. One at a time. */
#ifdef DB_BACKEND_POSTGRESQL
#define REFUSE_INSERTS(table) \
    "CREATE FUNCTION refuse_insert() RETURNS trigger LANGUAGE plpgsql " \
    "AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; " \
    "CREATE TRIGGER refuse_insert BEFORE INSERT ON " table " " \
    "FOR EACH ROW EXECUTE FUNCTION refuse_insert()"
#define ALLOW_INSERTS "DROP FUNCTION refuse_insert() CASCADE"
#else
#define REFUSE_INSERTS(table) \
    "CREATE TRIGGER refuse_insert BEFORE INSERT ON " table " " \
    "BEGIN SELECT RAISE(FAIL, 'refused'); END"
#define ALLOW_INSERTS "DROP TRIGGER refuse_insert"
#endif

/* The same for updates of one column */
#ifdef DB_BACKEND_POSTGRESQL
#define REFUSE_UPDATES(table, column) \
    "CREATE FUNCTION refuse_update() RETURNS trigger LANGUAGE plpgsql " \
    "AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; " \
    "CREATE TRIGGER refuse_update BEFORE UPDATE OF " column " ON " table " " \
    "FOR EACH ROW EXECUTE FUNCTION refuse_update()"
#define ALLOW_UPDATES "DROP FUNCTION refuse_update() CASCADE"
#else
#define REFUSE_UPDATES(table, column) \
    "CREATE TRIGGER refuse_update BEFORE UPDATE OF " column " ON " table " " \
    "BEGIN SELECT RAISE(FAIL, 'refused'); END"
#define ALLOW_UPDATES "DROP TRIGGER refuse_update"
#endif

/*
 * A bootstrap that fails part-way makes nothing. With its last step, the
 * org-admin grant, refused, it answers 500 and leaves neither the organization
 * nor its admin behind, so the same bootstrap runs once the cause is gone.
 */
static int test_failed_bootstrap(void) {
    printf("\n=== A failed bootstrap ===\n");

    const char *body = "{\"org_code_name\":\"third\",\"username\":\"third_admin\","
                       "\"password\":\"correct horse battery\"}";
    db_handle_t *conn = db_pool_get_connection();
    if (db_execute_direct(conn, REFUSE_INSERTS(TBL_ORGANIZATION_ADMIN)) != 0) {
        FAIL("could not make the grant refuse");
    }
    int status = post_status("/api/admin/bootstrap", body);
    if (db_execute_direct(conn, ALLOW_INSERTS) != 0) FAIL("could not drop the trigger");

    char found[8];
    int org = query_text("SELECT 1 FROM " TBL_ORGANIZATION " WHERE code_name = 'third'",
                         found, sizeof(found)) == 0;
    int admin = user_username_exists(conn, "third_admin") != 0;
    if (status != 500 || org || admin) {
        FAIL("a bootstrap refused at its last step answered %d%s%s", status,
             org ? ", leaving the organization" : "", admin ? ", leaving its admin" : "");
    }
    status = post_status("/api/admin/bootstrap", body);
    if (status != 200) FAIL("the same bootstrap, once the grant was allowed, answered %d", status);

    printf("✓ a bootstrap refused at its last step makes nothing, and runs again\n");
    return 0;
}

/*
 * A database failure isn't answered as a bad credential: a client takes
 * invalid_grant as final and discards its refresh token, a user told "Invalid
 * credentials" doubts a right password, and a console told 401 asks to sign in
 * again. Nor is it an empty list or an invalid link. With the query each needs
 * failing, the answer is 500, and what was sent works once the cause is gone.
 */
static int test_database_failures(void) {
    printf("\n=== A database failure isn't a bad credential ===\n");

    db_handle_t *conn = db_pool_get_connection();
    char code[2048], rt[256];
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize did not redirect with a code");
    Reply r = exchange(code, PKCE_VERIFIER);
    int got = r.status == 200 && field(&r, "refresh_token", rt, sizeof(rt)) == 0;
    reply_free(&r);
    if (!got) FAIL("the code exchange failed");

    /* 1. A refresh whose new token can't be stored */
    if (db_execute_direct(conn, REFUSE_INSERTS(TBL_REFRESH_TOKEN)) != 0) {
        FAIL("could not make refresh tokens refuse");
    }
    r = refresh(rt);
    int status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_INSERTS) != 0) FAIL("could not drop the trigger");
    if (status != 500) FAIL("a refresh the database failed answered %d, not 500", status);
    r = refresh(rt);
    status = r.status;
    got = field(&r, "refresh_token", rt, sizeof(rt)) == 0;
    reply_free(&r);
    if (status != 200 || !got) {
        FAIL("the same refresh token, once the database worked, answered %d", status);
    }
    printf("✓ a refresh the database fails answers 500, and the token still works\n");

    /* A scope beyond the grant is no verdict on the token: invalid_scope, and the same
       token goes on working. A client that takes invalid_grant as final would have
       discarded it. */
    char form[1024];
    snprintf(form, sizeof(form), "grant_type=refresh_token&refresh_token=%s&client_id=%s&scope=beyond",
             rt, g_ui_client);
    r = post_form("/token", form);
    status = r.status;
    got = strstr(r.body, "invalid_scope") != NULL;
    reply_free(&r);
    if (status != 400 || !got) FAIL("a scope beyond the grant answered %d, not invalid_scope", status);
    r = refresh(rt);
    status = r.status;
    got = field(&r, "refresh_token", rt, sizeof(rt)) == 0;
    reply_free(&r);
    if (status != 200 || !got) FAIL("the same token, without the scope, answered %d", status);

    /* A second resource server linked, so a refresh that names none has no one to fall
       back on: invalid_target, and the same token works when it names one */
    char json[512], second[33], link[256];
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"second_rs\","
             "\"display_name\":\"Second\",\"address\":\"https://second.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", second, sizeof(second)) != 0) return 1;
    snprintf(json, sizeof(json), "{\"client_id\":\"%s\",\"resource_server_id\":\"%s\"}",
             g_ui_client, second);
    r = post_json("/api/admin/client-resource-servers", g_admin_cookie, json);
    status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("linking a second resource server answered %d", status);
    r = refresh(rt);
    status = r.status;
    got = strstr(r.body, "invalid_target") != NULL;
    reply_free(&r);
    if (status != 400 || !got) FAIL("a refresh with no resource to fall back on answered %d", status);
    snprintf(form, sizeof(form), "grant_type=refresh_token&refresh_token=%s&client_id=%s"
             "&resource=https%%3A%%2F%%2Fsecond.example", rt, g_ui_client);
    r = post_form("/token", form);
    status = r.status;
    got = field(&r, "refresh_token", rt, sizeof(rt)) == 0;
    reply_free(&r);
    if (status != 200 || !got) FAIL("the same token, naming the resource, answered %d", status);
    snprintf(link, sizeof(link), "/api/admin/client-resource-servers?client_id=%s&resource_server_id=%s",
             g_ui_client, second);
    r = request("DELETE", link, g_admin_cookie, NULL, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("unlinking the second resource server answered %d", status);
    printf("✓ a refused resource or scope leaves the refresh token working\n");

    /* A client lookup that fails, not a client that isn't there */
    if (db_execute_direct(conn, HIDE_TABLE(SECURITY_, "client")) != 0) {
        FAIL("could not hide the clients");
    }
    r = refresh(rt);
    status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SECURITY_, "client")) != 0) {
        FAIL("could not show the clients");
    }
    if (status != 500) FAIL("a refresh whose client lookup failed answered %d, not 500", status);
    r = refresh(rt);
    status = r.status;
    reply_free(&r);
    if (status != 200) FAIL("the same token, once the lookup worked, answered %d", status);
    printf("✓ a failed client lookup answers 500, not an unknown client\n");

    /* 2. A sign-in whose session can't be stored */
    char cookie[256];
    if (db_execute_direct(conn, REFUSE_INSERTS(TBL_BROWSER)) != 0) {
        FAIL("could not make sessions refuse");
    }
    r = post_json("/login", NULL,
                  "{\"username\":\"admin\",\"password\":\"correct horse battery\"}");
    status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_INSERTS) != 0) FAIL("could not drop the trigger");
    if (status != 500) FAIL("a sign-in the database failed answered %d, not 500", status);
    if (login("admin", "correct horse battery", cookie, sizeof(cookie)) != 0) {
        FAIL("the same password, once the database worked, didn't sign in");
    }
    printf("✓ a sign-in the database fails answers 500, not \"Invalid credentials\"\n");

    /* 3. A list whose query fails, not an empty list */
    char target[128];
    snprintf(target, sizeof(target), "/api/admin/clients?organization_id=%s", g_org_id);
    if (db_execute_direct(conn, HIDE_TABLE(SECURITY_, "client")) != 0) {
        FAIL("could not hide the clients");
    }
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SECURITY_, "client")) != 0) {
        FAIL("could not show the clients");
    }
    if (status != 500) FAIL("a list of clients the database failed answered %d, not 500", status);
    r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
    got = r.status == 200 && strstr(r.body, "management_ui") != NULL;
    reply_free(&r);
    if (!got) FAIL("the same list, once the database worked, isn't the clients");
    printf("✓ a list the database fails answers 500, not an empty list\n");

    /* 4. A link page whose query fails doesn't call the link invalid */
    if (db_execute_direct(conn, HIDE_TABLE(SESSION_, "invitation_token")) != 0) {
        FAIL("could not hide the invitations");
    }
    r = request("GET", "/accept-invitation?token=nosuchtoken", NULL, NULL, NULL, NULL);
    status = r.status;
    got = strstr(r.body, "wasn't used") != NULL;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SESSION_, "invitation_token")) != 0) {
        FAIL("could not show the invitations");
    }
    if (status != 500 || !got) FAIL("a link page the database failed answered %d", status);
    r = request("GET", "/accept-invitation?token=nosuchtoken", NULL, NULL, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (status != 400) FAIL("an unknown link, once the database worked, answered %d", status);
    printf("✓ a link page the database fails answers 500, not \"invalid\"\n");

    /* 5. A session the server can't check isn't a bad one: 500, not 401, so the console
          doesn't ask to sign in again. An org key too, and a good key still answers
          when it's the session lookup that can't run. */
    r = admin_port("POST", "/api/admin/organization-keys", NULL,
                   "{\"organization_code_name\":\"system\"}");
    char key_id[33], secret[128], headers[256], bad_headers[256];
    got = r.status == 200 && field(&r, "key_id", key_id, sizeof(key_id)) == 0 &&
          field(&r, "secret", secret, sizeof(secret)) == 0;
    reply_free(&r);
    if (!got) FAIL("could not make an organization key");
    snprintf(headers, sizeof(headers), "X-Org-Key-Id: %s\r\nX-Org-Key-Secret: %s\r\n", key_id, secret);
    snprintf(bad_headers, sizeof(bad_headers), "X-Org-Key-Id: %s\r\nX-Org-Key-Secret: wrong\r\n", key_id);
    const char *orgs = "/api/admin/organizations";

    if (db_execute_direct(conn, HIDE_TABLE(SESSION_, "browser")) != 0) FAIL("could not hide the sessions");
    r = request("GET", "/api/user/profile", g_admin_cookie, NULL, NULL, NULL);
    int profile = r.status;
    reply_free(&r);
    r = request("GET", orgs, g_admin_cookie, NULL, NULL, NULL);
    int by_cookie = r.status;
    reply_free(&r);
    r = request("GET", orgs, g_admin_cookie, headers, NULL, NULL);
    int with_good_key = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SESSION_, "browser")) != 0) FAIL("could not show the sessions");
    if (profile != 500 || by_cookie != 500 || with_good_key != 200) {
        FAIL("with sessions failing, the profile answered %d, the organizations %d, and with a "
             "good org key too %d", profile, by_cookie, with_good_key);
    }

    if (db_execute_direct(conn, HIDE_TABLE(SECURITY_, "organization_key")) != 0) FAIL("could not hide the keys");
    r = request("GET", orgs, NULL, headers, NULL, NULL);
    status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SECURITY_, "organization_key")) != 0) FAIL("could not show the keys");
    if (status != 500) FAIL("an org key the database failed answered %d, not 500", status);
    r = request("GET", orgs, NULL, headers, NULL, NULL);
    int good = r.status;
    reply_free(&r);
    r = request("GET", orgs, NULL, bad_headers, NULL, NULL);
    int wrong = r.status;
    reply_free(&r);
    r = request("GET", "/api/user/profile", g_admin_cookie, NULL, NULL, NULL);
    profile = r.status;
    reply_free(&r);
    if (good != 200 || wrong != 401 || profile != 200) {
        FAIL("once the database worked, a good org key answered %d, a wrong one %d, the cookie %d",
             good, wrong, profile);
    }
    printf("✓ a session or org key the database can't check answers 500, not 401\n");

    /* 6. /authorize: before the redirect URI is trusted a failure can't be sent to it;
          after, it goes there as server_error, not invalid_request or the sign-in page */
    if (db_execute_direct(conn, HIDE_TABLE(SECURITY_, "client")) != 0) FAIL("could not hide the clients");
    r = authorize_with(PKCE_CHALLENGE);
    status = r.status;
    got = r.location == NULL;
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SECURITY_, "client")) != 0) FAIL("could not show the clients");
    if (status != 500 || !got) FAIL("/authorize with its client lookup failing answered %d", status);

    if (db_execute_direct(conn, HIDE_TABLE(SESSION_, "browser")) != 0) FAIL("could not hide the sessions");
    r = authorize_with(PKCE_CHALLENGE);
    status = r.status;
    got = r.location && strstr(r.location, "error=server_error") && strstr(r.location, "state=st8");
    reply_free(&r);
    if (db_execute_direct(conn, SHOW_TABLE(SESSION_, "browser")) != 0) FAIL("could not show the sessions");
    if (status != 302 || !got) FAIL("/authorize with its session lookup failing answered %d", status);

    if (db_execute_direct(conn, REFUSE_INSERTS(TBL_AUTHORIZATION_CODE)) != 0) {
        FAIL("could not make codes refuse");
    }
    r = authorize_with(PKCE_CHALLENGE);
    status = r.status;
    got = r.location && strstr(r.location, "error=server_error") && !strstr(r.location, "code=");
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_INSERTS) != 0) FAIL("could not drop the trigger");
    if (status != 302 || !got) FAIL("/authorize with its code refused answered %d", status);
    if (authorize(code, sizeof(code)) != 0) FAIL("/authorize, once the database worked, made no code");
    printf("✓ /authorize answers a failed server with 500 or server_error, by whether it can redirect\n");

    return 0;
}

/*
 * A first TOTP confirm stores the method's confirmation and its recovery codes
 * together. With the codes refused, it answers 500 and leaves the method
 * unconfirmed, so the same method confirms, with its codes, once the cause is
 * gone, rather than staying confirmed with no codes and the retry refused.
 */
static int test_failed_first_confirm(void) {
    printf("\n=== A first TOTP confirm that fails ===\n");

    char cookie[256], method[33], secret[64], code[16], json[256];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                         "{\"username\":\"halfway\",\"password\":\"halfway password\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 200 || login("halfway", "halfway password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }
    r = post_json("/api/user/mfa/totp/setup", cookie, "{\"display_name\":\"phone\"}");
    if (r.status != 200 || field(&r, "method_id", method, sizeof(method)) != 0 ||
        field(&r, "secret", secret, sizeof(secret)) != 0) {
        FAIL("TOTP setup answered %d", r.status);
    }
    reply_free(&r);

    /* 1. The codes can't be stored: 500 */
    db_handle_t *conn = db_pool_get_connection();
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    if (db_execute_direct(conn, REFUSE_INSERTS(TBL_RECOVERY_CODE_SET)) != 0) {
        FAIL("could not make recovery codes refuse");
    }
    r = post_json("/api/user/mfa/totp/confirm", cookie, json);
    status = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_INSERTS) != 0) FAIL("could not drop the trigger");
    if (status != 500) FAIL("a confirm whose codes couldn't be stored answered %d, not 500", status);

    /* 2. Once they can: the same method confirms, with its codes */
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    r = post_json("/api/user/mfa/totp/confirm", cookie, json);
    char codes[16][32];
    int count = r.status == 200 ? string_array(r.body, "recovery_codes", codes, 16) : 0;
    status = r.status;
    reply_free(&r);
    if (count <= 0) {
        FAIL("confirming the same method again answered %d, with %d recovery codes", status, count);
    }
    printf("✓ a first confirm whose codes can't be stored changes nothing, and confirms "
           "with codes after\n");

    return 0;
}

/*
 * A right MFA code whose session can't be marked complete answers 500, not
 * {"valid":true}. A recovery code is marked used in the same transaction, so
 * the failure leaves it good for the next try.
 */
static int test_failed_mfa_completion(void) {
    printf("\n=== An MFA step the session can't record ===\n");

    char first[256], second[256], method[33], secret[64], code[16], json[256], recover[128];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                         "{\"username\":\"unfinished\",\"password\":\"unfinished password\"}");
    int status = r.status;
    reply_free(&r);
    if (status != 200 || login("unfinished", "unfinished password", first, sizeof(first)) != 0) {
        FAIL("could not create and sign in the user");
    }
    r = post_json("/api/user/mfa/totp/setup", first, "{\"display_name\":\"phone\"}");
    if (r.status != 200 || field(&r, "method_id", method, sizeof(method)) != 0 ||
        field(&r, "secret", secret, sizeof(secret)) != 0) {
        FAIL("TOTP setup answered %d", r.status);
    }
    reply_free(&r);
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    r = post_json("/api/user/mfa/totp/confirm", first, json);
    char codes[16][32];
    int count = r.status == 200 ? string_array(r.body, "recovery_codes", codes, 16) : 0;
    status = r.status;
    reply_free(&r);
    if (count <= 0) FAIL("confirming answered %d, with %d recovery codes", status, count);
    snprintf(recover, sizeof(recover), "{\"recovery_code\":\"%s\"}", codes[0]);

    /* A second sign-in, which owes the factor */
    if (login("unfinished", "unfinished password", second, sizeof(second)) != 0) FAIL("second sign-in");

    /* 1. The session can't be marked: 500, for a right TOTP code and a right recovery code */
    db_handle_t *conn = db_pool_get_connection();
    if (totp_now(secret, code, sizeof(code)) != 0) FAIL("could not make a TOTP code");
    snprintf(json, sizeof(json), "{\"method_id\":\"%s\",\"code\":\"%s\"}", method, code);
    if (db_execute_direct(conn, REFUSE_UPDATES(TBL_BROWSER, "mfa_completed")) != 0) {
        FAIL("could not make the session refuse");
    }
    r = post_json("/api/user/mfa/verify", second, json);
    int verified = r.status;
    reply_free(&r);
    r = post_json("/api/user/mfa/recover", second, recover);
    int recovered = r.status;
    reply_free(&r);
    if (db_execute_direct(conn, ALLOW_UPDATES) != 0) FAIL("could not drop the trigger");
    if (verified != 500 || recovered != 500) {
        FAIL("with the session refusing, a right code answered %d, a right recovery code %d",
             verified, recovered);
    }

    /* 2. Once it can be marked, the session still owes the factor, and the same recovery
          code works */
    r = request("GET", "/api/user/mfa/recovery-codes", second, NULL, NULL, NULL);
    int gated = r.status;
    reply_free(&r);
    r = post_json("/api/user/mfa/recover", second, recover);
    int valid = r.status == 200 && strstr(r.body, "\"valid\":true") != NULL;
    status = r.status;
    reply_free(&r);
    r = request("GET", "/api/user/mfa/recovery-codes", second, NULL, NULL, NULL);
    int opened = r.status;
    reply_free(&r);
    if (gated != 403 || !valid || opened != 200) {
        FAIL("after the failure the session got %d, the same code answered %d (valid: %d), and "
             "then the session got %d", gated, status, valid, opened);
    }
    printf("✓ a right code the session can't record answers 500, and a recovery code stays good\n");

    return 0;
}

/*
 * The operator lists a user's addresses, with when each was added and
 * verified, and removes one the user doesn't recognize; one not on the account
 * is a 404, not a silent success. With email support, the removed address no
 * longer takes reset links.
 */
static int test_operator_addresses(void) {
    printf("\n=== The operator and a user's addresses ===\n");

    char user_id[33], cookie[256], json[256], sql[512];

    /* An address alone makes no account: it would go on unverified, so nothing
       could sign in to it */
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"email\":\"nameless@example.com\",\"password\":\"nameless password\"}");
    int refused = r.status == 400 && strstr(r.body, "username");
    reply_free(&r);
    if (!refused) FAIL("the operator made an account from an address alone");
    printf("✓ the operator makes no account from an address alone\n");

    r = admin_port("POST", "/api/admin/users", NULL,
                  "{\"username\":\"checked\",\"password\":\"checked password\"}");
    int created = r.status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    if (!created || login("checked", "checked password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }
    /* Theirs is added second, and verified as if by its link */
    const char *added[] = { "{\"email\":\"mine@example.com\"}", "{\"email\":\"theirs@example.com\"}" };
    for (int i = 0; i < 2; i++) {
        r = post_json("/api/user/emails", cookie, added[i]);
        int status = r.status;
        reply_free(&r);
        if (status != 200) FAIL("adding an address answered %d", status);
    }
    snprintf(sql, sizeof(sql),
             "UPDATE " TBL_USER_EMAIL " SET is_verified = " BOOL_TRUE ", verified_at = " NOW " "
             "WHERE pin = (SELECT max(pin) FROM " TBL_USER_EMAIL " WHERE user_account_pin = "
             "(SELECT pin FROM " TBL_USER_ACCOUNT " WHERE id = " ID_FROM_HEX("%s") "))", user_id);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not verify theirs");

    /* 1. Listed, with verified state and dates */
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    r = admin_port("GET", "/api/admin/users/emails", NULL, json);
    if (r.status != 200 || !strstr(r.body, "\"total\":2") ||
        !strstr(r.body, "\"address\":\"theirs@example.com\",\"is_verified\":true") ||
        !strstr(r.body, "\"address\":\"mine@example.com\",\"is_verified\":false") ||
        !strstr(r.body, "\"verified_at\":null") || !strstr(r.body, "\"added_at\":\"20")) {
        FAIL("listing the addresses answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    printf("✓ the operator lists a user's addresses, with when each was added and verified\n");

#ifdef EMAIL_SUPPORT
    char token[64];
    r = post_json("/request-password-reset", NULL, "{\"email\":\"theirs@example.com\"}");
    reply_free(&r);
    if (mail_token("theirs@example.com", token, sizeof(token)) != 0) {
        FAIL("a verified address added to the account took no reset link");
    }
#endif

    /* 2. Removed, matched without regard to case; then it's gone, and another
          removal is a 404 */
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\",\"email\":\"THEIRS@example.com\"}", user_id);
    r = admin_port("DELETE", "/api/admin/users/emails", NULL, json);
    int removed = r.status;
    reply_free(&r);
    r = admin_port("DELETE", "/api/admin/users/emails", NULL, json);
    int again = r.status;
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    r = admin_port("GET", "/api/admin/users/emails", NULL, json);
    int left = r.status == 200 && strstr(r.body, "\"total\":1") && !strstr(r.body, "theirs");
    reply_free(&r);
    if (removed != 200 || again != 404 || !left) {
        FAIL("removing an address answered %d, again %d, and it was %s", removed, again,
             left ? "gone" : "still listed");
    }
#ifdef EMAIL_SUPPORT
    r = post_json("/request-password-reset", NULL, "{\"email\":\"theirs@example.com\"}");
    reply_free(&r);
    if (!mail_none()) FAIL("a removed address still took a reset link");
#endif
    printf("✓ the operator removes one, and removing one the user hasn't is a 404\n");

    /* 3. An unknown user is a 404 both ways */
    const char *unknown = "{\"user_id\":\"ffffffffffffffffffffffffffffffff\",\"email\":\"x@example.com\"}";
    r = admin_port("GET", "/api/admin/users/emails", NULL, unknown);
    int listed = r.status;
    reply_free(&r);
    r = admin_port("DELETE", "/api/admin/users/emails", NULL, unknown);
    int deleted = r.status;
    reply_free(&r);
    if (listed != 404 || deleted != 404) {
        FAIL("an unknown user answered %d to the list and %d to the removal", listed, deleted);
    }
    printf("✓ an unknown user is a 404\n");

    return 0;
}

/* ============================================================================
 * Form passwords
 * ============================================================================ */

/*
 * A password's length is checked where it arrives, before anything is made,
 * and a refused one answers 400 with the reason. Bootstrap and create-user
 * refuse one too long or too short, and make nothing. The invitation form
 * takes one as long as the JSON endpoints do, 1024 bytes, and past that says
 * so instead of answering "Invalid request". (The reset form, with email
 * support, shares the decoding.)
 */
static int test_password_length(void) {
    printf("\n=== Password length ===\n");

    char user_id[33], sql[128], pin[24], invite[64], password[1026], form[1200];
    char json[1200], found[8];
    memset(password, 'p', 1025);
    password[1025] = '\0';

    /* 1. Bootstrap and create-user, with 1025 bytes and with none */
    const struct { const char *password, *reason; } refused[] = {
        { password, "at most 1024" }, { "", "at least" },
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        snprintf(json, sizeof(json), "{\"org_code_name\":\"lengthy\","
                 "\"username\":\"lengthy_admin\",\"password\":\"%s\"}", refused[i].password);
        Reply r = admin_port("POST", "/api/admin/bootstrap", NULL, json);
        int said = r.status == 400 && strstr(r.body, refused[i].reason) != NULL;
        int status = r.status;
        reply_free(&r);
        int made = query_text("SELECT 1 FROM " TBL_ORGANIZATION " WHERE code_name = 'lengthy'",
                              found, sizeof(found)) == 0;
        if (!said || made) {
            FAIL("a bootstrap with a %zu-byte password answered %d%s%s",
                 strlen(refused[i].password), status, said ? "" : ", not 400 with the reason",
                 made ? ", and made the organization" : "");
        }
        snprintf(json, sizeof(json), "{\"username\":\"lengthy_user\",\"password\":\"%s\"}",
                 refused[i].password);
        r = admin_port("POST", "/api/admin/users", NULL, json);
        said = r.status == 400 && strstr(r.body, refused[i].reason) != NULL;
        status = r.status;
        reply_free(&r);
        made = user_username_exists(db_pool_get_connection(), "lengthy_user") != 0;
        if (!said || made) {
            FAIL("creating a user with a %zu-byte password answered %d%s%s",
                 strlen(refused[i].password), status, said ? "" : ", not 400 with the reason",
                 made ? ", and made the user" : "");
        }
    }
    printf("✓ bootstrap and create-user refuse a password too long or too short with 400, "
           "and make nothing\n");

    /* 2. The invitation form */
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"longpass\",\"password\":\"a short password\"}");
    int created = r.status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    snprintf(sql, sizeof(sql), "SELECT pin FROM " TBL_USER_ACCOUNT " WHERE id = " ID_FROM_HEX("%s"),
             user_id);
    if (!created || query_text(sql, pin, sizeof(pin)) != 0 ||
        user_create_invitation_token(db_pool_get_connection(), atoll(pin), 0, 3600, NULL,
                                     invite) != 0) {
        FAIL("could not create the user and an invitation");
    }

    snprintf(form, sizeof(form), "token=%s&password=%s", invite, password);
    r = post_form("/accept-invitation", form);
    if (r.status != 400 || !strstr(r.body, "at most 1024")) {
        FAIL("a 1025-byte password answered %d: %.120s", r.status, r.body);
    }
    reply_free(&r);
    password[1024] = '\0';
    snprintf(form, sizeof(form), "token=%s&password=%s", invite, password);
    r = post_form("/accept-invitation", form);
    int status = r.status;
    reply_free(&r);
    char cookie[256];
    if (status != 200 || login("longpass", password, cookie, sizeof(cookie)) != 0) {
        FAIL("a 1024-byte password answered %d, or doesn't sign in", status);
    }
    printf("✓ a 1024-byte password is accepted, and a longer one refused with the reason\n");

    return 0;
}

/* ============================================================================
 * Emailed links
 * ============================================================================ */

#ifdef EMAIL_SUPPORT
/*
 * Through the mail, end to end: an address verified by its link, and a reset
 * link to it that sets the password. A verification link outstanding when the
 * account is deactivated is void after reactivation, like the other links: an
 * address someone added while they held the account doesn't verify after the
 * operator's recovery, so it can't then take reset links.
 */
static int test_email_links(void) {
    printf("\n=== Emailed links ===\n");

    char user_id[33], cookie[256], token[64], form[160], json[96];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"mailer\",\"password\":\"mailer password\"}");
    int created = r.status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    if (!created || login("mailer", "mailer password", cookie, sizeof(cookie)) != 0) {
        FAIL("could not create and sign in the user");
    }

    /* 1. Added, then verified by the link mailed to it; a reset link mailed to
          the verified address sets the password */
    const char *steps[][2] = {
        { "/api/user/emails", "{\"email\":\"mailer@example.com\"}" },
        { "/email-verification-token", "{\"email\":\"mailer@example.com\"}" },
    };
    for (int i = 0; i < 2; i++) {
        r = post_json(steps[i][0], cookie, steps[i][1]);
        if (r.status != 200) FAIL("%s answered %d", steps[i][0], r.status);
        reply_free(&r);
    }
    if (mail_token("mailer@example.com", token, sizeof(token)) != 0) FAIL("no verification mail");
    snprintf(form, sizeof(form), "token=%s", token);
    r = post_form("/verify-email", form);
    if (r.status != 200) FAIL("the verification link answered %d", r.status);
    reply_free(&r);
    r = post_json("/request-password-reset", NULL, "{\"email\":\"mailer@example.com\"}");
    if (r.status != 200) FAIL("requesting a reset answered %d", r.status);
    reply_free(&r);
    if (mail_token("mailer@example.com", token, sizeof(token)) != 0) FAIL("no reset mail");
    snprintf(form, sizeof(form), "token=%s&password=the+reset+password", token);
    r = post_form("/reset-password", form);
    if (r.status != 200) FAIL("the reset link answered %d", r.status);
    reply_free(&r);
    if (login("mailer", "the reset password", cookie, sizeof(cookie)) != 0 ||
        login("mailer", "mailer password", cookie, sizeof(cookie)) == 0) {
        FAIL("after the reset, the new password doesn't sign in, or the old one does");
    }
    printf("✓ an address verifies by its mailed link, and a reset link to it sets the password\n");

    /* 2. A verification link outstanding at deactivation is void after
          reactivation */
    if (login("mailer", "the reset password", cookie, sizeof(cookie)) != 0) FAIL("can't sign in");
    r = post_json("/api/user/emails", cookie, "{\"email\":\"added@example.com\"}");
    int added = r.status;
    reply_free(&r);
    r = post_json("/email-verification-token", cookie, "{\"email\":\"added@example.com\"}");
    int sent = r.status;
    reply_free(&r);
    if (added != 200 || sent != 200 || mail_token("added@example.com", token, sizeof(token)) != 0) {
        FAIL("adding an address and mailing its link answered %d, %d", added, sent);
    }
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", user_id);
    if (post_status("/api/admin/users/deactivate", json) != 200 ||
        post_status("/api/admin/users/activate", json) != 200) {
        FAIL("could not deactivate and reactivate");
    }
    snprintf(form, sizeof(form), "token=%s", token);
    r = post_form("/verify-email", form);
    if (r.status != 400) FAIL("a verification link from before deactivation answered %d", r.status);
    reply_free(&r);
    printf("✓ deactivation voids an outstanding verification link\n");

    return 0;
}
#endif

/* ============================================================================
 * Provisioning
 * ============================================================================ */

static char g_rs_auth[512];  /* a provisioning resource server's credential fields */

static Reply provision(const char *username, const char *email) {
    char json[768];
    if (username) {
        snprintf(json, sizeof(json), "{%s,\"username\":\"%s\",\"email\":\"%s\"}",
                 g_rs_auth, username, email);
    } else {
        snprintf(json, sizeof(json), "{%s,\"email\":\"%s\"}", g_rs_auth, email);
    }
    return post_json("/api/rs/users", NULL, json);
}

/* The username an account is created with: a server that can't email needs
   one, and one that can makes accounts from an address alone */
#ifdef EMAIL_SUPPORT
#define AS(name) NULL
#else
#define AS(name) name
#endif

/* The token in a reply's invitation, given for the resource server to deliver;
   -1 if the reply has none */
static int invitation_token(const Reply *r, char *out, size_t size) {
    const char *invitation = strstr(r->body, "\"invitation\":");
    char *token = invitation ? json_get_string(invitation + 13, "token") : NULL;
    if (!token) return -1;
    snprintf(out, size, "%s", token);
    free(token);
    return 0;
}

/* The reply is about this user, and says this about creating it */
static int provisioned(const Reply *r, const char *user, int created) {
    char id[33];
    return r->status == 200 && field(r, "user_id", id, sizeof(id)) == 0 &&
           strcmp(id, user) == 0 &&
           strstr(r->body, created ? "\"created\":true" : "\"created\":false") != NULL;
}

/* The invitation a reply says was issued to this address: without email support,
   the token the reply carries for the resource server to deliver; with it, the one
   emailed, and the reply carries none. -1 if there was none. */
static int invited(const Reply *r, const char *email, char *token, size_t size) {
#ifdef EMAIL_SUPPORT
    if (invitation_token(r, token, size) == 0 ||
        !strstr(r->body, "\"invitation\":{\"emailed\":true}")) {
        return -1;
    }
    return mail_token(email, token, size);
#else
    (void)email;
    return invitation_token(r, token, size);
#endif
}

/*
 * Provisioning an address twice makes one account, not two. With email support
 * one still pending is invited again, to the mailbox, up to five times an hour,
 * and only the newest invitation works once it's handed off. Without, it isn't:
 * the link would come back to whichever resource server asked. Accepted, the
 * address is verified and finds the account without inviting it. A deactivated
 * pending account is found, and not invited. In a build without email support
 * each link comes back for the resource server to deliver; with it, the server
 * emails them and none comes back.
 */
static int test_provisioning(void) {
    printf("\n=== Provisioning ===\n");

    char json[512], rs[33], key[33], secret[128], target[96];
    snprintf(json, sizeof(json), "{\"organization_id\":\"%s\",\"code_name\":\"rs_prov\","
             "\"display_name\":\"Provisioning\",\"address\":\"https://prov.example\"}", g_org_id);
    if (admin_create("/api/admin/resource-servers", json, "id", rs, sizeof(rs)) != 0) return 1;
    snprintf(target, sizeof(target), "/api/admin/resource-servers?id=%s", rs);
    Reply r = request("PUT", target, g_admin_cookie, NULL, "application/json",
                      "{\"allow_user_provisioning\":true}");
    if (r.status != 200) FAIL("enabling provisioning answered %d", r.status);
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"resource_server_id\":\"%s\"}", rs);
    r = post_json("/api/admin/resource-server-keys", g_admin_cookie, json);
    if (field(&r, "key_id", key, sizeof(key)) != 0 || field(&r, "secret", secret, sizeof(secret)) != 0) {
        FAIL("RS key create answered %d", r.status);
    }
    reply_free(&r);
    snprintf(g_rs_auth, sizeof(g_rs_auth), "\"resource_server_id\":\"%s\","
             "\"resource_server_key_id\":\"%s\",\"resource_server_secret\":\"%s\"",
             rs, key, secret);

    /* 0. A field of another kind names itself. Read as left out, a numeric username
          would make an address-only account, and a numeric user_id find by username */
    char kinds[640];
    snprintf(kinds, sizeof(kinds), "{%s,\"username\":123,\"email\":\"kinds@example.com\"}", g_rs_auth);
    r = post_json("/api/rs/users", NULL, kinds);
    int refused = r.status == 400 && strstr(r.body, "username must be text");
    reply_free(&r);
    if (!refused) FAIL("provisioning with a numeric username wasn't refused naming it");

    /* 1. A new address gets an account and an invitation. The same address
          again finds that account rather than making another. With email
          support it's invited again, to the mailbox, four more times, and only
          the newest invitation works. Without, the link would come back to
          whichever resource server asked, so it isn't invited, and the link it
          has still works */
    char user[33], tokens[5][64];
    r = provision(AS("pending"), "pending@example.com");
    if (r.status != 200 || field(&r, "user_id", user, sizeof(user)) != 0 ||
        !provisioned(&r, user, 1) ||
        invited(&r, "pending@example.com", tokens[0], sizeof(tokens[0])) != 0) {
        FAIL("provisioning a new address answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
#ifndef EMAIL_SUPPORT
    r = provision(AS("pending"), "pending@example.com");
    if (!provisioned(&r, user, 0) || strstr(r.body, "\"invitation\"")) {
        FAIL("without email, a pending address again answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    if (user_consume_invitation_token(db_pool_get_connection(), tokens[0], "a password") != 0) {
        FAIL("provisioning a pending address again voided its link");
    }
    printf("✓ a pending address finds its account, and without email isn't invited again\n");

    /* An address alone makes no account here, and finds no pending one: 400 */
    r = provision("still", "still@example.com");
    int still_status = r.status;
    int still = still_status == 200 && strstr(r.body, "\"created\":true");
    reply_free(&r);
    if (!still) FAIL("provisioning a username and address answered %d", still_status);
    const char *alone[] = { "nobody@example.com", "still@example.com" };
    for (int i = 0; i < 2; i++) {
        r = provision(NULL, alone[i]);
        int refused = r.status == 400 && strstr(r.body, "username required");
        reply_free(&r);
        if (!refused) FAIL("without email, provisioning %s alone wasn't refused", alone[i]);
    }
    printf("✓ without email, an address alone creates no account and finds no pending one\n");
#else
    for (int i = 1; i < 5; i++) {
        /* Earlier links issued earlier: SQLite dates to the second, and two from
           the same second both stay valid */
        if (db_execute_direct(db_pool_get_connection(), "UPDATE " TBL_INVITATION_TOKEN " SET "
                              "issued_at = " SECONDS_BEFORE("issued_at", "2")) != 0) {
            FAIL("could not date the earlier invitations");
        }
        r = provision(AS("pending"), "pending@example.com");
        if (!provisioned(&r, user, 0) ||
            invited(&r, "pending@example.com", tokens[i], sizeof(tokens[i])) != 0) {
            FAIL("provisioning a pending address again answered %d: %s", r.status, r.body);
        }
        reply_free(&r);
    }
    for (int i = 0; i < 4; i++) {
        if (user_consume_invitation_token(db_pool_get_connection(), tokens[i], "a password") != 1) {
            FAIL("an earlier invitation still works after a newer one");
        }
    }
    printf("✓ a pending address finds its account, invited again, and only the newest link works\n");

    /* 2. A sixth in the hour: the account, and no invitation */
    r = provision(AS("pending"), "pending@example.com");
    if (!provisioned(&r, user, 0) || strstr(r.body, "\"invitation\"")) {
        FAIL("a sixth provisioning in the hour answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    if (!mail_none()) FAIL("a sixth invitation in the hour was emailed");
    printf("✓ five invitations an hour, then none\n");

    /* A hand-off that fails (here, mail that can't be rendered) sends nothing,
       says so, and leaves the link the user already has working */
    char first[64];
    r = provision(NULL, "unsent@example.com");
    if (invited(&r, "unsent@example.com", first, sizeof(first)) != 0) {
        FAIL("provisioning a new address answered %d", r.status);
    }
    reply_free(&r);
    template_cleanup();
    r = provision(NULL, "unsent@example.com");
    template_init("./templates");
    int said = strstr(r.body, "\"invitation\":{\"emailed\":false}") != NULL;
    reply_free(&r);
    if (!said || !mail_none()) FAIL("a failed hand-off wasn't reported, or something was sent");
    if (user_consume_invitation_token(db_pool_get_connection(), first, "a password") != 0) {
        FAIL("a failed hand-off voided the link the user already had");
    }
    printf("✓ a failed hand-off says so, and the link the user has still works\n");
#endif

    /* 3. Accepted, the address is verified, and finds the account without
          inviting it. The account has no username: it signs in by the address,
          with or without email support */
    char accepted[33], token[64], cookie[256];
    r = provision(AS("accepted"), "accepted@example.com");
    if (r.status != 200 || field(&r, "user_id", accepted, sizeof(accepted)) != 0 ||
        invited(&r, "accepted@example.com", token, sizeof(token)) != 0) {
        FAIL("provisioning a new address answered %d", r.status);
    }
    reply_free(&r);
    if (user_consume_invitation_token(db_pool_get_connection(), token, "an accepted password") != 0) {
        FAIL("a fresh invitation was refused");
    }
    r = provision(NULL, "accepted@example.com");
    if (!provisioned(&r, accepted, 0) || strstr(r.body, "\"invitation\"") ||
        !strstr(r.body, "\"is_verified\":true")) {
        FAIL("an accepted address answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    printf("✓ once accepted, the verified address finds the account, and no one is invited\n");
    if (login("accepted@example.com", "an accepted password", cookie, sizeof(cookie)) != 0 ||
        login("accepted@example.com", "a wrong password", cookie, sizeof(cookie)) == 0) {
        FAIL("an account provisioned by address can't sign in by it, or signs in with anything");
    }
    printf("✓ a verified address signs in, and finds its account alone\n");

    /* 4. Deactivated while pending: found, inactive, and not invited */
    char banned[33];
    r = provision(AS("deactivated"), "deactivated@example.com");
    if (r.status != 200 || field(&r, "user_id", banned, sizeof(banned)) != 0 ||
        invited(&r, "deactivated@example.com", token, sizeof(token)) != 0) {
        FAIL("provisioning a new address answered %d", r.status);
    }
    reply_free(&r);
    snprintf(json, sizeof(json), "{\"user_id\":\"%s\"}", banned);
    if (post_status("/api/admin/users/deactivate", json) != 200) FAIL("could not deactivate");
    r = provision(AS("deactivated"), "deactivated@example.com");
    if (!provisioned(&r, banned, 0) || strstr(r.body, "\"invitation\"") ||
        !strstr(r.body, "\"is_active\":false")) {
        FAIL("a deactivated pending account answered %d: %s", r.status, r.body);
    }
    reply_free(&r);
    printf("✓ a deactivated pending account is found, and not invited\n");

    /* Patterns apply to new values only. An address stored while no pattern was
       set, which the default refuses, still finds its account: by provisioning,
       and with email support for a reset link. A new value like it is refused. */
    char obrien[33], obrien_cookie[256], obrien_sql[512];
    validation_patterns_t before = { .email = "" };
    validation_patterns_t configured = {
        .username = g_config->username_pattern, .email = g_config->email_pattern,
        .code_name = g_config->code_name_pattern, .password = g_config->password_pattern,
        .machine_secret = g_config->machine_secret_pattern,
    };
    if (validation_init(&before, g_config->password_min_length) != 0) {
        FAIL("could not set the patterns aside");
    }
    r = admin_port("POST", "/api/admin/users", NULL,
                   "{\"username\":\"obrien\",\"email\":\"o'brien@example.com\","
                   "\"password\":\"obrien password\"}");
    int made = r.status == 200 && field(&r, "user_id", obrien, sizeof(obrien)) == 0;
    reply_free(&r);
    if (validation_init(&configured, g_config->password_min_length) != 0) {
        FAIL("could not restore the patterns");
    }
    if (!made) FAIL("could not store an address the default refuses");
    snprintf(obrien_sql, sizeof(obrien_sql),
             "UPDATE " TBL_USER_EMAIL " SET is_verified = " BOOL_TRUE ", verified_at = " NOW " "
             "WHERE user_account_pin = (SELECT pin FROM " TBL_USER_ACCOUNT " WHERE id = "
             ID_FROM_HEX("%s") ")", obrien);
    if (db_execute_direct(db_pool_get_connection(), obrien_sql) != 0) FAIL("could not verify it");

    r = provision(NULL, "o'brien@example.com");
    if (!provisioned(&r, obrien, 0)) {
        FAIL("provisioning by a stored address the default refuses answered %d: %s",
             r.status, r.body);
    }
    reply_free(&r);
#ifdef EMAIL_SUPPORT
    r = post_json("/request-password-reset", NULL, "{\"email\":\"o'brien@example.com\"}");
    int asked = r.status;
    reply_free(&r);
    char reset[128];
    if (asked != 200 || mail_token("o'brien@example.com", reset, sizeof(reset)) != 0) {
        FAIL("a stored address the default refuses got no reset link (%d)", asked);
    }
#endif
    r = provision("oconnor", "o'connor@example.com");
    int new_refused = r.status == 400 && strstr(r.body, "Email must look like");
    reply_free(&r);
    if (login("obrien", "obrien password", obrien_cookie, sizeof(obrien_cookie)) != 0) {
        FAIL("the account with the stored address could not sign in");
    }
    r = post_json("/api/user/emails", obrien_cookie, "{\"email\":\"o'hara@example.com\"}");
    int add_refused = r.status == 400;
    reply_free(&r);
    if (!new_refused || !add_refused) {
        FAIL("a new address the default refuses was taken (provisioning %d, adding %d)",
             new_refused, add_refused);
    }
    printf("✓ an address stored before the pattern still finds its account; new ones must match\n");

    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    log_init(LOG_ERROR);
#ifdef EMAIL_SUPPORT
    printf("Handler Test Suite (with email support)\n");
#else
    printf("Handler Test Suite\n");
#endif

    if (!scratch_db_available()) return 0;

    config_t *config = config_load("auth.conf");
    if (!config) {
        printf("✗ could not load auth.conf\n");
        return 1;
    }
    /* One pass of Argon2: the flows sign in a dozen times, and the cost
       parameters aren't what's under test here */
    config->secret_hash_min_iterations = 1;
    config->secret_hash_max_iterations = 1;
    config->machine_secret_hash_min_iterations = 1;
    config->machine_secret_hash_max_iterations = 1;
    g_config = config;

    /* The pages and mails the handlers render, loaded as main.c loads them */
    template_init("./templates");

#ifdef EMAIL_SUPPORT
    /* Mail goes to a capture: the email command writes each message to a file of
       its own, renamed into place once whole, and the flows read the links back.
       Children reaped as main.c has them. */
    snprintf(g_outbox, sizeof(g_outbox), "/tmp/test-handlers-outbox.XXXXXX");
    char command[160];
    if (!mkdtemp(g_outbox) ||
        snprintf(command, sizeof(command),
                 "f=$(mktemp %s/mail.XXXXXX) && cat > \"$f\" && mv \"$f\" \"$f.json\"",
                 g_outbox) >= (int)sizeof(command)) {
        printf("✗ mail capture setup failed\n");
        return 1;
    }
    free(config->email_command);
    config->email_command = str_dup(command);
    signal(SIGCHLD, SIG_IGN);
#endif

    /* One database, empty, bound to this thread as a worker's would be; the
       schema and history made in it as the server makes them at its first start */
    validation_patterns_t patterns = {
        .username = config->username_pattern, .email = config->email_pattern,
        .code_name = config->code_name_pattern, .password = config->password_pattern,
        .machine_secret = config->machine_secret_pattern,
    };
    char conninfo[1024];
    if (validation_init(&patterns, config->password_min_length) != 0 ||
        encrypt_init(config->encryption_key) != 0 || crypto_password_init(config) != 0 ||
        scratch_db_new(conninfo, sizeof(conninfo)) != 0 ||
        db_pool_init(1, SCRATCH_DB_TYPE, conninfo) != 0) {
        printf("✗ setup failed\n");
        return 1;
    }
    db_handle_t *db = db_pool_get_connection_by_index(0);
    db_pool_set_connection(db);
    int schema_rc = db_init_schema(db, SCRATCH_DB_TYPE, config->schema_dir,
                                   scratch_db_owner_role(config));
    if (schema_rc < 0 ||
        (config->enable_history_tables &&
         db_init_history_tables(db, SCRATCH_DB_TYPE, schema_rc == 0) != 0)) {
        printf("✗ schema setup failed\n");
        return 1;
    }

    g_router = router_create();
    register_routes(g_router);

    int failed = setup() || test_logout() || test_authorization_code_flow() ||
                 test_redirect_uris() || test_issuer() ||
                 test_client_credentials() || test_field_kinds() ||
                 test_active_clashes() ||
                 test_mfa_gates() || test_mfa_daily_cap() ||
                 test_localhost_only() || test_admin_socket_caller() ||
                 test_account_recovery() || test_usernames() || test_failed_bootstrap() ||
                 test_database_failures() || test_failed_first_confirm() ||
                 test_failed_mfa_completion() ||
                 test_operator_addresses() ||
                 test_password_length() ||
#ifdef EMAIL_SUPPORT
                 test_email_links() ||
#endif
                 test_provisioning();

    router_destroy(g_router);
    db_pool_shutdown();
    config_free(config);

#ifdef EMAIL_SUPPORT
    /* Anything a failed flow left unread, then the outbox itself */
    char leftover[8192];
    while (mail_take(0, leftover, sizeof(leftover)) == 0) {}
    rmdir(g_outbox);
#endif
    template_cleanup();
    validation_cleanup();

    printf(failed ? "\n=== Handler tests FAILED ===\n" : "\n=== All Handler Tests Passed! ===\n");
    return failed;
}
