/* strndup */
#define _POSIX_C_SOURCE 200809L

/*
 * Handler-level tests: raw requests through the server's own route table,
 * router and handlers, against an in-memory SQLite database, one flow per test.
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
#include "db/init/db_init.h"
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
#ifdef EMAIL_SUPPORT
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#endif

/* main.c's, read by the handlers */
const config_t *g_config = NULL;

static Router *g_router;

/* Set while a request goes to the admin listener (admin_port), where the
   localhost-only endpoints are served; otherwise it's the public one */
static int g_on_admin_port;

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
    str_copy(req.remote_ip, sizeof(req.remote_ip), "127.0.0.1");
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
    if (query_text("SELECT lower(hex(id)) FROM organization WHERE code_name = 'system'",
                   g_org_id, sizeof(g_org_id)) != 0) {
        FAIL("no bootstrap organization");
    }
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

/* /authorize as the admin, through the console's client; the code from the redirect */
static int authorize(char *code, size_t size) {
    char target[512];
    snprintf(target, sizeof(target),
             "/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=st8"
             "&code_challenge=" PKCE_CHALLENGE "&code_challenge_method=S256",
             g_ui_client, g_redirect_enc);
    Reply r = request("GET", target, g_admin_cookie, NULL, NULL, NULL);
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

    if (query_text("SELECT lower(hex(id)) FROM client WHERE code_name = 'management_ui'",
                   g_ui_client, sizeof(g_ui_client)) != 0) {
        FAIL("no management UI client");
    }
    char redirect[256];
    snprintf(redirect, sizeof(redirect), "%s/callback", g_config->public_base_url);
    str_url_encode(g_redirect_enc, sizeof(g_redirect_enc), redirect);

    char code[2048], access[2048], rt[256], rt2[256];

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
                          "UPDATE client SET issue_refresh_tokens = 0 "
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
                          "UPDATE client SET issue_refresh_tokens = 1 "
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
        "INSERT INTO client_user (client_pin, user_account_pin) "
        "SELECT C.pin, A.user_account_pin FROM client C, organization_admin A "
        "WHERE C.code_name = 'management_ui'";
    const char *unlink =
        "DELETE FROM client_user WHERE client_pin = "
        "(SELECT pin FROM client WHERE code_name = 'management_ui')";
    if (db_execute_direct(db, "UPDATE client SET is_universal = 0 "
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
        db_execute_direct(db, "UPDATE client SET is_universal = 1 "
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
 * http is the client deployer's call, to any host.
 */
static int test_redirect_uris(void) {
    printf("\n=== Redirect URIs ===\n");

    static const struct { const char *uri; int status; } cases[] = {
        { "https://app.example.com/callback", 200 },
        { "http://localhost:3000/callback", 200 },
        { "http://app.example.com/callback", 200 },
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
    snprintf(sql, sizeof(sql), "UPDATE client SET access_token_ttl_seconds = %d "
             "WHERE id = x'%s'", cap + 3600, svc);
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

/* ============================================================================
 * MFA gates
 * ============================================================================ */

static int totp_now(const char *secret, char *code, size_t size) {
    return crypto_totp_generate_code(secret, time(NULL), code, size);
}

/*
 * Once a user has a factor, managing factors takes that factor, whatever the
 * require preference says, so a password alone can't add, remove or replace
 * one. With require on, the user's own endpoints and the admin API refuse a
 * session that hasn't completed MFA.
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
    reply_free(&r);

    /* 1. Enrolled, require off, a password-only session: every factor-management
          endpoint wants the factor first */
    if (login("mfa-user", "mfa user password", second, sizeof(second)) != 0) FAIL("second sign-in");
    char target[128];
    snprintf(target, sizeof(target), "/api/user/mfa/methods?id=%s", method);
    Reply gated[5] = {
        post_json("/api/user/mfa/totp/setup", second, "{\"display_name\":\"other\"}"),
        post_json("/api/user/mfa/totp/confirm", second, json),
        request("DELETE", target, second, NULL, NULL, NULL),
        post_json("/api/user/mfa/recovery-codes/regenerate", second, "{}"),
        post_json("/api/user/mfa/require", second, "{\"enabled\":true}"),
    };
    const char *names[5] = { "setup", "confirm", "delete", "regenerate", "require" };
    for (int i = 0; i < 5; i++) {
        int bad = gated[i].status != 403;
        if (bad) printf("✗ %s answered %d to a password-only session\n", names[i], gated[i].status);
        reply_free(&gated[i]);
        if (bad) return 1;
    }
    printf("✓ the five factor-management endpoints refuse a password-only session\n");

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
             "INSERT INTO password_reset_token (id, user_account_pin, token, issued_at, "
             "expected_expiry) SELECT randomblob(16), pin, '%s', datetime('now'), "
             "datetime('now', '+1 hour') FROM user_account WHERE id = x'%s'", reset_hash, user_id);
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

    return 0;
}

/*
 * Ten failed codes in a day, across the user's methods, refuse even a right
 * code; failures older than a day don't count. (The per-minute limit is
 * avoided by dating the failures hours back.)
 */
static int test_mfa_daily_cap(void) {
    printf("\n=== MFA daily cap ===\n");

    char cookie[256], method[33], secret[64], code[16], json[256], sql[256];
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
             "INSERT INTO user_mfa_usage (user_mfa_pin, submitted_at, success) "
             "SELECT pin, datetime('now', '-2 hours'), 0 FROM user_mfa WHERE id = x'%s'", method);
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
             "DELETE FROM user_mfa_usage WHERE rowid = (SELECT max(rowid) FROM user_mfa_usage "
             "WHERE success = 0 AND user_mfa_pin = (SELECT pin FROM user_mfa WHERE id = x'%s'))",
             method);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not remove a failure");
    r = post_json("/api/user/mfa/verify", cookie, json);
    int nine = r.status == 200 && strstr(r.body, "\"valid\":true") != NULL;
    reply_free(&r);
    if (!nine) FAIL("after nine failures in a day, a right code was refused");
    printf("✓ ten failed codes in a day refuse even a right one; nine don't\n");

    /* 3. Failures older than a day don't count */
    snprintf(sql, sizeof(sql),
             "UPDATE user_mfa_usage SET submitted_at = datetime('now', '-25 hours') "
             "WHERE success = 0 AND user_mfa_pin = (SELECT pin FROM user_mfa WHERE id = x'%s')",
             method);
    if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not age the failures");
    snprintf(sql, sizeof(sql),
             "INSERT INTO user_mfa_usage (user_mfa_pin, submitted_at, success) "
             "SELECT pin, datetime('now', '-25 hours'), 0 FROM user_mfa WHERE id = x'%s'", method);
    for (int i = 0; i < 5; i++) {
        if (db_execute_direct(db_pool_get_connection(), sql) != 0) FAIL("could not plant failures");
    }
    r = post_json("/api/user/mfa/verify", cookie, json);
    int aged = r.status == 200 && strstr(r.body, "\"valid\":true") != NULL;
    reply_free(&r);
    if (!aged) FAIL("fourteen failures more than a day old still refused a right code");
    printf("✓ failures more than a day old don't count\n");

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
        int served = adm.status != 401 && adm.status != 403;
        int pub_status = pub.status, adm_status = adm.status;
        reply_free(&pub);
        reply_free(&adm);
        if (!refused || !served) {
            FAIL("%s %s answered %d on the public listener and %d on the admin one",
                 method, target, pub_status, adm_status);
        }
    }
    printf("✓ every operator endpoint is refused on the public listener, served on the admin one\n");

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
    snprintf(sql, sizeof(sql), "SELECT pin FROM user_account WHERE id = x'%s'", user_id);
    if (query_text(sql, pin, sizeof(pin)) != 0 ||
        user_create_invitation_token(db_pool_get_connection(), atoll(pin), 0, 3600, NULL,
                                     invite) != 0 ||
        crypto_sha256_hex("recovery-reset", 14, reset_hash, sizeof(reset_hash)) != 0) {
        FAIL("could not plant an invitation");
    }
    /* A reset link is a row with a known token hash: all its redemption reads */
    snprintf(insert, sizeof(insert),
             "INSERT INTO password_reset_token (id, user_account_pin, token, issued_at, "
             "expected_expiry) VALUES (randomblob(16), %s, '%s', datetime('now'), "
             "datetime('now', '+1 hour'))", pin, reset_hash);
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
 * The operator lists a user's addresses, with when each was added and
 * verified, and removes one the user doesn't recognize; one not on the account
 * is a 404, not a silent success. With email support, the removed address no
 * longer takes reset links.
 */
static int test_operator_addresses(void) {
    printf("\n=== The operator and a user's addresses ===\n");

    char user_id[33], cookie[256], json[256], sql[256];

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
             "UPDATE user_email SET is_verified = 1, verified_at = datetime('now') WHERE pin = "
             "(SELECT max(pin) FROM user_email WHERE user_account_pin = "
             "(SELECT pin FROM user_account WHERE id = x'%s'))", user_id);
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
 * The invitation form takes a password as long as the JSON endpoints do, 1024
 * bytes, and past that says so instead of answering "Invalid request". (The
 * reset form, with email support, shares the decoding.)
 */
static int test_form_password_length(void) {
    printf("\n=== Form password length ===\n");

    char user_id[33], sql[128], pin[24], invite[64], password[1026], form[1200];
    Reply r = admin_port("POST", "/api/admin/users", NULL,
                        "{\"username\":\"longpass\",\"password\":\"a short password\"}");
    int created = r.status == 200 && field(&r, "user_id", user_id, sizeof(user_id)) == 0;
    reply_free(&r);
    snprintf(sql, sizeof(sql), "SELECT pin FROM user_account WHERE id = x'%s'", user_id);
    if (!created || query_text(sql, pin, sizeof(pin)) != 0 ||
        user_create_invitation_token(db_pool_get_connection(), atoll(pin), 0, 3600, NULL,
                                     invite) != 0) {
        FAIL("could not create the user and an invitation");
    }

    memset(password, 'p', 1025);
    password[1025] = '\0';
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
        if (db_execute_direct(db_pool_get_connection(), "UPDATE invitation_token SET "
                              "issued_at = datetime(issued_at, '-2 seconds')") != 0) {
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

#ifdef DB_BACKEND_POSTGRESQL
    printf("Skipped: test-handlers runs in the SQLite build only.\n");
    return 0;
#endif

    config_t *config = config_load("auth.conf");
    if (!config) {
        printf("✗ could not load auth.conf\n");
        return 1;
    }
    /* One pass of Argon2: the flows sign in a dozen times, and the cost
       parameters aren't what's under test here */
    config->secret_hash_min_iterations = 1;
    config->secret_hash_max_iterations = 1;
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

    /* One in-memory database, bound to this thread as a worker's would be */
    if (encrypt_init(config->encryption_key) != 0 || crypto_password_init(config) != 0 ||
        db_pool_init(1, DB_TYPE_SQLITE, ":memory:") != 0) {
        printf("✗ setup failed\n");
        return 1;
    }
    db_handle_t *db = db_pool_get_connection_by_index(0);
    db_pool_set_connection(db);
    const char *owner_role = config->db_owner_role ? config->db_owner_role : config->db_user;
    if (db_init_schema(db, DB_TYPE_SQLITE, config->schema_dir, owner_role) < 0) {
        printf("✗ schema setup failed\n");
        return 1;
    }

    g_router = router_create();
    register_routes(g_router);

    int failed = setup() || test_authorization_code_flow() || test_redirect_uris() ||
                 test_issuer() ||
                 test_client_credentials() || test_mfa_gates() || test_mfa_daily_cap() ||
                 test_localhost_only() ||
                 test_account_recovery() || test_operator_addresses() ||
                 test_form_password_length() ||
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

    printf(failed ? "\n=== Handler tests FAILED ===\n" : "\n=== All Handler Tests Passed! ===\n");
    return failed;
}
