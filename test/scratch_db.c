/* getpid */
#define _POSIX_C_SOURCE 200809L

#include "scratch_db.h"
#include "db/init/db_init.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef DB_BACKEND_POSTGRESQL

/* The connection that makes the databases and drops them, the role it connects
   as, and what it has made: the template (number 0), databases 1 to g_made, and
   roles 1 to g_roles */
static db_handle_t *g_admin;
static char g_owner[64];
static int g_template_made;
static int g_made;
static int g_roles;

static const char *server(void) {
    const char *s = getenv("AUTH_TEST_PG");
    return s && *s ? s : NULL;
}

static void name_of(int n, char *out, size_t size) {
    if (n == 0) {
        snprintf(out, size, "auth_test_%d_template", (int)getpid());
    } else {
        snprintf(out, size, "auth_test_%d_%d", (int)getpid(), n);
    }
}

static void role_name_of(int n, char *out, size_t size) {
    snprintf(out, size, "auth_test_%d_role_%d", (int)getpid(), n);
}

/* At exit: every database made, whatever a test left connected to it, then the
   roles, which nothing refers to once the databases are gone */
static void drop_all(void) {
    char name[64], sql[128];
    for (int n = g_template_made ? 0 : 1; n <= g_made; n++) {
        name_of(n, name, sizeof(name));
        snprintf(sql, sizeof(sql), "DROP DATABASE IF EXISTS %s WITH (FORCE)", name);
        db_execute_direct(g_admin, sql);
    }
    for (int n = 1; n <= g_roles; n++) {
        role_name_of(n, name, sizeof(name));
        snprintf(sql, sizeof(sql), "DROP ROLE IF EXISTS %s", name);
        db_execute_direct(g_admin, sql);
    }
    db_disconnect(g_admin);
    g_admin = NULL;
}

static int admin(void) {
    if (g_admin) return 0;
    if (db_connect(&g_admin, DB_TYPE_POSTGRESQL, server()) != 0) {
        log_error("Can't connect to the server AUTH_TEST_PG names");
        return -1;
    }
    db_result_t *role = NULL;
    if (db_query(g_admin, &role, "%s", "SELECT current_user") != 0 ||
        db_result_row_count(role) != 1) {
        db_result_free(role);
        db_disconnect(g_admin);
        g_admin = NULL;
        return -1;
    }
    snprintf(g_owner, sizeof(g_owner), "%s", db_result_get(role, 0, 0));
    db_result_free(role);
    atexit(drop_all);
    return 0;
}

/* Database n, empty or a copy of the template, and the string that connects to it */
static int create(int n, int from_template, char *conninfo, size_t size) {
    char name[64], template_name[64], sql[192];
    name_of(n, name, sizeof(name));
    name_of(0, template_name, sizeof(template_name));
    snprintf(sql, sizeof(sql), "CREATE DATABASE %s%s%s", name,
             from_template ? " TEMPLATE " : "", from_template ? template_name : "");
    if (db_execute_direct(g_admin, sql) != 0) {
        log_error("Can't create the database %s", name);
        return -1;
    }
    int len = snprintf(conninfo, size, "%s dbname=%s", server(), name);
    return len < 0 || (size_t)len >= size ? -1 : 0;
}

/* The template the scratch databases copy: the schema, as db_init_schema makes it */
static int make_template(const config_t *config) {
    char conninfo[1024];
    db_handle_t *db = NULL;
    if (create(0, 0, conninfo, sizeof(conninfo)) != 0) return -1;
    g_template_made = 1;
    if (db_connect(&db, DB_TYPE_POSTGRESQL, conninfo) != 0) return -1;
    int rc = db_init_schema(db, DB_TYPE_POSTGRESQL, config->schema_dir, g_owner);
    db_disconnect(db);
    if (rc != 0) {
        log_error("Can't apply the schema to the template database");
        return -1;
    }
    return 0;
}

#endif /* DB_BACKEND_POSTGRESQL */

int scratch_db_available(void) {
#ifdef DB_BACKEND_POSTGRESQL
    if (!server()) {
        printf("Skipped: set AUTH_TEST_PG to a PostgreSQL server's connection string to run "
               "these (make DB_BACKEND=postgresql test-postgresql starts one).\n");
        return 0;
    }
#endif
    return 1;
}

int scratch_db_new(char *conninfo, size_t size) {
#ifdef DB_BACKEND_POSTGRESQL
    if (admin() != 0) return -1;
    return create(++g_made, 0, conninfo, size);
#else
    int len = snprintf(conninfo, size, ":memory:");
    return len < 0 || (size_t)len >= size ? -1 : 0;
#endif
}

db_handle_t *scratch_db_open(const config_t *config) {
    char conninfo[1024];
    return scratch_db_open_shared(config, conninfo, sizeof(conninfo));
}

db_handle_t *scratch_db_open_shared(const config_t *config, char *conninfo, size_t size) {
    db_handle_t *db = NULL;
#ifdef DB_BACKEND_POSTGRESQL
    if (admin() != 0 || (!g_template_made && make_template(config) != 0) ||
        create(++g_made, 1, conninfo, size) != 0 ||
        db_connect(&db, DB_TYPE_POSTGRESQL, conninfo) != 0) {
        return NULL;
    }
#else
    snprintf(conninfo, size, ":memory:");
    if (db_connect(&db, DB_TYPE_SQLITE, ":memory:") != 0) return NULL;
    if (db_init_schema(db, DB_TYPE_SQLITE, config->schema_dir,
                       scratch_db_owner_role(config)) < 0) {
        db_disconnect(db);
        return NULL;
    }
#endif
    return db;
}

const char *scratch_db_owner_role(const config_t *config) {
#ifdef DB_BACKEND_POSTGRESQL
    (void)config;
    return admin() == 0 ? g_owner : NULL;
#else
    return config->db_owner_role ? config->db_owner_role : config->db_user;
#endif
}

#ifdef DB_BACKEND_POSTGRESQL
int scratch_db_role(char *name, size_t size) {
    char sql[128];
    if (admin() != 0) return -1;
    role_name_of(++g_roles, name, size);
    snprintf(sql, sizeof(sql), "CREATE ROLE %s NOLOGIN", name);
    return db_execute_direct(g_admin, sql) == 0 ? 0 : -1;
}
#endif
