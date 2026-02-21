#ifndef DB_INIT_H
#define DB_INIT_H

#include "db/db.h"

/*
 * Database Initialization
 *
 * Handles schema setup and database creation.
 */

/*
 * Initialize database schema
 *
 * Checks if schema exists, and creates it if not.
 * For SQLite: Enables WAL mode
 * For PostgreSQL: Assumes database already exists, uses SET ROLE for schema ownership
 *
 * Parameters:
 *   - db: Database handle
 *   - type: Database type
 *   - schema_dir: Directory containing schema files (e.g., "./sql")
 *   - owner_role: PostgreSQL role name for SET ROLE during schema creation
 *                 (ignored for SQLite; must be a valid SQL identifier, max 32 chars)
 *
 * Returns: 0 on success (schema freshly created),
 *          1 on success (schema already existed),
 *          negative on error
 */
int db_init_schema(db_handle_t *db, db_type_t type, const char *schema_dir,
                   const char *owner_role);

#endif /* DB_INIT_H */
