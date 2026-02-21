#ifndef DB_HISTORY_H
#define DB_HISTORY_H

#include "db/db.h"

/*
 * Database History Table Management
 *
 * Auto-generates history tables for auditing changes to core tables.
 * History tables track UPDATE and DELETE operations via triggers.
 *
 * For each base table with a "pin" primary key in lookup/security schemas:
 * - Creates a shadow history table (history__<table_name> for SQLite,
 *   same name in <schema>_history for PostgreSQL)
 * - History table has: history_created_at, history_triggering_action_code,
 *   all base table columns (with actual types), and history_pin
 * - Installs BEFORE UPDATE and BEFORE DELETE triggers to populate history
 *
 * Design:
 * - Only tables with "pin" as primary key get history tables
 * - Only UPDATE ('U') and DELETE ('D') operations are tracked
 * - History records are append-only (no updates/deletes on history tables)
 */

/*
 * Initialize history tables for all eligible tables
 *
 * Queries system catalogs to find tables with "pin" as primary key
 * in the lookup and security schemas. For each table:
 * - Creates corresponding history table if it doesn't exist
 * - Creates triggers for UPDATE and DELETE operations
 *
 * SQLite naming: history__<table_name> (flat namespace)
 * PostgreSQL naming: <schema>_history.<table_name> (separate schemas)
 *
 * Parameters:
 *   - db: Database handle
 *   - type: Database type (DB_TYPE_SQLITE or DB_TYPE_POSTGRESQL)
 *   - fresh_schema: Non-zero if db_init_schema() just ran schema.sql (base tables
 *                   freshly created, so triggers on them cannot exist yet — skips
 *                   DROP TRIGGER IF EXISTS to suppress unnecessary NOTICE messages)
 *
 * Returns: 0 on success, negative on error
 *
 * Note: This should be called after db_init_schema() completes
 */
int db_init_history_tables(db_handle_t *db, db_type_t type, int fresh_schema);

#endif /* DB_HISTORY_H */
