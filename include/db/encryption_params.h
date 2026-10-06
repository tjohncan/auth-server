#ifndef ENCRYPTION_PARAMS_H
#define ENCRYPTION_PARAMS_H

#include "db/db.h"
#include "crypto/encrypt.h"

/*
 * The database's record of how encryption_key is stretched (crypto/encrypt.h):
 * one row of encryption_params. A database made before the table existed has
 * neither table nor row until the table is added by hand (sql/README.md), and
 * derives its keys by HKDF alone until it's re-keyed.
 */

/* Is there an encryption_params table? 1, 0, or -1 on error */
int encryption_params_table_exists(db_handle_t *db);

/* The row: 0 with *out set, 1 if there's no row or no table, -1 on error */
int encryption_params_load(db_handle_t *db, encrypt_params_t *out);

/* Write the row, replacing any. Returns 0, or -1 on error (logged). */
int encryption_params_store(db_handle_t *db, const encrypt_params_t *params);

/*
 * encryption_params_get_or_make - The row the server derives its field keys by,
 * at startup
 *
 * A database with nothing sealed yet gets a row now, with the method and
 * iterations given and a fresh salt, so it's stretched from the start. The row
 * is inserted only if there's none, then read back, so instances starting
 * together on a new database all derive by whichever row landed first. A
 * database with values sealed and no row derives by HKDF alone until --rekey,
 * and so does one without the table.
 *
 * Returns: 0 with *out set; 1 for HKDF alone; -1 on error (logged)
 */
int encryption_params_get_or_make(db_handle_t *db, const char *method, int iterations,
                                  encrypt_params_t *out);

#endif /* ENCRYPTION_PARAMS_H */
