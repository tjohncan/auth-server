#ifndef DB_QUERIES_SECRET_H
#define DB_QUERIES_SECRET_H

#include "db/db.h"
#include "crypto/password.h"

/*
 * secret_rehash - Store a secret again under its kind's configured method
 *
 * For a secret that just verified under another method than its kind's, or an
 * iteration count outside the kind's range (crypto_password_verify's
 * out_rehash), so a change of method rolls forward as secrets are used. The
 * secret is hashed again and written to table's row by pin, only while that row
 * still holds the hash that verified, so a change made meanwhile isn't
 * overwritten. table is one of the TBL_ names whose rows keep salt,
 * hash_iterations and secret_hash. With history on, the replaced hash is copied
 * into history like any update, so retiring a method is finished when history
 * is purged.
 *
 * Returns: 0 if stored; 1 if the row had changed, or the secret is outside
 *          today's length limits; -1 on error (logged). The old hash stays and
 *          still verifies unless stored, so callers carry on either way.
 */
int secret_rehash(db_handle_t *db, const char *table, long long pin, secret_kind_t kind,
                  const char *secret, const char *verified_hash);

#endif /* DB_QUERIES_SECRET_H */
