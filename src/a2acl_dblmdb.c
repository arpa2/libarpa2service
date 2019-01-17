/*
 * Copyright (c) 2018 Tim Kuijsten
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <limits.h>
#include <lmdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * LMDB database backend for ARPA2 ACL.
 */

static MDB_env *env;
static MDB_txn *txn;
static MDB_dbi dbi;

struct dbentry {
	char *remotesel;
	size_t remoteselsize;
	char *localid;
	size_t localidsize;
	char *aclrule;
	size_t aclrulesize;
};

void
printdbentry(FILE *fp, const struct dbentry *ep)
{
	fprintf(fp, "remotesel: %zu %.*s\nlocalid: %zu %.*s\naclrule: %zu %.*s\n",
	    ep->remoteselsize, (int)ep->remoteselsize, ep->remotesel,
	    ep->localidsize, (int)ep->localidsize, ep->localid, ep->aclrulesize,
	    (int)ep->aclrulesize, ep->aclrule);
}

/* Let "de" point into the right spots of "data". */
void
db_datatodbentry(struct dbentry *de, const MDB_val *data)
{
	char *cp;

	cp = data->mv_data;

	de->remoteselsize = *cp;
	cp += sizeof(size_t);
	de->remotesel = cp;
	cp += de->remoteselsize;

	de->localidsize = *cp;
	cp += sizeof(size_t);
	de->localid = cp;
	cp += de->localidsize;

	de->aclrulesize = *cp;
	cp += sizeof(size_t);
	de->aclrule = cp;
	cp += de->aclrulesize;
}

/*
 * Print an MDB error and exit.
 */
void
printerrx(FILE *fp, int r, int e)
{
	fprintf(fp, "%s\n", mdb_strerror(r));
	exit(e);
}

/*
 * Print an MDB error.
 */
void
printerr(FILE *fp, int r)
{
	fprintf(fp, "%s", mdb_strerror(r));
}

void
printkey(FILE *fp, MDB_val *key)
{
	fprintf(fp, "key: %zu %.*s\n", key->mv_size, (int)key->mv_size,
	    key->mv_data);
}

/*
 * Print all keys and values in the database.
 */
void
printdb(FILE *fp)
{
	struct dbentry de;
	MDB_val key, data;
	MDB_cursor *cursor;
	int r;

	if ((r = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
		printerrx(fp, r, 1);

	if ((r = mdb_cursor_open(txn, dbi, &cursor)) != 0)
		printerrx(fp, r, 1);

	if ((r = mdb_cursor_get(cursor, &key, &data, MDB_FIRST)) != 0)
		printerrx(fp, r, 1);

	do {
		if (key.mv_size > INT_MAX)
			continue;
		if (data.mv_size > INT_MAX)
			continue;
		printkey(fp, &key);
		db_datatodbentry(&de, &data);
		printdbentry(fp, &de);
	} while ((r = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0);
	if (r != MDB_NOTFOUND)
		printerrx(fp, r, 1);

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
}

/*
 * Initialize a database path.
 *
 * Must return 0 on success, -1 on failure.
 */
int
a2acl_dbopen(const char *path)
{
	int r;

	if (path == NULL)
		return -1;

	if ((r = mdb_env_create(&env)) != 0)
		printerrx(stderr, 1, r);

	if ((r = mdb_env_open(env, path, MDB_NOSUBDIR, 0640)) != 0)
		printerrx(stderr, 1, r);

	/*
	 * Open a new database handle and commit the transaction so that the
	 * handle becomes available in the shared environment where subsequent
	 * transactions can use it.
	 */
	if ((r = mdb_txn_begin(env, NULL, 0, &txn)) != 0)
		printerrx(stderr, 1, r);

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi)) != 0)
		printerrx(stderr, 1, r);

	if ((r = mdb_txn_commit(txn)) != 0)
		printerrx(stderr, 1, r);

	return 0;
}

/*
 * Close a database backend by purging everything from memory.
 *
 * Must return 0 on success, -1 on failure.
 */
int
a2acl_dbclose(void)
{
	mdb_dbi_close(env, dbi);
	mdb_env_close(env);
	return 0;
}

/*
 * Free "val".
 */
void
db_freeval(MDB_val *val)
{
	if (val == NULL)
		return;

	free(val->mv_data);
	val->mv_data = NULL;

	free(val);
	val = NULL;
}

/*
 * Return a new key on success, NULL on failure.
 */
MDB_val *
db_newkey(const char *remotesel, size_t remoteselsize, const char *localid,
    size_t localidsize)
{
	MDB_val *key;
	int r;

	if (INT_MAX <= localidsize)
		return NULL;
	if (INT_MAX - localidsize - 2 < remoteselsize)
		return NULL;

	if ((key = malloc(sizeof(*key))) == NULL)
		return NULL;

	key->mv_size = remoteselsize + localidsize + 2;
	if ((key->mv_data = malloc(key->mv_size)) == NULL) {
		db_freeval(key);
		return NULL;
	}

	r = snprintf(key->mv_data, key->mv_size, "%.*s %.*s",
	    (int)remoteselsize, remotesel, (int)localidsize, localid);

	if (r <= 0 || r >= (int)key->mv_size) {
		db_freeval(key);
		return NULL;
	}

	return key;
}

/*
 * Return a new data value on success, NULL on failure.
 *
 * Each dbvalue consists of three serial length + value combinations.
 */
MDB_val *
db_newdata(const char *aclrule, size_t aclrulesize, const char *remotesel,
    size_t remoteselsize, const char *localid, size_t localidsize)
{
	const size_t sizesz = sizeof(size_t);
	MDB_val *data;
	char *cp;

	if (INT_MAX <= 3 * sizesz)
		return NULL;
	if (INT_MAX - 3 * sizesz <= localidsize)
		return NULL;
	if (INT_MAX - 3 * sizesz - localidsize < remoteselsize)
		return NULL;
	if (INT_MAX - 3 * sizesz - localidsize - remoteselsize < aclrulesize)
		return NULL;

	if ((data = malloc(sizeof(*data))) == NULL)
		return NULL;

	data->mv_size = 3 * sizesz + localidsize + remoteselsize + aclrulesize;

	if ((data->mv_data = malloc(data->mv_size)) == NULL) {
		db_freeval(data);
		return NULL;
	}

	cp = data->mv_data;

	*cp = remoteselsize;
	cp += sizesz;
	memcpy(cp, remotesel, remoteselsize);
	cp += remoteselsize;

	*cp = localidsize;
	cp += sizesz;
	memcpy(cp, localid, localidsize);
	cp += localidsize;

	*cp = aclrulesize;
	cp += sizesz;
	memcpy(cp, aclrule, aclrulesize);
	cp += aclrulesize;

	return data;
}

/*
 * Store a communication ACL rule given a remote and local ID. A copy of
 * "aclrule", "remotesel" and "localid" must be made since these are being
 * free(3)d after this functions returns.
 *
 * Must return 0 on success, -1 on failure.
 */
int
a2acl_putaclrule(const char *aclrule, size_t aclrulesize, const char *remotesel,
    size_t remoteselsize, const char *localid, size_t localidsize)
{
	MDB_val *key, *data;
	int r;

	key = data = NULL;

	if (aclrule == NULL || aclrulesize == 0 || remotesel == NULL ||
	    remoteselsize == 0 || localid == NULL || localidsize == 0)
		return -1;

	key = db_newkey(remotesel, remoteselsize, localid, localidsize);
	if (key == NULL)
		return -1;

	data = db_newdata(aclrule, aclrulesize, remotesel, remoteselsize,
	    localid, localidsize);
	if (data == NULL) {
		db_freeval(key);
		return -1;
	}

	if ((r = mdb_txn_begin(env, NULL, 0, &txn)) != 0)
		printerrx(stderr, r, 1);

	if ((r = mdb_put(txn, dbi, key, data, 0)) != 0) {
		printerr(stderr, r);
		mdb_txn_abort(txn);
		db_freeval(key);
		db_freeval(data);
		return -1;
	}

	if ((r = mdb_txn_commit(txn)) != 0)
		printerrx(stderr, 1, r);
	db_freeval(key);
	db_freeval(data);

	return 0;
}

/*
 * Search for a communication ACL rule based on a remote selector and local ID.
 *
 * "aclrule" must be allocated by the caller. "aclrulesize" is a value/result
 * parameter. If no ACL rule is found then "aclrule" is left untouched and
 * "aclrulesize" is set to 0.
 *
 * Must return 0 on success, -1 on error. If no "aclrule" is found, 0 is
 * returned and *aclrulesize is set to 0.
 */
int
a2acl_getaclrule(char *aclrule, size_t *aclrulesize, const char *remotesel,
    size_t remoteselsize, const char *localid, size_t localidsize)
{
	struct dbentry de;
	MDB_val *key, data;
	int r;

	if (aclrule == NULL || aclrulesize == NULL || remotesel == NULL ||
	    remoteselsize == 0 || localid == NULL || localidsize == 0)
		return -1;

	key = db_newkey(remotesel, remoteselsize, localid, localidsize);
	if (key == NULL)
		return -1;

	if ((r = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
		printerrx(stderr, r, 1);

	r = mdb_get(txn, dbi, key, &data);
	db_freeval(key);

	if (r != 0) {
		mdb_txn_abort(txn);
		if (r == MDB_NOTFOUND) {
			*aclrulesize = 0;
			return 0;
		} else
			printerrx(stderr, r, 1);
	}

	db_datatodbentry(&de, &data);

	if (de.aclrulesize > *aclrulesize) {
		mdb_txn_abort(txn);
		return -1;
	}

	memcpy(aclrule, de.aclrule, de.aclrulesize);
	*aclrulesize = de.aclrulesize;

	mdb_txn_abort(txn);

	return 0;
}
