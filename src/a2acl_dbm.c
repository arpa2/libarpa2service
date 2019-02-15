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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(x,y) ((x) < (y) ? (x) : (y))

/*
 * Extremely simple memory-only database implementation for ARPA2 ACL.
 *
 * Time complexity:
 *   find: O(n)
 *   insert/delete: O(n)
 *
 * Space complexity:
 *   O(n)
 */

struct dbmentry {
	void *remotesel;
	size_t remoteselsize;
	void *localid;
	size_t localidsize;
	void *aclrule;
	size_t aclrulesize;
};

void
printdbmentry(FILE *fp, const struct dbmentry *ep)
{
	fprintf(fp, "remotesel: %zu %.*s\nlocalid: %zu %.*s\naclrule: %zu %.*s\n",
	    ep->remoteselsize, (int)ep->remoteselsize, (char*)ep->remotesel,
	    ep->localidsize, (int)ep->localidsize, (char*)ep->localid, ep->aclrulesize,
	    (int)ep->aclrulesize, (char*)ep->aclrule);
}

struct dbmentry *dbm_alloc(const void *, size_t, const void *, size_t,
    const void *, size_t);
void dbm_free(struct dbmentry *);

static struct dbmentry **list = NULL;
static size_t listsize = 0;

/*
 * Initialize a database backend.
 *
 * Must return 0 on success, -1 on failure.
 */
int
a2acl_dbopen(const char *path)
{
	/* silence compiler */
	path = NULL;

	if (list != NULL)
		return -1;

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
	if (list == NULL)
		return 0;

	while (listsize-- > 0) {
		dbm_free(list[listsize]);
		list[listsize] = NULL;
	}

	if (listsize > 0)
		return -1;

	free(list);
	list = NULL;

	return 0;
}

/*
 * Update "count" to the total number of rules in the database.
 *
 * Return 0 on success, -1 on failure.
 */
int a2acl_count(size_t *count)
{
	*count = listsize;
	return 0;
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
	struct dbmentry *ep;

	if (aclrule == NULL || aclrulesize == 0 || remotesel == NULL ||
	    remoteselsize == 0 || localid == NULL || localidsize == 0)
		return -1;

	if ((listsize * sizeof(ep)) > ((listsize + 1) * sizeof(ep)))
		return -1; /* overflow */

	if ((ep = dbm_alloc(aclrule, aclrulesize, remotesel, remoteselsize, localid,
	    localidsize)) == NULL)
		return -1;

	if ((list = realloc(list, (listsize + 1) * sizeof(ep))) == NULL) {
		dbm_free(ep);
		ep = NULL;
		return -1;
	}

	list[listsize] = ep;
	listsize++;

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
	if (aclrule == NULL || aclrulesize == NULL || remotesel == NULL ||
	    remoteselsize == 0 || localid == NULL || localidsize == 0)
		return -1;

	for (size_t i = 0; i < listsize; i++) {
		if (memcmp(list[i]->remotesel, remotesel, MIN(list[i]->remoteselsize,
		    remoteselsize)) != 0)
			continue;

		if (memcmp(list[i]->localid, localid, MIN(list[i]->localidsize,
		    localidsize)) != 0)
			continue;

		if (list[i]->aclrulesize > *aclrulesize)
			return -1;

		memcpy(aclrule, list[i]->aclrule, list[i]->aclrulesize);
		*aclrulesize = list[i]->aclrulesize;
		return 0;
	}

	*aclrulesize = 0;
	return 0;
}

/*
 * Allocate a new dbmentry structure.
 *
 * Return a newly allocated structure on success that should be freed with
 * dbm_free by the caller when done. Return NULL on error with errno set.
 */
struct dbmentry *
dbm_alloc(const void *aclrule, size_t aclrulesize, const void *remotesel,
    size_t remoteselsize, const void *localid, size_t localidsize)
{
	struct dbmentry *ep = NULL;

	if ((ep = calloc(1, sizeof(*ep))) == NULL)
		goto err; /* errno set */

	if ((ep->aclrule = malloc(aclrulesize)) == NULL)
		goto err; /* errno set */

	if ((ep->remotesel = malloc(remoteselsize)) == NULL)
		goto err; /* errno set */

	if ((ep->localid = malloc(localidsize)) == NULL)
		goto err; /* errno set */

	memcpy(ep->aclrule, aclrule, aclrulesize);
	memcpy(ep->remotesel, remotesel, remoteselsize);
	memcpy(ep->localid, localid, localidsize);

	ep->aclrulesize = aclrulesize;
	ep->remoteselsize = remoteselsize;
	ep->localidsize = localidsize;

	return ep;

err:
	dbm_free(ep);
	return NULL;
}

/*
 * Free dbmentry structure.
 */
void
dbm_free(struct dbmentry *ep)
{
	if (ep == NULL)
		return;

	free(ep->aclrule);
	ep->aclrule = NULL;

	free(ep->remotesel);
	ep->remotesel = NULL;

	free(ep->localid);
	ep->localid = NULL;

	free(ep);
	ep = NULL;
}
