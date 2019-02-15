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

#include <assert.h>
#include <err.h>

#include "../src/a2acl.h"

static char *aclrule;
static size_t aclrulesize;
static int fetchcalled;
static int putcalled;

struct a2aclit *a2acl_newit(const char *aclrule, size_t aclrulesize);
int a2acl_nextsegment(char *, struct a2aclseg *, struct a2aclit *);
int a2acl_parsepolicyline(const char **aclrule, size_t *aclrulesize,
    const char **remotesel, size_t *remoteselsize, const char **localid,
    size_t *localidsize, const char *line, size_t linesize, const char **err);

/*
 * DB mock.
 */
int
a2acl_dbopen(const char *path)
{
	path = NULL;
	return 0;
}

int
a2acl_dbclose(void)
{
	return 0;
}

int
a2acl_count(size_t *count)
{
	count = NULL;
	return 0;
}

/*
 * Stores nothing but always returns 0 and increments the global "putcalled".
 *
 * Must return 0 on success, -1 on failure.
 */
int
a2acl_putaclrule(const char *aclrule, size_t aclrulesize,
     const char *remotesel, size_t remoteselsize, const char *localid,
    size_t localidsize)
{
	/* suppress compiler warnings */
	aclrule = remotesel = localid = NULL;
	aclrulesize = remoteselsize = localidsize = 0;

	putcalled++;
	return 0;
}

/*
 * Fetch a communication ACL rule given a remote and local ID.
 *
 * A shim ACL rule k/v implementation.
 *
 * Returns whatever is stored in the global "aclrule".
 *
 * Return 0 on success, -1 on error.
 */
int
a2acl_getaclrule(char *aclr, size_t *aclrsize, const char *remotesel,
    size_t remoteselsize, const char *localid, size_t localidsize)
{
	if (aclrulesize > *aclrsize)
		return -1;

	memcpy(aclr, aclrule, aclrulesize);
	*aclrsize = aclrulesize;

	/* suppress compiler warnings */
	remotesel = localid = NULL;
	remoteselsize = localidsize = 0;

	fetchcalled++;
	return 0;
}

void
test_a2acl_nextsegment(void)
{
	struct a2aclseg aclseg;
	struct a2aclit *aclit;
	const char *rule;
	char list;
	int r;

	list = 0;

	/* invalid ACL rule */
	rule = "";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == -1);
	free(aclit);

	rule = "%W +";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	r = a2acl_nextsegment(&list, &aclseg, aclit);
	assert(r == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 0);
	assert(aclseg.reqsigflags == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W + ";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 0);
	assert(aclseg.reqsigflags == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W +foo";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 3);
	assert(aclseg.reqsigflags == 0);
	assert(strncmp(aclseg.seg, "foo", aclseg.segsize) == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W +foo ";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 3);
	assert(aclseg.reqsigflags == 0);
	assert(strncmp(aclseg.seg, "foo", aclseg.segsize) == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W++";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 0);
	assert(aclseg.reqsigflags == 1);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W ++";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 0);
	assert(aclseg.reqsigflags == 1);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W ++ ";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 0);
	assert(aclseg.reqsigflags == 1);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	rule = "%W bar";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == -1);
	free(aclit);

	rule = "%W +++";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == -1);
	free(aclit);

	rule = "%W +++";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == -1);
	free(aclit);

	rule = "%W+foo +bar+baz %B+foo+bar";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 3);
	assert(aclseg.reqsigflags == 0);
	assert(strncmp(aclseg.seg, "foo", aclseg.segsize) == 0);
	r = a2acl_nextsegment(&list, &aclseg, aclit);
	assert(r == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 7);
	assert(aclseg.reqsigflags == 0);
	assert(strncmp(aclseg.seg, "bar+baz", aclseg.segsize) == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 1);
	assert(list == 'B');
	assert(aclseg.segsize == 7);
	assert(aclseg.reqsigflags == 0);
	assert(strncmp(aclseg.seg, "foo+bar", aclseg.segsize) == 0);
	assert(a2acl_nextsegment(&list, &aclseg, aclit) == 0);
	free(aclit);

	/* regress */
	rule = "%W +arpa2+";
	if ((aclit = a2acl_newit(rule, strlen(rule))) == NULL)
		abort();
	r = a2acl_nextsegment(&list, &aclseg, aclit);
	assert(r == 1);
	assert(list == 'W');
	assert(aclseg.segsize == 5);
	assert(aclseg.reqsigflags == 1);
	assert(strncmp(aclseg.seg, "arpa2", aclseg.segsize) == 0);
	r = a2acl_nextsegment(&list, &aclseg, aclit);
	assert(r == 0);
	free(aclit);
}

void
test_a2acl_whichlist(void)
{
	struct a2id remoteid, localid;
	int r;
	char list;

	if (a2id_parsestr(&localid, "foo+bar@example.net", 0) == -1)
		abort();

	aclrule = "";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'G');
	assert(fetchcalled == 5);

	aclrule = "%W +bar";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'W');
	assert(fetchcalled == 1);

	aclrule = "%W +baz";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'G');
	assert(fetchcalled == 5);

	aclrule = "%W +foo +barbaz %B +foo +bar";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'B');
	assert(fetchcalled == 1);

	aclrule = "%W +foo +barbaz %B +foo+bar";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'G');
	assert(fetchcalled == 5);

	aclrule = "%W +foo +barbaz %B +foo +bar+baz";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'G');
	assert(fetchcalled == 5);

	if (a2id_parsestr(&localid, "foo+bar+baz@example.net", 0) == -1)
		abort();

	aclrule = "%W +foo +barbaz %B +foo +bar+baz";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == 0);
	assert(list == 'B');
	assert(fetchcalled == 1);

	aclrule = "%X +foo";
	aclrulesize = strlen(aclrule);
	fetchcalled = 0;
	if (a2id_parsestr(&remoteid, "baz@example.com", 0) == -1)
		abort();
	r = a2acl_whichlist(&list, &remoteid, &localid);
	assert(r == -1);
}

void
test_a2acl_parsepolicyline(void)
{
	const char *aclrule, *remotesel, *localid, *err, *policyline;
	size_t aclrulesize, remoteselsize, localidsize;
	int r;

	policyline = "";
	r = a2acl_parsepolicyline(&remotesel, &remoteselsize, &localid,
	    &localidsize, &aclrule, &aclrulesize, policyline,
	    strlen(policyline), &err);
	assert(r == -1);
	assert(err == NULL);

	policyline = "a";
	r = a2acl_parsepolicyline(&remotesel, &remoteselsize, &localid,
	    &localidsize, &aclrule, &aclrulesize, policyline,
	    strlen(policyline), &err);
	assert(r == -1);
	assert(err == &policyline[0]);

	policyline = "xx xxx xx";
	r = a2acl_parsepolicyline(&remotesel, &remoteselsize, &localid,
	    &localidsize, &aclrule, &aclrulesize, policyline,
	    strlen(policyline), &err);
	assert(r == -1);
	assert(err == &policyline[0]);

	policyline = "xx xxx xx ";
	r = a2acl_parsepolicyline(&remotesel, &remoteselsize, &localid,
	    &localidsize, &aclrule, &aclrulesize, policyline,
	    strlen(policyline), &err);
	assert(r == 0);
	assert(remotesel == &policyline[0]);
	assert(remoteselsize == 2);
	assert(localid == &policyline[3]);
	assert(localidsize == 3);
	assert(aclrule == &policyline[7]);
	assert(aclrulesize == 3);

	policyline = " a@selector.   someone@b  %B + %W ++ ";
	r = a2acl_parsepolicyline(&remotesel, &remoteselsize, &localid,
	    &localidsize, &aclrule, &aclrulesize, policyline,
	    strlen(policyline), &err);
	assert(r == 0);
	assert(remotesel == &policyline[1]);
	assert(remoteselsize == 11);
	assert(localid == &policyline[15]);
	assert(localidsize == 9);
	assert(aclrule == &policyline[26]);
	assert(aclrulesize == 11);
}

int
main(void)
{
	test_a2acl_nextsegment();
	test_a2acl_whichlist();
	test_a2acl_parsepolicyline();

	return 0;
}
