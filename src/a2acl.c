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

/*
 * ARPA2 ACL library
 *
 * Retreive, validate and modify access policies.
 */

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "a2acl.h"

static const char basechar[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, /* ! */
	1, /* " */
	1, /* # */
	1, /* $ */
	1, /* % */
	1, /* & */
	1, /* ' */
	1, /* ( */
	1, /* ) */
	1, /* * */
	0, /* "+" PLUS is special */
	1, /* , */
	1, /* - */
	0, /* "." DOT is special */
	1, /* / */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-9 */
	1, /* : */
	1, /* ; */
	1, /* < */
	1, /* = */
	1, /* > */
	1, /* ? */
	0, /* "@" AT is special */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* A-Z */
	1, /* [ */
	1, /* \ */
	1, /* ] */
	1, /* ^ */
	1, /* _ */
	1, /* ` */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* a-z */
	1, /* { */
	1, /* | */
	1, /* } */
	1  /* ~ */
	/* let rest of static array initialize to 0 */
};

/*
 * Allocate and initialize a new ACL rule segment iterator, to be used by
 * a2acl_nextsegment(3).
 *
 * On successful return the new structure should be free(3)d by the caller.
 *
 * Return a newly initialized structure on success or NULL on error with errno
 * set.
 */
struct a2aclit *
a2acl_newit(const char *aclrule, size_t aclrulesize)
{
	struct a2aclit *it;

	if ((it = calloc(1, sizeof(*it))) == NULL)
		return NULL;

	it->initialized = 42;
	it->state = S;
	it->aclrule = aclrule;
	it->aclrulesize = aclrulesize;
	it->n = 0;

	return it;
}

/*
 * Check if "id" matches with "aclseg".
 *
 * Signature presence is tested if required, but not validated.
 *
 * Return 1 if true, 0 if false.
 */
int
a2acl_aclsegmatch(const struct a2id *id, const struct a2aclseg *aclseg)
{
	const char *idoptseg;
	size_t idoptsegsize;

	if (id == NULL || aclseg == NULL)
		return 0;

	/* Handle signature presence requirements. */
	if (aclseg->reqsigflags)
		if (id->sigflagslen == 0)
			return 0;

	/* Handle wildcard ACL */
	if (aclseg->segsize == 0)
		return 1;

	if ((idoptsegsize = a2id_optsegments(&idoptseg, id)) == 0)
		return 0;

	/* assume no leading '+' in segments */
	assert(aclseg->seg[0] != '+');
	assert(idoptseg[0] != '+');

	if (aclseg->segsize > idoptsegsize)
		return 0;

	if (strncmp(aclseg->seg, idoptseg, aclseg->segsize) != 0)
		return 0;

	if (aclseg->segsize == idoptsegsize)
		return 1;

	if (idoptseg[aclseg->segsize] == ' ' ||
	    idoptseg[aclseg->segsize] == '+')
		return 1;

	return 0;
}

/*
 * Parse an ACL rule. Returns whenever a new segment is parsed or the end of the
 * ACL rule is reached. "aclit" should be created once with a2acl_newit(3) and
 * used with this function repeatedly until 0 or -1 is returned.
 *
 * Returns 1 if "list", "aclseg" are set to a new segment. 0 if there are no
 * more segments and -1 on error (illegal syntax or list-types etc.).
 */
int
a2acl_nextsegment(char *list, struct a2aclseg *aclseg, struct a2aclit *aclit)
{
	unsigned char c, lookahead;

	if (list == NULL || aclseg == NULL || aclit == NULL)
		return -1;

	if (aclit->initialized != 42 || aclit->aclrule == NULL)
		return -1; /* not initialized with a2acl_newit(3) */

	aclseg->reqsigflags = 0;
	aclseg->segsize = 0;
	aclseg->seg = NULL;

	for (; aclit->n < aclit->aclrulesize; aclit->n++) {
		c = aclit->aclrule[aclit->n];

		switch (aclit->state) {
		case S:
			if (isblank(c)) {
				/* keep going */
			} else if (c == '%') {
				aclit->state = SETLIST;
			} else
				goto done;
			break;
		case SETLIST:
			switch (c) {
			case 'W':
				/* FALLTHROUGH */
			case 'G':
				/* FALLTHROUGH */
			case 'B':
				/* FALLTHROUGH */
			case 'A':
				aclit->state = LIST;
				*list = c;
				break;
			default:
				goto done;
			}
			break;
		case LIST:
			if (isblank(c)) {
				/* keep going */
			} else if (c == '+') {
				aclit->state = WILDCARD;
			} else
				goto done;
			break;
		case WILDCARD:
			aclseg->seg = &aclit->aclrule[aclit->n];
			if (isblank(c)) {
				aclit->state = POSTSEGMENT;
				return 1;
			} else if (c == '+') {
				aclseg->reqsigflags = 1;
				aclit->state = REQSIGFLAGS;
			} else if (basechar[c] || c == '.') {
				aclseg->segsize++;
				aclit->state = SEGMENTNAME;
			} else
				goto done;
			break;
		case SEGMENTNAME:
			if (basechar[c] || c == '.') {
				aclseg->segsize++;
			} else if (isblank(c)) {
				aclit->state = POSTSEGMENT;
				return 1;
			} else if (c == '+') {
				/* look-ahead for SUBSEGMENT or REQSIGFLAGS */
				if (aclit->n + 1 < aclit->aclrulesize) {
					lookahead = aclit->aclrule[aclit->n + 1];
				} else
					lookahead = '\0';

				if (basechar[lookahead] || lookahead == '.') {
					aclseg->segsize++;
					aclit->state = SUBSEGMENT;
				} else if (lookahead == '\0' ||
				    isblank(lookahead)) {
					/* REQSIGFLAGS */
					aclseg->reqsigflags = 1;
					aclit->state = REQSIGFLAGS;
				} else {
					goto done;
				}
			} else
				goto done;
			break;
		case SUBSEGMENT:
			if (basechar[c] || c == '.') {
				aclseg->segsize++;
				aclit->state = SEGMENTNAME;
			} else
				goto done;
			break;
		case POSTSEGMENT:
			if (isblank(c)) {
				/* keep going */
			} else if (c == '+') {
				aclit->state = WILDCARD;
			} else if (c == '%') {
				aclit->state = SETLIST;
			} else
				goto done;
			break;
		case REQSIGFLAGS:
			if (isblank(c)) {
				aclit->state = POSTSEGMENT;
				return 1;
			} else
				goto done;
			break;
		default:
			abort();
		}
	}

done:
	/* Is all input processed? */
	if (aclit->n != aclit->aclrulesize)
		return -1;

	/* Are we in one of the final states? */
	if (aclit->state != WILDCARD &&
	    aclit->state != REQSIGFLAGS &&
	    aclit->state != POSTSEGMENT &&
	    aclit->state != SEGMENTNAME &&
	    aclit->state != E)
		return -1;

	/* Is there a segment left? */
	if (aclit->state == WILDCARD ||
	    aclit->state == SEGMENTNAME ||
	    aclit->state == REQSIGFLAGS) {
		aclit->state = E;
		return 1;
	}

	return 0;
}

/*
 * Determine if communication between "remoteid" and "localid" is whitelisted,
 * greylisted, blacklisted or abandoned.
 *
 * The result is written to "list" in the form of the first letter of the list
 * this pair is on which is one of: 'W', 'G', 'B', 'A'. If no policy is found it
 * is set to 'G'.
 *
 * "remoteid" will be generalized until an ACL rule is found or until it equals
 * the most general selector "@." which can not be further generalized.
 *
 * Returns 0 on success and updates "*list" to point to the applicable list-
 * character which is either a 'W', 'G', 'B', or 'A'. Returns -1 on error.
 *
 * XXX returns -1 if an ACL rule is syntactically incorrect, these checks should
 * better be done on import.
 */
int
a2acl_whichlist(char *list, struct a2id *remoteid, const struct a2id *localid)
{
	struct a2aclseg aclseg;
	struct a2aclit *it;
	char aclrule[A2ACL_MAXLEN], coreid[A2ID_MAXLEN + 1], remotestr[A2ID_MAXLEN + 1];
	size_t aclrulesize, remotestrsz, coreidsz;
	int match, r;

	coreidsz = sizeof(coreid);
	if (a2id_coreform(coreid, localid, &coreidsz) == -1)
		return -1;

	for (;;) {
		remotestrsz = sizeof(remotestr);
		if (a2id_tostr(remotestr, remoteid, &remotestrsz) == -1)
			return -1;

		aclrulesize = sizeof(aclrule);
		if (a2acl_getaclrule(aclrule, &aclrulesize, remotestr,
		    remotestrsz, coreid, coreidsz) == -1)
			return -1;

		if (aclrulesize == 0) {
			if (a2id_generalize(remoteid))
				continue;
			else
				break;
		}

		if ((it = a2acl_newit(aclrule, aclrulesize)) == NULL)
			return -1;

		/* iterate over acl segments and see if there is a match */
		match = 0;
		while ((r = a2acl_nextsegment(list, &aclseg, it)) == 1) {
			if (a2acl_aclsegmatch(localid, &aclseg)) {
				match = 1;
				break;
			}
		}

		free(it);
		it = NULL;

		if (r == -1)
			return -1;

		if (match)
			return 0;

		if (a2id_generalize(remoteid) != 1)
			break;
	}

	/* default policy */
	*list = 'G';
	return 0;
}

/*
 * Parse an ACL policy line consisting of a remote selector, a local id and an
 * ACL rule. The IDs and ACL rule are only parsed loosely and "line" must have
 * the following form:
 *
 *    policyline = *WSP remotesel 1*WSP localid 1*WSP aclrule
 *    remotesel  = 2*graph
 *    localid    = 3*graph
 *    aclrule    = 3*print
 *    graph      = %x21-7e
 *    print      = %x20-7e
 *
 * Return 0 on success and set "remotesel", "localid" and "aclrule" to point to
 * the start of the respective part in "line". Sizes are updated accordingly and
 * "err" is set to NULL.
 * Return -1 on error. If there was a syntax error in "line" then "err" is set
 * to point to the first erroneous character in "line". If there was another
 * error then "err" is set to NULL and errno is set.
 */
int
a2acl_parsepolicyline(const char **remotesel, size_t *remoteselsize,
    const char **localid, size_t *localidsize, const char **aclrule,
    size_t *aclrulesize, const char *line, size_t linesize, const char **err)
{
	const size_t minrulelen = sizeof("@. a@b %B+") - 1;
	size_t n;

	*err = NULL;
	n = 0;

	if (remotesel == NULL || remoteselsize == NULL || localid == NULL ||
	    localidsize == NULL || aclrule == NULL || aclrulesize == NULL ||
	    line == NULL || linesize == 0 || err == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (linesize < minrulelen) {
		*err = &line[0];
		return -1;
	}

	/*
	 * Parse remote selector.
	 */

	while (n < linesize && isblank(line[n]))
		n++;
	if (n == linesize) {
		*err = &line[n - 1];
		return -1;
	}

	*remotesel = &line[n];

	while (n < linesize && isgraph(line[n]))
		n++;
	if (n == linesize) {
		*err = &line[n - 1];
		return -1;
	}

	if (!isblank(line[n])) {
		*err = &line[n];
		return -1;
	}

	*remoteselsize = &line[n] - *remotesel;
	if (*remoteselsize < 2) {
		*err = &line[n];
		return -1;
	}

	/*
	 * Parse local id.
	 */

	while (n < linesize && isblank(line[n]))
		n++;
	if (n == linesize) {
		*err = &line[n - 1];
		return -1;
	}

	*localid = &line[n];

	while (n < linesize && isgraph(line[n]))
		n++;
	if (n == linesize) {
		*err = &line[n - 1];
		return -1;
	}

	if (!isblank(line[n])) {
		*err = &line[n];
		return -1;
	}

	*localidsize = &line[n] - *localid;
	if (*localidsize < 3) {
		*err = &line[n];
		return -1;
	}

	/*
	 * Parse ACL rule until end of line.
	 */

	while (n < linesize && isblank(line[n]))
		n++;
	if (n == linesize) {
		*err = &line[n - 1];
		return -1;
	}

	*aclrule = &line[n];

	while (n < linesize && isprint(line[n]))
		n++;

	if (n != linesize) {
		assert(n < linesize);
		*err = &line[n];
		return -1;
	}

	*aclrulesize = (&line[n - 1] - *aclrule) + 1;
	if (*aclrulesize < 3) {
		*err = &line[n - 1];
		return -1;
	}

	return 0;
}

/*
 * Import an ACL policy from a readable descriptor yielding ACL rules.
 *
 * Each line in the file must be of the format "remotesel localid aclrule".
 * Extraneous blanks are ignored.
 *
 * Returns the number of imported ACL rules on success or -1 on error with errno
 * set. If "errstr" is passed and -1 is returned a descriptive error is set in
 * "errstr", nul terminated and at most "errstrsize" bytes, including the
 * terminating nul.
 */
ssize_t
a2acl_fromdes(int d, char *errstr, size_t errstrsize)
{
	const ssize_t minrulelen = sizeof("@. a@b %B+") - 1;
	const char *remotesel, *localid, *aclrule, *err;
	char *line;
	ssize_t i, n;
	size_t remoteselsize, localidsize, aclrulesize, s;
	FILE *fp;

	if (errstrsize)
		errstr[0] = '\0';

	if ((fp = fdopen(d, "re")) == NULL)
		return -1; /* errno set */

	i = 0;
	line = NULL;

	while ((n = getline(&line, &s, fp)) > 0) {
		i++;
		if (n < minrulelen) {
			if (errstrsize)
				snprintf(errstr, errstrsize, "illegal ACL rule "
				    "at line %zu: %s\n", i, line);
			errno = EINVAL;
			free(line);
			return -1;
		}

		if (line[n - 1] == '\n')
			n--;

		if (a2acl_parsepolicyline((const char **)&remotesel,
		    &remoteselsize, (const char **)&localid, &localidsize,
		    (const char **)&aclrule, &aclrulesize, line, n,
		    (const char **)&err) == -1) {
			free(line);
			if (err) {
				if (errstrsize)
					snprintf(errstr, errstrsize, "illegal "
					    "ACL policy line at #%zu,%lu: %s\n",
					    i, err - line, line);
				errno = EINVAL;
				return -1;
			} else
				return -1; /* errno is set */
		}

		if (a2acl_putaclrule(aclrule, aclrulesize, remotesel,
		    remoteselsize, localid, localidsize) == -1) {
			free(line);
			errno = EINVAL;
			return -1;
		}
	}

	free(line);
	if (ferror(fp)) {
		fprintf(stderr, "%s: error while reading ACL file\n", __func__);
		exit(1);
	}

	return i;
}

/*
 * Check if "subject" is newer than "reference" when looking at the last
 * modification times.
 *
 * Return 1 if "subject" is newer than "reference" or if "reference" does not
 * exist. Return 0 if subject is older or equal to "reference". Return -1 if an
 * error occurred with errno set (i.e. subject does not exist).
 */
int
a2acl_isnewer(const char *subject, const char *reference)
{
	struct stat rst, sst;
	int r, refd, subd;

	if (subject == NULL || reference == NULL)
		return -1;

	if ((subd = open(subject, O_RDONLY|O_CLOEXEC)) == -1)
		return -1;

	if ((refd = open(reference, O_RDONLY|O_CLOEXEC)) == -1)
		return 1;

	r = 0;

	/* compare mtimes */
	if (fstat(refd, &rst) == -1)
		goto out; /* errno set */

	if (fstat(subd, &sst) == -1)
		goto out; /* errno set */

	if (rst.st_mtime < sst.st_mtime)
		r = 1;

out:
	close(refd);
	close(subd);

	return r;
}

/*
 * Import an ACL policy from a text file specified by "filename" into an
 * internal database cache. If a database cache file does not exist, it is
 * created and if the cache is stale it is automatically recreated. The
 * currently supported database backends are "dbm" and "dblmdb" of which the
 * first is a simple memory based key-value store, and the latter is using LMDB.
 *
 * Each line in "filename" must consist of exactly one ACL rule, which is a
 * triplet of the form: <remote selector, local ID, ACL segments>
 *
 * Where remote selector is an ARPA2 ID Selector, local ID is an ARPA2 ID in
 * core form and ACL segments are one or more ACL segments. Extraneous blanks
 * are ignored.
 *
 * If "totrules" is not NULL, it will be updated with the total number of rules
 * in the database. If "updrules" is not NULL it will be updated with the number
 * of newly imported rules by this call.
 *
 * If there is an error and "errstr" is not NULL, then "errstr" is updated with
 * a descriptive error of at most "errstrsize" bytes, including the terminating
 * nul.
 *
 * Returns 0 on success or -1 on error with errno set.
 */
int
a2acl_fromfile(const char *filename, size_t *totrules, size_t *updrules,
    char *errstr, size_t errstrsize)
{
	char dbcache[104];
	size_t s;
	int fd, r, recreate;

	if (errstrsize)
		errstr[0] = '\0';

	if (filename == NULL) {
		errno = EINVAL;
		return -1;
	}

	s = strlen(filename);
	if (s == 0 || sizeof(dbcache) - 4 < s) {
		errno = EINVAL;
		return -1;
	}

	r = snprintf(dbcache, sizeof(dbcache), "%.*s.db", (int)s,
	    filename);
	if (r <= 0 || sizeof(dbcache) <= (size_t)r) {
		errno = EINVAL;
		return -1;
	}

	/* remove stale db caches before opening/creating */
        recreate = a2acl_isnewer(filename, dbcache);
        if (recreate == -1)
		return -1;

        if (recreate != 0)
		if (unlink(dbcache) == -1 && errno != ENOENT)
			return -1; /* errno set */

	if (a2acl_dbopen(dbcache) == -1) {
		if (errstrsize)
			snprintf(errstr, errstrsize, "error opening database,"
			    " param: %s\n", dbcache);
		errno = EINVAL;
		return -1;
	}

	if (updrules)
		*updrules = 0;

        if (recreate) {
		if ((fd = open(filename, O_RDONLY|O_CLOEXEC)) == -1) {
			a2acl_dbclose();
			return -1; /* errno set */
		}

		if ((r = a2acl_fromdes(fd, errstr, sizeof(errstr))) < 0) {
			a2acl_dbclose();
			close(fd);
			errno = EINVAL;
			return -1;
		}

		close(fd);
		if (updrules)
			*updrules = r;
	}


	if (totrules) {
		if (a2acl_count(totrules) == -1) {
			errno = EINVAL;
			return -1;
		}
	}

	return 0;
}
