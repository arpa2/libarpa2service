/*
 * Copyright (c) 2018, 2019 Tim Kuijsten
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

#ifndef A2ID_H
#define A2ID_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Practial upper bound to the lenght of an ARPA2 ID (not including an optional
 * terminating null.
 */
#define A2ID_MAXLEN 512

enum A2ID_TYPE { A2IDT_DOMAINONLY, A2IDT_GENERIC, A2IDT_SERVICE };

/*
 * The ARPA2 Identifier. Each string must be null terminated. The lengths are
 * excluding the terminating nul byte. Each string must have at least the
 * terminating null byte and must never be NULL.
 *
 * "_str" is private and should not be used.
 */
struct a2id {
	enum A2ID_TYPE type;
	int hassig;	/* whether the ID has a signature */
	int nropts;	/* total number of options, may exceed three */
	int generalized;	/* total times this a2id is generalized */
	char *localpart;	/* points to '+' or '\0' in str */
	char *basename;	/* points to '+' or NULL in str */
	char *firstopt;	/* points to '+' or NULL in str */
	char *sigflags;	/* points to '+' or NULL in str */
	char *domain;	/* points to '@' in str */
	char _str[A2ID_MAXLEN + 1];	/* contains the actual id, might be
					 * broken up by generalization */
	size_t localpartlen;
	size_t basenamelen;
	size_t firstoptlen;
	size_t sigflagslen;	/* length including leading '+', excluding
				   trailing '+' */
	size_t domainlen;	/* can not be 0 because of '@' requirement */
	size_t idlen;
};

int a2id_parsestr(struct a2id *, const char *, int);
int a2id_match(const struct a2id *, const struct a2id *);
int a2id_generalize(struct a2id *);
int a2id_coreform(char *, const struct a2id *, size_t *);
int a2id_tostr(char *, const struct a2id *, size_t *);
size_t a2id_optsegments(const char **, const struct a2id *);

void printa2id(FILE *, const struct a2id *);

#endif /* A2ID_H */
