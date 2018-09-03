#ifndef A2DONAI_H
#define A2DONAI_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nai.h"

/*
 * Impose a practial upper bound to the lenght of a DoNAI, a domain-or-NAI.
 * This is important to avoid overzealous allocations and subsequent buffer
 * or stack overflows.
 */
#define A2DONAI_MAXLEN 512

enum A2DONAI_TYPE { DT_INVALID, DT_DOMAIN, DT_NAI };

enum A2DONAI_SUBTYPE { DST_INVALID, DST_FQDN, DST_SERVICE, DST_USER,
    DST_USERALIAS, DST_USERFLAGS, DST_USERSIG };

struct a2donai {
	char *username;
	char *domain;
	enum A2DONAI_TYPE type;
	enum A2DONAI_SUBTYPE subtype;
};

struct a2donai *a2donai_alloc(const char *, const char *);
void a2donai_free(struct a2donai *);
struct a2donai *a2donai_fromstr(const char *);
struct a2donai *a2donai_fromselstr(const char *);
int a2donai_parseuserstr(const char *, const char **, const char **,
    const char **, const char **, const char **);
int a2donai_parsestr(const char *, const char **, const char **, const char **,
    int *);
int a2donai_match(const struct a2donai *, const struct a2donai *);

#endif /* A2DONAI_H */
