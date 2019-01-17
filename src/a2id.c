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
 * ARPA2 ID library
 *
 * The ARPA2 ID is the identifier used in the ARPA2 Identity infrastructure.
 */

#include "a2id.h"

/*
 * Allocate a new a2id structure. "domain" is required, while "localpart" and
 * "firstopt" may be NULL. If "localpart" is not NULL then "firstopt" must not
 * be NULL. If "localpart" has no options then "firstopt" must point to it's
 * terminating '\0' character otherwise to the first '+' in "localpart".
 *
 * Return a newly allocated a2id structure on success that should be freed by
 * a2id_free when done. Return NULL on error with errno set.
 */
struct a2id *
a2id_alloc(const char *domain, const char *localpart, const char *firstopt)
{
	struct a2id *a2id;

	if (domain == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* Both set or both unset. */
	if (!localpart != !firstopt) {
		errno = EINVAL;
		return NULL;
	}

	if ((a2id = calloc(1, sizeof(*a2id))) == NULL)
		goto err; /* errno is set by calloc */

	/* Default to domain-only type. */
	a2id->type = A2IDT_DOMAINONLY;

	if (localpart) {
		if (localpart > firstopt) {
			errno = EINVAL;
			goto err;
		}

		if (strlen(localpart) < (firstopt - localpart)) {
			errno = EINVAL;
			goto err;
		}

		if (*firstopt != '+' && *firstopt != '\0') {
			errno = EINVAL;
			goto err;
		}

		if ((a2id->localpart = strdup(localpart)) == NULL)
			goto err; /* errno is set by strdup */

		a2id->firstopt = a2id->localpart + (firstopt - localpart);

		if (*localpart == '+')
			a2id->type = A2IDT_SERVICE;
		else
			a2id->type = A2IDT_GENERIC;
	}

	if ((a2id->domain = strdup(domain)) == NULL)
		goto err; /* errno is set by strdup */

	return a2id;

err:

	/* assume errno is set */
	return NULL;
}

/*
 * Copy an a2id structure.
 *
 * Note: domain, localpart, basename, firstopt and sigflags all point into the
 * complete A2ID string representation.
 *
 * Note2: The caller is responsible for allocating an a2id structure.
 *
 * Return 0 on success, -1 on failure with errno set.
 */
int
a2id_copy(struct a2id *out, const struct a2id *id)
{
	if (out == NULL || id == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (id->localpartlen < id->basenamelen ||
	    id->localpartlen < id->firstoptlen ||
	    id->localpartlen < id->sigflagslen ||
	    id->localpartlen > A2ID_MAXLEN ||
	    id->domainlen > A2ID_MAXLEN ||
	    A2ID_MAXLEN - id->domainlen < id->localpartlen
	) {
		errno = EINVAL;
		return -1;
	}

	memset(out, 0, sizeof(*out));

	out->strlen = id->localpartlen + id->domainlen;
	out->localpartlen = id->localpartlen;
	out->basenamelen = id->basenamelen;
	out->firstoptlen = id->firstoptlen;
	out->sigflagslen = id->sigflagslen;
	out->domainlen = id->domainlen;

	if (id->localpartlen)
		memcpy(out->str, id->localpart, id->localpartlen);

	memcpy(&out->str[id->localpartlen], id->domain,
	    id->domainlen);

	if (id->localpartlen > 0)
		out->localpart = out->str;
	else /* point to trailing 0 */
		out->localpart = &out->str[sizeof(out->str) - 1];

	if (id->basenamelen > 0)
		out->basename = id->basename;
	else /* point to trailing 0 */
		out->basename = &out->str[sizeof(out->str) - 1];

	if (id->firstoptlen > 0)
		out->firstopt = id->firstopt;
	else /* point to trailing 0 */
		out->firstopt = &out->str[sizeof(out->str) - 1];

	if (id->sigflagslen > 0)
		out->sigflags = id->sigflags;
	else /* point to trailing 0 */
		out->sigflags = &out->str[sizeof(out->str) - 1];

	if (id->domainlen > 0)
		out->domain = (char *)id->str;
	else /* point to trailing 0 */
		out->domain = &out->str[sizeof(out->str) - 1];

	out->type = id->type;
	out->hassig = id->hassig;
	out->nropts = id->nropts;

	return 0;
}

/*
 * Parse an ARPA2 ID Selector. The input may contain a localpart and must contain an '@'
 * character followed by a domain.
 *
 * Return a newly allocated a2id structure on success that should be freed by
 * a2id_free when done. Return NULL on error with errno set.
 */
struct a2id *
a2id_fromselstr(const char *a2idstr)
{
	struct a2id *a2id;
	const char *lp, *dp, *fp;
	char *a2idstrcpy;
	size_t len;

	a2id = NULL;
	dp = lp = fp = NULL;
	a2idstrcpy = NULL;
	len = 0;

	if (a2idstr == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((len = strlen(a2idstr)) > A2ID_MAXLEN) {
		errno = EINVAL;
		return NULL;
	}

	/* Create a mutable copy of the input. */
	if ((a2idstrcpy = strdup(a2idstr)) == NULL)
		goto err;

	if (a2id_parseselstr(a2idstrcpy, &lp, &dp, &fp, NULL) == -1) {
		errno = EINVAL;
		goto err;
	}

	/*
	 * If there is a localpart without options, let fp point to the end of
	 * the localpart.
	 * dp points the '@' in a2idstrcpy.
	 */
	if (lp && !fp)
		fp = dp;

	/*
	 * Separate (any) localpart from the domain by replacing the '@' with a
	 * '\0'.
	 * dp points the '@' in a2idstrcpy.
	 */
	assert(*dp == '@');
	a2idstrcpy[dp - a2idstrcpy] = '\0';
	dp++;

	if ((a2id = a2id_alloc(dp, lp, fp)) == NULL)
		goto err;

	/* SUCCESS */

	free(a2idstrcpy);

	return a2id;

err:
	if (a2idstrcpy)
		free(a2idstrcpy);

	return NULL;
}

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
 * Static ARPA2 ID parser.
 *
 * Parse a null terminated input string.
 *
 * Returns 0 is if the input is a valid ARPA2 ID or -1 otherwise.
 *
 * If "input" is valid and has a localpart then "id->localpart" points to the
 * first character of "input" or NULL if there is no localpart. "id->domain"
 * points to the one and only "@" or otherwise the input is invalid.
 * "id->nropts" contains the number of options in the localpart. If the
 * localpart has one or more options then "id->firstopt" points to the '+' of
 * the first option in "input" or NULL if there are no options. The same goes
 * for "id->secondopt" and "id->thirdopt".
 *
 * On error id->str contains a null terminated up to but not including the first
 * erroneous character.
 *
 * XXX rename firstopt to options + optionslen
 */
int
a2id_parsestr(struct a2id *out, const char *input)
{
	enum states { S, SERVICE, LOCALPART, OPTION, NEWLABEL, DOMAIN } state;
	char *curopt, *prevopt, *secondopt;
	size_t i;
	unsigned char c;

	if (input == NULL || out == NULL)
		return -1;

	secondopt = prevopt = curopt = NULL;

	out->nropts = 0;
	out->localpart = NULL;
	out->basename = NULL;
	out->firstopt = NULL;
	out->sigflags = NULL;
	out->domain = NULL;

	state = S;
	for (i = 0; i < A2ID_MAXLEN && input[i] != '\0'; i++) {
		c = input[i];

		/* Copy string. */
		out->str[i] = c;

		switch (state) {
		case S:
			if (basechar[c] || c == '.') {
				out->localpart = &out->str[i];
				out->basename = &out->str[i];
				state = LOCALPART;
			} else if (c == '+') {
				out->localpart = &out->str[i];
				state = SERVICE;
			} else if (c == '@') {
				out->domain = &out->str[i];
				state = NEWLABEL;
			} else
				goto done;
			break;
		case SERVICE:
			if (basechar[c] || c == '.') {
				out->basename = &out->str[i];
				state = LOCALPART;
			} else
				goto done;
			break;
		case LOCALPART:
			if (basechar[c] || c == '.') {
				/* keep going */
			} else if (c == '+') {
				prevopt = curopt;
				curopt = &out->str[i];
				if (out->firstopt == NULL) {
					out->firstopt = &out->str[i];
				} else if (secondopt == NULL) {
					secondopt = &out->str[i];
				}

				out->nropts++;
				state = OPTION;
			} else if (c == '@') {
				out->domain = &out->str[i];
				state = NEWLABEL;
			} else
				goto done;
			break;
		case OPTION:
			if (basechar[c] || c == '.') {
				state = LOCALPART;
			} else if (c == '+') {
				prevopt = curopt;
				curopt = &out->str[i];
				if (secondopt == NULL) {
					secondopt = &out->str[i];
				}
				out->nropts++;
			} else if (c == '@') {
				out->domain = &out->str[i];
				state = NEWLABEL;
			} else
				goto done;
			break;
		case DOMAIN:
			if (basechar[c]) {
				/* keep going */
			} else if (c == '.') {
				state = NEWLABEL;
			} else
				goto done;
			break;
		case NEWLABEL:
			if (basechar[c]) {
				state = DOMAIN;
			} else
				goto done;
			break;
		default:
			abort();
		}
	}

done:
	/* Ensure termination. */
	out->strlen = i;
	out->str[i] = '\0';

	out->generalized = 0;

	/*
	 * Make sure the end of the input is reached and the state is one of the
	 * final states.
	 */
	if (input[i] != '\0' || state != DOMAIN)
		return -1;

	/* Determine type. */
	if (out->localpart) {
		if (*out->localpart == '+')
			out->type = A2IDT_SERVICE;
		else
			out->type = A2IDT_GENERIC;
	} else {
		out->type = A2IDT_DOMAINONLY;
	}

	/* Calculate lengths and point to trailing '\0' if length is 0. */

	out->domainlen = &out->str[i] - out->domain;
	assert(out->domainlen > 0);

	out->localpartlen = out->domain - out->str;

	if (out->localpartlen == 0)
		out->localpart = &out->str[i];

	/* First determine if there was a signature. */
	if (curopt && prevopt && curopt + 1 == out->domain) {
		out->hassig = 1;
		out->sigflags = prevopt;
		out->sigflagslen = curopt - prevopt;

		/*
		 * Undo the signature which has a leading and trailing '+' that
		 * are both counted as an option.
		 */
		out->nropts -= 2;
		if (out->nropts == 0) {
			out->firstopt = NULL;
			out->firstoptlen = 0;
		}
	} else {
		out->hassig = 0;
		out->sigflagslen = 0;
		out->sigflags = &out->str[i];
	}

	if (out->firstopt) {
		if (secondopt) {
			out->firstoptlen = secondopt - out->firstopt;
		} else if (out->sigflagslen)
			out->firstoptlen = out->sigflags - out->firstopt;
		else
			out->firstoptlen = out->domain - out->firstopt;
	} else {
		out->firstoptlen = 0;
		out->firstopt = &out->str[i];
	}

	if (out->basename) {
		if (out->firstoptlen) {
			out->basenamelen = out->firstopt - out->basename;
		} else if (out->sigflagslen) {
			out->basenamelen = out->sigflags - out->basename;
		} else {
			out->basenamelen = out->domain - out->basename;
		}
	} else {
		out->basenamelen = 0;
		out->basename = &out->str[i];
	}

	return 0;
}

/*
 * Static ARPA2 ID Selector parser.
 *
 * Returns 0 is if the input is a valid ARPA2 ID Selector or -1 otherwise.
 *
 * If "input" is valid and has a localpart then "localpart" points to the first
 * character of "input" or NULL if there is no localpart. "domain" points to the
 * one and only "@" or otherwise the input is invalid. If the localpart has one
 * or more options then "firstopt" points to the '+' of the first option in
 * "input" or NULL if there are no options. If "nropts" is passed it is set to
 * contain the number of options in the localpart.
 *
 * On error "localpart" or "domain" are updated to point to the first erroneous
 * character encountered in "input" depending on where the error occurred,
 * "firstopt" and "nropts" are undefined.
 */
int
a2id_parseselstr(const char *input, const char **localpart, const char **domain,
    const char **firstopt, int *nropts)
{
	enum states { S, LOCALPART, DOMAIN, NEWLABEL } state;
	const unsigned char *cp;
	const char *fo;
	int no;

	*localpart = *domain= NULL;
	fo = NULL;
	no = 0;

	if (input == NULL)
		return -1;

	for (state = S, cp = (const unsigned char *)input; *cp != '\0'; cp++) {
		switch (state) {
		case S:
			if (basechar[*cp] || *cp == '.' || *cp == '+') {
				*localpart = (const char *)cp;
				state = LOCALPART;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = DOMAIN;
			} else
				goto done;
			break;
		case LOCALPART:
			/* fast-forward LOCALPART characters */
			while (basechar[*cp] || *cp == '.')
				cp++;
			/*
			 * After while: prevent out-of-bounds cp++ in for-loop.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '+') {
				if (fo == NULL)
					fo = (const char *)cp;

				no++;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = DOMAIN;
			} else
				goto done;
			break;
		case DOMAIN:
			/* fast-forward DOMAIN characters */
			while (basechar[*cp])
				cp++;
			/*
			 * After while: prevent out-of-bounds cp++ in for-loop.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '.') {
				state = NEWLABEL;
			} else
				goto done;
			break;
		case NEWLABEL:
			if (basechar[*cp]) {
				state = DOMAIN;
			} else
				goto done;
			break;
		default:
			abort();
		}
	}

done:
	/*
	 * Make sure the end of the input is reached and the state is one of the
	 * final states.
	 */
	if (*cp != '\0' || (state != DOMAIN && state != NEWLABEL)) {

		/*
		 * Let "localpart" or "domain" point to first erroneous character in
		 * "input".
		 */

		*localpart = NULL;
		*domain = NULL;

		switch (state) {
		case S:
			 /* FALLTHROUGH */
		case LOCALPART:
			*localpart = (const char *)cp;
			break;
		case NEWLABEL:
			 /* FALLTHROUGH */
		case DOMAIN:
			*domain = (const char *)cp;
			break;
		default:
			abort();
		}

		return -1;
	}

	*firstopt = fo;

	if (nropts)
		*nropts = no;

	return 0;
}

/*
 * Match an ARPA2 ID with an ARPA2 ID Selector.
 *
 * Return 1 if the subject matches the selector, 0 otherwise. If the localpart
 * and/or domain in the selector are an empty string it is considered to be a
 * match to the respective part in the subject.
 *
 * XXX rename subject into id
 *	nextselopt => nextselp en nextsubp
 */
int
a2id_match(const struct a2id *subject, const struct a2id *selector,
    int requiresig)
{
	char *selp, *subp;
	size_t selplen, subplen;

	if (subject == NULL || selector == NULL)
		abort();

	/* Default to "no match" on empty selectors. */
	if (selector->localpart == NULL && selector->domain == NULL)
		return 0;

	if (selector->localpartlen > 0)
		if (selector->localpartlen > subject->localpartlen)
			return 0;

	if (selector->basenamelen > 0) {
		if (selector->basenamelen != subject->basenamelen)
			return 0;

		if (strncmp(selector->basename, subject->basename,
		    selector->basenamelen) != 0)
			return 0;
	}

	if (selector->nropts > 0) {
		if (selector->nropts > subject->nropts)
			return 0;

		/* XXX guard against inconsistent a2id state */
		assert(selector->firstopt && subject->firstopt);

		/* compare each option */
		selp = selector->firstopt;
		subp = subject->firstopt;
		for (int i = 0; i < selector->nropts; i++) {
			/* XXX guard against inconsistent a2id state */
			assert(*selp == '+' && *subp == '+');

			/* Step over leading plus of current option. */
			selp++;
			subp++;

			selplen = strcspn(selp, "+");
			subplen = strcspn(subp, "+");

			if (selplen != subplen)
				return 0;

			if (strncasecmp(selp, subp, selplen) != 0)
				return 0;

			selp += selplen;
			subp += subplen;
		}
	}

	if (requiresig)
		if (subject->hassig == 0)
			return 0;

	if (selector->domainlen > 0) {
		/*
		 * Can't compare domain lengths because of optional trailing
		 * dots and possibly empty labels in the selector.
		 */
		if (subject->domainlen < 1)
			return 0;

		/* compare each label, starting from the back */
		assert(*selector->domain == '@' && *subject->domain == '@');
		selp = &selector->domain[selector->domainlen - 1];
		subp = &subject->domain[subject->domainlen - 1];

		for (;;) {
			/* Step over leading dot of current label. */
			if (*selp == '.') /* ROOT dot is optional */
				selp--;

			if (*subp == '.')
				subp--;

			for (selplen = 0; *selp != '@' && *selp != '.';
			    selplen++)
				selp--;

			for (subplen = 0; *subp != '@' && *subp != '.';
			    subplen++)
				subp--;

			if (*selp == '@' && selplen == 0)
				break; /* done, every selector label matches */

			if (selplen == 0)
				continue; /* label existence match */

			if (selplen != subplen)
				return 0;

			if (strncasecmp(selp, subp, selplen) != 0)
				return 0;

			/* exact label match */
		}
	}

	/* Match if we made it this far. */

	return 1;
}

/*
 * Wipe the string of the last option in-place. Retain the plus and move up
 * remaining plusses. "len" is a value-result parameter.
 *
 * Return 1 if option data is wiped with "len" set to contain the new length of
 * "localpart". Return, 0 if no option is left to be wiped.
 */
int
wipeoptiondata(char *localpart, int *len)
{
	char *cp;
	int plusses, poswipe;

	if (*len == 0)
		return 0;

	/*
	 * Go from the back of the localpart up to the second character
	 * (including). This way a leading '+' is automatically ignored.
	 */
	plusses = 0;
	poswipe = 0;
	for (cp = &localpart[*len - 1]; cp > localpart; cp--) {
		if (!poswipe && *cp != '+') {
			poswipe = 1;
		} else if (!poswipe && *cp == '+') {
			plusses++;
		} else if (poswipe && *cp == '+') {
			/*
			 * At the beginning of an option that should be wiped.
			 * Write down remaning plusses and terminate with '\0'.
			 */
			for (cp += 1; plusses > 0; plusses--)
				*cp++ = '+';

			*cp = '\0';
			*len = cp - localpart;

			return 1;
		}
	}

	return 0;
}

/*
 * Generalize an A2ID structure by one step.
 *
 * Returns 1 if a component is stripped from the localpart or the domain.
 * Returns 0 if nothing is stripped ("id" has an empty localpart and the catch-
 * all domain "@."). Returns 0 if id is NULL.
 *
 * XXX don't move domain by removing every label, just increment the domain
 * pointer now that the memory is allocated statically in the structure.
 */
int
a2id_generalize(struct a2id *id)
{
	char *cp;
	size_t i, n;

	if (id == NULL)
		return 0;

	if (id->sigflagslen > 0) {
		if (id->sigflagslen > 1) {
			/* remove signature data, but leave trailing '+' */
			*(id->sigflags + 1) = '+';
			*(id->sigflags + 2) = '\0';
			id->localpartlen -= id->sigflagslen - 1;
			id->sigflagslen = 1;
		} else {
			/* remove signature and trailing '+' */
			*id->sigflags = '\0';
			id->localpartlen -= id->sigflagslen + 1;
			id->sigflagslen = 0;
			id->hassig = 0;
		}

		id->strlen = id->localpartlen + id->domainlen;
		id->generalized++;
		return 1;
	}

	if (id->nropts > 0) {
		cp = &id->localpart[id->localpartlen - 1];

		/*
		 * Either delete the option data, or the option. If there is
		 * only a trailing '+', remove the option, else everything up
		 * to the previous '+' is removed, exclusive.
		 */

		/* remove the option */
		if (*cp == '+') {
			*cp = '\0';
			id->nropts--;
			id->localpartlen--;

			if (id->nropts == 0) {
				*id->firstopt = '\0';
				id->firstoptlen = 0;
			}
		} else /* remove option data only */
			for (; *cp != '+'; cp--, id->localpartlen--)
				*cp = '\0';

		id->strlen = id->localpartlen + id->domainlen;
		id->generalized++;
		return 1;
	}

	if (id->basenamelen > 0) {
		*id->basename = '\0';
		id->localpartlen -= id->basenamelen;
		id->basenamelen = 0;
		id->strlen = id->localpartlen + id->domainlen;
		id->generalized++;
		return 1;
	}

	/* Strip next label. */

	assert(id->domain[0] == '@');

	cp = id->domain;
	/* step over '@' */
	cp++;
	if (cp[0] != '.' || cp[1] != '\0') {
		/*
		 * Either remove leading dot, or up to, but not including, next
		 * dot.
		 */

		assert(id->domainlen >= 2);

		/* Find the number of characters before the first dot. */
		n = strcspn(cp, ".");

		/* If the first character is a dot, remove the dot itself. */
		if (n == 0)
			n = 1;

		/* move rtl */
		for (i = 0; cp[i + n]; i++)
			cp[i] = cp[i + n];

		/* and terminate */
		cp[i] = '\0';

		id->domainlen -= n;

		/* On end of string, ensure terminating ROOT dot. */
		if (cp[n] == '\0') {
			cp[0] = '.';
			cp[1] = '\0';
			id->domainlen = 2;
		}

		return 1;
	}

	return 0;
}

void
printa2id(FILE *fp, const struct a2id *id)
{
	fprintf(fp, "type %d\n", id->type);
	fprintf(fp, "hassig %d\n", id->hassig);
	fprintf(fp, "nropts %d\n", id->nropts);
	fprintf(fp, "generalized %d\n", id->generalized);

	fprintf(fp, "localpart %zu %.*s\n", id->localpartlen, (int)id->localpartlen,
	    id->localpart);
	fprintf(fp, "basename %zu %.*s\n", id->basenamelen, (int)id->basenamelen,
	    id->basename);
	fprintf(fp, "firstopt %zu %.*s\n", id->firstoptlen, (int)id->firstoptlen,
	    id->firstopt);
	fprintf(fp, "sigflags %zu %.*s\n", id->sigflagslen, (int)id->sigflagslen,
	    id->sigflags);
	fprintf(fp, "domain %zu %.*s\n", id->domainlen, (int)id->domainlen,
	    id->domain);
	fprintf(fp, "str %zu %.*s\n", id->strlen, (int)id->strlen, id->str);
}

/*
 * Write the core form of "id" as a string into "dst". "dstsize" is a
 * valid/result parameter.
 *
 * Return 0 on success, -1 if dst is too short (this should never happen if dst
 * is at least A2ID_MAXLEN + 1 bytes).
 */
int
a2id_coreform(char *dst, const struct a2id *id, size_t *dstsize)
{
	size_t r;

	switch (id->type) {
	case A2IDT_GENERIC:
		r = snprintf(dst, *dstsize, "%.*s%.*s", (int)id->basenamelen,
		    id->basename, (int)id->domainlen, id->domain);

		if (r >= *dstsize)
			return -1;
		*dstsize = r;
		return 0;
	case A2IDT_SERVICE:
		r = snprintf(dst, *dstsize, "+%.*s%.*s", (int)id->basenamelen,
		    id->basename, (int)id->domainlen, id->domain);

		if (r >= *dstsize)
			return -1;
		*dstsize = r;
		return 0;
	case A2IDT_DOMAINONLY:
		r = snprintf(dst, *dstsize, "%.*s", (int)id->domainlen,
		    id->domain);

		if (r >= *dstsize)
			return -1;
		*dstsize = r;
		return 0;
	}

	return -1;
}

/*
 * Write the string representation of "id" into "dst". dstsize is a value/result
 * parameter.
 *
 * Return 0 on success, -1 if dst is too short (this should never happen if dst
 * is at least A2ID_MAXLEN + 1 bytes).
 */
int
a2id_tostr(char *dst, const struct a2id *id, size_t *dstsize)
{
	size_t r;

	r = snprintf(dst, *dstsize, "%.*s%.*s", (int)id->localpartlen,
	    id->localpart, (int)id->domainlen, id->domain);

	if (r >= *dstsize)
		return -1;

	*dstsize = r;

	return 0;
}

/*
 * Determine the start and length of optional segments, excluding any sigflags
 * segment.
 *
 * "optseg" will be set to point to the first character of the first option,
 * right after it's leading '+'. If "id" has no optional segments then "optseg"
 * is not set.
 *
 * Returns the length of "optseg" or 0 if "optseg" is not set.
 *
 * XXX might want to make this part of a2id_parsestr
 */
size_t
a2id_optsegments(const char **optseg, const struct a2id *id)
{
	size_t s;

	if (id->firstoptlen <= 1)
		return 0;

	*optseg = id->firstopt;
	s = id->localpartlen - id->basenamelen;

	/* Step over leading optseg '+' */
	(*optseg)++;
	s--;

	if (id->type == A2IDT_SERVICE) {
		assert(*id->localpart == '+');
		assert(*id->basename != '+');
		s--;
	}

	if (id->sigflagslen > 0) {
		assert(s > id->sigflagslen);
		s -= id->sigflagslen;
		s--; /* trailing '+' */
	}

	return s;
}
