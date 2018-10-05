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
 * The ARPA2 ID is the identifier used in the ARPA2 Identity infrastructure. It
 * is loosely based on the Network Access Identifier (RFC 4282).
 */

#include "a2id.h"

/*
 * Allocate a new a2id structure. "domain" is required. "localpart" and
 * "firstopt" may be NULL. If "localpart" is not null than "firstopt" must not
 * be null. If "localpart" has no options than "firstopt" must point to it's
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
	if (a2id)
		a2id_free(&a2id);

	/* assume errno is set */
	return NULL;
}

/*
 * Free an a2id structure.
 */
void
a2id_free(struct a2id **a2id)
{
	if (*a2id == NULL)
		return;

	if ((*a2id)->localpart) {
		free((*a2id)->localpart);
		(*a2id)->localpart = NULL;
		(*a2id)->firstopt = NULL;
	}

	if ((*a2id)->domain) {
		free((*a2id)->domain);
		(*a2id)->domain = NULL;
	}

	free(*a2id);
	*a2id = NULL;
}

/*
 * Parse an ARPA2 ID. The input may contain a localpart and must contain an '@'
 * character followed by a domain.
 *
 * Return a newly allocated a2id structure on success that should be freed by
 * a2id_free when done. Return NULL on error with errno set.
 */
struct a2id *
a2id_fromstr(const char *a2idstr)
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

	if (a2id_parsestr(a2idstrcpy, &lp, &dp, &fp, NULL) == -1) {
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
 * Returns 0 is if the input is a valid ARPA2 ID or -1 otherwise.
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
a2id_parsestr(const char *input, const char **localpart, const char **domain,
    const char **firstopt, int *nropts)
{
	enum states { S, SERVICE, LOCALPART, OPTION, NEWLABEL, DOMAIN } state;
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
			if (basechar[*cp] || *cp == '.') {
				*localpart = (const char *)cp;
				state = LOCALPART;
			} else if (*cp == '+') {
				*localpart = (const char *)cp;
				state = SERVICE;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = NEWLABEL;
			} else
				goto done;
			break;
		case SERVICE:
			if (basechar[*cp] || *cp == '.') {
				state = LOCALPART;
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
				state = OPTION;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = NEWLABEL;
			} else
				goto done;
			break;
		case OPTION:
			if (basechar[*cp] || *cp == '.') {
				state = LOCALPART;
			} else if (*cp == '+') {
				no++;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = NEWLABEL;
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
	if (*cp != '\0' || state != DOMAIN) {

		/*
		 * Let "localpart" or "domain" point to first erroneous character in
		 * "input".
		 */

		*localpart = NULL;
		*domain = NULL;

		switch (state) {
		case S:
			 /* FALLTHROUGH */
		case SERVICE:
			 /* FALLTHROUGH */
		case LOCALPART:
			 /* FALLTHROUGH */
		case OPTION:
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
 * Check if "subject" ends with "suffix", ignoring case.
 *
 * Return 1 if "subject" ends with "suffix", 0 otherwise.
 */
int
endswithsuffix(const char *subject, size_t subjectlen, const char *suffix,
    size_t suffixlen)
{
	if (subjectlen < suffixlen)
		return 0;

	if (strncasecmp(&subject[subjectlen - suffixlen], suffix, suffixlen)
	    != 0)
		return 0;

	return 1;
}

/*
 * Match an ARPA2 ID with an ARPA2 ID Selector.
 *
 * Return 1 if the subject matches the selector, 0 otherwise. If the localpart
 * and/or domain in the selector are an empty string it is considered to be a
 * match to the respective part in the subject.
 */
int
a2id_match(const struct a2id *subject, const struct a2id *selector)
{
	char seldom[A2ID_MAXLEN + 1];
	char *selp, *subp, *nextselp, *nextsubp;
	size_t selectorlen, subjectlen;

	if (selector->localpart == NULL && selector->domain == NULL)
		return 0;

	if (selector->localpart && *selector->localpart != '\0') {
		if (subject->localpart == NULL)
			return 0;

		/* Compare any "+" separated sections. */
		selp = nextselp = selector->localpart;
		subp = nextsubp = subject->localpart;

		/* If first character in selector is "+", this must match. */
		if (*selp == '+' && *subp != '+')
			return 0;

		for (; *selp != '\0'; selp = nextselp, subp = nextsubp) {
			selectorlen = strcspn(selp, "+");
			nextselp += selectorlen;
			nextsubp += strcspn(subp, "+");

			/*
			 * If selector has another option, subject must have
			 * another option.
			 */
			if (*nextselp == '+' && *nextsubp != '+')
				return 0;

			if (selectorlen > 0) {
				assert(nextsubp >= subp);
				if (selectorlen != (size_t)(nextsubp - subp))
					return 0;

				if (strncasecmp(selp, subp, selectorlen) != 0)
					return 0;
			}

			/* Step over plus (not over '\0') */
			if (*nextselp == '+')
				nextselp++;

			if (*nextsubp == '+')
				nextsubp++;
		}

		/* localpart MATCH. */
	}

	if (selector->domain && *selector->domain != '\0') {
		selectorlen = snprintf(seldom, sizeof(seldom), "%s",
		    selector->domain);
		if (selectorlen <= 0 || selectorlen >= sizeof(seldom))
			return 0;

		/* Ensure there is no trailing dot in the selector. */
		if (seldom[selectorlen - 1] == '.') {
			seldom[selectorlen - 1] = '\0';
			selectorlen--;
		}

		if (selectorlen == 0)
			return 1; /* MATCH */

		if (subject->domain == NULL)
			return 0;

		subjectlen = strlen(subject->domain);

		if (subjectlen < selectorlen)
			return 0;

		if (!endswithsuffix(subject->domain, subjectlen, seldom,
		    selectorlen))
			return 0;

		/*
		 * Make sure there is a separator before the matched part if it
		 * was not already in the selector itself.
		 */
		if (seldom[0] != '.' && subjectlen > selectorlen)
			if (subject->domain[subjectlen - selectorlen - 1]
			    != '.')
				return 0;

		/* Domain MATCH. */
	}

	/* Match if we made it this far. */

	return 1;
}
