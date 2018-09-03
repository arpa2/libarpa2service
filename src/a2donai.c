/*
 * Copyright (c) 2018 Tim Kuijsten <info@netsend.nl>
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
 * A library with DoNAI utilities. A DoNAI consists of either a Domain-or-NAI.
 * An NAI is a Network Access Identifier as specified by RFC 4282.
 */

#include "a2donai.h"

/*
 * Allocate a new a2donai structure. "username" may be NULL, "domain" must not
 * be NULL.
 *
 * Return a newly allocated a2donai structure on success that should be freed by
 * a2donai_free when done. Return NULL on error with errno set.
 */
struct a2donai *
a2donai_alloc(const char *username, const char *domain)
{
	struct a2donai *donai;

	if (domain == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((donai = calloc(1, sizeof(*donai))) == NULL)
		goto err; /* errno is set by calloc */

	if (username)
		if ((donai->username = strdup(username)) == NULL)
			goto err; /* errno is set by strdup */

	if ((donai->domain = strdup(domain)) == NULL)
		goto err; /* errno is set by strdup */

	return donai;

err:
	if (donai)
		a2donai_free(donai);

	/* assume errno is set */
	return NULL;
}

/*
 * Free an a2donai structure.
 */
void
a2donai_free(struct a2donai *donai)
{
	assert(donai != NULL);

	if (donai->username) {
		free(donai->username);
		donai->username = NULL;
	}

	if (donai->domain) {
		free(donai->domain);
		donai->domain = NULL;
	}

	free(donai);
}

/*
 * Parse a DoNAI. The input may contain a username and must contain an '@'
 * character followed by a domain,
 *
 * Return a newly allocated a2donai structure on success that should be freed by
 * a2donai_free when done. Return NULL on error with errno set.
 */
struct a2donai *
a2donai_fromstr(const char *donaistr)
{
	struct a2donai *donai;
	const char *lp, *dp, *fp;
	char *donaistrcpy;
	size_t len;
	int nrparams;

	donai = NULL;
	lp = dp = fp = NULL;
	donaistrcpy = NULL;
	len = 0;

	if (donaistr == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((len = strlen(donaistr)) > A2DONAI_MAXLEN) {
		errno = EINVAL;
		return NULL;
	}

	/* Create a mutable copy of the input.  */
	if ((donaistrcpy = strdup(donaistr)) == NULL)
		goto err;

	if (a2donai_parsestr(donaistrcpy, &lp, &dp, &fp, &nrparams) == -1) {
		errno = EINVAL;
		goto err;
	}

	/*
	 * Separate (any) localpart from the domain by replacing the '@' with a
	 * '\0'. "dp" points into donaistrcpy if set.
	 */
	assert(*dp == '@');
	donaistrcpy[dp - donaistrcpy] = '\0';
	dp++;

	if ((donai = a2donai_alloc(lp, dp)) == NULL)
		goto err;

	/* SUCCESS */

	free(donaistrcpy);

	return donai;

err:
	if (donaistrcpy)
		free(donaistrcpy);

	return NULL;
}

/*
 * Parse a DoNAI selector. If the input contains an '@' character, treat it as a
 * username selector, else treat the input as a domain selector.
 *
 * Return a newly allocated a2donai structure on success that should be freed by
 * a2donai_free when done. Return NULL on error with errno set.
 */
struct a2donai *
a2donai_fromselstr(const char *donaiselstr)
{
	struct a2donai *donai;
	const char *up, *rp, *fmt;
	char *donaiselstrcpy;
	size_t len;

	donai = NULL;
	up = rp = NULL;
	donaiselstrcpy = NULL;
	len = 0;

	if (donaiselstr == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((len = strlen(donaiselstr)) > A2DONAI_MAXLEN) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * Determine if this is a Domain or NAI and parse accordingly. Create a
	 * mutable copy of the input.
	 *
	 * If the string contains an '@', treat it as a username selector, if it
	 * does not contain an '@', treat it as a domain-only selector and
	 * prepend an '@' temporarily ourselves so that we can still use the
	 * NAI selector parser.
	 */

	if (strchr(donaiselstr, '@') == NULL) {
		fmt = "@%s";
		assert(INT_MAX - 1 > len);
		len++;
	} else {
		fmt = "%s";
	}

	assert(INT_MAX - 1 > len);
	if ((donaiselstrcpy = malloc(len + 1)) == NULL)
		return NULL; /* errno set by malloc */

	if (snprintf(donaiselstrcpy, len + 1, fmt, donaiselstr) >= len + 1) {
		errno = EINVAL;
		goto err;
	}

	if (nai_parseselstr(donaiselstrcpy, &up, &rp) == -1) {
		errno = EINVAL;
		goto err;
	}

	/*
	 * Separate the username from the domain by replacing the '@' with a
	 * '\0'. "rp" points into donaiselstrcpy if set.
	 */
	if (rp) {
		assert(*rp == '@');
		donaiselstrcpy[rp - donaiselstrcpy] = '\0';
		rp++;
	}

	if ((donai = a2donai_alloc(up, rp)) == NULL)
		goto err;

	/* SUCCESS */

	free(donaiselstrcpy);
	donaiselstrcpy = NULL;

	return donai;

err:
	if (donaiselstrcpy)
		free(donaiselstrcpy);
	donaiselstrcpy = NULL;

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
 * Static DoNAI parser.
 *
 * Returns 0 is if the input is a valid DoNAI or -1 otherwise.
 *
 * If "input" is valid then "localpart" points to the first character of "input".
 * "firstparam" points to the first '+' in "input" or NULL if there are no
 * parameters. "nrparams" is set to contain the number of parameters that follow
 * the subject of the localpart and domain is set to point to the "@" symbol.
 *
 * On error "localpart" or "domain" are updated to point to the first
 * erroneous character encountered in "input" depending on where the error
 * occurred, "firstparam" and "nrparams" are undefined.
 */
int
a2donai_parsestr(const char *input, const char **localpart, const char **domain,
    const char **firstparam, int *nrparams)
{
	enum states { S, LOCALPART, PARAM, NEWLABEL, DOMAIN } state;
	const unsigned char *cp;

	*localpart = *firstparam = *domain = NULL;
	*nrparams = 0;

	if (input == NULL)
		return -1;

	for (state = S, cp = (const unsigned char *)input; *cp != '\0'; cp++) {
		switch (state) {
		case S:
			if (basechar[*cp] || *cp == '.') {
				*localpart = (const char *)cp;
				state = LOCALPART;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = NEWLABEL;
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
				if (*firstparam == NULL)
					*firstparam = (const char *)cp;

				(*nrparams)++;
				state = PARAM;
			} else if (*cp == '@') {
				*domain = (const char *)cp;
				state = NEWLABEL;
			} else
				goto done;
			break;
		case PARAM:
			if (basechar[*cp] || *cp == '.') {
				state = LOCALPART;
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
		case LOCALPART:
			 /* FALLTHROUGH */
		case PARAM:
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
 * Return 1 if the subject matches the selector, 0 otherwise. If the selector
 * username and/or domain are an empty string it is considered to be a match to
 * the respective part in the subject.
 */
int
a2donai_match(const struct a2donai *selector, const struct a2donai *subject)
{
	char seldom[A2DONAI_MAXLEN + 1];
	size_t selectorlen, subjectlen;

	if (selector->username == NULL && selector->domain == NULL)
		return 0;

	if (selector->username && *selector->username != '\0') {
		selectorlen = strlen(selector->username);

		if (subject->username == NULL)
			return 0;

		if (strncmp(selector->username, subject->username, selectorlen)
		    != 0)
			return 0;

		/*
		 * Make sure there is a separator after the matched part if it
		 * was not already in the selector itself.
		 */
		if (selector->username[selectorlen - 1] != '+' &&
		    subject->username[selectorlen] != '\0' &&
		    subject->username[selectorlen] != '+')
			return 0;

		/* Username MATCH. */
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
