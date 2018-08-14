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
 * A NAI is a Network Access Identifier as specified by RFC 4282.
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

	if (username) {
		if ((donai->username = strdup(username)) == NULL)
			goto err; /* errno is set by strdup */
		donai->type = DT_NAI;
	} else
		donai->type = DT_DOMAIN;


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
 * Parse a DoNAI. If the input contains an '@' character, treat it as a RFC 4282
 * compliant NAI, else treat the input as a domain, compliant with the realm
 * part of RFC 4282.
 *
 * Return a newly allocated a2donai structure on success that should be freed by
 * a2donai_free when done. Return NULL on error with errno set.
 */
struct a2donai *
a2donai_fromstr(const char *donaistr)
{
	struct a2donai *donai;
	const char *up, *rp, *fmt;
	char *donaistrcpy;
	size_t len;

	donai = NULL;
	up = rp = NULL;
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

	/*
	 * Determine if this is a Domain or NAI and parse accordingly. Create a
	 * mutable copy of the input.
	 *
	 * If the string contains an '@', treat it as a NAI, if it does not
	 * contain an '@', treat it as a realm-only part of a NAI and prepend an
	 * '@' temporarily ourselves so that we can still use the NAI parser.
	 */

	if (strchr(donaistr, '@') == NULL) {
		fmt = "@%s";
		assert(INT_MAX - 1 > len);
		len++;
	} else {
		fmt = "%s";
	}

	assert(INT_MAX - 1 > len);
	if ((donaistrcpy = malloc(len + 1)) == NULL)
		return NULL; /* errno set by malloc */

	if (snprintf(donaistrcpy, len + 1, fmt, donaistr) >= len + 1) {
		errno = EINVAL;
		goto err;
	}

	if (nai_parsestr(donaistrcpy, &up, &rp) == -1) {
		errno = EINVAL;
		goto err;
	}

	/*
	 * Separate the username from the domain by replacing the '@' with a
	 * '\0'. "rp" points into donaistrcpy if set.
	 */
	if (rp) {
		assert(*rp == '@');
		donaistrcpy[rp - donaistrcpy] = '\0';
		rp++;
	}

	if ((donai = a2donai_alloc(up, rp)) == NULL)
		goto err;

	/* SUCCESS */

	free(donaistrcpy);
	donaistrcpy = NULL;

	return donai;

err:
	if (donaistrcpy)
		free(donaistrcpy);
	donaistrcpy = NULL;

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
 * Return 1 if the subject matches the selector, 0 otherwise.
 */
int
a2donai_match(const struct a2donai *selector, const struct a2donai *subject)
{
	size_t selectorlen, subjectlen;

	if (selector->username == NULL && selector->domain == NULL)
		return 0;

	if (selector->username) {
		if ((selectorlen = strlen(selector->username)) == 0)
			return 0;

		if (subject->username == NULL)
			return 0;

		if (strncmp(selector->username, subject->username, selectorlen)
		    != 0)
			return 0;

		/* Make sure there is a separator after the matched part. */
		if (subject->username[selectorlen] != '\0' &&
		    subject->username[selectorlen] != '+')
			return 0;

		/* Username MATCH. */
	}

	if (selector->domain) {
		if ((selectorlen = strlen(selector->domain)) == 0)
			return 0;

		if (subject->domain == NULL)
			return 0;

		subjectlen = strlen(subject->domain);

		if (subjectlen < selectorlen)
			return 0;

		if (!endswithsuffix(subject->domain, subjectlen,
		    selector->domain, selectorlen))
			return 0;

		/*
		 * Make sure there is a separator before the matched part if it
		 * was not already in the selector itself.
		 */
		if (selector->domain[0] != '.' && subjectlen > selectorlen)
			if (subject->domain[subjectlen - selectorlen - 1]
			    != '.')
				return 0;

		/* Domain MATCH. */
	}

	/* Match if we made it this far. */

	return 1;
}
