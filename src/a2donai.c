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
	const char *up, *rp, *fmt, *service, *user, *useralias, *userflags,
	    *usersig;
	char *donaistrcpy;
	size_t len;

	donai = NULL;
	up = rp = fmt = service = user = useralias = userflags = usersig = NULL;
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
	 * If the string contains an '@', treat it as an NAI, if it does not
	 * contain an '@', treat it as a realm-only part of an NAI and prepend
	 * an '@' temporarily ourselves so that we can still use the NAI parser.
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
	 * Separate (any) username from the domain by replacing the '@' with a
	 * '\0'. "rp" points into donaistrcpy if set.
	 */
	if (rp) {
		assert(*rp == '@');
		donaistrcpy[rp - donaistrcpy] = '\0';
		rp++;
	}

	/*
	 * Now try to parse the username itself (so that later we can determine
	 * it's subtype).
	 */
	if (up) {
		if (a2donai_parseuserstr(up, &service, &user, &useralias,
		    &userflags, &usersig) == -1)
			goto err;
	}

	if ((donai = a2donai_alloc(up, rp)) == NULL)
		goto err;

	/* set type and subtype */
	if (up) {
		donai->type = DT_NAI;

		if (service) {
			donai->subtype = DST_SERVICE;
		} else if (usersig) {
			donai->subtype = DST_USERSIG;
		} else if (userflags) {
			donai->subtype = DST_USERFLAGS;
		} else if (useralias) {
			donai->subtype = DST_USERALIAS;
		} else if (user) {
			donai->subtype = DST_USER;
		} else
			abort();
	} else {
		donai->type = DT_DOMAIN;
		donai->subtype = DST_FQDN;
	}

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
 * DoNAI user formal syntax.
 *
 * The grammar for the user is given below, described in Augmented
 * Backus-Naur Form (ABNF) as documented in [RFC5234].
 *
 * donai-user     = user /
 *                  useralias /
 *                  userflags /
 *                  usersig /
 *                  service
 * user           = dot-string
 * useralias      = dot-string "+" dot-string
 * userflags      = dot-string "+" dot-string "+"
 * usersig        = dot-string "+" dot-string "+" dot-string
 * service        = "+" plus-string
 * plus-string    = dot-string *("+" dot-string)
 * dot-string     = string *("." string)
 * string         = 1*atext
 * atext          = ALPHA / DIGIT /
 *                  "!" / "#" /
 *                  "$" / "%" /
 *                  "&" / "'" /
 *                  "*" /
 *                  "-" / "/" /
 *                  "=" / "?" /
 *                  "^" / "_" /
 *                  "`" / "{" /
 *                  "|" / "}" /
 *                  "~" /
 *                  UTF8-xtra-char
 *
 * UTF8-xtra-char = UTF8-2 / UTF8-3 / UTF8-4
 *
 * UTF8-2         = %xC2-DF UTF8-tail
 *
 * UTF8-3         = %xE0 %xA0-BF UTF8-tail /
 *                  %xE1-EC 2( UTF8-tail ) /
 *                  %xED %x80-9F UTF8-tail /
 *                  %xEE-EF 2( UTF8-tail )
 *
 * UTF8-4         = %xF0 %x90-BF 2( UTF8-tail ) /
 *                  %xF1-F3 3( UTF8-tail ) /
 *                  %xF4 %x80-8F 2( UTF8-tail )
 *
 * UTF8-tail      = %x80-BF
 */

static const char userchar[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, /* ! */
	0,
	1, /* # */
	1, /* $ */
	1, /* % */
	1, /* & */
	1, /* ' */
	0, 0,
	1, /* * */
	0, /* "+" PLUS is special */
	0,
	1, /* - */
	0, /* "." DOT is special */
	1, /* / */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-9 */
	0, 0, 0,
	1, /* = */
	0,
	1, /* ? */
	0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* A-Z */
	0, 0, 0,
	1, /* ^ */
	1, /* _ */
	1, /* ` */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* a-z */
	1, /* { */
	1, /* | */
	1, /* } */
	1, /* ~ */
	0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 /* %x80-FF */
};

/*
 * Static DoNAI user parser.
 *
 * Returns 0 is if the input is a valid DoNAI user or -1 otherwise.
 *
 * If "input" is a service, then "service" points to the first character in
 * "input" (which is a '+') and all other parameters are set to NULL. If "input"
 * is not a service but a user then "user" points to the first character of
 * "intput". Furthermore, "useralias" points to the first '+' in "input" or NULL
 * if there is no useralias. "userflags" points to the second '+' in "input" or
 * NULL if there are no userflags. "usersig" points to the third '+' in "input"
 * or NULL if there is no usersig.
 *
 * Note that valid input is either a user or a service but not both.
 *
 * On error the values of "service", "user", "useralias", "userflags" and
 * "usersig" are undefined.
 */
int
a2donai_parseuserstr(const char *input, const char **service, const char **user,
    const char **useralias, const char **userflags, const char **usersig)
{
	enum states { S, SERVICE, SERVICE_E, SERVICEDOT, SERVICEPLUS, USER,
	    USERDOT, USERALIAS, USERALIAS_E, USERALIASDOT, USERFLAGS,
	    USERFLAGS_E, USERFLAGSDOT, USERSIG, USERSIG_E, USERSIGDOT } state;
	const char *cp;

	*service = *user = *useralias = *userflags = *usersig = NULL;

	if (input == NULL)
		return -1;

	for (state = S, cp = input; *cp != '\0'; cp++) {
		switch (state) {
		case S:
			if (userchar[(unsigned char)*cp]) {
				*user = cp;
				state = USER;
			} else if (*cp == '+') {
				*service = cp;
				state = SERVICE;
			} else
				goto done;
			break;
		case SERVICE:
			if (userchar[(unsigned char)*cp]) {
				state = SERVICE_E;
			} else
				goto done;
			break;
		case SERVICE_E:
			/* fast-forward SERVICE_E characters */
			while (userchar[(unsigned char)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '+') {
				state = SERVICEPLUS;
			} else if (*cp == '.') {
				state = SERVICEDOT;
			} else
				goto done;
			break;
		case SERVICEDOT:
			if (userchar[(unsigned char)*cp]) {
				state = SERVICE_E;
			} else
				goto done;
			break;
		case SERVICEPLUS:
			if (userchar[(unsigned char)*cp]) {
				state = SERVICE_E;
			} else
				goto done;
			break;
		case USER:
			/* fast-forward USER characters */
			while (userchar[(unsigned char)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '+') {
				*useralias = cp;
				state = USERALIAS;
			} else if (*cp == '.') {
				state = USERDOT;
			} else
				goto done;
			break;
		case USERDOT:
			if (userchar[(unsigned char)*cp]) {
				state = USER;
			} else
				goto done;
			break;
		case USERALIAS:
			if (userchar[(unsigned char)*cp]) {
				state = USERALIAS_E;
			} else
				goto done;
			break;
		case USERALIAS_E:
			/* fast-forward USERALIAS_E characters */
			while (userchar[(unsigned char)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '+') {
				*userflags = cp;
				state = USERFLAGS;
			} else if (*cp == '.') {
				state = USERALIASDOT;
			} else
				goto done;
			break;
		case USERALIASDOT:
			if (userchar[(unsigned char)*cp]) {
				state = USERALIAS_E;
			} else
				goto done;
			break;
		case USERFLAGS:
			if (userchar[(unsigned char)*cp]) {
				state = USERFLAGS_E;
			} else
				goto done;
			break;
		case USERFLAGS_E:
			/* fast-forward USERFLAGS_E characters */
			while (userchar[(unsigned char)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '+') {
				*usersig = cp;
				state = USERSIG;
			} else if (*cp == '.') {
				state = USERFLAGSDOT;
			} else
				goto done;
			break;
		case USERFLAGSDOT:
			if (userchar[(unsigned char)*cp]) {
				state = USERFLAGS_E;
			} else
				goto done;
			break;
		case USERSIG:
			if (userchar[(unsigned char)*cp]) {
				state = USERSIG_E;
			} else
				goto done;
			break;
		case USERSIG_E:
			/* fast-forward USERSIG_E characters */
			while (userchar[(unsigned char)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '.') {
				state = USERSIGDOT;
			} else
				goto done;
			break;
		case USERSIGDOT:
			if (userchar[(unsigned char)*cp]) {
				state = USERSIG_E;
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
	if (*cp != '\0' || (
	    state != SERVICE_E &&
	    state != USER &&
	    state != USERALIAS_E &&
	    state != USERFLAGS_E &&
	    state != USERSIG_E)) {
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
