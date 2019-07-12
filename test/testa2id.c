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
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../src/a2id.c"

void
test_parsestr(void)
{
	struct a2id id;
	const char *input;
	int r;

	/* Run some tests. */

	input = "foo@example.org";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[3]) == 0);
	assert(id.nropts == 0);

	input = "!foo@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(id.nropts == 0);

	input = "a+b@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[3]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 1);

	input = "a+b+@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(strcmp(id.sigflags, &input[1]) == 0);
	assert(id.hassig == 1);
	assert(id.basenamelen == 1);
	assert(id.nropts == 0);

	input = "a+b+c@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[5]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);

	input = "~@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[1]) == 0);
	assert(id.nropts == 0);

	input = " @example.com";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 0);

	input = "@";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 1);

	input = "\x7f@example.com";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 0);

	input = "+a@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[2]) == 0);
	assert(id.nropts == 0);

	input = "+@example.com";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 1);

	input = "a+@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[2]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 1);

	input = "a++b@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);

	input = "+a++b@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[5]) == 0);
	assert(strcmp(id.firstopt, &input[2]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);

	input = "++@example.com";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 1);

	input = "foo! bar~\177@example.com";
	r = parsestr(&id, input, 0);
	assert(r == -1);
	assert(id.idlen == 4);

	/* test valid ids */
	input = "@example.com";
	input = "@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "", id.localpartlen) == 0);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_DOMAINONLY);

	input = "user@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "user", 4) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 4);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "user+subid@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "user+subid", id.localpartlen) == 0);
	assert(*id.firstopt == '+');
	assert(id.basenamelen == 4);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "user+flags+signature@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "user+flags+signature", id.localpartlen) == 0);
	assert(*id.firstopt == '+');
	assert(id.basenamelen == 4);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "+service+arg1+arg2@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "+service+arg1+arg2", id.localpartlen) == 0);
	assert(*id.firstopt == '+');
	assert(id.basenamelen == 7);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_SERVICE);

	/* Adapted list from RFC 4282 */
	input = "joe@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "joe", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 3);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "fred@foo-9.example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "fred", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 4);
	assert(strncmp(id.domain, "@foo-9.example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "jack@3rd.depts.example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "jack", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 4);
	assert(strncmp(id.domain, "@3rd.depts.example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "fred.smith@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "fred.smith", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 10);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "fred_smith@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "fred_smith", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 10);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "fred$@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "fred$", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 5);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "fred=?#$&*+-/^smith@example.com";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "fred=?#$&*+-/^smith", id.localpartlen) == 0);
	assert(*id.firstopt == '+');
	assert(id.basenamelen == 10);
	assert(strncmp(id.domain, "@example.com", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "nancy@eng.example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "nancy", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 5);
	assert(strncmp(id.domain, "@eng.example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "eng.example.net!nancy@example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "eng.example.net!nancy", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 21);
	assert(strncmp(id.domain, "@example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "eng%nancy@example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "eng%nancy", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 9);
	assert(strncmp(id.domain, "@example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "@privatecorp.example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(id.localpartlen == 0);
	assert(strncmp(id.domain, "@privatecorp.example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_DOMAINONLY);

	input = "\\(user\\)@example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(id.localpart != NULL);
	assert(*id.firstopt == '\0');
	assert(strncmp(id.localpart, "\\(user\\)", id.localpartlen) == 0);
	assert(id.basenamelen == 8);
	assert(strncmp(id.domain, "@example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "<user>@example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(id.localpart != NULL);
	assert(*id.firstopt == '\0');
	assert(strncmp(id.localpart, "<user>", id.localpartlen) == 0);
	assert(id.basenamelen == 6);
	assert(strncmp(id.domain, "@example.net", id.domainlen) == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "alice@xn--tmonesimerkki-bfbb.example.net";
	r = parsestr(&id, input, 0);
	assert(r == 0);
	assert(strncmp(id.localpart, "alice", id.localpartlen) == 0);
	assert(*id.firstopt == '\0');
	assert(id.basenamelen == 5);
	assert(strncmp(id.domain, "@xn--tmonesimerkki-bfbb.example.net", id.domainlen) ==
	    0);
	assert(id.type == A2IDT_GENERIC);

	/* test invalid ids */
	assert(parsestr(&id, "", 0) == -1);
	assert(id.idlen == 0);
	assert(parsestr(&id, "joe", 0) == -1);
	assert(id.idlen == 3);
	assert(parsestr(&id, "fred@example.net@example.net", 0) == -1);
	assert(id.idlen == 16);

	/*
	 * Regressions
	 */

	/*
	 * A trailing dot is only accepted in selectors.
	 */
	assert(parsestr(&id, "foo@example.org.", 0) == -1);
	assert(parsestr(&id, "foo@example.org.", 1) == 0);
}

void
test_parsestr_selector(void)
{
	struct a2id id;
	const char *input;
	int r;

	/* Run some tests. */

	input = "foo@example.org";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[3]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "!foo@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_GENERIC);

	input = "a+b@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[3]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 1);
	assert(id.type == A2IDT_GENERIC);

	input = "a+b+@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 0);
	assert(id.hassig == 1);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(strcmp(id.sigflags, &input[1]) == 0);
	assert(id.type == A2IDT_GENERIC);
	assert(id.type == A2IDT_GENERIC);

	input = "a+b+c@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[5]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);
	assert(id.type == A2IDT_GENERIC);

	input = "~@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[1]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_GENERIC);

	input = " @example.com";
	r = parsestr(&id, input, 1);
	assert(r == -1);
	assert(id.idlen == 0);

	input = "@.";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.localpartlen == 0);
	assert(strcmp(id.domain, &input[0]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_DOMAINONLY);

	input = "@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.localpartlen == 0);
	assert(strcmp(id.domain, &input[0]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_DOMAINONLY);

	input = "\x7f@example.com";
	r = parsestr(&id, input, 1);
	assert(r == -1);
	assert(id.idlen == 0);

	input = "+a@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[2]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_SERVICE);

	input = "+@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[1]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_SERVICE);

	input = "+@.";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[1]) == 0);
	assert(strlen(id.firstopt) == 0);
	assert(id.nropts == 0);
	assert(id.type == A2IDT_SERVICE);

	input = "a+@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[2]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 1);
	assert(id.type == A2IDT_GENERIC);

	input = "a++b@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[4]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);
	assert(id.type == A2IDT_GENERIC);

	input = "+a++b@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[5]) == 0);
	assert(strcmp(id.firstopt, &input[2]) == 0);
	assert(id.basenamelen == 1);
	assert(id.nropts == 2);
	assert(id.type == A2IDT_SERVICE);

	input = "++@example.com";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[2]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 0);
	assert(id.nropts == 1);
	assert(id.hassig == 0);
	assert(id.type == A2IDT_SERVICE);

	input = "+++++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[5]) == 0);
	assert(strcmp(id.firstopt, &input[1]) == 0);
	assert(id.basenamelen == 0);
	assert(id.nropts == 2);
	assert(id.hassig == 1);
	assert(id.type == A2IDT_SERVICE);

	input = "foo! bar~\177@example.com";
	r = parsestr(&id, input, 1);
	assert(r == -1);
	assert(id.idlen == 4);
	assert(strcmp(id.localpart, "foo!") == 0);
	assert(id.domain == NULL);
	assert(id.type == A2IDT_GENERIC);

	input = "+abc++++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(strcmp(id.localpart, &input[0]) == 0);
	assert(strcmp(id.domain, &input[8]) == 0);
	assert(strcmp(id.firstopt, &input[4]) == 0);
	assert(id.basenamelen == 3);
	assert(id.nropts == 2);
	assert(id.hassig == 1);
	assert(id.type == A2IDT_SERVICE);

	/* leading '+' is always a service */
	input = "+@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_SERVICE);
	assert(id.localpartlen == 1);
	assert(id.basenamelen == 0);
	assert(id.sigflagslen == 0);
	assert(id.nropts == 0);
	assert(id.hassig == 0);

	/* trailing single '+' is always an option */
	input = "++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_SERVICE);
	assert(id.localpartlen == 2);
	assert(id.basenamelen == 0);
	assert(id.sigflagslen == 0);
	assert(id.nropts == 1);
	assert(id.hassig == 0);

	/* two trailing '+'s are always a signature */
	input = "+++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_SERVICE);
	assert(id.localpartlen == 3);
	assert(id.basenamelen == 0);
	assert(id.sigflagslen == 1);
	assert(id.nropts == 0);
	assert(id.hassig == 1);

	/* any '+'s except service and signature are options */
	input = "++++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_SERVICE);
	assert(id.localpartlen == 4);
	assert(id.basenamelen == 0);
	assert(id.sigflagslen == 1);
	assert(id.nropts == 1);
	assert(id.hassig == 1);

	/* same for generic ids */

	/* trailing single '+' is always an option */
	input = "G+@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_GENERIC);
	assert(id.localpartlen == 2);
	assert(id.basenamelen == 1);
	assert(id.sigflagslen == 0);
	assert(id.nropts == 1);
	assert(id.hassig == 0);

	/* two trailing '+'s are always a signature */
	input = "G++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_GENERIC);
	assert(id.localpartlen == 3);
	assert(id.basenamelen == 1);
	assert(id.sigflagslen == 1);
	assert(id.nropts == 0);
	assert(id.hassig == 1);

	/* any '+'s preceeding a signature are options */
	input = "G+++@";
	r = parsestr(&id, input, 1);
	assert(r == 0);
	assert(id.type == A2IDT_GENERIC);
	assert(id.localpartlen == 4);
	assert(id.basenamelen == 1);
	assert(id.sigflagslen == 1);
	assert(id.nropts == 1);
	assert(id.hassig == 1);
}

void
test_a2id_generalize(void)
{
	struct a2id id;
	a2id *idp = (a2id *)&id;
	char output[128];
	const size_t outputsz = sizeof(output);

	a2id_fromstr(idp, "foo+bar+asig+@some.example.org", 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "foo+bar++@some.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "foo+bar@some.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "foo+@some.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "foo@some.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@some.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@.example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@example.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@.org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@org") == 0);

	assert(a2id_generalize(idp) == 1);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@.") == 0);

	assert(a2id_generalize(idp) == 0);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "@.") == 0);
}

void
test_a2id_coreform(void)
{
	struct a2id id;
	a2id *idp = (a2id *)&id;
	char output[128];
	const char *input;
	const size_t outputsz = sizeof(output);
	int r;

	input = "foo+bar++@some.example.org";

	r = a2id_fromstr(idp, input, 1);
	assert(r == 0);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, input) == 0);

	assert(a2id_coreform(output, outputsz, idp) < outputsz);
	assert(strcmp(output, "foo@some.example.org") == 0);
}

void
test_a2id_localpart_options(void)
{
	struct a2id id;
	a2id *idp = (a2id *)&id;
	char output[128];
	const char *input;
	const size_t outputsz = sizeof(output);
	int r, opts;

	input = "foo+bar+other+signflags+@some.example.org";

	r = a2id_fromstr(idp, input, 1);
	assert(r == 0);
	assert(a2id_tostr(output, outputsz, idp) < outputsz);
	assert(strcmp(output, input) == 0);

	assert(a2id_localpart_options(output, outputsz, &opts, idp) == 9);
	assert(strcmp(output, "bar+other") == 0);
	assert(opts == 2);

	input = "foo+a@some.example.org";

	a2id_fromstr(idp, input, 1);
	assert(a2id_localpart_options(output, outputsz, &opts, idp) == 1);
	assert(strcmp(output, "a") == 0);
	assert(opts == 1);

	input = "foo+@some.example.org";

	a2id_fromstr(idp, input, 1);
	assert(a2id_localpart_options(output, outputsz, &opts, idp) == 0);
	assert(strcmp(output, "") == 0);
	assert(opts == 1);
}

int
main(void)
{
	test_parsestr();
	test_parsestr_selector();
	test_a2id_generalize();
	test_a2id_coreform();
	test_a2id_localpart_options();

	return 0;
}
