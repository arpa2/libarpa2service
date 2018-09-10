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

#include "../src/a2id.h"

void
test_a2id_parsestr(void)
{
	const char *input, *localpart, *domain, *firstparam;
	int r, nrparams;

	/* Run some tests. */

	input = "foo@example.org";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[3]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "!foo@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[4]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "a+b@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[3]);
	assert(firstparam == &input[1]);
	assert(nrparams == 1);

	input = "a+b+@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[4]);
	assert(firstparam == &input[1]);
	assert(nrparams == 2);

	input = "a+b+c@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[5]);
	assert(firstparam == &input[1]);
	assert(nrparams == 2);

	input = "~@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[1]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = " @example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[0]);
	assert(domain == NULL);

	input = "@";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == NULL);
	assert(domain == &input[1]);

	input = "\x7f@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[0]);
	assert(domain == NULL);

	input = "+a@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[2]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "+@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[1]);
	assert(domain == NULL);

	input = "a+@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[2]);
	assert(firstparam == &input[1]);
	assert(nrparams == 1);

	input = "a++b@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[4]);
	assert(firstparam == &input[1]);
	assert(nrparams == 2);

	input = "+a++b@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[5]);
	assert(firstparam == &input[2]);
	assert(nrparams == 2);

	input = "++@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[1]);
	assert(domain == NULL);

	input = "foo! bar~\177@example.com";
	r = a2id_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[4]);
	assert(domain == NULL);
}

/* Test if a string can be converted to an ARPA2 ID structure. */
void
test_a2id_fromstr(void)
{
	struct a2id *id;

	/* test valid ids */
	id = a2id_fromstr("@example.com");
	assert(id != NULL);
	assert(id->localpart == NULL);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_DOMAINONLY);
	a2id_free(id);

	id = a2id_fromstr("user@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "user") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("user+subid@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "user+subid") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("user+flags+signature@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "user+flags+signature") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("+service+arg1+arg2@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "+service+arg1+arg2") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_SERVICE);
	a2id_free(id);

	/* Adapted list from RFC 4282 */
	id = a2id_fromstr("joe@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "joe") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("fred@foo-9.example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "fred") == 0);
	assert(strcmp(id->domain, "foo-9.example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("jack@3rd.depts.example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "jack") == 0);
	assert(strcmp(id->domain, "3rd.depts.example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("fred.smith@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "fred.smith") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("fred_smith@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "fred_smith") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("fred$@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "fred$") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("fred=?#$&*+-/^smith@example.com");
	assert(id != NULL);
	assert(strcmp(id->localpart, "fred=?#$&*+-/^smith") == 0);
	assert(strcmp(id->domain, "example.com") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("nancy@eng.example.net");
	assert(id != NULL);
	assert(strcmp(id->localpart, "nancy") == 0);
	assert(strcmp(id->domain, "eng.example.net") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("eng.example.net!nancy@example.net");
	assert(id != NULL);
	assert(strcmp(id->localpart, "eng.example.net!nancy") == 0);
	assert(strcmp(id->domain, "example.net") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("eng%nancy@example.net");
	assert(id != NULL);
	assert(strcmp(id->localpart, "eng%nancy") == 0);
	assert(strcmp(id->domain, "example.net") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("@privatecorp.example.net");
	assert(id != NULL);
	assert(id->localpart == NULL);
	assert(strcmp(id->domain, "privatecorp.example.net") == 0);
	assert(id->type == A2IDT_DOMAINONLY);
	a2id_free(id);

	id = a2id_fromstr("\\(user\\)@example.net");
	assert(id != NULL);
	assert(id->localpart != NULL);
	assert(strcmp(id->localpart, "\\(user\\)") == 0);
	assert(strcmp(id->domain, "example.net") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("<user>@example.net");
	assert(id != NULL);
	assert(id->localpart != NULL);
	assert(strcmp(id->localpart, "<user>") == 0);
	assert(strcmp(id->domain, "example.net") == 0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	id = a2id_fromstr("alice@xn--tmonesimerkki-bfbb.example.net");
	assert(id != NULL);
	assert(strcmp(id->localpart, "alice") == 0);
	assert(strcmp(id->domain, "xn--tmonesimerkki-bfbb.example.net") ==
	    0);
	assert(id->type == A2IDT_GENERIC);
	a2id_free(id);

	/* test invalid ids */
	assert(a2id_fromstr("") == NULL);
	assert(a2id_fromstr("joe") == NULL);
	assert(a2id_fromstr("fred@example.net@example.net") == NULL);
}

int
main(void)
{
	test_a2id_parsestr();
	test_a2id_fromstr();

	return 0;
}
