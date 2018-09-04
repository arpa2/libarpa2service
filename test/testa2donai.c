#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../src/a2donai.h"

void
test_a2donai_parsestr(void)
{
	const char *input, *localpart, *domain, *firstparam;
	int r, nrparams;

	/* Run some tests. */

	input = "foo@example.org";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[3]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "!foo@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[4]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "a+b@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[3]);
	assert(firstparam == &input[1]);
	assert(nrparams == 1);

	input = "a+b+@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);

	input = "a+b+c@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[5]);
	assert(firstparam == &input[1]);
	assert(nrparams == 2);

	input = "~@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[1]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = " @example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[0]);
	assert(domain == NULL);

	input = "@";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == NULL);
	assert(domain == &input[1]);

	input = "\x7f@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[0]);
	assert(domain == NULL);

	input = "+a@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == 0);
	assert(localpart == &input[0]);
	assert(domain == &input[2]);
	assert(firstparam == NULL);
	assert(nrparams == 0);

	input = "+@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[1]);
	assert(domain == NULL);

	input = "a+@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[2]);
	assert(domain == NULL);

	input = "a++b@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[2]);
	assert(domain == NULL);

	input = "foo! bar~\177@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
	assert(localpart == &input[4]);
	assert(domain == NULL);
}

/* Test if a string can be converted to a DoNAI structure. */
void
test_a2donai_fromstr(void)
{
	struct a2donai *donai;

	/* test valid DoNAIs */
	donai = a2donai_fromstr("@example.com");
	assert(donai != NULL);
	assert(donai->localpart == NULL);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("user@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "user") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+subid@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "user+subid") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 1);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+flags+signature@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "user+flags+signature") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 2);
	a2donai_free(donai);

	donai = a2donai_fromstr("service+arg1+arg2@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "service+arg1+arg2") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 2);
	a2donai_free(donai);

	/* Adapted list from RFC 4282 */
	donai = a2donai_fromstr("joe@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "joe") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred@foo-9.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "fred") == 0);
	assert(strcmp(donai->domain, "foo-9.example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("jack@3rd.depts.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "jack") == 0);
	assert(strcmp(donai->domain, "3rd.depts.example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred.smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "fred.smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred_smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "fred_smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred$@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "fred$") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred=?#$&*+-/^smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "fred=?#$&*+-/^smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->nrparams == 1);
	a2donai_free(donai);

	donai = a2donai_fromstr("nancy@eng.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "nancy") == 0);
	assert(strcmp(donai->domain, "eng.example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng.example.net!nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "eng.example.net!nancy") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng%nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "eng%nancy") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("@privatecorp.example.net");
	assert(donai != NULL);
	assert(donai->localpart == NULL);
	assert(strcmp(donai->domain, "privatecorp.example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("\\(user\\)@example.net");
	assert(donai != NULL);
	assert(donai->localpart != NULL);
	assert(strcmp(donai->localpart, "\\(user\\)") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("<user>@example.net");
	assert(donai != NULL);
	assert(donai->localpart != NULL);
	assert(strcmp(donai->localpart, "<user>") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	donai = a2donai_fromstr("alice@xn--tmonesimerkki-bfbb.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->localpart, "alice") == 0);
	assert(strcmp(donai->domain, "xn--tmonesimerkki-bfbb.example.net") ==
	    0);
	assert(donai->nrparams == 0);
	a2donai_free(donai);

	/* test invalid DoNAIs */
	assert(a2donai_fromstr("") == NULL);
	assert(a2donai_fromstr("joe") == NULL);
	assert(a2donai_fromstr("fred@example.net@example.net") == NULL);
	assert(a2donai_fromstr("foo+@example.net") == NULL);
}

int
main(void)
{
	test_a2donai_parsestr();
	test_a2donai_fromstr();

	return 0;
}
