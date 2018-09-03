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

	input = "@";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);

	input = "\x7f@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);

	input = "+a@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);

	input = "+@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);

	input = "a+@example.com";
	r = a2donai_parsestr(input, &localpart, &domain, &firstparam, &nrparams);
	assert(r == -1);
}

void
test_a2donai_parseuserstr(void)
{
	const char *input, *service, *user, *useralias, *userflags, *usersig;

	/* Run some tests. */

	input = "foo! bar~\177";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "fo++bar";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "fo..bar";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "fo.+bar";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "foo+";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "foo+bar+baz+";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	/* RFC 7542 doesn't allow escaping like RFC 4282. */
	input = "\\(user\\)";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == -1);

	input = "foo";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(user == &input[0]);
	assert(useralias == NULL);
	assert(userflags == NULL);
	assert(usersig == NULL);

	input = "foo+alias";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(user == &input[0]);
	assert(useralias == &input[3]);
	assert(userflags == NULL);
	assert(usersig == NULL);

	input = "foo+rwx+";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(user == &input[0]);
	assert(useralias == NULL);
	assert(userflags == &input[3]);
	assert(usersig == NULL);

	input = "foo+rwx+sig";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(user == &input[0]);
	assert(useralias == NULL);
	assert(userflags == &input[3]);
	assert(usersig == &input[7]);

	input = "fo.o+rw.x+si.g";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(user == &input[0]);
	assert(useralias == NULL);
	assert(userflags == &input[4]);
	assert(usersig == &input[9]);

	/* try a single two-byte utf8 character */
	input = "כ";
	assert(a2donai_parseuserstr(input, &service, &user, &useralias,
	    &userflags, &usersig) == 0);
	assert(service == NULL);
	assert(&user[0] == &input[0]);
	assert(useralias == NULL);
	assert(userflags == NULL);
	assert(usersig == NULL);
}

/* Test if a string can be converted to a DoNAI structure. */
void
test_a2donai_fromstr(void)
{
	struct a2donai *donai;

	/* test valid DoNAIs */
	donai = a2donai_fromstr("example.com");
	assert(donai != NULL);
	assert(donai->username == NULL);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_DOMAIN);
	a2donai_free(donai);

	donai = a2donai_fromstr("user@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+subid@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+subid") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+flags+@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+flags+") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+flags+signature@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+flags+signature") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("+service@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "+service") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("+service+arg1+arg2@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "+service+arg1+arg2") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	/* Adapted list from RFC 4282 */
	donai = a2donai_fromstr("joe@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "joe") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred@foo-9.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred") == 0);
	assert(strcmp(donai->domain, "foo-9.example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("jack@3rd.depts.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "jack") == 0);
	assert(strcmp(donai->domain, "3rd.depts.example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred.smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred.smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred_smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred_smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred$@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred$") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred=?#$&*+-/^smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred=?#$&*+-/^smith") == 0);
	assert(strcmp(donai->domain, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("nancy@eng.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "nancy") == 0);
	assert(strcmp(donai->domain, "eng.example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng.example.net!nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "eng.example.net!nancy") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng%nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "eng%nancy") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("@privatecorp.example.net");
	assert(donai != NULL);
	assert(donai->username == NULL);
	assert(strcmp(donai->domain, "privatecorp.example.net") == 0);
	assert(donai->type == DT_DOMAIN);
	a2donai_free(donai);

	/* XXX mailed author about contradicting words in RFC 7542 according
	 * escaping with "\".
	donai = a2donai_fromstr("\\(user\\)@example.net");
	assert(donai != NULL);
	assert(donai->username != NULL);
	assert(strcmp(donai->username, "\\(user\\)") == 0);
	assert(strcmp(donai->domain, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);
	 */

	donai = a2donai_fromstr("alice@xn--tmonesimerkki-bfbb.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "alice") == 0);
	assert(strcmp(donai->domain, "xn--tmonesimerkki-bfbb.example.net") ==
	    0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	/* test invalid DoNAIs */
	assert(a2donai_fromstr("") == NULL);
	assert(a2donai_fromstr("joe") == NULL);
	assert(a2donai_fromstr("fred@example_9.com") == NULL);
	assert(a2donai_fromstr("fred@example.net@example.net") == NULL);
	assert(a2donai_fromstr("fred.@example.net") == NULL);
	assert(a2donai_fromstr("eng:nancy@example.net") == NULL);
	assert(a2donai_fromstr("eng;nancy@example.net") == NULL);
	assert(a2donai_fromstr("(user)@example.net") == NULL);
	assert(a2donai_fromstr("<nancy>@example.net") == NULL);
}

int
main(void)
{
	test_a2donai_parsestr();
	test_a2donai_parseuserstr();
	test_a2donai_fromstr();

	return 0;
}
