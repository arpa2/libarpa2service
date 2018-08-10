#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../src/a2donai.h"

/* Test if a string can be converted to a DoNAI structure. */
void
test_a2donai_fromstr(void)
{
	struct a2donai *donai;

	/* test valid DoNAIs */
	donai = a2donai_fromstr("example.com");
	assert(donai != NULL);
	assert(donai->username == NULL);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_DOMAIN);
	a2donai_free(donai);

	donai = a2donai_fromstr("user@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+subid@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+subid") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+flags+@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+flags+") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("user+flags+signature@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "user+flags+signature") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("+service@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "+service") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("+service+arg1+arg2@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "+service+arg1+arg2") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	/* Adapted list from RFC 4282 */
	donai = a2donai_fromstr("joe@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "joe") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred@foo-9.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred") == 0);
	assert(strcmp(donai->realm, "foo-9.example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("jack@3rd.depts.example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "jack") == 0);
	assert(strcmp(donai->realm, "3rd.depts.example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred.smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred.smith") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred_smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred_smith") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred$@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred$") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("fred=?#$&*+-/^smith@example.com");
	assert(donai != NULL);
	assert(strcmp(donai->username, "fred=?#$&*+-/^smith") == 0);
	assert(strcmp(donai->realm, "example.com") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("nancy@eng.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "nancy") == 0);
	assert(strcmp(donai->realm, "eng.example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng.example.net!nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "eng.example.net!nancy") == 0);
	assert(strcmp(donai->realm, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("eng%nancy@example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "eng%nancy") == 0);
	assert(strcmp(donai->realm, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("@privatecorp.example.net");
	assert(donai != NULL);
	assert(donai->username == NULL);
	assert(strcmp(donai->realm, "privatecorp.example.net") == 0);
	assert(donai->type == DT_DOMAIN);
	a2donai_free(donai);

	donai = a2donai_fromstr("\\(user\\)@example.net");
	assert(donai != NULL);
	assert(donai->username != NULL);
	assert(strcmp(donai->username, "\\(user\\)") == 0);
	assert(strcmp(donai->realm, "example.net") == 0);
	assert(donai->type == DT_NAI);
	a2donai_free(donai);

	donai = a2donai_fromstr("alice@xn--tmonesimerkki-bfbb.example.net");
	assert(donai != NULL);
	assert(strcmp(donai->username, "alice") == 0);
	assert(strcmp(donai->realm, "xn--tmonesimerkki-bfbb.example.net") == 0);
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

/* Test if type is set correctly. */
void
test_a2donai_dettype(void)
{
	struct a2donai donai;
	enum A2DONAI_TYPE dt;

	donai.username = "joe";
	donai.realm = "example.com";
	assert(a2donai_dettype(&donai, &dt) == 0);
	assert(dt == DT_NAI);

	donai.username = NULL;
	donai.realm = "example.com";
	assert(a2donai_dettype(&donai, &dt) == 0);
	assert(dt == DT_DOMAIN);

	donai.username = NULL;
	donai.realm = NULL;
	assert(a2donai_dettype(&donai, &dt) == 0);
	assert(dt == DT_INVALID);
}

int
main(void)
{
	test_a2donai_fromstr();
	test_a2donai_dettype();

	return 0;
}
