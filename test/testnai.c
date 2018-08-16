#include <assert.h>

#include "../src/nai.h"

void
test_nai_parsestr(void)
{
	const char *input, *username, *realm;

	/* Run some tests. */

	input = "foo! bar~\177";
	assert(nai_parsestr(input, &username, &realm) == -1);
	assert(&username[0] == &input[4]);
	assert(realm == NULL);

	input = "foo!bar~\177";
	assert(nai_parsestr(input, &username, &realm) == -1);
	assert(&username[0] == &input[8]);
	assert(realm == NULL);

	input = "foo!bar@\177";
	assert(nai_parsestr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[8]);

	input = "foo!bar@com";
	assert(nai_parsestr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[11]);

	/* try a two-byte utf8 character in the realm */
	input = "a@כ.com";
	assert(nai_parsestr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[2]);

	/* try a two-byte utf8 character in the username */
	input = "כ@example.com";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[2]);

	input = "foo@example.com";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[3]);

	input = "\\(user\\)@example.net";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[8]);

	input = "alice@xn--tmonesimerkki-bfbb.example.net";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[5]);
}

void
test_nai_parseselstr(void)
{
	const char *input, *username, *realm;

	/* Run some tests. */

	input = "foo! bar~\177";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == &input[4]);
	assert(realm == NULL);

	input = "foo!bar~\177";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == &input[8]);
	assert(realm == NULL);

	input = "foo!bar@\177";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[8]);

	input = "@a..b";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[3]);

	input = "";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[0]);

	input = "@";
	assert(nai_parseselstr(input, &username, &realm) == -1);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[1]);

	input = "foo!bar@com";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[7]);

	input = "@.";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[0]);

	input = "@.org";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[0]);

	input = "@.org.";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[0]);

	input = "@com";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == NULL);
	assert(&realm[0] == &input[0]);

	input = "foo@example.com";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[3]);

	input = "\\(user\\)@example.net";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[8]);

	input = "alice@xn--tmonesimerkki-bfbb.example.net";
	assert(nai_parseselstr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[5]);
}

int
main(void)
{
	test_nai_parsestr();
	test_nai_parseselstr();

	return 0;
}
