#include <assert.h>

#include "../src/nai.h"

int
main(void)
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

	input = "foo@example.com";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[4]);

	input = "\\(user\\)@example.net";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[9]);

	input = "alice@xn--tmonesimerkki-bfbb.example.net";
	assert(nai_parsestr(input, &username, &realm) == 0);
	assert(&username[0] == &input[0]);
	assert(&realm[0] == &input[6]);

	return 0;
}
