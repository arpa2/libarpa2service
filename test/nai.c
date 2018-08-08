#include <assert.h>
#include <err.h>

#include "../src/nai.h"

int
main(void)
{
	const char *input, *username, *realm;

	/* Run some tests. */

	input = "foo! bar~\177";
	if (nai_parsestr(input, &username, &realm) == -1 &&
	    &username[0] == &input[4] &&
	    realm == NULL)
		warnx("SUCCESS %s", input);
	else
		warnx("FAIL %s", input);

	input = "foo!bar~\177";
	if (nai_parsestr(input, &username, &realm) == -1 &&
	    &username[0] == &input[8] &&
	    realm == NULL)
		warnx("SUCCESS %s", input);
	else
		warnx("FAIL %s", input);

	input = "foo!bar@\177";
	if (nai_parsestr(input, &username, &realm) == -1 &&
	    &username[0] == &input[0] &&
	    &realm[0] == &input[8])
		warnx("SUCCESS %s", input);
	else
		warnx("FAIL %s", input);

	input = "foo!bar@com";
	if (nai_parsestr(input, &username, &realm) == -1 &&
	    &username[0] == &input[0] &&
	    &realm[0] == &input[11])
		warnx("SUCCESS %s", input);
	else
		warnx("FAIL %s", input);

	input = "foo@example.com";
	if (nai_parsestr(input, &username, &realm) == 0 &&
	    &username[0] == &input[0] &&
	    &realm[0] == &input[4])
		warnx("SUCCESS %s", input);
	else
		warnx("FAIL %s", input);

	return 0;
}
