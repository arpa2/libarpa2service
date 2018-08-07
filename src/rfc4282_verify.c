#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/rfc4282.h"

/*
 * Parse give input and exit success if it's a valid NAI, error otherwise.
 */

int
main(int argc, char *argv[])
{
	const char *progname, *username, *realm;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	if (argc != 2) {
		fprintf(stderr, "usage: %s nai\n", progname);
		exit(1);
	}

	if (rfc4282_parsestr(argv[1], &username, &realm) == -1) {
		if (username != NULL) {
			fprintf(stderr, "invalid character in username %ld\n",
			    username - argv[1]);
		} else if (realm != NULL) {
			fprintf(stderr, "invalid character in realm %ld\n",
			    realm - argv[1]);
		} else {
			fprintf(stderr, "invalid input %s\n", argv[1]);
		}

		exit(1);
	}

	return 0;
}
