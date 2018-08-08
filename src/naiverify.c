#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/nai.h"

static int verbose;

/*
 * Parse give input and exit success if it's a valid NAI, error otherwise.
 */

int
main(int argc, char *argv[])
{
	const char *progname, *username, *realm, *input, *err;
	int c;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	while ((c = getopt(argc, argv, "hqv")) != -1) {
		switch (c) {
		case 'h':
			fprintf(stdout, "usage: %s [-hv] nai\n", progname);
			exit(0);
		case 'q':
			verbose--;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "usage: %s [-hv] nai\n", progname);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		fprintf(stderr, "usage: %s [-hv] nai\n", progname);
		exit(1);
	}

	input = argv[0];

	if (nai_parsestr(input, &username, &realm) == -1) {
		if (verbose > -1)
			printf("FAIL");

		err = NULL;
		if (username != NULL) {
			err = username;
		} else if (realm != NULL) {
			err = realm;
		}

		if (err && verbose > 0) {
			if (*err == '\0') {
				printf(" unexpected end of %s",
				    username ? "username" : (realm ? "realm" :
				    "input"));
			} else {
				printf(" \"%c\" is an invalid character at "
				    "position %ld in \"%s\"", *err,
				    (err - input) + 1,
				    input);
			}
		}

		if (verbose > -1)
			printf("\n");

		exit(1);
	}

	if (verbose > -1)
		printf("OK\n");

	return 0;
}
