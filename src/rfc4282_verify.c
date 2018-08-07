#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/rfc4282.h"

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

	while ((c = getopt(argc, argv, "hv")) != -1) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'h':
			fprintf(stdout, "usage: %s [-hv] nai\n", progname);
			exit(0);
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

	if (rfc4282_parsestr(input, &username, &realm) == -1) {
		if (verbose > 0) {
			err = NULL;
			if (username != NULL) {
				err = username;
			} else if (realm != NULL) {
				err = realm;
			}

			if (err) {
				if (*err == '\0') {
					printf("unexpected end of %s: %s\n",
					    username ? "username" : (realm ?
					    "realm" : "input"), input);
				} else {
					printf("invalid character %ld \"%c\": "
					    "%s\n", (err - input) + 1, *err,
					    input);
				}
			} else {
				printf("invalid: %s\n", input);
			}
		}

		exit(1);
	}

	if (verbose > 0)
		printf("valid: %s\n", input);

	return 0;
}
