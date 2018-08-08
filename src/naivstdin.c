#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/nai.h"

static int verbose;

/*
 * Verify if a given input is a valid NAI by feeding it to the parser. Reads one
 * input per line and outputs one line starting with either OK or FAIL depending
 * on whether the input was a valid NAI.
 */

int
main(int argc, char *argv[])
{
	char input[1024];
	const char *progname, *username, *realm, *err;
	int c;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	while ((c = getopt(argc, argv, "hqv")) != -1) {
		switch (c) {
		case 'h':
			fprintf(stdout, "usage: %s [-hv]\n", progname);
			exit(0);
		case 'q':
			verbose--;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "usage: %s [-hv]\n", progname);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		fprintf(stderr, "usage: %s [-hv]\n", progname);
		exit(1);
	}

	while (fgets(input, sizeof(input), stdin) != NULL) {
		/* replace potential \n */
		input[strcspn(input, "\n")] = '\0';

		if (nai_parsestr(input, &username, &realm) == 0) {
			printf("OK\n");
			continue;
		}

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

		printf("\n");
	}

	if (ferror(stdin) != 0) {
		fprintf(stderr, "fgets");
		exit(1);
	}

	return 0;
}
