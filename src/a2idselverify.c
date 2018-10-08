/*
 * Copyright (c) 2018 Tim Kuijsten
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/a2id.h"

static const char *progname;
static int verbose;

void printusage(FILE *);

/*
 * Verify if a given input is a valid ARPA2 ID Selector by feeding it to the
 * parser. Reads one input per line and outputs one line starting with either
 * OK or FAIL depending on whether the input was a valid A2ID Selector.
 */

int
main(int argc, char *argv[])
{
	char input[1024];
	const char *localpart, *domain, *firstopt, *err;
	int c;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	while ((c = getopt(argc, argv, "hqv")) != -1) {
		switch (c) {
		case 'h':
			printusage(stdout);
			exit(0);
		case 'q':
			verbose--;
			break;
		case 'v':
			verbose++;
			break;
		default:
			printusage(stderr);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		printusage(stderr);
		exit(1);
	}

	while (fgets(input, sizeof(input), stdin) != NULL) {
		/* replace potential \n */
		input[strcspn(input, "\n")] = '\0';

		if (a2id_parseselstr(input, &localpart, &domain, &firstopt, NULL) == 0) {
			printf("OK\n");
			continue;
		}

		printf("FAIL");

		err = NULL;
		if (localpart != NULL) {
			err = localpart;
		} else if (domain != NULL) {
			err = domain;
		}

		if (err && verbose > 0) {
			if (*err == '\0') {
				printf(" unexpected end of %s",
				    localpart ? "localpart" : (domain ? "domain" :
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

void
printusage(FILE *stream)
{
	fprintf(stream, "usage: %s [-hqv]\n", progname);
}
