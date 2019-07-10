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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "a2id.h"

static const char *progname;
static int verbose;

void printusage(FILE *);

/*
 * Match an ARPA2 ID with a selector. Return 0 if ID matches the selector, 1
 * if not.
 */

int
main(int argc, char *argv[])
{
	a2id id, selector;
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

	if (argc != 2) {
		printusage(stderr);
		exit(1);
	}

	if (a2id_parsestr(&id, argv[0], 0) == -1) {
		fprintf(stderr, "illegal a2id: %s\n", argv[0]);
		exit(1);
	}

	if (a2id_parsestr(&selector, argv[1], 1) == -1) {
		fprintf(stderr, "illegal selector: %s\n", argv[1]);
		exit(1);
	}

	if (a2id_match(&id, &selector) == 0) {
		if (verbose > -1)
			printf("MISMATCH\n");

		exit(2);
	}

	if (verbose > -1)
		printf("MATCH\n");

	return 0;
}

void
printusage(FILE *stream)
{
	fprintf(stream, "usage: %s [-hqv] a2id selector\n", progname);
}
