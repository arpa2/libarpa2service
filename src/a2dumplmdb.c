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
#include <unistd.h>

#include "a2acl.h"
#include "a2acl_dblmdb.h"

static const char *progname;
static int verbose;

void printusage(FILE *);

int
main(int argc, char *argv[])
{
	int c, i;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	while ((c = getopt(argc, argv, "bhqv")) != -1) {
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

	if (argc < 1) {
		printusage(stderr);
		exit(1);
	}

	for (i = 0; i < argc; i++) {
		if (argc > 1) {
			if (i > 0)
				fprintf(stdout, "\n");
			fprintf(stdout, "%s\n", argv[i]);
		}

		if (a2acl_dbopen(argv[i]) == -1) {
			fprintf(stderr, "%s: %s\n", argv[i], strerror(errno));
			exit(4);
		}

		printdb(stdout);
		a2acl_dbclose();
	}

	return 0;
}

void
printusage(FILE *fp)
{
	fprintf(fp, "usage: %s [-qv] <file>\n", progname);
}
