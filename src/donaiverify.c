#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/a2donai.h"

static const char *progname;
static int verbose;

void printusage(FILE *);

/*
 * Match a DoNAI with a selector. Return 0 if donai matches the selector, 1
 * if not.
 */

int
main(int argc, char *argv[])
{
	struct a2donai *donai, *selector;
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

	if ((selector = a2donai_fromstr(argv[0])) == NULL) {
		fprintf(stderr, "illegal selector: %s\n", argv[0]);
		exit(1);
	}

	if ((donai = a2donai_fromstr(argv[1])) == NULL) {
		fprintf(stderr, "illegal donai: %s\n", argv[1]);
		exit(1);
	}

	if (a2donai_match(selector, donai) == 0) {
		if (verbose > -1)
			printf("MISMATCH\n");

		exit(1);
	}

	if (verbose > -1)
		printf("MATCH\n");

	return 0;
}

void
printusage(FILE *stream)
{
	fprintf(stream, "usage: %s [-hqv] selector donai\n", progname);
}
