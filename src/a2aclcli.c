/*
 * Copyright (c) 2018, 2019 Tim Kuijsten
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

#include "a2acl.h"

static const char *progname;
static int verbose;

void printusage(FILE *);
int whichlist(const char *, const char *);

/*
 * Test if a communication pair may communicate with each other under a given
 * ACL policy.
 *
 * Reads a policy from a text file and a communication pair from the
 * command-line. Returns one of the following exit codes:
 *   0 - Whitelist
 *   1 - Greylist
 *   2 - Blacklist
 *   3 - Abandoned
 *   4 - Some error occurred
 *
 * If not silenced using "-q" one of the following letters is output on stdout:
 *   W - Whitelist
 *   G - Greylist
 *   B - Blacklist
 *   A - Abandoned
 *
 * Note that if a policy is not defined, it defaults to Greylist.
 */

int
main(int argc, char *argv[])
{
	char errstr[100];
	size_t t, u;
	int r, list;

	if ((progname = basename(argv[0])) == NULL) {
		perror("basename");
		exit(1);
	}

	while ((r = getopt(argc, argv, "hqv")) != -1) {
		switch (r) {
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

	if (argc != 3) {
		printusage(stderr);
		exit(1);
	}

	if (a2acl_fromfile(argv[0], &t, &u, errstr, sizeof(errstr)) == -1) {
		fprintf(stderr, "%s: %s, %s\n", argv[0], strerror(errno), errstr);
		exit(4);
	}

	if (t == 0) {
		fprintf(stderr, "%s: empty ruleset\n", argv[0]);
		exit(4);
	}

	if (verbose > 0)
		fprintf(stdout, "total number of ACL rules: %zu, newly imported %zu\n", t, u);

	list = whichlist(argv[1], argv[2]);
	a2acl_dbclose();

	if (verbose > -1)
		fprintf(stdout, "%c\n", list);

	switch (list) {
	case 'W': return 0;
	case 'G': return 1;
	case 'B': return 2;
	case 'A': return 3;
	}

	return 4;
}

/*
 * Return 'W', 'G', 'B' or 'A' on success, -1 on error.
 */
int
whichlist(const char *remotestr, const char *localstr)
{
	struct a2id remoteid, localid;
	int list;

	if (a2id_parsestr(&remoteid, remotestr, 0) == -1) {
		fprintf(stderr, "illegal remoteid: %s\n", remotestr);
		exit(4);
	}

	if (a2id_parsestr(&localid, localstr, 0) == -1) {
		fprintf(stderr, "illegal localid: %s\n", localstr);
		exit(4);
	}

	if (a2acl_whichlist((char *)&list, &remoteid, &localid) == -1) {
		fprintf(stderr, "internal error\n");
		exit(4);
	}

	return list;
}

void
printusage(FILE *stream)
{
	fprintf(stream, "usage: %s [-qv] policyfile remoteid localid\n", progname);
}
