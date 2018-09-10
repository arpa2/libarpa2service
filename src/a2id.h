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

#ifndef A2ID_H
#define A2ID_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Impose a practial upper bound to the lenght of an ARPA2 ID. */
#define A2ID_MAXLEN 512

enum A2ID_TYPE { A2IDT_INVALID, A2IDT_DOMAINONLY, A2IDT_GENERIC, A2IDT_SERVICE };

struct a2id {
	char *localpart;
	char *domain;
	enum A2ID_TYPE type;
};

struct a2id *a2id_alloc(const char *, const char *);
void a2id_free(struct a2id *);
struct a2id *a2id_fromstr(const char *);
struct a2id *a2id_fromselstr(const char *);
int a2id_parsestr(const char *, const char **, const char **, const char **,
    int *);
int a2id_parseselstr(const char *, const char **, const char **);
int a2id_match(const struct a2id *, const struct a2id *);

#endif /* A2ID_H */
