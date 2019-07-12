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

#ifndef A2ID_H
#define A2ID_H

#include <stddef.h>
#include <stdint.h>

/*
 * Practial upper bound to the lenght of an ARPA2 ID (not including an optional
 * terminating null.
 */
#define A2ID_MAXLEN 512

enum A2ID_TYPE { A2IDT_DOMAINONLY, A2IDT_GENERIC, A2IDT_SERVICE };

typedef struct {
	uint8_t a2id[((A2ID_MAXLEN) + 128)];
} a2id;

int a2id_hassignature(const a2id *a2id);
int a2id_fromstr(a2id *a2id, const char *in, int isselector);
size_t a2id_tostr(char *dst, size_t dstsz, const a2id *a2id);

int a2id_coreform(char *dst, const a2id *a2id, size_t *dstsize);
int a2id_generalize(a2id *a2id);
int a2id_match(const a2id *subject, const a2id *selector);
void a2id_print(FILE *fp, const a2id *a2id);
size_t a2id_optsegments(const char **optseg, const a2id *a2id);

#endif /* A2ID_H */
