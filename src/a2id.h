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

/*
 * Public API of the ARPA2 Identifier and ARPA2 Identifier Selector library.
 *
 * Input from a string and output to a string is utilized with a2id_fromstr(3)
 * and a2id_tostr(3).
 *
 * Once a string is successfully converted into an A2ID using a2id_fromstr,
 * the other utility functions that take an "a2id" can be used.
 */

#ifndef A2ID_H
#define A2ID_H

#include <stddef.h>
#include <stdint.h>

/*
 * The maximum length of an A2ID is 512 bytes, excluding a terminating nul byte.
 */
#define A2ID_MAXLEN 512

enum A2ID_TYPE { A2IDT_DOMAINONLY, A2IDT_GENERIC, A2IDT_SERVICE };

/* opaque id container */
typedef struct {
	uint8_t a2id[((A2ID_MAXLEN) + 128)];
} a2id;

/* import from, and export to a nul terminated string */
int a2id_fromstr(a2id *a2id, const char *in, int isselector);
size_t a2id_tostr(char *dst, size_t dstsz, const a2id *a2id);

int a2id_hassignature(const a2id *a2id);
size_t a2id_coreform(char *dst, size_t dstsize, const a2id *a2id);
int a2id_generalize(a2id *a2id);
int a2id_match(const a2id *subject, const a2id *selector);
void a2id_dprint(int d, const a2id *a2id);

#endif /* A2ID_H */
