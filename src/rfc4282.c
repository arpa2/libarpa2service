/*
 * Copyright (c) 2018 Tim Kuijsten <info@netsend.nl>
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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * A RFC 4282 NAI compliant parser.
 *
 * FSM: doc/design/rfc4282_fsm.*
 */

/*
 * RFC 4282 NAI Formal Syntax in ABNF.
 *
 * nai         =  username
 * nai         =/ "@" realm
 * nai         =/ username "@" realm
 *
 * username    =  dot-string
 * dot-string  =  string
 * dot-string  =/ dot-string "." string
 * string      =  char
 * string      =/ string char
 * char        =  c
 * char        =/ "\" x
 *
 * c           =  %x21    ; '!'              allowed
 *                        ; '"'              not allowed
 * c           =/ %x23    ; '#'              allowed
 * c           =/ %x24    ; '$'              allowed
 * c           =/ %x25    ; '%'              allowed
 * c           =/ %x26    ; '&'              allowed
 * c           =/ %x27    ; '''              allowed
 *                        ; '(', ')'         not allowed
 * c           =/ %x2A    ; '*'              allowed
 * c           =/ %x2B    ; '+'              allowed
 *                        ; ','              not allowed
 * c           =/ %x2D    ; '-'              allowed
 *                        ; '.'              not allowed
 * c           =/ %x2F    ; '/'              allowed
 * c           =/ %x30-39 ; '0'-'9'          allowed
 *                        ; ';', ':', '<'    not allowed
 * c           =/ %x3D    ; '='              allowed
 *                        ; '>'              not allowed
 * c           =/ %x3F    ; '?'              allowed
 *                        ; '@'              not allowed
 * c           =/ %x41-5a ; 'A'-'Z'          allowed
 *                        ; '[', '\', ']'    not allowed
 * c           =/ %x5E    ; '^'              allowed
 * c           =/ %x5F    ; '_'              allowed
 * c           =/ %x60    ; '`'              allowed
 * c           =/ %x61-7A ; 'a'-'z'          allowed
 * c           =/ %x7B    ; '{'              allowed
 * c           =/ %x7C    ; '|'              allowed
 * c           =/ %x7D    ; '}'              allowed
 * c           =/ %x7E    ; '~'              allowed
 *                        ; DEL              not allowed
 * c           =/ %x80-FF ; UTF-8-Octet      allowed (not in RFC 2486)
 *                        ; Where UTF-8-octet is any octet in the
 *                        ; multi-octet UTF-8 representation of a
 *                        ; unicode codepoint above %x7F.
 *                        ; Note that c must also satisfy rules in
 *                        ; Section 2.4, including, for instance,
 *                        ; checking that no prohibited output is
 *                        ; used (see also Section 2.3 of
 *                        ; [RFC4013]).
 * x           =  %x00-FF ; all 128 ASCII characters, no exception;
 *                        ; as well as all UTF-8-octets as defined
 *                        ; above (this was not allowed in
 *                        ; RFC 2486).  Note that x must nevertheless
 *                        ; again satisfy the Section 2.4 rules.
 *
 * realm       =  1*( label "." ) label
 * label       =  let-dig *(ldh-str)
 * ldh-str     =  *( alpha / digit / "-" ) let-dig
 * let-dig     =  alpha / digit
 * alpha       =  %x41-5A  ; 'A'-'Z'
 * alpha       =/ %x61-7A  ; 'a'-'z'
 * digit       =  %x30-39  ; '0'-'9'
 */

static const char alphadig[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-9 */
	0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* A-Z */
	0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1 /* a-z */
	/* let rest of static arr initialize to 0 */
};

static const char userchar[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, /* ! */
	0,
	1, /* # */
	1, /* $ */
	1, /* % */
	1, /* & */
	1, /* ' */
	0, 0,
	1, /* * */
	1, /* + */
	0,
	1, /* - */
	0,
	1, /* / */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-9 */
	0, 0, 0,
	1, /* = */
	0,
	1, /* ? */
	0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* A-Z */
	0, 0, 0,
	1, /* ^ */
	1, /* _ */
	1, /* ` */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, /* a-z */
	1, /* { */
	1, /* | */
	1, /* } */
	1, /* ~ */
	0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 /* %x80-FF */
};

/*
 * Static NAI parser.
 *
 * Return 0 on success or -1 on failure.
 *
 * On success "username" and/or "realm" point to the corresponding start in
 * "input".
 *
 * Note that either "username" or "realm" may point to NULL in case one of them
 * is not present in "input" (which is allowed by the standard).
 *
 * On error "username" and/or "realm" point to NULL or to the first erroneous
 * character in the input, depending on where the error occurred.
 */
int
rfc4282_parsestr(const char *input, const char **username, const char **realm)
{
	enum states { S, USERNAME, USERESC, REALM1, LABEL1, REALM2, LABEL2 }
	    state;
	const char *cp;

	*username = NULL;
	*realm = NULL;

	if (input == NULL)
		return -1;

	for (state = S, cp = input; *cp != '\0'; cp++) {
		switch (state) {
		case S:
			if (userchar[(int)*cp]) {
				*username = cp;
				state = USERNAME;
			} else if (*cp == '\\') {
				state = USERESC;
			} else if (*cp == '@') {
				*realm = cp + 1;
				state = REALM1;
			} else
				goto done;
			break;
		case USERNAME:
			/* fast-forward USERNAME characters */
			while (userchar[(int)*cp] || *cp == '.')
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '\\') {
				state = USERESC;
			} else if (*cp == '@') {
				*realm = cp + 1;
				state = REALM1;
			} else
				goto done;
			break;
		case USERESC:
			/* \x00-\xFF allowed */
			state = USERNAME;
			break;
		case REALM1:
			if (alphadig[(int)*cp]) {
				state = LABEL1;
			} else
				goto done;
			break;
		case LABEL1:
			/* fast-forward LABEL1 characters */
			while (alphadig[(int)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '-') {
				state = REALM1;
			} else if (*cp == '.') {
				state = REALM2;
			} else
				goto done;
			break;
		case REALM2:
			if (alphadig[(int)*cp]) {
				state = LABEL2;
			} else
				goto done;
			break;
		case LABEL2:
			/* fast-forward LABEL2 characters */
			while (alphadig[(int)*cp])
				cp++;
			/*
			 * After while: prevent dangerous subsequent cp++ in
			 * for-loop, never let cp point beyond the input.
			 */
			if (*cp == '\0')
				goto done;

			if (*cp == '-') {
				state = REALM2;
			} else if (*cp == '.') {
				state = REALM2;
			} else
				goto done;
			break;
		default:
			abort();
		}
	}

done:
	/*
	 * Make sure the end of the input is reached and the state is one of the
	 * final states.
	 */
	if (*cp != '\0' || (state != USERNAME && state != LABEL2)) {

		/*
		 * Let "username" and/or "realm" point to first erroneous character in
		 * "input".
		 */

		*username = NULL;
		*realm = NULL;

		switch (state) {
		case S:
			*username = cp;
			*realm = cp;
			break;
		case USERNAME:
			 /* FALLTHROUGH */
		case USERESC:
			*username = cp;
			break;
		case REALM1:
			 /* FALLTHROUGH */
		case LABEL1:
			 /* FALLTHROUGH */
		case LABEL2:
			 /* FALLTHROUGH */
		case REALM2:
			*realm = cp;
			break;
		default:
			abort();
		}

		return -1;
	}

	return 0;
}

void
printcharmap(const char *input, int len)
{
	for (int i = 0; i < len; i++)
		if (input[i] == 1)
			printf("YES %d %c\n", i, i);
		else
			printf("NO %d\n", i);
}
