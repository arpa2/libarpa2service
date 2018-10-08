# Copyright (c) 2018 Tim Kuijsten
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

a2idmatch: a2id.o src/a2idmatch.c
	cc -Wall a2id.o src/a2idmatch.c -o $@

a2id.o: src/a2id.c src/a2id.h
	cc -Wall src/a2id.c -c

liba2id.a: a2id.o
	ar -q liba2id.a a2id.o

testa2id: src/a2id.c test/testa2id.c
	cc -Wall -g src/a2id.c test/testa2id.c -o $@

test:	testa2id a2idmatch
	./testa2id
	./test/testa2idmatch

install: liba2id.a a2idmatch
	cp liba2id.a /usr/local/lib/
	cp src/a2id.h /usr/local/include/
	cp a2idmatch /usr/local/bin/
	test -e /usr/local/share/man/man3 || mkdir -p /usr/local/share/man/man3
	cp doc/man/*.3 /usr/local/share/man/man3/
	test -e /usr/local/share/man/man1 || mkdir -p /usr/local/share/man/man1
	cp doc/man/*.1 /usr/local/share/man/man1/

manhtml:
	mandoc -T html -Ostyle=man.css man/a2idmatch.1 > \
	build/a2idmatch.1.html
	mandoc -T html -Ostyle=man.css man/a2id_alloc.3 > \
	build/a2id_alloc.3.html
	mandoc -T html -Ostyle=man.css man/a2id_fromstr.3 > \
	build/a2id_fromstr.3.html
	mandoc -T html -Ostyle=man.css man/a2id_match.3 > \
	build/a2id_match.3.html
	mandoc -T html -Ostyle=man.css man/a2id_parsestr.3 > \
	build/a2id_parsestr.3.html

fsmpngsvg:
	dot -Tpng doc/design/a2idfsm.gv -o doc/design/a2idfsm.png
	dot -Tsvg doc/design/a2idfsm.gv -o doc/design/a2idfsm.svg
	dot -Tpng doc/design/a2idselfsm.gv -o doc/design/a2idselfsm.png
	dot -Tsvg doc/design/a2idselfsm.gv -o doc/design/a2idselfsm.svg

a2idverify: a2id.o src/a2idverify.c
	cc -Wall a2id.o src/a2idverify.c -o $@

# create instrumented binary for use by afl-fuzz
a2idverifyafl: src/a2id.c src/a2idverify.c
	afl-clang -Wall src/a2id.c src/a2idverify.c -o $@

clean:
	rm -f a2idmatch a2id.o testa2id liba2id.a a2idverify a2idverifyafl
