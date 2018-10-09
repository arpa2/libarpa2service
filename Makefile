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

INSTALL_BIN 	= install -m 0555
INSTALL_LIB	= install -m 0444
INSTALL_MAN	= install -m 0444

PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
LIBDIR	= $(PREFIX)/lib
MANDIR	= $(PREFIX)/man
INCDIR	= $(PREFIX)/include

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
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)$(INCDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	$(INSTALL_LIB) liba2id.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_LIB) src/a2id.h $(DESTDIR)$(INCDIR)
	$(INSTALL_BIN) a2idmatch $(DESTDIR)$(BINDIR)
	$(INSTALL_MAN) man/a2idmatch.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL_MAN) man/a2id_alloc.3 man/a2id_fromstr.3 man/a2id_match.3 \
		man/a2id_parsestr.3 $(DESTDIR)$(MANDIR)/man3

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/liba2id.a
	rm -f $(DESTDIR)$(INCDIR)/src/a2id.h
	rm -f $(DESTDIR)$(BINDIR)/a2idmatch
	rm -f $(DESTDIR)$(MANDIR)/man1/a2idmatch.1
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_alloc.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_fromstr.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_match.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_parsestr.3

manhtml:
	mkdir -p build
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

a2idselverify: a2id.o src/a2idselverify.c
	cc -Wall a2id.o src/a2idselverify.c -o $@

# create instrumented binary for use by afl-fuzz
a2idselverifyafl: src/a2id.c src/a2idselverify.c
	afl-clang -Wall src/a2id.c src/a2idselverify.c -o $@

clean:
	rm -f a2idmatch a2id.o testa2id liba2id.a a2idverify a2idverifyafl
