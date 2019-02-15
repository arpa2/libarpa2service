CFLAGS = -O0 -g -W -Wall -Wextra -Wpedantic

INSTALL_BIN 	= install -m 0555
INSTALL_LIB	= install -m 0444
INSTALL_MAN	= install -m 0444

PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
LIBDIR	= $(PREFIX)/lib
MANDIR	= $(PREFIX)/man
INCDIR	= $(PREFIX)/include

all:	a2idmatch a2acl

a2idmatch: a2id.o src/a2idmatch.c
	cc -Wall a2id.o src/a2idmatch.c -o $@

a2id.o: src/a2id.c src/a2id.h
	${CC} ${CFLAGS} -c src/a2id.c

a2acl.o: src/a2acl.c src/a2acl.h
	${CC} ${CFLAGS} -c src/a2acl.c

liba2id.a: a2id.o
	ar -q liba2id.a a2id.o

testa2id: a2id.o test/testa2id.c
	${CC} ${CFLAGS} a2id.o test/testa2id.c -o $@

testa2acl: a2acl.o a2id.o test/testa2acl.c
	${CC} ${CFLAGS} a2id.o a2acl.o test/testa2acl.c -o $@

runtest: a2idmatch testa2id testa2acl
	./testa2id
	./test/testa2idmatch
	./testa2acl

install: liba2id.a a2idmatch
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)$(INCDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	$(INSTALL_LIB) liba2id.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_LIB) src/a2id.h $(DESTDIR)$(INCDIR)
	$(INSTALL_BIN) a2acl a2idmatch $(DESTDIR)$(BINDIR)
	$(INSTALL_MAN) man/a2acl.3 man/a2id.3 man/a2id_match.3 \
		man/a2id_parsestr.3 $(DESTDIR)$(MANDIR)/man3
	$(INSTALL_MAN) man/a2acl.1 man/a2idmatch.1 $(DESTDIR)$(MANDIR)/man1

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/liba2id.a
	rm -f $(DESTDIR)$(INCDIR)/src/a2id.h
	rm -f $(DESTDIR)$(BINDIR)/a2idmatch
	rm -f $(DESTDIR)$(MANDIR)/man3/a2acl.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_match.3
	rm -f $(DESTDIR)$(MANDIR)/man3/a2id_parsestr.3
	rm -f $(DESTDIR)$(MANDIR)/man1/a2acl.1
	rm -f $(DESTDIR)$(MANDIR)/man1/a2idmatch.1

manhtml:
	mkdir -p build
	cd doc/man && mandoc -T html -Ostyle=man.css a2acl.3 > \
		../../a2acl.3.html
	cd doc/man && mandoc -T html -Ostyle=man.css a2id.3 > \
		../../a2id.3.html
	cd doc/man && mandoc -T html -Ostyle=man.css a2id_match.3 > \
		../../a2id_match.3.html
	cd doc/man && mandoc -T html -Ostyle=man.css a2id_parsestr.3 > \
		../../a2id_parsestr.3.html
	cd doc/man && mandoc -T html -Ostyle=man.css a2acl.1 > \
		../../a2acl.1.html
	cd doc/man && mandoc -T html -Ostyle=man.css a2idmatch.1 > \
		../../a2idmatch.1.html

gv:
	dot -Tpng doc/design/a2idfsm.gv -o doc/design/a2idfsm.png
	dot -Tsvg doc/design/a2idfsm.gv -o doc/design/a2idfsm.svg
	dot -Tpng doc/design/a2idselfsm.gv -o doc/design/a2idselfsm.png
	dot -Tsvg doc/design/a2idselfsm.gv -o doc/design/a2idselfsm.svg
	dot -Tpng doc/design/a2aclfsm.gv -o doc/design/a2aclfsm.png
	dot -Tsvg doc/design/a2aclfsm.gv -o doc/design/a2aclfsm.svg

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
lmdb:	lmdb.c
	cc -Wall -g -lpthread midl.o mdb.o lmdb.c -o $@

clean:
	rm -f a2idmatch a2id.o a2acl.o liba2id.a testa2id testa2acl a2idverify \
		a2idverifyafl lmdb a2acl_dbm.o a2acl_dblmdb.o a2acllmdb a2acl \
		tags src/tags test/tags

tags: src/*.[ch]
	ctags src/*.[ch]
	cd src && ctags *.[ch]
	cd test && ctags *.[ch]

a2acl_dbm.o: src/a2acl_dbm.c
	${CC} ${CFLAGS} -c src/a2acl_dbm.c

a2acl_dblmdb.o: src/a2acl_dblmdb.c
	${CC} ${CFLAGS} ${LDFLAGS} -I${INCDIR} -Wno-unused-parameter -c src/a2acl_dblmdb.c

a2acl: a2id.o a2acl.o a2acl_dbm.o src/a2aclcli.c
	${CC} ${CFLAGS} a2id.o a2acl.o a2acl_dbm.o src/a2aclcli.c -o $@

a2acllmdb: a2id.o a2acl.o a2acl_dblmdb.o src/a2aclcli.c
	${CC} ${CFLAGS} ${LDFLAGS} -I${INCDIR} -L${LIBDIR} -llmdb a2id.o a2acl.o a2acl_dblmdb.o src/a2aclcli.c -o $@

a2dumplmdb: a2acl_dblmdb.o src/a2dumplmdb.c
	${CC} ${CFLAGS} ${LDFLAGS} -I${INCDIR} -L${LIBDIR} -llmdb a2acl_dblmdb.o src/a2dumplmdb.c -o $@
