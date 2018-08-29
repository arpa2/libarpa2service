naiverify: nai.o src/naiverify.c
	cc -Wall nai.o src/naiverify.c -o $@

donaimatch: nai.o a2donai.o src/donaimatch.c
	cc -Wall nai.o a2donai.o src/donaimatch.c -o $@

nai.o: src/nai.c src/nai.h
	cc -Wall src/nai.c -c

a2donai.o: src/a2donai.c src/a2donai.h
	cc -Wall src/a2donai.c -c

testnai: nai.o test/testnai.c
	cc -Wall -g nai.o test/testnai.c -o $@

testa2donai: nai.o src/a2donai.c test/testa2donai.c
	cc -Wall -g nai.o src/a2donai.c test/testa2donai.c -o $@

test:	testnai testa2donai naiverify donaimatch
	./testnai
	./testa2donai
	./test/testnaiverify
	./test/testdonaimatch

naifsm:
	dot -Tpng doc/design/naifsm.gv -o doc/design/naifsm.png
	dot -Tsvg doc/design/naifsm.gv -o doc/design/naifsm.svg
	dot -Tpng doc/design/naiselfsm.gv -o doc/design/naiselfsm.png
	dot -Tsvg doc/design/naiselfsm.gv -o doc/design/naiselfsm.svg
	dot -Tpng doc/design/donaiuserfsm.gv -o doc/design/donaiuserfsm.png
	dot -Tsvg doc/design/donaiuserfsm.gv -o doc/design/donaiuserfsm.svg
	dot -Tpng doc/design/donaiselfsm.gv -o doc/design/donaiselfsm.png
	dot -Tsvg doc/design/donaiselfsm.gv -o doc/design/donaiselfsm.svg

# create instrumented binary for use by afl-fuzz
naiverifyafl: src/nai.c src/naivstdin.c
	afl-clang -Wall src/nai.c src/naivstdin.c -o $@

clean:
	rm -f naiverify nai.o a2donai.o testnai testa2donai naiverifyafl
