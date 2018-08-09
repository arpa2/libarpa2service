naiverify: nai.o src/naiverify.c
	cc -Wall nai.o src/naiverify.c -o $@

nai.o: src/nai.c src/nai.h
	cc -Wall src/nai.c -c

a2donai.o: src/a2donai.c src/a2donai.h
	cc -Wall src/a2donai.c -c

testnai: nai.o test/nai.c
	cc -Wall nai.o test/nai.c -o $@

testa2donai: nai.o a2donai.o test/a2donai.c
	cc -Wall nai.o a2donai.o test/a2donai.c -o $@

test!	testnai testa2donai naiverify
	./testnai
	./testa2donai
	./test/testnaiverify

naifsm:
	dot -Tpng doc/design/naifsm.gv -o doc/design/naifsm.png
	dot -Tsvg doc/design/naifsm.gv -o doc/design/naifsm.svg

# create instrumented binary for use by afl-fuzz
naiverifyafl: src/nai.c src/naivstdin.c
	afl-clang -Wall src/nai.c src/naivstdin.c -o $@

clean:
	rm -f naiverify nai.o a2donai.o testnai testa2donai naiverifyafl
