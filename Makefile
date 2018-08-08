naiverify: nai.o src/naiverify.c
	cc -Wall -g nai.o src/naiverify.c -o $@

nai.o: src/nai.c src/nai.h
	cc -Wall -g src/nai.c -c

testnai: ./nai.o
	cc -Wall -g src/nai.c test/nai.c
	./a.out

testnaiverify: naiverify
	test/naiverify

naifsm:
	dot -Tpng doc/design/naifsm.gv -o doc/design/naifsm.png
	dot -Tsvg doc/design/naifsm.gv -o doc/design/naifsm.svg

naiverifyfuzz: src/nai.c src/naivstdin.c
	afl-clang -Wall src/nai.c src/naivstdin.c -o $@
