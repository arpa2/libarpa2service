naiverify: rfc4282.o src/rfc4282_verify.c
	cc -Wall -g rfc4282.o src/rfc4282_verify.c -o $@

rfc4282.o: src/rfc4282.c src/rfc4282.h
	cc -Wall -g src/rfc4282.c -c

testrfc4282: ./rfc4282.o
	cc -Wall -g src/rfc4282.c test/rfc4282.c
	./a.out

testnaiverify: naiverify
	test/naiverify

rfc4282fsm:
	dot -Tpng doc/design/rfc4282_fsm.gv -o doc/design/rfc4282_fsm.png
	dot -Tsvg doc/design/rfc4282_fsm.gv -o doc/design/rfc4282_fsm.svg
