testrfc4282: src/rfc4282.c src/rfc4282.h
	cc -Wall -g src/rfc4282.c test/rfc4282.c
	./a.out

rfc4282fsm:
	dot -Tpng doc/design/rfc4282_fsm.gv -o doc/design/rfc4282_fsm.png
	dot -Tsvg doc/design/rfc4282_fsm.gv -o doc/design/rfc4282_fsm.svg
