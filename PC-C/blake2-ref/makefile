CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include

all:		blake2s blake2b

blake2s:	src/blake2s-ref.c
		$(CC) src/blake2s-ref.c -o bin/$@ $(CFLAGS) -DBLAKE2S_SELFTEST
		$(CC) src/blake2s-ref.c -c -o bin/$@.o $(CFLAGS)
		ar rcs lib/libblake2s-ref.a bin/$@.o

blake2b:	src/blake2b-ref.c
		$(CC) src/blake2b-ref.c -o bin/$@ $(CFLAGS) -DBLAKE2B_SELFTEST

kat:
		$(CC) $(CFLAGS) -Llib -lblake2s-ref -o bin/genkat src/genkat.c src/blake2b-ref.c src/blake2s-ref.c
		bin/genkat > include/blake2-kat.h

clean:		
		rm -rf *.o bin/* lib/*
