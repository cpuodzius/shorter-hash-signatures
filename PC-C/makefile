CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include -I blake2-ref/include

all:		blake2 sponge winternitz merkle_tree

blake2:		blake2-ref/makefile
		cd blake2-ref; make blake2s;

sponge:		src/sponge.c
		make blake2
		cp blake2-ref/lib/* lib
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS) -Llib -lblake2s-ref

winternitz:	src/sponge.c src/winternitz.c
		make sponge
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

merkle_tree:	src/merkle_tree.c
		make winternitz
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

tests:		src/winternitz.c src/util.c
		make winternitz
		make util
		$(CC) src/merkle_tree.c -o bin/merkle_tree -DMERKLE_TREE_SELFTEST bin/*.o $(CFLAGS) -Llib -lblake2s-ref
		$(CC) src/merkle_tree.c -o bin/merkle_tree.dbg -DDEBUG bin/*.o $(CFLAGS) -Llib -lblake2s-ref
		#$(CC) src/winternitz.c -o bin/winternitz -DWINTERNITZ_SELFTEST bin/*.o $(CFLAGS) -Llib -lblake2s-ref

util:		src/util.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

clean:		
		rm -rf *.o bin/* lib/*
		cd blake2-ref; make clean
