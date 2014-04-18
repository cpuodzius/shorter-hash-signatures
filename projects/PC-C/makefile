CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include -I ../resources/blake2-ref/include

all:		blake2 mmo aes sponge winternitz merkle_tree

hash:
	#make blake2
	#cp blake2-ref/lib/* lib
	make mmo
	
aes:	src/aes.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		
mmo:	src/mmo.c
		make aes
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

blake2:		blake2-ref/makefile
		cd ../resources/blake2-ref; make blake2s;

sponge:		src/sponge.c
		make hash
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS) -Llib -lblake2s-ref

winternitz:	src/sponge.c src/winternitz.c
		make sponge
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

mss:		src/mss.c
		make winternitz
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

test:		src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		#$(CC) src/merkle_tree.c -o bin/merkle_tree -DMERKLE_TREE_SELFTEST bin/*.o $(CFLAGS) -Llib -lblake2s-ref
		#$(CC) src/merkle_tree.c -o bin/merkle_tree.dbg -DDEBUG bin/*.o $(CFLAGS) -Llib -lblake2s-ref
		#$(CC) src/winternitz.c -o bin/winternitz -DWINTERNITZ_SELFTEST bin/*.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss -DMSS_SELFTEST bin/*.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss.dbg -DDEBUG bin/*.o $(CFLAGS)

util:		src/util.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

clean:		
		rm -rf *.o bin/* lib/*
		cd resources/blake2-ref; make clean
