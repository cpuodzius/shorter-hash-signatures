CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include

all:		mmo aes sponge winternitz mss example

hash:
	make mmo
	
aes:	src/ti_aes.c
		$(CC) src/ti_aes.c -c -o bin/aes.o $(CFLAGS)
		
mmo:	src/mmo.c
		make aes
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

sponge:		src/sponge.c
		make hash
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

winternitz:	src/sponge.c src/winternitz.c
		make sponge
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

mss:		src/mss.c
		make winternitz
		$(CC) src/$@.c -c -o bin/$@.o -DMSS_CALC_RETAIN $(CFLAGS)

test:		src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		#$(CC) src/mss.c -o bin/mss -DMSS_SELFTEST bin/*.o $(CFLAGS)
		#$(CC) src/mss.c -o bin/mss.dbg -DDEBUG bin/*.o $(CFLAGS)
		#$(CC) src/winternitz.c -o bin/winternitz -DWINTERNITZ_SELFTEST bin/*.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss -DMSS_SELFTEST bin/*.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss.dbg -DDEBUG bin/*.o $(CFLAGS)

util:		src/util.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

example:	src/example.c
		$(CC) src/$@.c -o bin/$@ -DMSS_CALC_RETAIN bin/*.o $(CFLAGS)

clean:		
		rm -rf *.o bin/* lib/*
