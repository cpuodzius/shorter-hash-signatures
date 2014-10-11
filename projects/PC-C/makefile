CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include
MSS_OBJS=bin/winternitz.o bin/sponge.o bin/mmo.o bin/aes.o bin/util.o bin/test.o

all:		test mmo aes sponge winternitz mss example libs

hash:
		make mmo
	
aes:		src/ti_aes.c
		$(CC) src/ti_aes.c -c -o bin/aes.o $(CFLAGS)
		
mmo:		src/mmo.c
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
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

test:		src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss -DMSS_SELFTEST $(MSS_OBJS) $(CFLAGS)
		$(CC) src/mss.c -o bin/mss.dbg -DDEBUG $(MSS_OBJS) $(CFLAGS)

util:		src/util.c
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)


example:	src/example.c
		make mss
		make util
		$(CC) src/$@.c -o bin/$@ bin/*.o $(CFLAGS)

libs:
		gcc -c -fPIC -o bin/dyn_aes.o src/ti_aes.c
		gcc -c -fPIC -o bin/dyn_mmo.o src/mmo.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_sponge.o src/sponge.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_winternitz.o src/winternitz.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_mss.o src/mss.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_util.o src/util.c $(CFLAGS)
		gcc -shared -fPIC -Wl,-soname,libcrypto.so -o bin/libcrypto.so bin/dyn_*.o -lc
		ar rcs bin/libcrypto.a bin/aes.o bin/mmo.o bin/sponge.o bin/winternitz.o bin/mss.o bin/util.o
clean:		
		rm -rf *.o bin/* lib/*
