CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include 
MSS_OBJS=bin/winternitz.o bin/hash.o bin/aes.o bin/ti_aes.o bin/util.o

all:	test winternitz mss libs #example

ti_aes:	src/TI_aes_128_encr_only.c
		$(CC) src/TI_aes_128_encr_only.c -c -o bin/ti_aes.o $(CFLAGS)
		
aes:	src/aes_128.c
		make ti_aes
		$(CC) src/aes_128.c -c -o bin/aes.o $(CFLAGS)

hash:   src/hash.c		
		make aes
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

#mmo:	src/mmo.c
#		make aes
#		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

#sponge:		src/sponge.c
#		make hash
#		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

util:	src/util.c
		$(CC) src/util.c -c -o bin/util.o $(CFLAGS)
		#$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

winternitz:	src/winternitz.c
		make hash		
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

mss:	src/mss.c
		make winternitz
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

test:	src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		$(CC) src/$@.c -c -o bin/$@.o -DVERBOSE -DMSS_SELFTEST -DSERIALIZATION $(CFLAGS)
		$(CC) src/mss.c -o bin/mss -DMSS_SELFTEST -DSERIALIZATION $(MSS_OBJS) bin/test.o $(CFLAGS)
		$(CC) src/mss.c -o bin/mss.dbg -DDEBUG -DMSS_SELFTEST -DSERIALIZATION $(MSS_OBJS) bin/test.o $(CFLAGS)

example:src/example.c
		make mss
		make util
		$(CC) src/$@.c -o bin/$@ bin/*.o $(CFLAGS)

libs:
		gcc -c -o bin/dyn_ti_aes.o src/TI_aes_128_encr_only.c $(CFLAGS) 
		gcc -c -o bin/dyn_aes.o src/aes_128.c $(CFLAGS)
		gcc -c -o bin/dyn_hash.o src/hash.c $(CFLAGS)
		gcc -c -o bin/dyn_util.o src/util.c $(CFLAGS)
		gcc -c -o bin/dyn_test.o src/test.c $(CFLAGS)
		gcc -c -o bin/dyn_winternitz.o src/winternitz.c $(CFLAGS)
		gcc -c -o bin/dyn_mss.o src/mss.c $(CFLAGS)
		gcc -shared -Wl,-soname,libcrypto.so -o bin/libcrypto.so bin/dyn_*.o -lc
		ar rcs bin/libcrypto.a bin/aes.o bin/hash.o bin/winternitz.o bin/util.o bin/mss.o
clean:		
		rm -rf *.o bin/* lib/*
