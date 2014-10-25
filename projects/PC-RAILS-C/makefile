CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include
AES_SELFTEST_OBJS=bin/ti_aes_128.o
MSS_AES_OBJS=bin/mss_aes.o bin/ti_aes_128_enc.o
MSS_HASH_OBJS=bin/hash.o $(MSS_AES_OBJS)
MSS_WINTERNITZ_OBJS=bin/winternitz.o $(MSS_HASH_OBJS)
MSS_OBJS=bin/mss.o $(MSS_WINTERNITZ_OBJS)

all:		test mmo aes sponge winternitz mss example libs

aes:		src/TI_aes_128.c  src/TI_aes_128_encr_only.c src/aes_128.c
		################ MSS_AES #############
		$(CC) src/TI_aes_128_encr_only.c -c -o bin/ti_aes_128_enc.o $(CFLAGS)
		$(CC) src/aes_128.c -c -o bin/mss_aes.o $(CFLAGS)
		################ AES for symmetric encryption #############
		$(CC) src/TI_aes_128.c -c -o bin/ti_aes_128.o $(CFLAGS)
		$(CC) src/aes_128.c -c -o bin/aes_128.o -DAES_ENC_DEC -DAES_CBC_MODE $(CFLAGS)
		################ AES Unity Test #############
		$(CC) src/aes_128.c -o bin/aes -DAES_ENC_DEC -DAES_CBC_MODE -DAES_SELFTEST $(AES_SELFTEST_OBJS) $(CFLAGS)

hash:		src/hash.c
		make aes
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ HASH Unity Test #############
		$(CC) src/$@.c -o bin/$@ -DMMO_SELFTEST $(MSS_AES_OBJS) $(CFLAGS)

winternitz:	src/winternitz.c
		make hash
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ Winternitz Unity Test #############
		#$(CC) src/$@.c -o bin/$@.o -DWINTERNITZ_SELFTEST $(MSS_HASH_OBJS) $(CFLAGS)

mss:		src/mss.c
		make winternitz
		make util
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ MSS Unity Test #############
		$(CC) src/$@.c -o bin/$@ -DMSS_SELFTEST $(MSS_WINTERNITZ_OBJS) bin/util.o $(CFLAGS)

test:		src/winternitz.c src/util.c src/test.c
		make winternitz
		make util
		$(CC) src/$@.c -c -o bin/$@.o -DMSS_SELFTEST $(CFLAGS)

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
