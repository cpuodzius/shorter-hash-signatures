CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -I include
LFLAGS=-c -fPIC
AES_SELFTEST_OBJS=bin/ti_aes_128.o
MSS_AES_OBJS=bin/mss_aes.o bin/ti_aes_128_enc.o
MSS_HASH_OBJS=bin/hash.o $(MSS_AES_OBJS)
MSS_WINTERNITZ_OBJS=bin/winternitz.o $(MSS_HASH_OBJS)
MSS_OBJS=bin/mss.o bin/util.o $(MSS_WINTERNITZ_OBJS)
LIB_OBJS=bin/dyn_ti_aes_128.o bin/dyn_aes_128.o bin/dyn_hash.o bin/dyn_winternitz.o bin/dyn_mss.o bin/dyn_util.o

all:		mss test example libs

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
		################ MSS_HASH #############
		make aes
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ HASH Unity Test #############
		$(CC) src/$@.c -o bin/$@ -DMMO_SELFTEST $(MSS_AES_OBJS) $(CFLAGS)

winternitz:	src/winternitz.c
		################ MSS_WINTERNITZ #############
		make hash
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ Winternitz Unity Test #############
		$(CC) src/$@.c -o bin/$@ -DWINTERNITZ_SELFTEST $(MSS_HASH_OBJS) $(CFLAGS)

mss:		src/mss.c
		################ MSS #############
		make winternitz
		make util
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)
		################ MSS Unity Test #############
		$(CC) src/$@.c -o bin/$@ -DMSS_SELFTEST $(MSS_WINTERNITZ_OBJS) bin/util.o $(CFLAGS)
		$(CC) src/$@.c -g -o bin/$@.dbg -DDEBUG -DMSS_SELFTEST $(MSS_WINTERNITZ_OBJS) bin/util.o $(CFLAGS)

test:		src/test.c
		################ MSS_TEST #############
		make mss
		$(CC) src/$@.c -o bin/lib$@ -DLIB_TEST $(MSS_OBJS) $(CFLAGS)

util:		src/util.c
		################ MSS_UTIL #############
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)


example:	src/example.c
		################ MSS_EXAMPLE #############
		make mss
		$(CC) src/$@.c -o bin/$@ $(MSS_OBJS) $(CFLAGS)

libs:
		################ MSS - RAILS - LIBS #############
		$(CC) $(LFLAGS) -o bin/dyn_ti_aes_128.o src/TI_aes_128.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_aes_128.o src/aes_128.c -DAES_ENC_DEC -DAES_CBC_MODE $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_hash.o src/hash.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_winternitz.o src/winternitz.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_mss.o src/mss.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_util.o src/util.c $(CFLAGS)
		$(CC) -shared -fPIC -Wl,-soname,libcrypto.so -o bin/libcrypto.so $(LIB_OBJS) -lc
		ar rcs bin/libcrypto.a $(LIB_OBJS)
		rm $(LIB_OBJS)

clean:		
		rm -rf *.o bin/* lib/*
