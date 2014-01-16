CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic

all:		merkle_tree

merkle_tree:	src/merkle_tree.c
		$(CC) src/merkle_tree.c -o bin/$@ $(CFLAGS)

clean:		
		rm -rf *.o bin/* lib/*
