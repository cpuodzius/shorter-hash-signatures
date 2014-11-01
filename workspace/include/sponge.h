#ifndef _SPONGE_H_
#define _SPONGE_H_

#define PROCESSOR_WORD	8

#if SPONGE_SBLAKE2
#define SBLAKE2_WORD_SIZE 64 // Values supported 64,32
#define SPONGE_STATE_SIZE_BITS (16*(SBLAKE2_WORD_SIZE))
#else
#define KECCAK_VALUE_W 16 // Values supported 64,32,16
#define SPONGE_STATE_SIZE_BITS (25*(KECCAK_VALUE_W))
#endif

typedef struct sponge_state_struct {
#if PROCESSOR_WORD == 8
    unsigned char state[SPONGE_STATE_SIZE_BITS/8];
#elif PROCESSOR_WORD == 16
	unsigned short state[SPONGE_STATE_SIZE_BITS/16];
#else
	unsigned char state[SPONGE_STATE_SIZE_BITS/16];
#endif
    unsigned char state_control;
    unsigned char squeezing_mode;
} sponge_state;

/**
* Computes the hash of array "message" with "message_size_bytes" bytes and writes on array "hash" with "hash_size_bytes" requested
* The number of bytes to be hashed and output hash can be from 1 to the limit of unsigned short.
* This instances makes the keccak sponge init, absorb and squeeze internally.
*/
void sponge_hash(unsigned char * message, unsigned short message_size_bytes, unsigned char * hash, unsigned short hash_size_bytes);

/**
* Initialize keccak sponge "state" internal state with all zeros and reset "state" internal counters.
* This initialization is to be used with sponge functions absorb and squeeze.
*/
void sponge_init(sponge_state * state);

/**
* Absorbs array "message" with "message_size_bytes" bytes into keccak sponge "state" state.
* This function works as sponge, where it can be feed any amount of data by repeatedly calling this function.
*/
void sponge_absorb(sponge_state * state, unsigned char * message, unsigned short message_size_bytes);

/**
* Squeeze array "output" with "output_size_bytes" bytes from keccak sponge "state" state.
* This function works as sponge, where it can be squeezed any amount of data by repeatedly calling this function.
* After first squeeze, it should never be called absorb function again.
* In case it is necessary to absorb, it should be called first init function to clean "state".
*/
void sponge_squeeze(sponge_state * state, unsigned char * output, unsigned short output_size_bytes);


/**
* Initialize keccak sponge "state" internal state with all zeros.
* This initialization is to be used with duplex function duplexing.
*/
void sponge_duplex_init(sponge_state * state);

/**
* Absorbs array "message" with "message_size_bytes" bytes into keccak duplex "state" state.
* Array "message" should not be greater than sponge rate/8 bytes, in case it is only the first rate/8 will be absorbed.
* Squeeze array "duplex" with "duplex_size_bytes" bytes from keccak duplex "state" state.
* The amount to be squeezed is always no more than rate/8 bytes, in case it is asked only the first rate/8 will given.
*/
void sponge_duplex_duplexing(sponge_state * state, unsigned char * message, unsigned char message_size_bytes, unsigned char * duplex, unsigned char duplex_size_bytes);

#endif
