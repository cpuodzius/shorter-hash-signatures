/**
 * AES128.c
 *
 * The Advanced Encryption Standard (Rijndael, aka AES) block cipher,
 * designed by J. Daemen and V. Rijmen.
 *
 * @author Marcos A. Simplicio Jr
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*********************************************************************************
*                                  CONFIGURATION                                 *
**********************************************************************************/

//#include <avr/eeprom.h>

#define __AES_CIPHER__

/***************************************************************************
*					             DEFINES   							       *
****************************************************************************/

//------------------------ PLATFORM ------------------------------------

//Used to indicate that data is stored as program-memory (not RAM)
//You may need to edit this. The following defines can be used when
//there is EEPROM available or when an AVR device is used
#ifndef PROGMEM
	#define PROGMEM 
	//#define PROGMEM EEMEM
#endif

	#ifndef rb
		#define rb(value) *(value)
		//#define rb(value) eeprom_read_byte((unsigned char*)value)
	#endif


//------------- OPTIMIZATIONS: pre-computed tables -------------//

//#define USE_TABX        //table for xtimes operation

//---------------------------------- CONSTANTS ---------------------------------------

#define N_ROUNDS				10		//The number of rounds used by the cipher
#define BLOCK_SIZE              16
#define KEY_SIZE				BLOCK_SIZE
#define BLOCK_SIZE_BITS         128

//------------------------ TESTS ------------------------------------

//#define ENABLE_TESTS_CIPHER    //Enable tests

#ifdef ENABLE_TESTS_CIPHER
	//#define ENABLE_DEBUG_CIPHER    //Enables debugging
	void printMatrix(unsigned char matrix[]);
	void printvector(unsigned char vector[], unsigned char size);
#endif


/***********************************************************************************/


/***********************************************************************************
*			                  GLOBAL VARIABLES                                     *
************************************************************************************/

//--------------------------- COMPLETE S-BOX ---------------------------

static const unsigned char PROGMEM sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
#define sBox(value) (rb(sBox+(value)))


#ifdef USE_TABX
static const unsigned char PROGMEM tabX[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
    0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
    0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
    0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
    0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
    0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
    0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
    0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
    0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
    0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
    0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
};
#define xTimes(value) (rb(tabX+(value)))
#else
static unsigned char xTimes(const unsigned char value){
    if (value & 0x80){
    	return ((value << 1) ^ 0x1B);
	}
	return (value << 1);
}
#endif

//-------------- "CIPHER ATRIBUTES"  --------------

//holds the round keys
static unsigned char k_round[BLOCK_SIZE];
//Offset used by the key schedule
static unsigned char constantsOffSet;



/***********************************************************************************
*                                 CRYPT FUNCTIONS                                  *
************************************************************************************/

//-------------- " KEY SCHEDULE "  --------------

/** Evolutes the key.
  *
  *        {k[0], k[1], k[2], ... , k[13], k[14], k[15]}
  *         ^									  ^
  * most significant						least significant
  *
  */
static void createNextKey(void){
	unsigned char i;
	//Computes 1st column
	k_round[0] ^= sBox(k_round[13]) ^ constantsOffSet;
	k_round[1] ^= sBox(k_round[14]);
	k_round[2] ^= sBox(k_round[15]);
	k_round[3] ^= sBox(k_round[12]);

	//Computes other collumns
	for(i = 4 ; i < BLOCK_SIZE ; i++){
		k_round[i] ^= k_round[i-4];
	}

	//Updates the offset
	constantsOffSet = xTimes(constantsOffSet);
}


/**
 * Encrypts a single data block.
 * @param key The encryption key
 * @param src Pointer to the source block
 * @param dst Pointer to the destination block
 */
void cipherCryptB(const unsigned char* key, const unsigned char* src, unsigned char* dst){
	unsigned char i, j, _round, aux1, aux2;
	//Loads the key into the 'k' buffer (so it is not replaced
	//by the key evolution process) and applies the first key
	for(i = 0 ; i < BLOCK_SIZE ; i++){
		k_round[i] = key[i];
		dst[i] = src[i] ^ k_round[i];
	}

	//Initializes offset
	constantsOffSet  = 1;

	//round function
	for(_round = 0;  ; ){
		
		//----ShiftRows
		//2nd row
		aux1 = dst[1]; dst[1] = dst[5]; dst[5] = dst[9];
		dst[9] = dst[13]; dst[13] = aux1;
		//3rd row
		aux1 = dst[2]; dst[2] = dst[10]; dst[10] = aux1;
		aux1 = dst[6]; dst[6] = dst[14]; dst[14] = aux1;
		//4th row
		aux1 = dst[3]; dst[3] = dst[15]; dst[15] = dst[11];
		dst[11] = dst[7]; dst[7] = aux1;

		//----ByteSub (applies SBox)
		for(i = 0; i < BLOCK_SIZE ; i++){
			dst[i] = sBox(dst[i]);
		}

		//Create the key for this round
		createNextKey();

        //Checks if the final round is achieved
		if(++_round == 10){
			//Final round lacks mixCollumns operation
			for(i = 0 ; i < BLOCK_SIZE ; i++){
				dst[i] ^= k_round[i];
			}

			break;
        }

		//----Mixcolumn + AddRoundKey

		for(i = 0;  i <= 12 ; i++)
		{
			aux2 = dst[i];
			aux1 = aux2 ^ dst[i+1] ^ dst[i+2] ^ dst[i+3];
			for(j = 0 ; j < 3 ; j++)
			{
				dst[i] ^= aux1 ^ xTimes(dst[i] ^ dst[i+1]) ^ k_round[i];
				i++;
			}
			dst[i] ^= aux1 ^ xTimes(dst[i] ^ aux2) ^ k_round[i];
		}

#ifdef ENABLE_DEBUG_CIPHER
dbsp("\nDEBUG. Round ");
dbch(_round);
dbsp("\nKey:");
printMatrix(k);
dbsp("\nBLock:");
printMatrix(dst);
#endif


	}//end of for (all rounds)
	
	return;
}




/*******************************************************************************/
/********************************* TESTS ***************************************/
/*******************************************************************************/

#ifdef ENABLE_TESTS_CIPHER

void printMatrix(unsigned char matrix[]) {
    unsigned char nCol = 4;
    unsigned char nRow = BLOCK_SIZE/4;
    int row, a;

    dbsp("\n");
    for (row = 0; row < nRow; row++) {
        dbsp("| ");
        for (a = 0; a < nCol; a++) {
            dbsp(" ");
            dbch(matrix[row + nRow * a]);
            dbsp(" ");
        }
        dbsp(" |\n");
    }
}

//Prints a vector
void printvector(unsigned char vector[], unsigned char size) {
    int a;

	dbsp("\n");
    for (a = 0; a < size; a++) {
        dbsp("| ");
        dbch(vector[a]);
        dbsp(" ");
    }
    dbsp("|\n");
}


int main(void){

//---------------------- INPUTS ---------------------------//

	unsigned char plain[BLOCK_SIZE];		//plaintext
	unsigned char cKey[BLOCK_SIZE];		//key
	unsigned char ciphertext[BLOCK_SIZE];	//resulting ciphertext
	unsigned char res[BLOCK_SIZE];			//expected ciphertext

	unsigned char ok1;

	//----- Test 1 -----//

	for(unsigned char i = 0 ; i < BLOCK_SIZE; i++){
		plain[i] = 0;
		cKey[i] = 0;
	}

	res[0] = 0x66; res[1] = 0xe9; res[2] = 0x4b; res[3] = 0xd4;
	res[4] = 0xef; res[5] = 0x8a; res[6] = 0x2c; res[7] = 0x3b;
	res[8] = 0x88; res[9] = 0x4c; res[10] = 0xfa; res[11] = 0x59;
	res[12] = 0xca; res[13] = 0x34; res[14] = 0x2b; res[15] = 0x2e;


	//--- Run Test --- //

	dbsp("Plaintext: ");
	printMatrix(plain);
	dbsp("Key: ");
	printMatrix(cKey);
	cipherCryptB(cKey, plain, ciphertext);
	dbsp("Result: ");
	printMatrix(ciphertext);


	//--- check if results are OK ---//
	ok1 = 1;
	for(unsigned char i = 0 ; i < BLOCK_SIZE ; i++){
		if(ciphertext[i] != res[i]){
			ok1 = 0;
			break;
		}
	}

	if(ok1){
        dbsp("\n *** OK! ***\n");
    }
    else{
        dbsp("\n *** ERROR! ***\n");
    }

	//----- Test 2 (see FIPS 197) -----//
	
	plain[0] = 0x32; plain[1] = 0x43; plain[2] = 0xf6; plain[3] = 0xa8;
	plain[4] = 0x88; plain[5] = 0x5a; plain[6] = 0x30; plain[7] = 0x8d;
	plain[8] = 0x31; plain[9] = 0x31; plain[10] = 0x98; plain[11] = 0xa2;
	plain[12] = 0xe0; plain[13] = 0x37; plain[14] = 0x07; plain[15] = 0x34;

	cKey[0] = 0x2b; cKey[1] = 0x7e; cKey[2] = 0x15; cKey[3] = 0x16;
	cKey[4] = 0x28; cKey[5] = 0xae; cKey[6] = 0xd2; cKey[7] = 0xa6;
	cKey[8] = 0xab; cKey[9] = 0xf7; cKey[10] = 0x15; cKey[11] = 0x88;
	cKey[12] = 0x09; cKey[13] = 0xcf; cKey[14] = 0x4f; cKey[15] = 0x3c;

	res[0] = 0x39; res[1] = 0x25; res[2] = 0x84; res[3] = 0x1d;
	res[4] = 0x02; res[5] = 0xdc; res[6] = 0x09; res[7] = 0xfb;
	res[8] = 0xdc; res[9] = 0x11; res[10] = 0x85; res[11] = 0x97;
	res[12] = 0x19; res[13] = 0x6a; res[14] = 0x0b; res[15] = 0x32;

	//--- Run Test --- //

	dbsp("\nPlaintext: ");
	printMatrix(plain);
	dbsp("Key: ");
	printMatrix(cKey);
	cipherCryptB(cKey, plain, ciphertext);
	dbsp("Result: ");
	printMatrix(ciphertext);


	//--- check if results are OK ---//
	ok1 = 1;
	for(unsigned char i = 0 ; i < BLOCK_SIZE ; i++){
		if(ciphertext[i] != res[i]){
			ok1 = 0;
			break;
		}
	}

	if(ok1){
        dbsp("\n *** OK! ***\n");
    }
    else{
        dbsp("\n *** ERROR! ***\n");
    }

    return 1;
}

#endif

