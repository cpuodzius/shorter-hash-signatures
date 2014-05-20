/**
 * AES128.c
 *
 * The Advanced Encryption Standard (Rijndael, aka AES) block cipher,
 * designed by J. Daemen and V. Rijmen.
 *
 * @author Marcos A. Simplicio Jr, Geovandro C. C. F. Pereira
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

//#include <avr/eeprom.h>
#include "aes.h"


/***********************************************************************************
*			                  GLOBAL VARIABLES                                     *
************************************************************************************/


#ifdef USE_TABX
static const u8 PROGMEM tabX[256] = {
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
static u8 xTimes(const u8 value){
    if (value & 0x80){
    	return ((value << 1) ^ 0x1B);
	}
	return (value << 1);
}
#endif

//-------------- "CIPHER ATRIBUTES"  --------------

//holds the round keys
static u8 k[BLOCK_SIZE];
//Offset used by the key schedule
static u8 constantsOffSet;



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
	u8 i;
	//Computes 1st column
	k[0] ^= sBox(k[13]) ^ constantsOffSet;
	k[1] ^= sBox(k[14]);
	k[2] ^= sBox(k[15]);
	k[3] ^= sBox(k[12]);

	//Computes other collumns
	for(i = 4 ; i < BLOCK_SIZE ; i++){
		k[i] ^= k[i-4];
	}

	//Updates the offset
	constantsOffSet = xTimes(constantsOffSet);
}

//------- " ROUND FUNCTION "  ---------

#ifdef REQUIRE_SCT

/**Computes a unkeyed round over the 'bl' array.
 *
 * @param doMixColumn If '0', the MixColumn
 * operation is not performed; it will be performed otherwise.
 */
static void unkeyedRound(u8* bl, u8 doMixColumn){
	u8 aux1, i;

	//----ShiftRows
	//2nd row
	aux1 = bl[1]; bl[1] = bl[5]; bl[5] = bl[9];
	bl[9] = bl[13]; bl[13] = aux1;
	//3rd row
	aux1 = bl[2]; bl[2] = bl[10]; bl[10] = aux1;
	aux1 = bl[6]; bl[6] = bl[14]; bl[14] = aux1;
	//4th row
	aux1 = bl[3]; bl[3] = bl[15]; bl[15] = bl[11];
	bl[11] = bl[7]; bl[7] = aux1;

	//----ByteSub (applies SBox)
	for(i = 0; i < BLOCK_SIZE ; i++){
		bl[i] = sBox(bl[i]);
	}

	//----Mixcolumn
	if(doMixColumn){
		for(i = 0;  i <= 12 ; i++)
		{
			u8 aux2 = bl[i];
			aux1 = aux2 ^ bl[i+1] ^ bl[i+2] ^ bl[i+3];
			for(u8 j = 0 ; j < 3 ; j++)
			{
				bl[i] ^= aux1 ^ xTimes(bl[i] ^ bl[i+1]);
				i++;
			}
			bl[i] ^= aux1 ^ xTimes(bl[i] ^ aux2);
		}
	}
}


//-------------- "ENCRYPTION FUNCTION"  --------------

/**
 * Encrypts a single data block.
 * @param key The encryption key
 * @param src Pointer to the source block
 * @param dst Pointer to the destination block
 */
void cipherCryptB(u8* key, u8* src, u8* dst){
	u8 i, aes_round; 
	//Loads the key into the 'k' buffer (so it is not replaced
	//by the key evolution process) and applies the first key
	for(i = 0 ; i < BLOCK_SIZE ; i++){
		k[i] = key[i];
		dst[i] = src[i] ^ k[i];
	}

	//Initializes offset
	constantsOffSet  = 1;

    //round function applied 10 times
    for(aes_round = 1; aes_round <= N_ROUNDS ; aes_round++){

        //Creates the key for this round
        createNextKey();

        //Computes a single unkeyed round.
		//The last round does not include the multiplication by matrix D
        unkeyedRound(dst, aes_round < N_ROUNDS);

        //Applies the key for this round
		for(i = 0 ; i < BLOCK_SIZE ; i++){
			dst[i] ^= k[i];
		}

#ifdef ENABLE_DEBUG_CIPHER
dbsp("\nDEBUG. Round ");
dbch(aes_round);
dbsp("\nKey:");
printMatrix(k);
dbsp("\nBLock:");
printMatrix(dst);
#endif


    }//end of all rounds
}

#else

/**
 * Encrypts a single data block.
 * @param key The encryption key
 * @param src Pointer to the source block
 * @param dst Pointer to the destination block
 */
void cipherCryptB(u8* key, u8* src, u8* dst){
	u8 i, j, aes_round, aux1, aux2;
	//Loads the key into the 'k' buffer (so it is not replaced
	//by the key evolution process) and applies the first key
	for(i = 0 ; i < BLOCK_SIZE ; i++){
		k[i] = key[i];
		dst[i] = src[i] ^ k[i];
	}

	//Initializes offset
	constantsOffSet  = 1;

	//round function
	for(aes_round = 0;  ; ){
		
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
		if(++aes_round == 10){
			//Final round lacks mixCollumns operation
			for(i = 0 ; i < BLOCK_SIZE ; i++){
				dst[i] ^= k[i];
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
				dst[i] ^= aux1 ^ xTimes(dst[i] ^ dst[i+1]) ^ k[i];
				i++;
			}
			dst[i] ^= aux1 ^ xTimes(dst[i] ^ aux2) ^ k[i];
		}

#ifdef ENABLE_DEBUG_CIPHER
dbsp("\nDEBUG. Round ");
dbch(aes_round);
dbsp("\nKey:");
printMatrix(k);
dbsp("\nBLock:");
printMatrix(dst);
#endif


	}//end of for (all rounds)

	return;
}

#endif



