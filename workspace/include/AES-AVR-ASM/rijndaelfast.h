#ifndef RIJNDAEL_FAST_H_
#define RIJNDAEL_FAST_H_

//#include <stdint.h>
//#include "aes_types.h"
//#include "aes128_enc.h"
//#include "aes_enc.h"
//#include "aes_keyschedule.h"


void key_expand(void* buffer, aes128_ctx_t* ctx);
void encrypt(void* key, void* plain);

#endif
