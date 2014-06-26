#ifndef _UTIL_H_
#define _UTIL_H_

#include "mss.h"

typedef unsigned char rand_dig_f_type(void);

unsigned char rand_dig_f(void);

void Display(const char *tag, const unsigned char *u, unsigned short n);
short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f);
short Comp(const unsigned char *u, short ud, const unsigned char *v, short vd);
void start_seed(unsigned char seed[], short len);
void print_retain(const struct state_mt *state);

#endif // _UTIL_H_
