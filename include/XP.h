#ifndef __XP_H
#define __XP_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG_IO

#define DIGIT_LGBITS (3)
#define DIGIT_BITS (1 << DIGIT_LGBITS)
#define DIGIT_SIZE (DIGIT_BITS >> 3)
#define DIGIT_BASE (1 << DIGIT_BITS)
#define DIGIT_LAST (DIGIT_BASE - 1)
#define DIGIT_MASK DIGIT_LAST

//#define MAX_XP_BITS     ( 12) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 13) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 14) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 15) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 16) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 17) /* DEBUG ONLY */
//#define MAX_XP_BITS     ( 19) /* DEBUG ONLY */

//#define MAX_XP_BITS     (160) /* OK */
//#define MAX_XP_BITS     (192) /* OK */
//#define MAX_XP_BITS     (221) /* not Elligator 1 */
////#define MAX_XP_BITS     (222) /* distance between p and next power of 2 is too large to fit a digit */
////#define MAX_XP_BITS     (251) /* distance between p and next power of 2 is too large to fit a digit */
//#define MAX_XP_BITS     (255) /* not Elligator 1 */
#define MAX_XP_BITS     (256) /* OK */
////#define MAX_XP_BITS     (382) /* distance between p and next power of 2 is too large to fit a digit */
//#define MAX_XP_BITS     (383) /* not Elligator 1 */
//#define MAX_XP_BITS     (389) /* OK */
////#define MAX_XP_BITS     (511) /* not Elligator 1 */
//#define MAX_XP_BITS     (521) /* OK */

#if   (MAX_XP_BITS ==  12)
    #define XP_DELTA    (  5)
    #define ED_A        1
    #define ED_D        "08" /* or "07" with ED_A == -1 */
    #define ED_N        "03F5"
    #define ED_GY       4
#elif (MAX_XP_BITS ==  13)
    #define XP_DELTA    (  1)
    #define ED_A        1
    #define ED_D        "0E"
    #define ED_N        "07EB"
    #define ED_GY       9
#elif (MAX_XP_BITS ==  14)
    #define XP_DELTA    ( 21)
    #define ED_A        1
    #define ED_D        "0112"
    #define ED_N        "0FD1"
    #define ED_GY       6
#elif (MAX_XP_BITS ==  15)
    #define XP_DELTA    ( 49)
    #define ED_A        1
    #define ED_D        "3C"
    #define ED_N        "1FB5"
    #define ED_GY       12
#elif (MAX_XP_BITS ==  16)
    #define XP_DELTA    ( 17)
    #define ED_A        1
    #define ED_D        "9A"
    #define ED_N        "3FD3"
    #define ED_GY       3
#elif (MAX_XP_BITS ==  17)
    #define XP_DELTA    (  1)
    #define ED_A        -1
    #define ED_D        "0184"
    #define ED_N        "7F5B"
    #define ED_GY       13
#elif (MAX_XP_BITS ==  19)
    #define XP_DELTA    (  1)
    #define ED_A        1
    #define ED_D        "0448"
    #define ED_N        "2011D"
    #define ED_GY       11
#elif (MAX_XP_BITS == 160)
    #define XP_DELTA    ( 57)
    #define ED_A        -1
    #define ED_D        "10CA"
    #define ED_N        "3FFFFFFFFFFFFFFFFFFF9B51EE19F79163C9DA09"
    #define ED_GY       2
#elif (MAX_XP_BITS == 192)
    #define XP_DELTA    (237)
    #define ED_A        1
    #define ED_D        "01EE5E"
    #define ED_N        "3FFFFFFFFFFFFFFFFFFFFFFFC6D01A2F9A6879B538264A6D"
    #define ED_GY       12
#elif (MAX_XP_BITS == 221)
    #define XP_DELTA    (  3)
    #define ED_A        1
    #define ED_D        "0"
    #define ED_N        "0"
    #define ED_GY       1
#elif (MAX_XP_BITS == 222)
    #define XP_DELTA    (117)
    #define ED_A        1
    #define ED_D        "027166"
    #define ED_N        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF70CBC95E932F802F31423598CBF"
    #define ED_GY       28
#elif (MAX_XP_BITS == 251)
    #define XP_DELTA    (  9)
    #define ED_A        -1
    #define ED_D        "0496"
    #define ED_N        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C971"
    #define ED_GY       2
#elif (MAX_XP_BITS == 255)
    #define XP_DELTA    ( 19)
#elif (MAX_XP_BITS == 256)
    #define XP_DELTA    (189)
    #define ED_A        1
    #define ED_D        "05B072"
    #define ED_N        "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF966ABA3FBE3B4DB6D7E7ABED1DE551C7"
    #define ED_GY       4
#elif (MAX_XP_BITS == 382)
    #define XP_DELTA    (105)
    #define ED_A        -1
    #define ED_D        "0106B6"
    #define ED_N        "1000000000000000000000000000000000000000000000002A04DE0DE16A111E83A196D7E4EFD2D88C1D81EC02C368B3"
    #define ED_GY       7
#elif (MAX_XP_BITS == 383)
    #define XP_DELTA    (187)
#elif (MAX_XP_BITS == 389)
    #define XP_DELTA    ( 21)
    #define ED_A        1
    #define ED_D        "153EB"
    #define ED_N        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDEC8E81BD4908B075D9915874B26A356B9501D3A9D9952A8D"
    #define ED_GY       13
#elif (MAX_XP_BITS == 511)
    #define XP_DELTA    (187)
#elif (MAX_XP_BITS == 521)
    #define XP_DELTA    (  1)
    #define ED_A        -1
    #define ED_D        "05BCCE"
    #define ED_N        "800000000000000000000000000000000000000000000000000000000000000002EA4939B8B9037A08C94750A1813AC0FB04273BA96570E0BABF15DBCA0AE7F295"
    #define ED_GY       5
#else
#error "Unsupported modulus"
#endif

#define MAX_XP_BYTES  ((MAX_XP_BITS + 7) / 8)
#define MAX_XP_DIGITS ((MAX_XP_BITS + DIGIT_BITS - 1)/DIGIT_BITS)

#define XP_SetDigit(x, d) ((x)[0] = (d), ((d) > 0) ? 1 : 0)
#define XP_GetBit(x, n) (((x)[(n) >> DIGIT_LGBITS] >> ((n) & (DIGIT_BITS-1))) & 1)

typedef unsigned char   XP_digit_t;
typedef unsigned short  XP_digit2_t;
typedef XP_digit_t XP_rand_dig_f(void);

#ifdef DEBUG_IO
void    XP_Display(const char *name, const XP_digit_t *u, short ud);
#endif /* DEBUG_IO */
void    XP_Clear(XP_digit_t *x, short xd);
short   XP_Set(XP_digit_t *x, const char *hexval);
short   XP_Rand(XP_digit_t *x, short bits, XP_rand_dig_f rand_dig_f);
short   XP_Copy(XP_digit_t *d, const XP_digit_t *s, short sd);
short   XP_Digits(const XP_digit_t *u, short n);
short   XP_Comp(const XP_digit_t *u, short ud, const XP_digit_t *v, short vd);
short   XP_Add(XP_digit_t *w, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd);
short   XP_Sub(XP_digit_t *w, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd);
short   XP_Lshift(XP_digit_t *w, const XP_digit_t *u, short ud, short s);
short   XP_Rshift(XP_digit_t *w, const XP_digit_t *u, short ud, short s);
short   XP_Mul(XP_digit_t *p, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd,
            XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_ShortMul(XP_digit_t *p, const XP_digit_t *u, short ud, XP_digit_t d,
            XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_ShortDiv(XP_digit_t *q, XP_digit_t *r, const XP_digit_t *u, short ud, XP_digit_t v);
short   XP_Div(XP_digit_t *q, XP_digit_t *r, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd,
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_QuasiMod(XP_digit_t *r, XP_digit_t *u, short ud,
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_ModMul(XP_digit_t *p, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd,
            XP_digit_t X[2*MAX_XP_DIGITS + 1],
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_InvMod(XP_digit_t *inv, XP_digit_t *a, short ad, const XP_digit_t *m, short md,
            XP_digit_t b[MAX_XP_DIGITS + 1], XP_digit_t g[MAX_XP_DIGITS + 1], XP_digit_t c[MAX_XP_DIGITS + 1], XP_digit_t h[MAX_XP_DIGITS + 1],
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_PowMod(XP_digit_t *e, const XP_digit_t *a, short ad, const XP_digit_t *x, short xd, const XP_digit_t *m, short md,
            XP_digit_t z[2*MAX_XP_DIGITS + 1],
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);
short   XP_Sqrt(XP_digit_t *r, XP_digit_t *v, short vd, const XP_digit_t *m, short md,
            XP_digit_t x[MAX_XP_DIGITS + 1], XP_digit_t A[2 * MAX_XP_DIGITS + 1], XP_digit_t g[MAX_XP_DIGITS + 1],
#if (XP_DELTA%4 != 1)
            XP_digit_t gamma[MAX_XP_DIGITS + 1],
#endif
            XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]);

#ifdef __cplusplus
}
#endif

#endif /* __XP_H */
