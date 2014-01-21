/**
 *
 *  XP.C -- Extended Precision Arithmetic Library
 *
 *  References:
 *
 *  1.  Knuth, D. E.: "The Art of Computer Programming",
 *      2nd ed. (1981), vol. II (Seminumerical Algorithms).
 *      Addison Wesley Publishing Company.
 *
 *  2.  Hansen, P. B.: "Multiple-length Division Revisited:
 *      a Tour of the Minefield".
 *      Software - Practice and Experience 24:6 (1994), 579--601.
 *
 * @author Paulo S. L. M. Barreto
 * @version 0.0 (1995)
 *
 */

#include <assert.h>

#include "../include/xp.h"

#ifdef DEBUG_IO

#include <stdio.h>

void XP_Display(const char *name, const XP_digit_t *u, short ud) {
    short i, j;
    assert(ud >= 0);
    printf("%s[%d]:", name, ud);
    if (ud > 0) {
        for (i = ud - 1, j = 0; i >= 0; i--, j++) {
            //printf("%s%02X%s", (j % MAX_XP_BYTES) ? "" : "\t", u[i], ((j+1) % MAX_XP_BYTES) ? "" : "\n");
            printf("%s%02X%s", (j % (2*MAX_XP_BYTES)) ? "" : "\t", u[i], ((j+1) % (2*MAX_XP_BYTES)) ? "" : "\n");
        }
    } else {
        printf("\t%02X", 0);
    }
    printf("\n");
}

#endif /* DEBUG_IO */

void XP_Clear(XP_digit_t *x, short xd) {
    memset(x, 0, xd*sizeof(XP_digit_t));
}

short XP_Set(XP_digit_t *x, const char *val) {
    int i, j, n = strlen(val), xd = 0;
    XP_digit2_t k;
    XP_Clear(x, MAX_XP_DIGITS);
    for (i = 0; i < n; i++) {
        XP_Lshift(x, x, xd, 4); xd = XP_Digits(x, xd + 1);
        switch (val[i]) {
        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
            k = (XP_digit2_t)(val[i] - '0');
            break;
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            k = (XP_digit2_t)(val[i] - 'A' + 10);
            break;
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            k = (XP_digit2_t)(val[i] - 'a' + 10);
            break;
        default:
            k = (XP_digit2_t)0;
        }
        for (j = 0; j < xd; j++) {
            k += (XP_digit2_t)x[j];
            x[j] = (XP_digit_t)(k & DIGIT_MASK);
            k >>= DIGIT_BITS;
        }
        x[xd++] = (XP_digit_t)(k & DIGIT_MASK);
    }
    while (xd > 0 && x[xd - 1] == 0) {
        xd--;
    }
    return xd;
}

short XP_Rand(XP_digit_t *x, short bits, XP_rand_dig_f rand_dig_f) {
    short i, xd = (bits + DIGIT_BITS - 1)/DIGIT_BITS;
    for (i = 0; i < xd; i++) {
        x[i] = rand_dig_f();
    }
    i = (bits % DIGIT_BITS);
    if (xd > 0 && i > 0) {
        x[xd - 1] &= (XP_digit_t)(1 << i) - 1;
    }
    /*
    if (xd < MAX_XP_DIGITS) {
        memset(x + xd, 0, (MAX_XP_DIGITS - xd)*sizeof(XP_digit_t));
    }
    //*/
    while (xd > 0 && x[xd - 1] == 0) {
        xd--;
    }
    return xd;
}

short XP_Copy(XP_digit_t *d, const XP_digit_t *s, short sd) {
    short i;
    for (i = 0; i < sd; i++) {
        d[i] = s[i];
    }
    /*
    if (sd < MAX_XP_DIGITS) {
        memset(d + sd, 0, (MAX_XP_DIGITS - sd)*sizeof(XP_digit_t));
    }
    //*/
    return sd;
}

/**
 * Returns the number of effective digits of u
 */
short XP_Digits(const XP_digit_t *u, short ud) {
    short i;
    for (i = ud - 1; i >= 0; i--) {
        if (u[i] != 0) {
            return i + 1;
        }
    }
    return 0;
}

/**
 * Returns -1, 0, or +1 if u < v, u = v, or u > v, respectively
 */
short XP_Comp(const XP_digit_t *u, short ud, const XP_digit_t *v, short vd) {
    short i;
    assert(ud >= 0);
    assert(vd >= 0);
    if (ud < vd) {
        return -1;
    }
    if (ud > vd) {
        return +1;
    }
    // ud == vd
    for (i = ud - 1; i >= 0; i--) {
        if (u[i] < v[i]) {
            return -1;
        }
        if (u[i] > v[i]) {
            return +1;
        }
    }
    return 0;
}

/**
 * Sets w = u + v.
 * If v == NULL, set w = u + vd instead (single-digit addition).
 * Requires: u[0:n-1], v[0:n-1], w[0:n].
 */
short XP_Add(XP_digit_t *w, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd) {
    short i, wl, wh;
    XP_digit2_t k;
    const XP_digit_t *z;
    if (v != NULL) {
        if (ud <= vd) {
            wl = ud; wh = vd; z = v;
        } else {
            wl = vd; wh = ud; z = u;
        }
        k = 0;
        // add lower common part:
        for (i = 0; i < wl; i++) {
            k += (XP_digit2_t)u[i] + (XP_digit2_t)v[i];
            w[i] = (XP_digit_t)(k & DIGIT_MASK);
            k >>= DIGIT_BITS;
            assert(k == 0 || k == 1);
        }
    } else {
        wl = 0; wh = ud; z = u;
        k = vd; // vd represents a single-digit term
    }
	// add higher exclusive part:
    for (i = wl; i < wh; i++) {
        k += (XP_digit2_t)z[i];
        w[i] = (XP_digit_t)(k & DIGIT_MASK);
		k >>= DIGIT_BITS;
		assert(k == 0 || k == 1);
	}
	// handle carry and final length:
    w[wh++] = (XP_digit_t)k;
    while (wh > 0 && w[wh - 1] == 0) {
        wh--;
    }
    return wh;
}

/**
 * Sets w = u - v.
 * If v == NULL, set w = u - vd instead (single-digit subtraction).
 * Requires: u[0:n-1], v[0:n-1], w[0:n].
 */
short XP_Sub(XP_digit_t *w, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd) {
    short i, wl;
    short k;
    /*
    if (ud < vd || (ud == vd && XP_Comp(u, ud, v, vd) < 0)) {
        XP_Display("u", u, ud);
        XP_Display("v", v, vd);
    }
    //*/
    //assert(ud > vd || (ud == vd && XP_Comp(u, ud, v, vd) >= 0));
    if (v != NULL) {
        wl = vd;
        k = 0;
        // sub lower common part:
        for (i = 0; i < wl; i++) {
            k += (XP_digit2_t)u[i] - (XP_digit2_t)v[i];
            w[i] = (XP_digit_t)(k & DIGIT_MASK);
            k >>= DIGIT_BITS;
            assert(k == 0 || k == -1);
        }
    } else {
        wl = 0;
        k = -vd; // vd represents a single-digit term
    }
	// sub higher exclusive part:
	for (i = wl; i < ud; i++) {
        k += (XP_digit2_t)u[i];
        w[i] = (XP_digit_t)(k & DIGIT_MASK);
        k >>= DIGIT_BITS;
        //printf("k = %d\n", k);
        assert(k == 0 || k == -1);
    }
	// handle carry and final length:
	w[ud++] = (XP_digit_t)k;
	while (ud > 0 && w[ud - 1] == 0) {
		ud--;
	}
    return ud;
}

/**
 * Sets w = u << s.
 * Requires: w[0:ud+ (s+DIGIT_BITS-1)/DIGIT_BITS-1], u[0:ud-1].
 * Caution: w and u should not overlap unless &w <= &u
 */
short XP_Lshift(XP_digit_t *w, const XP_digit_t *u, short ud, short s) {
    short i, q = s/DIGIT_BITS, r = s%DIGIT_BITS;
    assert(s >= 0);
    w[ud + q] = u[ud - 1] >> (DIGIT_BITS - r);
    for (i = ud - 1; i > 0; i--) {
        w[i + q] = (u[i] << r) | (u[i - 1] >> (DIGIT_BITS - r));
    }
    w[q] = u[0] << r;
    if (q > 0) {
        XP_Clear(w, q); /* w[0:q-1] = 0 */
    }
    /* length of shifted array is ud + (s + DIGIT_BITS - 1)/DIGIT_BITS */
    return ud + (s + DIGIT_BITS - 1)/DIGIT_BITS;
}

/**
 * Sets w = u >> s.
 * Requires: u[0:ud-1].
 * Caution: w and u should not overlap unless &w <= &u
 */
short XP_Rshift(XP_digit_t *w, const XP_digit_t *u, short ud, short s) {
    short i, q = s/DIGIT_BITS, r = s%DIGIT_BITS;
    assert(s >= 0);
    q = s/DIGIT_BITS;
    r = s%DIGIT_BITS;
    if (q >= ud) {
        q  = ud; /* this will force w[0:ud-1] = 0 (see below) */
    } else {
        for (i = 0; i < ud - q - 1; i++) {
            w[i] = (u[i + q] >> r) | (u[i + q + 1] << (DIGIT_BITS - r));
        }
        w[ud - q - 1] = u[ud - 1] >> r;
    }
    if (q > 0) {
        XP_Clear(w + ud - q, q); /* w[ud-q:ud-1] = 0 */
    }
    return ud - q;
}

/**
 *   Sets p = u * v. Result length is ud + vd digits.
 *   Requires:   p[0:ud+vd-1]
 *               u[0:ud-1], 0 < ud <= MAX_XP_DIGITS
 *               v[0:vd-1], 0 < vd <= MAX_XP_DIGITS
 */
short XP_Mul(XP_digit_t *p, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd, XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short i, j, pd = ud + vd;
    XP_digit2_t k;

    if (ud < 0) {
        ud = -1;
    }
    assert(ud >= 0); assert(ud <= MAX_XP_DIGITS);
    assert(vd >= 0); assert(vd <= MAX_XP_DIGITS);
    XP_Clear(ww, ud + vd);
    for (j = 0; j < vd; j++) {
        k = 0;
        for (i = 0; i < ud; i++) {
            k += (XP_digit2_t)u[i]*(XP_digit2_t)v[j] + (XP_digit2_t)ww[i + j];
            ww[i + j] = (XP_digit_t)(k & DIGIT_MASK);
            k >>= DIGIT_BITS;
        }
        ww[ud + j] = (XP_digit_t)k;
    }
    XP_Copy(p, ww, pd);
    while (pd > 0 && p[pd - 1] == 0) {
        pd--;
    }
    return pd;
}

/**
 *   Sets p = u*d, where d is a single digit.
 *   Result length is ALWAYS ud + 1 digits (perhaps with a leading zero).
 *   Requires:   p[0:ud]
 *               u[0:ud-1], 0 < ud <= MAX_XP_DIGITS
 *   Warning: w is scratch
 */
short XP_ShortMul(XP_digit_t *p, const XP_digit_t *u, short ud, XP_digit_t d, XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short i;
    XP_digit2_t k;
    //printf("ud = %d\n", ud);
    assert(ud >= 0);
    assert(ud <= 2*MAX_XP_DIGITS + 1);
    XP_Clear(ww, ud + 1);
    k = 0;
    for (i = 0; i < ud; i++) {
        k += (XP_digit2_t)u[i]*(XP_digit2_t)d + (XP_digit2_t)ww[i];
        ww[i] = (XP_digit_t)(k & DIGIT_MASK);
        k >>= DIGIT_BITS;
    }
    ww[ud] = (XP_digit_t)k;
    XP_Copy(p, ww, ud + 1);
    return ud + 1; // remember: leading digit can be 0
}

/**
 * Sets q = u / v and r = u % v, where v is a single digit.
 * Quotient length is ud digits, remainder length is 1.
 * Requires:   q[0:ud-1], u[0:ud-1], 0 < ud <= 2*MAX_XP_DIGITS + 1.
 *             v != 0(obvious).
 *             q and r must not overlap, but r can be NULL (in which case the remainder is not computed).
 * Caution: q and u should not overlap unless &q <= &u.
 */
short XP_ShortDiv(XP_digit_t *q, XP_digit_t *r, const XP_digit_t *u, short ud, XP_digit_t v) {
    /* short division(see Knuth vol. II, p. 266(ex. 16) and p. 582 */
    short i;
    XP_digit2_t r0, v0;

    assert(ud >= 0); assert(ud <= 2*MAX_XP_DIGITS + 1);
    /* divide u[0...ud-1] by v: */
    r0 = 0; v0 = (XP_digit2_t)v;
    for (i = ud - 1; i >= 0; i--) {
        r0 = (r0 << DIGIT_BITS) + (XP_digit2_t)u[i];
        // TODO: replace / and % by library call to get quotient and remainder at once
        if (q != NULL) {
            q[i] = (XP_digit_t)(r0/v0);
        }
        r0 %= v0;
    }
    if (r != NULL) {
        r[0] = (XP_digit_t)r0;
        i = (r[0] != 0) ? 1 : 0; // i == remainder length
    }
    if (q != NULL) {
        while (ud > 0 && q[ud - 1] == 0) {
            ud--;
        }
        i = ud; // i == quotient length
    }
    /* q[0:ud-1] is the quotient, r[0] is the remainder */
    return i; // i == quotient length, except remainder length when q is NULL, except -1 when both are NULL
}

/**
 * Sets q = u div v and r = u mod v. Values are not returned if buffers are null (e.g. q == NULL implies only the remainder is returned)
 * See D. E. Knuth, "TAOCP" vol. 2, Algorithm D (p. 272).
 * Quotient length is at most max(ud - vd + 1, 1) digits.
 * Remainder length is at most min(ud, vd) digits.
 * Requires:   u[0:ud-1], 0 < ud <= 2*MAX_XP_DIGITS + 1
 *             v[0:vd-1], 0 < vd <=   MAX_XP_DIGITS
 *             Beware: U, V, t, w are all scratch
 */
short XP_Div(XP_digit_t *q, XP_digit_t *r, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd,
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short i, z;
    XP_digit2_t phat, qhat, v1, v2;
    XP_digit_t d, toggle;

    assert(ud >= 0); assert(ud <= 2*MAX_XP_DIGITS + 1);
    assert(vd >  0); assert(vd <=   MAX_XP_DIGITS + 1);
    if (vd == 1) {
        /* short division: */
        return XP_ShortDiv(q, r, u, ud, v[0]);
    } else if (ud < vd) {
        /* trivial division: q = 0, r = u */
        /*
        if (q != NULL) {
            XP_Clear(q, MAX_XP_DIGITS);
        }
        //*/
        if (r != NULL) {
            XP_Copy(r, u, ud); // NB: in this case, the remainder length is ud, not vd (i.e. rd = MIN(ud, vd) always)
        }
        return (q != NULL) ? 0 : ud;
    } else {
        /* long division(see Knuth vol. II, p. 257-258): */
        /* normalize: */
        d = (XP_digit_t)(DIGIT_BASE/((XP_digit2_t) v[vd - 1] + 1));
        XP_ShortMul(U, u, ud, d, ww); /* this sets U[ud] = 0 */
        XP_ShortMul(V, v, vd, d, ww); /* this sets V[vd] = 0 */
        v1 = (XP_digit2_t)V[vd - 1];
        v2 = (XP_digit2_t)V[vd - 2];
        /* loop on i: */
        for (i = ud; i >= vd; i--) {
            /* calculate qhat as a trial quotient digit: */
            phat = ((XP_digit2_t)U[i] << DIGIT_BITS) + (XP_digit2_t)U[i - 1];
            qhat = ((XP_digit2_t)U[i] == v1) ? DIGIT_LAST : phat/v1;
            while (v2*qhat > ((phat - v1*qhat) << DIGIT_BITS) + (XP_digit2_t)U[i - 2]) {
                qhat--;
            }
            /* multiply, subtract, and check result: */
            XP_ShortMul(t, V, vd, (XP_digit_t)qhat, ww); /* this sets t[vd] = 0 if necessary */
			toggle = (U + i - vd)[vd + 1]; // save the component that can be overwritten due to carry propagation
			z = XP_Sub(U + i - vd, U + i - vd, vd + 1, t, vd + 1);
			if (z > vd + 1) { // oops, negative carry went too far...
				qhat--;
                XP_Add(U + i - vd, U + i - vd, vd + 1, V, vd + 1);
				(U + i - vd)[vd + 1] = toggle; // restore the component overwritten by carry propagation
				/* probability of this happening: ~2/DIGIT_BASE */
            }
            if (q != NULL) {
                q[i - vd] = (XP_digit_t)qhat;
            }
        }
        /* evaluate the remainder: */
        if (r != NULL) {
            i = XP_ShortDiv(r, NULL, U, vd, d);
        }
        if (q != NULL) {
            i = ud - vd + 1;
            while (i > 0 && q[i - 1] == 0) {
                i--;
            }
        }
        return i; // NB: this is the quotient length unless q is NULL, in which case it is the remainder length
    }
}

/**
 * Compute an m-digit representative of u mod (2^{wm - g} - d), where w is the digit size in bits. It is required that d*2^g fit one digit.
 *
 * u = q*(2^w)^m + r = q*(2^{wm}) + r = q*(2^{wm - g + g}) + r = q*(2^{wm - g}*2^g) + r =
 * (q*2^g)*(2^{wm - g} - d + d) + r = (q*2^g)*(2^{wm - g} - d) + d*(q*2^g) + r.
 * :: u = (d*2^g)*q + r mod (2^{wm-g} - d)
 *
 * What if m is the plain _bit length_ instead?
 * u = q*2^m + r = q*(2^m - d) + q*d + r
 * :: u = q*d + r mod (2^m - d)
 */
short XP_QuasiMod(XP_digit_t *r, XP_digit_t *u, short ud,
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    //*
    short rd;
    short m = MAX_XP_DIGITS;
    short g = ((MAX_XP_BITS + 7) >> 3)*8 - MAX_XP_BITS;
    XP_digit_t d = XP_DELTA;
    assert((d << g) <= DIGIT_LAST); // s = d*2^g, u = s*q + r
    //printf("m = %d, g = %d, d = %d, d*2^g = %d, mod = 2^%d - %d = %0X\n", m, g, d, d << g, DIGIT_BITS*m - g, d, (1 << (DIGIT_BITS*m - g)) - d);
    assert(ud <= 2*m);

    rd = (ud >= m) ? m : ud;
    // 1st pass:
    //XP_Display("*** q", u + m, (ud >= m) ? ud - m : 0);
    //XP_Display("*** r", u, rd);
    //printf("*** d*2^g = %d\n", d << g);
    ud = XP_ShortMul(U, u + m, (ud >= m) ? ud - m : 0, d << g, ww); // U = s*q
    //XP_Display("(d*2^g)*q", U, ud);
    rd = XP_Add(r, U, ud, u, rd); // U = s*q + r
    //XP_Display("{1} (d*2^g)*q + r", r, rd);

    // 2nd pass:
    ud = XP_ShortMul(U, r + m, (rd >= m) ? rd - m : 0, d << g, ww); // U = s*q
    rd = XP_Add(r, U, ud, r, (rd >= m) ? m : rd); // U = s*q + r
    //XP_Display("{2} (d*2^g)*q + r", r, rd);

    ud = XP_SetDigit(U, 1);
    ud = XP_Lshift(U, U, ud, MAX_XP_BITS);
    ud = XP_Sub(U, U, ud, NULL, XP_DELTA);
    while (XP_Comp(r, rd, U, ud) >= 0) {
        rd = XP_Sub(r, r, rd, U, ud);
    }
    assert(rd <= m);

    return rd;
    /*/
    static XP_digit_t v[MAX_XP_DIGITS + 1], V[MAX_XP_DIGITS + 1], t[MAX_XP_DIGITS + 1];
    short vd;
    // fill v with 2^{wm - g} - d:
    vd = XP_SetDigit(v, 1); // v == 1
    vd = XP_Lshift(v, v, vd, DIGIT_BITS*m - g); // v == 2^{wm - g}
    vd = XP_Sub(v, v, vd, NULL, d); // v == 2^{wm - g} - d
    // compute the remainder the long way:
    return XP_Div(NULL, r, u, ud, v, vd, U, V, t, ww);
    //*/
}

#if 0
short XP_RandMod(XP_digit_t *x, short bits, XP_rand_dig_f rand_dig_f,
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short xd = XP_Rand(x, bits, rand_dig_f);
    xd = XP_QuasiMod(x, x, xd, U, ww);
    return xd;
}
#endif

/**
 *   Sets p = (u * v) mod m where m is the default modulus. Result length is d digits. Beware: w and t are scratch.
 *   Requires: p[0:d-1], u[0:d-1], v[0:d-1], x[0:2d-1],
 *             0 < md <= MAX_XP_DIGITS.
 */
short XP_ModMul(XP_digit_t *p, const XP_digit_t *u, short ud, const XP_digit_t *v, short vd,
        XP_digit_t X[2*MAX_XP_DIGITS + 1],
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short Xd, pd;
    Xd = XP_Mul(X, u, ud, v, vd, ww);
    pd = XP_QuasiMod(p, X, Xd, U, ww);
    return pd;
}

/**
 * Compute a^-1 mod m. Return 0 when a is not invertible.
 */
short XP_InvMod(XP_digit_t *inv, XP_digit_t *a, short ad, const XP_digit_t *m, short md,
        XP_digit_t b[MAX_XP_DIGITS + 1], XP_digit_t g[MAX_XP_DIGITS + 1], XP_digit_t c[MAX_XP_DIGITS + 1], XP_digit_t h[MAX_XP_DIGITS + 1],
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    //F := A; B := 1; G := M; C := 0; // X := 0; Y := 1;
    XP_digit_t *F = a; short Fd = ad;
    XP_digit_t *G = g; short Gd = md;
    XP_digit_t *B = b; short Bd;
    XP_digit_t *C = c; short Cd;
    XP_digit_t *T;
    XP_digit_t signB = 0;
    XP_digit_t signC = 0;
    XP_digit_t signT;
    short hd, td;

    XP_Clear(B, md);
    Bd = XP_SetDigit(B, 1); // B = 1
    XP_Clear(C, md);
    Cd = XP_SetDigit(C, 0); // C = 0
    XP_Copy(g, m, md);

    // ensure F < G initially:
    //XP_Display("F0  ", F, Fd);
    //XP_Display("G0  ", G, Gd);
    Fd = XP_Div(NULL, F, F, Fd, G, Gd, U, V, t, ww);
    //XP_Display("F mod G", F, Fd);
    assert(XP_Comp(F, Fd, G, Gd) < 0);
    while (Fd > 1 || (Fd == 1 && F[0] > 1)) { // F > 1
		// assert F < G
        T = F; F = G; G = T; hd = Fd; Fd = Gd; Gd = hd;
        T = B; B = C; C = T; hd = Bd; Bd = Cd; Cd = hd;
        // assert F > G
        assert(XP_Comp(F, Fd, G, Gd) > 0);
        signT = signB; signB = signC; signC = signT;
        // apply Euclid rule (subtract from the larger operand the largest possible multiple of the smaller operand):
        hd = XP_Div(h, NULL, F, Fd, G, Gd, U, V, t, ww); // h = F div G
        td = XP_Mul(t, h, hd, G, Gd, ww); // t = h*G
        //printf("# 1-\n");
        //XP_Display("F", F, Fd);
        //XP_Display("G", G, Gd);
        //XP_Display("h", h, hd);
        //XP_Display("t", t, td);
        Fd = XP_Sub(F, F, Fd, t, td);     // F = F - h*G
        //printf("# 1+\n");
        td = XP_Mul(t, h, hd, C, Cd, ww); // t = h*C
        // fact: |B| < M, |h*C| < M, |B - 8*C| < M
        // 4 cases:
        // signB eq 0, signC eq 0: if |B| gt |hC| then B := B - hC; else if |B| lt |hC| then B := hC - B; signB := 1; else B := 0; signB := 0; end if;
        // signB eq 0, signC eq 1: B := B + |hC|;
        // signB eq 1, signC eq 0: B := B + |hC|;
        // signB eq 1, singC eq 1: if |B| gt |hC| then B := B - hC; else if |B| lt |hC| then B := hC - B; signB := 0; else B := 0; signB := 0; end if;
        while (td < Bd) {
            t[td++] = 0;
        }
        while (Bd < td) {
            B[Bd++] = 0;
        }
        assert(Bd == td);
        if (signB == signC) {
            short cmp = XP_Comp(B, Bd, t, td);
            if (cmp > 0) {        // B > hC
                //printf("# 2-\n");
                Bd = XP_Sub(B, B, Bd, t, td); // B = B - hC
                //printf("# 2+\n");
                signB = signB;
            } else if (cmp < 0) { // B < hC
                //printf("# 3-\n");
                Bd = XP_Sub(B, t, td, B, Bd); // B = hC - B
                //printf("# 3+\n");
                signB = 1 - signB; // 0 <-> 1
            } else { // B = hC
                //printf("# 4-\n");
                Bd = XP_Sub(B, B, Bd, B, Bd); // B = 0
                //printf("# 4+\n");
                signB = 0;
            }
        } else {
            Bd = XP_Add(B, B, Bd, t, td); // B = B + hC
            signB = signB;
        }
    }
    if (Fd == 1 && F[0] == 1) { // F == 1
        if (signB == 1) {
            while (Bd < md) {
                B[Bd++] = 0; // TODO: check if this is really necessary
            }
            //printf("# 5-\n");
            Bd = XP_Sub(B, m, md, B, Bd); // B = M - B
            //printf("# 5+\n");
            //signB = 0;
        }
        // assert B*A mod M eq 1;
        Bd = XP_Digits(B, Bd); // TODO: check if this is really necessary
        XP_Copy(inv, B, Bd);
        return Bd;
    } else {
        //XP_Clear(inv, md); // not invertible
        return 0;
    }
}

/**
 * Sets e = (a^x) mod m.
 * Beware: A, z, w, t are scratch
 */
short XP_PowMod(XP_digit_t *e, const XP_digit_t *a, short ad, const XP_digit_t *x, short xd, const XP_digit_t *m, short md,
        XP_digit_t z[2*MAX_XP_DIGITS + 1],
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    // TODO: data-independent exponentiation (may not be necessary if limited to square root computation)
    short b, zd;
    //XP_Clear(z, md);
    zd = XP_SetDigit(z, 1); // z = 1
    for (b = DIGIT_BITS*xd - 1; b >= 0; b--) {
        zd = XP_Mul(z, z, zd, z, zd, ww);
        //zd = XP_Div(NULL, z, z, zd, m, md, U, V, t, ww);
        zd = XP_QuasiMod(z, z, zd, U, ww);
        if (XP_GetBit(x, b)) {
            zd = XP_Mul(z, z, zd, a, ad, ww);
            //zd = XP_Div(NULL, z, z, zd, m, md, U, V, t, ww);
            zd = XP_QuasiMod(z, z, zd, U, ww);
        }
    }
    return XP_Copy(e, z, zd);
}

/**
 * Compute a square root of v (mod p).
 *
 * @return  a square root of v (mod p) if one exists, or null otherwise.
 */
short XP_Sqrt(XP_digit_t *r, XP_digit_t *v, short vd, const XP_digit_t *p, short pd,
        XP_digit_t x[MAX_XP_DIGITS + 1], XP_digit_t A[2 * MAX_XP_DIGITS + 1], XP_digit_t g[MAX_XP_DIGITS + 1],
#if (XP_DELTA%4 != 1)
        XP_digit_t gamma[MAX_XP_DIGITS + 1],
#endif
        XP_digit_t U[2*MAX_XP_DIGITS + 1], XP_digit_t V[MAX_XP_DIGITS + 1], XP_digit_t t[MAX_XP_DIGITS + 1], XP_digit_t ww[2*MAX_XP_DIGITS + 1]) {
    short rd, gd,
#if (XP_DELTA%4 != 1)
        Ad, gammad,
#endif
        xd;
    if (vd == 0) {
        XP_Clear(r, vd);
        return 0;
    }
    // TODO: compute the exponent directly rather than from a parameter
#if (XP_DELTA%4 == 1)
    assert((p[0] & 0x3) == 3);
    // case I: p = 3 (mod 4):
    // prepare exponent x = (p + 1)/4 = (p div 4) + 1:
    xd = XP_Rshift(x, p, pd, 2); // x == p div 4
    xd = XP_Add(x, x, xd, NULL, 1); // x = (p div 4) + 1 = (p + 1)/4
    gd = XP_PowMod(g, v, vd, x, xd, p, pd, A, U, V, t, ww); // g = v^{(p + 1)/4} mod p
#else
    assert((p[0] & 0x7) == 5);
    // TODO: fast modular reduction
    // case II: p = 5 (mod 8):
    gd = XP_Lshift(g, v, vd, 1); // g == 2v
    gd = XP_Div(NULL, g, g, gd, p, pd, U, V, t, ww); // g = g mod p = (2v mod p)
    xd = XP_Rshift(x, p, pd, 3); // x == p div 8
    gammad = XP_PowMod(gamma, g, gd, x, xd, p, pd, A, U, V, t, ww); // gamma == g^{p div 8} mod p
    Ad = XP_Mul(A, gamma, gammad, gamma, gammad, ww); // A = (gamma * gamma)
    Ad = XP_Div(NULL, A, A, Ad, p, pd, U, V, t, ww); // A = A mod m = gamma^2 mod p
    Ad = XP_Mul(A, A, Ad, g, gd, ww); // A = g*(gamma^2 mod p)
    Ad = XP_Div(NULL, A, A, Ad, p, pd, U, V, t, ww); // A = A mod m = (g*gamma^2) mod p
    Ad = XP_Sub(A, A, Ad, NULL, 1); // A = i - 1
    Ad = XP_Mul(A, A, Ad, gamma, gammad, ww); // A = A*gamma
    Ad = XP_Div(NULL, A, A, Ad, p, pd, U, V, t, ww); // A = A mod p
    Ad = XP_Mul(A, A, Ad, v, vd, ww); // A = A*v
    gd = XP_Div(NULL, g, A, Ad, p, pd, U, V, t, ww); // g = A mod p
#endif
    // test solution:
    xd = XP_ModMul(x, g, gd, g, gd, A, U, V, t, ww); // x = g^2 mod p
    if (XP_Comp(x, xd, v, vd) == 0) {
        rd = XP_Copy(r, g, gd);
    }
    else {
        rd = -1;
    }
    return rd;
}
