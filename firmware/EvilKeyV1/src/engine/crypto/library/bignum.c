#include "../../../pf_build_config.h"
/*
 *  Multi-precision integer library
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 *  The following sources were referenced in the design of this Multi-precision
 *  Integer library:
 *
 *  [1] Handbook of Applied Cryptography - 1997
 *      Menezes, van Oorschot and Vanstone
 *
 *  [2] Multi-Precision Math
 *      Tom St Denis
 *      https://github.com/libtom/libtommath/blob/develop/tommath.pdf
 *
 *  [3] GNU Multi-Precision Arithmetic Library
 *      https://gmplib.org/manual/index.html
 *
 */

#include "common.h"

#if defined(PF_MBEDTLS_BIGNUM_C)

#include "../include/mbedtls/bignum.h"
#include "bignum_core.h"
#include "bignum_internal.h"
#include "bn_mul.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#include "constant_time_internal.h"

#include <limits.h>
#include <string.h>

#include "../include/mbedtls/platform.h"



/*
 * Conditionally select an MPI sign in constant time.
 * (MPI sign is the field s in mbedtls_mpi. It is unsigned short and only 1 and -1 are valid
 * values.)
 */
static inline signed short pf_mbedtls_ct_mpi_sign_if(pf_mbedtls_ct_condition_t cond,
                                                  signed short sign1, signed short sign2)
{
    return (signed short) pf_mbedtls_ct_uint_if(cond, sign1 + 1, sign2 + 1) - 1;
}

/*
 * Compare signed values in constant time
 */
int pf_mbedtls_mpi_lt_mpi_ct(const pf_mbedtls_mpi *X,
                          const pf_mbedtls_mpi *Y,
                          unsigned *ret)
{
    pf_mbedtls_ct_condition_t different_sign, X_is_negative, Y_is_negative, result;

    if (X->n != Y->n) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /*
     * Set N_is_negative to MBEDTLS_CT_FALSE if N >= 0, MBEDTLS_CT_TRUE if N < 0.
     * We know that N->s == 1 if N >= 0 and N->s == -1 if N < 0.
     */
    X_is_negative = pf_mbedtls_ct_bool((X->s & 2) >> 1);
    Y_is_negative = pf_mbedtls_ct_bool((Y->s & 2) >> 1);

    /*
     * If the signs are different, then the positive operand is the bigger.
     * That is if X is negative (X_is_negative == 1), then X < Y is true and it
     * is false if X is positive (X_is_negative == 0).
     */
    different_sign = pf_mbedtls_ct_bool_ne(X_is_negative, Y_is_negative); // true if different sign
    result = pf_mbedtls_ct_bool_and(different_sign, X_is_negative);

    /*
     * Assuming signs are the same, compare X and Y. We switch the comparison
     * order if they are negative so that we get the right result, regardles of
     * sign.
     */

    /* This array is used to conditionally swap the pointers in const time */
    void * const p[2] = { X->p, Y->p };
    size_t i = pf_mbedtls_ct_size_if_else_0(X_is_negative, 1);
    pf_mbedtls_ct_condition_t lt = pf_mbedtls_mpi_core_lt_ct(p[i], p[i ^ 1], X->n);

    /*
     * Store in result iff the signs are the same (i.e., iff different_sign == false). If
     * the signs differ, result has already been set, so we don't change it.
     */
    result = pf_mbedtls_ct_bool_or(result,
                                pf_mbedtls_ct_bool_and(pf_mbedtls_ct_bool_not(different_sign), lt));

    *ret = pf_mbedtls_ct_uint_if_else_0(result, 1);

    return 0;
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
#if defined(_MSC_VER) && defined(PF_MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64) && \
    (_MSC_FULL_VER < 193131103)
/*
 * MSVC miscompiles this function if it's inlined prior to Visual Studio 2022 version 17.1. See:
 * https://developercommunity.visualstudio.com/t/c-compiler-miscompiles-part-of-mbedtls-library-on/1646989
 */
__declspec(noinline)
#endif
int pf_mbedtls_mpi_safe_cond_assign(pf_mbedtls_mpi *X,
                                 const pf_mbedtls_mpi *Y,
                                 unsigned char assign)
{
    int ret = 0;

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, Y->n));

    {
        pf_mbedtls_ct_condition_t do_assign = pf_mbedtls_ct_bool(assign);

        X->s = pf_mbedtls_ct_mpi_sign_if(do_assign, Y->s, X->s);

        pf_mbedtls_mpi_core_cond_assign(X->p, Y->p, Y->n, do_assign);

        pf_mbedtls_ct_condition_t do_not_assign = pf_mbedtls_ct_bool_not(do_assign);
        for (size_t i = Y->n; i < X->n; i++) {
            X->p[i] = pf_mbedtls_ct_mpi_uint_if_else_0(do_not_assign, X->p[i]);
        }
    }

cleanup:
    return ret;
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which would lead to
 * different memory access patterns when X and Y are used afterwards.
 */
int pf_mbedtls_mpi_safe_cond_swap(pf_mbedtls_mpi *X,
                               pf_mbedtls_mpi *Y,
                               unsigned char swap)
{
    int ret = 0;
    int s;

    if (X == Y) {
        return 0;
    }

    pf_mbedtls_ct_condition_t do_swap = pf_mbedtls_ct_bool(swap);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, Y->n));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(Y, X->n));

    s = X->s;
    X->s = pf_mbedtls_ct_mpi_sign_if(do_swap, Y->s, X->s);
    Y->s = pf_mbedtls_ct_mpi_sign_if(do_swap, s, Y->s);

    pf_mbedtls_mpi_core_cond_swap(X->p, Y->p, X->n, do_swap);

cleanup:
    return ret;
}

/* Implementation that should never be optimized out by the compiler */
#define pf_mbedtls_mpi_zeroize_and_free(v, n) pf_mbedtls_zeroize_and_free(v, ciL * (n))

/*
 * Initialize one MPI
 */
void pf_mbedtls_mpi_init(pf_mbedtls_mpi *X)
{
    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void pf_mbedtls_mpi_free(pf_mbedtls_mpi *X)
{
    if (X == NULL) {
        return;
    }

    if (X->p != NULL) {
        pf_mbedtls_mpi_zeroize_and_free(X->p, X->n);
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
int pf_mbedtls_mpi_grow(pf_mbedtls_mpi *X, size_t nblimbs)
{
    pf_mbedtls_mpi_uint *p;

    if (nblimbs > PF_MBEDTLS_MPI_MAX_LIMBS) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    if (X->n < nblimbs) {
        if ((p = (pf_mbedtls_mpi_uint *) pf_mbedtls_calloc(nblimbs, ciL)) == NULL) {
            return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
        }

        if (X->p != NULL) {
            memcpy(p, X->p, X->n * ciL);
            pf_mbedtls_mpi_zeroize_and_free(X->p, X->n);
        }

        /* nblimbs fits in n because we ensure that MBEDTLS_MPI_MAX_LIMBS
         * fits, and we've checked that nblimbs <= MBEDTLS_MPI_MAX_LIMBS. */
        X->n = (unsigned short) nblimbs;
        X->p = p;
    }

    return 0;
}

/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
int pf_mbedtls_mpi_shrink(pf_mbedtls_mpi *X, size_t nblimbs)
{
    pf_mbedtls_mpi_uint *p;
    size_t i;

    if (nblimbs > PF_MBEDTLS_MPI_MAX_LIMBS) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    /* Actually resize up if there are currently fewer than nblimbs limbs. */
    if (X->n <= nblimbs) {
        return pf_mbedtls_mpi_grow(X, nblimbs);
    }
    /* After this point, then X->n > nblimbs and in particular X->n > 0. */

    for (i = X->n - 1; i > 0; i--) {
        if (X->p[i] != 0) {
            break;
        }
    }
    i++;

    if (i < nblimbs) {
        i = nblimbs;
    }

    if ((p = (pf_mbedtls_mpi_uint *) pf_mbedtls_calloc(i, ciL)) == NULL) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    if (X->p != NULL) {
        memcpy(p, X->p, i * ciL);
        pf_mbedtls_mpi_zeroize_and_free(X->p, X->n);
    }

    /* i fits in n because we ensure that MBEDTLS_MPI_MAX_LIMBS
     * fits, and we've checked that i <= nblimbs <= MBEDTLS_MPI_MAX_LIMBS. */
    X->n = (unsigned short) i;
    X->p = p;

    return 0;
}

/* Resize X to have exactly n limbs and set it to 0. */
static int pf_mbedtls_mpi_resize_clear(pf_mbedtls_mpi *X, size_t limbs)
{
    if (limbs == 0) {
        pf_mbedtls_mpi_free(X);
        return 0;
    } else if (X->n == limbs) {
        memset(X->p, 0, limbs * ciL);
        X->s = 1;
        return 0;
    } else {
        pf_mbedtls_mpi_free(X);
        return pf_mbedtls_mpi_grow(X, limbs);
    }
}

/*
 * Copy the contents of Y into X.
 *
 * This function is not constant-time. Leading zeros in Y may be removed.
 *
 * Ensure that X does not shrink. This is not guaranteed by the public API,
 * but some code in the bignum module might still rely on this property.
 */
int pf_mbedtls_mpi_copy(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *Y)
{
    int ret = 0;
    size_t i;

    if (X == Y) {
        return 0;
    }

    if (Y->n == 0) {
        if (X->n != 0) {
            X->s = 1;
            memset(X->p, 0, X->n * ciL);
        }
        return 0;
    }

    for (i = Y->n - 1; i > 0; i--) {
        if (Y->p[i] != 0) {
            break;
        }
    }
    i++;

    X->s = Y->s;

    if (X->n < i) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, i));
    } else {
        memset(X->p + i, 0, (X->n - i) * ciL);
    }

    memcpy(X->p, Y->p, i * ciL);

cleanup:

    return ret;
}

/*
 * Swap the contents of X and Y
 */
void pf_mbedtls_mpi_swap(pf_mbedtls_mpi *X, pf_mbedtls_mpi *Y)
{
    pf_mbedtls_mpi T;

    memcpy(&T,  X, sizeof(pf_mbedtls_mpi));
    memcpy(X,  Y, sizeof(pf_mbedtls_mpi));
    memcpy(Y, &T, sizeof(pf_mbedtls_mpi));
}

static inline pf_mbedtls_mpi_uint mpi_sint_abs(pf_mbedtls_mpi_sint z)
{
    if (z >= 0) {
        return z;
    }
    /* Take care to handle the most negative value (-2^(biL-1)) correctly.
     * A naive -z would have undefined behavior.
     * Write this in a way that makes popular compilers happy (GCC, Clang,
     * MSVC). */
    return (pf_mbedtls_mpi_uint) 0 - (pf_mbedtls_mpi_uint) z;
}

/* Convert x to a sign, i.e. to 1, if x is positive, or -1, if x is negative.
 * This looks awkward but generates smaller code than (x < 0 ? -1 : 1) */
#define TO_SIGN(x) ((pf_mbedtls_mpi_sint) (((pf_mbedtls_mpi_uint) x) >> (biL - 1)) * -2 + 1)

/*
 * Set value from integer
 */
int pf_mbedtls_mpi_lset(pf_mbedtls_mpi *X, pf_mbedtls_mpi_sint z)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, 1));
    memset(X->p, 0, X->n * ciL);

    X->p[0] = mpi_sint_abs(z);
    X->s    = TO_SIGN(z);

cleanup:

    return ret;
}

/*
 * Get a specific bit
 */
int pf_mbedtls_mpi_get_bit(const pf_mbedtls_mpi *X, size_t pos)
{
    if (X->n * biL <= pos) {
        return 0;
    }

    return (X->p[pos / biL] >> (pos % biL)) & 0x01;
}

/*
 * Set a bit to a specific value of 0 or 1
 */
int pf_mbedtls_mpi_set_bit(pf_mbedtls_mpi *X, size_t pos, unsigned char val)
{
    int ret = 0;
    size_t off = pos / biL;
    size_t idx = pos % biL;

    if (val != 0 && val != 1) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (X->n * biL <= pos) {
        if (val == 0) {
            return 0;
        }

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, off + 1));
    }

    X->p[off] &= ~((pf_mbedtls_mpi_uint) 0x01 << idx);
    X->p[off] |= (pf_mbedtls_mpi_uint) val << idx;

cleanup:

    return ret;
}

#if defined(__has_builtin)
#if (PF_MBEDTLS_MPI_UINT_MAX == UINT_MAX) && __has_builtin(__builtin_ctz)
    #define pf_mbedtls_mpi_uint_ctz __builtin_ctz
#elif (PF_MBEDTLS_MPI_UINT_MAX == ULONG_MAX) && __has_builtin(__builtin_ctzl)
    #define pf_mbedtls_mpi_uint_ctz __builtin_ctzl
#elif (PF_MBEDTLS_MPI_UINT_MAX == ULLONG_MAX) && __has_builtin(__builtin_ctzll)
    #define pf_mbedtls_mpi_uint_ctz __builtin_ctzll
#endif
#endif

#if !defined(pf_mbedtls_mpi_uint_ctz)
static size_t pf_mbedtls_mpi_uint_ctz(pf_mbedtls_mpi_uint x)
{
    size_t count = 0;
    pf_mbedtls_ct_condition_t done = PF_MBEDTLS_CT_FALSE;

    for (size_t i = 0; i < biL; i++) {
        pf_mbedtls_ct_condition_t non_zero = pf_mbedtls_ct_bool((x >> i) & 1);
        done = pf_mbedtls_ct_bool_or(done, non_zero);
        count = pf_mbedtls_ct_size_if(done, count, i + 1);
    }

    return count;
}
#endif

/*
 * Return the number of less significant zero-bits
 */
size_t pf_mbedtls_mpi_lsb(const pf_mbedtls_mpi *X)
{
    size_t i;

    for (i = 0; i < X->n; i++) {
        if (X->p[i] != 0) {
            return i * biL + pf_mbedtls_mpi_uint_ctz(X->p[i]);
        }
    }

    return 0;
}

/*
 * Return the number of bits
 */
size_t pf_mbedtls_mpi_bitlen(const pf_mbedtls_mpi *X)
{
    return pf_mbedtls_mpi_core_bitlen(X->p, X->n);
}

/*
 * Return the total size in bytes
 */
size_t pf_mbedtls_mpi_size(const pf_mbedtls_mpi *X)
{
    return (pf_mbedtls_mpi_bitlen(X) + 7) >> 3;
}

/*
 * Convert an ASCII character to digit value
 */
static int mpi_get_digit(pf_mbedtls_mpi_uint *d, int radix, char c)
{
    *d = 255;

    if (c >= 0x30 && c <= 0x39) {
        *d = c - 0x30;
    }
    if (c >= 0x41 && c <= 0x46) {
        *d = c - 0x37;
    }
    if (c >= 0x61 && c <= 0x66) {
        *d = c - 0x57;
    }

    if (*d >= (pf_mbedtls_mpi_uint) radix) {
        return PF_MBEDTLS_ERR_MPI_INVALID_CHARACTER;
    }

    return 0;
}

/*
 * Import from an ASCII string
 */
int pf_mbedtls_mpi_read_string(pf_mbedtls_mpi *X, int radix, const char *s)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j, slen, n;
    int sign = 1;
    pf_mbedtls_mpi_uint d;
    pf_mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&T);

    if (s[0] == 0) {
        pf_mbedtls_mpi_free(X);
        return 0;
    }

    if (s[0] == '-') {
        ++s;
        sign = -1;
    }

    slen = strlen(s);

    if (radix == 16) {
        if (slen > SIZE_MAX >> 2) {
            return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        n = BITS_TO_LIMBS(slen << 2);

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, n));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(X, 0));

        for (i = slen, j = 0; i > 0; i--, j++) {
            PF_MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i - 1]));
            X->p[j / (2 * ciL)] |= d << ((j % (2 * ciL)) << 2);
        }
    } else {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(X, 0));

        for (i = 0; i < slen; i++) {
            PF_MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i]));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_int(&T, X, radix));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(X, &T, d));
        }
    }

    if (sign < 0 && pf_mbedtls_mpi_bitlen(X) != 0) {
        X->s = -1;
    }

cleanup:

    pf_mbedtls_mpi_free(&T);

    return ret;
}

/*
 * Helper to write the digits high-order first.
 */
static int mpi_write_hlp(pf_mbedtls_mpi *X, int radix,
                         char **p, const size_t buflen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi_uint r;
    size_t length = 0;
    char *p_end = *p + buflen;

    do {
        if (length >= buflen) {
            return PF_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
        }

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_int(&r, X, radix));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_div_int(X, NULL, X, radix));
        /*
         * Write the residue in the current position, as an ASCII character.
         */
        if (r < 0xA) {
            *(--p_end) = (char) ('0' + r);
        } else {
            *(--p_end) = (char) ('A' + (r - 0xA));
        }

        length++;
    } while (pf_mbedtls_mpi_cmp_int(X, 0) != 0);

    memmove(*p, p_end, length);
    *p += length;

cleanup:

    return ret;
}

/*
 * Export into an ASCII string
 */
int pf_mbedtls_mpi_write_string(const pf_mbedtls_mpi *X, int radix,
                             char *buf, size_t buflen, size_t *olen)
{
    int ret = 0;
    size_t n;
    char *p;
    pf_mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    n = pf_mbedtls_mpi_bitlen(X);   /* Number of bits necessary to present `n`. */
    if (radix >=  4) {
        n >>= 1;                 /* Number of 4-adic digits necessary to present
                                  * `n`. If radix > 4, this might be a strict
                                  * overapproximation of the number of
                                  * radix-adic digits needed to present `n`. */
    }
    if (radix >= 16) {
        n >>= 1;                 /* Number of hexadecimal digits necessary to
                                  * present `n`. */

    }
    n += 1; /* Terminating null byte */
    n += 1; /* Compensate for the divisions above, which round down `n`
             * in case it's not even. */
    n += 1; /* Potential '-'-sign. */
    n += (n & 1);   /* Make n even to have enough space for hexadecimal writing,
                     * which always uses an even number of hex-digits. */

    if (buflen < n) {
        *olen = n;
        return PF_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }

    p = buf;
    pf_mbedtls_mpi_init(&T);

    if (X->s == -1) {
        *p++ = '-';
        buflen--;
    }

    if (radix == 16) {
        int c;
        size_t i, j, k;

        for (i = X->n, k = 0; i > 0; i--) {
            for (j = ciL; j > 0; j--) {
                c = (X->p[i - 1] >> ((j - 1) << 3)) & 0xFF;

                if (c == 0 && k == 0 && (i + j) != 2) {
                    continue;
                }

                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
    } else {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&T, X));

        if (T.s == -1) {
            T.s = 1;
        }

        PF_MBEDTLS_MPI_CHK(mpi_write_hlp(&T, radix, &p, buflen));
    }

    *p++ = '\0';
    *olen = (size_t) (p - buf);

cleanup:

    pf_mbedtls_mpi_free(&T);

    return ret;
}

#if defined(PF_MBEDTLS_FS_IO)
/*
 * Read X from an opened file
 */
int pf_mbedtls_mpi_read_file(pf_mbedtls_mpi *X, int radix, FILE *fin)
{
    pf_mbedtls_mpi_uint d;
    size_t slen;
    char *p;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[PF_MBEDTLS_MPI_RW_BUFFER_SIZE];

    if (radix < 2 || radix > 16) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    memset(s, 0, sizeof(s));
    if (fgets(s, sizeof(s) - 1, fin) == NULL) {
        return PF_MBEDTLS_ERR_MPI_FILE_IO_ERROR;
    }

    slen = strlen(s);
    if (slen == sizeof(s) - 2) {
        return PF_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }

    if (slen > 0 && s[slen - 1] == '\n') {
        slen--; s[slen] = '\0';
    }
    if (slen > 0 && s[slen - 1] == '\r') {
        slen--; s[slen] = '\0';
    }

    p = s + slen;
    while (p-- > s) {
        if (mpi_get_digit(&d, radix, *p) != 0) {
            break;
        }
    }

    return pf_mbedtls_mpi_read_string(X, radix, p + 1);
}

/*
 * Write X into an opened file (or stdout if fout == NULL)
 */
int pf_mbedtls_mpi_write_file(const char *p, const pf_mbedtls_mpi *X, int radix, FILE *fout)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n, slen, plen;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[PF_MBEDTLS_MPI_RW_BUFFER_SIZE];

    if (radix < 2 || radix > 16) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    memset(s, 0, sizeof(s));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_string(X, radix, s, sizeof(s) - 2, &n));

    if (p == NULL) {
        p = "";
    }

    plen = strlen(p);
    slen = strlen(s);
    s[slen++] = '\r';
    s[slen++] = '\n';

    if (fout != NULL) {
        if (fwrite(p, 1, plen, fout) != plen ||
            fwrite(s, 1, slen, fout) != slen) {
            return PF_MBEDTLS_ERR_MPI_FILE_IO_ERROR;
        }
    } else {
        pf_mbedtls_printf("%s%s", p, s);
    }

cleanup:

    return ret;
}
#endif /* MBEDTLS_FS_IO */

/*
 * Import X from unsigned binary data, little endian
 *
 * This function is guaranteed to return an MPI with exactly the necessary
 * number of limbs (in particular, it does not skip 0s in the input).
 */
int pf_mbedtls_mpi_read_binary_le(pf_mbedtls_mpi *X,
                               const unsigned char *buf, size_t buflen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t limbs = CHARS_TO_LIMBS(buflen);

    /* Ensure that target MPI has exactly the necessary number of limbs */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_resize_clear(X, limbs));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_core_read_le(X->p, X->n, buf, buflen));

cleanup:

    /*
     * This function is also used to import keys. However, wiping the buffers
     * upon failure is not necessary because failure only can happen before any
     * input is copied.
     */
    return ret;
}

/*
 * Import X from unsigned binary data, big endian
 *
 * This function is guaranteed to return an MPI with exactly the necessary
 * number of limbs (in particular, it does not skip 0s in the input).
 */
int pf_mbedtls_mpi_read_binary(pf_mbedtls_mpi *X, const unsigned char *buf, size_t buflen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t limbs = CHARS_TO_LIMBS(buflen);

    /* Ensure that target MPI has exactly the necessary number of limbs */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_resize_clear(X, limbs));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_core_read_be(X->p, X->n, buf, buflen));

cleanup:

    /*
     * This function is also used to import keys. However, wiping the buffers
     * upon failure is not necessary because failure only can happen before any
     * input is copied.
     */
    return ret;
}

/*
 * Export X into unsigned binary data, little endian
 */
int pf_mbedtls_mpi_write_binary_le(const pf_mbedtls_mpi *X,
                                unsigned char *buf, size_t buflen)
{
    return pf_mbedtls_mpi_core_write_le(X->p, X->n, buf, buflen);
}

/*
 * Export X into unsigned binary data, big endian
 */
int pf_mbedtls_mpi_write_binary(const pf_mbedtls_mpi *X,
                             unsigned char *buf, size_t buflen)
{
    return pf_mbedtls_mpi_core_write_be(X->p, X->n, buf, buflen);
}

/*
 * Left-shift: X <<= count
 */
int pf_mbedtls_mpi_shift_l(pf_mbedtls_mpi *X, size_t count)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;

    i = pf_mbedtls_mpi_bitlen(X) + count;

    if (X->n * biL < i) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, BITS_TO_LIMBS(i)));
    }

    ret = 0;

    pf_mbedtls_mpi_core_shift_l(X->p, X->n, count);
cleanup:

    return ret;
}

/*
 * Right-shift: X >>= count
 */
int pf_mbedtls_mpi_shift_r(pf_mbedtls_mpi *X, size_t count)
{
    if (X->n != 0) {
        pf_mbedtls_mpi_core_shift_r(X->p, X->n, count);
    }
    return 0;
}

/*
 * Compare unsigned values
 */
int pf_mbedtls_mpi_cmp_abs(const pf_mbedtls_mpi *X, const pf_mbedtls_mpi *Y)
{
    size_t i, j;

    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0) {
            break;
        }
    }

    for (j = Y->n; j > 0; j--) {
        if (Y->p[j - 1] != 0) {
            break;
        }
    }

    /* If i == j == 0, i.e. abs(X) == abs(Y),
     * we end up returning 0 at the end of the function. */

    if (i > j) {
        return 1;
    }
    if (j > i) {
        return -1;
    }

    for (; i > 0; i--) {
        if (X->p[i - 1] > Y->p[i - 1]) {
            return 1;
        }
        if (X->p[i - 1] < Y->p[i - 1]) {
            return -1;
        }
    }

    return 0;
}

/*
 * Compare signed values
 */
int pf_mbedtls_mpi_cmp_mpi(const pf_mbedtls_mpi *X, const pf_mbedtls_mpi *Y)
{
    size_t i, j;

    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0) {
            break;
        }
    }

    for (j = Y->n; j > 0; j--) {
        if (Y->p[j - 1] != 0) {
            break;
        }
    }

    if (i == 0 && j == 0) {
        return 0;
    }

    if (i > j) {
        return X->s;
    }
    if (j > i) {
        return -Y->s;
    }

    if (X->s > 0 && Y->s < 0) {
        return 1;
    }
    if (Y->s > 0 && X->s < 0) {
        return -1;
    }

    for (; i > 0; i--) {
        if (X->p[i - 1] > Y->p[i - 1]) {
            return X->s;
        }
        if (X->p[i - 1] < Y->p[i - 1]) {
            return -X->s;
        }
    }

    return 0;
}

/*
 * Compare signed values
 */
int pf_mbedtls_mpi_cmp_int(const pf_mbedtls_mpi *X, pf_mbedtls_mpi_sint z)
{
    pf_mbedtls_mpi Y;
    pf_mbedtls_mpi_uint p[1];

    *p  = mpi_sint_abs(z);
    Y.s = TO_SIGN(z);
    Y.n = 1;
    Y.p = p;

    return pf_mbedtls_mpi_cmp_mpi(X, &Y);
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int pf_mbedtls_mpi_add_abs(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t j;
    pf_mbedtls_mpi_uint *p;
    pf_mbedtls_mpi_uint c;

    if (X == B) {
        const pf_mbedtls_mpi *T = A; A = X; B = T;
    }

    if (X != A) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(X, A));
    }

    /*
     * X must always be positive as a result of unsigned additions.
     */
    X->s = 1;

    for (j = B->n; j > 0; j--) {
        if (B->p[j - 1] != 0) {
            break;
        }
    }

    /* Exit early to avoid undefined behavior on NULL+0 when X->n == 0
     * and B is 0 (of any size). */
    if (j == 0) {
        return 0;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, j));

    /* j is the number of non-zero limbs of B. Add those to X. */

    p = X->p;

    c = pf_mbedtls_mpi_core_add(p, p, B->p, j);

    p += j;

    /* Now propagate any carry */

    while (c != 0) {
        if (j >= X->n) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, j + 1));
            p = X->p + j;
        }

        *p += c; c = (*p < c); j++; p++;
    }

cleanup:

    return ret;
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9, 14.10)
 */
int pf_mbedtls_mpi_sub_abs(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    pf_mbedtls_mpi_uint carry;

    for (n = B->n; n > 0; n--) {
        if (B->p[n - 1] != 0) {
            break;
        }
    }
    if (n > A->n) {
        /* B >= (2^ciL)^n > A */
        ret = PF_MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
        goto cleanup;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, A->n));

    /* Set the high limbs of X to match A. Don't touch the lower limbs
     * because X might be aliased to B, and we must not overwrite the
     * significant digits of B. */
    if (A->n > n && A != X) {
        memcpy(X->p + n, A->p + n, (A->n - n) * ciL);
    }
    if (X->n > A->n) {
        memset(X->p + A->n, 0, (X->n - A->n) * ciL);
    }

    carry = pf_mbedtls_mpi_core_sub(X->p, A->p, B->p, n);
    if (carry != 0) {
        /* Propagate the carry through the rest of X. */
        carry = pf_mbedtls_mpi_core_sub_int(X->p + n, X->p + n, carry, X->n - n);

        /* If we have further carry/borrow, the result is negative. */
        if (carry != 0) {
            ret = PF_MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
            goto cleanup;
        }
    }

    /* X should always be positive as a result of unsigned subtractions. */
    X->s = 1;

cleanup:
    return ret;
}

/* Common function for signed addition and subtraction.
 * Calculate A + B * flip_B where flip_B is 1 or -1.
 */
static int add_sub_mpi(pf_mbedtls_mpi *X,
                       const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B,
                       int flip_B)
{
    int ret, s;

    s = A->s;
    if (A->s * B->s * flip_B < 0) {
        int cmp = pf_mbedtls_mpi_cmp_abs(A, B);
        if (cmp >= 0) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_abs(X, A, B));
            /* If |A| = |B|, the result is 0 and we must set the sign bit
             * to +1 regardless of which of A or B was negative. Otherwise,
             * since |A| > |B|, the sign is the sign of A. */
            X->s = cmp == 0 ? 1 : s;
        } else {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_abs(X, B, A));
            /* Since |A| < |B|, the sign is the opposite of A. */
            X->s = -s;
        }
    } else {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_abs(X, A, B));
        X->s = s;
    }

cleanup:

    return ret;
}

/*
 * Signed addition: X = A + B
 */
int pf_mbedtls_mpi_add_mpi(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    return add_sub_mpi(X, A, B, 1);
}

/*
 * Signed subtraction: X = A - B
 */
int pf_mbedtls_mpi_sub_mpi(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    return add_sub_mpi(X, A, B, -1);
}

/*
 * Signed addition: X = A + b
 */
int pf_mbedtls_mpi_add_int(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, pf_mbedtls_mpi_sint b)
{
    pf_mbedtls_mpi B;
    pf_mbedtls_mpi_uint p[1];

    p[0] = mpi_sint_abs(b);
    B.s = TO_SIGN(b);
    B.n = 1;
    B.p = p;

    return pf_mbedtls_mpi_add_mpi(X, A, &B);
}

/*
 * Signed subtraction: X = A - b
 */
int pf_mbedtls_mpi_sub_int(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, pf_mbedtls_mpi_sint b)
{
    pf_mbedtls_mpi B;
    pf_mbedtls_mpi_uint p[1];

    p[0] = mpi_sint_abs(b);
    B.s = TO_SIGN(b);
    B.n = 1;
    B.p = p;

    return pf_mbedtls_mpi_sub_mpi(X, A, &B);
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int pf_mbedtls_mpi_mul_mpi(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j;
    pf_mbedtls_mpi TA, TB;
    int result_is_zero = 0;

    pf_mbedtls_mpi_init(&TA);
    pf_mbedtls_mpi_init(&TB);

    if (X == A) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&TA, A)); A = &TA;
    }
    if (X == B) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&TB, B)); B = &TB;
    }

    for (i = A->n; i > 0; i--) {
        if (A->p[i - 1] != 0) {
            break;
        }
    }
    if (i == 0) {
        result_is_zero = 1;
    }

    for (j = B->n; j > 0; j--) {
        if (B->p[j - 1] != 0) {
            break;
        }
    }
    if (j == 0) {
        result_is_zero = 1;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, i + j));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(X, 0));

    pf_mbedtls_mpi_core_mul(X->p, A->p, i, B->p, j);

    /* If the result is 0, we don't shortcut the operation, which reduces
     * but does not eliminate side channels leaking the zero-ness. We do
     * need to take care to set the sign bit properly since the library does
     * not fully support an MPI object with a value of 0 and s == -1. */
    if (result_is_zero) {
        X->s = 1;
    } else {
        X->s = A->s * B->s;
    }

cleanup:

    pf_mbedtls_mpi_free(&TB); pf_mbedtls_mpi_free(&TA);

    return ret;
}

/*
 * Baseline multiplication: X = A * b
 */
int pf_mbedtls_mpi_mul_int(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, pf_mbedtls_mpi_uint b)
{
    size_t n = A->n;
    while (n > 0 && A->p[n - 1] == 0) {
        --n;
    }

    /* The general method below doesn't work if b==0. */
    if (b == 0 || n == 0) {
        return pf_mbedtls_mpi_lset(X, 0);
    }

    /* Calculate A*b as A + A*(b-1) to take advantage of mbedtls_mpi_core_mla */
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* In general, A * b requires 1 limb more than b. If
     * A->p[n - 1] * b / b == A->p[n - 1], then A * b fits in the same
     * number of limbs as A and the call to grow() is not required since
     * copy() will take care of the growth if needed. However, experimentally,
     * making the call to grow() unconditional causes slightly fewer
     * calls to calloc() in ECP code, presumably because it reuses the
     * same mpi for a while and this way the mpi is more likely to directly
     * grow to its final size.
     *
     * Note that calculating A*b as 0 + A*b doesn't work as-is because
     * A,X can be the same. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, n + 1));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(X, A));
    pf_mbedtls_mpi_core_mla(X->p, X->n, A->p, n, b - 1);

cleanup:
    return ret;
}

/*
 * Unsigned integer divide - double mbedtls_mpi_uint dividend, u1/u0, and
 * mbedtls_mpi_uint divisor, d
 */
static pf_mbedtls_mpi_uint pf_mbedtls_int_div_int(pf_mbedtls_mpi_uint u1,
                                            pf_mbedtls_mpi_uint u0,
                                            pf_mbedtls_mpi_uint d,
                                            pf_mbedtls_mpi_uint *r)
{
#if defined(PF_MBEDTLS_HAVE_UDBL)
    pf_mbedtls_t_udbl dividend, quotient;
#else
    const pf_mbedtls_mpi_uint radix = (pf_mbedtls_mpi_uint) 1 << biH;
    const pf_mbedtls_mpi_uint uint_halfword_mask = ((pf_mbedtls_mpi_uint) 1 << biH) - 1;
    pf_mbedtls_mpi_uint d0, d1, q0, q1, rAX, r0, quotient;
    pf_mbedtls_mpi_uint u0_msw, u0_lsw;
    size_t s;
#endif

    /*
     * Check for overflow
     */
    if (0 == d || u1 >= d) {
        if (r != NULL) {
            *r = ~(pf_mbedtls_mpi_uint) 0u;
        }

        return ~(pf_mbedtls_mpi_uint) 0u;
    }

#if defined(PF_MBEDTLS_HAVE_UDBL)
    dividend  = (pf_mbedtls_t_udbl) u1 << biL;
    dividend |= (pf_mbedtls_t_udbl) u0;
    quotient = dividend / d;
    if (quotient > ((pf_mbedtls_t_udbl) 1 << biL) - 1) {
        quotient = ((pf_mbedtls_t_udbl) 1 << biL) - 1;
    }

    if (r != NULL) {
        *r = (pf_mbedtls_mpi_uint) (dividend - (quotient * d));
    }

    return (pf_mbedtls_mpi_uint) quotient;
#else

    /*
     * Algorithm D, Section 4.3.1 - The Art of Computer Programming
     *   Vol. 2 - Seminumerical Algorithms, Knuth
     */

    /*
     * Normalize the divisor, d, and dividend, u0, u1
     */
    s = pf_mbedtls_mpi_core_clz(d);
    d = d << s;

    u1 = u1 << s;
    u1 |= (u0 >> (biL - s)) & (-(pf_mbedtls_mpi_sint) s >> (biL - 1));
    u0 =  u0 << s;

    d1 = d >> biH;
    d0 = d & uint_halfword_mask;

    u0_msw = u0 >> biH;
    u0_lsw = u0 & uint_halfword_mask;

    /*
     * Find the first quotient and remainder
     */
    q1 = u1 / d1;
    r0 = u1 - d1 * q1;

    while (q1 >= radix || (q1 * d0 > radix * r0 + u0_msw)) {
        q1 -= 1;
        r0 += d1;

        if (r0 >= radix) {
            break;
        }
    }

    rAX = (u1 * radix) + (u0_msw - q1 * d);
    q0 = rAX / d1;
    r0 = rAX - q0 * d1;

    while (q0 >= radix || (q0 * d0 > radix * r0 + u0_lsw)) {
        q0 -= 1;
        r0 += d1;

        if (r0 >= radix) {
            break;
        }
    }

    if (r != NULL) {
        *r = (rAX * radix + u0_lsw - q0 * d) >> s;
    }

    quotient = q1 * radix + q0;

    return quotient;
#endif
}

/*
 * Division by mbedtls_mpi: A = Q * B + R  (HAC 14.20)
 */
int pf_mbedtls_mpi_div_mpi(pf_mbedtls_mpi *Q, pf_mbedtls_mpi *R, const pf_mbedtls_mpi *A,
                        const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, n, t, k;
    pf_mbedtls_mpi X, Y, Z, T1, T2;
    pf_mbedtls_mpi_uint TP2[3];

    if (pf_mbedtls_mpi_cmp_int(B, 0) == 0) {
        return PF_MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
    }

    pf_mbedtls_mpi_init(&X); pf_mbedtls_mpi_init(&Y); pf_mbedtls_mpi_init(&Z);
    pf_mbedtls_mpi_init(&T1);
    /*
     * Avoid dynamic memory allocations for constant-size T2.
     *
     * T2 is used for comparison only and the 3 limbs are assigned explicitly,
     * so nobody increase the size of the MPI and we're safe to use an on-stack
     * buffer.
     */
    T2.s = 1;
    T2.n = sizeof(TP2) / sizeof(*TP2);
    T2.p = TP2;

    if (pf_mbedtls_mpi_cmp_abs(A, B) < 0) {
        if (Q != NULL) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(Q, 0));
        }
        if (R != NULL) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(R, A));
        }
        return 0;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&X, A));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&Y, B));
    X.s = Y.s = 1;

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(&Z, A->n + 2));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(&Z,  0));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(&T1, A->n + 2));

    k = pf_mbedtls_mpi_bitlen(&Y) % biL;
    if (k < biL - 1) {
        k = biL - 1 - k;
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(&X, k));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(&Y, k));
    } else {
        k = 0;
    }

    n = X.n - 1;
    t = Y.n - 1;
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(&Y, biL * (n - t)));

    while (pf_mbedtls_mpi_cmp_mpi(&X, &Y) >= 0) {
        Z.p[n - t]++;
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(&X, &X, &Y));
    }
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&Y, biL * (n - t)));

    for (i = n; i > t; i--) {
        if (X.p[i] >= Y.p[t]) {
            Z.p[i - t - 1] = ~(pf_mbedtls_mpi_uint) 0u;
        } else {
            Z.p[i - t - 1] = pf_mbedtls_int_div_int(X.p[i], X.p[i - 1],
                                                 Y.p[t], NULL);
        }

        T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
        T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
        T2.p[2] = X.p[i];

        Z.p[i - t - 1]++;
        do {
            Z.p[i - t - 1]--;

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(&T1, 0));
            T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_int(&T1, &T1, Z.p[i - t - 1]));
        } while (pf_mbedtls_mpi_cmp_mpi(&T1, &T2) > 0);

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_int(&T1, &Y, Z.p[i - t - 1]));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(&T1,  biL * (i - t - 1)));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(&X, &X, &T1));

        if (pf_mbedtls_mpi_cmp_int(&X, 0) < 0) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&T1, &Y));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(&T1, biL * (i - t - 1)));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_mpi(&X, &X, &T1));
            Z.p[i - t - 1]--;
        }
    }

    if (Q != NULL) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(Q, &Z));
        Q->s = A->s * B->s;
    }

    if (R != NULL) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&X, k));
        X.s = A->s;
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(R, &X));

        if (pf_mbedtls_mpi_cmp_int(R, 0) == 0) {
            R->s = 1;
        }
    }

cleanup:

    pf_mbedtls_mpi_free(&X); pf_mbedtls_mpi_free(&Y); pf_mbedtls_mpi_free(&Z);
    pf_mbedtls_mpi_free(&T1);
    pf_mbedtls_platform_zeroize(TP2, sizeof(TP2));

    return ret;
}

/*
 * Division by int: A = Q * b + R
 */
int pf_mbedtls_mpi_div_int(pf_mbedtls_mpi *Q, pf_mbedtls_mpi *R,
                        const pf_mbedtls_mpi *A,
                        pf_mbedtls_mpi_sint b)
{
    pf_mbedtls_mpi B;
    pf_mbedtls_mpi_uint p[1];

    p[0] = mpi_sint_abs(b);
    B.s = TO_SIGN(b);
    B.n = 1;
    B.p = p;

    return pf_mbedtls_mpi_div_mpi(Q, R, A, &B);
}

/*
 * Modulo: R = A mod B
 */
int pf_mbedtls_mpi_mod_mpi(pf_mbedtls_mpi *R, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (pf_mbedtls_mpi_cmp_int(B, 0) < 0) {
        return PF_MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_div_mpi(NULL, R, A, B));

    while (pf_mbedtls_mpi_cmp_int(R, 0) < 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_mpi(R, R, B));
    }

    while (pf_mbedtls_mpi_cmp_mpi(R, B) >= 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(R, R, B));
    }

cleanup:

    return ret;
}

/*
 * Modulo: r = A mod b
 */
int pf_mbedtls_mpi_mod_int(pf_mbedtls_mpi_uint *r, const pf_mbedtls_mpi *A, pf_mbedtls_mpi_sint b)
{
    size_t i;
    pf_mbedtls_mpi_uint x, y, z;

    if (b == 0) {
        return PF_MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
    }

    if (b < 0) {
        return PF_MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    }

    /*
     * handle trivial cases
     */
    if (b == 1 || A->n == 0) {
        *r = 0;
        return 0;
    }

    if (b == 2) {
        *r = A->p[0] & 1;
        return 0;
    }

    /*
     * general case
     */
    for (i = A->n, y = 0; i > 0; i--) {
        x  = A->p[i - 1];
        y  = (y << biH) | (x >> biH);
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = (y << biH) | (x >> biH);
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if (A->s < 0 && y != 0) {
        y = b - y;
    }

    *r = y;

    return 0;
}

/*
 * Warning! If the parameter E_public has MBEDTLS_MPI_IS_PUBLIC as its value,
 * this function is not constant time with respect to the exponent (parameter E).
 */
static int pf_mbedtls_mpi_exp_mod_optionally_safe(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A,
                                               const pf_mbedtls_mpi *E, int E_public,
                                               const pf_mbedtls_mpi *N, pf_mbedtls_mpi *prec_RR)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (pf_mbedtls_mpi_cmp_int(N, 0) <= 0 || (N->p[0] & 1) == 0) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_mpi_cmp_int(E, 0) < 0) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_mpi_bitlen(E) > PF_MBEDTLS_MPI_MAX_BITS ||
        pf_mbedtls_mpi_bitlen(N) > PF_MBEDTLS_MPI_MAX_BITS) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /*
     * Ensure that the exponent that we are passing to the core is not NULL.
     */
    if (E->n == 0) {
        ret = pf_mbedtls_mpi_lset(X, 1);
        return ret;
    }

    /*
     * Allocate working memory for mbedtls_mpi_core_exp_mod()
     */
    size_t T_limbs = pf_mbedtls_mpi_core_exp_mod_working_limbs(N->n, E->n);
    pf_mbedtls_mpi_uint *T = (pf_mbedtls_mpi_uint *) pf_mbedtls_calloc(T_limbs, sizeof(pf_mbedtls_mpi_uint));
    if (T == NULL) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    pf_mbedtls_mpi RR;
    pf_mbedtls_mpi_init(&RR);

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if (prec_RR == NULL || prec_RR->p == NULL) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_core_get_mont_r2_unsafe(&RR, N));

        if (prec_RR != NULL) {
            *prec_RR = RR;
        }
    } else {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(prec_RR, N->n));
        RR = *prec_RR;
    }

    /*
     * To preserve constness we need to make a copy of A. Using X for this to
     * save memory.
     */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(X, A));

    /*
     * Compensate for negative A (and correct at the end).
     */
    X->s = 1;

    /*
     * Make sure that X is in a form that is safe for consumption by
     * the core functions.
     *
     * - The core functions will not touch the limbs of X above N->n. The
     *   result will be correct if those limbs are 0, which the mod call
     *   ensures.
     * - Also, X must have at least as many limbs as N for the calls to the
     *   core functions.
     */
    if (pf_mbedtls_mpi_cmp_mpi(X, N) >= 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(X, X, N));
    }
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(X, N->n));

    /*
     * Convert to and from Montgomery around mbedtls_mpi_core_exp_mod().
     */
    {
        pf_mbedtls_mpi_uint mm = pf_mbedtls_mpi_core_montmul_init(N->p);
        pf_mbedtls_mpi_core_to_mont_rep(X->p, X->p, N->p, N->n, mm, RR.p, T);
        if (E_public == PF_MBEDTLS_MPI_IS_PUBLIC) {
            pf_mbedtls_mpi_core_exp_mod_unsafe(X->p, X->p, N->p, N->n, E->p, E->n, RR.p, T);
        } else {
            pf_mbedtls_mpi_core_exp_mod(X->p, X->p, N->p, N->n, E->p, E->n, RR.p, T);
        }
        pf_mbedtls_mpi_core_from_mont_rep(X->p, X->p, N->p, N->n, mm, T);
    }

    /*
     * Correct for negative A.
     */
    if (A->s == -1 && (E->p[0] & 1) != 0) {
        pf_mbedtls_ct_condition_t is_x_non_zero = pf_mbedtls_mpi_core_check_zero_ct(X->p, X->n);
        X->s = pf_mbedtls_ct_mpi_sign_if(is_x_non_zero, -1, 1);

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_mpi(X, N, X));
    }

cleanup:

    pf_mbedtls_mpi_zeroize_and_free(T, T_limbs);

    if (prec_RR == NULL || prec_RR->p == NULL) {
        pf_mbedtls_mpi_free(&RR);
    }

    return ret;
}

int pf_mbedtls_mpi_exp_mod(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A,
                        const pf_mbedtls_mpi *E, const pf_mbedtls_mpi *N,
                        pf_mbedtls_mpi *prec_RR)
{
    return pf_mbedtls_mpi_exp_mod_optionally_safe(X, A, E, PF_MBEDTLS_MPI_IS_SECRET, N, prec_RR);
}

int pf_mbedtls_mpi_exp_mod_unsafe(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A,
                               const pf_mbedtls_mpi *E, const pf_mbedtls_mpi *N,
                               pf_mbedtls_mpi *prec_RR)
{
    return pf_mbedtls_mpi_exp_mod_optionally_safe(X, A, E, PF_MBEDTLS_MPI_IS_PUBLIC, N, prec_RR);
}

/* Constant-time GCD and/or modinv with odd modulus and A <= N */
int pf_mbedtls_mpi_gcd_modinv_odd(pf_mbedtls_mpi *G,
                               pf_mbedtls_mpi *I,
                               const pf_mbedtls_mpi *A,
                               const pf_mbedtls_mpi *N)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi local_g;
    pf_mbedtls_mpi_uint *T = NULL;
    const size_t T_factor = I != NULL ? 5 : 4;
    const pf_mbedtls_mpi_uint zero = 0;

    /* Check requirements on A and N */
    if (pf_mbedtls_mpi_cmp_int(A, 0) < 0 ||
        pf_mbedtls_mpi_cmp_mpi(A, N) > 0 ||
        pf_mbedtls_mpi_get_bit(N, 0) != 1 ||
        (I != NULL && pf_mbedtls_mpi_cmp_int(N, 1) == 0)) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /* Check aliasing requirements */
    if (A == N || (I != NULL && (I == N || G == N))) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&local_g);

    if (G == NULL) {
        G = &local_g;
    }

    /* We can't modify the values of G or I before use in the main function,
     * as they could be aliased to A or N. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(G, N->n));
    if (I != NULL) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(I, N->n));
    }

    T = pf_mbedtls_calloc(sizeof(pf_mbedtls_mpi_uint) * N->n, T_factor);
    if (T == NULL) {
        ret = PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }

    pf_mbedtls_mpi_uint *Ip = I != NULL ? I->p : NULL;
    /* If A is 0 (null), then A->p would be null, and A->n would be 0,
     * which would be an issue if A->p and A->n were passed to
     * mbedtls_mpi_core_gcd_modinv_odd below. */
    const pf_mbedtls_mpi_uint *Ap = A->p != NULL ? A->p : &zero;
    size_t An = A->n >= N->n ? N->n : A->p != NULL ? A->n : 1;
    pf_mbedtls_mpi_core_gcd_modinv_odd(G->p, Ip, Ap, An, N->p, N->n, T);

    G->s = 1;
    if (I != NULL) {
        I->s = 1;
    }

    if (G->n > N->n) {
        memset(G->p + N->n, 0, ciL * (G->n - N->n));
    }
    if (I != NULL && I->n > N->n) {
        memset(I->p + N->n, 0, ciL * (I->n - N->n));
    }

cleanup:
    pf_mbedtls_mpi_free(&local_g);
    pf_mbedtls_free(T);
    return ret;
}

/*
 * Greatest common divisor: G = gcd(A, B)
 * Wrapper around mbedtls_mpi_gcd_modinv() that removes its restrictions.
 */
int pf_mbedtls_mpi_gcd(pf_mbedtls_mpi *G, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *B)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi TA, TB;

    pf_mbedtls_mpi_init(&TA); pf_mbedtls_mpi_init(&TB);

    /* Make copies and take absolute values */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&TA, A));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&TB, B));
    TA.s = TB.s = 1;

    /* Make the two values the same (non-zero) number of limbs.
     * This is needed to use mbedtls_mpi_core functions below. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(&TA, TB.n != 0 ? TB.n : 1));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_grow(&TB, TA.n)); // non-zero from above

    /* Handle special cases (that don't happen in crypto usage) */
    if (pf_mbedtls_mpi_core_check_zero_ct(TA.p, TA.n) == PF_MBEDTLS_CT_FALSE) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(G, &TB)); // GCD(0, B) = abs(B)
        goto cleanup;
    }
    if (pf_mbedtls_mpi_core_check_zero_ct(TB.p, TB.n) == PF_MBEDTLS_CT_FALSE) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(G, &TA)); // GCD(A, 0) = abs(A)
        goto cleanup;
    }

    /* Make boths inputs odd by putting powers of 2 on the side */
    const size_t za = pf_mbedtls_mpi_lsb(&TA);
    const size_t zb = pf_mbedtls_mpi_lsb(&TB);
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&TA, za));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&TB, zb));

    /* Ensure A <= B: if B < A, swap them */
    pf_mbedtls_ct_condition_t swap = pf_mbedtls_mpi_core_lt_ct(TB.p, TA.p, TA.n);
    pf_mbedtls_mpi_core_cond_swap(TA.p, TB.p, TA.n, swap);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd_modinv_odd(G, NULL, &TA, &TB));

    /* Re-inject the power of 2 we had previously put aside */
    size_t zg = za > zb ? zb : za; // zg = min(za, zb)
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_l(G, zg));

cleanup:

    pf_mbedtls_mpi_free(&TA); pf_mbedtls_mpi_free(&TB);

    return ret;
}

/*
 * Fill X with size bytes of random.
 * The bytes returned from the RNG are used in a specific order which
 * is suitable for deterministic ECDSA (see the specification of
 * mbedtls_mpi_random() and the implementation in mbedtls_mpi_fill_random()).
 */
int pf_mbedtls_mpi_fill_random(pf_mbedtls_mpi *X, size_t size,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t limbs = CHARS_TO_LIMBS(size);

    /* Ensure that target MPI has exactly the necessary number of limbs */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_resize_clear(X, limbs));
    if (size == 0) {
        return 0;
    }

    ret = pf_mbedtls_mpi_core_fill_random(X->p, X->n, size, f_rng, p_rng);

cleanup:
    return ret;
}

int pf_mbedtls_mpi_random(pf_mbedtls_mpi *X,
                       pf_mbedtls_mpi_sint min,
                       const pf_mbedtls_mpi *N,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
    if (min < 0) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    if (pf_mbedtls_mpi_cmp_int(N, min) <= 0) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /* Ensure that target MPI has exactly the same number of limbs
     * as the upper bound, even if the upper bound has leading zeros.
     * This is necessary for mbedtls_mpi_core_random. */
    int ret = pf_mbedtls_mpi_resize_clear(X, N->n);
    if (ret != 0) {
        return ret;
    }

    return pf_mbedtls_mpi_core_random(X->p, min, N->p, X->n, f_rng, p_rng);
}

/*
 * Modular inverse: X = A^-1 mod N with N odd (and A any range)
 */
int pf_mbedtls_mpi_inv_mod_odd(pf_mbedtls_mpi *X,
                            const pf_mbedtls_mpi *A,
                            const pf_mbedtls_mpi *N)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi T, G;

    pf_mbedtls_mpi_init(&T);
    pf_mbedtls_mpi_init(&G);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&T, A, N));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd_modinv_odd(&G, &T, &T, N));
    if (pf_mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(X, &T));

cleanup:
    pf_mbedtls_mpi_free(&T);
    pf_mbedtls_mpi_free(&G);

    return ret;
}

/*
 * Compute X = A^-1 mod N with N even, A odd and 1 < A < N.
 *
 * This is not obvious because our constant-time modinv function only works with
 * an odd modulus, and here the modulus is even. The idea is that computing a
 * a^-1 mod b is really just computing the u coefficient in the Bézout relation
 * a*u + b*v = 1 (assuming gcd(a,b) = 1, i.e. the inverse exists). But if we know
 * one of u, v in this relation then the other is easy to find. So we can
 * actually start by computing N^-1 mod A with gives us "the wrong half" of the
 * Bézout relation, from which we'll deduce the interesting half A^-1 mod N.
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
int pf_mbedtls_mpi_inv_mod_even_in_range(pf_mbedtls_mpi *X,
                                      pf_mbedtls_mpi const *A,
                                      pf_mbedtls_mpi const *N)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi I, G;

    pf_mbedtls_mpi_init(&I);
    pf_mbedtls_mpi_init(&G);

    /* Set I = N^-1 mod A */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&I, N, A));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd_modinv_odd(&G, &I, &I, A));
    if (pf_mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    /* We know N * I = 1 + k * A for some k, which we can easily compute
     * as k = (N*I - 1) / A (we know there will be no remainder). */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(&I, &I, N));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_int(&I, &I, 1));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_div_mpi(&G, NULL, &I, A));

    /* Now we have a Bézout relation N * (previous value of I) - G * A = 1,
     * so A^-1 mod N is -G mod N, which is N - G.
     * Note that 0 < k < N since 0 < I < A, so G (k) is already in range. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(X, N, &G));

cleanup:
    pf_mbedtls_mpi_free(&I);
    pf_mbedtls_mpi_free(&G);
    return ret;
}

/*
 * Compute X = A^-1 mod N with N even and A odd (but in any range).
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
static int pf_mbedtls_mpi_inv_mod_even(pf_mbedtls_mpi *X,
                                    pf_mbedtls_mpi const *A,
                                    pf_mbedtls_mpi const *N)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi AA;

    pf_mbedtls_mpi_init(&AA);

    /* Bring A in the range [0, N). */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&AA, A, N));

    /* We know A >= 0 but the next function wants A > 1 */
    int cmp = pf_mbedtls_mpi_cmp_int(&AA, 1);
    if (cmp < 0) { // AA == 0
        ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }
    if (cmp == 0) { // AA = 1
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(X, 1));
        goto cleanup;
    }

    /* Now we know 1 < A < N, N is even and AA is still odd */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_inv_mod_even_in_range(X, &AA, N));

cleanup:
    pf_mbedtls_mpi_free(&AA);
    return ret;
}

/*
 * Modular inverse: X = A^-1 mod N
 *
 * Wrapper around mbedtls_mpi_gcd_modinv_odd() that lifts its limitations.
 */
int pf_mbedtls_mpi_inv_mod(pf_mbedtls_mpi *X, const pf_mbedtls_mpi *A, const pf_mbedtls_mpi *N)
{
    if (pf_mbedtls_mpi_cmp_int(N, 1) <= 0) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_mpi_get_bit(N, 0) == 1) {
        return pf_mbedtls_mpi_inv_mod_odd(X, A, N);
    }

    if (pf_mbedtls_mpi_get_bit(A, 0) == 1) {
        return pf_mbedtls_mpi_inv_mod_even(X, A, N);
    }

    /* If A and N are both even, 2 divides their GCD, so no inverse. */
    return PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
}

#if defined(PF_MBEDTLS_GENPRIME)

static const pf_mbedtls_mpi_sint small_primes_limit = 997;
/* Product of small primes up to small_primes_limit included */
static const pf_mbedtls_mpi_uint small_primes_product_limbs[] = {
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x4b, 0x13, 0x6a, 0x97, 0xbb, 0xd0, 0xdf, 0x95),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xa7, 0x2c, 0x10, 0xa4, 0x20, 0xa4, 0x9f, 0x7b),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x9d, 0x18, 0xd6, 0xdf, 0xc0, 0xf5, 0x61, 0x65),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xfc, 0x35, 0x79, 0xfb, 0x30, 0xa8, 0xd5, 0xbf),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xdb, 0x37, 0xba, 0x2c, 0xfb, 0xbb, 0x89, 0xfb),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xad, 0xc2, 0x8c, 0x1d, 0x99, 0x18, 0xe8, 0xe5),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x8d, 0x77, 0xc9, 0x5d, 0x96, 0x8a, 0x61, 0x9d),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x39, 0x41, 0x3e, 0xf4, 0x34, 0x07, 0x57, 0xe0),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x4a, 0xf1, 0x54, 0x3a, 0x43, 0x67, 0x46, 0xa2),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x83, 0x0c, 0xe5, 0x31, 0xa2, 0xfc, 0x05, 0x45),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xf0, 0x1d, 0x66, 0xfc, 0x7a, 0x85, 0x37, 0xe1),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x17, 0xe0, 0x80, 0x62, 0x0d, 0xa2, 0xbc, 0x32),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x6d, 0xce, 0x84, 0x68, 0x00, 0xb5, 0xe3, 0x35),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x14, 0x19, 0x0d, 0xe4, 0x92, 0xd5, 0xd8, 0xdf),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x20, 0x1c, 0x7d, 0x38, 0x3b, 0xe8, 0xd9, 0xa8),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xf6, 0xac, 0x11, 0xe6, 0xb4, 0x03, 0xf7, 0x6c),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x78, 0x3d, 0xf2, 0x3a, 0x8f, 0xf9, 0x2f, 0x6a),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x7b, 0x72, 0x66, 0xa9, 0x48, 0xe4, 0x6d, 0x02),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x69, 0xc7, 0x32, 0xcb, 0xf2, 0xf7, 0xa9, 0x0b),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xd3, 0x52, 0x72, 0x9d, 0xbf, 0x54, 0xea, 0xc7),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0xf5, 0xf3, 0x8a, 0xc5, 0xf0, 0xe1, 0x21, 0x81),
    PF_MBEDTLS_BYTES_TO_T_UINT_8(0x8e, 0x61, 0x78, 0xf0, 0x05, 0x00, 0x00, 0x00),
};
/* Could make ECP_MPI_INIT_ARRAY() available outside ecp, but not doing it now
 * as it would lead to conflicts with other in-flight PRs. */
static const pf_mbedtls_mpi small_primes_product = {
    .p = (pf_mbedtls_mpi_uint *) small_primes_product_limbs,
    .s = 1,
    .n = sizeof(small_primes_product_limbs) / sizeof(pf_mbedtls_mpi_uint),
};

/*
 * Small divisors test (X must be positive)
 *
 * Return values:
 * 0: no small factor (possible prime, more tests needed)
 * 1: certain prime
 * MBEDTLS_ERR_MPI_NOT_ACCEPTABLE: certain non-prime
 * other negative: error
 */
static int mpi_check_small_factors(const pf_mbedtls_mpi *X)
{
    int ret = 0;
    pf_mbedtls_mpi g;

    pf_mbedtls_mpi_init(&g);

    if ((X->p[0] & 1) == 0) {
        return PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }

    /* The GCD test below only works if X > small_primes_limit.
     * Below this limit, use trial division: numbers that small are of no
     * interest for cryptography, so we don't care about performance or side
     * channels. We're supporting them only for backwards compatibility, so
     * let's not waste code size on those. */
    if (pf_mbedtls_mpi_cmp_int(X, small_primes_limit) <= 0) {
        pf_mbedtls_mpi_uint x = X->p[0];
        pf_mbedtls_mpi_uint d = 2;
        while (x % d != 0) {
            ++d;
        }
        return x == d ? 1 : PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }

    /* We can't directly use mbedtls_mpi_gcd_modinv_odd() because we don't know
     * if X is larger than prod or not (prod is 1380 bits). So, use this generic
     * wrapper - it does a bit more than what we need (handles even inputs as
     * well, while we know our inputs are both odd), but that's OK. */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd(&g, &small_primes_product, X));

    if (pf_mbedtls_mpi_cmp_int(&g, 1) == 0) {
        /* X is not divisible by a small prime */
        ret = 0;
    } else {
        ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }

cleanup:
    pf_mbedtls_mpi_free(&g);
    return ret;
}

/*
 * Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
static int mpi_miller_rabin(const pf_mbedtls_mpi *X, size_t rounds,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret, count;
    size_t i, j, k, s;
    pf_mbedtls_mpi W, R, T, A, RR;

    pf_mbedtls_mpi_init(&W); pf_mbedtls_mpi_init(&R);
    pf_mbedtls_mpi_init(&T); pf_mbedtls_mpi_init(&A);
    pf_mbedtls_mpi_init(&RR);

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_int(&W, X, 1));
    s = pf_mbedtls_mpi_lsb(&W);
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&R, &W));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&R, s));

    for (i = 0; i < rounds; i++) {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        count = 0;
        do {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_fill_random(&A, X->n * ciL, f_rng, p_rng));

            j = pf_mbedtls_mpi_bitlen(&A);
            k = pf_mbedtls_mpi_bitlen(&W);
            if (j > k) {
                A.p[A.n - 1] &= ((pf_mbedtls_mpi_uint) 1 << (k - (A.n - 1) * biL - 1)) - 1;
            }

            if (count++ > 30) {
                ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
                goto cleanup;
            }

        } while (pf_mbedtls_mpi_cmp_mpi(&A, &W) >= 0 ||
                 pf_mbedtls_mpi_cmp_int(&A, 1)  <= 0);

        /*
         * A = A^R mod |X|
         */
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_exp_mod(&A, &A, &R, X, &RR));

        if (pf_mbedtls_mpi_cmp_mpi(&A, &W) == 0 ||
            pf_mbedtls_mpi_cmp_int(&A,  1) == 0) {
            continue;
        }

        j = 1;
        while (j < s && pf_mbedtls_mpi_cmp_mpi(&A, &W) != 0) {
            /*
             * A = A * A mod |X|
             */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(&T, &A, &A));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&A, &T, X));

            if (pf_mbedtls_mpi_cmp_int(&A, 1) == 0) {
                break;
            }

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if (pf_mbedtls_mpi_cmp_mpi(&A, &W) != 0 ||
            pf_mbedtls_mpi_cmp_int(&A,  1) == 0) {
            ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    pf_mbedtls_mpi_free(&W); pf_mbedtls_mpi_free(&R);
    pf_mbedtls_mpi_free(&T); pf_mbedtls_mpi_free(&A);
    pf_mbedtls_mpi_free(&RR);

    return ret;
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int pf_mbedtls_mpi_is_prime_ext(const pf_mbedtls_mpi *X, int rounds,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi XX;

    XX.s = 1;
    XX.n = X->n;
    XX.p = X->p;

    if (pf_mbedtls_mpi_cmp_int(&XX, 0) == 0 ||
        pf_mbedtls_mpi_cmp_int(&XX, 1) == 0) {
        return PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }

    if (pf_mbedtls_mpi_cmp_int(&XX, 2) == 0) {
        return 0;
    }

    if ((ret = mpi_check_small_factors(&XX)) != 0) {
        if (ret == 1) {
            return 0;
        }

        return ret;
    }

    return mpi_miller_rabin(&XX, rounds, f_rng, p_rng);
}

/*
 * Prime number generation
 *
 * To generate an RSA key in a way recommended by FIPS 186-4, both primes must
 * be either 1024 bits or 1536 bits long, and flags must contain
 * MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR.
 */
int pf_mbedtls_mpi_gen_prime(pf_mbedtls_mpi *X, size_t nbits, int flags,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
#ifdef PF_MBEDTLS_HAVE_INT64
// ceil(2^63.5)
#define CEIL_MAXUINT_DIV_SQRT2 0xb504f333f9de6485ULL
#else
// ceil(2^31.5)
#define CEIL_MAXUINT_DIV_SQRT2 0xb504f334U
#endif
    int ret = PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    size_t k, n;
    int rounds;
    pf_mbedtls_mpi_uint r;
    pf_mbedtls_mpi Y;

    if (nbits < 3 || nbits > PF_MBEDTLS_MPI_MAX_BITS) {
        return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&Y);

    n = BITS_TO_LIMBS(nbits);

    if ((flags & PF_MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR) == 0) {
        /*
         * 2^-80 error probability, number of rounds chosen per HAC, table 4.4
         */
        rounds = ((nbits >= 1300) ?  2 : (nbits >=  850) ?  3 :
                  (nbits >=  650) ?  4 : (nbits >=  350) ?  8 :
                  (nbits >=  250) ? 12 : (nbits >=  150) ? 18 : 27);
    } else {
        /*
         * 2^-100 error probability, number of rounds computed based on HAC,
         * fact 4.48
         */
        rounds = ((nbits >= 1450) ?  4 : (nbits >=  1150) ?  5 :
                  (nbits >= 1000) ?  6 : (nbits >=   850) ?  7 :
                  (nbits >=  750) ?  8 : (nbits >=   500) ? 13 :
                  (nbits >=  250) ? 28 : (nbits >=   150) ? 40 : 51);
    }

    while (1) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_fill_random(X, n * ciL, f_rng, p_rng));
        /* make sure generated number is at least (nbits-1)+0.5 bits (FIPS 186-4 §B.3.3 steps 4.4, 5.5) */
        if (X->p[n-1] < CEIL_MAXUINT_DIV_SQRT2) {
            continue;
        }

        k = n * biL;
        if (k > nbits) {
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(X, k - nbits));
        }
        X->p[0] |= 1;

        if ((flags & PF_MBEDTLS_MPI_GEN_PRIME_FLAG_DH) == 0) {
            ret = pf_mbedtls_mpi_is_prime_ext(X, rounds, f_rng, p_rng);

            if (ret != PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
                goto cleanup;
            }
        } else {
            /*
             * A necessary condition for Y and X = 2Y + 1 to be prime
             * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
             * Make sure it is satisfied, while keeping X = 3 mod 4
             */

            X->p[0] |= 2;

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_int(&r, X, 3));
            if (r == 0) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(X, X, 8));
            } else if (r == 1) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(X, X, 4));
            }

            /* Set Y = (X-1) / 2, which is X / 2 because X is odd */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(&Y, X));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(&Y, 1));

            while (1) {
                /*
                 * First, check small factors for X and Y
                 * before doing Miller-Rabin on any of them
                 */
                if ((ret = mpi_check_small_factors(X)) == 0 &&
                    (ret = mpi_check_small_factors(&Y)) == 0 &&
                    (ret = mpi_miller_rabin(X, rounds, f_rng, p_rng))
                    == 0 &&
                    (ret = mpi_miller_rabin(&Y, rounds, f_rng, p_rng))
                    == 0) {
                    goto cleanup;
                }

                if (ret != PF_MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
                    goto cleanup;
                }

                /*
                 * Next candidates. We want to preserve Y = (X-1) / 2 and
                 * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
                 * so up Y by 6 and X by 12.
                 */
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(X,  X, 12));
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_int(&Y, &Y, 6));
            }
        }
    }

cleanup:

    pf_mbedtls_mpi_free(&Y);

    return ret;
}

#endif /* MBEDTLS_GENPRIME */

#if defined(PF_MBEDTLS_SELF_TEST)

#define GCD_PAIR_COUNT  3

static const int gcd_pairs[GCD_PAIR_COUNT][3] =
{
    { 693, 609, 21 },
    { 1764, 868, 28 },
    { 768454923, 542167814, 1 }
};

/*
 * Checkup routine
 */
int pf_mbedtls_mpi_self_test(int verbose)
{
    int ret, i;
    pf_mbedtls_mpi A, E, N, X, Y, U, V;

    pf_mbedtls_mpi_init(&A); pf_mbedtls_mpi_init(&E); pf_mbedtls_mpi_init(&N); pf_mbedtls_mpi_init(&X);
    pf_mbedtls_mpi_init(&Y); pf_mbedtls_mpi_init(&U); pf_mbedtls_mpi_init(&V);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&A, 16,
                                            "EFE021C2645FD1DC586E69184AF4A31E" \
                                            "D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(&X, &A, &N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&U, 16,
                                            "602AB7ECA597A3D6B56FF9829A5E8B85" \
                                            "9E857EA95A03512E2BAE7391688D264A" \
                                            "A5663B0341DB9CCFD2C4C5F421FEC814" \
                                            "8001B72E848A38CAE1C65F78E56ABDEF" \
                                            "E12D3C039B8A02D6BE593F0BBBDA56F1" \
                                            "ECF677152EF804370C1A305CAF3B5BF1" \
                                            "30879B56C61DE584A0F53A2447A51E"));

    if (verbose != 0) {
        pf_mbedtls_printf("  MPI test #1 (mul_mpi): ");
    }

    if (pf_mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            pf_mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        pf_mbedtls_printf("passed\n");
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_div_mpi(&X, &Y, &A, &N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&U, 16,
                                            "256567336059E52CAE22925474705F39A94"));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&V, 16,
                                            "6613F26162223DF488E9CD48CC132C7A" \
                                            "0AC93C701B001B092E4E5B9F73BCD27B" \
                                            "9EE50D0657C77F374E903CDFA4C642"));

    if (verbose != 0) {
        pf_mbedtls_printf("  MPI test #2 (div_mpi): ");
    }

    if (pf_mbedtls_mpi_cmp_mpi(&X, &U) != 0 ||
        pf_mbedtls_mpi_cmp_mpi(&Y, &V) != 0) {
        if (verbose != 0) {
            pf_mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        pf_mbedtls_printf("passed\n");
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_exp_mod(&X, &A, &E, &N, NULL));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&U, 16,
                                            "36E139AEA55215609D2816998ED020BB" \
                                            "BD96C37890F65171D948E9BC7CBAA4D9" \
                                            "325D24D6A3C12710F10A09FA08AB87"));

    if (verbose != 0) {
        pf_mbedtls_printf("  MPI test #3 (exp_mod): ");
    }

    if (pf_mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            pf_mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        pf_mbedtls_printf("passed\n");
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_inv_mod(&X, &A, &N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_string(&U, 16,
                                            "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
                                            "C3DBA76456363A10869622EAC2DD84EC" \
                                            "C5B8A74DAC4D09E03B5E0BE779F2DF61"));

    if (verbose != 0) {
        pf_mbedtls_printf("  MPI test #4 (inv_mod): ");
    }

    if (pf_mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            pf_mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        pf_mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        pf_mbedtls_printf("  MPI test #5 (simple gcd): ");
    }

    for (i = 0; i < GCD_PAIR_COUNT; i++) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(&X, gcd_pairs[i][0]));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_lset(&Y, gcd_pairs[i][1]));

        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd(&A, &X, &Y));

        if (pf_mbedtls_mpi_cmp_int(&A, gcd_pairs[i][2]) != 0) {
            if (verbose != 0) {
                pf_mbedtls_printf("failed at %d\n", i);
            }

            ret = 1;
            goto cleanup;
        }
    }

    if (verbose != 0) {
        pf_mbedtls_printf("passed\n");
    }

cleanup:

    if (ret != 0 && verbose != 0) {
        pf_mbedtls_printf("Unexpected error, return code = %08X\n", (unsigned int) ret);
    }

    pf_mbedtls_mpi_free(&A); pf_mbedtls_mpi_free(&E); pf_mbedtls_mpi_free(&N); pf_mbedtls_mpi_free(&X);
    pf_mbedtls_mpi_free(&Y); pf_mbedtls_mpi_free(&U); pf_mbedtls_mpi_free(&V);

    if (verbose != 0) {
        pf_mbedtls_printf("\n");
    }

    return ret;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_BIGNUM_C */
