/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2010-2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * BabelTrace - bitfield test program
 */

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

#include "compat/bitfield.h"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

unsigned int glob;

/*
 * This function is only declared to show the size of a bitfield write in
 * objdump.  The declaration is there to avoid a -Wmissing-prototypes warning.
 */
void fct(void);
void fct(void)
{
    bt_bitfield_write(&glob, unsigned int, 12, 15, 0x12345678);
}

/* Test array size, in bytes */
#define TEST_LEN                           128
#define SIGNED_INT_READ_TEST_DESC          "signed int dest, varying read unit size"
#define SIGNED_INT_WRITE_TEST_DESC         "signed int source, varying write unit size"
#define SIGNED_LONG_LONG_READ_TEST_DESC    "signed long long dest, varying read unit size"
#define SIGNED_LONG_LONG_WRITE_TEST_DESC   "signed long long source, varying write unit size"
#define UNSIGNED_INT_READ_TEST_DESC        "unsigned int dest, varying read unit size"
#define UNSIGNED_INT_WRITE_TEST_DESC       "unsigned int source, varying write unit size"
#define UNSIGNED_LONG_LONG_READ_TEST_DESC  "unsigned long long dest, varying read unit size"
#define UNSIGNED_LONG_LONG_WRITE_TEST_DESC "unsigned long long source, varying write unit size"

static unsigned int fls_u64(uint64_t x)
{
    unsigned int r = 64;

    if (!x)
        return 0;

    if (!(x & 0xFFFFFFFF00000000ULL)) {
        x <<= 32;
        r -= 32;
    }
    if (!(x & 0xFFFF000000000000ULL)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xFF00000000000000ULL)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xF000000000000000ULL)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xC000000000000000ULL)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x8000000000000000ULL)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static unsigned int fls_u32(uint32_t x)
{
    unsigned int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xFFFF0000U)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xFF000000U)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xF0000000U)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xC0000000U)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000U)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static std::string format_byte_array(unsigned char *c, unsigned long len)
{
    std::string result;
    char buf[8];

    for (unsigned long i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "0x%X", c[i]);
        result += buf;
        if (i != len - 1)
            result += " ";
    }
    return result;
}

#define init_byte_array(c, len, val)                                                               \
    do {                                                                                           \
        unsigned long i;                                                                           \
                                                                                                   \
        for (i = 0; i < (len); i++)                                                                \
            (c)[i] = (val);                                                                        \
    } while (0)

template <typename RefT, typename ValT, typename BufT>
static bool check_result_impl(RefT ref, ValT val, BufT *buffer, const char *typeName,
                              unsigned int start, unsigned int len, const char *testDesc)
{
    if (val != ref) {
        INFO("test: " << testDesc);
        INFO("written \"" << typeName << "\"-wise");
        CAPTURE(start, len, ref, val);
        INFO("buffer: " << format_byte_array(reinterpret_cast<unsigned char *>(buffer), TEST_LEN));
        FAIL();
    }
    return val != ref;
}

#define check_result(ref, val, buffer, typename, start, len, test_desc)                            \
    check_result_impl(ref, val, buffer, #typename, start, len, test_desc)

static void run_test_unsigned_write(unsigned int src_ui, unsigned long long src_ull)
{
    unsigned int nrbits_ui, nrbits_ull;
    union
    {
        unsigned char c[TEST_LEN];
        unsigned short s[TEST_LEN / sizeof(unsigned short)];
        unsigned int i[TEST_LEN / sizeof(unsigned int)];
        unsigned long l[TEST_LEN / sizeof(unsigned long)];
        unsigned long long ll[TEST_LEN / sizeof(unsigned long long)];
    } target;
    unsigned long long readval;
    unsigned int s, l;

    /* The number of bits needed to represent 0 is 0. */
    nrbits_ui = fls_u32(src_ui);

    /* Write from unsigned integer src input. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ui; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ui, readval, target.c, unsigned char, s, l,
                             UNSIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.s, unsigned short, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ui, readval, target.c, unsigned short, s, l,
                             UNSIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.i, unsigned int, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ui, readval, target.c, unsigned int, s, l,
                             UNSIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.l, unsigned long, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ui, readval, target.c, unsigned long, s, l,
                             UNSIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.ll, unsigned long long, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ui, readval, target.c, unsigned long long, s, l,
                             UNSIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }
        }
    }

    /* The number of bits needed to represent 0 is 0. */
    nrbits_ull = fls_u64(src_ull);

    /* Write from unsigned long long src input. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ull; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ull, readval, target.c, unsigned char, s, l,
                             UNSIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.s, unsigned short, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ull, readval, target.c, unsigned short, s, l,
                             UNSIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.i, unsigned int, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ull, readval, target.c, unsigned int, s, l,
                             UNSIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.l, unsigned long, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ull, readval, target.c, unsigned long, s, l,
                             UNSIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.ll, unsigned long long, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval);
            if (check_result(src_ull, readval, target.c, unsigned long long, s, l,
                             UNSIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }
        }
    }
}

static void run_test_unsigned_read(unsigned int src_ui, unsigned long long src_ull)
{
    unsigned int nrbits_ui, nrbits_ull, readval_ui;
    union
    {
        unsigned char c[TEST_LEN];
        unsigned short s[TEST_LEN / sizeof(unsigned short)];
        unsigned int i[TEST_LEN / sizeof(unsigned int)];
        unsigned long l[TEST_LEN / sizeof(unsigned long)];
        unsigned long long ll[TEST_LEN / sizeof(unsigned long long)];
    } target;
    unsigned long long readval_ull;
    unsigned int s, l;

    /* The number of bits needed to represent 0 is 0. */
    nrbits_ui = fls_u32(src_ui);

    /* Read to unsigned integer readval output. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ui; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval_ui);
            if (check_result(src_ui, readval_ui, target.c, unsigned char, s, l,
                             UNSIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.s, unsigned short, s, l, &readval_ui);
            if (check_result(src_ui, readval_ui, target.c, unsigned short, s, l,
                             UNSIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.i, unsigned int, s, l, &readval_ui);
            if (check_result(src_ui, readval_ui, target.c, unsigned int, s, l,
                             UNSIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.l, unsigned long, s, l, &readval_ui);
            if (check_result(src_ui, readval_ui, target.c, unsigned long, s, l,
                             UNSIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ui);
            bt_bitfield_read(target.ll, unsigned long long, s, l, &readval_ui);
            if (check_result(src_ui, readval_ui, target.c, unsigned long long, s, l,
                             UNSIGNED_INT_READ_TEST_DESC)) {
                return;
            }
        }
    }

    /* The number of bits needed to represent 0 is 0. */
    nrbits_ull = fls_u64(src_ull);

    /* Read to unsigned long long readval output. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ull; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.c, unsigned char, s, l, &readval_ull);
            if (check_result(src_ull, readval_ull, target.c, unsigned char, s, l,
                             UNSIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.s, unsigned short, s, l, &readval_ull);
            if (check_result(src_ull, readval_ull, target.c, unsigned short, s, l,
                             UNSIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.i, unsigned int, s, l, &readval_ull);
            if (check_result(src_ull, readval_ull, target.c, unsigned int, s, l,
                             UNSIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.l, unsigned long, s, l, &readval_ull);
            if (check_result(src_ull, readval_ull, target.c, unsigned long, s, l,
                             UNSIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, unsigned char, s, l, src_ull);
            bt_bitfield_read(target.ll, unsigned long long, s, l, &readval_ull);
            if (check_result(src_ull, readval_ull, target.c, unsigned long long, s, l,
                             UNSIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }
        }
    }
}

static void run_test_unsigned(unsigned int src_ui, unsigned long long src_ull)
{
    run_test_unsigned_write(src_ui, src_ull);
    run_test_unsigned_read(src_ui, src_ull);
}

static void run_test_signed_write(int src_i, long long src_ll)
{
    unsigned int nrbits_i, nrbits_ll;
    union
    {
        signed char c[TEST_LEN];
        short s[TEST_LEN / sizeof(short)];
        int i[TEST_LEN / sizeof(int)];
        long l[TEST_LEN / sizeof(long)];
        long long ll[TEST_LEN / sizeof(long long)];
    } target;
    long long readval;
    unsigned int s, l;

    if (!src_i)
        nrbits_i = 0; /* The number of bits needed to represent 0 is 0. */
    else if (src_i & 0x80000000U)
        nrbits_i = fls_u32(~src_i) + 1; /* Find least significant bit conveying sign */
    else
        nrbits_i = fls_u32(src_i) + 1; /* Keep sign at 0 */

    /* Write from signed integer src input. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_i; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_i, readval, target.c, signed char, s, l,
                             SIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.s, short, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_i, readval, target.c, short, s, l, SIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.i, int, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_i, readval, target.c, int, s, l, SIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.l, long, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_i, readval, target.c, long, s, l, SIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.ll, long long, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_i, readval, target.c, long long, s, l,
                             SIGNED_INT_WRITE_TEST_DESC)) {
                return;
            }
        }
    }

    if (!src_ll)
        nrbits_ll = 0; /* The number of bits needed to represent 0 is 0. */
    else if (src_ll & 0x8000000000000000ULL)
        nrbits_ll = fls_u64(~src_ll) + 1; /* Find least significant bit conveying sign */
    else
        nrbits_ll = fls_u64(src_ll) + 1; /* Keep sign at 0 */

    /* Write from signed long long src input. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ll; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_ll, readval, target.c, signed char, s, l,
                             SIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.s, short, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_ll, readval, target.c, short, s, l,
                             SIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.i, int, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_ll, readval, target.c, int, s, l,
                             SIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.l, long, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_ll, readval, target.c, long, s, l,
                             SIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0x0);
            bt_bitfield_write(target.ll, long long, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval);
            if (check_result(src_ll, readval, target.c, long long, s, l,
                             SIGNED_LONG_LONG_WRITE_TEST_DESC)) {
                return;
            }
        }
    }
}

static void run_test_signed_read(int src_i, long long src_ll)
{
    unsigned int nrbits_i, nrbits_ll;
    int readval_i;
    union
    {
        unsigned char c[TEST_LEN];
        unsigned short s[TEST_LEN / sizeof(unsigned short)];
        unsigned int i[TEST_LEN / sizeof(unsigned int)];
        unsigned long l[TEST_LEN / sizeof(unsigned long)];
        unsigned long long ll[TEST_LEN / sizeof(unsigned long long)];
    } target;
    long long readval_ll;
    unsigned int s, l;

    if (!src_i)
        nrbits_i = 0; /* The number of bits needed to represent 0 is 0. */
    else if (src_i & 0x80000000U)
        nrbits_i = fls_u32(~src_i) + 1; /* Find least significant bit conveying sign */
    else
        nrbits_i = fls_u32(src_i) + 1; /* Keep sign at 0 */

    /* Read to signed integer readval output. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_i; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.c, signed char, s, l, &readval_i);
            if (check_result(src_i, readval_i, target.c, signed char, s, l,
                             SIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.s, short, s, l, &readval_i);
            if (check_result(src_i, readval_i, target.c, short, s, l, SIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.i, int, s, l, &readval_i);
            if (check_result(src_i, readval_i, target.c, int, s, l, SIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.l, long, s, l, &readval_i);
            if (check_result(src_i, readval_i, target.c, long, s, l, SIGNED_INT_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_i);
            bt_bitfield_read(target.ll, long long, s, l, &readval_i);
            if (check_result(src_i, readval_i, target.c, long long, s, l,
                             SIGNED_INT_READ_TEST_DESC)) {
                return;
            }
        }
    }

    if (!src_ll)
        nrbits_ll = 0; /* The number of bits needed to represent 0 is 0. */
    if (src_ll & 0x8000000000000000ULL)
        nrbits_ll = fls_u64(~src_ll) + 1; /* Find least significant bit conveying sign */
    else
        nrbits_ll = fls_u64(src_ll) + 1; /* Keep sign at 0 */

    /* Read to signed long long readval output. */
    for (s = 0; s < CHAR_BIT * TEST_LEN; s++) {
        for (l = nrbits_ll; l <= (CHAR_BIT * TEST_LEN) - s; l++) {
            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.c, signed char, s, l, &readval_ll);
            if (check_result(src_ll, readval_ll, target.c, signed char, s, l,
                             SIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.s, short, s, l, &readval_ll);
            if (check_result(src_ll, readval_ll, target.c, short, s, l,
                             SIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.i, int, s, l, &readval_ll);
            if (check_result(src_ll, readval_ll, target.c, int, s, l,
                             SIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.l, long, s, l, &readval_ll);
            if (check_result(src_ll, readval_ll, target.c, long, s, l,
                             SIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }

            init_byte_array(target.c, TEST_LEN, 0xFF);
            bt_bitfield_write(target.c, signed char, s, l, src_ll);
            bt_bitfield_read(target.ll, long long, s, l, &readval_ll);
            if (check_result(src_ll, readval_ll, target.c, long long, s, l,
                             SIGNED_LONG_LONG_READ_TEST_DESC)) {
                return;
            }
        }
    }
}

static void run_test_signed(int src_i, long long src_ll)
{
    run_test_signed_write(src_i, src_ll);
    run_test_signed_read(src_i, src_ll);
}

TEST_CASE("Zero values (unsigned)")
{
    run_test_unsigned(0, 0);
}

TEST_CASE("Zero values (signed)")
{
    run_test_signed(0, 0);
}

TEST_CASE("Value one")
{
    run_test_unsigned(1, 1);
}

TEST_CASE("All bits set (unsigned)")
{
    run_test_unsigned(~0U, ~0ULL);
}

TEST_CASE("Minus one (signed)")
{
    run_test_signed(-1U, -1ULL);
}

TEST_CASE("Minimum signed values")
{
    run_test_signed(0x80000000U, 0x8000000000000000ULL);
}

namespace {

void run_test_random(int i)
{
    srand(time(NULL) + i);

    unsigned int src_ui = rand();
    unsigned long long src_ull = ((unsigned long long) (unsigned int) rand() << 32) |
                                 (unsigned long long) (unsigned int) rand();

    run_test_unsigned(src_ui, src_ull);
    run_test_signed((int) src_ui, (long long) src_ull);
}

} /* namespace */

TEST_CASE("Random values (0)")
{
    run_test_random(0);
}
TEST_CASE("Random values (1)")
{
    run_test_random(1);
}
TEST_CASE("Random values (2)")
{
    run_test_random(2);
}
TEST_CASE("Random values (3)")
{
    run_test_random(3);
}
TEST_CASE("Random values (4)")
{
    run_test_random(4);
}
TEST_CASE("Random values (5)")
{
    run_test_random(5);
}
TEST_CASE("Random values (6)")
{
    run_test_random(6);
}
TEST_CASE("Random values (7)")
{
    run_test_random(7);
}
TEST_CASE("Random values (8)")
{
    run_test_random(8);
}
TEST_CASE("Random values (9)")
{
    run_test_random(9);
}
