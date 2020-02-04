/* gost28147.c - GOST 28147-89 cipher implementation
 *
 * based on Russian standard GOST 28147-89
 * For English description, check RFC 5830.
 * S-Boxes are expanded from the tables defined in RFC4357:
 *   https://tools.ietf.org/html/rfc4357
 *
 * Copyright: 2019 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright: 2009-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "macros.h"
#include "gost28147-internal.h"

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 */
#define GOST_ENCRYPT_ROUND(l, r, key1, key2, sbox) \
  do { \
    uint32_t round_tmp; \
      \
    round_tmp = (key1) + r; \
    l ^= (sbox)[0][(round_tmp & 0xff)] ^ \
         (sbox)[1][((round_tmp >> 8) & 0xff)] ^ \
         (sbox)[2][((round_tmp >> 16) & 0xff)] ^ \
         (sbox)[3][(round_tmp >> 24)]; \
    round_tmp = (key2) + l; \
    r ^= (sbox)[0][(round_tmp & 0xff)] ^ \
         (sbox)[1][((round_tmp >> 8) & 0xff)] ^ \
         (sbox)[2][((round_tmp >> 16) & 0xff)] ^ \
         (sbox)[3][(round_tmp >> 24)]; \
  } while (0)

/* encrypt a block with the given key */
void _gost28147_encrypt_block (const uint32_t *key, const uint32_t sbox[4][256],
			       const uint32_t *in, uint32_t *out)
{
  uint32_t l, r;

  r = in[0], l = in[1];
  GOST_ENCRYPT_ROUND(l, r, key[0], key[1], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[2], key[3], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[4], key[5], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[6], key[7], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[0], key[1], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[2], key[3], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[4], key[5], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[6], key[7], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[0], key[1], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[2], key[3], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[4], key[5], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[6], key[7], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[7], key[6], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[5], key[4], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[3], key[2], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[1], key[0], sbox);
  *out = l, *(out + 1) = r;
}
