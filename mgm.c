/* mgm.c

   Multilinear Galois Mode,
   https://tools.ietf.org/id/draft-smyshlyaev-mgm-11.html

   Copyright (C) 2019 Dmitry Eremin-Solenikov

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "mgm.h"
#include "macros.h"
#include "memxor.h"
#include "block-internal.h"

static void
mgm_gf_mul_sum (struct mgm_ctx *ctx, union nettle_block16 *x, const uint8_t *y)
{
  union nettle_block16 V;
  union nettle_block16 Z;
  unsigned i;

  memcpy(V.b, x, sizeof(V));
  memset(Z.b, 0, sizeof(Z));

  for (i = 0; i < MGM_BLOCK_SIZE; i++)
    {
      uint8_t b = y[MGM_BLOCK_SIZE - i - 1];
      unsigned j;
      for (j = 0; j < 8; j++, b >>= 1)
	{
	  if (b & 1)
	    block16_xor(&Z, &V);

	  block16_mulx_be(&V, &V);
	}
    }

  ctx->sum.u64[0] ^= Z.u64[0];
  ctx->sum.u64[1] ^= Z.u64[1];
}

void
mgm_set_iv (struct mgm_ctx *ctx,
	    const void *cipher, nettle_cipher_func *f,
	    const uint8_t *nonce)
{
  memcpy(ctx->y.b, nonce, MGM_BLOCK_SIZE);
  memcpy(ctx->z.b, nonce, MGM_BLOCK_SIZE);

  ctx->y.b[0] &= 0x7f;
  ctx->z.b[0] |= 0x80;

  f(cipher, MGM_BLOCK_SIZE, ctx->y.b, ctx->y.b);
  f(cipher, MGM_BLOCK_SIZE, ctx->z.b, ctx->z.b);

  memset(ctx->sum.b, 0, MGM_BLOCK_SIZE);
  ctx->auth_size = 0;
  ctx->data_size = 0;
}

static void
mgm_hash_block(struct mgm_ctx *ctx,
	       const void *cipher, nettle_cipher_func *f,
	       const uint8_t *data)
{
  union nettle_block16 tmp;

  f(cipher, MGM_BLOCK_SIZE, tmp.b, ctx->z.b);
  mgm_gf_mul_sum(ctx, &tmp, data);
  INCREMENT(MGM_BLOCK_SIZE / 2, ctx->z.b);
}

void
mgm_update (struct mgm_ctx *ctx,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, const uint8_t *data)
{
  assert(ctx->auth_size % MGM_BLOCK_SIZE == 0);
  assert(ctx->data_size == 0);

  ctx->auth_size += length;

  while (length >= MGM_BLOCK_SIZE)
    {
      mgm_hash_block(ctx, cipher, f, data);
      data += MGM_BLOCK_SIZE;
      length -= MGM_BLOCK_SIZE;
    }

  if (length > 0)
    {
      union nettle_block16 aad_pad;

      aad_pad.u64[0] = 0;
      aad_pad.u64[1] = 0;
      memcpy(aad_pad.b, data, length);
      mgm_hash_block(ctx, cipher, f, aad_pad.b);
    }
}

void
mgm_encrypt (struct mgm_ctx *ctx,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  assert(ctx->data_size % MGM_BLOCK_SIZE == 0);

  ctx->data_size += length;

  while (length >= MGM_BLOCK_SIZE)
    {
      /* FIXME: here we can optimize the case when dst != src */
      /* Also we can do multi-block here */
      /* copy from CTR or GCM */
      union nettle_block16 tmp;

      f(cipher, MGM_BLOCK_SIZE, tmp.b, ctx->y.b);
      memxor3(dst, tmp.b, src, MGM_BLOCK_SIZE);
      INCREMENT(MGM_BLOCK_SIZE / 2, ctx->y.b + MGM_BLOCK_SIZE / 2);

      mgm_hash_block(ctx, cipher, f, dst);

      dst += MGM_BLOCK_SIZE;
      src += MGM_BLOCK_SIZE;
      length -= MGM_BLOCK_SIZE;
    }

  if (length != 0)
    {
      union nettle_block16 tmp;

      f(cipher, MGM_BLOCK_SIZE, tmp.b, ctx->y.b);
      memxor(tmp.b, src, length);
      memcpy(dst, tmp.b, length);
      memset(tmp.b + length, 0, MGM_BLOCK_SIZE - length);

      mgm_hash_block(ctx, cipher, f, tmp.b);
    }
}

void
mgm_decrypt (struct mgm_ctx *ctx,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  assert(ctx->data_size % MGM_BLOCK_SIZE == 0);

  ctx->data_size += length;

  while (length >= MGM_BLOCK_SIZE)
    {
      /* FIXME: here we can optimize the case when dst != src */
      /* Also we can do multi-block here */
      /* copy from CTR or GCM */
      union nettle_block16 tmp;

      mgm_hash_block(ctx, cipher, f, src);

      f(cipher, MGM_BLOCK_SIZE, tmp.b, ctx->y.b);
      memxor3(dst, tmp.b, src, MGM_BLOCK_SIZE);
      INCREMENT(MGM_BLOCK_SIZE / 2, ctx->y.b + MGM_BLOCK_SIZE / 2);

      dst += MGM_BLOCK_SIZE;
      src += MGM_BLOCK_SIZE;
      length -= MGM_BLOCK_SIZE;
    }

  if (length != 0)
    {
      union nettle_block16 tmp;

      memcpy(tmp.b, src, length);
      memset(tmp.b + length, 0, MGM_BLOCK_SIZE - length);
      mgm_hash_block(ctx, cipher, f, tmp.b);

      f(cipher, MGM_BLOCK_SIZE, tmp.b, ctx->y.b);
      memxor3(dst, tmp.b, src, length);
    }
}

void
mgm_digest(struct mgm_ctx *ctx,
	   const void *cipher, nettle_cipher_func *f,
	   size_t length, uint8_t *digest)
{
  uint8_t buffer[MGM_BLOCK_SIZE];

  WRITE_UINT64 (buffer, ctx->auth_size * 8);
  WRITE_UINT64 (buffer + 8, ctx->data_size * 8);

  mgm_hash_block(ctx, cipher, f, buffer);

  f(cipher, MGM_BLOCK_SIZE, ctx->sum.b, ctx->sum.b);
  memcpy(digest, ctx->sum.b, length);
}
