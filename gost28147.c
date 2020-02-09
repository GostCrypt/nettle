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

#include <assert.h>
#include <string.h>

#include "macros.h"
#include "gost28147.h"
#include "gost28147-internal.h"
#include "memxor.h"

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

static
void _gost28147_decrypt_block (const uint32_t *key, const uint32_t sbox[4][256],
			       const uint32_t *in, uint32_t *out)
{
  uint32_t l, r;

  r = in[0], l = in[1];
  GOST_ENCRYPT_ROUND(l, r, key[0], key[1], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[2], key[3], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[4], key[5], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[6], key[7], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[7], key[6], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[5], key[4], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[3], key[2], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[1], key[0], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[7], key[6], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[5], key[4], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[3], key[2], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[1], key[0], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[7], key[6], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[5], key[4], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[3], key[2], sbox);
  GOST_ENCRYPT_ROUND(l, r, key[1], key[0], sbox);
  *out = l, *(out + 1) = r;
}

static const uint32_t gost28147_key_mesh_cryptopro_data[GOST28147_KEY_SIZE / 4] = {
  0x22720069, 0x2304c964,
  0x96db3a8d, 0xc42ae946,
  0x94acfe18, 0x1207ed00,
  0xc2dc86c0, 0x2ba94cef,
};

static void gost28147_key_mesh_cryptopro(struct gost28147_ctx *ctx)
{
  uint32_t newkey[GOST28147_KEY_SIZE/4];

  _gost28147_decrypt_block(ctx->key, ctx->sbox,
			   &gost28147_key_mesh_cryptopro_data[0],
			   &newkey[0]);

  _gost28147_decrypt_block(ctx->key, ctx->sbox,
			   &gost28147_key_mesh_cryptopro_data[2],
			   &newkey[2]);

  _gost28147_decrypt_block(ctx->key, ctx->sbox,
			   &gost28147_key_mesh_cryptopro_data[4],
			   &newkey[4]);

  _gost28147_decrypt_block(ctx->key, ctx->sbox,
			   &gost28147_key_mesh_cryptopro_data[6],
			   &newkey[6]);

  memcpy(ctx->key, newkey, sizeof(newkey));
  ctx->key_count = 0;
}

void
gost28147_set_key(struct gost28147_ctx *ctx, const uint8_t *key)
{
  unsigned i;

  assert(key);
  for (i = 0; i < 8; i++, key += 4)
    ctx->key[i] = LE_READ_UINT32(key);
  ctx->key_count = 0;
}

void
gost28147_set_param(struct gost28147_ctx *ctx, const struct gost28147_param *param)
{
  assert(param);
  ctx->sbox = param->sbox;
  ctx->key_meshing = param->key_meshing;
}

void
gost28147_encrypt(const struct gost28147_ctx *ctx,
		  size_t length, uint8_t *dst,
		  const uint8_t *src)
{
  uint32_t block[2];

  assert(!(length % GOST28147_BLOCK_SIZE));

  while (length)
    {
      block[0] = LE_READ_UINT32(src); src += 4;
      block[1] = LE_READ_UINT32(src); src += 4;
      _gost28147_encrypt_block(ctx->key, ctx->sbox, block, block);
      LE_WRITE_UINT32(dst, block[0]); dst += 4;
      LE_WRITE_UINT32(dst, block[1]); dst += 4;
      length -= GOST28147_BLOCK_SIZE;
    }
}

void
gost28147_decrypt(const struct gost28147_ctx *ctx,
		  size_t length, uint8_t *dst,
		  const uint8_t *src)
{
  uint32_t block[2];

  assert(!(length % GOST28147_BLOCK_SIZE));

  while (length)
    {
      block[0] = LE_READ_UINT32(src); src += 4;
      block[1] = LE_READ_UINT32(src); src += 4;
      _gost28147_decrypt_block(ctx->key, ctx->sbox, block, block);
      LE_WRITE_UINT32(dst, block[0]); dst += 4;
      LE_WRITE_UINT32(dst, block[1]); dst += 4;
      length -= GOST28147_BLOCK_SIZE;
    }
}

void
gost28147_encrypt_keymesh(struct gost28147_ctx *ctx,
			  size_t length, uint8_t *dst,
			  const uint8_t *src)
{
  uint32_t block[2];

  assert(!(length % GOST28147_BLOCK_SIZE));

  while (length)
    {
      block[0] = LE_READ_UINT32(src); src += 4;
      block[1] = LE_READ_UINT32(src); src += 4;
      if (ctx->key_meshing && ctx->key_count == 1024)
	{
	  gost28147_key_mesh_cryptopro(ctx);
	  _gost28147_encrypt_block(ctx->key, ctx->sbox, block, block);
	  ctx->key_count = 0;
	}
      _gost28147_encrypt_block(ctx->key, ctx->sbox, block, block);
      LE_WRITE_UINT32(dst, block[0]); dst += 4;
      LE_WRITE_UINT32(dst, block[1]); dst += 4;
      length -= GOST28147_BLOCK_SIZE;
      ctx->key_count += GOST28147_BLOCK_SIZE;
    }
}

static void
gost28147_cnt_next_iv(struct gost28147_cnt_ctx *ctx,
		      uint8_t *out)
{
  uint32_t block[2];
  uint32_t temp;

  if (ctx->ctx.key_meshing && ctx->ctx.key_count == 1024)
    {
      gost28147_key_mesh_cryptopro(&ctx->ctx);
      _gost28147_encrypt_block(ctx->ctx.key, ctx->ctx.sbox, ctx->iv, ctx->iv);
      ctx->ctx.key_count = 0;
    }

  ctx->iv[0] += 0x01010101;
  temp = ctx->iv[1] + 0x01010104;
  if (temp < ctx->iv[1])
    ctx->iv[1] = temp + 1; /* Overflow */
  else
    ctx->iv[1] = temp;

  _gost28147_encrypt_block(ctx->ctx.key, ctx->ctx.sbox, ctx->iv, block);

  LE_WRITE_UINT32(out + 0, block[0]);
  LE_WRITE_UINT32(out + 4, block[1]);

  ctx->ctx.key_count += GOST28147_BLOCK_SIZE;
}

void
gost28147_cnt_set_key(struct gost28147_cnt_ctx *ctx,
		      const uint8_t *key,
		      const struct gost28147_param *param)
{
  gost28147_set_param(&ctx->ctx, param);
  gost28147_set_key(&ctx->ctx, key);
  ctx->bytes = 0;
}

void
gost28147_cnt_set_iv(struct gost28147_cnt_ctx *ctx,
		     const uint8_t *iv)
{
  uint32_t block[2];

  block[0] = LE_READ_UINT32(iv + 0);
  block[1] = LE_READ_UINT32(iv + 4);

  _gost28147_encrypt_block(ctx->ctx.key, ctx->ctx.sbox, block, ctx->iv);
}

void
gost28147_cnt_crypt(struct gost28147_cnt_ctx *ctx,
		    size_t length, uint8_t *dst,
		    const uint8_t *src)
{
  size_t block_size = GOST28147_BLOCK_SIZE;

  if (ctx->bytes)
    {
      size_t part = ctx->bytes < length ? ctx->bytes : length;
      memxor3(dst, src, ctx->buffer + block_size - ctx->bytes, part);
      dst += part;
      src += part;
      length -= part;
      ctx->bytes -= part;
      ctx->bytes %= block_size;
    }
  while (length >= block_size)
    {
      gost28147_cnt_next_iv(ctx, ctx->buffer);
      memxor3(dst, src, ctx->buffer, block_size);
      length -= block_size;
      src += block_size;
      dst += block_size;
    }

  if (length != 0)
    {
      gost28147_cnt_next_iv(ctx, ctx->buffer);
      memxor3(dst, src, ctx->buffer, length);
      ctx->bytes = block_size - length;
    }
}
