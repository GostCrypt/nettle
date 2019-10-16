/*
 * Copyright (C) 2019 Dmitry Eremin-Solenikov

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

#include "hmac.h"
#include "macros.h"
#include "gost-kdf.h"

/* See RFC 7836 */
static void
kdf_tree_gostr3411_2012_256_single (struct hmac_streebog256_ctx *ctx,
				    size_t i_length, const uint8_t *i,
				    size_t label_length, const uint8_t *label,
				    size_t seed_length, const uint8_t *seed,
				    size_t l_length, const uint8_t *l,
				    size_t length, uint8_t *out)
{
  /* i label 0x00 seed l */
  uint8_t data[] = { 0x00 };

  hmac_streebog256_update(ctx, i_length, i);
  hmac_streebog256_update(ctx, label_length, label);
  hmac_streebog256_update(ctx, 1, data);
  hmac_streebog256_update(ctx, seed_length, seed);
  hmac_streebog256_update(ctx, l_length, l);

  hmac_streebog256_digest(ctx, length, out);
}

void
kdf_gostr3411_2012_256 (size_t key_length, const uint8_t *key,
			size_t label_length, const uint8_t *label,
			size_t seed_length, const uint8_t *seed,
			size_t length, uint8_t *out)
{
  struct hmac_streebog256_ctx ctx;
  uint8_t data1[] = { 0x01 };
  uint8_t data2[] = { 0x01, 0x00 };

  hmac_streebog256_set_key(&ctx, key_length, key);
  kdf_tree_gostr3411_2012_256_single (&ctx,
				     sizeof(data1), data1,
				     label_length, label,
				     seed_length, seed,
				     sizeof(data2), data2,
				     length, out);
}

void
kdf_tree_gostr3411_2012_256 (size_t key_length, const uint8_t *key,
			     size_t label_length, const uint8_t *label,
			     size_t seed_length, const uint8_t *seed,
			     size_t r,
			     size_t length, uint8_t *out)
{
  size_t i;
  uint8_t i_block[4], l_block[8];
  struct hmac_streebog256_ctx ctx;
  size_t l_length, l_off;
  size_t i_off = 4 - r;

  hmac_streebog256_set_key(&ctx, key_length, key);
  WRITE_UINT64(l_block, length * 8ULL);
  for (i = 0; i < 8; i++)
    {
      if (l_block[i] != 0)
	break;
    }
  l_off = i;
  l_length = 8 - l_off;
  for (i = 1; length > 0; i++)
    {
      size_t block = length > 32 ? 32 : length;
      WRITE_UINT32(i_block, i);
      kdf_tree_gostr3411_2012_256_single(&ctx,
					 r, i_block + i_off,
					 label_length, label,
					 seed_length, seed,
					 l_length, l_block + l_off,
					 block, out);
      out += block;
      length -= block;
    }
}
