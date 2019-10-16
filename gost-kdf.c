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

#include <string.h>

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

/* draft-smyshlyaev-tls12-gost-suites */

#define TLSTREE_L1 ((uint8_t *)"level1")
#define TLSTREE_L2 ((uint8_t *)"level2")
#define TLSTREE_L3 ((uint8_t *)"level3")

const struct tlstree_const tlstree_magma_const =
{
  .c1 = UINT64_C(0xFFFFFFC000000000),
  .c2 = UINT64_C(0xFFFFFFFFFE000000),
  .c3 = UINT64_C(0xFFFFFFFFFFFFF000)
};

const struct tlstree_const tlstree_kuznyechik_const =
{
  .c1 = UINT64_C(0xFFFFFFFF00000000),
  .c2 = UINT64_C(0xFFFFFFFFFFF80000),
  .c3 = UINT64_C(0xFFFFFFFFFFFFFFC0)
};

void tlstree_init(struct tlstree_ctx *ctx,
		  const struct tlstree_const *tlsconst,
		  const uint8_t *key)
{
  uint8_t s[8];

  ctx->seq = 0;

  memset(s, 0, sizeof(s));
  kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, key,
			 6, TLSTREE_L1,
			 sizeof(s), s,
			 TLSTREE_KEY_LENGTH, ctx->k1);
  kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, ctx->k1,
			 6, TLSTREE_L2,
			 sizeof(s), s,
			 TLSTREE_KEY_LENGTH, ctx->k2);
  kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, ctx->k2,
			 6, TLSTREE_L3,
			 sizeof(s), s,
			 TLSTREE_KEY_LENGTH, ctx->k3);
}

void tlstree_get(struct tlstree_ctx *ctx,
		 const struct tlstree_const *tlsconst,
		 const uint8_t *key,
		 uint64_t seq, uint8_t *out)
{
  uint8_t s[8];

  if ((seq & tlsconst->c1) != (ctx->seq & tlsconst->c1))
    {
      WRITE_UINT64(s, seq & tlsconst->c1);
      kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, key,
			     6, TLSTREE_L1,
			     sizeof(s), s,
			     TLSTREE_KEY_LENGTH, ctx->k1);
    }

  if ((seq & tlsconst->c2) != (ctx->seq & tlsconst->c2))
    {
      WRITE_UINT64(s, seq & tlsconst->c2);
      kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, ctx->k1,
			     6, TLSTREE_L2,
			     sizeof(s), s,
			     TLSTREE_KEY_LENGTH, ctx->k2);
    }

  if ((seq & tlsconst->c3) != (ctx->seq & tlsconst->c3))
    {
      WRITE_UINT64(s, seq & tlsconst->c3);
      kdf_gostr3411_2012_256(TLSTREE_KEY_LENGTH, ctx->k2,
			     6, TLSTREE_L3,
			     sizeof(s), s,
			     TLSTREE_KEY_LENGTH, ctx->k3);
    }

  ctx->seq = seq;

  memcpy(out, ctx->k3, TLSTREE_KEY_LENGTH);
}
