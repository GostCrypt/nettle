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

#ifndef GOST_KDF_H_INCLUDED
#define GOST_KDF_H_INCLUDED

#define kdf_gostr3411_2012_256 nettle_kdf_gostr3411_2012_256
#define kdf_tree_gostr3411_2012_256 nettle_kdf_tree_gostr3411_2012_256
#define tlstree_init nettle_tlstree_init
#define tlstree_get nettle_tlstree_get
#define tlstree_magma_const nettle_tlstree_magma_const
#define tlstree_kuznyechik_const nettle_tlstree_kuznyechik_const

void
kdf_gostr3411_2012_256 (size_t key_length, const uint8_t *key,
			size_t label_length, const uint8_t *label,
			size_t seed_length, const uint8_t *seed,
			size_t length, uint8_t *out);

void
kdf_tree_gostr3411_2012_256 (size_t key_length, const uint8_t *key,
			     size_t label_length, const uint8_t *label,
			     size_t seed_length, const uint8_t *seed,
			     size_t r,
			     size_t length, uint8_t *out);

#define TLSTREE_KEY_LENGTH 32

struct tlstree_const
{
	uint64_t c1, c2, c3;
};

struct tlstree_ctx
{
  uint8_t k1[TLSTREE_KEY_LENGTH];
  uint8_t k2[TLSTREE_KEY_LENGTH];
  uint8_t k3[TLSTREE_KEY_LENGTH];
  uint64_t seq;
};

extern const struct tlstree_const tlstree_magma_const;
extern const struct tlstree_const tlstree_kuznyechik_const;

void tlstree_init(struct tlstree_ctx *ctx,
		  const struct tlstree_const *tlsconst, const uint8_t *key);
void tlstree_get(struct tlstree_ctx *ctx,
		 const struct tlstree_const *tlsconst, const uint8_t *key,
		 uint64_t seq, uint8_t *out);

#endif
