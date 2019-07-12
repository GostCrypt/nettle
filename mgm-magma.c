/* mgm-magma.c

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

#include "mgm.h"
#include "magma.h"

void
mgm_magma_set_key(struct mgm_magma_ctx *ctx, const uint8_t *key)
{
  MGM64_SET_KEY (ctx, magma_set_key, key);
}

void
mgm_magma_set_iv (struct mgm_magma_ctx *ctx, const uint8_t *iv)
{
  MGM64_SET_IV (ctx, magma_encrypt, iv);
}

void
mgm_magma_update (struct mgm_magma_ctx *ctx,
		       size_t length, const uint8_t *data)
{
  MGM64_UPDATE (ctx, magma_encrypt, length, data);
}

void
mgm_magma_encrypt(struct mgm_magma_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src)
{
  MGM64_ENCRYPT (ctx, magma_encrypt, length, dst, src);
}

void
mgm_magma_decrypt(struct mgm_magma_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src)
{
  MGM64_DECRYPT (ctx, magma_encrypt, length, dst, src);
}

void
mgm_magma_digest(struct mgm_magma_ctx *ctx,
		      size_t length, uint8_t *digest)
{
  MGM64_DIGEST (ctx, magma_encrypt, length, digest);
}
