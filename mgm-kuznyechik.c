/* mgm-kuznyechik.c

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
#include "kuznyechik.h"

void
mgm_kuznyechik_set_key(struct mgm_kuznyechik_ctx *ctx, const uint8_t *key)
{
  MGM_SET_KEY (ctx, kuznyechik_set_key, key);
}

void
mgm_kuznyechik_set_iv (struct mgm_kuznyechik_ctx *ctx, const uint8_t *iv)
{
  MGM_SET_IV (ctx, kuznyechik_encrypt, iv);
}

void
mgm_kuznyechik_update (struct mgm_kuznyechik_ctx *ctx,
		       size_t length, const uint8_t *data)
{
  MGM_UPDATE (ctx, kuznyechik_encrypt, length, data);
}

void
mgm_kuznyechik_encrypt(struct mgm_kuznyechik_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src)
{
  MGM_ENCRYPT (ctx, kuznyechik_encrypt, length, dst, src);
}

void
mgm_kuznyechik_decrypt(struct mgm_kuznyechik_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src)
{
  MGM_DECRYPT (ctx, kuznyechik_encrypt, length, dst, src);
}

void
mgm_kuznyechik_digest(struct mgm_kuznyechik_ctx *ctx,
		      size_t length, uint8_t *digest)
{
  MGM_DIGEST (ctx, kuznyechik_encrypt, length, digest);
}
