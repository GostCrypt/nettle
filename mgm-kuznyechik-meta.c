/* mgm-kuznyechik-meta.c

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

#include "nettle-meta.h"

#include "mgm.h"

const struct nettle_aead nettle_mgm_kuznyechik =
  { "mgm_kuznyechik", sizeof(struct mgm_kuznyechik_ctx),
    MGM_BLOCK_SIZE, KUZNYECHIK_KEY_SIZE,
    MGM_IV_SIZE, MGM_DIGEST_SIZE,
    (nettle_set_key_func *) mgm_kuznyechik_set_key,
    (nettle_set_key_func *) mgm_kuznyechik_set_key,
    (nettle_set_key_func *) mgm_kuznyechik_set_iv,
    (nettle_hash_update_func *) mgm_kuznyechik_update,
    (nettle_crypt_func *) mgm_kuznyechik_encrypt,
    (nettle_crypt_func *) mgm_kuznyechik_decrypt,
    (nettle_hash_digest_func *) mgm_kuznyechik_digest,
  };
