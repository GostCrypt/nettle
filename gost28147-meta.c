/* gost28147-meta.c

   Copyright (C) 2016 Dmitry Eremin-Solenikov

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

#include "nettle-meta.h"

#include "gost28147.h"
#include "gost28147-internal.h"

static void _gost28147_set_key_cpa (void *ctx, const uint8_t *key)
{
  gost28147_set_param (ctx, &_gost28147_param_CryptoPro_A);
  gost28147_set_key (ctx, key);
}

static void _gost28147_set_key_cpb (void *ctx, const uint8_t *key)
{
  gost28147_set_param (ctx, &_gost28147_param_CryptoPro_B);
  gost28147_set_key (ctx, key);
}

static void _gost28147_set_key_cpc (void *ctx, const uint8_t *key)
{
  gost28147_set_param (ctx, &_gost28147_param_CryptoPro_C);
  gost28147_set_key (ctx, key);
}

static void _gost28147_set_key_cpd (void *ctx, const uint8_t *key)
{
  gost28147_set_param (ctx, &_gost28147_param_CryptoPro_D);
  gost28147_set_key (ctx, key);
}

static void _gost28147_set_key_tc26z (void *ctx, const uint8_t *key)
{
  gost28147_set_param (ctx, &_gost28147_param_TC26_Z);
  gost28147_set_key (ctx, key);
}

const struct nettle_cipher nettle_gost28147_cpa =
  { "gost28147_cpa", sizeof(struct gost28147_ctx),
    GOST28147_BLOCK_SIZE, GOST28147_KEY_SIZE,
    (nettle_set_key_func *) _gost28147_set_key_cpa,
    (nettle_set_key_func *) _gost28147_set_key_cpa,
    (nettle_cipher_func *) gost28147_encrypt_keymesh,
    (nettle_cipher_func *) gost28147_encrypt_keymesh
  };

const struct nettle_cipher nettle_gost28147_cpb =
  { "gost28147_cpb", sizeof(struct gost28147_ctx),
    GOST28147_BLOCK_SIZE, GOST28147_KEY_SIZE,
    (nettle_set_key_func *) _gost28147_set_key_cpb,
    (nettle_set_key_func *) _gost28147_set_key_cpb,
    (nettle_cipher_func *) gost28147_encrypt_keymesh,
    (nettle_cipher_func *) gost28147_encrypt_keymesh
  };

const struct nettle_cipher nettle_gost28147_cpc =
  { "gost28147_cpc", sizeof(struct gost28147_ctx),
    GOST28147_BLOCK_SIZE, GOST28147_KEY_SIZE,
    (nettle_set_key_func *) _gost28147_set_key_cpc,
    (nettle_set_key_func *) _gost28147_set_key_cpc,
    (nettle_cipher_func *) gost28147_encrypt_keymesh,
    (nettle_cipher_func *) gost28147_encrypt_keymesh
  };

const struct nettle_cipher nettle_gost28147_cpd =
  { "gost28147_cpd", sizeof(struct gost28147_ctx),
    GOST28147_BLOCK_SIZE, GOST28147_KEY_SIZE,
    (nettle_set_key_func *) _gost28147_set_key_cpd,
    (nettle_set_key_func *) _gost28147_set_key_cpd,
    (nettle_cipher_func *) gost28147_encrypt_keymesh,
    (nettle_cipher_func *) gost28147_encrypt_keymesh
  };

const struct nettle_cipher nettle_gost28147_tc26z =
  { "gost28147_tc26z", sizeof(struct gost28147_ctx),
    GOST28147_BLOCK_SIZE, GOST28147_KEY_SIZE,
    (nettle_set_key_func *) _gost28147_set_key_tc26z,
    (nettle_set_key_func *) _gost28147_set_key_tc26z,
    (nettle_cipher_func *) gost28147_encrypt_keymesh,
    (nettle_cipher_func *) gost28147_encrypt_keymesh
  };
