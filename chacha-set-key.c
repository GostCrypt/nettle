/* chacha-set-key.c
 *
 * Copyright (C) 2014 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include "chacha.h"

void
chacha_set_key(struct chacha_ctx *ctx, size_t length, const uint8_t *key)
{
  switch (length)
    {
    default:
      abort ();
    case CHACHA128_KEY_SIZE:
      chacha128_set_key (ctx, key);
      break;
    case CHACHA256_KEY_SIZE:
      chacha256_set_key (ctx, key);
      break;
    }
}