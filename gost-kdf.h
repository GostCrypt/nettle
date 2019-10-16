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

#endif
