/*
   Copyright: 2017 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>

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

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "macros.h"

static uint8_t pi[256] =
{
  0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16,
  0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
  0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
  0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
  0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21,
  0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
  0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0,
  0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
  0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
  0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
  0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12,
  0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
  0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7,
  0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
  0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
  0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
  0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9,
  0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
  0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc,
  0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
  0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
  0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
  0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f,
  0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
  0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7,
  0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
  0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
  0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
  0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b,
  0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
  0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0,
  0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
};

static uint8_t MGF2(uint16_t a, uint8_t b)
{
  uint16_t s = 0;
  uint16_t m;
  uint16_t p;

  for (m = 1; m != 0x100; m <<= 1, a <<= 1)
    {
      if (b & m)
	{
	  s ^= a;
	}
    }

  for (m = 0x8000, p = 0xc3 << 7; m >= 256; m >>= 1, p >>= 1)
    {
      if (s & m)
	{
	  s &= ~m;
	  s ^= p;
	}
    }
  return s;
}

static uint8_t larr[16] =
{
  1, 148, 32, 133, 16,
  194, 192, 1, 251, 1, 192,
  194, 16, 133, 32, 148,
};

static void Linv(uint8_t *a)
{
  uint8_t i;

  for (i = 0; i < 16; i++)
    {
      uint8_t c = 0;
      unsigned j;

      for (j = 0; j < 16; j++)
	c ^= MGF2(larr[j], a[(i + j) % 16]);
      a[i] = c;
    }
}

static void L(uint8_t *a)
{
  uint8_t i;

  for (i = 15; i < 16; i--) { /* 16 iterations from 15 to 0 */
      uint8_t c = 0;
      unsigned j;

      for (j = 0; j < 16; j++)
	c ^= MGF2(larr[j], a[(i + j) % 16]);
      a[i] = c;
  }
}


int main(void)
{
  unsigned i, j, k;
  uint8_t pi_inv[256];

  printf("static const uint8_t pi[256] =\n{\n  ");
  for (i = 0; i < 256; i++)
    {
      printf("0x%02hhx,%s", pi[i], (i + 1) % 8 ? " " : i == 255 ? "\n" : "\n  ");
    }
  printf("};\n\n");
  for (i = 0; i < 256; i++)
    {
      pi_inv[pi[i]] = i;
    }
  printf("static const uint8_t pi_inv[256] =\n{\n  ");
  for (i = 0; i < 256; i++)
    {
      printf("0x%02hhx,%s", pi_inv[i], (i + 1) % 8 ? " " : i == 255 ? "\n" : "\n  ");
    }
  printf("};\n\n");
  printf("static const uint8_t kuz_key_table[32][16] =\n{\n");
  for (i = 0; i < 32; i++)
    {
      uint8_t a[16] = {};
      a[15] = i + 1;
      L(a);
      printf("  {");
      for (j = 0; j < 16; j++)
	printf(" 0x%02hhx,", a[j]);
      printf("},\n");
#if 0
      printf("\t{ 0x%016" PRIx64 "ULL, 0x%016" PRIx64 "ULL, },\n", READ_UINT64(a), READ_UINT64(a+8));
#endif
    }
  printf("};\n\n");
  printf("static const uint8_t kuz_table[16][256 * 16] =\n{\n");
  for (i = 0; i < 16; i++)
    {
      printf("  { /* %d */\n", i);
      for (j = 0; j < 256; j++)
	{
	  uint8_t a[16] = {};

	  a[i] = pi[j];
	  L(a);
	  printf("   ");
	  for (k = 0; k < 16; k++)
	    printf(" 0x%02hhx,", a[k]);
	  printf("\n");
	}
      printf("  },\n");
    }
  printf("};\n\n");
  printf("static const uint8_t kuz_table_inv[16][256 * 16] =\n{\n");
  for (i = 0; i < 16; i++)
    {
      printf("  { /* %d */\n", i);
      for (j = 0; j < 256; j++)
	{
	  uint8_t a[16] = {};

	  a[i] = j;
	  Linv(a);
	  printf("   ");
	  for (k = 0; k < 16; k++)
	    printf(" 0x%02hhx,", a[k]);
	  printf("\n");
	}
      printf("  },\n");
    }
  printf("};\n\n");
  printf("static const uint8_t kuz_table_inv_LS[16][256 * 16] =\n{\n");
  for (i = 0; i < 16; i++)
    {
      printf("  { /* %d */\n", i);
      for (j = 0; j < 256; j++)
	{
	  uint8_t a[16] = {};

	  a[i] = pi_inv[j];
	  Linv(a);
	  printf("   ");
	  for (k = 0; k < 16; k++)
	    printf(" 0x%02hhx,", a[k]);
	  printf("\n");
	}
      printf("  },\n");
    }
  printf("};\n");

  return 0;
}
