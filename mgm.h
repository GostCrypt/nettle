/* mgm.h

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

#ifndef NETTLE_MGM_H_INCLUDED
#define NETTLE_MGM_H_INCLUDED

#include "nettle-types.h"
#include "kuznyechik.h"
#include "magma.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define mgm_set_key nettle_mgm_set_key
#define mgm_set_iv nettle_mgm_set_iv
#define mgm_update nettle_mgm_update
#define mgm_encrypt nettle_mgm_encrypt
#define mgm_decrypt nettle_mgm_decrypt
#define mgm_digest nettle_mgm_digest

#define mgm64_set_key nettle_mgm64_set_key
#define mgm64_set_iv nettle_mgm64_set_iv
#define mgm64_update nettle_mgm64_update
#define mgm64_encrypt nettle_mgm64_encrypt
#define mgm64_decrypt nettle_mgm64_decrypt
#define mgm64_digest nettle_mgm64_digest

#define mgm_kuznyechik_set_key nettle_mgm_kuznyechik_set_key
#define mgm_kuznyechik_set_iv nettle_mgm_kuznyechik_set_iv
#define mgm_kuznyechik_update nettle_mgm_kuznyechik_update
#define mgm_kuznyechik_encrypt nettle_mgm_kuznyechik_encrypt
#define mgm_kuznyechik_decrypt nettle_mgm_kuznyechik_decrypt
#define mgm_kuznyechik_digest nettle_mgm_kuznyechik_digest

#define mgm_magma_set_key nettle_mgm_magma_set_key
#define mgm_magma_set_iv nettle_mgm_magma_set_iv
#define mgm_magma_update nettle_mgm_magma_update
#define mgm_magma_encrypt nettle_mgm_magma_encrypt
#define mgm_magma_decrypt nettle_mgm_magma_decrypt
#define mgm_magma_digest nettle_mgm_magma_digest

#define MGM_BLOCK_SIZE  16
#define MGM_IV_SIZE  16
#define MGM_DIGEST_SIZE  16

#define MGM64_BLOCK_SIZE  8
#define MGM64_IV_SIZE  8
#define MGM64_DIGEST_SIZE  8

struct mgm_ctx
{
  union nettle_block16 y;
  union nettle_block16 z;
  union nettle_block16 sum;
  uint64_t auth_size;
  uint64_t data_size;
};

void
mgm_set_iv (struct mgm_ctx *ctx,
	    const void *cipher, nettle_cipher_func *f,
	    const uint8_t *nonce);

void
mgm_update (struct mgm_ctx *ctx,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, const uint8_t *data);

void
mgm_encrypt (struct mgm_ctx *ctx,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_decrypt (struct mgm_ctx *ctx,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_digest(struct mgm_ctx *ctx,
	   const void *cipher, nettle_cipher_func *f,
	   size_t length, uint8_t *digest);

struct mgm64_ctx
{
  union nettle_block8 y;
  union nettle_block8 z;
  union nettle_block8 sum;
  uint32_t auth_size;
  uint32_t data_size;
};

void
mgm64_set_iv (struct mgm64_ctx *ctx,
	      const void *cipher, nettle_cipher_func *f,
	      const uint8_t *nonce);

void
mgm64_update (struct mgm64_ctx *ctx,
	      const void *cipher, nettle_cipher_func *f,
	      size_t length, const uint8_t *data);

void
mgm64_encrypt (struct mgm64_ctx *ctx,
	       const void *cipher, nettle_cipher_func *f,
	       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm64_decrypt (struct mgm64_ctx *ctx,
	       const void *cipher, nettle_cipher_func *f,
	       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm64_digest(struct mgm64_ctx *ctx,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *digest);

/* Convenience macrology (not sure how useful it is) */
/* All-in-one context, with hash subkey, message state, and cipher. */
#define MGM_CTX(type) \
  { struct mgm_ctx mgm; type cipher; }

/* NOTE: Avoid using NULL, as we don't include anything defining it. */
#define MGM_SET_KEY(ctx, set_key, mgm_key)				\
  do {									\
    (set_key)(&(ctx)->cipher, (mgm_key));				\
  } while (0)

#define MGM_SET_IV(ctx, encrypt, data)					\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm_set_iv(&(ctx)->mgm, &(ctx)->cipher,				\
		  (nettle_cipher_func *) (encrypt), (data)))

#define MGM_UPDATE(ctx, encrypt, length, data)				\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm_update(&(ctx)->mgm, &(ctx)->cipher,				\
		  (nettle_cipher_func *) (encrypt),			\
		  (length), (data)))

#define MGM_ENCRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm_encrypt(&(ctx)->mgm, &(ctx)->cipher,				\
		   (nettle_cipher_func *) (encrypt),			\
		   (length), (dst), (src)))

#define MGM_DECRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm_decrypt(&(ctx)->mgm, &(ctx)->cipher,				\
		   (nettle_cipher_func *) (encrypt),			\
		   (length), (dst), (src)))

#define MGM_DIGEST(ctx, encrypt, length, digest)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm_digest(&(ctx)->mgm, &(ctx)->cipher,				\
		  (nettle_cipher_func *) (encrypt),			\
		  (length), (digest)))

#define MGM64_CTX(type) \
  { struct mgm64_ctx mgm64; type cipher; }

/* NOTE: Avoid using NULL, as we don't include anything defining it. */
#define MGM64_SET_KEY(ctx, set_key, mgm64_key)				\
  do {									\
    (set_key)(&(ctx)->cipher, (mgm64_key));				\
  } while (0)

#define MGM64_SET_IV(ctx, encrypt, data)				\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm64_set_iv(&(ctx)->mgm64, &(ctx)->cipher,			\
		  (nettle_cipher_func *) (encrypt), (data)))

#define MGM64_UPDATE(ctx, encrypt, length, data)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm64_update(&(ctx)->mgm64, &(ctx)->cipher,			\
		  (nettle_cipher_func *) (encrypt),			\
		  (length), (data)))

#define MGM64_ENCRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm64_encrypt(&(ctx)->mgm64, &(ctx)->cipher,			\
		   (nettle_cipher_func *) (encrypt),			\
		   (length), (dst), (src)))

#define MGM64_DECRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm64_decrypt(&(ctx)->mgm64, &(ctx)->cipher,			\
		   (nettle_cipher_func *) (encrypt),			\
		   (length), (dst), (src)))

#define MGM64_DIGEST(ctx, encrypt, length, digest)			\
  (0 ? (encrypt)(&(ctx)->cipher, ~(size_t) 0,				\
		 (uint8_t *) 0, (const uint8_t *) 0)			\
     : mgm64_digest(&(ctx)->mgm64, &(ctx)->cipher,			\
		  (nettle_cipher_func *) (encrypt),			\
		  (length), (digest)))

struct mgm_kuznyechik_ctx MGM_CTX(struct kuznyechik_ctx);

void
mgm_kuznyechik_set_key(struct mgm_kuznyechik_ctx *ctx, const uint8_t *key);

void
mgm_kuznyechik_set_iv (struct mgm_kuznyechik_ctx *ctx, const uint8_t *iv);

void
mgm_kuznyechik_update (struct mgm_kuznyechik_ctx *ctx,
		       size_t length, const uint8_t *data);
void
mgm_kuznyechik_encrypt(struct mgm_kuznyechik_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_kuznyechik_decrypt(struct mgm_kuznyechik_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_kuznyechik_digest(struct mgm_kuznyechik_ctx *ctx,
		      size_t length, uint8_t *digest);

struct mgm_magma_ctx MGM64_CTX(struct magma_ctx);

void
mgm_magma_set_key(struct mgm_magma_ctx *ctx, const uint8_t *key);

void
mgm_magma_set_iv (struct mgm_magma_ctx *ctx, const uint8_t *iv);

void
mgm_magma_update (struct mgm_magma_ctx *ctx,
		       size_t length, const uint8_t *data);
void
mgm_magma_encrypt(struct mgm_magma_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_magma_decrypt(struct mgm_magma_ctx *ctx,
		       size_t length, uint8_t *dst, const uint8_t *src);

void
mgm_magma_digest(struct mgm_magma_ctx *ctx,
		      size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_MGM_H_INCLUDED */
