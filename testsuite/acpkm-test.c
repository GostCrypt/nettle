#include "testutils.h"
#include "acpkm.h"
#include "aes.h"
#include "magma.h"
#include "ctr.h"

struct test_acpkm_ctx
{
  void *cipher;
  struct acpkm_ctx ctx;
  nettle_set_key_func *set_key;
  nettle_cipher_func *crypt;
  unsigned key_size;
};

static void test_acpkm_crypt(struct test_acpkm_ctx *ctx,
			     size_t length, uint8_t *dst,
			     const uint8_t *src)
{
  acpkm_crypt(&ctx->ctx, ctx->cipher, ctx->crypt, ctx->set_key,
	      length, dst, src);
}

static
void test_cipher_ctr_acpkm(const struct nettle_cipher *cipher, size_t N,
			   const struct tstring *key,
			   const struct tstring *cleartext,
			   const struct tstring *ciphertext,
			   const struct tstring *ictr)
{
  struct test_acpkm_ctx *acpkm_ctx = xalloc(cipher->context_size + sizeof(struct test_acpkm_ctx));
  void *ctx = acpkm_ctx + 1;
  uint8_t *data = xalloc(cleartext->length);
  uint8_t *ctr = xalloc(cipher->block_size);
  size_t length = cleartext->length;

  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  ASSERT (key->length == cipher->key_size);
  ASSERT (ictr->length == cipher->block_size);

  /* Set key */
  cipher->set_encrypt_key(ctx, key->data);

  /* Setup ACPKM */
  acpkm_ctx->ctx.pos = 0;
  acpkm_ctx->ctx.N = N;

  /* Set test state */
  acpkm_ctx->cipher = ctx;
  acpkm_ctx->set_key = cipher->set_encrypt_key;
  acpkm_ctx->crypt = cipher->encrypt;
  acpkm_ctx->key_size = cipher->key_size;

  memcpy(ctr, ictr->data, cipher->block_size);
  memset(data, 17, length);

  ctr_crypt(acpkm_ctx, (nettle_cipher_func *)test_acpkm_crypt,
	    cipher->block_size, ctr,
	    length, data, cleartext->data);

  if (!MEMEQ(length, data, ciphertext->data))
    {
      fprintf(stderr, "CTR encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(acpkm_ctx);
  free(data);
  free(ctr);
}

void test_main(void)
{
  test_cipher_ctr_acpkm(&nettle_aes256, 256 / 8,
		  SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		  SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"
		       "00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
		       "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00"
		       "22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11"
		       "33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22"
		       "44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33"
		       "55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44"),
		  SHEX("EC 5C CB DE 8C 18 D3 B8 72 56 68 D0 A7 37 F4 58"
		       "19 89 E7 42 32 62 9D 60 99 7D E2 4B C0 E3 9F B8"
		       "F5 AA BA 0B E3 64 F0 53 EE F0 BC 15 C2 76 4C EA"
		       "9E 7C C3 76 BD 87 19 C9 77 0F CA 2D E2 A3 7C B5"
		       "5B 2B 77 1B F8 3A 05 17 BE 04 2D 82 28 FE 2A 95"
		       "84 4E 9F 08 FD F7 B8 94 4C B7 AA B7 DE 3C 67 B4"
		       "56 B8 43 FC 32 31 DE 46 D5 AB 14 F8 AC 09 C7 39"),
		  SHEX("12 34 56 78 90 AB CE F0 00 00 00 00 00 00 00 00"));

  test_cipher_ctr_acpkm(&nettle_magma, 128 / 8,
		  SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		  SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"
		       "00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
		       "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00"
		       "22 33 44 55 66 77 88 99"),
		  SHEX("2A B8 1D EE EB 1E 4C AB 68 E1 04 C4 BD 6B 94 EA"
		       "C7 2C 67 AF 6C 2E 5B 6B 0E AF B6 17 70 F1 B3 2E"
		       "A1 AE 71 14 9E ED 13 82 AB D4 67 18 06 72 EC 6F"
		       "84 A2 F1 5B 3F CA 72 C1"),
		  SHEX("12 34 56 78 00 00 00 00"));

  test_cipher_ctr_acpkm(&nettle_kuznyechik, 256 / 8,
		  SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		  SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"
		       "00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
		       "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00"
		       "22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11"
		       "33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22"
		       "44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33"
		       "55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44"),
		  SHEX("F1 95 D8 BE C1 0E D1 DB D5 7B 5F A2 40 BD A1 B8"
		       "85 EE E7 33 F6 A1 3E 5D F3 3C E4 B3 3C 45 DE E4"
		       "4B CE EB 8F 64 6F 4C 55 00 17 06 27 5E 85 E8 00"
		       "58 7C 4D F5 68 D0 94 39 3E 48 34 AF D0 80 50 46"
		       "CF 30 F5 76 86 AE EC E1 1C FC 6C 31 6B 8A 89 6E"
		       "DF FD 07 EC 81 36 36 46 0C 4F 3B 74 34 23 16 3E"
		       "64 09 A9 C2 82 FA C8 D4 69 D2 21 E7 FB D6 DE 5D"),
		  SHEX("12 34 56 78 90 AB CE F0 00 00 00 00 00 00 00 00"));
}
