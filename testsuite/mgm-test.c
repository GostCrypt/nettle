#include "config.h"
#include "nettle-types.h"
#include "testsuite/testutils.h"
#include "kuznyechik.h"
#include "magma.h"
#include "mgm.h"

static void
test_mgm_kuznyechik(void)
{
  const struct tstring *key =
    SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
  const struct tstring *aad =
    SHEX("02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01 "
	 "04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03 "
	 "EA 05 05 05 05 05 05 05 05 ");
  const struct tstring *cleartext =
    SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 "
	 "00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A "
	 "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 "
	 "22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 "
	 "AA BB CC");
  const struct tstring *iv =
    SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88");
  const struct tstring *ciphertext =
    SHEX("a9 75 7b 81 47 95 6e 90 55 b8 a3 3d e8 9f 42 fc"
	 "80 75 d2 21 2b f9 fd 5b d3 f7 06 9a ad c1 6b 39"
	 "49 7a b1 59 15 a6 ba 85 93 6b 5d 0e a9 f6 85 1c"
	 "c6 0c 14 d4 d3 f8 83 d0 ab 94 42 06 95 c7 6d eb"
	 "2c 75 52");
  const struct tstring *tag =
    SHEX("cf 5d 65 6f 40 c3 4f 5c 46 e8 bb 0e 29 fc db 4c");

  uint8_t data[cleartext->length];
  uint8_t tag_data[MGM_DIGEST_SIZE];

  struct mgm_ctx mgm;
  struct kuznyechik_ctx kuznyechik_ctx;

  /* set key */
  kuznyechik_set_key(&kuznyechik_ctx, key->data);

  /* set IV */
  mgm_set_iv(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, iv->data);

  /* update */
  mgm_update(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, aad->length, aad->data);

  /* encrypt */
  mgm_encrypt(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, cleartext->length, data, cleartext->data);

  if (!MEMEQ(ciphertext->length, data, ciphertext->data))
    {
      fprintf(stderr, "Encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(ciphertext->length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* tag */
  mgm_digest(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, MGM_DIGEST_SIZE, tag_data);

  if (!MEMEQ(tag->length, tag_data, tag->data))
    {
      fprintf(stderr, "Encrypt Tag failed:");
      fprintf(stderr, "\nOutput: ");
      print_hex(tag->length, tag_data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(tag);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* set IV */
  mgm_set_iv(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, iv->data);

  /* update */
  mgm_update(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, aad->length, aad->data);

  /* decrypt */
  mgm_decrypt(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, cleartext->length, data, data);

  if (!MEMEQ(cleartext->length, data, cleartext->data))
    {
      fprintf(stderr, "Decrypt failed:\nInput:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(cleartext->length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* tag */
  mgm_digest(&mgm, &kuznyechik_ctx, (nettle_cipher_func *) kuznyechik_encrypt, MGM_DIGEST_SIZE, tag_data);

  if (!MEMEQ(tag->length, tag_data, tag->data))
    {
      fprintf(stderr, "Decrypt Tag failed:");
      fprintf(stderr, "\nOutput: ");
      print_hex(tag->length, tag_data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(tag);
      fprintf(stderr, "\n");
      FAIL();
    }
}

static void
test_mgm_magma(void)
{
  const struct tstring *key =
    SHEX("FFEEDDCCBBAA99887766554433221100"
	 "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
  const struct tstring *aad =
    SHEX("01 01 01 01 01 01 01 01 02 02 02 02 02 02 02 02 "
	 "03 03 03 03 03 03 03 03 04 04 04 04 04 04 04 04 "
	 "05 05 05 05 05 05 05 05 EA ");
  const struct tstring *cleartext =
    SHEX("FF EE DD CC BB AA 99 88 11 22 33 44 55 66 77 00 "
	 "88 99 AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 "
	 "99 AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 88 "
	 "AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 88 99 "
	 "AA BB CC");
  const struct tstring *iv =
    SHEX("92DEF06B3C130A59");
  const struct tstring *ciphertext =
    SHEX("c795066c5f9ea03b 85113342459185ae"
	 "1f2e00d6bf2b785d 940470b8bb9c8e7d"
	 "9a5dd3731f7ddc70 ec27cb0ace6fa576"
	 "70f65c646abb75d5 47aa37c3bcb5c34e"
	 "03bb9c");
  const struct tstring *tag =
    SHEX("a7928069aa10fd10");

  uint8_t data[cleartext->length];
  uint8_t tag_data[MGM64_DIGEST_SIZE];

  struct mgm64_ctx mgm;
  struct magma_ctx magma_ctx;

  /* set key */
  magma_set_key(&magma_ctx, key->data);

  /* set IV */
  mgm64_set_iv(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, iv->data);

  /* update */
  mgm64_update(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, aad->length, aad->data);

  /* encrypt */
  mgm64_encrypt(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, cleartext->length, data, cleartext->data);

  if (!MEMEQ(ciphertext->length, data, ciphertext->data))
    {
      fprintf(stderr, "Encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(ciphertext->length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* tag */
  mgm64_digest(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, MGM64_DIGEST_SIZE, tag_data);

  if (!MEMEQ(tag->length, tag_data, tag->data))
    {
      fprintf(stderr, "Encrypt Tag failed:");
      fprintf(stderr, "\nOutput: ");
      print_hex(tag->length, tag_data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(tag);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* set IV */
  mgm64_set_iv(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, iv->data);

  /* update */
  mgm64_update(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, aad->length, aad->data);

  /* decrypt */
  mgm64_decrypt(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, cleartext->length, data, data);

  if (!MEMEQ(cleartext->length, data, cleartext->data))
    {
      fprintf(stderr, "Decrypt failed:\nInput:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(cleartext->length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  /* tag */
  mgm64_digest(&mgm, &magma_ctx, (nettle_cipher_func *) magma_encrypt, MGM64_DIGEST_SIZE, tag_data);

  if (!MEMEQ(tag->length, tag_data, tag->data))
    {
      fprintf(stderr, "Decrypt Tag failed:");
      fprintf(stderr, "\nOutput: ");
      print_hex(tag->length, tag_data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(tag);
      fprintf(stderr, "\n");
      FAIL();
    }
}

void
test_main(void)
{
  test_mgm_kuznyechik();

  test_mgm_magma();

  test_aead (&nettle_mgm_kuznyechik, NULL,
	     SHEX("88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77"
		  "fe dc ba 98 76 54 32 10 01 23 45 67 89 ab cd ef"),
	     SHEX("02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01 "
		  "04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03 "
		  "EA 05 05 05 05 05 05 05 05 "),
	     SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 "
		  "00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A "
		  "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 "
		  "22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 "
		  "AA BB CC"),
	     SHEX("a9 75 7b 81 47 95 6e 90 55 b8 a3 3d e8 9f 42 fc"
		  "80 75 d2 21 2b f9 fd 5b d3 f7 06 9a ad c1 6b 39"
		  "49 7a b1 59 15 a6 ba 85 93 6b 5d 0e a9 f6 85 1c"
		  "c6 0c 14 d4 d3 f8 83 d0 ab 94 42 06 95 c7 6d eb"
		  "2c 75 52"),
	     SHEX("11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"),
	     SHEX("cf 5d 65 6f 40 c3 4f 5c 46 e8 bb 0e 29 fc db 4c"));

  test_aead (&nettle_mgm_magma, NULL,
	     SHEX("FFEEDDCCBBAA99887766554433221100"
		  "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),
	     SHEX("01 01 01 01 01 01 01 01 02 02 02 02 02 02 02 02 "
		  "03 03 03 03 03 03 03 03 04 04 04 04 04 04 04 04 "
		  "05 05 05 05 05 05 05 05 EA "),
	     SHEX("FF EE DD CC BB AA 99 88 11 22 33 44 55 66 77 00 "
		  "88 99 AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 "
		  "99 AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 88 "
		  "AA BB CC EE FF 0A 00 11 22 33 44 55 66 77 88 99 "
		  "AA BB CC"),
	     SHEX("c795066c5f9ea03b 85113342459185ae"
		  "1f2e00d6bf2b785d 940470b8bb9c8e7d"
		  "9a5dd3731f7ddc70 ec27cb0ace6fa576"
		  "70f65c646abb75d5 47aa37c3bcb5c34e"
		  "03bb9c"),
	     SHEX("92DEF06B3C130A59"),
	     SHEX("a7928069aa10fd10"));

}
