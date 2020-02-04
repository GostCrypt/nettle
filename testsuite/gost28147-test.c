#include "testutils.h"
#include "gost28147.h"
#include "cfb.h"
#include "macros.h"

static void
test_gost28147(const struct gost28147_param *param,
	       const struct tstring *key,
	       const struct tstring *cleartext,
	       const struct tstring *ciphertext)
{
  struct gost28147_ctx ctx;
  uint8_t *data = xalloc(cleartext->length);
  size_t length;

  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  gost28147_set_param(&ctx, param);
  gost28147_set_key(&ctx, key->data);
  gost28147_encrypt(&ctx, length, data, cleartext->data);

  if (!MEMEQ(length, data, ciphertext->data))
    {
      fprintf(stderr, "Encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }

  gost28147_set_param(&ctx, param);
  gost28147_set_key(&ctx, key->data);
  gost28147_decrypt(&ctx, length, data, data);

  if (!MEMEQ(length, data, cleartext->data))
    {
      fprintf(stderr, "Decrypt failed:\nInput:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(data);
}

void test_main(void)
{
  /* Examples from GOST R 34.11-94 standard, see RFC 5831, Section 7.3.1.
   * Exaples there are represented in different endianness */
  test_gost28147(gost28147_get_param_test_3411(),
      SHEX("546D2033 68656C32 69736520 73736E62 20616779 69677474 73656865 202C3D73"),
      SHEX("00000000 00000000"),
      SHEX("1B0BBC32 CEBCAB42"));

  test_gost28147(gost28147_get_param_test_3411(),
      SHEX("2033394D 6C320D09 65201A16 6E62001D 67794106 74740E13 6865160D 3D730C11"),
      SHEX("00000000 00000000"),
      SHEX("FDCF9B5D C8EB0352"));

  test_gost28147(gost28147_get_param_test_3411(),
      SHEX("39B213F5 F209A13F 1AE9BA3A FF1D0C62 41F9E1C7 F1130085 16F20D73 F311B180"),
      SHEX("00000000 00000000"),
      SHEX("280EFF00 9958348D"));

  test_gost28147(gost28147_get_param_test_3411(),
      SHEX("EC0A8BA1 5EC004A8 BAC50CAC 0C621DEE E1C7B8E7 007AE2EC F2731BFF 4E80E2A0 "),
      SHEX("00000000 00000000"),
      SHEX("2D562A0D 190486E7 "));
}
