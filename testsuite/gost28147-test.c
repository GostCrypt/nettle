#include "testutils.h"
#include "gost28147.h"

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

  /* Manually calculated */
  test_gost28147(gost28147_get_param_test_3411(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("ced52a7ff7f260d5 bc81a80bb5e65976"));

  test_gost28147(gost28147_get_param_CryptoPro_3411(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("e42175e16922d0a8 48e59157d7106518"));

  test_gost28147(gost28147_get_param_Test_89(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("9856cf8bfcc282f4 3f465801c6539a5c"));

  test_gost28147(gost28147_get_param_CryptoPro_A(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("668184aedc48c917 4164347058845cac"));

  test_gost28147(gost28147_get_param_CryptoPro_B(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("dbee81147b74b0f2 db5ef00eff4bd528"));

  test_gost28147(gost28147_get_param_CryptoPro_C(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("31a3859d0aeeb80e 4afbd6ce7798ffa9"));

  test_gost28147(gost28147_get_param_CryptoPro_D(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("b1323e0b2173cbd1 c5282f2461e97aa8"));

  test_gost28147(gost28147_get_param_TC26_Z(),
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("ce5a5ed7e0577a5f d0cc85ce31635b8b"));

  /* From Magma spec, retrofitted for GOST 28147-89 */
  test_gost28147(gost28147_get_param_TC26_Z(),
      SHEX("ccddeeff8899aabb4455667700112233f3f2f1f0f7f6f5f4fbfaf9f8fffefdfc"),
      SHEX("1032547698badcfe"),
      SHEX("3dcad8c2e501e94e"));
}
