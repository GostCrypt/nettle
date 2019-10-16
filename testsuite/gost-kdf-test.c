#include "testutils.h"
#include "gost-kdf.h"
#include <assert.h>

/* See RFC 7836 */
static void test_kdf(void)
{
  const struct tstring *kin =
    SHEX("000102030405060708090a0b0c0d0e0f"
         "101112131415161718191a1b1c1d1e1f");
  const struct tstring *label =
    SHEX("26bdb878");
  const struct tstring *seed =
    SHEX("af21434145656378");

  const struct tstring *kdf_out =
    SHEX("a1aa5f7de402d7b3 d323f2991c8d4534"
	 "013137010a83754f d0af6d7cd4922ed9");

  const struct tstring *kdf_tree_out =
    SHEX("22b6837845c6bef6 5ea71672b2658310"
	 "86d3c76aebe6dae9 1cad51d83f79d16b"
	 "074c9330599d7f8d 712fca54392f4ddd"
	 "e93751206b3584c8 f43f9e6dc51531f9");

  uint8_t outbuf[64];

  assert(kdf_out->length <= sizeof(outbuf));

  kdf_gostr3411_2012_256(kin->length, kin->data,
			 label->length, label->data,
			 seed->length, seed->data,
			 kdf_out->length, outbuf);

  if (!MEMEQ(kdf_out->length, kdf_out->data, outbuf))
    {
      fprintf(stderr, "kdf_gostr3411_2012_256 failed:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(kdf_out->length, outbuf);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(kdf_out);
      fprintf(stderr, "\n");
      FAIL();
    }

  assert(kdf_out->length <= sizeof(outbuf));
  kdf_tree_gostr3411_2012_256(kin->length, kin->data,
			      label->length, label->data,
			      seed->length, seed->data,
			      1,
			      kdf_out->length, outbuf);

  if (!MEMEQ(kdf_out->length, kdf_out->data, outbuf))
    {
      fprintf(stderr, "kdf_tree_gostr3411_2012_256 failed:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(kdf_out->length, outbuf);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(kdf_out);
      fprintf(stderr, "\n");
      FAIL();
    }

  assert(kdf_tree_out->length <= sizeof(outbuf));
  kdf_tree_gostr3411_2012_256(kin->length, kin->data,
			      label->length, label->data,
			      seed->length, seed->data,
			      1,
			      kdf_tree_out->length, outbuf);

  if (!MEMEQ(kdf_tree_out->length, kdf_tree_out->data, outbuf))
    {
      fprintf(stderr, "kdf_tree_gostr3411_2012_256 failed:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(kdf_tree_out->length, outbuf);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(kdf_tree_out);
      fprintf(stderr, "\n");
      FAIL();
    }
}

/* draft-smyshlyaev-tls12-gost-suites */
static void test_tlstree_magma(void)
{
  const uint8_t *kroot =
    H("00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
      "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00");

  struct
    {
      uint64_t seq;
      const uint8_t *result;
    } tests[] =
  {
      { 0, H("19a76ed30f4d6d1f 5b7263ec491ad838 17c0b57d8a035612 7140fb4f7425494d") },
      { 4095, H("19a76ed30f4d6d1f 5b7263ec491ad838 17c0b57d8a035612 7140fb4f7425494d") },
      { 4096, H("fb30ee53cfcf89d7 48fc0c72ef160b8b 53cbbbfd031282b0 26214ab2e07758ff") },
      { 33554431, H("b85b36dc2282326b c035c572dc93f18d 83aa0174f394209a 513bb374dc0935ae") },
      { 33554432, H("0fd7c09efdf8e815 73eeccf86e4b95e3 af7f34dab1177cfd 7db97b6da906408a") },
      { 274877906943, H("480f9972baf25d4c 369a96af91bca455 3f79d8f0c5618b19 fd44cfdc57fa3733") },
      { 274877906944, H("2528c1c6a8f0927b f2be27bb78d27f21 46d65593b0c7173a 06cb9d88df923265") },
  };

  struct tlstree_ctx ctx;
  uint8_t buf[TLSTREE_KEY_LENGTH];
  unsigned int i;

  tlstree_init(&ctx, &tlstree_magma_const, kroot);

  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
      tlstree_get(&ctx, &tlstree_magma_const, kroot, tests[i].seq, buf);
      if (!MEMEQ(TLSTREE_KEY_LENGTH, buf, tests[i].result))
	{
	  fprintf(stderr, "tlstree magma test %u (%llu) failed:\n", i, (unsigned long long)tests[i].seq);
	  fprintf(stderr, "\nOutput: ");
	  print_hex(TLSTREE_KEY_LENGTH, buf);
	  fprintf(stderr, "\nExpected:");
	  print_hex(TLSTREE_KEY_LENGTH, tests[i].result);
	  fprintf(stderr, "\n");
	  FAIL();
	}
    }
}

static void test_tlstree_kuznyechik(void)
{
  const uint8_t *kroot =
    H("00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
      "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00");

  struct
    {
      uint64_t seq;
      const uint8_t *result;
    } tests[] =
  {
      { 0, H("19a76ed30f4d6d1f 5b7263ec491ad838 17c0b57d8a035612 7140fb4f7425494d") },
      { 63, H("19a76ed30f4d6d1f 5b7263ec491ad838 17c0b57d8a035612 7140fb4f7425494d") },
      { 64, H("aebe1ef418713bf0 44b9fcd9e572d437 fb38b5d829567a6f 7918396d9f4e096b") },
      { 524287, H("6f18d4003ea2cb30 f5fec193a234f07d 7c4394987f50758d e22b220d8a105106") },
      { 524288, H("e54b16415b3b663e 780b062d24f736c4 495463c3a891e1fa 46f7ae99fff9f378") },
      { 4294967295, H("cf600904c71e7b88 a49ac8e245774b3d beedfb81de9a0e2f 4e46c35607bc2f04") },
      { 4294967296, H("16180b24645400b8 36143837d86aac93 952ae3eb8244d5ec 2ab02cff30781138") },
  };

  struct tlstree_ctx ctx;
  uint8_t buf[TLSTREE_KEY_LENGTH];
  unsigned int i;

  tlstree_init(&ctx, &tlstree_kuznyechik_const, kroot);

  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
      tlstree_get(&ctx, &tlstree_kuznyechik_const, kroot, tests[i].seq, buf);
      if (!MEMEQ(TLSTREE_KEY_LENGTH, buf, tests[i].result))
	{
	  fprintf(stderr, "tlstree kuznyechik test %u (%llu) failed:\n", i, (unsigned long long)tests[i].seq);
	  fprintf(stderr, "\nOutput: ");
	  print_hex(TLSTREE_KEY_LENGTH, buf);
	  fprintf(stderr, "\nExpected:");
	  print_hex(TLSTREE_KEY_LENGTH, tests[i].result);
	  fprintf(stderr, "\n");
	  FAIL();
	}
    }
}

void test_main(void)
{
  test_kdf();
  test_tlstree_magma();
  test_tlstree_kuznyechik();
}
