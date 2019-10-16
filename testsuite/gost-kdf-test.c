#include "testutils.h"
#include "gost-kdf.h"
#include <assert.h>

void test_main(void)
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
