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

  gost28147_set_key(&ctx, key->data);
  gost28147_set_param(&ctx, param);
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

  gost28147_set_key(&ctx, key->data);
  gost28147_set_param(&ctx, param);
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

static void
test_gost28147_cfb(const struct gost28147_param *param,
		   const struct tstring *key,
		   const struct tstring *iv,
		   const struct tstring *cleartext,
		   const struct tstring *ciphertext)
{
  struct ctx CFB_CTX(struct gost28147_ctx, GOST28147_BLOCK_SIZE) ctx;
  uint8_t *data = xalloc(cleartext->length);
  size_t length;

  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  gost28147_set_key(&ctx.ctx, key->data);
  gost28147_set_param(&ctx.ctx, param);
  CFB_SET_IV(&ctx, iv->data);

  CFB_ENCRYPT(&ctx, gost28147_encrypt_for_cfb, length,
	      data, cleartext->data);

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

  gost28147_set_key(&ctx.ctx, key->data);
  gost28147_set_param(&ctx.ctx, param);
  CFB_SET_IV(&ctx, iv->data);
  CFB_DECRYPT(&ctx, gost28147_encrypt_for_cfb, length,
	      data, data);

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

static void
test_gost28147_cnt(const struct gost28147_param *param,
		   const struct tstring *key,
		   const struct tstring *start_iv,
		   const struct tstring *end_iv,
		   const struct tstring *cleartext,
		   const struct tstring *ciphertext)
{
  struct gost28147_cnt_ctx ctx;
  uint8_t *data = xalloc(cleartext->length);
  uint8_t iv[GOST28147_BLOCK_SIZE];
  size_t length;

  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  gost28147_cnt_init(&ctx, key->data, param);
  gost28147_cnt_set_iv(&ctx, start_iv->data);
  gost28147_cnt_crypt(&ctx, length, data, cleartext->data);

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

  LE_WRITE_UINT32(iv + 0, ctx.iv[0]);
  LE_WRITE_UINT32(iv + 4, ctx.iv[1]);

  if (!MEMEQ(GOST28147_BLOCK_SIZE, iv, end_iv->data))
    {
      fprintf(stderr, "Encrypt failed IV check:\nOutput:");
      print_hex(GOST28147_BLOCK_SIZE, iv);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(end_iv);
      fprintf(stderr, "\n");
      FAIL();
    }

  gost28147_cnt_init(&ctx, key->data, param);
  gost28147_cnt_set_iv(&ctx, start_iv->data);
  gost28147_cnt_crypt(&ctx, length, data, data);

  if (!MEMEQ(length, data, cleartext->data))
    {
      fprintf(stderr, "Decrypt failed:\nOutput:");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  LE_WRITE_UINT32(iv + 0, ctx.iv[0]);
  LE_WRITE_UINT32(iv + 4, ctx.iv[1]);

  if (!MEMEQ(GOST28147_BLOCK_SIZE, iv, end_iv->data))
    {
      fprintf(stderr, "Decrypt failed IV check:\nInput:");
      fprintf(stderr, "\nOutput: ");
      print_hex(GOST28147_BLOCK_SIZE, iv);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(end_iv);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(data);
}

void test_main(void)
{
  /* Examples from GOST R 34.11-94 standard */
  test_gost28147(&gost28147_param_test_3411,
      SHEX("546D2033 68656C32 69736520 73736E62 20616779 69677474 73656865 202C3D73"),
      SHEX("00000000 00000000"),
      SHEX("1B0BBC32 CEBCAB42"));

  test_gost28147(&gost28147_param_test_3411,
      SHEX("2033394D 6C320D09 65201A16 6E62001D 67794106 74740E13 6865160D 3D730C11"),
      SHEX("00000000 00000000"),
      SHEX("FDCF9B5D C8EB0352"));

  test_gost28147(&gost28147_param_test_3411,
      SHEX("39B213F5 F209A13F 1AE9BA3A FF1D0C62 41F9E1C7 F1130085 16F20D73 F311B180"),
      SHEX("00000000 00000000"),
      SHEX("280EFF00 9958348D"));

  test_gost28147(&gost28147_param_test_3411,
      SHEX("EC0A8BA1 5EC004A8 BAC50CAC 0C621DEE E1C7B8E7 007AE2EC F2731BFF 4E80E2A0 "),
      SHEX("00000000 00000000"),
      SHEX("2D562A0D 190486E7 "));

  test_gost28147(&gost28147_param_test_3411,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("ced52a7ff7f260d5 bc81a80bb5e65976"));

  test_gost28147(&gost28147_param_CryptoPro_3411,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("e42175e16922d0a8 48e59157d7106518"));

  test_gost28147(&gost28147_param_Test_89,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("9856cf8bfcc282f4 3f465801c6539a5c"));

  test_gost28147(&gost28147_param_CryptoPro_A,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("668184aedc48c917 4164347058845cac"));

  test_gost28147(&gost28147_param_CryptoPro_B,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("dbee81147b74b0f2 db5ef00eff4bd528"));

  test_gost28147(&gost28147_param_CryptoPro_C,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("31a3859d0aeeb80e 4afbd6ce7798ffa9"));

  test_gost28147(&gost28147_param_CryptoPro_D,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("b1323e0b2173cbd1 c5282f2461e97aa8"));

  test_gost28147(&gost28147_param_TC26_Z,
      SHEX("8182838485868788 898a8b8c8d8e8f80 d1d2d3d4d5d6d7d8 d9dadbdcdddedfd0"),
      SHEX("0102030405060708 f1f2f3f4f5f6f7f8"),
      SHEX("ce5a5ed7e0577a5f d0cc85ce31635b8b"));

  test_gost28147(&gost28147_param_TC26_Z,
      SHEX("ccddeeff8899aabb4455667700112233f3f2f1f0f7f6f5f4fbfaf9f8fffefdfc"),
      SHEX("1032547698badcfe"),
      SHEX("3dcad8c2e501e94e"));

  test_gost28147_cfb(&gost28147_param_CryptoPro_A,
      SHEX("8d5a2c83a7c70a61 d61b34b51fdf4268 6671a35d874cfd84 993663b61ed60dad"),
      SHEX("46606f0d8834235a"),
      SHEX("d2fdf83ac1b43923 2eaacc980a02da33"),
      SHEX("88b7751674a5ee2d 14fe9167d05ccc40"));

  test_gost28147_cfb(&gost28147_param_CryptoPro_C,
      SHEX("77c3458ef642e704 8efc08e47096d605 9359026d6f97cae9 cf89444bde6c221d"),
      SHEX("437c3e8e2f2a0098"),
      SHEX("079c91be"),
      SHEX("19358134"));

  test_gost28147_cfb(&gost28147_param_CryptoPro_D,
      SHEX("389fe837ff9c5d29 fc4855a087eae840 20875bb2011555a7 e32dcb3dd6590473"),
      SHEX("c5a2d21f2fdfb8eb"),
      SHEX("2f31d883b420e86e da"),
      SHEX("6da4ed40088871ad 16"));

  test_gost28147_cfb(&gost28147_param_CryptoPro_B,
      SHEX("480c741b026b55d5 b66dd71d4048056b 6deb3c290f848023 ee0d4777e3fe61c9"),
      SHEX("1f3f821e0dd81e22"),
      SHEX("8c9c4435fbe9a5a3 a0ae285691108e1e d2bb185381270da6 685936c581629a8e"
	   "7d50f16f976229ec 8051e37d6cc40795 2863dcb4b92db813 b105b5f9eb75374e"
	   "f7bf51f1988643c4 e43d3ea762ec4159 e0bdfbb6fdece077 13d25990a1b8976b"
	   "3d8b7dfc9dca8273 32700a7403c60c26 7f56f09db2eb7140 d7c3b1a7c51e2017"
	   "b3501d8a6e19cbbe 20862bd61cfdb4b7 5d9ab3e37d157a35 019f5d65894b34c6"
	   "f4813f7830cfe915 909af9deba63d019 14663cb9a4b28494 02cfce20cf76e7c5"
	   "48f7693a5decaf41 a7126483f5991e9e b2ab861600238ee6 d9800b6dc593e25c"
	   "8cd85e5aae4a85fd 7601ea30f3783410 7251bc9f76ce1fd4 8f335034c74d7bcf"
	   "91637d829ea12345 f545ac987a48ff64 d55947de2b3ffaec 50e081608bc3fc80"
	   "9817c7a3c2573dab 9167f5c4ab92c8d6 3b6b3fff156bcf53 6502f174caa9be24"
	   "d2f0b726a8d76ded 90367b3e41a97fa3 1bf443c551be2859 e94526493832f8f3"
	   "926e30ccb0a0f901 14c8bad9f02a29e2 529a76953a1632ec f410ecee47007019"
	   "e472356644532da2 f3aa7e8a3313cdc8 bf0e409000e442c3 0984e16617a2af03"
	   "ab6ba1ecfb177281 fe9a9ff4b2331fae 0cd16aae19b8afec e3ea00f8ac87075f"
	   "6db0ac6b224836bf 2218b0039f6c7045 36f06bc6c2a5722c d8e0273dec560705"
	   "7d83a1657d415bcd 7724e5aa7647d050 f6e7b559753127ef d8a64e7fb840b1df"
	   "5314edf1685ffc3f 02db05eb31e42c7f 32b5708e7585a45c 162337f21079cbdc"
	   "f81c25c2a13d9c33 6cedc3e7f3028782 4efbacb32dfcf80d 1d4a39d4b309bbe9"
	   "25c7ec6a877284ed 12601964eb162a5b 107627ff7be4aee5 a404027fbb0ab5f4"
	   "05a5561c53317a93 ba1615ab6260fcde 72366e28af980de6 f4de60a77e060786"
	   "f394b66d0d93a6bc 607033ac3fa1a84a 2061b6b543a3155a 00be76985772ab7a"
	   "0e1893823a18786e 717b784f7e8cde7a 62b50a7c451d16d5 c38c9b25b45090cd"
	   "9693ad0fd443cb49 0ffc5a31f419b7d4 eb4d4058d03bc8e0 4a542fdb22c3297b"
	   "40906143d37ee230 2b483cce9093b18b 3196656d578b9d4d 53f0831ce5a19d55"
	   "e3bf7eca1a746614 cc4743d9bbef977d b76efff122f8102d 3fcd4996d90911b8"
	   "33d0239afa16cb50 2657245c0ebaf03f 372fa3f718574848 95cfef87672ae9b6"
	   "8a21367fff486c46 3557f2bc48678f63 2378112bc208de51 e88b9229f99a9ead"
	   "ed0feba2d24092d4 de629576fd6e3cbf c0d70de51ba4c718 e158a456ef2e171b"
	   "75cbbcf92a9571a7 1d7fe77363056b19 4cf42214c4598866 9286615c6aaeec58"
	   "ffc9f244d4a2f598 eb5f09bc8abf3cb4 3eb120054496790a 40927f9dd1afbc90"
	   "950a81d4a7c6b8e0 e439301d79c0e5fa b4e963b409723b3e d9f6d91021187ee5"
	   "ad81d7d582d08c3b 3895f89201a99200 70d1a788771f3aeb b5e4f59dc73786b2"
	   "12463419728cf58c f67898e07cd3f4"),
      SHEX("23c67f20a12358bc 7b05db2115cf9641 c788ef765c49db42 bff3c0f5bd5dd98e"
	   "af3df4e4da88bdbc 475d7607c95f541d 1d6aa12e18d66084 021837929215ab21"
	   "ee21cc716e51d92b cc81973feb4599b8 1bdaff90d341069c 3ffbe4b2dcc9030d"
	   "a7aed77d02b832ab f365a3656c4ee4a2 5e9eeecdde79366b 1be13cdf10ad4f02"
	   "e114aa09b40b76eb 69382002cb8ec0df ca4874c331ad422c 519bd06ac136d721"
	   "dfb045baca7f3520 28bbc176fd435d23 7d31841a974d83aa 7ef1c4e683ac0def"
	   "ef3ca47c48e4c8ca 0d7dea7c45d77350 251d01c4021acde0 385ba85a169a1059"
	   "74d719c6f3b517f6 598d62af44e8dce9 c176f1d0bd29d7ec 1dac57db1a3fd8f6"
	   "6eb6e6df36e789ce 5635431c7d57790e d8f4d7a70dc68f91 6667820f49c9c565"
	   "81a1395a539f02a5 d53622a8a81c370e 7646dfbd6adbfc1b bd10b8b1bc724c58"
	   "4ada6d6600da7a66 a0e73b39a3f70507 fa214bc794c0d37b 19025d4a10f1c20f"
	   "196827c77dbf5503 577daf77ae802f7a e61f4bdc1518c062 a1e8d91c9e8c9639"
	   "c1c488f70ce10484 6851cef190da7f76 c8c088ef8e15253e 7be479b5662d9cd1"
	   "13dad0d546d58d46 1807eed8c964e3be 0e6827099626f6e2 19613ff458270aeb"
	   "ce7cb66892e7123b 31d448df358df486 422a154be8191f26 659ba8da4b791f8e"
	   "e6137e498fc1cedc 5e6474ce0278e0cf a0ed5e3174d1d0b4 ee7019143c8f16a6"
	   "cf12931588eb9165 7698fda19430ba43 62654004779ed6ab 8b0d9380505fa276"
	   "20a7d69c271527bc a55abfe9928205a8 41e9b560d5c0d74b ad38b2e9d1e5515f"
	   "2478249a23d2c248 bd0ef137729187b0 4ebd996b2c01b679 69ec0cede53f5064"
	   "7cb9dde19281b5d0 cb1783868bea4f93 08bc220cefe80df5 9e23e1f9b76b450b"
	   "cba9b64d2825ba3e 86f275475d9d6bf6 8a0558733d00defd 69b16116f52eb09f"
	   "316a00b9ef716347 a3cae040a87e0204 fee5ce4873e394cf e2ff297ef632bbb7"
	   "5512217a9c75040c b47cb03d40b3119a 7a9a13fb77a75168 f705473b0f525ce6"
	   "c2993a37545c4f2b a7010874bc91e3e2 fe6594fd3d18e0f0 62edc210829c587f"
	   "b2a3878a74d9c1fb 842817c72bcb531f 4e8a82fcb43fc147 25f321dc4c2d08fa"
	   "e70f03a968de6b41 a0f9416c574d3a0e ea51ca9f97117df6 8e886367c96513ca"
	   "38ed35bef427a9fc a9e6c34086083972 37eeb2870996b740 873692c15d6a2c43"
	   "ca25c835372db5a9 274450f26d227541 772adbb18c6d05e8 c999c708f9148f78"
	   "a98fc25a7a65c5d8 86bb72696b6b4583 5bb1f7cd1673eee9 8085fe8ee1ae538f"
	   "debe488b59eff67e d8b5a847c04e1558 cad32ff86ca63d78 4d7a54d610e5cc05"
	   "e229b58607397d78 8e5a8f834ce73d68 3ee502e6644f5eb4 4977f0c0fa6fc8fb"
	   "9f846f55fb305e89 93a9f3a6a3d726bb d8a8d9951dfefcd7 a893662f04530664"
	   "7f3129aeb79fbac4 6d68d12432f411"));

  test_gost28147_cnt(&gost28147_param_CryptoPro_A,
      SHEX("599f84bac3f3d2f1 60e1e3f26a961af9 9c48b24ebcbbbf7c d8f3accd968d286a"),
      SHEX("8dafa8d158ed058d"),
      SHEX("f1a0e3294f65be75"),
      SHEX("90a23966ae01b9a3 524ec8ed6cdd8830"),
      SHEX("6e7262cce3593690 833afea91bc9bece"));
  test_gost28147_cnt(&gost28147_param_CryptoPro_A,
      SHEX("1b5ddb77cff9ec95 5ecc679f5d28ad4a 27f432c6b2cbb145 6a88140c9b9b5f48"),
      SHEX("71588ce155f4f6b3"),
      SHEX("6aeaa0a59e10e0ce"),
      SHEX("3d0b69f7a8e4fc99 222eeed16312fea8 9dcb6c4d488ce8bd 8b60f1bf7be379d5"
           "2b259713ef35daf4 bc77ceeae93fa4b6 01d5732958dad767 17ace4752f5723ac"
           "9621c7622df732b5 445f72b15fba1b1e db4a098c9261a2b0 4968e5b3a28f134b"
           "f54d84daaba0b6d1 5a6319e8a209f676 6f9b480a155db720 219a2eb96dfa1ec2"
           "0eef15ab5901fe43 90f262ca4a9a4838 ab6f9d21b3ada760 46e3efd0e31dc5e1"
           "b8a1e29920c576cc aa8aa94555a07800 64decf5bdf2648cd ba8ab5fbfd4ad5c4"
           "e043a67190a48bca 2e887bacb2dcf201 cbda6e9127284488 9ad212f1a6f5b761"
           "ce7962523ce61473 d1419250bddc3bd0 a7118c3ae42df252 d32f7c8e54904e23"
           "aeb3a0f3257e66aa 0f6f817277bbd347 e805ffe15bc93750 334917afab1de115"
           "f2e5985e2d051f0d 5597edff5ee00fc3 9cbd82c206be4566 ae33be2848e92d1a"
           "e6658edf7603734b c08071f9acbaa0b0 191a0ad435128876 05758f7cb5f01975"
           "6d05cb0dbc8de9f0 d4db3c3c298e2c32 1df7b649cfdb63ee 3cfa33736fe4974e"
           "2fc94c5c65feeafb c6ddc11c473ff450 2fde1b5b0b16cab6 4644f2c10da11da6"
           "dbf03db16c053185 8e74aef23926f7c1 e74cdd9d40b8f3c5 c216646baadb4b82"
           "5cd302d38f26798d b0787019580cb431 88441c916ff45239 a8f5c01bfef20e4b"
           "ac0ac27e9c9beb5d 4e4f42d8710a9727 031496a63d04ea9f 1414274cd9a2895f"
           "654ae19d2cb8f8d4 8f2a5736cc069c2c c51316dffcae2216 a82b716f1db34754"
           "3f2d0a689f2ef690 d8a12109d497b97b 7f9b6aedd1f0e3b6 28c7628200c938a1"
           "8278ce87c853ac4f 2e31b9507f36004a 32e6d8bb59450e91 1b38a9bcb95e6c6a"
           "9c03011cdee81f1e e3de25a25679e1bd 58c493e6d08a4d08 abf7aac37dc1ee68"
           "37bc780b19682b2b 2e6dc46faa3bc619 cbf158b9608545ae 5297ba2432137216"
           "6e7bc198acb1edb4 cc6ccf45fc508980 8e7aa4d364506337 c96cf1c43dfbde5a"
           "5ca82135e62e8c2a 3c1217799a0d2e79 eb671f2bf86ecac1 fa45189edf6ae6cb"
           "e95cc309af935813 bf90848775d68228 8de72fa3fb97742a 730482067669b10b"
           "19fcaeb3dd2ae5c1 05d88095229071fc c29242fdf170b468 88a49e0a244013c8"
           "a2564f39e606f1dc f5130ead9c8bafe9 e38872ffa06dda08 70b92e83c5bb32a5"
           "74c7fb7b76af02bb 2bb85e6502fe0ea0 99ce013b35e1b022 e594bddd8ebbf675"
           "bfbfee7ab158b481 b8393eb61ededa1b d5f7dd7d659caa56 93b8af4853c722e4"
           "1cdfe979b42089cc 2a792c09be78cfcc f290d665c529fcda 69fcc0d67099613f"
           "6002d81222c834c6 3bb3c233a15c8f4c d15272f242058e18 1f16dab853a15f01"
           "321b90b3539bd085 612d17ed0aa4a527 09757cbc30f75e59 9a07968428864ba7"
           "223528c7ed0dc3ce 98cc2decd498098e 525f2b9a13be9916 73d11f81e5a20878"
           "cb0c20d4a5ea4b5b 955a929a52"),
      SHEX("8ecd8fc8ace11548 2dae248ac7fbba0f 1d8a95a243efcbdc 5957a7c70ee3e2b9"
           "0d862962cb834d07 0c40d47b2ecababf 4a603b3198c88847 d982abfc8f48e246"
           "abd3a1ab8a05228c f4ec9a1e76ab1a60 d9256bb856e5b2ea 10f36204325eaa3b"
           "7b57bc3b8b4347f2 d5037e5101ff7728 ca90a3fe7e2e7016 751844f01b8505ea"
           "e321f72686763c67 9dfcbc107f77e4ed d312f883001f4b92 95925cf35af3b7d0"
           "a95ff218c46662c1 840e66e8807d1ff0 ba019b71ae93cc27 54349abdcaee5209"
           "929db0d5d9ba2fb9 96dcfabdceea1a7b 9a1d13a711e29a64 f6d3eec633b76eef"
           "259e1e7ce31f2c6e a9c0f8c1bf3bf834 039ba1405b0c3c09 669d63e2e2048f06"
           "847468b25c3b4cad 0b3f03b3078a64a7 3656263966dae96d 1bd588e85caf5a4c"
           "49f7f5b778f0deec cd16239e8c13be6b 6f9b07e5bbcc3a1b 6f43dfff462aae47"
           "19189a2509c92440 0c4ba7da5e0deefa 62458ecc2f23081d 92f0fe820fd71160"
           "7e0b0b75f4f53bc0 a4e872a5b6fa5aad 5a4f39b5a212960a 3284b2a106685657"
           "97a37b2261765d30 1a31ab9906c51a96 cfcf14ffb2c4cc2b bf0c9d918f795bbc"
           "a96b916ab4935c7b 5dc28a75c0c108fa 99f94d5e0c066460 a9014a340f338495"
           "6930c11c36f8fc30 23b271e5524d121a c9beeec9cb0185f3 db30f941a940b006"
           "2977cdc5ec580248 8353446ad2ca05d8 5a08eba9f4e6c79d d57b740b31b7a557"
           "7c7afd1a0ed79741 bfddc6196c778c18 525783ba7125ee39 bbe243a014dc0e84"
           "b42bde3ee536b7a2 929805b896e5d08c 089335c281e0fc59 71e244495ddafb9c"
           "aa709f43a8a5d967 d98fa31ebe0eecdf 122b6ae71c1217e7 c46d50c9527ad5e8"
           "7fbc0715acdb9366 b1f0a77b2fe9ecd0 47695987f14c3e4b 9b117913e496f656"
           "046e0b33fc40f6c7 c143b1bf0eb387fd 0b1c63463ad3a017 5925946c9c3d0c81"
           "ce82724228f9376a 6de412f421aaf7fe 2755401a14c3395b bf63c25f101f1425"
           "d0cef3144813a50b 4d38cf0d34c00a11 b4b572c84bc26fe7 9d93f7dfb843727e"
           "da3e201fbc212ace 00fa969f3de58896 ef2984df6c1c96d8 5847aa92f307e5fb"
           "afea957e0b71cd81 0fb70a598f314dd1 c3f32f705c591897 af77955eaf400612"
           "816186084ebc8946 072e5b10aa12f0a7 84e29a08f1de59e3 0e474bffc3c918af"
           "959c672ade8a7a99 04c4b8974c042971 05dab3d6db6c71e6 e803bf947dde3dc8"
           "44fa7d62b43603ee 365264b4856dd578 f06f672d0ee02c88 9b55192940f68c12"
           "bb2c839640c036f5 77ff708c75920bad 059b7ea2fca9d164 768213ba225e330e"
           "2670a9be7428f5e2 c496ee3abc97a62c 2ae0648d35c61aca f492fac3f11f98e4"
           "4388693a09bf63e5 96290b9b6223148a 95e41c5c0aa9c5b9 6f4f2b256f741e18"
           "d5fe277d3f6e552c 67e6deb5ccc02dff c4e40621a5c8d3d6 6ca1c3fb8892b11d"
           "90e135059b296dba f1f41e232e"));

  test_gost28147_cnt(&gost28147_param_TC26_Z,
      SHEX("599f84bac3f3d2f1 60e1e3f26a961af9 9c48b24ebcbbbf7c d8f3accd968d286a"),
      SHEX("8dafa8d158ed058d"),
      SHEX("626804b2e7ba1be2"),
      SHEX("90a23966ae01b9a3 524ec8ed6cdd8830"),
      SHEX("e8b14fc730dc25bb 36ba643c17dbff99"));
}
