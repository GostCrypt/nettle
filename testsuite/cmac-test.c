#include "testutils.h"
#include "nettle-internal.h"
#include "cmac.h"

const struct nettle_mac nettle_cmac_aes128 =
{
  "CMAC-AES128",
  sizeof(struct cmac_aes128_ctx),
  CMAC128_DIGEST_SIZE,
  AES128_KEY_SIZE,

  (nettle_set_key_func*) cmac_aes128_set_key,
  (nettle_hash_update_func*) cmac_aes128_update,
  (nettle_hash_digest_func*) cmac_aes128_digest
};

const struct nettle_mac nettle_cmac_aes256 =
{
  "CMAC-AES256",
  sizeof(struct cmac_aes256_ctx),
  CMAC128_DIGEST_SIZE,
  AES256_KEY_SIZE,

  (nettle_set_key_func*) cmac_aes256_set_key,
  (nettle_hash_update_func*) cmac_aes256_update,
  (nettle_hash_digest_func*) cmac_aes256_digest
};

const struct nettle_mac nettle_cmac_des3 =
{
  "CMAC-3DES",
  sizeof(struct cmac_des3_ctx),
  CMAC64_DIGEST_SIZE,
  DES3_KEY_SIZE,

  (nettle_set_key_func*) cmac_des3_set_key,
  (nettle_hash_update_func*) cmac_des3_update,
  (nettle_hash_digest_func*) cmac_des3_digest
};

const struct nettle_mac nettle_cmac_magma =
{
  "CMAC-MAGMA",
  sizeof(struct cmac_magma_ctx),
  CMAC64_DIGEST_SIZE,
  MAGMA_KEY_SIZE,

  (nettle_set_key_func*) cmac_magma_set_key,
  (nettle_hash_update_func*) cmac_magma_update,
  (nettle_hash_digest_func*) cmac_magma_digest
};

const struct nettle_mac nettle_cmac_magma_32 =
{
  "CMAC-MAGMA-32",
  sizeof(struct cmac_magma_ctx),
  4,
  MAGMA_KEY_SIZE,

  (nettle_set_key_func*) cmac_magma_set_key,
  (nettle_hash_update_func*) cmac_magma_update,
  (nettle_hash_digest_func*) cmac_magma_digest
};

const struct nettle_mac nettle_cmac_kuznyechik =
{
  "CMAC-KUZNYECHIK",
  sizeof(struct cmac_kuznyechik_ctx),
  CMAC128_DIGEST_SIZE,
  KUZNYECHIK_KEY_SIZE,

  (nettle_set_key_func*) cmac_kuznyechik_set_key,
  (nettle_hash_update_func*) cmac_kuznyechik_update,
  (nettle_hash_digest_func*) cmac_kuznyechik_digest
};

const struct nettle_mac nettle_cmac_kuznyechik_64 =
{
  "CMAC-KUZNYECHIK-64",
  sizeof(struct cmac_kuznyechik_ctx),
  8,
  KUZNYECHIK_KEY_SIZE,

  (nettle_set_key_func*) cmac_kuznyechik_set_key,
  (nettle_hash_update_func*) cmac_kuznyechik_update,
  (nettle_hash_digest_func*) cmac_kuznyechik_digest
};

#define test_cmac_aes128(key, msg, ref)					\
  test_mac(&nettle_cmac_aes128, key, msg, ref)

#define test_cmac_aes256(key, msg, ref)					\
  test_mac(&nettle_cmac_aes256, key, msg, ref)

#define test_cmac_des3(key, msg, ref)					\
  test_mac(&nettle_cmac_des3, key, msg, ref)

void
test_main(void)
{
  /*
   * CMAC-AES Test Vectors from RFC4493.
   */
  test_cmac_aes128 (SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
		  SDATA(""),
		  SHEX("bb1d6929e95937287fa37d129b756746"));

  test_cmac_aes128 (SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"),
		  SHEX("070a16b46b4d4144f79bdd9dd04a287c"));

  test_cmac_aes128 (SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"
		       "ae2d8a571e03ac9c9eb76fac45af8e51"
		       "30c81c46a35ce411"),
		  SHEX("dfa66747de9ae63030ca32611497c827"));

  test_cmac_aes128 (SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"
		       "ae2d8a571e03ac9c9eb76fac45af8e51"
		       "30c81c46a35ce411e5fbc1191a0a52ef"
		       "f69f2445df4f9b17ad2b417be66c3710"),
		  SHEX("51f0bebf7e3b9d92fc49741779363cfe"));

  /* Additional tests with different keys (same plaintext)
   * to check all variants of set_key() */
  test_cmac_aes128 (SHEX("2b7e151628aed2a8abf7158809cf4f3c"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"
		       "ae2d8a571e03ac9c9eb76fac45af8e51"
		       "30c81c46a35ce411"),
		  SHEX("87dd33c2945a4e228028690ae8954945"));

  test_cmac_aes128 (SHEX("2b7e1ab628aed2a8abf7158809cf4f3c"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"
		       "ae2d8a571e03ac9c9eb76fac45af8e51"
		       "30c81c46a35ce411"),
		  SHEX("f0dc613a88886c7ed76eeb51f1c5e8d3"));

  test_cmac_aes128 (SHEX("2b7e1ab628aed2a8abf7158809cf4f3d"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"
		       "ae2d8a571e03ac9c9eb76fac45af8e51"
		       "30c81c46a35ce411"),
		  SHEX("b9d092dc387a9e42cdfeb9f9930cf567"));

  /* CMAC-AES256 vectors taken from phplib */
  test_cmac_aes256 (SHEX("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  SDATA(""),
		  SHEX("028962f61b7bf89efc6b551f4667d983"));

  test_cmac_aes256 (SHEX("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"),
		  SHEX("28a7023f452e8f82bd4bf28d8c37c35c"));

  test_cmac_aes256 (SHEX("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  SHEX("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
		  SHEX("aaf3d8f1de5640c232f5b169b9c911e6"));

  test_cmac_aes256 (SHEX("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  SHEX("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
		  SHEX("e1992190549f6ed5696a2c056c315410"));

  /* CMAC-3DES vectors from NIST SP800-38B examples */
  test_cmac_des3 (SHEX("0123456789abcdef23456789abcdef01456789abcdef0123"),
		  SDATA(""),
		  SHEX("7db0d37df936c550"));

  test_cmac_des3 (SHEX("0123456789abcdef23456789abcdef01456789abcdef0123"),
		  SHEX("6bc1bee22e409f96e93d7e117393172a"),
		  SHEX("30239cf1f52e6609"));

  test_cmac_des3 (SHEX("0123456789abcdef23456789abcdef01456789abcdef0123"),
		  SHEX("6bc1bee22e409f96e93d7e117393172aae2d8a57"),
		  SHEX("6c9f3ee4923f6be2"));


  test_cmac_des3 (SHEX("0123456789abcdef23456789abcdef01456789abcdef0123"),
		  SHEX("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"),
		  SHEX("99429bd0bf7904e5"));

  /* Truncated CMACs come from GOST R 34.13-2015
   * Full-length examples are from TLS (draft) standard */
  test_mac(&nettle_cmac_magma,
      SHEX("507642d958c520c6d7eef5ca8a5316d4 f34b855d2dd4bcbf4e5bf0ff641a19ff"),
      SHEX("0000000000000000170303000700000000000000"),
      SHEX("3070b864779d9547"));

  test_mac(&nettle_cmac_kuznyechik,
      SHEX("507642d958c520c6d7eef5ca8a5316d4 f34b855d2dd4bcbf4e5bf0ff641a19ff"),
      SHEX("0000000000000000170303000f000000000000000000000000000000"),
      SHEX("755309cbc73bb949 c50ebb86160a0fee"));

  test_mac(&nettle_cmac_magma_32,
      SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
      SHEX("92def06b3c130a59 db54c704f8189d20 4a98fb2e67a8024c 8912409b17b57e41"),
      SHEX("154e7210"));

  test_mac(&nettle_cmac_kuznyechik_64,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1122334455667700ffeeddccbbaa9988"
	   "00112233445566778899aabbcceeff0a"
	   "112233445566778899aabbcceeff0a00"
	   "2233445566778899aabbcceeff0a0011"),
      SHEX("336f4d296059fbe3"));
}
