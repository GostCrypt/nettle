#include "testutils.h"
#include "magma.h"
#include "cfb.h"

void test_main(void)
{
  test_cipher(&nettle_magma,
      SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
      SHEX("92def06b3c130a59 db54c704f8189d20 4a98fb2e67a8024c 8912409b17b57e41"),
      SHEX("2b073f0494f372a0 de70e715d3556e48 11d8d9e9eacfbc1e 7c68260996c67efb"));

  test_cipher(&nettle_magma,
      SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
      SHEX("fedcba9876543210"),
      SHEX("4ee901e5c2d8ca3d"));

  test_cipher(&nettle_magma,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567800000000"),
      SHEX("3b9a2eaabe783bab"));

  test_cipher(&nettle_magma,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567800000001"),
      SHEX("970fd90806c10d62"));

  test_cipher(&nettle_magma,
      SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
      SHEX("1234567800000002"),
      SHEX("c73d459c287b3d1c"));

  test_cipher(&nettle_magma,
      SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
      SHEX("1234567800000003"),
      SHEX("86361cacbc1f4c24"));

  test_cipher(&nettle_magma,
      SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
      SHEX("1234567800000004"),
      SHEX("b08c4250cb8b640a"));

  test_cipher(&nettle_magma,
      SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
      SHEX("1234567800000005"),
      SHEX("327edcd4e88de66f"));

  test_cipher(&nettle_magma,
      SHEX("3256bf3f97b5667426a9fb1c5eaabe41893ccdd5a868f9b63b0aa90720fa43c4"),
      SHEX("1234567800000006"),
      SHEX("a691b50e59bdfa58"));
}
