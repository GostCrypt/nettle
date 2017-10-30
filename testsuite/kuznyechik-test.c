#include "testutils.h"
#include "kuznyechik.h"
#include "cfb.h"

void test_main(void)
{
  test_cipher(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1122334455667700ffeeddccbbaa9988"
	   "00112233445566778899aabbcceeff0a"
	   "112233445566778899aabbcceeff0a00"
	   "2233445566778899aabbcceeff0a0011"),
      SHEX("7f679d90bebc24305a468d42b9d4edcd"
	   "b429912c6e0032f9285452d76718d08b"
	   "f0ca33549d247ceef3f5a5313bd4b157"
	   "d0b09ccde830b9eb3a02c4c5aa8ada98"));

  test_cipher(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567890abcef00000000000000000"),
      SHEX("e0b7ebfa9468a6db2a95826efb173830"));

  test_cipher(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567890abcef00000000000000001"),
      SHEX("85ffc500b2f4582a7ba54e08f0ab21ee"));

  test_cipher(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567890abcef00000000000000002"),
      SHEX("b4c8dbcfb353195b4c42cc3ddb9ba9a5"));

  test_cipher(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1234567890abcef00000000000000003"),
      SHEX("e9a2bee4947b322f7b7d1db6dfb7ba62"));

  test_cipher(&nettle_kuznyechik,
      SHEX("2666ed40ae687811745ca0b448f57a7b390adb5780307e8e9659ac403ae60c60"),
      SHEX("1234567890abcef00000000000000002"),
      SHEX("5aecd8cb31093bdd99bdbdebb07ae200"));

  test_cipher(&nettle_kuznyechik,
      SHEX("2666ed40ae687811745ca0b448f57a7b390adb5780307e8e9659ac403ae60c60"),
      SHEX("1234567890abcef00000000000000003"),
      SHEX("7a4f09a00ea71ca094f3f8412f8a5057"));

  test_cipher(&nettle_kuznyechik,
      SHEX("bb3dd5402e999b7a3debb0db45448ec530f07365dfee3aba8415f77ac8f34ce8"),
      SHEX("1234567890abcef00000000000000004"),
      SHEX("fc74a010f126754ba73082ce618a984c"));

  test_cipher(&nettle_kuznyechik,
      SHEX("bb3dd5402e999b7a3debb0db45448ec530f07365dfee3aba8415f77ac8f34ce8"),
      SHEX("1234567890abcef00000000000000005"),
      SHEX("9ba8619b09af9cfdc0a1c47e3432340d"));

  test_cipher(&nettle_kuznyechik,
      SHEX("23362fd553cad2178299a5b5a2d4722e3bb83c730a8bf57ce2dd004017f8c565"),
      SHEX("1234567890abcef00000000000000006"),
      SHEX("316fde4a1b507318872d2be7eaf4ed19"));

  test_cipher_ctr(&nettle_kuznyechik,
      SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      SHEX("1122334455667700ffeeddccbbaa9988"
	   "00112233445566778899aabbcceeff0a"
	   "112233445566778899aabbcceeff0a00"
	   "2233445566778899aabbcceeff0a0011"),
      SHEX("f195d8bec10ed1dbd57b5fa240bda1b8"
	   "85eee733f6a13e5df33ce4b33c45dee4"
	   "a5eae88be6356ed3d5e877f13564a3a5"
	   "cb91fab1f20cbab6d1c6d15820bdba73"),
      SHEX("1234567890abcef00000000000000000"));
}
