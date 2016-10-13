#include "testutils.h"

static void
test_gostdsa (const struct ecc_curve *ecc,
	    /* Public key */
	    const char *xs, const char *ys,
	    /* Hash */
	    struct tstring *h,
	    /* Valid signature */
	    const char *r, const char *s)
{
  struct ecc_point pub;
  struct dsa_signature signature;
  mpz_t x, y;

  ecc_point_init (&pub, ecc);
  dsa_signature_init (&signature);

  mpz_init_set_str (x, xs, 16);
  mpz_init_set_str (y, ys, 16);

  if (!ecc_point_set (&pub, x, y))
    die ("ecc_point_set failed.\n");

  mpz_set_str (signature.r, r, 16);
  mpz_set_str (signature.s, s, 16);

  if (!gostdsa_verify (&pub, h->length, h->data, &signature))
    {
      fprintf (stderr, "gostdsa_verify failed with valid signature.\n");
    fail:
      fprintf (stderr, "bit_size = %u\nx = ", ecc->p.bit_size);
      mpz_out_str (stderr, 16, x);
      fprintf (stderr, "\ny = ");
      mpz_out_str (stderr, 16, y);
      fprintf (stderr, "\ndigest ");
      print_hex (h->length, h->data);
      fprintf (stderr, "r = ");
      mpz_out_str (stderr, 16, signature.r);
      fprintf (stderr, "\ns = ");
      mpz_out_str (stderr, 16, signature.s);
      fprintf (stderr, "\n");
      abort();
    }

  mpz_combit (signature.r, ecc->p.bit_size / 3);
  if (gostdsa_verify (&pub, h->length, h->data, &signature))
    {
      fprintf (stderr, "gostdsa_verify unexpectedly succeeded with invalid signature.\n");
      goto fail;
    }
  mpz_combit (signature.r, ecc->p.bit_size / 3);

  mpz_combit (signature.s, 4*ecc->p.bit_size / 5);
  if (gostdsa_verify (&pub, h->length, h->data, &signature))
    {
      fprintf (stderr, "gostdsa_verify unexpectedly succeeded with invalid signature.\n");
      goto fail;
    }
  mpz_combit (signature.s, 4*ecc->p.bit_size / 5);

  h->data[2*h->length / 3] ^= 0x40;
  if (gostdsa_verify (&pub, h->length, h->data, &signature))
    {
      fprintf (stderr, "gostdsa_verify unexpectedly succeeded with invalid signature.\n");
      goto fail;
    }
  h->data[2*h->length / 3] ^= 0x40;
  if (!gostdsa_verify (&pub, h->length, h->data, &signature))
    {
      fprintf (stderr, "gostdsa_verify failed, internal testsuite error.\n");
      goto fail;
    }

  ecc_point_clear (&pub);
  dsa_signature_clear (&signature);
  mpz_clear (x);
  mpz_clear (y);
}

void
test_main (void)
{
  test_gostdsa (nettle_get_gost_256cpa(),
	      "971566CEDA436EE7678F7E07E84EBB7217406C0B4747AA8FD2AB1453C3D0DFBA", /* x */

	      "AD58736965949F8E59830F8DE20FC6C0D177F6AB599874F1E2E24FF71F9CE643", /* y */

	      SHEX("1C067E20EA6CB183F22EFB0F3C6FD2A4E6A02821CB7A1B17FACD5E1F7AA76F70"), /* h */

	      "E9323A5E88DD87FB7C724383BFFE7CECD4B9FFA2AC33BEEF73A5A1F743404F6B", /* r */

	      "5E5B9B805B01147A8492C4A162643AC615DC777B9174108F3DC276A41F987AF3"); /* s */

  test_gostdsa (nettle_get_gost_256cpb(),
	      "347E354F60B8DA8DE659B432600418C7D0E70F01622477579FAB36A066B9B8FD", /* x */

	      "1DD2E31CF7840A5109DFAB561E15D42BC3CE2E64995FB70F3B86679655A1BAA1", /* y */

	      SHEX("1C067E20EA6CB183F22EFB0F3C6FD2A4E6A02821CB7A1B17FACD5E1F7AA76F70"), /* h */

	      "4E8F9973B31A134CE0942421573B0529B07EC96B835A07856C16CE8070C62547", /* r */

	      "10CE0EFA72741D5EB24837563AAB9369781D6F487ACF88BBEE3E49EC239F6A90"); /* s */

  test_gostdsa (nettle_get_gost_256cpc(),
	      "1F737CC71E43E3FB35B886383714CA5E1226ECDF21F6063E6EA2E40DD04C44EC", /* x */

	      "7DD94CE1044CCEAD21E4E985E281034058A5B11F37B5F96F31DDCF7D513D164E", /* y */

	      SHEX("1C067E20EA6CB183F22EFB0F3C6FD2A4E6A02821CB7A1B17FACD5E1F7AA76F70"), /* h */

	      "7A03B527F916AF43DB655362A54AA9EBAF1A02B5776B5EBD8F00484EE8FD4AC6", /* r */

	      "7D21C2C0D9AD2D03B5D0EF47AE85AB8861067C1FF5394A755BD4A30B5591F8C4"); /* s */

  test_gostdsa (nettle_get_gost_512a(),
	      "03A36340A95BB5F93D131961B5B1C1B3213DF7FF3B5A30376407E2A65C441BC6"
	      "D1B34662317083243F007B15A8512B526606D3B172B606DCE86DBD6F82DA3D40", /* x */

	      "DEAD76318012FED79507809C89CC44848743640EAC9A3C847DA9082E050760A1"
	      "0679F4B707ABC1872640AD20D7441F66C7A8B3BFF1B8E11B4A076F0A86749F73", /* y */

	      SHEX("EDC257BED45FDDE4F1457B7F5B19017A8F204184366689D938532CDBAA5CB29A"
		   "1D369DA57F8B983BE272219BD2C9A4FC57ECF7A77F34EE2E8AA553976A4766C0"), /* h */

	      "891AA75C2A6F3B4DE27E3903F61CBB0F3F85A4E3C62F39A6E4E84A7477679C6E"
	      "45008DC2774CA2FF64C12C0606FF918CAE3A50115440E9BF2971B627A882A1E8", /* r */

	      "31065479996DDBDEE180AFE22CA3CDC44B45CE4C6C83909D1D3B702922A32441"
	      "A9E11DCFBEA3D847C06B1A8A38EB1671D6C82FA21B79C99BE2EA809B10DAA5DF"); /* s */

  test_gostdsa (nettle_get_gost_512b(),
	      "07134627CE7FC6770953ABA4714B38AF8DE764B8870A502C2F4CC2D05541459A"
	      "18DA3B9D4EBC09BC06CB2EA1856A03747561CF04C34382111539230A550F1913", /* x */

	      "7E08A434CB2FA300F8974E3FF69A4BCDF36B6308E1D7A56144693A35E11CBD14"
	      "D502916E680E35FE1E6ABBA85BD4DAE7065308B16B1CCABFE3D91CE0655B0FFD", /* y */

	      SHEX("EDC257BED45FDDE4F1457B7F5B19017A8F204184366689D938532CDBAA5CB29A"
		   "1D369DA57F8B983BE272219BD2C9A4FC57ECF7A77F34EE2E8AA553976A4766C0"), /* h */

	      "5DBF2F4C2D6A7705880FB1458CC58335065BEA5621FC9FBC176C4ACA5BC1E672"
	      "25459A8EA3779434590DC872704029365A83A53B5EB3C06936B5D287E0A983E7", /* r */

	      "4E6D2EE8A693D35F31F2551D43B4F6BC6F9EE7B9D27323873386C7DE5F91C39E"
	      "D3AAE39B7D07FA92B3C742E9E1B16E11D9F7308E485B715987668346AEF1723D"); /* s */
}
