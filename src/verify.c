/*
  Public domain by Andrew M. <liquidsun@gmail.com>

  Ed25519 reference implementation using Ed25519-donna
*/
#include "../header/sign.h"
int
ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS) {
    ge25519 ALIGN(16) R, A;
    hash_512bits hash;
    bignum256modm hram, S;
    unsigned char checkR[32];

    if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
        return -1;

    /* hram = H(R,A,m) */
    ed25519_hram(hash, RS, pk, m, mlen);
    expand256_modm(hram, hash, 64);

    /* S */
    expand256_modm(S, RS + 32, 32);

    /* SB - H(R,A,m)A */
    ge25519_double_scalarmult_vartime(&R, &A, hram, S);
    ge25519_pack(checkR, &R);

    /* check that R = SB - H(R,A,m)A */
    return ed25519_verify(RS, checkR, 32) ? 0 : -1;
}