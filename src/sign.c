//
// Created by haojun on 8/1/20.
//

#include "../header/sign.h"

int
ed25519_donna_sign(unsigned char *sig, const unsigned char *m, size_t mlen,
                   const unsigned char *sk, const unsigned char *pk)
{
    ed25519_hash_context ctx;
    bignum256modm r = {0}, S, a;
    ge25519 ALIGN(16) R = {{0}, {0}, {0}, {0}};
    hash_512bits hashr, hram;

    /* r = H(aExt[32..64], m) */
    ed25519_hash_init(&ctx);
    ed25519_hash_update(&ctx, sk + 32, 32);
    ed25519_hash_update(&ctx, m, mlen);
    ed25519_hash_final(&ctx, hashr);
    expand256_modm(r, hashr, 64);

    /* R = rB */
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
    ge25519_pack(sig, &R);

    /* S = H(R,A,m).. */
    ed25519_hram(hram, sig, pk, m, mlen);
    expand256_modm(S, hram, 64);

    /* S = H(R,A,m)a */
    expand256_modm(a, sk, 32);
    mul256_modm(S, S, a);

    /* S = (r + H(R,A,m)a) */
    add256_modm(S, S, r);

    /* S = (r + H(R,A,m)a) mod L */
    contract256_modm(sig + 32, S);

    return 0;
}