#include "header/sign.h"
#include <stdio.h>

unsigned char * convert(char *s) {
    size_t src_len = strlen(s);
    if (src_len % 2 != 0) { return NULL; }
    size_t dest_len = src_len / 2;
    unsigned char *result = malloc((sizeof(*result)+1)*dest_len);
    for (size_t i=0, j=0; j<dest_len; i+=2, j++) {
        result[j] = (s[i] % 32 + 9) % 25 * 16 + (s[i + 1] % 32 + 9) % 25;
    }
    result[dest_len+1] = '\0';
    return result;
}

int main() {
    char pubkey_hex[] = "ce8b7b36ea7cd2c2097b3fe8b1fe0764d62d27abd41e103b57e99ed080a1e4a9";
    char prikey_hex[] = "300fd119c08c9066a62b344e56737a88b5393650d8937b9d1102f643a1a581434e07cc0b0437058e85f2256389e86e08c6421e1c87c0a54df62b117c3fc80857";
    const unsigned char message[7] = "123456";
    ed25519_signature signature;
    unsigned char *pk, *sk;
    pk = convert(pubkey_hex);
    printf("pk: %s\n", pk);
    sk = convert(prikey_hex);
    printf("sk: %s\n", sk);

    ed25519_donna_sign(signature, message, 7, sk, pk);
    printf("signature: %s\n", signature);
    int status = ed25519_sign_open(message, 7, pk, signature);
    printf("%d\n", status);
    return 0;
}
