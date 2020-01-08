#include "header/sign.h"
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

//unsigned char * convert(const char * hexstr) {
//    size_t len = strlen(hexstr);
//    if (len % 2 != 0) { return NULL; }
//    size_t final_len = len / 2;
//    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
//    for (size_t i=0, j=0; j<final_len; i+=2, j++) {
//        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
//    }
//    chrs[final_len] = '\0';
//    return chrs;
//}

unsigned char * convert(const char *s) {
    size_t src_len = strlen(s);
    if (src_len % 2 != 0) { return NULL; }
    size_t dest_len = src_len / 2;
    unsigned char *result = malloc(sizeof(*result)*dest_len);
    for (size_t i=0, j=0; j<32; i+=2, j++) {
        result[j] = (s[i] % 32 + 9) % 25 * 16 + (s[i + 1] % 32 + 9) % 25;
    }
    return result;
}

int main() {
    const char pubkey_hex[] = "062711e01fb18dbed7f8103c73e2affc7c7487d8443e3011255a153bda054b8f";
    const unsigned char prikey_hex[] = "e82302ec5156938ea33710191ea68596e626ff7889344292c23b7aee2917754062203fc6ff4959b806472bde1b9db593eeff11ea326c3bec98a891fed8a9db4b";
    unsigned char LH[64];
    const unsigned char message[7] = "123456";
    for (int i = 0; i < 64; i++) {
        LH[i] = prikey_hex[i];
    }
    unsigned char signature[64];
    unsigned char *pk = NULL;
    pk = convert(pubkey_hex);
    printf("pk: %s\n", pk);

    ed25519_donna_sign(signature, message, 7, LH, pk);
    int status = ed25519_sign_open(message, 7, pk, signature);
    printf("%d\n", status);
    return 0;
}
