#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *s = BN_new();
BIGNUM *snew =BN_new();
BIGNUM *e = BN_new();
BIGNUM *n = BN_new();
BIGNUM *dec = BN_new();
BIGNUM *decnew = BN_new();
// first find the hex value of M ="I owe you $2000 " using python -c 'print("I owe you $2000".encode("hex"))' command
BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
BN_hex2bn(&snew, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
BN_hex2bn(&e,"010001");
BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
BN_mod_exp(decnew, s, e, n, ctx);
BN_mod_exp(dec, snew, e, n, ctx);
printBN("dec =",dec);
printBN("newdec",decnew);
return 0;
}

