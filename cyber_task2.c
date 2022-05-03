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
BIGNUM *m = BN_new();
BIGNUM *e = BN_new();
BIGNUM *n = BN_new();
BIGNUM *encrypted = BN_new();
BIGNUM *decrypted = BN_new();
BIGNUM *enc = BN_new();
BIGNUM *d = BN_new();

BN_hex2bn(&d," 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&enc,"6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC");
BN_hex2bn(&m,"4120746f702073656372657421");
BN_hex2bn(&e, "10001");
BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
// encrypted = m^e mod n
BN_mod_exp(encrypted, m, e, n, ctx);
printBN("encrypted message ", encrypted);
BN_mod_exp(decrypted,enc,d,n,ctx);
printBN("decrytped",decrypted);
return 0;
}
