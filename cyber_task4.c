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
BIGNUM *M = BN_new();
BIGNUM *Mnew =BN_new();
BIGNUM *e = BN_new();
BIGNUM *n = BN_new();
BIGNUM *enc = BN_new();
BIGNUM *encnew = BN_new();
// first find the hex value of M ="I owe you $2000 " using python -c 'print("I owe you $2000".encode("hex"))' command
BN_hex2bn(&M, "49206f776520796f752024323030302e");
BN_hex2bn(&Mnew, "49206f776520796f752024333030302e");
BN_hex2bn(&e,"010001");
BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_mod_exp(enc, M, e, n, ctx);
BN_mod_exp(encnew, Mnew, e, n, ctx);
printBN("encrypted =", enc);
printBN("new enc=",encnew);
return 0;
}
