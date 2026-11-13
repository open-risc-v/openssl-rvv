// openssl A/B 探针：AES-128-CBC 加解密回环 + SHA-256，覆盖 EVP 的块加密与哈希两条主路径。
// 只调公开 EVP API；密文与摘要都必须逐字节一致。
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 65536   /* 64KiB：够大以进入多块流水线，又不至于让构建慢 */

static uint64_t fnv1a(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

static int do_cbc(const unsigned char *in, size_t n, unsigned char *out, int enc)
{
    unsigned char key[16], iv[16];
    for (int i = 0; i < 16; i++) { key[i] = (unsigned char)(0x30 + i); iv[i] = (unsigned char)(0xa0 + i); }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, outl = 0, tmpl = 0;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, enc) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);          /* 定长输入，关掉 padding 求确定性 */
    if (EVP_CipherUpdate(ctx, out, &outl, in, (int)n) != 1) goto done;
    if (EVP_CipherFinal_ex(ctx, out + outl, &tmpl) != 1) goto done;
    ok = outl + tmpl;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    const char *outb = argc > 1 ? argv[1] : NULL;
    unsigned char *plain = malloc(N), *enc = malloc(N), *dec = malloc(N);
    unsigned char md[SHA256_DIGEST_LENGTH];
    if (!plain || !enc || !dec) return 2;

    for (size_t i = 0; i < N; i++) plain[i] = (unsigned char)((i * 37 + (i >> 8)) & 0xff);

    int el = do_cbc(plain, N, enc, 1);
    if (el != (int)N) { fprintf(stderr, "encrypt=%d\n", el); return 3; }
    int dl = do_cbc(enc, N, dec, 0);
    if (dl != (int)N || memcmp(plain, dec, N) != 0) { fprintf(stderr, "decrypt=%d\n", dl); return 4; }

    SHA256(plain, N, md);

    printf("n=%d evp=%s cipher=%s sha256=", N,
           OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_CFLAGS));
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", md[i]);
    printf(" fnv_ct=%016llx\n", (unsigned long long)fnv1a(enc, N));

    if (outb) {
        FILE *f = fopen(outb, "wb");
        if (!f) return 5;
        fwrite(enc, 1, N, f);
        fclose(f);
    }
    free(plain); free(enc); free(dec);
    return 0;
}
