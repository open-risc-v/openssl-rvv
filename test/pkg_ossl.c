// openssl A/B 探针：AES-128-CBC 回环 + AES-128-CTR + SHA-256。
// 只调公开 EVP API；密文与摘要都必须逐字节一致。
// 计时写 stderr，保持 stdout 的哈希行在两侧可比。
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static int do_ctr(const unsigned char *in, size_t n, unsigned char *out)
{
    unsigned char key[16], iv[16];
    for (int i = 0; i < 16; i++) { key[i] = (unsigned char)(0x30 + i); iv[i] = (unsigned char)(0xa0 + i); }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, outl = 0, tmpl = 0;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv, 1) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_CipherUpdate(ctx, out, &outl, in, (int)n) != 1) goto done;
    if (EVP_CipherFinal_ex(ctx, out + outl, &tmpl) != 1) goto done;
    ok = outl + tmpl;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
    const char *outb = (argc > 1 && argv[1][0]) ? argv[1] : NULL;
    int reps = argc > 2 ? atoi(argv[2]) : 1;
    if (reps < 1) reps = 1;

    unsigned char *plain = malloc(N), *enc = malloc(N), *dec = malloc(N), *ctr = malloc(N);
    unsigned char md[SHA256_DIGEST_LENGTH];
    if (!plain || !enc || !dec || !ctr) return 2;

    for (size_t i = 0; i < N; i++) plain[i] = (unsigned char)((i * 37 + (i >> 8)) & 0xff);

    int el = do_cbc(plain, N, enc, 1);
    if (el != (int)N) { fprintf(stderr, "encrypt=%d\n", el); return 3; }
    int dl = do_cbc(enc, N, dec, 0);
    if (dl != (int)N || memcmp(plain, dec, N) != 0) { fprintf(stderr, "decrypt=%d\n", dl); return 4; }
    int tl = do_ctr(plain, N, ctr);
    if (tl != (int)N) { fprintf(stderr, "ctr=%d\n", tl); return 6; }

    SHA256(plain, N, md);

    /* 计时：best-of-reps，全部走真实 EVP 路径 */
    double bc = 1e18, bd = 1e18, bt = 1e18, bs = 1e18;
    for (int r = 0; r < reps; r++) {
        double t0 = now_ms();
        do_cbc(plain, N, enc, 1);
        double t1 = now_ms(); if (t1 - t0 < bc) bc = t1 - t0;
        t0 = now_ms();
        do_cbc(enc, N, dec, 0);
        t1 = now_ms(); if (t1 - t0 < bd) bd = t1 - t0;
        t0 = now_ms();
        do_ctr(plain, N, ctr);
        t1 = now_ms(); if (t1 - t0 < bt) bt = t1 - t0;
        t0 = now_ms();
        SHA256(plain, N, md);
        t1 = now_ms(); if (t1 - t0 < bs) bs = t1 - t0;
    }
    fprintf(stderr, "cbc_enc_ms=%.3f cbc_dec_ms=%.3f ctr_ms=%.3f sha256_ms=%.3f\n",
            bc, bd, bt, bs);

    printf("n=%d evp=%s cipher=%s sha256=", N,
           OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_CFLAGS));
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", md[i]);
    printf(" fnv_ct=%016llx fnv_ctr=%016llx\n",
           (unsigned long long)fnv1a(enc, N), (unsigned long long)fnv1a(ctr, N));

    if (outb) {
        FILE *f = fopen(outb, "wb");
        if (!f) return 5;
        fwrite(enc, 1, N, f);
        fwrite(ctr, 1, N, f);
        fclose(f);
    }
    free(plain); free(enc); free(dec); free(ctr);
    return 0;
}
