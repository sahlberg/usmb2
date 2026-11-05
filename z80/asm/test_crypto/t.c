/* Differential test harness for MD4/MD5/HMAC-MD5 (C vs asm) */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "md4.h"
#include "md5.h"
#include "hmac-md5.h"

static unsigned char buf[600];
static unsigned char pat[260];
static unsigned char out[16];

static void hex(unsigned char *p, int n)
{
        while (n--) printf("%02x", *p++);
}

static void md4s(unsigned char *p, unsigned int n, int mode)
{
        MD4_CTX *c = (MD4_CTX *)buf;
        unsigned int i, k;
        MD4Init(c);
        if (mode == 0) MD4Update(c, p, n);
        else if (mode == 1) for (i = 0; i < n; i++) MD4Update(c, p + i, 1);
        else for (i = 0; i < n; i += k) { k = n - i; if (k > mode) k = mode; MD4Update(c, p + i, k); }
        MD4Final(out, c);
        hex(out, 16);
        /* state + count are well defined after Final */
        printf(" ");
        hex(buf, 24);
        printf("\n");
}

static void md5s(unsigned char *p, unsigned int n, int mode)
{
        struct MD5Context *c = (struct MD5Context *)buf;
        unsigned int i, k;
        md5Init(c);
        if (mode == 0) md5Update(c, p, n);
        else if (mode == 1) for (i = 0; i < n; i++) md5Update(c, p + i, 1);
        else for (i = 0; i < n; i += k) { k = n - i; if (k > mode) k = mode; md5Update(c, p + i, k); }
        md5Finalize(c);
        hex(c->input, 16);
        printf(" ");
        hex(buf + 4, 16);   /* buffer; size after finalize is not used */
        printf("\n");
}

static char *vec[] = {
        "", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        NULL
};

static void hm(unsigned char *t0, unsigned char *t1, int l1, unsigned char *t2, int l2,
               unsigned char *key, unsigned int kl)
{
        memset(buf, 0xa5, 200);
        hmac_md5((struct MD5Context *)buf, t0, t1, l1, t2, l2, key, kl, out);
        hex(out, 16);
        printf("\n");
}

int main(void)
{
        int i, j, n;
        unsigned char key[80];
        unsigned char *pw = (unsigned char *)"Passw0rd";
        unsigned char z;
        uint32_t st[4];

        for (i = 0; i < 260; i++) pat[i] = (unsigned char)(i * 37 + (i >> 3) * 11 + 5);

        printf("MD4 vectors\n");
        for (i = 0; vec[i]; i++) md4s((unsigned char *)vec[i], strlen(vec[i]), 0);
        printf("MD5 vectors\n");
        for (i = 0; vec[i]; i++) md5s((unsigned char *)vec[i], strlen(vec[i]), 0);

        printf("MD4 lengths\n");
        for (n = 0; n <= 200; n++) {
                printf("%d ", n); md4s(pat, n, 0);
                printf("%d ", n); md4s(pat, n, 1);
                printf("%d ", n); md4s(pat, n, 7);
                if ((n & 7) == 0) { printf("%d ", n); md4s(pat, n, 63); }
        }
        printf("MD5 lengths\n");
        for (n = 0; n <= 200; n++) {
                printf("%d ", n); md5s(pat, n, 0);
                printf("%d ", n); md5s(pat, n, 1);
                printf("%d ", n); md5s(pat, n, 7);
                if ((n & 7) == 0) { printf("%d ", n); md5s(pat, n, 65); }
        }

        printf("md5Step\n");
        st[0] = 0x01234567; st[1] = 0x89abcdef; st[2] = 0xfedcba98; st[3] = 0x76543210;
        memcpy(buf, pat, 64);
        md5Step(st, (uint32_t *)buf);
        hex((unsigned char *)st, 16);
        printf("\n");

        printf("HMAC RFC2104\n");
        memset(key, 0x0b, 16);
        hm(NULL, (unsigned char *)"Hi There", 8, NULL, 0, key, 16);
        hm(NULL, (unsigned char *)"what do ya want for nothing?", 28, NULL, 0, (unsigned char *)"Jefe", 4);
        memset(key, 0xaa, 16);
        memset(pat + 200, 0xdd, 50);
        hm(NULL, pat + 200, 50, NULL, 0, key, 16);
        for (i = 0; i < 260; i++) pat[i] = (unsigned char)(i * 37 + (i >> 3) * 11 + 5);

        printf("HMAC combos\n");
        for (i = 0; i < 80; i++) key[i] = (unsigned char)(i * 13 + 7);
        for (j = 0; j <= 65; j++) {
                printf("k%d ", j);
                hm((unsigned char *)"UserName_az@[`{AZ~", pat, j * 3, pat + 17, j, key, j);
        }
        hm((unsigned char *)"", NULL, 0, NULL, 0, key, 16);
        hm(NULL, NULL, 0, NULL, 0, key, 0);
        hm((unsigned char *)"Administrator", NULL, 0, (unsigned char *)"WORKGROUP", 9, key, 16);
        hm((unsigned char *)"x", pat, 0, NULL, 0, key, 64);   /* NULL text must have length 0 */
        hm((unsigned char *)"\x80\xe1\xff\x7fmIxEd", pat, 119, pat + 3, 1, key, 16);

        printf("NTLM pattern\n");
        memset(buf, 0x5a, sizeof(buf));
        MD4Init((MD4_CTX *)&buf[0]);
        z = 0;
        while (*pw) {
                MD4Update((MD4_CTX *)&buf[0], pw++, 1);
                MD4Update((MD4_CTX *)&buf[0], &z, 1);
        }
        MD4Final(&buf[96], (MD4_CTX *)&buf[0]);
        hex(&buf[96], 16); printf("\n");
        {
                unsigned char ntowf[16];
                unsigned char *dom = (unsigned char *)"D\0o\0m\0";
                hmac_md5((struct MD5Context *)&buf[0], (unsigned char *)"user", NULL, 0,
                         dom, 6, &buf[96], 16, ntowf);
                hex(ntowf, 16); printf("\n");
                for (i = 0; i < 300; i++) buf[200 + i] = (unsigned char)(i ^ 0x3c);
                hmac_md5((struct MD5Context *)&buf[0], NULL, &buf[208], 150, NULL, 0,
                         ntowf, 16, &buf[200]);
                hex(&buf[200], 24); printf("\n");
                /* digest aliasing key */
                memcpy(&buf[400], ntowf, 16);
                hmac_md5((struct MD5Context *)&buf[0], (unsigned char *)"a", NULL, 0, NULL, 0,
                         &buf[400], 16, &buf[400]);
                hex(&buf[400], 16); printf("\n");
        }
        printf("done\n");
        return 0;
}
