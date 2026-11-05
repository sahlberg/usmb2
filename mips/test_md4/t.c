/* Differential test: md4c.c (renamed c_*) against mips/md4c.S */
#include "../common/libt.h"
/* md4c.c uses memcpy, which the IOP gets from sysclib */
void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }
#include "md4.h"
void c_MD4Init(MD4_CTX *);
void c_MD4Update(MD4_CTX *, unsigned char *, unsigned int);
void c_MD4Final(unsigned char [16], MD4_CTX *);

static int fails;
static void check(const char *what, const void *a, const void *b, size_t n, int iter)
{
	if (t_memcmp(a, b, n)) {
		t_puts("FAIL "); t_puts(what); t_puts(" iter "); t_hex((uint8_t *)&iter, 4); t_puts("\n  c   ");
		t_hex(a, n); t_puts("\n  asm "); t_hex(b, n); t_puts("\n");
		fails++;
	}
}

static void vector(const char *s, const char *want)
{
	MD4_CTX c; uint32_t d[4]; size_t n = 0; static const char h[] = "0123456789abcdef"; char got[33];
	uint8_t *p = (uint8_t *)d;
	while (s[n]) n++;
	MD4Init(&c); MD4Update(&c, (unsigned char *)s, n); MD4Final(p, &c);
	for (int i = 0; i < 16; i++) { got[2*i] = h[p[i] >> 4]; got[2*i+1] = h[p[i] & 15]; }
	got[32] = 0;
	if (t_memcmp(got, want, 32)) { t_puts("FAIL vector "); t_puts(s); t_puts(" got "); t_puts(got); t_puts("\n"); fails++; }
}

static uint8_t data[300];

int main(void)
{
	MD4_CTX a, b;
	uint32_t da[4], db[4];
	vector("", "31d6cfe0d16ae931b73c59d7e0c089c0");
	vector("abc", "a448017aaf21d8525fc10ae87aa6729d");
	vector("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	       "e33b4ddc9c38f2199c3e7b164fcc0536");
	for (int iter = 0; iter < 3000; iter++) {
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = ((uint8_t *)&b)[i] = t_rand();
		c_MD4Init(&a); MD4Init(&b);
		check("init", &a, &b, sizeof(a), iter);
		int nup = t_rand() % 6;
		/* ntlm.c feeds the password one byte at a time: do that sometimes */
		int bytewise = t_rand() % 3 == 0;
		for (int u = 0; u < nup; u++) {
			size_t len = t_rand() % 4 == 0 ? t_rand() % 300 : t_rand() % 70;
			for (size_t i = 0; i < len; i++) data[i] = t_rand();
			if (bytewise) {
				for (size_t i = 0; i < len; i++) { c_MD4Update(&a, data + i, 1); MD4Update(&b, data + i, 1); }
			} else {
				c_MD4Update(&a, data, len); MD4Update(&b, data, len);
			}
			/* state, count and the pending input bytes must match */
			check("update", &a, &b, 24 + ((a.count[0] >> 3) & 63), iter);
		}
		c_MD4Final((unsigned char *)da, &a); MD4Final((unsigned char *)db, &b);
		check("final", da, db, 16, iter);
	}
	t_puts(fails ? "md4: FAILED\n" : "md4: all tests passed\n");
	return fails != 0;
}
