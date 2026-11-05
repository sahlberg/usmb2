/* Differential test: md5.c (renamed c_*) against mips/md5.S */
#include "../common/libt.h"
#include "md5.h"
void c_md5Init(struct MD5Context *ctx);
void c_md5Update(struct MD5Context *ctx, uint8_t *input, size_t input_len);
void c_md5Finalize(struct MD5Context *ctx);

static int fails;
static void check(const char *what, struct MD5Context *a, struct MD5Context *b, size_t n, int iter)
{
	if (t_memcmp(a, b, n)) {
		t_puts("FAIL "); t_puts(what); t_puts(" iter "); t_hex((uint8_t *)&iter, 4); t_puts("\n  c  ");
		t_hex((uint8_t *)a, n); t_puts("\n  asm "); t_hex((uint8_t *)b, n); t_puts("\n");
		fails++;
	}
}

static void vector(const char *s, const char *want)
{
	struct MD5Context c; size_t n = 0; static const char h[] = "0123456789abcdef"; char got[33];
	while (s[n]) n++;
	md5Init(&c); md5Update(&c, (uint8_t *)s, n); md5Finalize(&c);
	for (int i = 0; i < 16; i++) { got[2*i] = h[c.input[i] >> 4]; got[2*i+1] = h[c.input[i] & 15]; }
	got[32] = 0;
	if (t_memcmp(got, want, 32)) { t_puts("FAIL vector "); t_puts(s); t_puts(" got "); t_puts(got); t_puts("\n"); fails++; }
}

static uint8_t data[300];

int main(void)
{
	struct MD5Context a, b;
	vector("", "d41d8cd98f00b204e9800998ecf8427e");
	vector("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6");
	for (int iter = 0; iter < 3000; iter++) {
		/* same garbage in both, md5Init must not depend on it */
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = ((uint8_t *)&b)[i] = t_rand();
		c_md5Init(&a); md5Init(&b);
		check("init", &a, &b, sizeof(a), iter);
		int nup = t_rand() % 6;
		for (int u = 0; u < nup; u++) {
			size_t len = t_rand() % 4 == 0 ? t_rand() % 300 : t_rand() % 70;
			for (size_t i = 0; i < len; i++) data[i] = t_rand();
			c_md5Update(&a, data, len); md5Update(&b, data, len);
			check("update", &a, &b, sizeof(a), iter);
		}
		c_md5Finalize(&a); md5Finalize(&b);
		/* input[56..63] after finalize is documented as different, and
		   size after finalize is not used: md5.c leaves it padded */
		a.size = b.size = 0;
		check("final", &a, &b, 20 + 56, iter);
	}
	t_puts(fails ? "md5: FAILED\n" : "md5: all tests passed\n");
	return fails != 0;
}
