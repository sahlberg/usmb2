/* Differential test: hmac-md5.c + md5.c (renamed c_*) against mips/hmac-md5.S + md5.S */
#include "../common/libt.h"
#include "md5.h"
typedef unsigned char uc;
void c_hmac_md5(struct MD5Context *, uc *, uc *, int, uc *, int, uc *, unsigned int, uc *);
void hmac_md5(struct MD5Context *, uc *, uc *, int, uc *, int, uc *, unsigned int, uc *);

/* what the C needs from the IOP's sysclib */
char _toupper(char c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
void *memset(void *d, int c, size_t n) { uint8_t *p = d; while (n--) *p++ = c; return d; }
void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }
void *memmove(void *d, const void *s, size_t n)
{
	uint8_t *p = d; const uint8_t *q = s;
	if (p < q) while (n--) *p++ = *q++; else { p += n; q += n; while (n--) *--p = *--q; }
	return d;
}

static int fails;
static void check(const char *what, const void *a, const void *b, size_t n, int iter)
{
	if (t_memcmp(a, b, n)) {
		t_puts("FAIL "); t_puts(what); t_puts(" iter "); t_hex((uint8_t *)&iter, 4); t_puts("\n  c   ");
		t_hex(a, n); t_puts("\n  asm "); t_hex(b, n); t_puts("\n");
		fails++;
	}
}

static void vector(uc *key, int klen, const char *data, const char *want)
{
	struct MD5Context c; uint8_t d[16]; size_t n = 0; static const char h[] = "0123456789abcdef"; char got[33];
	while (data[n]) n++;
	hmac_md5(&c, NULL, (uc *)data, n, NULL, 0, key, klen, d);
	for (int i = 0; i < 16; i++) { got[2*i] = h[d[i] >> 4]; got[2*i+1] = h[d[i] & 15]; }
	got[32] = 0;
	if (t_memcmp(got, want, 32)) { t_puts("FAIL vector "); t_puts(data); t_puts(" got "); t_puts(got); t_puts("\n"); fails++; }
}

static uint8_t key[64], t0[40], t1[300], t2[300], da[20], db[20];

int main(void)
{
	struct MD5Context a, b;
	/* RFC 2104 test vectors */
	for (int i = 0; i < 16; i++) key[i] = 0x0b;
	vector(key, 16, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d");
	vector((uc *)"Jefe", 4, "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738");
	for (int iter = 0; iter < 3000; iter++) {
		unsigned klen = t_rand() % 65;
		for (unsigned i = 0; i < klen; i++) key[i] = t_rand();
		int n0 = t_rand() % 40;
		for (int i = 0; i < n0; i++) t0[i] = 1 + t_rand() % 127;	/* ASCII, see hmac-md5.S */
		t0[n0 < 39 ? n0 : 39] = 0;
		int l1 = t_rand() % 300, l2 = t_rand() % 300;
		for (int i = 0; i < l1; i++) t1[i] = t_rand();
		for (int i = 0; i < l2; i++) t2[i] = t_rand();
		uc *p0 = t_rand() % 3 ? t0 : NULL;
		uc *p1 = t1, *p2 = t2;
		if (t_rand() % 3 == 0) { p1 = NULL; l1 = 0; }
		if (t_rand() % 3 == 0) { p2 = NULL; l2 = 0; }
		int off = t_rand() % 4;					/* unaligned digests */
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = ((uint8_t *)&b)[i] = t_rand();
		for (size_t i = 0; i < sizeof(da); i++) da[i] = db[i] = t_rand();
		c_hmac_md5(&a, p0, p1, l1, p2, l2, key, klen, da + off);
		hmac_md5(&b, p0, p1, l1, p2, l2, key, klen, db + off);
		check("digest", da, db, sizeof(da), iter);
		/* ctx->input[56..63] after md5Finalize is documented as different */
		/* size after finalize is not used: md5.c leaves it padded */
		a.size = b.size = 0;
		check("ctx", &a, &b, 20 + 56, iter);
	}
	t_puts(fails ? "hmac: FAILED\n" : "hmac: all tests passed\n");
	return fails != 0;
}
