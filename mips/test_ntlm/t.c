/* Differential test: ntlm.c (renamed c_*, with C md4/hmac/md5) against mips/ntlm.S (with the asm ones) */
#include "../common/libt.h"
#include "usmb2.h"
#include "ntlm.h"
int c_ntlm_generate_auth(struct usmb2_context *, char *, char *);

_Static_assert(offsetof(struct usmb2_context, buf) == 92, "ntlm.S has BUF = 92");

/* what the C needs from the IOP's sysclib */
char _toupper(char c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
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
		const uint8_t *x = a, *y = b; size_t i = 0;
		while (x[i] == y[i]) i++;
		t_puts("FAIL "); t_puts(what); t_puts(" iter "); t_hex((uint8_t *)&iter, 4);
		t_puts(" first difference at "); t_hex((uint8_t *)&i, 2); t_puts("\n  c   ");
		t_hex(x + i, n - i < 32 ? n - i : 32); t_puts("\n  asm "); t_hex(y + i, n - i < 32 ? n - i : 32); t_puts("\n");
		fails++;
	}
}
static void put16(uint8_t *p, unsigned v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }

static struct usmb2_context a, b;

int main(void)
{
	for (int iter = 0; iter < 3000; iter++) {
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = t_rand();
		int ulen = 1 + t_rand() % 31, plen = t_rand() % 32;
		for (int i = 0; i < ulen; i++) a.username[i] = 1 + t_rand() % 127;	/* ASCII, see hmac-md5.S */
		a.username[ulen] = 0;
		for (int i = 0; i < plen; i++) a.password[i] = 1 + t_rand() % 255;
		a.password[plen] = 0;
		/* the CHALLENGE, 4-byte aligned in buf like ntlm.c needs (servers put it at buf[8]) */
		unsigned in = 8 + 4 * (t_rand() % 4);	/* after the 8-byte SessionSetup reply header */
		unsigned dlen = 2 * (t_rand() % 21);
		unsigned room = 512 - (230 + 2 * dlen + 2 * ulen) - 8;
		unsigned maxti = room < MAXTI ? room : MAXTI;
		uint8_t *p = a.buf + in;
		put16(a.buf + 4, 64 + in);
		p[0] = 'N'; p[1] = 'T'; p[2] = 'L'; p[3] = 'M'; p[4] = 'S'; p[5] = 'S'; p[6] = 'P'; p[7] = 0;
		put32(p + 8, 2);
		put16(p + 12, dlen); put16(p + 14, dlen); put32(p + 16, 56);
		/* AvPairs: random types, even lengths, then EndOfList */
		unsigned ti = 0;
		uint8_t *q = p + 56 + dlen;
		while (t_rand() % 6) {
			unsigned l = 2 * (t_rand() % 20);
			if (ti + 4 + l > maxti) break;
			put16(q + ti, 1 + t_rand() % 10); put16(q + ti + 2, l);
			ti += 4 + l;
		}
		put16(q + ti, 0); put16(q + ti + 2, 0);
		put16(p + 40, ti + 4); put16(p + 42, ti + 4); put32(p + 44, 56 + dlen);
		b = a;
		int ra = c_ntlm_generate_auth(&a, a.username, a.password);
		int rb = ntlm_generate_auth(&b, b.username, b.password);
		check("return", &ra, &rb, 4, iter);
		/* buf[76..83] is md5.S's documented md5Finalize difference */
		check("context", &a, &b, 92 + 76, iter);
		check("buf", &a.buf[84], &b.buf[84], sizeof(a.buf) - 84, iter);
	}
	t_puts(fails ? "ntlm: FAILED\n" : "ntlm: all tests passed\n");
	return fails != 0;
}
