/* Differential test: z80/ip.c (renamed c_*) against mips/ip.S */
#include "../common/libt.h"
#include "ip.h"
uint16_t c_csum(uint16_t *ptr, int nbytes);
uint8_t *c_ip_buffer(ip_context_t *ip, int offset);
void c_ip_build_and_send(ip_context_t *ip, uint16_t total_len, uint8_t proto);

void *memset(void *d, int c, size_t n) { uint8_t *p = d; while (n--) *p++ = c; return d; }
void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }

static uint8_t *sent_p; static int sent_len, sent_n;
void send_packet(uint8_t *p, int len) { sent_p = p; sent_len = len; sent_n++; }

static int fails;
static void check(const char *what, const void *a, const void *b, size_t n, int iter)
{
	if (t_memcmp(a, b, n)) {
		t_puts("FAIL "); t_puts(what); t_puts(" iter "); t_hex((uint8_t *)&iter, 4); t_puts("\n  c   ");
		t_hex(a, n); t_puts("\n  asm "); t_hex(b, n); t_puts("\n");
		fails++;
	}
}

static uint8_t buf[1600] __attribute__((aligned(4)));
static uint8_t pa[64] __attribute__((aligned(4))), pb[64] __attribute__((aligned(4)));

int main(void)
{
	for (int iter = 0; iter < 20000; iter++) {
		int n = t_rand() % 4 == 0 ? (int)(t_rand() % 1500) - 2 : (int)(t_rand() % 70);
		int off = 2 * (t_rand() % 8);
		for (int i = 0; i < n + 2 && i < 1550; i++) buf[off + i] = t_rand();
		uint16_t ca = c_csum((uint16_t *)&buf[off], n), cb = csum((uint16_t *)&buf[off], n);
		check("csum", &ca, &cb, 2, iter);
	}
	for (int iter = 0; iter < 20000; iter++) {
		ip_context_t a, b;
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = t_rand();
		for (size_t i = 0; i < sizeof(pa); i++) pa[i] = pb[i] = t_rand();
		if (t_rand() % 8 == 0) a.id = 0xffff;
		b = a; a.pkt = pa; b.pkt = pb;
		uint16_t len = t_rand() % 8 ? 20 + t_rand() % 1480 : t_rand();
		uint8_t proto = t_rand();
		int n0 = sent_n;
		c_ip_build_and_send(&a, len, proto);
		uint8_t *sp_a = sent_p; int sl_a = sent_len;
		ip_build_and_send(&b, len, proto);
		check("pkt", pa, pb, sizeof(pa), iter);
		a.pkt = b.pkt = 0;
		check("ip", &a, &b, sizeof(a), iter);
		if (sent_n != n0 + 2 || sp_a != pa || sent_p != pb || sl_a != len || sent_len != len) {
			t_puts("FAIL send_packet args\n"); fails++;
		}
		int o = t_rand() % 100;
		a.pkt = pa; b.pkt = pa;
		if (c_ip_buffer(&a, o) != ip_buffer(&b, o)) { t_puts("FAIL ip_buffer\n"); fails++; }
	}
	t_puts(fails ? "ip: FAILED\n" : "ip: all tests passed\n");
	return fails != 0;
}
