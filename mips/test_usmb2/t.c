/*
 * Differential test: usmb2.c (renamed c_*) against mips/usmb2.S, both with
 * Neutrino's features. A stub server behind stub tcp_send/tcp_recv answers
 * each request it is sent, in random segments, and every stub hashes what
 * it gets. Each side has its own TCP context, allocation pool and buffers.
 */
#include "../common/libt.h"
#include "usmb2.h"
#include "ip.h"
#include "tcp.h"
_Static_assert(sizeof(struct usmb2_context) == 608, "usmb2.S's SIZEOF_CTX");
_Static_assert(offsetof(struct usmb2_context, buf) == 92, "usmb2.S's BUF");

#define C2(r, f, ...) (side ? f(__VA_ARGS__) : c_##f(__VA_ARGS__))
struct usmb2_context *c_usmb2_init_context(uint32_t, char *, char *);
int c_usmb2_negotiateprotocol(struct usmb2_context *);
int c_usmb2_sessionsetup(struct usmb2_context *);
int c_usmb2_treeconnect(struct usmb2_context *, const char *);
uint8_t *c_usmb2_open(struct usmb2_context *, const char *, int);
int32_t c_usmb2_prw(struct usmb2_context *, int, uint8_t *, uint8_t *, uint8_t *, int, uint64_t);
int32_t c_usmb2_pread(struct usmb2_context *, uint8_t *, uint8_t *, int, uint64_t);
int c_usmb2_size(struct usmb2_context *, uint8_t *);
int usmb2_negotiateprotocol(struct usmb2_context *);
int usmb2_sessionsetup(struct usmb2_context *);
extern tcp_context_t *c_usmb2_tcp;

static int side;
static uint32_t g_seed, hash;
static uint32_t g_rand(void) { g_seed = g_seed * 1664525u + 1013904223u; return g_seed >> 8; }
static void h(uint32_t v) { hash = (hash ^ v) * 16777619u; }
static void hb(const void *p, int n) { const uint8_t *q = p; while (n-- > 0) h(*q++); }

void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }
void *memset(void *d, int c, size_t n) { uint8_t *p = d; while (n--) *p++ = c; return d; }
char *strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++)) ; return r; }
size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

/* allocation: a pool each, pointers compared by their offset */
static uint8_t pool[2][8192] __attribute__((aligned(8)));
static int pool_used[2];
static void *alloc(size_t n, size_t m)
{
	h(20); h(n * m);
	if (g_rand() % 40 == 0 || pool_used[side] + n * m > 8000) return NULL;
	void *p = &pool[side][pool_used[side]];
	memset(p, 0, n * m);
	pool_used[side] += (n * m + 7) & ~7;
	return p;
}
static void release(void *p) { h(21); h(p ? (uint8_t *)p - pool[side] : 0xffffffff); }
void *c_calloc(size_t n, size_t m) { return alloc(n, m); }
void *calloc(size_t n, size_t m) { return alloc(n, m); }
void c_free(void *p) { release(p); }
void free(void *p) { release(p); }

/* NTLM: puts some AUTHENTICATE bytes in place */
static int auth(struct usmb2_context *u, char *user, char *pass)
{
	h(30); h((uint8_t *)user - (uint8_t *)u); h((uint8_t *)pass - (uint8_t *)u); hb(u, sizeof(*u));
	int len = 64 + 2 * (g_rand() % 100);
	for (int i = 0; i < len; i++) u->buf[92 + i] = g_rand();
	return len;
}
int c_ntlm_generate_auth(struct usmb2_context *u, char *a, char *b) { return auth(u, a, b); }
int ntlm_generate_auth(struct usmb2_context *u, char *a, char *b) { return auth(u, a, b); }

/* TCP and the server */
static tcp_context_t tcp[2];
static uint8_t tbuf[2][1600] __attribute__((aligned(4)));
static uint8_t stream[2 * (4 + 64 + 16 + 2048) + 64];	/* what the server has still to send: a stale reply and the reply */
static int s_len, s_pos;

static void put32be(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static void reply(uint32_t mid, int cmd, uint32_t want)
{
	if (want > 2048) want = 2048;
	/*
	 * No more data than asked for: both usmb2.c and usmb2.S copy what is
	 * left over into buf, which a longer reply overruns.
	 */
	int n = cmd == 8 ? 16 + (g_rand() % 4 ? want : g_rand() % (want + 1)) : g_rand() % 3 ? 16 + g_rand() % 120 : g_rand() % 400;
	uint8_t *p = &stream[s_len];
	put32be(p, 64 + n);
	for (int i = 4; i < 4 + 64 + n; i++) p[i] = g_rand();
	uint32_t st = g_rand() % 3 ? 0 : g_rand() % 2 ? 0xc0000016 : g_rand();
	memcpy(&p[4 + 8], &st, 4);
	memcpy(&p[4 + 24], &mid, 4);
	if (g_rand() % 8 == 0) put32be(p, 3000);	/* too big for reasm */
	s_len += 4 + 64 + n;
}
int tcp_send(tcp_context_t *t, int len, uint8_t *data, int window)
{
	uint8_t *p = t->ip.pkt + 40;
	h(40); h(t == &tcp[side]); h(len); h(data == NULL); h(window); hb(p, len);
	uint32_t mid; memcpy(&mid, &p[4 + 24], 4);
	uint32_t want = p[4 + 64 + 4] | p[4 + 64 + 5] << 8;
	s_len = s_pos = 0;
	if (g_rand() % 6 == 0) reply(mid - 1 - g_rand() % 3, p[4 + 12], want);	/* a stale one first */
	reply(mid, p[4 + 12], want > 2048 ? 2048 : want);
	return 0;
}
int tcp_recv(tcp_context_t *t, int len)
{
	h(41); h(t == &tcp[side]); h(len);
	unsigned r = g_rand() % 30;
	if (r == 0) return -11;
	if (r == 1 || s_pos >= s_len) return s_pos >= s_len ? -11 : 0;
	t->ths = 20 + 4 * (g_rand() % 4);
	int n = 1 + g_rand() % 1460;
	if (n > s_len - s_pos) n = s_len - s_pos;
	memcpy(t->ip.pkt + 20 + t->ths, &stream[s_pos], n);
	s_pos += n;
	return n;
}
int c_tcp_send(tcp_context_t *t, int len, uint8_t *d, int w) { return tcp_send(t, len, d, w); }
int c_tcp_recv(tcp_context_t *t, int len) { return tcp_recv(t, len); }
uint8_t *c_tcp_rx_buffer(tcp_context_t *t) { return t->ip.pkt + 20 + t->ths; }
uint8_t *c_tcp_tx_buffer(tcp_context_t *t) { return t->ip.pkt + 40; }

static int fails;
static uint8_t data[2][2200], snap[1600];
static char user[40], pass[40], name[100];

static void rnd_str(char *s, int max) { int n = t_rand() % max; for (int i = 0; i < n; i++) s[i] = 1 + t_rand() % 126; s[n] = 0; }

int main(void)
{
	struct usmb2_context *u[2] = { 0, 0 };
	uint8_t *fid[2] = { 0, 0 };
	for (int op = 0; op < 20000; op++) {
		int what = t_rand() % 12;
		if (!u[0] || !u[1]) what = 0;
		if (what == 0) { side = 0; pool_used[0] = pool_used[1] = 0; fid[0] = fid[1] = 0; }
		rnd_str(user, 31); rnd_str(pass, 31); rnd_str(name, 60);
		int mode = t_rand() % 2 ? 0 : 8, count = t_rand() % 4 ? 1 + t_rand() % 2048 : t_rand() % 2200;
		uint64_t off = (uint64_t)t_rand() << 24 | t_rand();
		int cmd = t_rand() % 2 ? 8 : 9;
		if (cmd == 9 && count > 1300) count = 1300;	/* a write has to fit in one segment, in C too */
		for (int i = 0; i < 2200; i++) data[0][i] = data[1][i] = t_rand();
		uint32_t seed = t_rand(), hh[2]; intptr_t rc[2];
		for (side = 0; side < 2; side++) {
			g_seed = seed; hash = 2166136261u;
			tcp[side].ip.pkt = tbuf[side]; tcp[side].ip.pkt_size = 1500;
			if (side) usmb2_tcp = &tcp[1]; else c_usmb2_tcp = &tcp[0];
			struct usmb2_context *x = u[side];
			uint8_t *f = fid[side] ? fid[side] : (uint8_t *)name;
			switch (what) {
			case 0: x = side ? usmb2_init_context(1, user, pass) : c_usmb2_init_context(1, user, pass);
				u[side] = x; rc[side] = x ? (uint8_t *)x - pool[side] : -1; break;
			case 1: rc[side] = side ? usmb2_treeconnect(x, name) : c_usmb2_treeconnect(x, name); break;
			case 2: case 3: { uint8_t *p = side ? usmb2_open(x, name, mode) : c_usmb2_open(x, name, mode);
				rc[side] = p ? p - pool[side] : -1; if (p) fid[side] = p; break; }
			case 4: case 5: case 6: case 7:
				rc[side] = side ? usmb2_pread(x, f, data[side], count, off) : c_usmb2_pread(x, f, data[side], count, off); break;
			case 8: rc[side] = side ? usmb2_prw(x, cmd, f, cmd == 8 ? data[side] : NULL, cmd == 9 ? data[side] : NULL, count, off)
					     : c_usmb2_prw(x, cmd, f, cmd == 8 ? data[side] : NULL, cmd == 9 ? data[side] : NULL, count, off); break;
			case 9: rc[side] = side ? usmb2_size(x, f) : c_usmb2_size(x, f); break;
			case 10: rc[side] = side ? usmb2_negotiateprotocol(x) : c_usmb2_negotiateprotocol(x); break;
			default: rc[side] = side ? usmb2_sessionsetup(x) : c_usmb2_sessionsetup(x); break;
			}
			hh[side] = hash;
			if (side == 0) memcpy(snap, tbuf[0], 1600);
			else if (t_memcmp(snap, tbuf[0], 1600)) {
				t_puts("asm side wrote into the C side's tbuf, op "); t_hex((uint8_t *)&op, 4); t_puts(" what ");
				t_hex((uint8_t *)&what, 1); t_puts(" pool_used "); t_hex((uint8_t *)&pool_used[1], 2);
				t_puts(" u "); int o = (uint8_t *)u[1] - pool[1]; t_hex((uint8_t *)&o, 2); t_puts("\n");
			}
		}
		int bad = rc[0] != rc[1] || hh[0] != hh[1] || t_memcmp(data[0], data[1], 2200) ||
			  t_memcmp(tbuf[0], tbuf[1], 1600) || t_memcmp(pool[0], pool[1], 8192) ||
			  t_memcmp(&tcp[0].ths, &tcp[1].ths, 1);
		if (bad) {
			t_puts("FAIL op "); t_hex((uint8_t *)&op, 4); t_puts(" what "); t_hex((uint8_t *)&what, 1);
			t_puts(" rc "); t_hex((uint8_t *)rc, 8); t_puts(" hash "); t_hex((uint8_t *)hh, 8);
			for (int i = 0; i < 8192; i++) if (pool[0][i] != pool[1][i]) { t_puts(" pool@"); t_hex((uint8_t *)&i, 2); t_puts(" "); t_hex(&pool[0][i], 8); t_puts(" "); t_hex(&pool[1][i], 8); break; }
			for (int i = 0; i < 1600; i++) if (tbuf[0][i] != tbuf[1][i]) { t_puts(" tbuf@"); t_hex((uint8_t *)&i, 2); t_puts("\n   c "); t_hex(&tbuf[0][i], 48); t_puts("\n asm "); t_hex(&tbuf[1][i], 48); break; }
			for (int i = 0; i < 2200; i++) if (data[0][i] != data[1][i]) { t_puts(" data@"); t_hex((uint8_t *)&i, 2); break; }
			t_puts("\n");
			if (++fails > 5) return 1;
		}
	}
	t_puts(fails ? "usmb2: FAILED\n" : "usmb2: all tests passed\n");
	return fails != 0;
}
