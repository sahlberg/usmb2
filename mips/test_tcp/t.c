/*
 * Differential test: z80/tcp.c + ip.c (renamed c_*) against mips/tcp.S + ip.S.
 * The same random calls run on both against the same scripted network:
 * recv_packet() makes up packets, many of them plausible for the
 * connection's state, and send_packet() hashes what is sent.
 */
#include <errno.h>
#include "../common/libt.h"
#include "ip.h"
#include "tcp.h"
_Static_assert(EAGAIN == 11, "tcp.S has EAGAIN = 11");
_Static_assert(sizeof(tcp_context_t) == 32, "tcp.S's offsets");

#define C(f) c_##f
int c_tcp_connect(tcp_context_t *tcp);
int c_tcp_send(tcp_context_t *tcp, int len, uint8_t *data, int window);
int c_tcp_recv(tcp_context_t *tcp, int len);
int c_tcp_recv_timeout(tcp_context_t *tcp, int len, int to);
uint8_t *c_tcp_rx_buffer(tcp_context_t *tcp);
uint8_t *c_tcp_tx_buffer(tcp_context_t *tcp);

void *memset(void *d, int c, size_t n) { uint8_t *p = d; while (n--) *p++ = c; return d; }
void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }
int memcmp(const void *a, const void *b, size_t n) { return t_memcmp(a, b, n); }

/* the network */
static tcp_context_t *cur;		/* the context under test, for plausible packets */
static uint32_t g_seed;
static uint32_t g_rand(void) { g_seed = g_seed * 1664525u + 1013904223u; return g_seed >> 8; }
static uint32_t hash, nsent, nrecv, recv_to, recv_len;

void send_packet(uint8_t *p, int len)
{
	nsent++;
	hash = (hash ^ len) * 16777619u;
	for (int i = 0; i < len && i < 1600; i++) hash = (hash ^ p[i]) * 16777619u;
}

static void put32be(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

int recv_packet(uint8_t *p, int len, int to)
{
	nrecv++;
	recv_to = recv_to * 31 + to; recv_len = recv_len * 31 + len;
	if (nrecv > 40) return -EAGAIN;		/* make every call end */
	unsigned r = g_rand() % 20;
	if (r == 0) return -EAGAIN;
	if (r == 1) return -5;
	int ths = 20 + 4 * (g_rand() % 3 == 0 ? g_rand() % 11 : 0);
	int pay = g_rand() % 3 == 0 ? 0 : g_rand() % 600;
	int n = 20 + ths + pay;
	for (int i = 0; i < n && i < len; i++) p[i] = g_rand();
	if (r == 2) return g_rand() % 40;		/* too short */
	p[0] = r == 3 ? 0x46 : 0x45;
	p[9] = r == 4 ? 17 : 6;
	memcpy(&p[20], &cur->dst_port, 4);
	if (r == 5) p[20 + (g_rand() & 3)] ^= 1 << (g_rand() & 7);
	p[32] = (ths / 4) << 4;
	static const uint8_t fl[] = { 0x10, 0x18, 0x12, 0x02, 0x11, 0x10, 0x18, 0x10 };
	p[33] = r == 6 ? 0x14 : fl[g_rand() % 8];
	unsigned k = g_rand() % 8;
	uint32_t seq = k < 4 ? cur->ack : k == 4 ? cur->ack - 1 : g_rand();
	if (k == 5) { pay = 0; n = 20 + ths; }	/* a zero window probe */
	k = g_rand() % 8;
	uint32_t ack = k < 3 ? cur->seq + (g_rand() % 3) * (g_rand() % 300) : k < 5 ? 2 : k < 6 ? cur->seq : g_rand();
	put32be(&p[24], seq);
	put32be(&p[28], ack);
	return n < len ? n : len;
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

#define PKT 1600
static uint8_t pa[PKT] __attribute__((aligned(4))), pb[PKT] __attribute__((aligned(4)));
static uint8_t data[1600];
struct obs { int rc; uint32_t hash, nsent, nrecv, to, len; int rxoff, txoff; };

static void run(int side, tcp_context_t *t, int op, int len, uint8_t *d, int win, uint32_t seed, struct obs *o)
{
	cur = t; g_seed = seed; hash = 2166136261u; nsent = nrecv = recv_to = recv_len = 0;
	switch (op) {
	case 0: o->rc = side ? tcp_connect(t) : c_tcp_connect(t); break;
	case 1: o->rc = side ? tcp_send(t, len, d, win) : c_tcp_send(t, len, d, win); break;
	case 2: o->rc = side ? tcp_recv(t, len) : c_tcp_recv(t, len); break;
	default: o->rc = side ? tcp_recv_timeout(t, len, win) : c_tcp_recv_timeout(t, len, win); break;
	}
	o->hash = hash; o->nsent = nsent; o->nrecv = nrecv; o->to = recv_to; o->len = recv_len;
	o->rxoff = (side ? tcp_rx_buffer(t) : c_tcp_rx_buffer(t)) - t->ip.pkt;
	o->txoff = (side ? tcp_tx_buffer(t) : c_tcp_tx_buffer(t)) - t->ip.pkt;
}

int main(void)
{
	tcp_context_t a, b;
	int ops = 0;
	for (int conn = 0; conn < 400; conn++) {
		for (size_t i = 0; i < sizeof(a); i++) ((uint8_t *)&a)[i] = t_rand();
		a.ip.pkt_size = 200 + 4 * (t_rand() % 326);
		a.ip.pkt = pa;
		if (t_rand() % 2) { a.seq = 1 + t_rand() % 3; a.ack = t_rand() % 3; }
		a.ths = 20;
		for (int i = 0; i < PKT; i++) pa[i] = pb[i] = t_rand();
		b = a; b.ip.pkt = pb;
		for (int step = 0; step < 50; step++, ops++) {
			int op = t_rand() % 10; op = op < 1 ? 0 : op < 5 ? 1 : op < 8 ? 2 : 3;
			int len = t_rand() % 3 == 0 ? 0 : t_rand() % 600;
			if (op == 1 && len > a.ip.pkt_size - 44) len = a.ip.pkt_size - 44;
			uint8_t *d = t_rand() % 3 ? data : NULL;
			int win = t_rand() % 3 == 0 ? 0 : t_rand() % (op == 3 ? 200 : 2000);
			for (int i = 0; i < len; i++) data[i] = t_rand();
			uint32_t seed = t_rand();
			struct obs oa, ob;
			run(0, &a, op, len, d, win, seed, &oa);
			run(1, &b, op, len, d, win, seed, &ob);
			check("calls/results", &oa, &ob, sizeof(oa), ops);
			a.ip.pkt = b.ip.pkt = NULL;
			check("context", &a, &b, sizeof(a), ops);
			a.ip.pkt = pa; b.ip.pkt = pb;
			check("packet buffer", pa, pb, PKT, ops);
			if (fails > 5) return 1;
		}
	}
	t_puts(fails ? "tcp: FAILED\n" : "tcp: all tests passed\n");
	return fails != 0;
}
