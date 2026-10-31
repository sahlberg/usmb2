/*
 * Differential test: z80/ps2smap.c (renamed c_*) against mips/ps2smap.S.
 * smap, ministack and the kernel are stubs that play the same seeded script
 * to both, and hash every call they get.
 */
#include <errno.h>
#include <thbase.h>
#include <thevent.h>
#include "../common/libt.h"
#include "smap.h"
#include "mstack.h"
#include "slip.h"
int c_ps2smap_init(uint32_t ip, uint32_t mask, uint32_t gw);
void c_ps2smap_set_port(const uint16_t *port);
void c_send_packet(uint8_t *p, int len);
int c_recv_packet(uint8_t *p, int len, int to);

static int side;			/* 0: C, 1: asm */
static ip_proto_handler handler[2];
static unsigned int (*alarm_cb[2])(void *);
static uint32_t g_seed, hash;
static uint32_t g_rand(void) { g_seed = g_seed * 1664525u + 1013904223u; return g_seed >> 8; }
static void h(uint32_t v) { hash = (hash ^ v) * 16777619u; }
static void hb(const void *p, int n) { const uint8_t *q = p; while (n-- > 0) h(*q++); }

void *memcpy(void *d, const void *s, size_t n) { uint8_t *p = d; const uint8_t *q = s; h(n); while (n--) *p++ = *q++; return d; }
int memcmp(const void *a, const void *b, size_t n) { return t_memcmp(a, b, n); }

static uint8_t frame[1600];		/* the frame in the SMAP FIFO */
static uint16_t ports[2] = { 0x3412, 0xbd01 };

/* a frame from the network, as ministack hands it over */
static int deliver(void)
{
	int ihl = g_rand() % 4 ? 5 : 5 + g_rand() % 11;
	int len = g_rand() % 8 ? 40 + g_rand() % 1480 : g_rand() % 1600;
	for (int i = 0; i < 1600; i++) frame[i] = g_rand();
	frame[14] = 0x40 | ihl;
	frame[16] = len >> 8; frame[17] = len;
	if (g_rand() % 4) memcpy(&frame[14 + ihl * 4 + 2], &ports[g_rand() % 2], 2);
	int hl = g_rand() % 3 ? 14 + ihl * 4 + 4 + g_rand() % 10 : g_rand() % 64;
	if (!handler[side]) return 0;
	int rc = handler[side](frame, hl);
	h(0x100 + rc);
	return rc;
}

int CreateEventFlag(iop_event_t *ev) { h(1); hb(ev, sizeof(*ev)); return g_rand() % 5 ? 7 : -400; }
int SetEventFlag(int ef, u32 bits) { h(2); h(ef); h(bits); return 0; }
int iSetEventFlag(int ef, u32 bits) { h(3); h(ef); h(bits); return 0; }
int ClearEventFlag(int ef, u32 bits) { h(4); h(ef); h(bits); return 0; }
int WaitEventFlag(int ef, u32 bits, int mode, u32 *res)
{
	h(5); h(ef); h(bits); h(mode);
	int n = g_rand() % 3;		/* frames that come in while we wait */
	while (n--) deliver();
	if (g_rand() % 2 && alarm_cb[side]) h(0x200 + alarm_cb[side](0));
	*res = 0;
	return 0;
}
int SetAlarm(iop_sys_clock_t *c, unsigned int (*cb)(void *), void *arg) { h(6); h(c->lo); h(c->hi); h((uint32_t)arg); alarm_cb[side] = cb; return 0; }
int CancelAlarm(unsigned int (*cb)(void *), void *arg) { h(7); h(cb == alarm_cb[side]); h((uint32_t)arg); return 0; }
void USec2SysClock(u32 usec, iop_sys_clock_t *c) { h(8); h(usec); c->lo = usec * 3; c->hi = usec >> 20; }
void ip_set_tcp_handler(ip_proto_handler hd) { h(9); handler[side] = hd; }
int arp_resolve(uint32_t ip, uint8_t mac[6])
{
	h(10); h(ip);
	if (g_rand() % 5 == 0) return -1;
	for (int i = 0; i < 6; i++) mac[i] = g_rand();
	return 0;
}
int SMAPGetMACAddress(uint8_t *b) { h(11); for (int i = 0; i < 6; i++) b[i] = 0xa0 + i; return 0; }
int smap_transmit(void *hdr, uint16_t hs, const void *data, uint16_t ds) { h(12); h(hs); h(ds); h(data == 0); hb(hdr, hs); return 0; }
void smap_fifo_read(uint16_t off, void *dst, uint32_t n) { h(13); h(off); h(n); for (uint32_t i = 0; i < n; i++) ((uint8_t *)dst)[i] = frame[off + i]; }

static int fails;
static uint8_t pkt[2][1600] __attribute__((aligned(4)));

int main(void)
{
	for (int op = 0; op < 30000; op++) {
		int what = t_rand() % 16;
		uint32_t a1 = t_rand() << 8 | t_rand(), a2 = t_rand() % 4 ? 0xffffff00 : t_rand() << 8, a3 = t_rand() << 4;
		int len = t_rand() % 6 ? t_rand() % 1520 : t_rand() % 1700;	/* never negative, the C would memcpy that too */
		int to = t_rand() % 4 ? t_rand() % 100 : (int)(t_rand() % 5) - 2;
		int port = t_rand() % 2;
		for (int i = 0; i < 1600; i++) pkt[0][i] = pkt[1][i] = t_rand();
		if (t_rand() % 2) { pkt[0][16] = pkt[1][16] = a1 >> 24; }	/* same subnet, sometimes */
		uint32_t seed = t_rand(), hh[2]; int rc[2];
		for (side = 0; side < 2; side++) {
			g_seed = seed; hash = 2166136261u; rc[side] = 0;
			if (op == 0 || what == 0) {
				rc[side] = side ? ps2smap_init(a1, a2, a3) : c_ps2smap_init(a1, a2, a3);
			} else if (what == 1 || op == 1) {
				side ? ps2smap_set_port(&ports[port]) : c_ps2smap_set_port(&ports[port]);
			} else if (what < 6) {
				rc[side] = deliver();
			} else if (what < 10) {
				side ? send_packet(pkt[side], len) : c_send_packet(pkt[side], len);
			} else {
				rc[side] = side ? recv_packet(pkt[side], len, to) : c_recv_packet(pkt[side], len, to);
			}
			hh[side] = hash;
		}
		if (rc[0] != rc[1] || hh[0] != hh[1] || t_memcmp(pkt[0], pkt[1], 1600)) {
			t_puts("FAIL op "); t_hex((uint8_t *)&op, 4); t_puts(" what "); t_hex((uint8_t *)&what, 1);
			t_puts(" rc "); t_hex((uint8_t *)rc, 8); t_puts(" hash "); t_hex((uint8_t *)hh, 8); t_puts("\n");
			if (++fails > 5) return 1;
		}
	}
	t_puts(fails ? "ps2smap: FAILED\n" : "ps2smap: all tests passed\n");
	return fails != 0;
}
