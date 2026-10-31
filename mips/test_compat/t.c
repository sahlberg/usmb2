/* Differential test: ps2iop-compat.c (renamed c_*) against mips/ps2iop-compat.S */
#include "../common/libt.h"
void *c_malloc(int); void c_free(void *); void *c_calloc(size_t, size_t); char *c_strdup(const char *);
void *malloc(int); void free(void *); void *calloc(size_t, size_t); char *strdup(const char *);

static int side, intr;
static uint32_t g_seed, hash;
static uint32_t g_rand(void) { g_seed = g_seed * 1664525u + 1013904223u; return g_seed >> 8; }
static void h(uint32_t v) { hash = (hash ^ v) * 16777619u; }
static uint8_t pool[2][65536] __attribute__((aligned(16)));
static int used[2];
static uint32_t off(const void *p) { return p ? (uint32_t)((const uint8_t *)p - pool[side]) : 0xffffffff; }

int CpuSuspendIntr(int *state) { h(1); h(intr); intr = 1; *state = 0x55; return 0; }
int CpuResumeIntr(int state) { h(2); h(state); h(intr); intr = 0; return 0; }
void *AllocSysMemory(int mode, int size, void *ptr)
{
	h(3); h(mode); h(size); h(ptr == 0); h(intr);
	if (g_rand() % 5 == 0 || used[side] + size > 60000) return NULL;
	void *p = &pool[side][used[side]];
	for (int i = 0; i < size; i++) ((uint8_t *)p)[i] = g_rand();	/* not cleared */
	used[side] += (size + 15) & ~15;
	return p;
}
int FreeSysMemory(void *p) { h(4); h(intr); h(off(p)); return 0; }
void *memset(void *d, int c, size_t n) { h(5); h(off(d)); h(c); h(n); uint8_t *p = d; while (n--) *p++ = c; return d; }
void *memcpy(void *d, const void *s, size_t n) { h(6); h(off(d)); h(n); uint8_t *p = d; const uint8_t *q = s; while (n--) *p++ = *q++; return d; }
size_t strlen(const char *s) { h(7); size_t n = 0; while (s[n]) n++; return n; }

static int fails;
static char str[300];

int main(void)
{
	for (int op = 0; op < 20000; op++) {
		if (op % 500 == 0) used[0] = used[1] = 0;
		int what = t_rand() % 4;
		int a = t_rand() % 4 ? t_rand() % 600 : t_rand() % 3, b = t_rand() % 4 ? 1 : t_rand() % 50;
		int n = t_rand() % 250;
		for (int i = 0; i < n; i++) str[i] = 1 + t_rand() % 255;
		str[n] = 0;
		uint32_t seed = t_rand(), hh[2], rc[2];
		for (side = 0; side < 2; side++) {
			g_seed = seed; hash = 2166136261u; intr = 0;
			void *p = NULL;
			switch (what) {
			case 0: p = side ? malloc(a) : c_malloc(a); break;
			case 1: side ? free(&pool[side][a]) : c_free(&pool[side][a]); break;
			case 2: p = side ? calloc(b, a) : c_calloc(b, a); break;
			default: p = side ? strdup(str) : c_strdup(str); break;
			}
			rc[side] = off(p); hh[side] = hash;
			if (intr) { t_puts("FAIL interrupts left suspended\n"); fails++; }
		}
		if (rc[0] != rc[1] || hh[0] != hh[1] || t_memcmp(pool[0], pool[1], sizeof(pool[0]))) {
			t_puts("FAIL op "); t_hex((uint8_t *)&op, 4); t_puts(" what "); t_hex((uint8_t *)&what, 1); t_puts("\n");
			if (++fails > 5) return 1;
		}
	}
	t_puts(fails ? "compat: FAILED\n" : "compat: all tests passed\n");
	return fails != 0;
}
