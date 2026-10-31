/* Tiny freestanding helpers for the test programs. */
#include <stdint.h>
#include <stddef.h>
int sys_write(int fd, const void *buf, size_t len);
static inline void t_puts(const char *s) { size_t n = 0; while (s[n]) n++; sys_write(1, s, n); }
static inline void t_hex(const uint8_t *p, size_t n) {
	static const char h[] = "0123456789abcdef"; char c[2];
	while (n--) { c[0] = h[*p >> 4]; c[1] = h[*p++ & 15]; sys_write(1, c, 2); }
}
static inline int t_memcmp(const void *a, const void *b, size_t n) {
	const uint8_t *x = a, *y = b; while (n--) { if (*x != *y) return *x - *y; x++; y++; } return 0;
}
static uint32_t t_seed = 12345;
static inline uint32_t t_rand(void) { t_seed = t_seed * 1103515245u + 12345u; return t_seed >> 8; }
