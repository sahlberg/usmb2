/* Differential test for unicode.c vs unicode.asm.
 * Built twice (C and asm implementation), outputs must be identical. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int utf16_to_utf8(const uint16_t *utf16, int utf16_len);
int utf8_to_utf16(const char *utf8, uint16_t *utf16);

static unsigned int h, h2;
static unsigned int rnd = 12345;

static void mix(unsigned int x)
{
        h = ((h << 7) | (h >> 9)) + x + 0x3b1;
        h2 += h + (h2 >> 5) + (h2 << 3);
}

static unsigned int lcg(void)
{
        rnd = rnd * 25173U + 13849U;
        return rnd;
}

static unsigned char in8[40];
static uint16_t out16[40];
static uint16_t buf16[48];

/* run utf8_to_utf16 on in8, hash return + whole output buffer */
static void t8(void)
{
        int r, i;
        memset(out16, 0xa5, sizeof(out16));
        r = utf8_to_utf16((char *)in8, out16);
        mix(r);
        for (i = 0; i < 12; i++) mix(out16[i]);
}

/* run utf16_to_utf8 on buf16 (in place), hash return + whole buffer */
static void t16(int len, int n)
{
        int r, i;
        unsigned char *p = (unsigned char *)buf16;
        r = utf16_to_utf8(buf16, len);
        mix(r);
        for (i = 0; i < n; i++) mix(p[i]);
}

static void report(char *name)
{
        printf("%s %04x%04x\n", name, h, h2);
        h = h2 = 0;
}

int main(void)
{
        unsigned int a, b, c, d, i, n;
        static unsigned char cs[] = {0x00, 0x01, 0x3f, 0x7f, 0x80, 0x81, 0x8f,
                                     0x90, 0x9f, 0xa0, 0xaf, 0xb0, 0xbf, 0xc0, 0xe0, 0xff};

        /* ---- utf8_to_utf16 ---- */
        /* single bytes, print every result */
        for (a = 0; a < 256; a++) {
                in8[0] = a; in8[1] = 0; in8[2] = 0x41; in8[3] = 0;
                t8();
                printf("%02x:%d/%04x%c", a, utf8_to_utf16((char *)in8, out16), out16[0],
                       (a & 7) == 7 ? '\n' : ' ');
        }
        report("u8-1");
        /* all 2-byte strings */
        for (a = 0; a < 256; a++) {
                for (b = 0; b < 256; b++) {
                        in8[0] = a; in8[1] = b; in8[2] = 0; in8[3] = 0x41; in8[4] = 0;
                        t8();
                }
                if ((a & 31) == 31) report("u8-2");
        }
        /* 3-byte: every lead x every 2nd byte x sampled 3rd bytes */
        for (a = 0x80; a < 256; a++) {
                for (b = 0; b < 256; b++)
                        for (c = 0; c < sizeof(cs); c++) {
                                in8[0] = a; in8[1] = b; in8[2] = cs[c]; in8[3] = 0;
                                t8();
                        }
                if ((a & 15) == 15) report("u8-3s");
        }
        /* 3-byte exhaustive valid-continuation space for E0..EF */
        for (a = 0xe0; a < 0xf0; a++) {
                for (b = 0x80; b < 0xc0; b++)
                        for (c = 0x80; c < 0xc0; c++) {
                                in8[0] = a; in8[1] = b; in8[2] = c; in8[3] = 0;
                                t8();
                        }
                report("u8-3x");
        }
        /* 4-byte: F0..FF x all continuations for 2nd, sampled 3rd/4th */
        for (a = 0xf0; a < 0x100; a++) {
                for (b = 0x70; b < 0xd0; b++)
                        for (c = 0; c < sizeof(cs); c += 3)
                                for (d = 0; d < sizeof(cs); d += 2) {
                                        in8[0] = a; in8[1] = b; in8[2] = cs[c];
                                        in8[3] = cs[d]; in8[4] = 0x5a; in8[5] = 0;
                                        t8();
                                }
                report("u8-4s");
        }
        /* 4-byte: F0..F4 exhaustive 2nd x 3rd, sampled 4th */
        for (a = 0xf0; a < 0xf5; a++) {
                for (b = 0x80; b < 0xc0; b++)
                        for (c = 0x80; c < 0xc0; c++) {
                                in8[0] = a; in8[1] = b; in8[2] = c;
                                in8[3] = 0x80 + ((b ^ c) & 0x3f); in8[4] = 0;
                                t8();
                        }
                report("u8-4x");
        }
        /* random multi-char strings, biased to valid-ish bytes */
        for (i = 0; i < 20000; i++) {
                n = lcg() % 12;
                for (a = 0; a < n; a++) {
                        b = lcg() >> 8;
                        switch (b & 7) {
                        case 0: case 1: b = 0x80 | (b & 0x3f); break;
                        case 2: b = 0xc0 | ((b >> 3) & 0x1f); break;
                        case 3: b = 0xe0 | ((b >> 3) & 0x0f); break;
                        case 4: b = 0xf0 | ((b >> 3) & 0x07); break;
                        case 5: b = 0x20 + (b & 0x3f); break;
                        default: break;
                        }
                        in8[a] = b;
                }
                in8[n] = 0;
                t8();
        }
        report("u8-rnd");
        /* explicit valid multi-char strings */
        {
                static char *s[] = { "", "A", "hello", "\xc3\xa5\xc3\xa4\xc3\xb6",
                        "\xe2\x82\xac 5", "\xf0\x9f\x98\x80x\xf4\x8f\xbf\xbf",
                        "\xef\xbf\xbd\xed\x9f\xbf\xee\x80\x80", "\xf0\x90\x80\x80" };
                for (i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
                        strcpy((char *)in8, s[i]);
                        memset(out16, 0xa5, sizeof(out16));
                        printf("s%d:%d", i, utf8_to_utf16((char *)in8, out16));
                        for (a = 0; a < 8; a++) printf(" %04x", out16[a]);
                        printf("\n");
                }
        }

        /* ---- utf16_to_utf8 ---- */
        /* all single code units, len 1 and len 2 (followed by DC00) */
        for (a = 0; ; a++) {
                for (b = 0; b < 48; b++) buf16[b] = 0x1111 * (b & 15);
                buf16[0] = a; buf16[1] = 0xdc37;
                t16(1, 8);
                for (b = 0; b < 48; b++) buf16[b] = 0x1111 * (b & 15);
                buf16[0] = a; buf16[1] = 0xdc37; buf16[2] = 0x20ac;
                t16(3, 12);
                if ((a & 0xfff) == 0xfff) report("u16-1");
                if (a == 0xffff) break;
        }
        /* all leads x sampled trails */
        {
                static uint16_t tr[] = {0x0000, 0x0041, 0xd7ff, 0xd800, 0xdbff, 0xdc00,
                                        0xdc01, 0xdd55, 0xdfff, 0xe000, 0xffff, 0x07ff};
                for (a = 0xd7f0; a < 0xe010; a++) {
                        for (c = 0; c < sizeof(tr) / 2; c++) {
                                for (b = 0; b < 48; b++) buf16[b] = 0x0101 * b;
                                buf16[0] = a; buf16[1] = tr[c]; buf16[2] = 0xd801;
                                t16(3, 12);
                                t16(2, 8);
                        }
                        if ((a & 0xff) == 0xff) report("u16-L");
                }
                /* all trails x sampled leads */
                for (b = 0xdb00; b < 0xe100; b++) {
                        for (c = 0; c < 6; c++) {
                                for (d = 0; d < 48; d++) buf16[d] = 0x0303 * d;
                                buf16[0] = 0xd800 + c * 0xcc; buf16[1] = b;
                                t16(2, 8);
                        }
                        if ((b & 0xff) == 0xff) report("u16-T");
                }
        }
        /* random in-place strings, lengths 0..20, plus odd/neg lengths */
        for (i = 0; i < 20000; i++) {
                n = lcg() % 21;
                for (a = 0; a < 48; a++) {
                        b = lcg();
                        switch (b & 7) {
                        case 0: b &= 0x7f; break;
                        case 1: b &= 0x7ff; break;
                        case 2: b = 0xd800 | (b & 0x3ff); break;
                        case 3: b = 0xdc00 | (b & 0x3ff); break;
                        default: break;
                        }
                        buf16[a] = b;
                }
                t16(n, 96);
        }
        report("u16-rnd");
        for (i = 0; i < 48; i++) buf16[i] = 0x41 + i;
        t16(0, 96); t16(-1, 96); t16(-32768, 96); t16(32767, 96);
        report("u16-edge");
        /* length that wraps end below start (C compares pointers unsigned):
         * use a buffer high in memory so start + 2*len wraps past 0xffff */
        {
                uint16_t *hb = (uint16_t *)0xc000;
                unsigned char *hp = (unsigned char *)hb;
                for (i = 0; i < 16; i++) hb[i] = 0x20ac + i;
                mix(utf16_to_utf8(hb, 0x2001));
                mix(utf16_to_utf8(hb, 12));
                for (i = 0; i < 32; i++) mix(hp[i]);
                report("u16-wrap");
        }
        return 0;
}
