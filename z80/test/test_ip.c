/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Differential test for the IP layer.  Built twice by "make test-tcp",
 * once against ip.c and once against ip-z80.asm, and run under
 * z88dk-ticks; the two outputs must be identical.  See test_tcp.c.
 *
 * Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
 * MIT, see ip.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ip.h"
#include "slip.h"

static uint8_t buf[80];
static uint8_t pkt[80];
static ip_context_t ip;

void send_packet(uint8_t *p, int len)
{
        int i;

        printf("TX %d:", len);
        for (i = 0; i < len; i++) {
                printf(" %02x", (int)p[i]);
        }
        printf("\n");
}

static void sum(int n)
{
        printf("  csum(%d) = %04x\n", n, (int)csum((uint16_t *)buf, n));
}

/* Fill buf[] with a repeating pattern and checksum every length up to n. */
static void sweep(uint8_t a, uint8_t b, int n)
{
        int i;

        for (i = 0; i < (int)sizeof(buf); i++) {
                buf[i] = (i & 1) ? b : a;
        }
        for (i = 0; i <= n; i++) {
                sum(i);
        }
}

int main(void)
{
        int i;

        printf("== csum of zeros\n");
        memset(buf, 0, sizeof(buf));
        sum(0);
        sum(1);
        sum(2);
        sum(20);

        /* every word 0xffff: a carry out of every single addition, and a
         * one's complement sum that stays at 0xffff rather than dropping
         * to zero */
        printf("== csum of ones\n");
        sweep(0xff, 0xff, 24);

        printf("== csum, carry every other word\n");
        sweep(0x00, 0x80, 12);

        printf("== csum of a counting pattern\n");
        for (i = 0; i < (int)sizeof(buf); i++) {
                buf[i] = (uint8_t)(i * 7 + 1);
        }
        for (i = 0; i <= 41; i++) {
                sum(i);
        }

        printf("== csum of a real looking header\n");
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x45; buf[3] = 0x28; buf[4] = 0x34; buf[5] = 0x12;
        buf[8] = 64;   buf[9] = 6;
        buf[12] = 10;  buf[14] = 2; buf[15] = 2;
        buf[16] = 10;  buf[18] = 2; buf[19] = 1;
        sum(20);

        printf("== ip_build_and_send\n");
        memset(&ip, 0, sizeof(ip));
        memset(pkt, 0xaa, sizeof(pkt));
        ip.saddr = 0x0202000aUL;
        ip.daddr = 0x0102000aUL;
        ip.pkt_size = sizeof(pkt);
        ip.id = 0x1234;
        ip.pkt = pkt;
        ip_build_and_send(&ip, 20, IP_ICMP);
        printf("  id=%04x\n", (int)ip.id);
        ip_build_and_send(&ip, 40, IP_TCP);
        printf("  id=%04x\n", (int)ip.id);

        printf("== id carry across the byte boundary\n");
        ip.id = 0x00ff;
        ip_build_and_send(&ip, 21, IP_UDP);
        printf("  id=%04x\n", (int)ip.id);
        ip.id = 0xffff;
        ip_build_and_send(&ip, 20, IP_ICMP);
        printf("  id=%04x\n", (int)ip.id);

        printf("== payload past the header is left alone\n");
        memset(pkt, 0x5a, sizeof(pkt));
        ip.id = 1;
        ip_build_and_send(&ip, 26, IP_TCP);

        printf("== ip_buffer\n");
        printf("  %d %d %d\n",
               (int)ip_buffer(&ip, 0) - (int)pkt,
               (int)ip_buffer(&ip, 20) - (int)pkt,
               (int)ip_buffer(&ip, -4) - (int)pkt);

        printf("done\n");
        return 0;
}
