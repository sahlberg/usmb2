/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Differential test for the TCP layer.
 *
 * This is built twice by "make test": once against tcp.c and once against
 * the hand written tcp-z80.asm, and the two outputs must be identical.
 * It is a Z80 program -- it links the real ip.c and the real tcp code and
 * runs under z88dk-ticks -- so it is testing the code that goes on the
 * Spectrum, not a host recompile of it.
 *
 * Only slip.c is replaced: send_packet() dumps the packet and
 * recv_packet() replays a scripted one.
 *
 * Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
 * MIT, see tcp.c.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ip.h"
#include "tcp.h"
#include "slip.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define MAXQ 8
#define QSZ  120

static uint8_t inq[MAXQ][QSZ];
static int inqlen[MAXQ];
static int nin;
static int inpos;

static int txcount;
static int quiet;

static uint8_t pktbuf[QSZ];
static tcp_context_t tcp;

/* ------------------------------------------------------------------ */
/* slip.c replacement                                                  */

void send_packet(uint8_t *p, int len)
{
        int i;

        txcount++;
        if (quiet) {
                return;
        }
        printf("TX %d:", len);
        for (i = 0; i < len; i++) {
                printf(" %02x", (int)p[i]);
        }
        printf("\n");
}

int recv_packet(uint8_t *p, int len, int to)
{
        int n;

        if (inpos >= nin) {
                return -EAGAIN;
        }
        n = inqlen[inpos];
        if (n < 0) {
                inpos++;
                return -EAGAIN;
        }
        if (n > len) {
                n = len;
        }
        memcpy(p, inq[inpos], n);
        inpos++;
        return n;
}

/* ------------------------------------------------------------------ */

static void put32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)(v >> 24);
        p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);
        p[3] = (uint8_t)v;
}

/* Queue an incoming segment.  sport/dport are as they appear on the wire. */
static void queue(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                  uint8_t flags, int thl, int dlen, int ver, int proto)
{
        uint8_t *p = inq[nin];
        int i;

        memset(p, 0, QSZ);
        p[0] = (uint8_t)ver;
        p[9] = (uint8_t)proto;
        p[20] = (uint8_t)(sport >> 8);
        p[21] = (uint8_t)sport;
        p[22] = (uint8_t)(dport >> 8);
        p[23] = (uint8_t)dport;
        put32(&p[24], seq);
        put32(&p[28], ack);
        p[32] = (uint8_t)((thl / 4) << 4);
        p[33] = flags;
        p[34] = 0x20;
        for (i = 0; i < dlen; i++) {
                p[20 + thl + i] = (uint8_t)('A' + i);
        }
        inqlen[nin++] = 20 + thl + dlen;
}

static void queue_timeout(void)
{
        inqlen[nin++] = -1;
}

static void reset(uint32_t seq, uint32_t ack, uint8_t ths)
{
        memset(&tcp, 0, sizeof(tcp));
        memset(pktbuf, 0, sizeof(pktbuf));
        tcp.ip.saddr = 0x0202000aUL;    /* whatever, it is only copied */
        tcp.ip.daddr = 0x0102000aUL;
        tcp.ip.pkt_size = QSZ;
        tcp.ip.id = 0x1234;
        tcp.ip.pkt = pktbuf;
        tcp.dst_port = 0x1a00;          /* network order: port 26 */
        tcp.src_port = 0x3930;          /* network order: port 12345 */
        tcp.seq = seq;
        tcp.ack = ack;
        tcp.ths = ths;
        nin = 0;
        inpos = 0;
        txcount = 0;
        quiet = 0;
}

static void state(void)
{
        printf("  seq=%04x%04x ack=%04x%04x ths=%d sport=%04x tx=%d\n",
               (int)(tcp.seq >> 16), (int)(tcp.seq & 0xffff),
               (int)(tcp.ack >> 16), (int)(tcp.ack & 0xffff),
               (int)tcp.ths, (int)tcp.src_port, txcount);
}

int main(void)
{
        int rc;

        printf("== connect ok\n");
        reset(0, 0, 0);
        queue(26, 12345, 0x11223344UL, 2, TCP_SYN | TCP_ACK, 20, 0, 0x45, IP_TCP);
        rc = tcp_connect(&tcp);
        printf("  rc=%d\n", rc);
        state();

        printf("== connect, wrong ack in synack\n");
        reset(0, 0, 0);
        queue(26, 12345, 0x11223344UL, 99, TCP_SYN | TCP_ACK, 20, 0, 0x45, IP_TCP);
        quiet = 1;
        rc = tcp_connect(&tcp);
        printf("  rc=%d tx=%d\n", rc, txcount);

        printf("== connect, all attempts time out\n");
        reset(0, 0, 0);
        quiet = 1;
        rc = tcp_connect(&tcp);
        printf("  rc=%d tx=%d\n", rc, txcount);

        printf("== connect, rst\n");
        reset(0, 0, 0);
        queue(26, 12345, 5, 2, TCP_RST | TCP_ACK, 20, 0, 0x45, IP_TCP);
        quiet = 1;
        rc = tcp_connect(&tcp);
        printf("  rc=%d tx=%d\n", rc, txcount);

        printf("== recv data\n");
        reset(100, 200, 20);
        queue(26, 12345, 200, 100, TCP_ACK | TCP_PSH, 20, 10, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== recv data, larger header\n");
        reset(100, 200, 20);
        queue(26, 12345, 200, 150, TCP_ACK | TCP_PSH, 24, 10, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== zero window probe then timeout\n");
        reset(100, 200, 20);
        queue(26, 12345, 199, 100, TCP_ACK, 20, 0, 0x45, IP_TCP);
        queue_timeout();
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== zero window probe then data\n");
        reset(100, 200, 20);
        queue(26, 12345, 199, 100, TCP_ACK, 20, 0, 0x45, IP_TCP);
        queue(26, 12345, 200, 100, TCP_ACK | TCP_PSH, 20, 4, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== retransmission of already acked data\n");
        reset(100, 210, 20);
        queue(26, 12345, 200, 100, TCP_ACK | TCP_PSH, 20, 10, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== data after a missed segment\n");
        reset(100, 200, 20);
        queue(26, 12345, 250, 100, TCP_ACK | TCP_PSH, 20, 10, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== pure ack advances seq\n");
        reset(100, 200, 20);
        queue(26, 12345, 100, 175, TCP_ACK, 20, 0, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== rst on established\n");
        reset(100, 200, 20);
        queue(26, 12345, 200, 100, TCP_RST | TCP_ACK, 20, 0, 0x45, IP_TCP);
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== bad packets\n");
        reset(100, 200, 20);
        queue(26, 12345, 200, 100, TCP_ACK, 20, 0, 0x46, IP_TCP);
        queue(26, 12345, 200, 100, TCP_ACK, 20, 0, 0x45, IP_UDP);
        queue(27, 12345, 200, 100, TCP_ACK, 20, 0, 0x45, IP_TCP);
        queue(26, 12346, 200, 100, TCP_ACK, 20, 0, 0x45, IP_TCP);
        queue_timeout();
        for (rc = 0; rc < 5; rc++) {
                printf("  rc=%d\n", tcp_recv_timeout(&tcp, 0, 5));
        }
        state();

        printf("== short packet\n");
        reset(100, 200, 20);
        queue(26, 12345, 200, 100, TCP_ACK, 20, 0, 0x45, IP_TCP);
        inqlen[0] = 39;
        rc = tcp_recv_timeout(&tcp, 0, 5);
        printf("  rc=%d\n", rc);

        printf("== open window\n");
        reset(100, 200, 20);
        queue_timeout();
        rc = tcp_recv_timeout(&tcp, 40, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== open window, clamped\n");
        reset(100, 200, 20);
        queue_timeout();
        rc = tcp_recv_timeout(&tcp, 500, 5);
        printf("  rc=%d\n", rc);
        state();

        printf("== send data, acked\n");
        reset(1000, 2000, 20);
        queue(26, 12345, 2000, 1005, TCP_ACK, 20, 0, 0x45, IP_TCP);
        rc = tcp_send(&tcp, 5, (uint8_t *)"hello", 0);
        printf("  rc=%d\n", rc);
        state();

        printf("== send data from the tx buffer\n");
        reset(1000, 2000, 20);
        memcpy(tcp_tx_buffer(&tcp), "abcd", 4);
        queue(26, 12345, 2000, 1004, TCP_ACK, 20, 0, 0x45, IP_TCP);
        rc = tcp_send(&tcp, 4, NULL, 0);
        printf("  rc=%d\n", rc);
        state();

        printf("== send data, never acked\n");
        reset(1000, 2000, 20);
        quiet = 1;
        rc = tcp_send(&tcp, 3, (uint8_t *)"xyz", 0);
        printf("  rc=%d tx=%d\n", rc, txcount);

        printf("== send bare ack does not wait\n");
        reset(1000, 2000, 20);
        rc = tcp_send(&tcp, 0, NULL, 64);
        printf("  rc=%d\n", rc);
        state();

        printf("== buffers\n");
        reset(1000, 2000, 24);
        /* sccz80 warns on any pointer subtraction, so do it in ints. */
        printf("  rx=%d tx=%d\n",
               (int)tcp_rx_buffer(&tcp) - (int)pktbuf,
               (int)tcp_tx_buffer(&tcp) - (int)pktbuf);

        printf("done\n");
        return 0;
}
