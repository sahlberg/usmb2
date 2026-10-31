/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Differential test for the whole stack at once.
 *
 * test_ip.c, test_slip.c and test_tcp.c each mock the layer below the one
 * they are testing.  This one mocks nothing but the Interface 1 ROM: the
 * real tcp calls the real ip calls the real slip, and what comes out is
 * the SLIP byte stream that would go down the wire.  That seam -- what
 * ip_build_and_send() hands to send_packet(), and what recv_packet()
 * hands back to tcp_recv_timeout() -- is not covered by any of the
 * others.
 *
 * Built twice by "make test-z80", once from the .c files and once from
 * the .asm, and the two byte streams must be identical.
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

#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define END     0xc0
#define ESC     0xdb
#define ESC_END 0xdc
#define ESC_ESC 0xdd
#define ESC_ZER 0xde

#define BUF_SIZE 120

static uint8_t tcp_buf[BUF_SIZE];
static tcp_context_t tcp;

/* everything send_packet() has pushed out of the serial port */
static uint8_t txwire[600];
static int txlen;

/* everything rs232_get() will hand back, already SLIP encoded */
static uint8_t rxwire[1024];
static int rxlen;
static int rxpos;

int mock_init(void)
{
        return 0;
}

int mock_params(int param, int parity)
{
        return 0;
}

int mock_put(int c)
{
        if (txlen < (int)sizeof(txwire)) {
                txwire[txlen++] = (uint8_t)c;
        }
        return 0;
}

int mock_get(void)
{
        if (rxpos >= rxlen) {
                return -1;
        }
        return rxwire[rxpos++];
}

static void wire(uint8_t c)
{
        if (rxlen < (int)sizeof(rxwire)) {
                rxwire[rxlen++] = c;
        }
}

/* SLIP encode one packet into the receive stream, exactly as slip-tun
 * would put it on the wire. */
static void queue(uint8_t *p, int len)
{
        int i;

        wire(END);
        for (i = 0; i < len; i++) {
                switch (p[i]) {
                case END:
                        wire(ESC); wire(ESC_END); break;
                case ESC:
                        wire(ESC); wire(ESC_ESC); break;
                case 0x00:
                        wire(ESC); wire(ESC_ZER); break;
                default:
                        wire(p[i]);
                }
        }
        wire(END);
}

static void put32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)(v >> 24);
        p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);
        p[3] = (uint8_t)v;
}

/* Build a segment from the server and queue it. */
static void reply(uint32_t seq, uint32_t ack, uint8_t flags, char *data)
{
        static uint8_t p[120];
        int dlen = data ? (int)strlen(data) : 0;
        int i;

        memset(p, 0, sizeof(p));
        p[0] = 0x45;
        p[2] = (uint8_t)((40 + dlen) >> 8);
        p[3] = (uint8_t)(40 + dlen);
        p[8] = 64;
        p[9] = IP_TCP;
        p[12] = 192; p[13] = 0; p[14] = 2; p[15] = 1;
        p[16] = 192; p[17] = 0; p[18] = 2; p[19] = 2;
        p[20] = 0x1a; p[21] = 0x0b;     /* source port 6667 */
        p[22] = 0x80; p[23] = 0x00;     /* dest port 32768 */
        put32(&p[24], seq);
        put32(&p[28], ack);
        p[32] = 0x50;
        p[33] = flags;
        p[34] = 0x20;
        for (i = 0; i < dlen; i++) {
                p[40 + i] = (uint8_t)data[i];
        }
        queue(p, 40 + dlen);
}

static void showwire(void)
{
        int i;

        printf("  wire %d:", txlen);
        for (i = 0; i < txlen; i++) {
                printf(" %02x", (int)txwire[i]);
        }
        printf("\n");
        txlen = 0;
}

static void state(void)
{
        printf("  seq=%04x%04x ack=%04x%04x ths=%d\n",
               (int)(tcp.seq >> 16), (int)(tcp.seq & 0xffff),
               (int)(tcp.ack >> 16), (int)(tcp.ack & 0xffff),
               (int)tcp.ths);
}

static void reset(void)
{
        memset(&tcp, 0, sizeof(tcp));
        memset(tcp_buf, 0, sizeof(tcp_buf));
        tcp.ip.saddr = 0x020200c0UL;    /* 192.0.2.2 */
        tcp.ip.daddr = 0x010200c0UL;    /* 192.0.2.1 */
        tcp.ip.pkt_size = BUF_SIZE;
        tcp.ip.pkt = tcp_buf;
        tcp.src_port = 0x0080;          /* 32768, network order */
        tcp.dst_port = 0x0b1a;          /* 6667,  network order */
        txlen = 0;
        rxlen = 0;
        rxpos = 0;
}

int main(void)
{
        int rc;
        char *p;

        printf("== slip_init\n");
        printf("  rc=%d\n", slip_init(0x0b, 0x00));

        /* This is what tiny-irc.c does, in order. */
        printf("== connect\n");
        reset();
        reply(0x11223344UL, 2, TCP_SYN | TCP_ACK, NULL);
        rc = tcp_connect(&tcp);
        printf("  rc=%d\n", rc);
        state();
        showwire();

        printf("== register\n");
        strcpy((char *)tcp_tx_buffer(&tcp), "NICK zx\r\n");
        reply(0x11223345UL, 2 + 9, TCP_ACK, NULL);
        rc = tcp_send(&tcp, 9, NULL, 0);
        printf("  rc=%d\n", rc);
        state();
        showwire();

        printf("== open a window and receive a line\n");
        reply(0x11223345UL, 11, TCP_ACK | TCP_PSH, ":srv 001 zx :hi\r\n");
        rc = tcp_recv_timeout(&tcp, 40, 200);
        printf("  rc=%d\n", rc);
        state();
        if (rc > 0) {
                p = (char *)tcp_rx_buffer(&tcp);
                p[rc] = 0;
                printf("  got [%s]\n", p);
        }
        showwire();

        printf("== a second line, and a zero window probe first\n");
        reply(0x11223354UL, 11, TCP_ACK, NULL);
        reply(0x11223355UL, 11, TCP_ACK | TCP_PSH, "PING :x\r\n");
        rc = tcp_recv_timeout(&tcp, 40, 200);
        printf("  rc=%d\n", rc);
        state();
        if (rc > 0) {
                p = (char *)tcp_rx_buffer(&tcp);
                p[rc] = 0;
                printf("  got [%s]\n", p);
        }
        showwire();

        printf("== send a line with bytes SLIP has to escape\n");
        reset();
        tcp.seq = 100;
        tcp.ack = 200;
        tcp.ths = 20;
        p = (char *)tcp_tx_buffer(&tcp);
        p[0] = 0xc0; p[1] = 0xdb; p[2] = 0x00; p[3] = 'A';
        reply(200, 104, TCP_ACK, NULL);
        rc = tcp_send(&tcp, 4, NULL, 0);
        printf("  rc=%d\n", rc);
        state();
        showwire();

        /*
         * What actually happened on the wire on 2026-09-07: the server's
         * SYN-ACK advertised a zero window, so it followed up with a bare
         * window update that acknowledged nothing.  tcp_send() takes that
         * as its answer and returns, so tcp->seq never advances past the
         * data, and the next window we open carries a sequence number the
         * server has already passed.  RFC 793 makes that segment
         * unacceptable, so the window update is dropped and the peer
         * probes a closed window for ever.
         *
         * tcp_send() now notices that tcp->seq did not reach oseq + len
         * and retransmits, so what this checks is that both
         * implementations send the data twice and end up with tcp->seq
         * past the data.  Note the retransmission is only correct because
         * the segment that stole the ACK was a bare 40 byte ACK, which
         * recv_packet() writes over pkt[0..39] - the payload a data ==
         * NULL caller left at pkt[40] is still there.
         */
        printf("== a bare ack steals the ack tcp_send is waiting for\n");
        reset();
        reply(0x11223344UL, 2, TCP_SYN | TCP_ACK, NULL);
        rc = tcp_connect(&tcp);
        printf("  connect rc=%d\n", rc);
        state();
        txlen = 0;
        strcpy((char *)tcp_tx_buffer(&tcp), "NICK zx\r\n");
        reply(0x11223345UL, 2, TCP_ACK, NULL);          /* acks nothing */
        reply(0x11223345UL, 11, TCP_ACK, NULL);         /* the real ack */
        rc = tcp_send(&tcp, 9, NULL, 0);
        printf("  send rc=%d\n", rc);
        state();
        showwire();

        printf("== ...and gives up if the ack never covers the data\n");
        reset();
        reply(0x11223344UL, 2, TCP_SYN | TCP_ACK, NULL);
        tcp_connect(&tcp);
        txlen = 0;
        strcpy((char *)tcp_tx_buffer(&tcp), "NICK zx\r\n");
        for (rc = 0; rc < 8; rc++) {
                reply(0x11223345UL, 2, TCP_ACK, NULL);
        }
        rc = tcp_send(&tcp, 9, NULL, 0);
        printf("  send rc=%d\n", rc);
        state();
        printf("  wire %d bytes\n", txlen);
        txlen = 0;

        printf("== a tcp_tx_buffer() payload is not retransmitted\n");
        reset();
        reply(0x11223344UL, 2, TCP_SYN | TCP_ACK, NULL);
        tcp_connect(&tcp);
        txlen = 0;
        strcpy((char *)tcp_tx_buffer(&tcp), "NICK zx\r\n");
        reply(0x11223345UL, 2, TCP_ACK, NULL);          /* acks nothing */
        rc = tcp_send(&tcp, 9, NULL, 0);                /* data == NULL */
        printf("  send rc=%d wire %d bytes\n", rc, txlen);
        state();
        txlen = 0;

        printf("== poll with nothing there\n");
        reset();
        tcp.seq = 100;
        tcp.ack = 200;
        tcp.ths = 20;
        rc = tcp_recv_timeout(&tcp, 40, 20);
        printf("  rc=%d\n", rc);
        showwire();

        printf("== server resets us\n");
        reset();
        tcp.seq = 100;
        tcp.ack = 200;
        tcp.ths = 20;
        reply(200, 100, TCP_RST | TCP_ACK, NULL);
        rc = tcp_recv_timeout(&tcp, 0, 200);
        printf("  rc=%d\n", rc);
        showwire();

        printf("done\n");
        return 0;
}
