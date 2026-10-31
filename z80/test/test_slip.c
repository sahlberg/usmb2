/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Differential test for the SLIP layer.  Built twice by "make test-tcp",
 * once against slip.c and once against slip-z80.asm, and run under
 * z88dk-ticks; the two outputs must be identical.
 *
 * test/stub232.asm supplies the four rs232 entry points and forwards them
 * to the mock_*() functions here.
 *
 * Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
 * MIT, see slip.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "slip.h"

#define END     0xc0
#define ESC     0xdb
#define ESC_END 0xdc
#define ESC_ESC 0xdd
#define ESC_ZER 0xde

static uint8_t txbuf[128];
static int txlen;

static uint8_t rxbuf[128];
static int rxlen;
static int rxpos;
static int getcalls;

static uint8_t pkt[64];

int mock_init_rc = 0;
int mock_params_rc = 0;
int mock_params_param = -1;
int mock_params_parity = -1;

int mock_init(void)
{
        return mock_init_rc;
}

int mock_params(int param, int parity)
{
        mock_params_param = param;
        mock_params_parity = parity;
        return mock_params_rc;
}

int mock_put(int c)
{
        if (txlen < (int)sizeof(txbuf)) {
                txbuf[txlen++] = (uint8_t)c;
        }
        return 0;
}

/* Negative means "timed out", which is what an idle port does. */
int mock_get(void)
{
        getcalls++;
        if (rxpos >= rxlen) {
                return -1;
        }
        return rxbuf[rxpos++];
}

static void showtx(void)
{
        int i;

        printf("  put %d:", txlen);
        for (i = 0; i < txlen; i++) {
                printf(" %02x", (int)txbuf[i]);
        }
        printf("\n");
        txlen = 0;
}

static void feed(uint8_t *b, int n)
{
        memcpy(rxbuf, b, n);
        rxlen = n;
        rxpos = 0;
        getcalls = 0;
}

static void recv(int len, int to)
{
        int rc, i;

        memset(pkt, 0x5a, sizeof(pkt));
        rc = recv_packet(pkt, len, to);
        printf("  rc=%d gets=%d:", rc, getcalls);
        for (i = 0; i < rc && i < 40; i++) {
                printf(" %02x", (int)pkt[i]);
        }
        printf("\n");
}

int main(void)
{
        static uint8_t d1[] = { END, 1, 2, 3, END };
        static uint8_t d2[] = { 9, 9, END, 0x41, ESC, ESC_END, ESC, ESC_ESC,
                                ESC, ESC_ZER, 0x42, END };
        static uint8_t d3[] = { END, END, END, 7, 8, END };
        static uint8_t d4[] = { END, 1, 2, 3, 4, 5, 6, 7, 8, END };
        static uint8_t d5[] = { END, ESC, 0x30, 0x31, END };
        static uint8_t d6[] = { 1, 2, 3, 4 };
        static uint8_t d7[] = { 0, 0, 0, END, 0x77, END };
        static uint8_t p1[] = { 1, 2, 3 };
        static uint8_t p2[] = { END, ESC, 0x00, 0x41, END };
        static uint8_t p3[] = { 0xff };

        printf("== slip_init ok\n");
        mock_init_rc = 0; mock_params_rc = 0;
        printf("  rc=%d param=%d parity=%d\n", slip_init(0x0a, 0x00),
               mock_params_param, mock_params_parity);

        printf("== slip_init, other params\n");
        printf("  rc=%d param=%d parity=%d\n", slip_init(0x1234, 0x5678),
               mock_params_param, mock_params_parity);

        printf("== slip_init, init fails\n");
        mock_init_rc = 1;
        printf("  rc=%d\n", slip_init(0x0a, 0));
        mock_init_rc = 0;

        printf("== slip_init, params fail\n");
        mock_params_rc = 2;
        printf("  rc=%d\n", slip_init(0x0a, 0));
        mock_params_rc = 0;

        printf("== send_packet, plain\n");
        txlen = 0;
        send_packet(p1, 3);
        showtx();

        printf("== send_packet, every escape\n");
        send_packet(p2, 5);
        showtx();

        printf("== send_packet, empty\n");
        send_packet(p1, 0);
        showtx();

        printf("== send_packet, one byte\n");
        send_packet(p3, 1);
        showtx();

        printf("== recv_packet, plain\n");
        feed(d1, sizeof(d1));
        recv(sizeof(pkt), 10);

        printf("== recv_packet, leading junk and escapes\n");
        feed(d2, sizeof(d2));
        recv(sizeof(pkt), 10);

        printf("== recv_packet, empty frames are skipped\n");
        feed(d3, sizeof(d3));
        recv(sizeof(pkt), 10);

        printf("== recv_packet, does not overrun the buffer\n");
        feed(d4, sizeof(d4));
        recv(4, 10);

        printf("== recv_packet, unknown escape is dropped\n");
        feed(d5, sizeof(d5));
        recv(sizeof(pkt), 10);

        printf("== recv_packet, no END at all\n");
        feed(d6, sizeof(d6));
        recv(sizeof(pkt), 10);

        printf("== recv_packet, timeout is tight\n");
        feed(d7, sizeof(d7));
        recv(sizeof(pkt), 4);

        printf("== recv_packet, timeout is one short\n");
        feed(d7, sizeof(d7));
        recv(sizeof(pkt), 3);

        printf("== recv_packet, to = 1\n");
        feed(d1, sizeof(d1));
        recv(sizeof(pkt), 1);

        /* Note there is no len == 0 case: slip.c never returns from one,
         * because "received" can then never become non-zero and the END
         * case just keeps looping.  That is the reference behaviour, so
         * there is nothing here for the assembler version to differ on. */
        printf("== recv_packet, buffer holds one byte\n");
        feed(d1, sizeof(d1));
        recv(1, 10);

        printf("done\n");
        return 0;
}
