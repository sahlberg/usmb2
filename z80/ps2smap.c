/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the “Software”), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*
 * The link layer of the tiny stack on the PS2 IOP, on Neutrino's smap.irx and
 * ministack.irx, in place of SLIP: the stack's IP packets go out as
 * ethernet frames through smap_transmit(), and ministack hands us the TCP
 * packets that come in.
 *
 * ministack has no routing, so we pick the gateway for servers outside our
 * subnet ourselves, and ask ministack's ARP for its MAC address.
 */
#include <errno.h>
#include <stdint.h>
#include <sysclib.h>
#include <thbase.h>
#include <thevent.h>

#include "smap.h"
#include "mstack.h"
#include "slip.h"

/* recv_packet() waits for "to" ticks of 1/RS232_TPS seconds, as for SLIP */
#ifndef RS232_TPS
#define RS232_TPS 100
#endif

#define ETH_HDR    14
#define FRAME_SIZE 1516 /* a 1514 byte frame, rounded up to 4 */

/*
 * Frames are copied out of the SMAP FIFO in the receive callback, which runs
 * in the smap driver's thread, as the FIFO moves on when it returns. Two, as
 * a reply may be two segments that arrive back to back.
 */
#define RX_SLOTS 4
static struct {
        uint16_t len; /* of the IP packet */
        uint8_t frame[FRAME_SIZE] __attribute__((aligned(4)));
} rx[RX_SLOTS];
/*
 * Indexes count modulo 2 * RX_SLOTS, so that all slots can be in use:
 * empty when they are equal, full when they are RX_SLOTS apart.
 */
static volatile int rx_head, rx_tail;
#define RX_NEXT(i) (((i) + 1) % (2 * RX_SLOTS))
#define RX_SLOT(i) (rx[(i) % RX_SLOTS])

/* smap_transmit() copies whole words, so the frame has to be in one piece */
static uint8_t tx[FRAME_SIZE] __attribute__((aligned(4)));

#define EF_RX      1
#define EF_TIMEOUT 2
static int evf = -1;

static uint32_t my_ip, my_mask, my_gw; /* host order */
static const uint16_t *my_port;        /* network order */

static int rx_tcp(const uint8_t *hdr, uint16_t hdr_len)
{
        int ihl;
        uint16_t len;

        ihl = (hdr[ETH_HDR] & 0x0f) * 4;
        if (hdr_len < ETH_HDR + ihl + 4) {
                return -1;
        }
        /* Only the destination port: the stack checks the rest */
        if (memcmp(&hdr[ETH_HDR + ihl + 2], my_port, 2)) {
                return -1;
        }
        len = (hdr[ETH_HDR + 2] << 8) | hdr[ETH_HDR + 3];
        if (len > FRAME_SIZE - ETH_HDR ||
            (rx_head - rx_tail + 2 * RX_SLOTS) % (2 * RX_SLOTS) == RX_SLOTS) {
                return -1; /* full: TCP resends it */
        }
        smap_fifo_read(0, RX_SLOT(rx_head).frame, (ETH_HDR + len + 3) & ~3);
        RX_SLOT(rx_head).len = len;
        rx_head = RX_NEXT(rx_head);
        SetEventFlag(evf, EF_RX);
        /* -1 lets the driver skip to the end of the frame */
        return -1;
}

int ps2smap_init(uint32_t ip, uint32_t mask, uint32_t gw)
{
        iop_event_t ev = { 0, 0, 0 };

        my_ip = ip;
        my_mask = mask;
        my_gw = gw;
        if (evf < 0) {
                evf = CreateEventFlag(&ev);
                if (evf < 0) {
                        return -1;
                }
        }
        ip_set_tcp_handler(rx_tcp);
        return 0;
}

void ps2smap_set_port(const uint16_t *port)
{
        my_port = port;
        rx_head = rx_tail = 0;
}

void send_packet(uint8_t *p, int len)
{
        uint32_t dst;

        if (len > FRAME_SIZE - ETH_HDR) {
                return;
        }
        dst = (p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19];
        if ((dst ^ my_ip) & my_mask) {
                dst = my_gw;
        }
        if (arp_resolve(dst, tx)) {
                return;
        }
        SMAPGetMACAddress(&tx[6]);
        tx[12] = 0x08;
        tx[13] = 0x00;
        memcpy(&tx[ETH_HDR], p, len);
        smap_transmit(tx, ETH_HDR + len, NULL, 0);
}

static unsigned int timeout_cb(void *arg)
{
        iSetEventFlag(evf, EF_TIMEOUT);
        return 0;
}

int recv_packet(uint8_t *p, int len, int to)
{
        iop_sys_clock_t clock;
        u32 bits;

        if (rx_tail == rx_head) {
                if (to <= 0) {
                        return -EAGAIN;
                }
                /* The queue is the truth, the flag only wakes us up */
                ClearEventFlag(evf, 0);
                if (rx_tail == rx_head) {
                        USec2SysClock(to * (1000000 / RS232_TPS), &clock);
                        SetAlarm(&clock, timeout_cb, NULL);
                        WaitEventFlag(evf, EF_RX | EF_TIMEOUT, WEF_OR, &bits);
                        CancelAlarm(timeout_cb, NULL);
                }
                if (rx_tail == rx_head) {
                        return -EAGAIN;
                }
        }
        if (len > RX_SLOT(rx_tail).len) {
                len = RX_SLOT(rx_tail).len;
        }
        memcpy(p, &RX_SLOT(rx_tail).frame[ETH_HDR], len);
        rx_tail = RX_NEXT(rx_tail);
        return len;
}
