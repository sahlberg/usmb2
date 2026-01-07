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

#include <stdio.h>
#include <string.h>
#include "ip.h"
#include "tcp.h"
#include "slip.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct tcp_ctx {
        uint32_t src;
        uint16_t src_port;
        uint32_t dst;
        uint16_t dst_port;
        uint32_t seq;
        uint32_t ack;
        uint8_t ths;  /* most recent data segment tcp header size */
};

struct tcp_ctx tctx;

#define htons(x) ((x<<8)|(x>>8))
static uint32_t htonl(uint32_t val)
{
        uint32_t tmp = 0;
        uint8_t *ptr = (uint8_t *)&val;

        tmp  = *ptr++;
        tmp <<= 8;
        tmp |= *ptr++;
        tmp <<= 8;
        tmp |= *ptr++;
        tmp <<= 8;
        tmp |= *ptr++;

        return tmp;
}

int tcp_send(uint8_t *data, int len)
{
        uint8_t *ptr = ip_buffer(20);
        uint16_t cs;
        uint32_t u32;

        memset(ptr, 0, 20);
        if (data) {
                memcpy(ptr + 20, data, len);
        }
        cs = htons(tctx.src_port);
        memcpy(&ptr[0], &cs, 2);
        cs = htons(tctx.dst_port);
        memcpy(&ptr[2], &cs, 2);
        u32 = htonl(tctx.seq);
        memcpy(&ptr[4], &u32, 4);
        u32 = htonl(tctx.ack);
        memcpy(&ptr[8], &u32, 4);
        ptr[12] = 0x50;
        if (tctx.seq == 1) {
                ptr[13] = TCP_SYN;
        } else {
                if (len) {
                        ptr[13] = TCP_ACK | TCP_PSH;
                } else {
                        ptr[13] = TCP_ACK;
                }
        }
        ptr[14] = 4; /* window */

        /* pseudo header, will be overwritten by ip_build_and_send() */
        memcpy(ptr - 12, &tctx.src, 4);
        memcpy(ptr -  8, &tctx.dst, 4);
        ptr[-4] = 0;
        ptr[-3] = IP_TCP;
        cs = htons(20 + len);
        memcpy(ptr - 2, &cs, 2);
        
        cs = csum((uint16_t *)&ptr[-12], 12 + 20 + len);
        memcpy(&ptr[16], &cs, 2); 
        
        ip_build_and_send(tctx.src, tctx.dst, 20 + 20 + len, IP_TCP);
        
        return 0;
}

int tcp_recv(void)
{
        uint8_t *ptr = ip_buffer(20);
        uint32_t seq, ack;
        int len;
        int i;
        
        ptr = ip_buffer(0);
        len = recv_packet(ptr, IP_MAX_SIZE);

        /* sanity checks */
        if (len < 20 + 20) {
                return 0;
        }
        if (ptr[0] != 0x45) {
                return 0;
        }
        if (ptr[9] != IP_TCP) {
                return 0;
        }
        if (tctx.dst_port >> 8 != ptr[20 + 0] ||
            (tctx.dst_port & 0xff) != ptr[20 + 1]) {
                return 0;
        }
        if (tctx.src_port >> 8 != ptr[20 + 2] ||
            (tctx.src_port & 0xff) != ptr[20 + 3]) {
                return 0;
        }

        tctx.ths = ptr[20 + 12] >> 2;

        memcpy(&ack, &ptr[20 + 8], 4);
        ack = htonl(ack);
        if ((ptr[20 + 13] & TCP_ACK) && (tctx.seq < ack)) {
                tctx.seq = ack;
        }

        /* Track seq numbers for incoming packets and ignore retranmissions.
         * We are VERY slow so there will be many retransmissions just because we might
         * not be able to even ACK a segment in time
         */
        /* Send an immediate ACK to segments containing data */
        if (len > 20 + tctx.ths) {
                memcpy(&seq, &ptr[20 + 4], 4);
                seq = htonl(seq);

                /* Sequence number has reversed so this is likely a retransmission */
                if (seq < tctx.ack) {
                        return 0;
                }

                tctx.ack = seq;
                if (len > 20 + 20) {
                        tctx.ack += len - 20 - tctx.ths;
                }
                tcp_send(NULL, 0);
        }

        return len - 20 - tctx.ths;
}

void get_r_register(uint16_t *p) {
        (void) p;
#asm
        ld iy,$2
        add iy,sp ;Bypass the return address of the function
        ld hl,(iy)
        ld a,r
        ld (hl),a
#endasm
}

int tcp_connect(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
        uint8_t *ptr = ip_buffer(0);
        int rc, num_tries = 0;

 again:
        if (num_tries++ > 5) {
                return -1;
        }
        tctx.src = src;
        tctx.src_port = src_port;
        tctx.dst = dst;
        tctx.dst_port = dst_port;
        tctx.seq = 1;
        tctx.ack = 0;

        rc = tcp_send(NULL, 0);
        rc = tcp_recv();
        /* If we don't get a SYN+ACK then something went wrong.
         * Pick a different port and try again.
         */
        if ((ptr[9] != IP_TCP) ||
            ((ptr[20 + 13] & (TCP_SYN|TCP_ACK)) != (TCP_SYN|TCP_ACK))) {
                uint16_t t;
                src_port += *(uint16_t *)&ptr[20 + 16]; /* use checksum as random increment */
                /* use the r register for even more randomness */
                get_r_register(&t);
                src_port += t;
                goto again;
        }
        tctx.ack = htonl(*(uint32_t *)&ptr[20 + 4]) + 1;
        tctx.seq = 2;
        /* Send an ACK and complete the TCP session establish */
        tcp_send(NULL, 0);
        return 0;
}

uint8_t *tcp_buffer(void)
{
        uint8_t *pkt = ip_buffer(0);
        
        return &pkt[20 + tctx.ths];
}

