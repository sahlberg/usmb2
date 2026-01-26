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

#include <errno.h>    /* for EAGAIN */
#include <stdio.h>
#include <string.h>
#include <net/hton.h>
#include "ip.h"
#include "tcp.h"
#include "slip.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

typedef struct tcp_context {
        ip_context_t ip;
        /* Port numbers in network byte order, not host order, so we can check the src/dst
         * ports of received packets by a simple memcmp().
         * The ordering of dst_port/src_port is important.
         */
        uint16_t dst_port;
        uint16_t src_port;
        uint32_t seq;
        uint32_t ack;
        uint8_t ths;  /* most recent data segment tcp header size */
        int rx_data_len;
} tcp_context_t;

tcp_context_t tcp_ctx;

/*
 * tcp_send.
 * Send data and wait for it to be ACKed. Retransmit up to 5 times
 * if we do not receive a TCP ACK.
 *
 * If tcp_ctx.seq == 1 this means to use the SYN handshake
 * to esstablish a new connection. len must be 0 for this case.
 *
 * Otherwise data/len is the data to transfer on the connection.
 * Data can be NULL if the application has already written it
 * to the network buffer. Otherwise it will be memcpy()ied from
 * the argument.
 *
 * If we are sending a request, the ACK we wait for might be
 * piggy-backed on a data-segment carrying the reply.
 * In that case remember this in tcp_ctx.rx_data_len so that we can short-circuit
 * and just return the data immediately when the application later calls
 * tcp_recv().
 */
int tcp_send(uint8_t *data, int len)
{
        uint8_t *ptr = ip_buffer(&tcp_ctx.ip, 20);
        uint16_t cs;
        uint32_t u32, oseq;
        int rc, retries = 0;

        oseq = tcp_ctx.seq;
 again:
        memset(ptr, 0, 20);
        if (data) {
                memcpy(ptr + 20, data, len);
        }
        cs = tcp_ctx.src_port;
        memcpy(&ptr[0], &cs, 2);
        cs = tcp_ctx.dst_port;
        memcpy(&ptr[2], &cs, 2);
        u32 = htonl(tcp_ctx.seq);
        memcpy(&ptr[4], &u32, 4);
        u32 = htonl(tcp_ctx.ack);
        memcpy(&ptr[8], &u32, 4);
        ptr[12] = 0x50;
        if (tcp_ctx.seq == 1) {
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
        memcpy(ptr - 12, &tcp_ctx.ip.saddr, 4);
        memcpy(ptr -  8, &tcp_ctx.ip.daddr, 4);
        ptr[-4] = 0;
        ptr[-3] = IP_TCP;
        cs = htons(20 + len);
        memcpy(ptr - 2, &cs, 2);
        
        cs = csum((uint16_t *)&ptr[-12], 12 + 20 + len);
        memcpy(&ptr[16], &cs, 2); 

        ip_build_and_send(&tcp_ctx.ip, 20 + 20 + len, IP_TCP);

        /*
         * Not a SYN and not a data segment so we don't have to wait for
         * an ACK.
         */
        if (tcp_ctx.seq > 1 && len == 0) {
                return 0;
        }

        rc = tcp_recv();
        if (rc == -EAGAIN) {
                if (retries++ < 5)  {
                        goto again;
                }
                return -1;
        }
        if (rc < 0) {
                return rc;
        }
        /* check the ACK number */
        /* TODO: Check that all data has been acked and if not retransmit
         * this shouldn't happen since we do retransmit alread if we did not receive
         * any reponse at all.   Unless the server also retransmitted at the same time.
         */

        /* Remember we got rc number of bytes so that we can return it
         * next time the application calls tcp_recv()
         */
        tcp_ctx.rx_data_len = rc;
        return 0;
}

/* tcp_recv
 * Wait for a segment of data coming back from the server.
 * We might have already recived the data as part of waiting for the
 * ACK to a previous tcp_send.  In that case just return the amount of data
 * we already got in the buffer.
 *
 * Returns:
 *      >0: Amount of data received for this TCP sesison.
 *       0: Something was received but it it did not contain data
 *          for this session. It could have been an ACK.
 *          Try again.
 * -EAGAIN: Timed out waiting for a reply or we did not receive an
 *          ACK for the full amount of data. Try again.
 *      <0: Some other error.
 */
int tcp_recv(void)
{
        uint8_t *ptr;
        uint32_t seq, ack;
        int len;
        int i;

        /* We got some data last time we called tcp_recv() from within
         * tcp_send().  Return it now since the application wants it.
         */
        if (tcp_ctx.rx_data_len) {
                i = tcp_ctx.rx_data_len;
                tcp_ctx.rx_data_len = 0;
                return i;
        }
        
        ptr = ip_buffer(&tcp_ctx.ip, 0);
        len = recv_packet(ptr, IP_MAX_SIZE, RS232_TPS);
        if (len < 0) {
                return len;
        }

        /* sanity checks */
        if (len < 20 + 20) {
                return -EAGAIN;
        }
        if (ptr[0] != 0x45) {
                return -EAGAIN;
        }
        if (ptr[9] != IP_TCP) {
                return -EAGAIN;
        }
        if (memcmp(&tcp_ctx.dst_port, &ptr[20], 4)) {
                return -EAGAIN;
        }

        if (ptr[20 + 13] & TCP_RST) {
                return -EAGAIN;
        }

        tcp_ctx.ths = ptr[20 + 12] >> 2;

        memcpy(&ack, &ptr[20 + 8], 4);
        ack = htonl(ack);
        if (tcp_ctx.seq == 1) {
                /* if this was a SYN-ACK, just send an immediate ack an return */
                if (ptr[20 + 13] & TCP_SYN) {
                        tcp_ctx.seq = ack;
                        tcp_ctx.ack = htonl(*(uint32_t *)&ptr[20 + 4]) + 1;
                        tcp_send(NULL, 0);
                        return 0;
                }
                return -1;
        }

        /* Data got acked. Advance the sequemce number */
        if (tcp_ctx.seq < ack) {
                tcp_ctx.seq = ack;
        }
        
        /* Track seq numbers for incoming packets and ignore retranmissions.
         * We are VERY slow so there will be many retransmissions just because we might
         * not be able to even ACK a segment in time
         */
        /* Send an immediate ACK to segments containing data */
        if (len > 20 + tcp_ctx.ths) {
                memcpy(&seq, &ptr[20 + 4], 4);
                seq = htonl(seq);

                /* Sequence number has reversed so this is likely a retransmission */
                if (seq < tcp_ctx.ack) {
                        return 0;
                }

                tcp_ctx.ack = seq;
                if (len > 20 + 20) {
                        tcp_ctx.ack += len - 20 - tcp_ctx.ths;
                }
                tcp_send(NULL, 0);
        }

        return len - 20 - tcp_ctx.ths;
}

int get_r_register(void) {
#asm
        ld h,0
        ld a,r
        ld l,a
#endasm
}

/* tcp_connect
 * Try to establish a TCP connection to a server.
 *
 * Returns:
 *  0: on success.
 * <0: on failure.
 */
int tcp_connect(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
        uint8_t *ptr = ip_buffer(&tcp_ctx.ip, 0);
        int rc, retries = 0;

        while (retries++ < 5) {
                tcp_ctx.ip.saddr = src;
                tcp_ctx.src_port = htons(src_port);
                tcp_ctx.ip.daddr = dst;
                tcp_ctx.dst_port = htons(dst_port);
                tcp_ctx.seq = 1;
                tcp_ctx.ack = 0;

                rc = tcp_send(NULL, 0);
                if (rc >= 0) {
                        return rc;
                }
                src_port += *(uint16_t *)&ptr[20 + 16]; /* use checksum as random increment */
                /* use the r register for even more randomness */
                src_port += get_r_register();
        }
        return -1;
}

uint8_t *tcp_rx_buffer(void)
{
        uint8_t *pkt = ip_buffer(&tcp_ctx.ip, 0);
        
        return &pkt[20 + tcp_ctx.ths];
}

uint8_t *tcp_tx_buffer(void)
{
        uint8_t *pkt = ip_buffer(&tcp_ctx.ip, 0);
        
        return &pkt[20 + 20]; /* we always write a 20 byte tcp header */
}

