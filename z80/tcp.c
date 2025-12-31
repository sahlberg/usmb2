/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

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
        uint8_t send_syn;
        uint8_t ths;  /* most recent data segment tcp heaer size */
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

uint8_t ack_pkt[44];

int tcp_send(uint8_t *data, int len)
{
        uint8_t *ptr = ip_buffer(20);
        uint16_t cs;
        uint32_t u32;

        memset(ptr, 0, 24);
        if (data) {
                memcpy(ptr + 24, data, len);
        }
        cs = htons(tctx.src_port);
        memcpy(&ptr[0], &cs, 2);
        cs = htons(tctx.dst_port);
        memcpy(&ptr[2], &cs, 2);
        u32 = htonl(tctx.seq);
        memcpy(&ptr[4], &u32, 4);
        u32 = htonl(tctx.ack);
        memcpy(&ptr[8], &u32, 4);
        ptr[12] = 0x60;
        if (tctx.send_syn) {
                ptr[13] = TCP_SYN;
        } else {
                if (len) {
                        ptr[13] = TCP_ACK | TCP_PSH;
                } else {
                        ptr[13] = TCP_ACK;
                }
        }
        ptr[14] = 4; /* window */

        /* pseudo header, will be overwritten in ip_build_and_send() */
        memcpy(ptr - 12, &tctx.src, 4);
        memcpy(ptr -  8, &tctx.dst, 4);
        ptr[-4] = 0;
        ptr[-3] = IP_TCP;
        cs = htons(24 + len);
        memcpy(ptr - 2, &cs, 2);
        
        cs = csum((uint16_t *)&ptr[-12], 12 + 24 + len);
        memcpy(&ptr[16], &cs, 2); 
        
        ip_build_and_send(tctx.src, tctx.dst, 20 + 24 + len, IP_TCP);
        
        return 0;
}

int tcp_recv(void)
{
        uint8_t *ptr = ip_buffer(20);
        uint32_t seq, ack, tmp;
        int len;
        int i;
        
        ptr = ip_buffer(0);
        len = recv_packet(ptr, IP_MAX_SIZE);

        /* sanity checks */
        if (len < 20 + 20) {
                return -1;
        }
        if (ptr[0] != 0x45) {
                return -1;
        }
        if (ptr[9] != IP_TCP) {
                return -1;
        }
        tctx.ths = ptr[20 + 12] >> 2;

        memcpy(&ack, &ptr[20 + 8], 4);
        ack = htonl(ack);
        if ((ptr[20 + 13] & TCP_ACK) && (tctx.seq < ack)) {
                tctx.seq = ack;
        }

        /* Track seq numbers for incoming packets and ignore retranmsinnsions
         * we are VERY slow so there will be many retransmissions just because we might
         * not be able to even ACK a segment in time
         */
        /* do we need to send an immediate ack ? */
        if (ptr[20 + 13] & TCP_SYN || len > 20 + tctx.ths) {
                if (tctx.send_syn) {
                        tctx.send_syn = 0;
                }
                memcpy(&seq, &ptr[20 + 4], 4);
                seq = htonl(seq);

                /* Sequence number has reversed so this is likely a retransmission */
                if (seq < tctx.ack) {
                        return 0;
                }

                tctx.ack = seq;
                if (ptr[20 + 13] & TCP_SYN) {
                        tctx.ack++;
                }
                if (len > 20 + 24) {
                        tctx.ack += len - 20 - tctx.ths;
                }
                /* tcp_send above might corrupt the initial 4 bytes if the server gave us just a
                 * 20 byte tcp header (we write a 24 byte tcp header in tcp_send())
                 * so we must restore it
                 */
                memcpy(&tmp, tcp_buffer(), 4);
                tcp_send(NULL, 0);
                memcpy(tcp_buffer(), &tmp, 4);
        }

        return len - 20 - tctx.ths;
}

int tcp_connect(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
        int rc;

        tctx.src = src;
        tctx.src_port = src_port;
        tctx.dst = dst;
        tctx.dst_port = dst_port;
        tctx.seq = 1;
        tctx.ack = 0;
        tctx.send_syn = 1;

        rc = tcp_send(NULL, 0);
        rc = tcp_recv();
        
        return 0;
}

uint8_t *tcp_buffer(void)
{
        uint8_t *pkt = ip_buffer(0);
        
        return &pkt[20 + tctx.ths];
}

