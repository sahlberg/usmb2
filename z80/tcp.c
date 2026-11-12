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
#ifdef __Z88DK
#include <net/hton.h>
#elif defined(_IOP)
#include "ps2iop-compat.h"
#else
#include <arpa/inet.h>
#endif
#include "ip.h"
#include "tcp.h"
#include "slip.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* Length of the TCP header we send: 24 with the MSS option, outside z88dk */
#ifdef __Z88DK
#define tcp_hl 20
#endif


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
 * One caveat on writing the payload into tcp_tx_buffer() and passing
 * data == NULL. Retransmitting re-sends whatever is in the packet
 * buffer, and recv_packet() has been writing incoming packets into the
 * front of that same buffer while we waited for the ACK. A data argument
 * is copied in again on the way round so it survives; a tcp_tx_buffer()
 * payload cannot be. tcp_send() therefore returns -1 rather than
 * retransmit one, so such a caller gets a single attempt and has to
 * rebuild and resend for itself. Pass data if you want the retries.
 *
 * With the window closed the only thing that can arrive while we wait
 * here is an ACK, so a request/response protocol never sees this. IRC is
 * the outlier: the server talks unsolicited.
 */
int tcp_send(tcp_context_t *tcp, int len, uint8_t *data, int window)
{
        uint8_t *ptr = ip_buffer(&tcp->ip, 20);
        uint16_t cs;
        uint32_t u32, oseq;
        int rc, retries = 0;
#ifndef __Z88DK
        int tcp_hl;
#endif

        oseq = tcp->seq;
        //printf("FIRST\n");
 again:
#ifndef __Z88DK
        tcp_hl = 20;
#endif
        memset(ptr, 0, 20);
        if (data) {
                memcpy(ptr + 20, data, len);
        }
        cs = tcp->src_port;
        memcpy(&ptr[0], &cs, 2);
        cs = tcp->dst_port;
        memcpy(&ptr[2], &cs, 2);
        u32 = htonl(tcp->seq);
        memcpy(&ptr[4], &u32, 4);
        u32 = htonl(tcp->ack);
        memcpy(&ptr[8], &u32, 4);
        ptr[12] = 0x50;
        if (tcp->seq == 1) {
                ptr[13] = TCP_SYN;
#ifndef __Z88DK
                /*
                 * MSS option: segments that fit in our buffer. Then each
                 * window we open gets a single segment, instead of the
                 * peer's default of 536 bytes several at a time.
                 */
                ptr[12] = 0x60;
                ptr[20] = 2;
                ptr[21] = 4;
                cs = htons(tcp->ip.pkt_size - 40);
                memcpy(&ptr[22], &cs, 2);
                tcp_hl = 24;
#endif
        } else {
                if (len) {
                        ptr[13] = TCP_ACK | TCP_PSH;
                } else {
                        ptr[13] = TCP_ACK;
                }
        }

        /* pseudo header, will be overwritten by ip_build_and_send() */
        memcpy(ptr - 12, &tcp->ip.saddr, 4);
        memcpy(ptr -  8, &tcp->ip.daddr, 4);
        ptr[-4] = 0;
        ptr[-3] = IP_TCP;
        cs = htons(tcp_hl + len);
        memcpy(ptr - 2, &cs, 2);

        /* Window */
        cs = htons(window);
        memcpy(&ptr[14], &cs, 2); 

        /* Checksum */
        cs = csum((uint16_t *)&ptr[-12], 12 + tcp_hl + len);
        memcpy(&ptr[16], &cs, 2); 

        //printf("SS S:%d A:%d\n", (int)tcp->seq, (int)tcp->ack);
        ip_build_and_send(&tcp->ip, 20 + tcp_hl + len, IP_TCP);
        /*
         * Not a SYN and not a data segment so we don't have to wait for
         * an ACK.
         */
        if (tcp->seq > 1 && len == 0) {
                return 0;
        }
#ifndef __Z88DK
        /*
         * Data with an open window: the peer answers straight away and the
         * ACK of our data comes with its answer, which tcp_recv() takes.
         * Waiting for a bare ACK here would only wait out the peer's
         * delayed ACK, as it has to hold its answer back otherwise.
         */
        if (window && len) {
                /*
                 * The data is out, so the next segment, the ACK of the
                 * answer included, comes after it. Do not wait for the
                 * peer's ACK to move on: one that sends its answer
                 * before it ACKs our data would see segments behind
                 * its rcv.nxt.
                 */
                tcp->seq = oseq + len;
                return 0;
        }
#endif

        rc = tcp_recv(tcp, 0);
        //printf("RECV rc:%d\n", rc);        
        if (rc < 0 && rc != -EAGAIN) {
                return rc;
        }
        /*
         * Either nothing came back at all, or something did but it was
         * not necessarily an ACK of what we just sent. tcp_recv()
         * advances tcp->seq when it sees an ACK covering our data, so if
         * it has not reached oseq + len the peer has not taken the data
         * yet and we have to send it again.
         *
         * This is not a corner case. A peer whose SYN-ACK advertised a
         * zero window sends a bare window update as soon as it opens the
         * window, and that arrives before the ACK of our data and is what
         * tcp_recv() returns here. Returning success then leaves tcp->seq
         * behind the peer's rcv.nxt, and the next segment we send - the
         * ACK that opens our own window - carries a sequence number the
         * peer has already passed. RFC 793 makes that segment
         * unacceptable, so the peer drops it, never sees the open window,
         * and probes a closed one for ever while we wait for data that
         * will not come.
         */
        if (rc == -EAGAIN || tcp->seq < oseq + len) {
                /*
                 * A tcp_tx_buffer() payload cannot be retransmitted, see
                 * the caveat above. len is what tells the two apart: a
                 * pure ACK and the SYN both pass data == NULL with no
                 * payload, and the SYN in particular has to keep its
                 * retransmissions.
                 */
                if (data == NULL && len) {
                        return -1;
                }
                if (retries++ < 5) {
                        goto again;
                }
                return -1;
        }

        return 0;
}


/* tcp_recv
 * Wait for a segment of data coming back from the server or just an ACK
 * (if len == 0)
 *
 * Returns:
 *      >0: Amount of data received for this TCP sesison.
 *       0: Something was received but it it did not contain data
 *          for this session. It could have been an ACK.
 *          Try again.
 * -ERESET: Other side returned RST. If this happen during SYN
 *          we might be in TIME_WAIT and have to pick a different port.
 * -EAGAIN: Timed out waiting for a reply or we did not receive an
 *          ACK for the full amount of data. Try again.
 *      <0: Some other error.
 */
int tcp_recv(tcp_context_t *tcp, int len)
{
        return tcp_recv_timeout(tcp, len, RS232_TPS);
}


/* tcp_recv_timeout
 * Same as tcp_recv() but with an explicit timeout, expressed as the
 * number of rs232_get() timeouts to wait for a packet. See RS232_TPS,
 * which is what tcp_recv() uses and which is our idea of "one second".
 *
 * This is for applications that have something else to do than to sit in
 * the serial port for a whole second at a time, such as reading a
 * keyboard. Note that recv_packet() performs to-1 reads, so a timeout
 * below 2 does not read anything at all.
 *
 * Polling like this is only useful while a window is open towards the
 * peer, since the peer will not send us anything otherwise.
 */
int tcp_recv_timeout(tcp_context_t *tcp, int len, int to)
{
        uint8_t *ptr;
        uint32_t seq, ack;
        int i;

        //printf("TCP_RECV len:%d\n", len);
        if (len > tcp->ip.pkt_size - 44) {
                len = tcp->ip.pkt_size - 44;
        }
        /* We want data so we must first open the window */
        if (len) {
                tcp_send(tcp, 0, NULL, len);
        }

 again:        
        ptr = ip_buffer(&tcp->ip, 0);
        len = recv_packet(ptr, tcp->ip.pkt_size, to);
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
        if (memcmp(&tcp->dst_port, &ptr[20], 4)) {
                return -EAGAIN;
        }

        if (ptr[20 + 13] & TCP_RST) {
                return -ERESET;
        }

        tcp->ths = ptr[20 + 12] >> 2;

        memcpy(&seq, &ptr[20 + 4], 4);
        seq = htonl(seq);
        memcpy(&ack, &ptr[20 + 8], 4);
        ack = htonl(ack);
        if (tcp->seq == 1) {
                /* if this was a SYN-ACK, just send an immediate ack an return */
                if (ack != tcp->seq + 1) {
                        return -ERESET;
                }
                if (ptr[20 + 13] & TCP_SYN) {
                        tcp->seq = ack;
                        tcp->ack = htonl(*(uint32_t *)&ptr[20 + 4]) + 1;
                        tcp_send(tcp, 0, NULL, 0);
                        return 0;
                }
                return -1;
        }

        //printf("SEQ %d  A:%d\n", (int)seq, (int)tcp->ack);
        /* Since we keep the window clamped to 0 most of the time
         * we are going to see a LOT of zero window probes from the
         * peer. Just ignore them.
         */
        if ((seq + 1 == tcp->ack) && (len == 20 + tcp->ths)) {
                //printf("ZERO WINDOW PROBE ll:%d\n", len - 20 - tcp->ths);
                goto again;
        }

        /* Data got acked. Advance the sequemce number */
        if (tcp->seq < ack) {
                tcp->seq = ack;
        }
        
        /* Track seq numbers for incoming packets and ignore retranmissions.
         * We are VERY slow so there will be many retransmissions just because we might
         * not be able to even ACK a segment in time
         */
        /* Send an immediate ACK to segments containing data and close the window */
        if (len > 20 + tcp->ths) {
                /*
                 * Only the next data in sequence is ours. Anything else is
                 * a retransmission, or comes after a segment we missed:
                 * taking it would skip the missing data for good. ACK what
                 * we have so the peer resends what is missing.
                 */
                if (seq != tcp->ack) {
                        tcp_send(tcp, 0, NULL, 0);
                        return 0;
                }

                if (len > 20 + 20) {
                        tcp->ack += len - 20 - tcp->ths;
                }
                /* ACK the data we got and close the window */
                tcp_send(tcp, 0, NULL, 0);
        }

        return len - 20 - tcp->ths;
}


#ifdef __Z88DK
static int get_r_register(void) {
#asm
        ld h,0
        ld a,r
        ld l,a
#endasm
}
#else
/* The checksum alone has to do for randomness */
#define get_r_register() 0
#endif


/* tcp_connect
 * Try to establish a TCP connection to a server.
 *
 * Returns:
 *  0: on success.
 * <0: on failure.
 */
int tcp_connect(tcp_context_t *tcp)
{
        uint8_t *ptr = ip_buffer(&tcp->ip, 0);
        int rc, retries = 0;

        tcp->ths = 0;
        while (retries++ < 5) {
                tcp->seq = 1;
                tcp->ack = 0;

                //printf("SEND SYN\n");
                rc = tcp_send(tcp, 0, NULL, 1);
                if (rc >= 0) {
                        //printf("connected\n\n");
                        return rc;
                }
                /* use checksum as random increment */                
                tcp->src_port += *(uint16_t *)&ptr[20 + 16];
                /* use the r register for even more randomness */
                tcp->src_port += get_r_register();
        }
        return -1;
}

uint8_t *tcp_rx_buffer(tcp_context_t *tcp)
{
        uint8_t *pkt = ip_buffer(&tcp->ip, 0);
        
        return &pkt[20 + tcp->ths];
}

uint8_t *tcp_tx_buffer(tcp_context_t *tcp)
{
        uint8_t *pkt = ip_buffer(&tcp->ip, 0);

        // todo  change this to a 24 byte buffer
        return &pkt[20 + 20]; /* we always write a 20 byte tcp header */
}

