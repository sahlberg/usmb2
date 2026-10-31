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
#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

/* Used by tcp_recv to indicate the other side returned RST */
#define ERESET 20

typedef struct tcp_context {
        ip_context_t ip;
        /* Port numbers in network byte order, not host order,
         * so we can check the src/dst
         * ports of received packets by a simple memcmp().
         * The ordering of dst_port/src_port is important.
         */
        uint16_t dst_port;
        uint16_t src_port;
        uint32_t seq;
        uint32_t ack;
        uint8_t ths;  /* most recent data segment tcp header size */
} tcp_context_t;


int tcp_connect(tcp_context_t *tcp);
int tcp_send(tcp_context_t *tcp, int len, uint8_t *data, int window);
int tcp_recv(tcp_context_t *tcp, int len);
int tcp_recv_timeout(tcp_context_t *tcp, int len, int to);

uint8_t *tcp_rx_buffer(tcp_context_t *tcp);
uint8_t *tcp_tx_buffer(tcp_context_t *tcp);

#endif /*_TCP_H_ */
