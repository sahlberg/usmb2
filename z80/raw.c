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
 * The link layer of the tiny stack on a Linux host, instead of slip.c:
 * IP packets go out and come in on raw sockets. Needs CAP_NET_RAW.
 *
 * The kernel does not know about our TCP connection, and answers the
 * server's segments with a RST. Drop those, for example with
 *   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 *
 * The timeout of recv_packet() is counted in ticks of 1/RS232_TPS
 * seconds, as it is for slip.c.
 */
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "slip.h"

static int tx_fd = -1, rx_fd = -1;

int raw_init(void)
{
        tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (tx_fd < 0 || rx_fd < 0) {
                return -1;
        }
        return 0;
}

void send_packet(uint8_t *p, int len)
{
        struct sockaddr_in sin;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, &p[16], 4);
        sendto(tx_fd, p, len, 0, (struct sockaddr *)&sin, sizeof(sin));
}

int recv_packet(uint8_t *p, int len, int to)
{
        struct pollfd pfd = { .fd = rx_fd, .events = POLLIN };
        int rc;

        if (poll(&pfd, 1, to * 1000 / RS232_TPS) <= 0) {
                return -EAGAIN;
        }
        rc = recv(rx_fd, p, len, 0);
        if (rc < 0) {
                return -EAGAIN;
        }
        return rc;
}
