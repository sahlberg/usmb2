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
/* SLIP  From RFC1055 */
#ifndef _SLIP_H_
#define _SLIP_H_

#include <stdint.h>

int slip_init(int baud_rate, int parity);
void send_packet(uint8_t *p, int len);
int recv_packet(uint8_t *p, int len, int to);

/* raw.c, the link layer on a Linux host instead of SLIP */
int raw_init(void);

/*
 * ps2smap.c, the link layer on the PS2 IOP, on Neutrino's smap.irx and
 * ministack.irx. ip, mask and gw are in host order.
 */
int ps2smap_init(uint32_t ip, uint32_t mask, uint32_t gw);
/*
 * Where our TCP port is, in network order: tcp->src_port, which
 * tcp_connect() changes when the server still has a connection on it, as
 * after an IOP reset. Other TCP packets are dropped.
 */
void ps2smap_set_port(const uint16_t *port);

#endif /*_SLIP_H_ */
