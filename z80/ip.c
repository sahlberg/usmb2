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
#include <net/hton.h>
#include "ip.h"
#include "slip.h"

uint16_t id = 1;

uint16_t csum(uint16_t *ptr, int nbytes) 
{
	uint32_t sum;
	uint16_t oddbyte;
	uint16_t answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte=0;
		*((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (uint16_t)~sum;
	
	return(answer);
}

void ip_build_and_send(ip_context_t *ctx, uint16_t total_len, uint8_t proto)
{
        uint16_t cs, tl;
        uint8_t *pkt = ctx->pkt;

        memset(pkt, 0, 20);
        pkt[0] = 0x45;
        tl = htons(total_len);
        memcpy(&pkt[2], &tl, 2);
        memcpy(&pkt[4], &id, 2); id++;
        pkt[8] = 64;
        pkt[9] = proto;
        memcpy(&pkt[12], &ctx->saddr, 4);
        memcpy(&pkt[16], &ctx->daddr, 4);

        cs = csum((uint16_t *)&pkt[0], 20);
        memcpy(&pkt[10], &cs, 2);
        send_packet(pkt, total_len);
}

uint8_t *ip_buffer(ip_context_t *ctx, int offset)
{
        return &ctx->pkt[offset];
}
