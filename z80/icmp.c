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
#include "ip.h"
#include "icmp.h"
#include "slip.h"

int icmp_echo_request(uint32_t src, uint32_t dst)
{
        uint8_t *ptr;
        uint16_t cs;
        int len, retries = 5;

        ptr = ip_buffer(0);
 again:
        memset(ptr + 20, 0, 64);
        ptr[20] = ICMP_TYPE_ECHO;
        
        cs = csum((uint16_t *)&ptr[20], 64);
        memcpy(&ptr[22], &cs, 2);
        ip_build_and_send(src, dst, 20 + 16, IP_ICMP);

        len = recv_packet(ptr, IP_MAX_SIZE, RS232_TPS);
        if (len == -EAGAIN) {
                if (--retries) {
                        goto again;
                } else {
                        return -1;
                }
        }

        if (len < 28) {
                return -1;
        }
        if (ptr[0] != 0x45) {
                return -1;
        }
        if (ptr[9] != IP_ICMP) {
                return -1;
        }
        if (ptr[20] != ICMP_TYPE_ECHO_REPLY) {
                return -1;
        }

        return 0;
}

