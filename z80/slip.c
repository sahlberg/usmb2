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
x * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/* SLIP  From RFC1055 */

#include <stdio.h>
#include <rs232.h>

#include "slip.h"

/* SLIP special character codes
 */
#define END             0xC0    /* indicates end of packet */
#define ESC             0xDB    /* indicates byte stuffing */
#define ESC_END         0xDC    /* ESC ESC_END means END data byte */
#define ESC_ESC         0xDD    /* ESC ESC_ESC means ESC data byte */

/*
 * FUSE + Interface1 rs232 emulation seem to have a bug with the character 0x00
 * that makes us have to escape also this character.
 * This makes it no longer compatible with the normal SLIP protocol
 * but what can you do.
 * Define SLIP_ESC_00  if you are going to use this with a
 * FUSE Spectrum 48k with Interface1 RS232
 */
#ifdef SLIP_ESC_00
#define ZER             0x00
#define ESC_ZER         0xDE    /* ESC ESC_ZER means ZER data byte */
#endif

int slip_init(int baud_rate, int parity)
{
        if (rs232_init() != RS_ERR_OK) {
                return -1;
        }
        if (rs232_params(baud_rate, parity) != RS_ERR_OK) {
                return -1;
        }

        return 0;
}

void send_packet(uint8_t *p, int len)
{
        rs232_put(END);
        while(len--) {
                switch(*p) {
                case END:
                        rs232_put(ESC);
                        rs232_put(ESC_END);
                        break;
                case ESC:
                        rs232_put(ESC);
                        rs232_put(ESC_ESC);
                        break;
#ifdef SLIP_ESC_00
                case ZER:
                        /* Kludge/workaround.  Fuse emulator when application writes 0x00
                         * to the serial port this becomes 0x00 + 0x2a  on the fifo.
                         * Possibly an issue related to Interface1.
                         */
                        rs232_put(ESC);
                        rs232_put(ESC_ZER);
                        break;
#endif                        
                default:
                        rs232_put(*p);
                }
                
                p++;
        }
        rs232_put(END);
}

/* RECV_PACKET: receives a packet into the buffer located at "p".
 *      If more than len bytes are received, the packet will
 *      be truncated.
 *      Returns the number of bytes stored in the buffer.
 */
int recv_packet(uint8_t *p, int len)
{
        uint8_t c = 0;
        int received = 0;

        /* Wait for an END character */
        while (1) {
                rs232_get(&c);
                if (c == END) {
                        break;
                }
        }
        
        /* sit in a loop reading bytes until we put together
         * a whole packet.
         * Make sure not to copy them into the packet if we
         * run out of room.
         */
        while(1) {
                rs232_get(&c);
                switch(c) {
                case END:
                        if(received) {
                                return received;
                        }
                        break;
                case ESC:
                        rs232_get(&c);
                        switch(c) {
#ifdef SLIP_ESC_00
                        case ESC_ZER:
                                if(received < len) {
                                        p[received++] = ZER;
                                }
                                break;
#endif
                        case ESC_END:
                                if(received < len) {
                                        p[received++] = END;
                                }
                                break;
                        case ESC_ESC:
                                if(received < len) {
                                        p[received++] = ESC;
                                }
                                break;
                        }
                        break;
                default:
                        if(received < len) {
                                p[received++] = c;
                        }
                }
        }
}

