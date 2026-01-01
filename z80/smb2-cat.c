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
#include <arch/zx.h>
#include <stdio.h>
#include <rs232.h>

#include "slip.h"
#include "ip.h"
#include "tcp.h"

#include "usmb2.h"

char buf[256];

int main(void)
{
        int i, pos;
        uint32_t src = 0x020200c0; /* 192.0.2.2 */
        uint32_t dst;
        int32_t rc;
        int ipi[4];
        uint8_t *ip;
        struct usmb2_context *usmb2;
        uint8_t *fh;

        zx_cls();
        ip = (uint8_t *)&src;
        printf("My IP address: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
        
#if 0        
        printf("Server IP: ");fflush(stdout);
        scanf("%d.%d.%d.%d\n", &ipi[0], &ipi[1], &ipi[2], &ipi[3]);
        ip = (uint8_t *)&dst;
        ip[0] = ipi[0];
        ip[1] = ipi[1];
        ip[2] = ipi[2];
        ip[3] = ipi[3];
#else
        dst = 0x0b0a0a0a;
#endif
        printf("\n");

        slip_init(RS_BAUD_9600, RS_PAR_NONE);
        rc = tcp_connect(src, 118, dst, 445);

        usmb2 = usmb2_init_context(0x0b0a0a0a, "sahlberg", "otto1234"); /* 10.10.10.11 */
        if (usmb2 == NULL) {
                printf("failed to connect to server\n");
                return 0;
        }
        usmb2_treeconnect(usmb2, "\\\\10.10.10.11\\SNAP-1");
        fh = usmb2_open(usmb2, "client-specs.txt", O_RDONLY);
        if (fh == NULL) {
		printf("usmb2_open failed\n");
		return 0;
        }
        pos = 0;
 again:
        rc = usmb2_pread(usmb2, fh, buf, 100, pos);
        if (rc == STATUS_END_OF_FILE) {
                goto finished;
        }
        if (rc < 0) {
		printf("usmb2_read failed\n");
		return 0;
        }
        if (rc > 0) {
                for (i = 0; i < rc; i++) {
                        putchar(buf[i]);
                }
                pos += rc;
                goto again;
        }
 finished:
        printf("\n");

        usmb2_close(usmb2, fh);

        return 0;
}
