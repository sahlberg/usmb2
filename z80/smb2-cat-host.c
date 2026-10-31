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
 * smb2-cat for a Linux host, on the tiny stack and raw sockets (raw.c):
 * lists the root of a share and prints a file from it.
 *
 * smb2-cat-host <server-ip> <share> <file> <user> <password>
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "slip.h"
#include "ip.h"
#include "tcp.h"
#include "usmb2.h"

/* ip hdr + tcp hdr with options + smb2 hdr + 512 bytes of payload */
#define BUF_SIZE (20 + 60 + 64 + 512)
uint8_t tcp_buf[BUF_SIZE];
tcp_context_t tcp = {
        .ip = {
                .pkt_size = BUF_SIZE,
                .pkt = tcp_buf,
        },
};

int main(int argc, char *argv[])
{
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        struct usmb2_context *usmb2;
        uint8_t *fh, *dh, *de;
        char unc[256], buf[256];
        int fd, rc, pos;

        if (argc != 6) {
                fprintf(stderr, "usage: %s <server-ip> <share> <file> <user> <password>\n", argv[0]);
                return 1;
        }

        /* Our address is the one the kernel would use to reach the server */
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(445);
        inet_pton(AF_INET, argv[1], &sin.sin_addr);
        memcpy(&tcp.ip.daddr, &sin.sin_addr, 4);
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        connect(fd, (struct sockaddr *)&sin, sizeof(sin));
        getsockname(fd, (struct sockaddr *)&sin, &len);
        memcpy(&tcp.ip.saddr, &sin.sin_addr, 4);

        if (raw_init()) {
                fprintf(stderr, "no raw sockets, need CAP_NET_RAW\n");
                return 1;
        }
        tcp.src_port = htons(40000 + (getpid() & 0x3fff));
        tcp.dst_port = htons(445);
        if (tcp_connect(&tcp) < 0) {
                fprintf(stderr, "failed to connect to %s\n", argv[1]);
                return 1;
        }
        usmb2_tcp = &tcp;

        usmb2 = usmb2_init_context(0, argv[4], argv[5]);
        if (usmb2 == NULL) {
                fprintf(stderr, "failed to log in\n");
                return 1;
        }
        snprintf(unc, sizeof(unc), "\\\\%s\\%s", argv[1], argv[2]);
        if (usmb2_treeconnect(usmb2, unc)) {
                fprintf(stderr, "failed to map %s\n", unc);
                return 1;
        }

        dh = usmb2_opendir(usmb2, "");
        if (dh == NULL) {
                fprintf(stderr, "usmb2_opendir failed\n");
                return 1;
        }
        while ((de = usmb2_readdir(usmb2, dh))) {
                printf("%s %s\n", (de[0x38] & 0x10) ? "DIR " : "FILE", &de[0x40]);
        }

        fh = usmb2_open(usmb2, argv[3], O_RDONLY);
        if (fh == NULL) {
                fprintf(stderr, "usmb2_open failed\n");
                return 1;
        }
        for (pos = 0;; pos += rc) {
                rc = usmb2_pread(usmb2, fh, (uint8_t *)buf, sizeof(buf), pos);
                if (rc <= 0) {
                        break;
                }
                fwrite(buf, 1, rc, stdout);
        }
        return 0;
}
