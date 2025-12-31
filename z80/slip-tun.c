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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>

#define IFNAMSIZ 16

#define ZER             0000
#define END             0300    /* indicates end of packet */
#define ESC             0333    /* indicates byte stuffing */
#define ESC_END         0334    /* ESC ESC_END means END data byte */
#define ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */
#define ESC_ZER         0336    /* ESC ESC_ZER means ZER data byte */

int tun_open(char* devname) {
        struct ifreq ifr;
        int fd, err;

        if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
                perror("open /dev/net/tun");
                exit(1);
        }

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // Create a TUN device, no packet info
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);

        if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
                perror("ioctl TUNSETIFF");
                close(fd);
                exit(1);
        }

        return fd;
}

int main(int argc, char* argv[]) {
        int fds[4] = {-1, -1, -1, -1};
        unsigned char buffer[1500];
        unsigned char slip[1500];
        int nread, slip_pos, is_escape = 0, one = 1;
        struct sockaddr_in sin;

        if (argc != 4) {
                fprintf(stderr, "Usage: %s <tun> <rx> <tx>\n", argv[0]);
                fprintf(stderr, "\t<rx/tx> are the rx/tx channels from the spectrums perspective\n");
                exit(1);
        }
            
        fds[0] = tun_open(argv[1]);  // Open TUN device named tun0
        printf("Device %s opened\n", argv[1]);
        
        sprintf(slip, "ip link set dev %s up", argv[1]);
        system(slip);
        sprintf(slip, "ip addr add 192.0.2.1/24 dev %s metric 600", argv[1]);
        system(slip);

        fds[2] = open(argv[2], O_WRONLY);
        if (fds[2] == -1) {
                printf("Failed to open %s as rx\n", argv[2]);
                exit(10);
        }
        fds[1] = open(argv[3], O_RDONLY);
        if (fds[1] == -1) {
                printf("Failed to open %s as tx\n", argv[3]);
                exit(10);
        }

        fds[3] = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fds[3] == -1) {
                printf("Failed to open raw socket\n");
                exit(10);
        }
        setsockopt(fds[3], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        
        slip_pos = 0;
        slip[slip_pos] = 0;
        while (1) {
                struct pollfd pfds[2];
                int i, rc;

                pfds[0].fd      = fds[0];
                pfds[0].events  = POLLIN;
                pfds[0].revents = 0;
                pfds[1].fd      = fds[1];
                pfds[1].events  = POLLIN;
                pfds[1].revents = 0;
                rc = poll(pfds, 2, -1);

                if (pfds[0].revents) {
                        uint8_t c;
                        uint8_t b[4096];
                        int pos = 0;
                        
                        nread = read(fds[0], buffer, sizeof(buffer));
                        if (nread < 0) {
                                perror("Reading from interface");
                                exit(1);
                        }
                        /* only care about ipv4 */
                        if (buffer[0] != 0x45) {
                                continue;
                        }
                        /* only care about packets going to 192.0.2.2 */
                        if (buffer[16] != 0xc0 ||
                            buffer[17] != 0x00 ||
                            buffer[18] != 0x02 ||
                            buffer[19] != 0x02) {
                                continue;
                        }
                        
                        printf("Read %d bytes from device %s\n", nread, argv[1]);
                        b[pos++] = END;
                        for (i = 0; i < nread; i++) {
                                switch (buffer[i]) {
                                case ZER:
                                        b[pos++] = ESC;
                                        b[pos++] = ESC_ZER;
                                        break;
                                case END:
                                        b[pos++] = ESC;
                                        b[pos++] = ESC_END;
                                        break;
                                case ESC:
                                        b[pos++] = ESC;
                                        b[pos++] = ESC_ESC;
                                        break;
                                default: 
                                        b[pos++] = buffer[i];
                                }
                        }
                        b[pos++] = END;
                        write(fds[2], b, pos);
#if 0
                        printf("\n");
                        for (i = 0; i < pos; i++) {
                                printf("%02x ", b[i]);
                        }
                        printf("\n");
#endif
                }
                if (pfds[1].revents) {
                        unsigned char c;

                        do {
                                nread = read(fds[1], &c, 1);
                                if (nread == 0) {
                                        printf("closed\n");
                                        exit(0);
                                }
                        } while (nread != 1);
                        if (!slip_pos && c != END) {
                                continue;
                        }
                        if (!slip_pos) {
                                slip[slip_pos++] = c;
                                continue;
                        }
                        if (c == END) {
                                printf("Got full frame  %d bytes\n", slip_pos - 1);
#if 0                                
                                for (c = 1; c < slip_pos; c++) {
                                        printf("%02x ", slip[c]);
                                }
                                printf("\n");
#endif
                                sin.sin_family = AF_INET;
                                memcpy(&sin.sin_addr.s_addr, &slip[17], 4);
                                sendto(fds[3], &slip[1], slip_pos - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
                                is_escape = 0;
                                slip_pos = 0;
                                continue;
                        }
                        if (c == ESC) {
                                is_escape = 1;
                                continue;
                        }
                        if (is_escape && c == ESC_END) {
                                is_escape = 0;
                                slip[slip_pos++] = END;
                                continue;
                        }
                        if (is_escape && c == ESC_ESC) {
                                is_escape = 0;
                                slip[slip_pos++] = ESC;
                                continue;
                        }
                        if (is_escape && c == ESC_ZER) {
                                is_escape = 0;
                                slip[slip_pos++] = ZER;
                                continue;
                        }
                        is_escape = 0;
                        slip[slip_pos++] = c;
                }
        }

        close(fds[0]);
        close(fds[1]);
        close(fds[2]);
        close(fds[3]);
        return 0;
}


