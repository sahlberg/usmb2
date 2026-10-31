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
 * Bridge a SLIP speaking Spectrum emulator (FUSE, Interface1 RS232) onto the
 * local network.
 *
 * FUSE is given two fifos:
 *   <rx>  the emulated Spectrum reads from it,  we write to it
 *   <tx>  the emulated Spectrum writes to it,   we read from it
 * i.e. the names are from the Spectrums point of view.
 *
 * Traffic for the Spectrum is picked up from a tun device and IP packets
 * coming back from the Spectrum are injected onto the real network using a
 * raw socket.
 *
 * The fifos are treated as a session: FUSE opening <rx> for reading is what
 * we call a client attaching.  While no client is attached we never write to
 * the fifos, and when a client detaches both fifos are emptied so that a
 * restarted FUSE never sees leftovers from the previous instance.  That means
 * the fifos can stay around across FUSE restarts, they do not have to be
 * deleted and recreated.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/* SLIP special character codes.  From RFC1055. */
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

#define MTU             1500
/* Worst case every byte is escaped, plus the leading and trailing END. */
#define SLIP_MAX        (2 * MTU + 2)

#define LOCAL_ADDR      "192.0.2.1"     /* our end of the link, on the tun */
#define REMOTE_ADDR     "192.0.2.2"     /* the Spectrum */
#define PREFIX_LEN      24
#define ROUTE_METRIC    600

/* How long we are prepared to wait for FUSE to make room in the rx fifo
 * before we give up and drop the frame. */
#define WRITE_TIMEOUT_MS        500
/* How often we look for a client attaching while we are idle. */
#define ATTACH_POLL_MS          200

#define IP_HDR_MIN      20
#define IP_OFF_DADDR    16

struct bridge {
        const char *tun_name;
        const char *rx_path;    /* fifo we write to, Spectrum reads */
        const char *tx_path;    /* fifo we read from, Spectrum writes */

        int tun_fd;
        int raw_fd;
        int rx_fd;              /* -1 while no client is attached */
        int tx_fd;

        int attached;

        /* SLIP decoder state for the tx fifo */
        unsigned char frame[MTU];
        int frame_len;
        int in_escape;
        int in_sync;            /* seen the leading END of a frame */
        int truncated;          /* current frame overflowed, drop it */
};

static int verbose;

static void vrb(const char *fmt, ...)
{
        va_list ap;

        if (!verbose) {
                return;
        }
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        fflush(stdout);
}

static void die(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        exit(1);
}

static void run_cmd(const char *fmt, ...)
{
        char cmd[256];
        va_list ap;
        int rc;

        va_start(ap, fmt);
        vsnprintf(cmd, sizeof(cmd), fmt, ap);
        va_end(ap);

        rc = system(cmd);
        if (rc != 0) {
                fprintf(stderr, "Command failed (%d): %s\n", rc, cmd);
        }
}

static int tun_open(const char *devname)
{
        struct ifreq ifr;
        int fd;

        fd = open("/dev/net/tun", O_RDWR);
        if (fd == -1) {
                die("open /dev/net/tun: %s\n", strerror(errno));
        }

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;    /* TUN device, no packet info */
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", devname);

        if (ioctl(fd, TUNSETIFF, (void *)&ifr) == -1) {
                die("ioctl TUNSETIFF %s: %s\n", devname, strerror(errno));
        }

        return fd;
}

static int raw_open(void)
{
        int fd, one = 1;

        fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd == -1) {
                die("Failed to open raw socket: %s\n"
                    "(this program needs to run as root)\n", strerror(errno));
        }
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
                die("setsockopt IP_HDRINCL: %s\n", strerror(errno));
        }

        return fd;
}

/*
 * Open the fifo we read from.  O_NONBLOCK so that this succeeds even when
 * no client has it open for writing yet.
 */
static int tx_open(struct bridge *b)
{
        int fd;

        fd = open(b->tx_path, O_RDONLY | O_NONBLOCK);
        if (fd == -1) {
                die("Failed to open %s as tx: %s\n", b->tx_path,
                    strerror(errno));
        }

        return fd;
}

/* Read and discard whatever is sitting in the fifo right now. */
static void tx_drain(struct bridge *b)
{
        unsigned char buf[4096];
        ssize_t count = 0, n;

        while (1) {
                n = read(b->tx_fd, buf, sizeof(buf));
                if (n > 0) {
                        count += n;
                        continue;
                }
                if (n == -1 && errno == EINTR) {
                        continue;
                }
                break;  /* 0 == no writers left, -1 == EAGAIN, fifo is empty */
        }
        if (count) {
                vrb("Discarded %zd stale bytes from %s\n", count, b->tx_path);
        }

        b->frame_len = 0;
        b->in_escape = 0;
        b->in_sync = 0;
        b->truncated = 0;
}

/*
 * Empty the tx fifo.  Draining gets rid of everything buffered, and closing
 * our end afterwards throws away the fifos buffer altogether once the last
 * writer is gone, so nothing can survive into the next session.
 */
static void tx_flush(struct bridge *b)
{
        tx_drain(b);
        close(b->tx_fd);
        b->tx_fd = tx_open(b);
}

/*
 * A client is attached once it has the rx fifo open for reading.  Opening the
 * write side O_NONBLOCK fails with ENXIO for as long as there is no reader,
 * which is exactly the probe we want.
 */
static void client_attach(struct bridge *b)
{
        int fd;

        fd = open(b->rx_path, O_WRONLY | O_NONBLOCK);
        if (fd == -1) {
                if (errno != ENXIO) {
                        die("Failed to open %s as rx: %s\n", b->rx_path,
                            strerror(errno));
                }
                return;         /* nobody there yet */
        }

        b->rx_fd = fd;
        b->attached = 1;
        printf("Client attached\n");
        fflush(stdout);
}

static void client_detach(struct bridge *b)
{
        if (!b->attached) {
                return;
        }

        /*
         * Closing the write side drops everything we had queued up for a
         * client that is no longer listening.
         */
        close(b->rx_fd);
        b->rx_fd = -1;
        b->attached = 0;
        tx_flush(b);

        printf("Client detached, fifos flushed\n");
        fflush(stdout);
}

enum write_result {
        WRITE_OK = 0,
        WRITE_DROPPED,          /* client too slow, frame dropped */
        WRITE_GONE,             /* client went away */
};

static enum write_result rx_write(struct bridge *b, const unsigned char *buf,
                                  size_t len)
{
        while (len) {
                ssize_t n = write(b->rx_fd, buf, len);
                struct pollfd pfd;
                int rc;

                if (n > 0) {
                        buf += n;
                        len -= n;
                        continue;
                }
                if (n == -1 && errno == EINTR) {
                        continue;
                }
                if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        return WRITE_GONE;      /* EPIPE and friends */
                }

                /* Fifo is full, wait for the client to consume some of it. */
                pfd.fd = b->rx_fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                rc = poll(&pfd, 1, WRITE_TIMEOUT_MS);
                if (rc == -1) {
                        if (errno == EINTR) {
                                continue;
                        }
                        return WRITE_GONE;
                }
                if (rc == 0) {
                        return WRITE_DROPPED;
                }
                if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                        return WRITE_GONE;
                }
        }

        return WRITE_OK;
}

/* SLIP encode a packet into out[], which must hold at least SLIP_MAX bytes. */
static int slip_encode(const unsigned char *in, int len, unsigned char *out)
{
        int i, pos = 0;

        out[pos++] = END;
        for (i = 0; i < len; i++) {
                switch (in[i]) {
#ifdef SLIP_ESC_00
                case ZER:
                        out[pos++] = ESC;
                        out[pos++] = ESC_ZER;
                        break;
#endif
                case END:
                        out[pos++] = ESC;
                        out[pos++] = ESC_END;
                        break;
                case ESC:
                        out[pos++] = ESC;
                        out[pos++] = ESC_ESC;
                        break;
                default:
                        out[pos++] = in[i];
                }
        }
        out[pos++] = END;

        return pos;
}

/* A packet came in on the tun device, hand it to the Spectrum. */
static void handle_tun(struct bridge *b, in_addr_t remote)
{
        unsigned char packet[MTU];
        unsigned char slip[SLIP_MAX];
        int nread, len;

        nread = read(b->tun_fd, packet, sizeof(packet));
        if (nread == -1) {
                if (errno == EINTR || errno == EAGAIN) {
                        return;
                }
                die("Reading from %s: %s\n", b->tun_name, strerror(errno));
        }
        if (nread < IP_HDR_MIN) {
                return;
        }
        /* only care about ipv4 with no options */
        if (packet[0] != 0x45) {
                return;
        }
        /* only care about packets going to the Spectrum */
        if (memcmp(&packet[IP_OFF_DADDR], &remote, 4)) {
                return;
        }
        /*
         * With no client attached this is where the packet dies.  It must not
         * end up in the fifo, or the next FUSE instance to attach would pick
         * up traffic that was meant for the previous one.
         */
        if (!b->attached) {
                vrb("Dropped %d bytes from %s, no client attached\n", nread,
                    b->tun_name);
                return;
        }

        vrb("Read %d bytes from device %s\n", nread, b->tun_name);
        len = slip_encode(packet, nread, slip);
        switch (rx_write(b, slip, len)) {
        case WRITE_OK:
                break;
        case WRITE_DROPPED:
                fprintf(stderr, "Client is not draining %s, dropped a frame\n",
                        b->rx_path);
                break;
        case WRITE_GONE:
                client_detach(b);
                break;
        }
}

/* A complete SLIP frame arrived from the Spectrum, put it on the wire. */
static void inject_frame(struct bridge *b)
{
        struct sockaddr_in sin;

        if (b->frame_len < IP_HDR_MIN) {
                vrb("Ignoring short frame of %d bytes\n", b->frame_len);
                return;
        }
        if ((b->frame[0] & 0xf0) != 0x40) {
                vrb("Ignoring non ipv4 frame\n");
                return;
        }

        vrb("Got full frame  %d bytes\n", b->frame_len);

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr.s_addr, &b->frame[IP_OFF_DADDR], 4);

        if (sendto(b->raw_fd, b->frame, b->frame_len, 0,
                   (struct sockaddr *)&sin, sizeof(sin)) == -1) {
                fprintf(stderr, "sendto %s failed: %s\n",
                        inet_ntoa(sin.sin_addr), strerror(errno));
        }
}

static void slip_decode(struct bridge *b, unsigned char c)
{
        /* Ignore anything before the first END, it is a partial frame. */
        if (!b->in_sync) {
                if (c == END) {
                        b->in_sync = 1;
                }
                return;
        }

        if (c == END) {
                if (b->truncated) {
                        fprintf(stderr, "Dropped oversized frame\n");
                } else if (b->frame_len) {
                        inject_frame(b);
                }
                b->frame_len = 0;
                b->in_escape = 0;
                b->truncated = 0;
                return;
        }

        if (c == ESC) {
                b->in_escape = 1;
                return;
        }

        if (b->in_escape) {
                b->in_escape = 0;
                switch (c) {
                case ESC_END:
                        c = END;
                        break;
                case ESC_ESC:
                        c = ESC;
                        break;
#ifdef SLIP_ESC_00
                case ESC_ZER:
                        c = ZER;
                        break;
#endif
                default:
                        /* Protocol violation, RFC1055 says take it as is. */
                        break;
                }
        }

        if (b->frame_len == sizeof(b->frame)) {
                b->truncated = 1;
                return;
        }
        b->frame[b->frame_len++] = c;
}

/* Returns 0 if the client closed the tx fifo. */
static int handle_tx(struct bridge *b)
{
        unsigned char buf[1024];
        ssize_t n;
        int i;

        n = read(b->tx_fd, buf, sizeof(buf));
        if (n == 0) {
                return 0;       /* all writers gone, FUSE has quit */
        }
        if (n == -1) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        return 1;
                }
                die("Reading from %s: %s\n", b->tx_path, strerror(errno));
        }

        for (i = 0; i < n; i++) {
                slip_decode(b, buf[i]);
        }

        return 1;
}

static void make_fifo(const char *path)
{
        struct stat st;

        if (mkfifo(path, 0666) == 0) {
                /*
                 * We are likely running as root while FUSE is not, so make
                 * sure umask did not leave the fifo read only for the user.
                 */
                if (chmod(path, 0666) == -1) {
                        die("Failed to chmod %s: %s\n", path, strerror(errno));
                }
                return;
        }
        if (errno != EEXIST) {
                die("Failed to create fifo %s: %s\n", path, strerror(errno));
        }
        if (stat(path, &st) == -1) {
                die("Failed to stat %s: %s\n", path, strerror(errno));
        }
        if (!S_ISFIFO(st.st_mode)) {
                die("%s exists but is not a fifo\n", path);
        }
}

static void usage(const char *argv0)
{
        fprintf(stderr, "Usage: %s [-v] <tun> <rx> <tx>\n", argv0);
        fprintf(stderr, "\t<rx/tx> are the rx/tx channels from the "
                "spectrums perspective\n");
        fprintf(stderr, "\tThey are created if they do not already exist.\n");
        fprintf(stderr, "\t-v\tverbose, log every packet\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct bridge b;
        in_addr_t remote;
        int argi = 1;

        if (argc > 1 && !strcmp(argv[1], "-v")) {
                verbose = 1;
                argi++;
        }
        if (argc - argi != 3) {
                usage(argv[0]);
        }

        /* We want EPIPE from write(), not to be killed by it. */
        signal(SIGPIPE, SIG_IGN);

        memset(&b, 0, sizeof(b));
        b.tun_name = argv[argi];
        b.rx_path = argv[argi + 1];
        b.tx_path = argv[argi + 2];
        b.rx_fd = -1;

        remote = inet_addr(REMOTE_ADDR);

        b.tun_fd = tun_open(b.tun_name);
        printf("Device %s opened\n", b.tun_name);

        run_cmd("ip link set dev %s up", b.tun_name);
        run_cmd("ip addr add %s/%d dev %s metric %d", LOCAL_ADDR, PREFIX_LEN,
                b.tun_name, ROUTE_METRIC);

        make_fifo(b.rx_path);
        make_fifo(b.tx_path);

        b.tx_fd = tx_open(&b);
        b.raw_fd = raw_open();

        /* Whatever is in the fifo at startup predates us. */
        tx_drain(&b);

        printf("Waiting for a client on %s\n", b.rx_path);
        fflush(stdout);

        while (1) {
                struct pollfd pfds[3];
                int nfds = 0, tun_i, tx_i = -1, rx_i = -1;
                int rc;

                tun_i = nfds;
                pfds[nfds].fd = b.tun_fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;

                if (b.attached) {
                        tx_i = nfds;
                        pfds[nfds].fd = b.tx_fd;
                        pfds[nfds].events = POLLIN;
                        pfds[nfds].revents = 0;
                        nfds++;

                        /*
                         * No events requested, we only want to hear about
                         * POLLERR, which is how the write side of a fifo
                         * reports that the last reader went away.
                         */
                        rx_i = nfds;
                        pfds[nfds].fd = b.rx_fd;
                        pfds[nfds].events = 0;
                        pfds[nfds].revents = 0;
                        nfds++;
                }

                /*
                 * While detached we do not poll the tx fifo.  With no writer
                 * it is permanently POLLHUP and would spin us.  Instead we
                 * wake up now and then to see if a client has shown up.
                 */
                rc = poll(pfds, nfds, b.attached ? -1 : ATTACH_POLL_MS);
                if (rc == -1) {
                        if (errno == EINTR) {
                                continue;
                        }
                        die("poll: %s\n", strerror(errno));
                }

                if (pfds[tun_i].revents & POLLIN) {
                        handle_tun(&b, remote);
                }

                if (rx_i != -1 &&
                    (pfds[rx_i].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                        client_detach(&b);
                        continue;
                }

                if (tx_i != -1 && b.attached &&
                    (pfds[tx_i].revents & (POLLIN | POLLHUP))) {
                        if (!handle_tx(&b)) {
                                client_detach(&b);
                                continue;
                        }
                }

                if (!b.attached) {
                        client_attach(&b);
                }
        }

        /* not reached */
        return 0;
}
