/* Differential test harness for usmb2 (C reference vs hand-written asm).
 * Runs under z88dk-ticks (+test target). Prints every transmitted byte,
 * every return value and the relevant context / handle state so the output
 * of the C build and the asm build can be diffed.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "usmb2.h"
#include "tcp.h"

static uint8_t txb[1024];
static uint8_t rxb[1024];

static struct usmb2_context *g_ctx;   /* for relative pointer printing */

uint8_t *tcp_tx_buffer(void) { return txb; }
uint8_t *tcp_rx_buffer(void) { return rxb; }

/* ---------- output helpers ---------- */
static void hex(uint8_t *p, int n)
{
        int i;
        for (i = 0; i < n; i++) {
                printf("%02x", p[i]);
                if ((i & 31) == 31) printf("\n");
        }
        if (n & 31) printf("\n");
}

static uint16_t hash(uint8_t *p, int n)
{
        uint16_t h = 0x1234;
        while (n--) {
                h = (h << 3) ^ (h >> 13) ^ *p++;
        }
        return h;
}

static void pctx(void)
{
        if (g_ctx == NULL) { printf("ctx NULL\n"); return; }
        printf("ctx fd=%04x mid=", g_ctx->fd);
        hex((uint8_t *)&g_ctx->message_id, 8);
        printf("sid="); hex((uint8_t *)&g_ctx->session_id, 8);
        printf("tid="); hex((uint8_t *)&g_ctx->tree_id, 4);
        printf("user/pass hash %04x\n", hash((uint8_t *)g_ctx->username, 64));
        printf("buf hash %04x\n", hash(g_ctx->buf, USMB2_SIZE));
        hex(g_ctx->buf, 160);
}

/* ---------- canned server ---------- */
static uint32_t st_q[8];     /* queue of statuses for successive replies */
static int st_n, st_i;
static int recv_script[8];   /* per tcp_recv call: 1 = good, 0 = return 0,
                                2 = wrong mid, 3 = return -1 */
static int rs_n, rs_i;
static int g_extra;          /* extra body bytes / read length control */
static int g_rdlen;          /* READ: bytes of data returned */
static int g_dirvariant;
static uint8_t last_cmd;

static int g_maskmid;         /* hide wire mid (sccz80 l_i64_dec bug, see README) */
static void set_status(uint32_t s) { st_q[0] = s; st_n = 1; st_i = 0; }

int tcp_send(uint8_t *data, int len)
{
        uint8_t save[4];
        if (g_maskmid) { memcpy(save, &txb[28], 4); memset(&txb[28], 0x55, 4); }
        printf("SEND data=%s len=%d hash=%04x\n", data ? "PTR" : "NULL", len, hash(txb, len));
        hex(txb, len);
        if (g_maskmid) memcpy(&txb[28], save, 4);
        last_cmd = txb[16];
        return 0;
}

static void put32(uint8_t *p, uint32_t v)
{
        p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static const char *names[] = { ".", "a.txt", "hello_world.c", "Z" };

static int make_dir(uint8_t *b)
{
        /* FileDirectoryInformation entries, 8 byte aligned */
        int pos = 0, i, j, n, last = 0, cnt;
        const char *s;
        cnt = 3;
        for (i = 0; i < cnt; i++) {
                s = names[i + g_dirvariant];
                n = strlen(s);
                memset(&b[pos], 0x11 * (i + 1), 0x40);
                put32(&b[pos + 0x3c], n * 2 + (g_dirvariant && i == 0 ? 2 : 0));
                for (j = 0; j < n; j++) {
                        b[pos + 0x40 + j * 2] = s[j];
                        b[pos + 0x40 + j * 2 + 1] = 0;
                }
                if (g_dirvariant && i == 0) {
                        /* a non-ascii char: U+00E9 */
                        b[pos + 0x40 + n * 2] = 0xe9;
                        b[pos + 0x40 + n * 2 + 1] = 0;
                        n++;
                }
                last = pos;
                j = (0x40 + n * 2 + 7) & ~7;
                put32(&b[pos], j);
                pos += j;
        }
        put32(&b[last], 0);
        /* keep within the 252 byte directory buffer */
        return last + 0x40 + 2 * strlen(names[cnt - 1 + g_dirvariant]);
}

static void build_reply(void)
{
        uint32_t status = 0;
        int body, i, n;
        uint8_t *b = &rxb[68];

        if (st_i < st_n) status = st_q[st_i++];
        for (i = 0; i < 1024; i++) rxb[i] = (uint8_t)(i * 7 + last_cmd + 3);
        rxb[4] = 0xfe; rxb[5] = 'S'; rxb[6] = 'M'; rxb[7] = 'B';
        put32(&rxb[12], status);
        memcpy(&rxb[28], &txb[28], 8);
        switch (last_cmd) {
        case 0: body = 64 + 40; b[0] = 65; b[56] = 0x80; b[58] = 40; break;
        case 1: body = 8 + 120; b[4] = 72; b[6] = 120; break;
        case 3: body = 16; break;
        case 5: body = 88 + g_extra; break;
        case 6: body = 60; break;
        case 8:
                n = g_rdlen;
                body = 16 + n;
                put32(&b[4], n);
                break;
        case 9: body = 16; put32(&b[4], g_rdlen); break;
        case 14:
                n = make_dir(&b[8]);
                put32(&b[4], n);
                body = 8 + n;
                break;
        case 16: body = 8 + 24; b[16] = 0x34; b[17] = 0x12; break;
        default: body = 9; break;
        }
        if (status && status != 0xc0000016) body = 9;
        body += 64;
        rxb[0] = 0; rxb[1] = 0; rxb[2] = body >> 8; rxb[3] = body;
}

int tcp_recv(void)
{
        int m = 1;
        if (rs_i < rs_n) m = recv_script[rs_i++];
        printf("RECV mode %d\n", m);
        switch (m) {
        case 0: return 0;
        case 2: build_reply(); st_i--; rxb[29] ^= 0x40; return 100;
        case 3: build_reply(); return -1;
        case 4: build_reply(); st_i--; rxb[31] ^= 0x01; return 100;
        case 5: build_reply(); rxb[32] ^= 0x01; rxb[35] ^= 0x80; return 100;
        }
        build_reply();
        return 100;
}

#ifdef USMB2_FEATURE_NTLM
int ntlm_generate_auth(struct usmb2_context *usmb2, char *username, char *password)
{
        int i;
        printf("NTLM u=%d p=%d ctxok=%d bufhash=%04x\n",
               (int)(username - (char *)usmb2), (int)(password - (char *)usmb2),
               usmb2 == g_ctx, hash(usmb2->buf, USMB2_SIZE));
        for (i = 0; i < 400; i++) usmb2->buf[i] = i * 3 + 1;
        return 150 + (usmb2->buf[4] & 7);
}
#endif

/* ---------- tests ---------- */
static void pfh(uint8_t *fh, int n)
{
        if (fh == NULL) { printf("fh NULL\n"); return; }
        printf("fh: "); hex(fh, n);
}


static void rw(int wr, uint8_t *fh, uint8_t *b, int count, uint64_t off, int rdlen)
{
        int32_t rc;
        g_rdlen = rdlen;
        if (b) memset(b, 0xee, 300);
        if (wr) {
#ifdef USMB2_FEATURE_WRITE
                for (rc = 0; rc < count && rc < 300; rc++) b[rc] = rc + 0x20;
                rc = usmb2_pwrite(g_ctx, fh, b, count, off);
                printf("pwrite count=%d -> %ld\n", count, (long)rc);
#endif
        } else {
                rc = usmb2_pread(g_ctx, fh, b, count, off);
                printf("pread count=%d -> %ld\n", count, (long)rc);
        }
        if (b) {
                printf("b hash %04x\n", hash(b, 300));
                hex(b, 48);
        }
        pctx();
}

static uint8_t rbuf[300];

int main(void)
{
        uint8_t *fh, *dh, *de;
        int rc;
        int32_t r32;
        uint64_t off;

        printf("== init fail at negotiate\n");
        set_status(0xc0000022);
        g_ctx = usmb2_init_context(0x0b0a0a0a, "user", "pw");
        printf("ctx %s\n", g_ctx ? "ok" : "NULL");

        printf("== init fail at sessionsetup\n");
        st_q[0] = 0; st_q[1] = 0xc0000016; st_q[2] = 0xc000006d; st_n = 3; st_i = 0;
        g_ctx = usmb2_init_context(0x0b0a0a0a, "user", "pw");
        printf("ctx %s\n", g_ctx ? "ok" : "NULL");

        printf("== init ok\n");
        st_q[0] = 0; st_q[1] = 0xc0000016; st_q[2] = 0; st_n = 3; st_i = 0;
        recv_script[0] = 0; recv_script[1] = 2; recv_script[2] = 1; rs_n = 3; rs_i = 0;
        g_ctx = usmb2_init_context(0x0b0a0a0a, "sahlberg", "otto1234");
        printf("ctx %s\n", g_ctx ? "ok" : "NULL");
        if (g_ctx == NULL) return 1;
        pctx();

        printf("== negotiate/sessionsetup direct\n");
        set_status(0);
        rc = usmb2_negotiateprotocol(g_ctx);
        printf("neg -> %d\n", rc);
        st_q[0] = 0xc0000016; st_q[1] = 0xc0000016; st_q[2] = 0; st_n = 3; st_i = 0;
        rc = usmb2_sessionsetup(g_ctx);
        printf("ss -> %d\n", rc);
        pctx();

        printf("== treeconnect\n");
        set_status(0);
        rc = usmb2_treeconnect(g_ctx, "\\\\10.10.10.11\\SNAP-1");
        printf("tc -> %d\n", rc);
        pctx();
        set_status(0xc00000cc);
        rc = usmb2_treeconnect(g_ctx, "\\\\h\\x");
        printf("tc -> %d\n", rc);
        pctx();

        printf("== open fail\n");
        set_status(0xc0000034);
        fh = usmb2_open(g_ctx, "nofile", O_RDONLY);
        pfh(fh, 16);
        pctx();

        printf("== open rdonly\n");
        set_status(0); g_extra = 0;
        fh = usmb2_open(g_ctx, "client-specs.txt", O_RDONLY);
        pfh(fh, 16);
        pctx();
        set_status(0); g_extra = 40;
        free(fh);
        fh = usmb2_open(g_ctx, "dir\\sub\\file.bin", O_RDWR);
        pfh(fh, 16);
        pctx();
        set_status(0); g_extra = 0;
        free(fh);
        fh = usmb2_open(g_ctx, "", O_WRONLY);
        pfh(fh, 16);
        pctx();
#ifdef USMB2_FEATURE_UNICODE
        set_status(0);
        free(fh);
        fh = usmb2_open(g_ctx, "caf\xc3\xa9-\xe2\x82\xac.txt", O_RDONLY);
        pfh(fh, 16);
        pctx();
#endif
        set_status(0);
        dh = usmb2_open(g_ctx, "adir", O_RDONLY | O_DIRECTORY);
        pfh(dh, 20);
        printf("dh hash %04x\n", hash(dh, 272));
        free(dh);

        printf("== pread\n");
        set_status(0);
        rw(0, fh, rbuf, 100, 0, 100);
        set_status(0);
        rw(0, fh, rbuf, 100, 0x12345678UL, 37);
        set_status(0);
        off = 0x0123456789abcdefULL;
        rw(0, fh, rbuf, 64, off, 80);       /* server returns more than asked */
        set_status(0);
        off = 0xfedcba9800000001ULL;
        rw(0, fh, rbuf, 0, off, 0);
        set_status(0xC0000011);
        rw(0, fh, rbuf, 100, 4096, 0);       /* EOF */
        set_status(0);
        rw(0, fh, rbuf, 250, 0x100000000ULL, 250);

        printf("== prw direct\n");
        set_status(0); g_rdlen = 11;
        r32 = usmb2_prw(g_ctx, 8, fh, rbuf, rbuf + 100, 30, 0x55ULL);
        printf("prw8 -> %ld\n", (long)r32); hex(rbuf, 40); pctx();
        set_status(0); g_rdlen = 11;
        r32 = usmb2_prw(g_ctx, 9, fh, rbuf + 100, rbuf, 30, 0x66ULL);
        printf("prw9 -> %ld\n", (long)r32); hex(rbuf, 40); pctx();
        set_status(0); g_rdlen = 11;
        r32 = usmb2_prw(g_ctx, 16, fh, rbuf, rbuf, 30, 0x88ULL);
        printf("prw16 -> %ld\n", (long)r32); pctx();
        set_status(0xc0000022);
        r32 = usmb2_prw(g_ctx, 8, fh, rbuf, rbuf + 50, 30, 0x99ULL);
        printf("prw8 err -> %ld\n", (long)r32); pctx();

#ifdef USMB2_FEATURE_WRITE
        printf("== pwrite\n");
        set_status(0);
        rw(1, fh, rbuf, 100, 0, 100);
        set_status(0);
        rw(1, fh, rbuf, 7, 0x1122334455667788ULL, 7);
        set_status(0);
        rw(1, fh, rbuf, 300, 0x200000000ULL, 300);
        set_status(0xc000007f);
        rw(1, fh, rbuf, 5, 0, 0);
#endif

        printf("== size\n");
        set_status(0);
        rc = usmb2_size(g_ctx, fh);
        printf("size -> %d\n", rc);
        pctx();
        set_status(0xc0000008);
        rc = usmb2_size(g_ctx, fh);
        printf("size -> %d\n", rc);
        pctx();

        printf("== recv script\n");
        set_status(0);
        recv_script[0] = 0; recv_script[1] = 0; recv_script[2] = 2; recv_script[3] = 4; recv_script[4] = 5;
        rs_n = 5; rs_i = 0;
        rc = usmb2_size(g_ctx, fh);
        printf("size -> %d\n", rc);
        set_status(0);
        recv_script[0] = 3; rs_n = 1; rs_i = 0;
        rc = usmb2_size(g_ctx, fh);
        printf("size(-1) -> %d\n", rc);
        pctx();

        printf("== mid rollover\n");
        {
                int k;
                /* current mid low byte != 0xff: C wire mid is correct */
                static const uint32_t mids[6][2] = {
                        { 0xfffffffeUL, 0 }, { 0x00fffffeUL, 0xffffffffUL },
                        { 0xfffffffeUL, 0xffffffffUL }, { 0x12345678UL, 0x9abcdef0UL },
                        /* low byte 0xff: exercises the 64-bit carry chain of
                           message_id++ (wire mid masked, C is wrong there) */
                        { 0xffffffffUL, 0x00ffffffUL }, { 0x000000ffUL, 0 } };
                for (k = 0; k < 6; k++) {
                        memcpy((uint8_t *)&g_ctx->message_id, &mids[k][0], 4);
                        memcpy((uint8_t *)&g_ctx->message_id + 4, &mids[k][1], 4);
                        g_maskmid = k >= 4;
#ifdef SHOW_MID_BUG
                        g_maskmid = 0;
#endif
                        set_status(0);
                        rc = usmb2_size(g_ctx, fh);
                        g_maskmid = 0;
                        printf("size -> %d\n", rc);
                        pctx();
                }
                memset(&g_ctx->message_id, 0, 8);
                g_ctx->message_id = 0x40;
        }

#ifdef USMB2_FEATURE_OPENDIR
        {
                int k, round;
                for (round = 0; round < 2; round++) {
                        printf("== opendir %d\n", round);
                        g_dirvariant = round;
                        set_status(0);
                        dh = usmb2_opendir(g_ctx, round ? "sub\\dir" : "");
                        pfh(dh, 20);
                        if (dh == NULL) continue;
                        for (k = 0; k < 8; k++) {
                                set_status(0);
                                if (k == (round ? 3 : 6)) set_status(0x80000006);
                                de = usmb2_readdir(g_ctx, dh);
                                if (de == NULL) { printf("readdir NULL\n"); pctx(); break; }
                                printf("readdir off=%d name=[%s] dh hash %04x\n",
                                       (int)(de - dh), (char *)&de[0x40], hash(dh, 272));
                                hex(dh, 32);
                        }
                        printf("dh hash %04x\n", hash(dh, 272));
                        hex(dh, 272);
                        pctx();
#ifdef USMB2_FEATURE_CLOSE
                        set_status(0);
                        rc = usmb2_closedir(g_ctx, dh);
                        printf("closedir -> %d\n", rc);
#endif
                        free(dh);
                }
                set_status(0xc0000034);
                dh = usmb2_opendir(g_ctx, "missing");
                pfh(dh, 16);
                pctx();
        }
#endif

#ifdef USMB2_FEATURE_CLOSE
        printf("== close\n");
        set_status(0);
        rc = usmb2_close(g_ctx, fh);
        printf("close -> %d\n", rc);
        pctx();
        set_status(0xc0000128);
        rc = usmb2_close(g_ctx, fh);
        printf("close -> %d\n", rc);
        pctx();
#endif
        printf("== done\n");
        return 0;
}
