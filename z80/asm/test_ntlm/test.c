/* Differential test harness for ntlm_generate_auth (C vs asm). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "usmb2.h"
#include "ntlm.h"

static void w16(uint8_t *p, uint16_t v){ p[0]=v; p[1]=v>>8; }
static void w32(uint8_t *p, uint32_t v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }

/* append an AvPair to (*pp), advancing it */
static void avp(uint8_t **pp, uint16_t type, uint16_t len, const uint8_t *data)
{
        uint8_t *p = *pp;
        w16(p, type); w16(p+2, len);
        if (len) memcpy(p+4, data, len);
        *pp = p + 4 + len;
}

/* Build a CHALLENGE message into usmb2->buf.
 * tname : ascii target name (encoded UCS2 into the message)
 * avset : bitmask of which avpairs to include (bit0 NbDomain, 1 NbComputer,
 *         2 DnsDomain, 3 DnsComputer, 4 Timestamp)
 */
static void build_challenge(struct usmb2_context *u, const char *tname, int avset)
{
        uint8_t *buf = u->buf;
        uint8_t *blob;
        uint8_t *pay;
        int in = 8;          /* blob starts at buf[8] => buf[4]=0x48 */
        int tnlen = strlen(tname) * 2;
        int i;
        uint8_t *ti_start;
        uint16_t ti_len;

        memset(buf, 0, USMB2_SIZE);
        w16(&buf[4], 0x48);  /* security buffer offset = 64 + 8 */

        blob = &buf[in];
        memcpy(blob, "NTLMSSP", 8);      /* signature incl NUL */
        w32(blob+8, 2);                  /* CHALLENGE */

        /* payload area after the fixed 56-byte header of our layout */
        pay = blob + 56;

        /* TargetName */
        w16(blob+12, tnlen);
        w16(blob+14, tnlen);
        w32(blob+16, (uint32_t)(pay - blob));
        for (i = 0; i < tnlen/2; i++) { pay[i*2] = tname[i]; pay[i*2+1] = 0; }
        pay += tnlen;

        /* server challenge */
        for (i = 0; i < 8; i++) blob[24+i] = 0x10 + i;
        /* reserved */
        memset(blob+32, 0, 8);

        /* TargetInfo (AvPairs) */
        ti_start = pay;
        {
                uint8_t nb[]  = {'D','O','M',0,'A','I','N',0};        /* 8 */
                uint8_t nbc[] = {'S','E','R','V','E','R',0,0};        /* 8 */
                uint8_t dd[]  = {'d',0,'o',0,'m',0,'.',0,'x',0};      /* 10 */
                uint8_t dc[]  = {'s',0,'r',0,'v',0,'.',0,'d',0,0,0};  /* 12 */
                uint8_t ts[8] = {1,2,3,4,5,6,7,8};
                if (avset & 1) avp(&pay, 2, sizeof nb, nb);   /* NbDomainName */
                if (avset & 2) avp(&pay, 1, sizeof nbc, nbc); /* NbComputerName */
                if (avset & 4) avp(&pay, 4, sizeof dd, dd);   /* DnsDomainName */
                if (avset & 8) avp(&pay, 3, sizeof dc, dc);   /* DnsComputerName */
                if (avset & 16) avp(&pay, 7, sizeof ts, ts);  /* Timestamp */
                avp(&pay, 0, 0, 0);                           /* EOL */
        }
        ti_len = (uint16_t)(pay - ti_start);
        w16(blob+40, ti_len);
        w16(blob+42, ti_len);
        w32(blob+44, (uint32_t)(ti_start - blob));
}

static void dump(struct usmb2_context *u, int rv)
{
        int i;
        printf("RET=%d\n", rv);
        for (i = 0; i < USMB2_SIZE; i++) {
                printf("%02x", u->buf[i]);
                if ((i & 31) == 31) printf("\n");
        }
}

static struct usmb2_context ctx;

static void run(const char *tname, int avset, char *user, char *pass)
{
        int rv;
        build_challenge(&ctx, tname, avset);
        rv = ntlm_generate_auth(&ctx, user, pass);
        dump(&ctx, rv);
}

int main(void)
{
        run("WG", 1|2|4|8|16, "admin", "password");
        run("MYDOMAIN", 1|2|4|8|16, "Administrator", "");
        run("D", 1|2, "u", "p");
        run("LONGDOMAINNAME123", 1|2|4|8|16, "user1", "0123456789012345678901234567890");
        run("WORKGROUP", 1|4|16, "MixedCaseUser", "Secr3t!");
        run("X", 16, "a", "bb");
        run("ACME", 1|2|4|8, "john.doe", "hunter2hunter2hunter2hunter2");
        return 0;
}
