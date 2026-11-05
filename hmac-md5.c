/* From RFC2104 */

#ifdef USMB2_FEATURE_NTLM

/*
** Function: hmac_md5
*/
#include <ctype.h>
#if defined(_IOP)
#include "ps2iop-compat.h"
#else
#include <endian.h>
#endif
#include <string.h>

#include "hmac-md5.h"

#if defined(Z80)
#define htole16(x) (x)
#endif

/* Starts an MD5 with the key, zero padded to 64 bytes and xor'ed with val */
static void
init_pad(struct MD5Context *ctx, unsigned char *key, unsigned int key_len, unsigned char val)
{
        unsigned int i;
        unsigned char c;

        md5Init(ctx);
        for (i = 0; i < 64; i++) {
                c = (i < key_len ? key[i] : 0) ^ val;
                md5Update(ctx, &c, 1);
        }
}

/*
 * unsigned char*  text;                pointer to data stream/
 * int             text_len;            length of data stream
 * unsigned char*  key;                 pointer to authentication key
 * int             key_len;             length of authentication key
 * caddr_t         digest;              caller digest to be filled in
 */
void
hmac_md5(struct MD5Context *ctx,
	 unsigned char *text0,
	 unsigned char *text1, int text1_len,
	 unsigned char *text2, int text2_len,
	 unsigned char *key, unsigned int key_len,
	 unsigned char *digest)
{
        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * and text is the data being protected
         */

        /*
         * perform inner MD5
         */
        init_pad(ctx, key, key_len, 0x36);   /* start with inner pad */
	while (text0 && *text0) {
		uint16_t c = htole16(toupper(*text0++));
		md5Update(ctx, (uint8_t *)&c, 2);
	}
	md5Update(ctx, text1, text1_len);     /* then text of datagram */
	md5Update(ctx, text2, text2_len);     /* NULL, 0 adds nothing */
        md5Finalize(ctx);          /* finish up 1st pass */
	memcpy(digest, ctx->input, 16);
        /*
         * perform outer MD5
         */
        init_pad(ctx, key, key_len, 0x5c);   /* start with outer pad */
        md5Update(ctx, digest, 16);          /* then results of 1st
                                              * hash */
        md5Finalize(ctx);                    /* finish up 2nd pass */
	memcpy(digest, ctx->input, 16);
}

#endif /* USMB2_FEATURE_NTLM */
