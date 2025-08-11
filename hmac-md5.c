/* From RFC2104 */

#ifdef USMB2_FEATURE_NTLM

/*
** Function: hmac_md5
*/
#include <ctype.h>
#include <endian.h>
#include <strings.h>

#include "md5.h"

/*
 * unsigned char*  text;                pointer to data stream/
 * int             text_len;            length of data stream
 * unsigned char*  key;                 pointer to authentication key
 * int             key_len;             length of authentication key
 * caddr_t         digest;              caller digest to be filled in
 */
void
hmac_md5(unsigned char *text0,
	 unsigned char *text1, int text1_len,
	 unsigned char *text2, int text2_len,
	 unsigned char *key, unsigned int key_len,
	 unsigned char *digest)
{
        struct MD5Context context;
        unsigned char k_pad[65];
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {
		struct MD5Context tctx;

                md5Init(&tctx);
                md5Update(&tctx, key, key_len);
                md5Finalize(&tctx);

		memcpy(tk, tctx.digest, 16);
                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        memset(k_pad, 0, sizeof k_pad);
        memmove(k_pad, key, key_len);

        /* XOR key with ipad values */
        for (i=0; i<64; i++) {
                k_pad[i] ^= 0x36;
	}
        /*
         * perform inner MD5
         */
        md5Init(&context);                   /* init context for 1st
                                              * pass */
        md5Update(&context, k_pad, 64);     /* start with inner pad */
	while (text0 && *text0) {
		uint16_t c = htole16(toupper(*text0++));
		md5Update(&context, (uint8_t *)&c, 2);
	}
	if (text1) {
		md5Update(&context, text1, text1_len); /* then text of datagram */
	}
	if (text2) {
		md5Update(&context, text2, text2_len); /* then text of datagram */
	}
        md5Finalize(&context);          /* finish up 1st pass */
	memcpy(digest, context.digest, 16);
        /*
         * perform outer MD5
         */
        md5Init(&context);                   /* init context for 2nd
                                              * pass */
        /* XOR key with opad values */
        memset(k_pad, 0, sizeof k_pad);
        memmove(k_pad, key, key_len);
        for (i=0; i<64; i++) {
                k_pad[i] ^= 0x5c;
        }
        md5Update(&context, k_pad, 64);     /* start with outer pad */
        md5Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        md5Finalize(&context);          /* finish up 2nd pass */
	memcpy(digest, context.digest, 16);
}

#endif /* USMB2_FEATURE_NTLM */
