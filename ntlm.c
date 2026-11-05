/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* NTLMv2 */

#ifdef USMB2_FEATURE_NTLM

#if defined(_IOP)
#include "ps2iop-compat.h"
#else
#include <endian.h>
#endif

#if defined(Z80)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#endif

#include "usmb2.h"
#include "ntlm.h"
#include "md4.h"
#include "hmac-md5.h"

#include <stdio.h>

/* We are trying to re-use the same buffer we use for reading and writing to the socket as much as possible.
 * Makes the code hairy but saves several hundred bytes of buffers.
 * There are three things we nee from the original CHALLENGE message which was part of the previous reply
 * we goot and which is stored un usmb2->buf.
 * The server challenge, the TargetName and the TargetInfo. Are we are re-building the next SessionSetup request
 * within the same buffer as the reply we need data from, we must be careful so that we copy the data from their old
 * location in the reply to the new location in the to-be request before we overwrite that memory with new content.
 */
/* When this function is called the buffer contains
 * SessionSetup reply header: 8 bytes
 * Incoming NTLMSSP SecurityBuffer: hundreds of bytes.
 *
 * We are rewriting this in place to be
 * SPL                             : 4 bytes, to be filled in later
 * SMB2 header                     : 64 bytes, to be filled in later
 * SessionSetup Request header     : 24 bytes, to be filled in later
 * Outgoing NTLMSSP SecurityBuffer : hundreds of bytes. To be filled in by this function.
 */
/* Writes an NTLMSSP security buffer: length, maximum length and offset */
static void put_secbuf(uint8_t *p, uint16_t len, uint16_t offset)
{
        *(uint16_t *)&p[0] = htole16(len);
        *(uint16_t *)&p[2] = htole16(len);
        *(uint32_t *)&p[4] = htole32(offset);
}

int ntlm_generate_auth(struct usmb2_context *usmb2,
                       char *username,
                       char *password)
{
        char NTOWFv2[16], z;
        uint8_t *buf = usmb2->buf;
        uint8_t *in, *out, *resp, *p, *domain_name, *target_info;
        uint16_t domain_name_len, user_name_len, target_info_len;
        uint16_t ntlm_response_offset, ntlm_response_len, i;

        /* The incoming NTLMSSP blob, CHALLENGE, and the outgoing one, AUTH */
        in = &buf[le16toh(*(uint16_t *)&buf[4]) - 64];
        out = &buf[4 + 64 + 24];

        /* Grab Target/Domain name from the challenge buffer */
        domain_name_len = le16toh(*(uint16_t *)&in[12]);
        domain_name = &in[le32toh(*(uint32_t *)&in[16])];
        user_name_len = strlen(username) * 2;

        /* In AUTH the domain name comes at offset 72, which is where AUTH
         * ends on pre-2003, then the user name, then the NT response.
         * Offsets are relative to the start of NTLMSSP.
         */
        ntlm_response_offset = 72 + domain_name_len + user_name_len;
        resp = &out[ntlm_response_offset];

        /* Start by moving the TargetInfo buffer we received from the server in the CHALLENGE message
         * to where it will end up at the end of the auth message we are building.
         * Depending on the size of the TargetName, this shifts the offset into the NTLMSSP
         * buffer, but it is usually in the region 70-80 bytes for shortish target names.
         * In the AUTH we are building the LmChallengeResponse data often ends up laid
         * your starting at offset ~110 and the AvPairs are laid out another 16 + 28 bytes into that.
         */
        target_info = &in[le32toh(*(uint32_t *)&in[44])];

        /* Copy everything except the trailing EndOfList, the AvPair with type 0.
         * The length does not fit in a char: servers in a domain send 130+ bytes.
         */
        target_info_len = 0;
        while (*(uint16_t *)&target_info[target_info_len]) {
                target_info_len += 4 + le16toh(*(uint16_t *)&target_info[target_info_len + 2]);
        }
        p = &resp[16 + 28]; // AvPairs
        /* The new place overlaps the old one when the TargetInfo is longer than
         * about 144 + user_name_len bytes, so memmove and not memcpy.
         */
        memmove(p, target_info, target_info_len);

        /* Get offset to start of Server Challenge and copy it just before where 'temp'
           ends up in the response so we can compute the hmac-md5 as linear buffer.
           Only now that the TargetInfo is out of the way: this lands in it when it is
           longer than about 108 + user_name_len bytes.
         */
        memcpy(&resp[8], &in[24], 8);

        /* Add TargetName Av entry to the end: "cifs/" and the domain name in UCS2 */
        p += target_info_len;
        *(uint16_t *)&p[0] = htole16(9);
        *(uint16_t *)&p[2] = htole16(10 + domain_name_len);
        memcpy(&p[4], "c\0i\0f\0s\0/", 10);
        memcpy(&p[14], domain_name, domain_name_len);
        p += 14 + domain_name_len;

        /* and a final EndOfList plus 4 bytes of padding*/
        memset(p, 0, 8);
        p += 8;
        ntlm_response_len = p - resp;

        /*
         * Domain name. Copy to proper offset in the output  buffer and update length/offset.
         */
        /* This overlaps when the domain name is longer than 100 bytes */
        memmove(&out[72], domain_name, domain_name_len);
        domain_name = &out[72];
        put_secbuf(&out[28], domain_name_len, 72);

        /*
         * NT Response
         */
        put_secbuf(&out[20], ntlm_response_len, ntlm_response_offset);

        /*
         * User name
         */
        for (i = 0; i < user_name_len; i += 2) {
                out[72 + domain_name_len + i] = username[i >> 1];
                out[72 + domain_name_len + i + 1] = 0;
        }
        put_secbuf(&out[36], user_name_len, 72 + domain_name_len);

        /*
         * Host name, session key, negotiate flags and version
         */
        memset(&out[44], 0, 24);
        *(uint32_t *)&out[56] = htole32(0x20088037);

        /* At this point we no longer need to reference anything from the incoming security buffer
         * so we can use the early parts of the buffer as a scratch area. 4 + 64 + 24 + 20 bytes.
         */

        /* Generate NTOWFv1 */
        /* The MD4 context is 88 bytes so it fits in the scratch area
        * Store NTOWFv1 at offset 4 + 64 + 24 + 4 */
        MD4Init((MD4_CTX *)&buf[0]);
        z = 0;
        while (*password) {
                MD4Update((MD4_CTX *)&buf[0], (unsigned char *)password++, 1);
                MD4Update((MD4_CTX *)&buf[0], (unsigned char *)&z, 1);
        }
        MD4Final(&out[4], (MD4_CTX *)&buf[0]);

        /* Compute NTOWFv2 */
        /* We don't have enough scratch area to store NTOWFv2 too :-( */
        hmac_md5((struct MD5Context *)&buf[0],
                 (unsigned char *)username,
                 NULL, 0,
                 domain_name, domain_name_len,
                 &out[4], 16, (unsigned char *)NTOWFv2);

        /*
         * Clear beginning of ntlmv2 response and fill in all non-zero parts
         */
        memset(&resp[16], 0, 28);
        /* resp type and hi resp type */
        *(uint16_t *)&resp[16] = 0x0101;
        /* client challenge QQQQ */
        memset(&resp[32], 1, 8);

        hmac_md5((struct MD5Context *)&buf[0],
                 NULL,
                 &resp[8], ntlm_response_len - 8,
                 NULL, 0,
                 (unsigned char *)NTOWFv2, 16, resp);


        /* Fill in the first 20 bytes of the NTLMSSP buffer */
        memset(&out[8], 0, 12);
        out[8] = 3;

        return p - out;
}

#endif /* USMB2_FEATURE_NTLM */
