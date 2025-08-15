/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* NTLMv2 */

#ifdef USMB2_FEATURE_NTLM

#include <endian.h>

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
int ntlm_generate_auth(struct usmb2_context *usmb2,
                       char *username,
                       char *password)
{
        MD4_CTX ctx;
        char NTOWFv1[16], NTOWFv2[16], NTProofStr[16], z = 0, zero = 0;
        uint16_t ntlmssp_in_offset, ntlmssp_out_offset, offset;
        uint16_t domain_name_offset, domain_name_len; char *domain_name;
        uint16_t user_name_offset, user_name_len;
        uint16_t ntlm_response_offset, ntlm_response_len;
        uint16_t at_type, at_len, out_pdu_size;
        uint16_t target_info_len; char *target_info;

        /* Set offset to start of ntlmssp blob */
        ntlmssp_in_offset = le16toh(*(uint16_t *)&usmb2->buf[4]) - 64;
        ntlmssp_out_offset = 4 + 64 + 24;
 
        /* Get offset to start of TargetName */
        offset = ntlmssp_in_offset + 12; /* skip past NTLMSSP signature and message type */

        /* Grab Target/Domain name from the challenge buffer */
        domain_name_len = le16toh(*(uint16_t *)&usmb2->buf[offset]);
        domain_name = &usmb2->buf[ntlmssp_in_offset + le32toh(*(uint32_t *)&usmb2->buf[offset + 4])];
        domain_name_offset = 72; /* This is where AUTH ends on pre-2003 */
        user_name_len = strlen(username) * 2;
        user_name_offset = domain_name_len + domain_name_offset;

        ntlm_response_offset = user_name_len + user_name_offset; /* relative to start of NTLMSSP */

        /* Get offset to start of Server Challenge and copy it just before where 'temp'
           ends up in the response so we can compute the hmac-md5 as linear buffer.
         */
        memcpy(&usmb2->buf[4 + 64 + 24 + ntlm_response_offset + 8], &usmb2->buf[ntlmssp_in_offset + 24], 8);

 
        /* SessionSetup payload, i.e. NTLMSSP will start at the buffer offset 64 + 24 */
         
        /* Start by moving the TargetInfo buffer we received from the server in the CHALLENGE message
         * to where it will end up at the end of the auth message we are building.
         * Depending on the size of the TargetName, this shifts the offset into the NTLMSSP
         * buffer, but it is usually in the region 70-80 bytes for shortish target names.
         * In the AUTH we are building the LmChallengeResponse data often ends up laid
         * your starting at offset ~110 and the AvPairs are laid out another 16 + 28 bytes into that.
         */
        target_info_len = le16toh(*(uint16_t *)&usmb2->buf[ntlmssp_in_offset + 40]);
        target_info = &usmb2->buf[ntlmssp_in_offset + le32toh(*(uint32_t *)&usmb2->buf[ntlmssp_in_offset + 44])];

        /* Copy everything except the trailing EndOfList */

        z = 0;
        while(1) {
                at_type = le16toh(*(uint16_t *)&target_info[z]);
                at_len = le16toh(*(uint16_t *)&target_info[z + 2]);
                if (at_type == 0) {
                        break;
                }
                z += 4 + at_len;
        }
        offset = 4 + 64 + 24 + ntlm_response_offset + 16 + 28; // AvPairs
        memcpy(&usmb2->buf[offset], target_info, z);
        
        /* Add TargetName Av entry to the end */
        offset += z;
        *(uint16_t *)&usmb2->buf[offset] = htole16(9);
        *(uint16_t *)&usmb2->buf[offset + 2] = htole16(10 + domain_name_len);
        offset += 4;
        *(uint16_t *)&usmb2->buf[offset] = htole16('c');
        offset += 2;
        *(uint16_t *)&usmb2->buf[offset] = htole16('i');
        offset += 2;
        *(uint16_t *)&usmb2->buf[offset] = htole16('f');
        offset += 2;
        *(uint16_t *)&usmb2->buf[offset] = htole16('s');
        offset += 2;
        *(uint16_t *)&usmb2->buf[offset] = htole16('/');
        offset += 2;
        memcpy(&usmb2->buf[offset], domain_name, domain_name_len);
        offset += domain_name_len;
        
        /* and a final EndOfList plus 4 bytes of padding*/
        memset(&usmb2->buf[offset], 0, 8);
        offset += 8;
        out_pdu_size = offset;
                
        /*
         * Domain name. Copy to proper offset in the output  buffer and update length/offset.
         */
        memcpy(&usmb2->buf[4 + 64 + 24 + domain_name_offset], domain_name, domain_name_len);
        domain_name = &usmb2->buf[4 + 64 + 24 + domain_name_offset];
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 28] = htole32(domain_name_len << 16 | domain_name_len);
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 32] = htole32(domain_name_offset);

        /*
         * NT Response
         */
        at_type = out_pdu_size - 4 - 64 - 24 - ntlm_response_offset;
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 20] = htole32(at_type << 16 | at_type);
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 24] = htole32(ntlm_response_offset);
          
        /*
         * User name
         */
        for(at_type = 0; at_type < user_name_len;) {
                usmb2->buf[4 + 64 + 24 + user_name_offset + at_type++] = username[at_type >> 1];
                usmb2->buf[4 + 64 + 24 + user_name_offset + at_type++] = 0;
        }
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 36] = htole32(user_name_len << 16 | user_name_len);
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 40] = htole32(user_name_offset);
        /*
         * Host name and remaining fields
         */
        memset(&usmb2->buf[ntlmssp_out_offset + 44], 0, 12);

        /* Negotiate flags */
        *(uint32_t *)&usmb2->buf[ntlmssp_out_offset + 56] = htole32(0x20088037);

        /* Version */
        memset(&usmb2->buf[ntlmssp_out_offset + 60], 0, 8);

        memcpy(&usmb2->buf[4 + 64 + 24], "NTLMSSP", 8);
        memset(&usmb2->buf[4 + 64 + 24 + 8], 0, 12);
        usmb2->buf[4 + 64 + 24 + 8] = 3;

        
        
        /* Generate NTOWFv1 */
        MD4Init(&ctx);
        zero = 0;
        while (*password) {
                MD4Update(&ctx, password++, 1);
                MD4Update(&ctx, &zero, 1);
        }
        MD4Final(NTOWFv1, &ctx);

        /* Compute NTOWFv2 */
        hmac_md5(username,
                 NULL, 0,
                 domain_name, domain_name_len,
                 NTOWFv1, 16, NTOWFv2);

        /*
         * Clear beginning of ntlmv2 response and fill in all non-zero parts
         */
        memset(&usmb2->buf[4 + 64 + 24 + ntlm_response_offset + 16], 0, 28);
        /* resp type and hi resp type */
        *(uint16_t *)&usmb2->buf[4 + 64 + 24 + ntlm_response_offset + 16] = 0x0101;
        /* client challenge QQQQ */
        memset(&usmb2->buf[4 + 64 + 24 + ntlm_response_offset + 32], 1, 8);
        
        
        at_type = 4 + 64 + 24 + ntlm_response_offset;
        at_len = out_pdu_size - 4 - 64 - 24 - ntlm_response_offset;
        
        hmac_md5(NULL,
                 &usmb2->buf[at_type + 8],  at_len - 8,
                 NULL, 0,
                 NTOWFv2, 16, NTProofStr);
        memcpy(&usmb2->buf[4 + 64 + 24 + ntlm_response_offset], NTProofStr, 16);
        
        
        return out_pdu_size - 4 - 64 - 24;
}

#endif /* USMB2_FEATURE_NTLM */
