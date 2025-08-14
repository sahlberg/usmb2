/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* PS2IOP does not use read/write to access the socket but lwip calls.
   it will need this:

#define write(a,b,c) lwip_send(a,b,c,0)
#define read(a,b,c) lwip_recv(a,b,c,0)

*/
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "usmb2.h"
#ifdef USMB2_FEATURE_NTLM
#include "ntlm.h"
#endif /* USMB2_FEATURE_NTLM */

#define CMD_NEGOTIATE_PROTOCOL  0
#define CMD_SESSION_SETUP       1
#define CMD_TREE_CONNECT        3
#define CMD_CREATE              5
#define CMD_READ                8
#define CMD_WRITE               9
#define CMD_GETINFO            16

#define STATUS_SUCCESS          0x00000000
#define STATUS_MORE_PROCESSING  0xc0000016


/*
 * Special bufferless usmb2 implementation
 * Replace with code to integrate with the stack.  API is
 *
 * get_buffer()  This returns to usmb2 a pointer to a static buffer where the TCP payload is
 *               held.  Idea is that a stack might keep a single buffer for i/o
 *               that is use to both receive TCP segments and also to send segments,
 *               It is assume that this buffer pointer never changes for a tcp session.
 *
 * clear_buffer()  Clear the tcp payload buffer.
 *
 * send_pdu(len) : USMB2 has finishe constructing the SMB2 packet in the tcpo payload buffer.
 *                 Length of tcp payload is 'len' so now the stack should sen the tcp segment
 *                 to the server.
 *
 * len = wait_for_pdu() : wait until a reply is received from the server.  len is the amount of tcp payload
 *               data to process.
 */
 
#define USMB2_SIZE 4096
uint8_t buffer[USMB2_SIZE];

static uint8_t *get_buffer()
{
        return &buffer[0];
}
static void clear_buffer(struct usmb2_context *usmb2)
{
        memset(&usmb2->buff[0], 0, USMB2_SIZE);
}
/* We are finished building the PDUin the buffer. Size is 'len' bytes */
static int send_pdu(struct usmb2_context *usmb2, uint8_t *buf, int len)
{
        int count;
        
        while (len) {
                count = write(usmb2->fd, buf, len);
                if (count < 0) {
                        return -1;
                }
                len -= count;
                buf += count;
        }
        return 0;
}


static int read_from_socket(struct usmb2_context *usmb2, uint8_t *buf, int len)
{ 
        int count;
        
        while (len) {
                count = read(usmb2->fd, buf, len);
                if (count < 0) {
                        return -1;
                }
                len -= count;
                buf += count;
        }
        return 0;
}

static int wait_for_pdu(struct usmb2_context *usmb2)
{ 
        uint32_t spl;

        read_from_socket(usmb2, (uint8_t *)&spl, 4);
        spl = ntohl(spl);

        read_from_socket(usmb2, usmb2->buff, spl);
        
        return spl;
}

/*
 * End of  Special bufferless usmb2 implementation
 */




static int usmb2_build_request(struct usmb2_context *usmb2,
                               int command, int commandoutcount, int commandincount,
                               uint8_t *outdata, int outdatacount,
                               uint8_t *indata, int indatacount)
{
        uint32_t spl;
        uint8_t *buf = usmb2->buff;
        uint32_t status;
        int write_count = 0;
        
        /*
         * SPL
         */
        spl = 64 + commandoutcount + outdatacount;
        *(uint32_t *)usmb2->buff = htobe32(spl);
        buf += 4;
        
        /*
         * SMB2 header
         */
       
        /* signature */
        *(uint32_t *)buf = htole32(0x424d53fe);
        buf += 4;

        /* header length (16 bits) + credit charge (16 bits)
         * Credit charge in smb2 is 1 per 64kb requested but we never read > 2048 bytes
         * so we can hardcode it to 1.
         */
        if (command != CMD_NEGOTIATE_PROTOCOL) {
                *(uint32_t *)buf = htole32(0x00010040);
        } else {
                *(uint32_t *)buf = htole32(0x00000040);
        }
        buf += 8; /* status, 4 bytes, is zero */
        
        /* command + credit request */
        *(uint32_t *)buf = htole32(0x00010000 + command);
        buf += 12; /* flags and next command are both 0, 8 bytes */

        /* message id. no 64 bit support on zcc */
        *(uint32_t *)buf = htole32(usmb2->message_id++);
        buf += 12; /* 4 extra reserved bytes */

        /* tree id */
        *(uint32_t *)buf = htole32(usmb2->tree_id);
        buf += 4;

        /* session id */
        memcpy(buf, usmb2->session_id, 8);
        buf += 24; /* 16 byte signature is all zero */


        /*
         * Skip command. We already wrote it into the buffer.
         */
        write_count += 4 + 64 + commandoutcount;
        spl -= 64 + commandoutcount;
        
        /*
         * Copy payload to the buffer
         */
        if (outdata) {
                memcpy(usmb2->buff + write_count, outdata, outdatacount);
                write_count += outdatacount;
                spl -= outdatacount;
        }

        /*
         * Padding
         */
        if (spl) {
                write_count += spl;
        }
        /*
         * Write the request to the socket
         */
        send_pdu(usmb2, usmb2->buff, write_count);




        /*
         * Wait for the next PDU. Return value is size of PDU.
         */
        spl = wait_for_pdu(usmb2);

        /*
         * Skip the spl and smb2 header
         */
        spl -= 64;

        if (command == CMD_SESSION_SETUP) {
                memcpy(usmb2->session_id, usmb2->buff + 0x28, 8);
        }
        if (command == CMD_TREE_CONNECT) {
                usmb2->tree_id = *(uint32_t *)(usmb2->buff + 0x24);
        }

        //qqq handle keepalives
        
        /*
         * Read status before we read all the padding data into buf, potentially overwriting the smb2 header.
         * .. NegotiateProtocol contexts entered the chat ...
         */
        status = le32toh(*(uint32_t *)(usmb2->buff + 8));

        /* The memmove we do here, we only need to do this for SessionSetup
         * Fix that so we don't do it for every single READ too
         */
        /*
         * Finished with the header. Now copy the command header and payload to start of buffer.
         * We need to do this for SessionSetup to move the fields in this reply furhter away
         * from where ntlm will memcpy then when building the request (using the same buffer)
         * to make sure they do not overlap and corrupt.
         */
        if (commandincount > spl) {
                commandincount = spl;
        }
        memmove(usmb2->buff, usmb2->buff + 64, spl);
        spl -= commandincount;

        /*
         * Read data
         */
        if (indata) {
                if (indatacount > spl) {
                        indatacount = spl;
                }
                memcpy(indata, usmb2->buff + commandincount, indatacount);
                spl -= indatacount;
        }
        
        /*
         * Skip padding
         */

        return status;
}

/* NEGOTIATE PROTOCOL */
int usmb2_negotiateprotocol(struct usmb2_context *usmb2)
{
        uint8_t *ptr = usmb2->buff + 4 + 64;

        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + DialectCount=1 */
        *(uint32_t *)ptr = htole32(0x00010024);
        ptr += 12; /* SecurityMode=0, Capabilities=0 */

        /* client guid */
        ptr[0] = 0xaa;
        ptr[15] = 0xbb;
        ptr += 24;

        /* dialects 3.00 */
         *(uint32_t *)ptr = htole32(0x0000300);

        if (usmb2_build_request(usmb2,
                                CMD_NEGOTIATE_PROTOCOL, 40, 64,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }
        /* reply is in usmb2->buff */
        
        return 0;
}

static int create_ntlmssp_blob(struct usmb2_context *usmb2, int cmd)
{
        uint8_t *ptr;

        ptr = usmb2->buff + 4 + 64 + 24;
        memcpy(ptr, "NTLMSSP", 7);
        ptr += 8;
        if (cmd == 1) {
                /* NTLMSSP_NEGOTIATE */
                *ptr = cmd;
                ptr += 4;
                /* flags qqq trim this down  */
                *(uint32_t *)ptr = htole32(0x20080227);
                
                return 32;
        }
        if (cmd == 3) {
                /* NTLMSSP_AUTH */
                *ptr = cmd;
                ptr += 0x34;
                /* flags qqq trim this down */
                *(uint32_t *)ptr = htole32(0x20088817);
                
                return 72;
        }
        return -1;
}

/* SESSION_SETUP */
int usmb2_sessionsetup(struct usmb2_context *usmb2)
{
        int len, cmd;
        uint32_t status;
        uint8_t *ptr;

        cmd = 1;

 again:
#ifdef USMB2_FEATURE_NTLM
        if (cmd == 3) {
                len = ntlm_generate_auth(usmb2, usmb2->username, usmb2->password);
                memset(usmb2->buff, 0, 4 + 64 + 24);
        } else {
                clear_buffer(usmb2);
                len = create_ntlmssp_blob(usmb2, cmd);
        }
#else
        clear_buffer(usmb2);
        len = create_ntlmssp_blob(usmb2, cmd);
#endif /* USMB2_FEATURE_NTLM */

        /*
         * Command header
         */
        /* struct size (16 bits) + Flags=0 */
        *(uint32_t *)(usmb2->buff + 4 + 64) = htole32(0x00000019);

        /* buffer offset and buffer length */
        ptr = usmb2->buff + 4 + 64 + 12;
        *ptr = 0x58;
        ptr += 2;
        *(uint16_t *)ptr = htole16(len);
        
        status = usmb2_build_request(usmb2,
                                     CMD_SESSION_SETUP, (24 + len + 7) & 0xfff8, 64,
                                     NULL, 0, NULL, 0);
        if (cmd == 1 && status == STATUS_MORE_PROCESSING) {
                cmd = 3;
                goto again;
        }
        if (status) {
                   return -1;
        }
        /* reply is in usmb2->buff */
        
        return 0;
}

/* TREE CONNECT */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc)
{
        int len = strlen(unc) * 2;
        uint8_t *ptr;

        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) */
        *(usmb2->buff + 4 + 64) = 0x09;
        /* unc offset */
        *(usmb2->buff + 4 + 64 + 4) = 0x48;
        /* unc length in bytes. i.e. 2 times the number of ucs2 characters */
        *(usmb2->buff + 4 + 64 + 6) = len;


        ptr = usmb2->buff + 4 + 0x48;
        while (*unc) {
                *ptr = *unc++;
                ptr += 2;
        }

        if (usmb2_build_request(usmb2,
                                CMD_TREE_CONNECT, 8 + len, 16,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return 0;
}

/* OPEN */
uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode)
{
        int len = strlen(name) * 2;
        uint8_t *ptr, da, di;

        da = 0x89; /* desided access : READ, READ EA, READ ATTRIBUTES */
        di = 0x01; /* create disposition: open  if file exist open it, else fail */
#ifdef USMB2_FEATURE_WRITE
        if (mode == O_RDWR) {
                da = 0x8b; /* desided access : READ, WRITE, READ EA, READ ATTRIBUTES */
                di = 0x03; /* create disposition: open the file if it exists, otherwise create it */
        }
#endif /* USMB2_FEATURE_WRITE */
        
        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) */
        *(usmb2->buff + 4 + 64) = 0x39;
        /* impersonation level 2 */
        *(usmb2->buff + 4 + 64 +  4) = 0x02;
        /* desired access */
        *(usmb2->buff + 4 + 64 + 24) = da;
        /* share access : READ, WRITE */
        *(usmb2->buff + 4 + 64 + 32) = 0x03;
        /* create disposition */
        *(usmb2->buff + 4 + 64 + 36) = di;
        /* create options */
        *(usmb2->buff + 4 + 64 + 40) = 0x40;
        /* name offset */
        *(usmb2->buff + 4 + 64 + 44) = 0x78;
        /* name length in bytes. i.e. 2 times the number of ucs2 characters */
        *(usmb2->buff + 4 + 64 + 46) = len;

        ptr = usmb2->buff + 4 + 0x78;
        while (*name) {
                *ptr = *name++;
                ptr += 2;
        }


        if (usmb2_build_request(usmb2,
                                CMD_CREATE, 0x38 + len, 88,
                                NULL, 0, NULL, 0)) {
                   return NULL;
        }

        ptr = malloc(16);
        if (ptr) {
                memcpy(ptr, usmb2->buff + 64, 16);
        }
        return ptr;
}


/* READ */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint32_t offset)
{
        uint32_t u32;
        uint8_t *ptr = usmb2->buff + 4 + 64;

        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)ptr = htole32(0x00000031);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(count);
        ptr += 4;

        /* offset */
        *(uint32_t *)ptr = htole32(offset);
        ptr += 8;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        
        if (usmb2_build_request(usmb2,
                                CMD_READ, 48 + 8, 16,
                                NULL, 0, buf, count)) {
                   return -1;
        }

        /* number of bytes returned */
        u32 = le32toh(*(uint32_t *)(usmb2->buff + 4));

        return u32;
}

#ifdef USMB2_FEATURE_WRITE
/* WRITE */
int usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint32_t offset)
{
        uint8_t *ptr = usmb2->buff + 4 + 64;

        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + data offset == 0x70 */
        *(uint32_t *)ptr = htole32(0x00700031);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(count);
        ptr += 4;

        /* offset */
        *(uint32_t *)ptr = htole32(offset);
        ptr += 8;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);
        
        if (usmb2_build_request(usmb2,
                                CMD_WRITE, 48, 16,
                                buf, count, NULL, 0)) {
                   return -1;
        }

        /* number of bytes returned */
        return le32toh(*(uint32_t *)(usmb2->buff + 4));
}
#endif /* USMB2_FEATURE_WRITE */


/* SIZE in bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
{
        uint8_t *ptr = usmb2->buff + 4 + 64;

        clear_buffer(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)ptr = htole32(0x05010029);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(0x0000ffff);
        ptr += 4;

        /* offset */
        *(uint64_t *)ptr = htole64(0x00000068);
        ptr += 16;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        if (usmb2_build_request(usmb2,
                                CMD_GETINFO, 40, 8,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return le64toh(*(uint32_t *)(usmb2->buff + 8 + 8));
}

struct usmb2_context *usmb2_init_context(uint32_t ip, char *username, char *password)
{
        struct usmb2_context *usmb2;
        struct sockaddr_in sin;
        int socksize = sizeof(struct sockaddr_in);
        
        usmb2 = calloc(1, sizeof(struct usmb2_context));
        if (usmb2 == NULL) {
                return NULL;
        }

        usmb2->buff = get_buffer();
        usmb2->username = strdup(username);
        usmb2->password = strdup(password);
#if 0        
        usmb2->fd = socket(AF_INET, SOCK_STREAM, 0);

        sin.sin_family = AF_INET;
        sin.sin_port = htons(445);
        memcpy(&sin.sin_addr, &ip, 4);
#ifdef HAVE_SOCK_SIN_LEN
        sin.sin_len = socksize;
#endif
        if (connect(usmb2->fd, (struct sockaddr *)&sin, socksize) != 0) {
                free(usmb2);
                return NULL;
        }
#endif
        if (usmb2_negotiateprotocol(usmb2)) {
                free(usmb2);
                return NULL;
        }

        if (usmb2_sessionsetup(usmb2)) {
                free(usmb2);
                return NULL;
        }
        
        return usmb2;
}
