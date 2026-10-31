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
#if defined(_IOP)
#include "ps2iop-compat.h"
#else

#if !defined(Z80)
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#include <net/hton.h>
#endif

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>

#include "usmb2.h"
#ifdef USMB2_FEATURE_TINY_TCP
#include "ip.h"
#include "tcp.h"
#endif
#ifdef USMB2_FEATURE_NTLM
#include "ntlm.h"
#endif /* USMB2_FEATURE_NTLM */
#ifdef USMB2_FEATURE_UNICODE
#include "unicode.h"
#endif /* USMB2_FEATURE_UNICODE */

#define CMD_NEGOTIATE_PROTOCOL  0
#define CMD_SESSION_SETUP       1
#define CMD_TREE_CONNECT        3
#define CMD_CREATE              5
#define CMD_CLOSE               6
#define CMD_READ                8
#define CMD_WRITE               9
#define CMD_QUERYDIR           14
#define CMD_QUERYINFO          16
#define CMD_SETINFO            17

#define STATUS_SUCCESS          0x00000000
#define STATUS_MORE_PROCESSING  0xc0000016
#define STATUS_CONNECTION_DISCONNECTED 0xc000020c

/* Amount of QUERY_DIR payload to store in the directory handle */
#define MAX_DIR_SIZE 256


#ifdef USMB2_FEATURE_TINY_TCP
tcp_context_t *usmb2_tcp;

static int recv_pos = 0;

#ifdef USMB2_FEATURE_REASSEMBLY
/* Big enough for the reply to a 2 kbyte READ: SPL, SMB2 and READ headers */
#ifndef USMB2_REASSEMBLY_SIZE
#define USMB2_REASSEMBLY_SIZE (4 + 64 + 16 + 2048)
#endif
/* Replies that take more than one TCP segment are collected here */
static uint8_t reasm[USMB2_REASSEMBLY_SIZE];
#endif /* USMB2_FEATURE_REASSEMBLY */

static int recv_reply_from_socket(uint32_t wanted_mid)
{
        int rc;
        uint8_t *ptr;
        uint32_t mid;
#ifdef USMB2_FEATURE_REASSEMBLY
        uint32_t spl;
        int len = 0;
#endif /* USMB2_FEATURE_REASSEMBLY */

        recv_pos = 0;
 again:
        /* Open the window for the reply, tcp_recv() clamps it to the buffer */
        rc = tcp_recv(usmb2_tcp, usmb2_tcp->ip.pkt_size);
        if (rc < 0) {
                return -1;
        }
        if (rc == 0) {
                goto again;
        }
        ptr = tcp_rx_buffer(usmb2_tcp);
#ifdef USMB2_FEATURE_REASSEMBLY
        if (len + rc > USMB2_REASSEMBLY_SIZE) {
                return -1;
        }
        memcpy(&reasm[len], ptr, rc);
        len += rc;
        /* Wait for the rest of the PDU: SPL is its size, without the SPL */
        if (len < 4) {
                goto again;
        }
        memcpy(&spl, reasm, 4);
        spl = ntohl(spl);
        if (spl > USMB2_REASSEMBLY_SIZE - 4) {
                return -1;
        }
        if (len < 4 + (int)spl) {
                goto again;
        }
        ptr = reasm;
        len = 0;
#endif /* USMB2_FEATURE_REASSEMBLY */
        memcpy(&mid, &ptr[28], 4);
        mid = htole32(mid);
        if (mid != wanted_mid) {
                goto again;
        }

        return 0;
}


static int send_pos = 0;

static int send_rqst_to_socket(void)
{
        int rc;

#ifdef USMB2_FEATURE_REASSEMBLY
        /* Open the window for the whole reply, which then comes at once */
        rc = tcp_send(usmb2_tcp, send_pos, NULL, USMB2_REASSEMBLY_SIZE);
#else
        rc = tcp_send(usmb2_tcp, send_pos, NULL, 0);
#endif
        send_pos = 0;
        
        return 0;
}
#endif

#ifndef USMB2_FEATURE_TINY_TCP
/* Closes the socket so that all further reads and writes fail at once */
static int socket_failed(struct usmb2_context *usmb2)
{
        if (usmb2->fd >= 0) {
                close(usmb2->fd);
                usmb2->fd = -1;
        }
        return -1;
}
#endif

static int write_to_socket(struct usmb2_context *usmb2, uint8_t *buf, int len)
{
#ifdef USMB2_FEATURE_TINY_TCP
        uint8_t *ptr;
        ptr = tcp_tx_buffer(usmb2_tcp);

        memcpy(&ptr[send_pos], buf, len);
        send_pos += len;
#else
        int count;
        
        while (len) {
                count = write(usmb2->fd, buf, len);
                if (count <= 0) {
                        return socket_failed(usmb2);
                }
                len -= count;
                buf += count;
        }
#endif
        return 0;
}



static int read_from_socket(struct usmb2_context *usmb2, uint8_t *buf, int len)
{ 
#ifdef USMB2_FEATURE_TINY_TCP
        uint8_t *ptr;
#ifdef USMB2_FEATURE_REASSEMBLY
        ptr = reasm;
#else
        ptr = tcp_rx_buffer(usmb2_tcp);
#endif

        memcpy(buf, &ptr[recv_pos], len);
        recv_pos += len;
#else
        int count;
        
        while (len) {
                count = read(usmb2->fd, buf, len);
                if (count <= 0) {
                        return socket_failed(usmb2);
                }
                len -= count;
                buf += count;
        }
#endif
        return 0;
}
        
static uint32_t usmb2_build_request(struct usmb2_context *usmb2,
                               int command, int commandoutcount, int commandincount,
                               uint8_t *outdata, int outdatacount,
                               uint8_t *indata, int indatacount)
{
        uint32_t spl, current_mid;
        uint8_t *buf = &usmb2->buf[0];
        uint32_t status;

        /*
         * SPL
         */
        spl = 64 + commandoutcount + outdatacount;
        *(uint32_t *)&usmb2->buf[0] = htonl(spl);
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

        /* message id */
        current_mid = usmb2->message_id++;
        *(uint64_t *)buf = htole64(current_mid);
        buf += 12; /* 4 extra reserved bytes */

        /* tree id */
        *(uint32_t *)buf = htole32(usmb2->tree_id);
        buf += 4;

        /* session id */
        *(uint64_t *)buf = usmb2->session_id;
        buf += 24; /* 16 byte signature is all zero */


        /*
         * Write the request to the socket
         */
        write_to_socket(usmb2, &usmb2->buf[0], 4 + 64 + commandoutcount);
        spl -= 64 + commandoutcount;
        
        /*
         * Write payload data to the socket
         */
        if (outdata) {
                write_to_socket(usmb2, outdata, outdatacount);
                spl -= outdatacount;
        }

        /*
         * Write padding
         */
        if (spl) {
                write_to_socket(usmb2, &usmb2->buf[0], (int)spl);
        }

#ifdef USMB2_FEATURE_TINY_TCP
        send_rqst_to_socket();
        
        /* Receive the full request from the TCP layer to a buffer */
#ifdef USMB2_FEATURE_REASSEMBLY
        if (recv_reply_from_socket(current_mid)) {
                return STATUS_CONNECTION_DISCONNECTED;
        }
#else
        recv_reply_from_socket(current_mid);
#endif
#endif

        /*
         * Read SPL, SMB2 header and command reply header (and file info blob) from socket
         */
        read_from_socket(usmb2, (uint8_t *)&spl, 4);
        spl = ntohl(spl);

        /*
         * Read SMB2 header
         */
        read_from_socket(usmb2, &usmb2->buf[0], 64);
        spl -= 64;

        if (command == CMD_SESSION_SETUP) {
                usmb2->session_id = *(uint64_t *)&usmb2->buf[0x28];
        }
        if (command == CMD_TREE_CONNECT) {
                usmb2->tree_id = *(uint32_t *)&usmb2->buf[0x24];
        }

        //qqq handle keepalives
        
        /*
         * Status, fail hard if not successful.  Might need to add a check for pending here.
         * Read status before we read all the padding data into buf, potentially overwriting the smb2 header.
         * .. NegotiateProtocol contexts entered the chat ...
         */
        status = le32toh(*(uint32_t *)&usmb2->buf[8]);

        /*
         * Read command header
         */
        if (commandincount > spl) {
                commandincount = spl;
        }
        read_from_socket(usmb2, &usmb2->buf[0], commandincount);
        spl -= commandincount;

        /*
         * Read data
         */
        if (indata) {
                if (indatacount > spl) {
                        indatacount = spl;
                }
                read_from_socket(usmb2, indata, indatacount);
                spl -= indatacount;
        }
        
        /*
         * Read padding, and anything else the server sent, into buf after the
         * command, a buffer full at a time: a reply with more data than we
         * asked for must not run past the end of buf.
         */
        while (spl) {
                uint32_t n = sizeof(usmb2->buf) - commandincount;

                if (n > spl) {
                        n = spl;
                }
                read_from_socket(usmb2, &usmb2->buf[commandincount], (int)n);
                spl -= n;
        }

#ifndef USMB2_FEATURE_TINY_TCP
        if (usmb2->fd < 0) {
                return STATUS_CONNECTION_DISCONNECTED;
        }
#endif
        return status;
}

/* NEGOTIATE PROTOCOL */
int usmb2_negotiateprotocol(struct usmb2_context *usmb2)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
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
        /* reply is in usmb2->buf */
        
        return 0;
}

static int create_ntlmssp_blob(struct usmb2_context *usmb2, int cmd)
{
        uint8_t *ptr = &usmb2->buf[4 + 64 + 12];

        ptr = &usmb2->buf[4 + 64 + 24 + 8];
        if (cmd == 1) {
                /* NTLMSSP_NEGOTIATE */
                *ptr = cmd;
                ptr += 4;
                /* flags qqq trim this down  */
                *(uint32_t *)ptr = htole32(0x20080227);
                
                return 32;
        }
#ifndef USMB2_FEATURE_NTLM
        if (cmd == 3) {
                /* NTLMSSP_AUTH */
                *ptr = cmd;
                ptr += 0x34;
                /* flags qqq trim this down */
                *(uint32_t *)ptr = htole32(0x20088817);
                
                return 72;
        }
#endif /* !USMB2_FEATURE_NTLM */
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
                memset(usmb2->buf, 0, 4 + 64 + 24);
        } else {
                memset(usmb2->buf, 0, sizeof(usmb2->buf));
                len = create_ntlmssp_blob(usmb2, cmd);
        }
#else
        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        len = create_ntlmssp_blob(usmb2, cmd);
#endif /* USMB2_FEATURE_NTLM */
        memcpy(&usmb2->buf[4 + 64 + 24], "NTLMSSP", 8);

        /*
         * Command header
         */
        /* struct size (16 bits) + Flags=0 */
        *(uint32_t *)&usmb2->buf[4 + 64] = htole32(0x00000019);

        /* buffer offset and buffer length */
        ptr = &usmb2->buf[4 + 64 + 12];
        *ptr = 0x58;
        ptr += 2;
        *(uint16_t *)ptr = htole16(len);

        status = usmb2_build_request(usmb2,
                                     CMD_SESSION_SETUP, (24 + len + 7) & 0xfff8, 64,
                                     NULL, 0, NULL, 0);
        if (status == STATUS_MORE_PROCESSING) {
                cmd = 3;
                goto again;
        }
        if (status) {
                   return -1;
        }
        /* reply is in usmb2->buf */
        
        return 0;
}

/* TREE CONNECT */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc)
{
        int len = strlen(unc) * 2;
        uint8_t *ptr;

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        usmb2->buf[4 + 64] = 0x09;
        /* unc offset */
        usmb2->buf[4 + 64 + 4] = 0x48;
        /* unc length in bytes. i.e. 2 times the number of ucs2 characters */
        usmb2->buf[4 + 64 + 6] = len;


        ptr = &usmb2->buf[4 + 0x48];
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

/* Writes name to ptr in UCS2 and returns its length in bytes */
static int usmb2_put_name(uint8_t *ptr, const char *name)
{
#ifdef USMB2_FEATURE_UNICODE
        return utf8_to_utf16(name, (uint16_t *)ptr) * 2;
#else /* USMB2_FEATURE_UNICODE */
        int len = strlen(name) * 2;

        while (*name) {
                *ptr = *name++;
                ptr += 2;
        }
        return len;
#endif /* USMB2_FEATURE_UNICODE */
}

/* CREATE. Returns the file id in a buffer of size bytes, or NULL.
 * del is the third byte of the desired access and the second byte of the
 * create options, for DELETE and DELETE_ON_CLOSE.
 */
static uint8_t *usmb2_create(struct usmb2_context *usmb2, const char *name,
                             uint8_t da, uint8_t di, uint8_t co, uint8_t fa,
                             uint16_t del, int size)
{
        int len;
        uint8_t *ptr;

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        usmb2->buf[4 + 64] = 0x39;
        /* impersonation level 2 */
        usmb2->buf[4 + 64 +  4] = 0x02;
        /* desired access */
        usmb2->buf[4 + 64 + 24] = da;
        usmb2->buf[4 + 64 + 26] = del;
        /* file attributes */
        usmb2->buf[4 + 64 + 28] = fa;
        /* share access : READ, WRITE */
        usmb2->buf[4 + 64 + 32] = 0x03;
        /* create disposition */
        usmb2->buf[4 + 64 + 36] = di;
        /* create options */
        usmb2->buf[4 + 64 + 40] = co;
        usmb2->buf[4 + 64 + 41] = del >> 8;
        /* name offset */
        usmb2->buf[4 + 64 + 44] = 0x78;
        len = usmb2_put_name(&usmb2->buf[4 + 0x78], name);
        /* name length in bytes. i.e. 2 times the number of ucs2 characters */
        usmb2->buf[4 + 64 + 46] = len;

        if (usmb2_build_request(usmb2,
                                CMD_CREATE, 0x38 + len + 8, 88,
                                NULL, 0, NULL, 0)) {
                   return NULL;
        }

        ptr = calloc(1, size);

        if (ptr) {
                memcpy(ptr, &usmb2->buf[64], 16);
        }
        return ptr;
}

/* OPEN */
uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode)
{
        uint8_t da, di, co, fa;

        da = 0x89; /* desided access : READ, READ EA, READ ATTRIBUTES */
        di = 0x01; /* create disposition: open  if file exist open it, else fail */
        fa = 0x00; /* file attributes: */
        co = 0x40; /* create options: normal file */
#ifdef USMB2_FEATURE_WRITE
        if (mode == O_RDWR) {
                da = 0x8b; /* desided access : READ, WRITE, READ EA, READ ATTRIBUTES */
                di = 0x03; /* create disposition: open the file if it exists, otherwise create it */
        }
#endif /* USMB2_FEATURE_WRITE */
#ifdef USMB2_FEATURE_OPENDIR
        if (mode & O_DIRECTORY) {
                da = 0x81; /* desided access: READ, READ ATTRIBUTES */ //qqq can we skip this???
                fa = 0x10; /* file attributes: DIRECTORY */
                co = 0x01; /* create options: directory */
        }
#endif /* USMB2_FEATURE_OPENDIR */

        return usmb2_create(usmb2, name, da, di, co, fa, 0,
                            (mode & O_DIRECTORY) ? 16 + MAX_DIR_SIZE : 16);
}

#ifdef USMB2_FEATURE_OPENDIR
uint8_t *usmb2_opendir(struct usmb2_context *usmb2, const char *name)
{
        return usmb2_open(usmb2, name, O_RDONLY | O_DIRECTORY);
}

/*
 * Returns a directory entry in [MS-FSCC] 2.4.10 FileDirectoryInformation format.
 * except filename is returned as nul-terminated 7-bit ASCII string.
 * All fields are in little-endian.
 */
uint8_t *usmb2_readdir(struct usmb2_context *usmb2, uint8_t *dh)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];
        uint32_t u32, curr_de, next_de;
        int i;
        
        if (!*(uint32_t *)&dh[16]) {
                memset(usmb2->buf, 0, sizeof(usmb2->buf));
                /*
                 * Command header
                 */
                /* struct size (16 bits) + FILE_DIRECTORY_INFORMATION */
                *(uint32_t *)ptr = htole32(0x00010021);
                ptr += 8; /* file index == 0 */

                /* FileId */
                memcpy(ptr, dh, 16);
                ptr += 16;

                /* FileNameOffset */
                *ptr = 0x60;
                ptr+=2;
                /* FileNameLength */
                *ptr = 0x02;
                ptr+=2;
                /* OutputBufferLength */
                *(uint32_t *)ptr = htole32(MAX_DIR_SIZE - 4);
                ptr += 4;
                /* FileName */
                *ptr = 0x2a;
                
                if (usmb2_build_request(usmb2,
                                        CMD_QUERYDIR, 40, 8,
                                        NULL, 0, NULL, 0)) {
                        return NULL;
                }
                
                u32 = le32toh(*(uint32_t *)&usmb2->buf[4]);
                memcpy(&dh[16 + 4], &usmb2->buf[8], u32);
                *(uint32_t *)&dh[16] = 4;
        }
        curr_de = le32toh(*(uint32_t *)&dh[16]);
        next_de = le32toh(*(uint32_t *)&dh[16 + curr_de]);
        if (next_de) {
                *(uint32_t *)&dh[16] = curr_de + next_de;
        } else {
                *(uint32_t *)&dh[16] = 0;
        }


        /* file name length */
        ptr = &dh[16 + curr_de + 0x3c];
        u32 = le32toh(*(uint32_t *)&ptr[0]) >> 1;
        ptr += 4;
#ifdef USMB2_FEATURE_UNICODE
        i = utf16_to_utf8((uint16_t *)&ptr[0], u32);
#else /* USMB2_FEATURE_UNICODE */
        for(i = 0; i < u32; i++) {
                /* No unicode support so assume the world is 7-bit ASCII clean */
                ptr[i] = ptr[i * 2];
        }
#endif /* USMB2_FEATURE_UNICODE */
        ptr[i] = 0;
        return &dh[16 + curr_de];
}

#endif /* USMB2_FEATURE_OPENDIR */


int32_t usmb2_prw(struct usmb2_context *usmb2, int cmd, uint8_t *fid, uint8_t *rbuf, uint8_t *wbuf, int count, uint64_t offset)
{
        uint32_t u32;
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        *(uint32_t *)ptr = htole32(0x00000031);
        if (cmd == CMD_WRITE) {
                ptr[2] = 0x70;
        }
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(count);
        ptr += 4;

        /* offset */
        *(uint64_t *)ptr = htole64(offset);
        ptr += 8;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        u32 = usmb2_build_request(usmb2,
                                  cmd, 48 + ((cmd == CMD_READ) ? 8 : 0), 16,
                                  wbuf, (cmd == CMD_WRITE) ? count : 0,
                                  rbuf, (cmd == CMD_READ) ? count : 0);
        if (u32) {
                   return u32;
        }

        /* number of bytes returned */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4]);

        return u32;
}

#ifdef USMB2_FEATURE_CLOSE
int usmb2_close(struct usmb2_context *usmb2, uint8_t *fid)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        *(uint32_t *)ptr = htole32(0x00010018);
        ptr += 8;
        
        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        if (usmb2_build_request(usmb2,
                                CMD_CLOSE, 24, 60,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return 0;
}
#endif /* USMB2_FEATURE_CLOSE */


#ifdef USMB2_FEATURE_STAT
int usmb2_stat(struct usmb2_context *usmb2, const char *name, uint8_t *st)
{
        uint8_t *fid;

        /* desired access: READ ATTRIBUTES, of a file or a directory */
        fid = usmb2_create(usmb2, name, 0x80, 0x01, 0x00, 0x00, 0, 16);
        if (fid == NULL) {
                return -1;
        }
        /* CreationTime to FileAttributes in the CREATE reply */
        memcpy(st, &usmb2->buf[8], 56);
        usmb2_close(usmb2, fid);
        free(fid);
        return 0;
}
#endif /* USMB2_FEATURE_STAT */

#ifdef USMB2_FEATURE_MKDIR
int usmb2_mkdir(struct usmb2_context *usmb2, const char *name)
{
        uint8_t *fid;

        /* desired access: READ ATTRIBUTES, create a new directory */
        fid = usmb2_create(usmb2, name, 0x80, 0x02, 0x01, 0x10, 0, 16);
        if (fid == NULL) {
                return -1;
        }
        usmb2_close(usmb2, fid);
        free(fid);
        return 0;
}
#endif /* USMB2_FEATURE_MKDIR */

#ifdef USMB2_FEATURE_UNLINK
int usmb2_delete(struct usmb2_context *usmb2, const char *name, uint8_t co)
{
        uint8_t *fid;
        int rc;

        /* desired access: DELETE, READ ATTRIBUTES. Deleted when we close it */
        fid = usmb2_create(usmb2, name, 0x80, 0x01, co, 0x00, 0x1001, 16);
        if (fid == NULL) {
                return -1;
        }
        rc = usmb2_close(usmb2, fid);
        free(fid);
        return rc;
}
#endif /* USMB2_FEATURE_UNLINK */

#ifdef USMB2_FEATURE_RENAME
int usmb2_rename(struct usmb2_context *usmb2, const char *oldname, const char *newname)
{
        uint8_t *fid;
        int len;

        /* desired access: DELETE, READ ATTRIBUTES, of a file or a directory */
        fid = usmb2_create(usmb2, oldname, 0x80, 0x01, 0x00, 0x00, 0x0001, 16);
        if (fid == NULL) {
                return -1;
        }

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + FileRenameInformation */
        *(uint32_t *)&usmb2->buf[4 + 64] = htole32(0x0a010021);
        /* buffer offset */
        usmb2->buf[4 + 64 + 8] = 0x60;
        /* fid */
        memcpy(&usmb2->buf[4 + 64 + 16], fid, 16);

        /* FileRenameInformation: ReplaceIfExists=0, RootDirectory=0, then the new name */
        len = usmb2_put_name(&usmb2->buf[4 + 0x60 + 20], newname);
        usmb2->buf[4 + 0x60 + 16] = len;
        /* buffer length */
        *(uint16_t *)&usmb2->buf[4 + 64 + 4] = htole16(20 + len);

        len = usmb2_build_request(usmb2,
                                  CMD_SETINFO, 32 + 20 + len, 2,
                                  NULL, 0, NULL, 0) ? -1 : 0;
        usmb2_close(usmb2, fid);
        free(fid);
        return len;
}
#endif /* USMB2_FEATURE_RENAME */

int32_t usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint64_t offset)
{
        return usmb2_prw(usmb2, 8, fid, buf, NULL, count, offset);
}
#ifdef USMB2_FEATURE_WRITE
int32_t usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint64_t offset)
{
        return usmb2_prw(usmb2, 9, fid, NULL, buf, count, offset);
}
#endif /* USMB2_FEATURE_WRITE */

/* SIZE in bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
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
                                CMD_QUERYINFO, 40, 8,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return le64toh(*(uint32_t *)&usmb2->buf[8 + 8]);
}

struct usmb2_context *usmb2_init_context(uint32_t ip, char *username, char *password)
{
        struct usmb2_context *usmb2;
#ifndef USMB2_FEATURE_TINY_TCP
        struct sockaddr_in sin;
        int socksize = sizeof(struct sockaddr_in);
#endif

        usmb2 = calloc(1, sizeof(struct usmb2_context));
        if (usmb2 == NULL) {
                return NULL;
        }

#ifndef USMB2_FEATURE_TINY_TCP
        usmb2->fd = socket(AF_INET, SOCK_STREAM, 0);

        sin.sin_family = AF_INET;
        sin.sin_port = htons(445);
        memcpy(&sin.sin_addr, &ip, 4);
#ifdef HAVE_SOCK_SIN_LEN
        sin.sin_len = socksize;
#endif
        if (connect(usmb2->fd, (struct sockaddr *)&sin, socksize) != 0) {
                goto failed;
        }
#endif

        strcpy(usmb2->username, username);
        strcpy(usmb2->password, password);

        if (usmb2_negotiateprotocol(usmb2)) {
                goto failed;
        }

        if (usmb2_sessionsetup(usmb2)) {
                goto failed;
        }
        
        return usmb2;

 failed:
#ifndef USMB2_FEATURE_TINY_TCP
        if (usmb2->fd >= 0) {
                close(usmb2->fd);
        }
#endif
        free(usmb2);
        return NULL;
}
