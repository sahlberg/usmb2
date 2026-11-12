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
#define STATUS_PENDING          0x00000103
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

static void send_rqst_to_socket(void)
{
#ifdef USMB2_FEATURE_REASSEMBLY
        /* Open the window for the whole reply, which then comes at once */
        tcp_send(usmb2_tcp, send_pos, NULL, USMB2_REASSEMBLY_SIZE);
#else
        tcp_send(usmb2_tcp, send_pos, NULL, 0);
#endif
        send_pos = 0;
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
        
/* Reads up to len bytes of the rest of the reply, *left bytes, to buf.
 * Returns how many it read.
 */
static int read_reply(struct usmb2_context *usmb2, uint8_t *buf, int len, uint32_t *left)
{
        if ((uint32_t)len > *left) {
                len = *left;
        }
        read_from_socket(usmb2, buf, len);
        *left -= len;
        return len;
}

/* Clears buf and returns where the command header of the request goes */
static uint8_t *usmb2_cmd_hdr(struct usmb2_context *usmb2)
{
        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        return &usmb2->buf[4 + 64];
}

/* Sends the request in buf, which must start out zeroed, and outdata, and
 * reads the reply: the command header to buf and the data to indata.
 * outdata and indata may be NULL if their count is 0.
 * Returns the status.
 */
static uint32_t usmb2_build_request(struct usmb2_context *usmb2,
                               int command, int commandoutcount, int commandincount,
                               uint8_t *outdata, int outdatacount,
                               uint8_t *indata, int indatacount)
{
        uint8_t *hdr = &usmb2->buf[4];
        uint32_t spl, current_mid, status;
        unsigned int len = 64 + commandoutcount + outdatacount;

        /*
         * SPL, 32 bits big-endian. Our requests are always shorter than 64 kbyte.
         */
        usmb2->buf[2] = len >> 8;
        usmb2->buf[3] = len;

        /*
         * SMB2 header. Fields that are not set here are zero.
         */
        /* signature */
        memcpy(&hdr[0], "\xfeSMB", 4);
        /* header length */
        hdr[4] = 64;
        /* Credit charge in smb2 is 1 per 64kb requested but we never read > 2048 bytes
         * so we can hardcode it to 1. NEGOTIATE PROTOCOL must have 0.
         */
        hdr[6] = command != CMD_NEGOTIATE_PROTOCOL;
        /* command + credit request */
        hdr[12] = command;
        hdr[14] = 1;
        /* message id, 64 bits but the top 32 are zero */
        current_mid = usmb2->message_id++;
        *(uint32_t *)&hdr[24] = htole32(current_mid);
        /* tree id */
        *(uint32_t *)&hdr[36] = htole32(usmb2->tree_id);
        /* session id */
        *(uint64_t *)&hdr[40] = usmb2->session_id;

        /*
         * Write the request and the payload data to the socket
         */
        write_to_socket(usmb2, &usmb2->buf[0], 4 + 64 + commandoutcount);
        write_to_socket(usmb2, outdata, outdatacount);

#ifdef USMB2_FEATURE_TINY_TCP
        send_rqst_to_socket();
#endif

 again:
#ifdef USMB2_FEATURE_TINY_TCP
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
         * Read SPL and the SMB2 header to the start of buf
         */
        read_from_socket(usmb2, usmb2->buf, 4 + 64);
        spl = ntohl(*(uint32_t *)usmb2->buf) - 64;
        hdr = &usmb2->buf[4];

        if (command == CMD_SESSION_SETUP) {
                usmb2->session_id = *(uint64_t *)&hdr[40];
        }
        if (command == CMD_TREE_CONNECT) {
                usmb2->tree_id = *(uint32_t *)&hdr[36];
        }

        /*
         * Status, fail hard if not successful.
         * Read status before we read all the padding data into buf, potentially overwriting the smb2 header.
         * .. NegotiateProtocol contexts entered the chat ...
         */
        status = le32toh(*(uint32_t *)&hdr[8]);

        /*
         * An interim reply ([MS-SMB2] 3.3.4.2), which a server sends when the
         * request takes a while: the real one, with the same message id,
         * comes later. Reading the interim one as the reply would put us out
         * of step, so skip its body and wait for the next. The tiny TCP stack
         * already has it all and starts afresh with the next reply.
         */
        if (status == STATUS_PENDING) {
#ifndef USMB2_FEATURE_TINY_TCP
                read_reply(usmb2, usmb2->buf, sizeof(usmb2->buf), &spl);
                if (usmb2->fd >= 0)
#endif
                goto again;
        }

        /*
         * Read command header, then the data
         */
        commandincount = read_reply(usmb2, &usmb2->buf[0], commandincount, &spl);
        read_reply(usmb2, indata, indatacount, &spl);
        
        /*
         * Read padding, and anything else the server sent, into buf after the
         * command, a buffer full at a time: a reply with more data than we
         * asked for must not run past the end of buf.
         */
        while (spl) {
                read_reply(usmb2, &usmb2->buf[commandincount],
                           sizeof(usmb2->buf) - commandincount, &spl);
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
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + DialectCount=1. SecurityMode=0, Capabilities=0 */
        *(uint32_t *)&ptr[0] = htole32(0x00010024);
        /* client guid */
        ptr[12] = 0xaa;
        ptr[27] = 0xbb;
        /* dialects 3.00 */
        ptr[37] = 0x03;

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
        uint8_t *ptr = &usmb2->buf[4 + 64 + 24 + 8];
        if (cmd == 1) {
                /* NTLMSSP_NEGOTIATE */
                ptr[0] = cmd;
                /* flags qqq trim this down  */
                *(uint32_t *)&ptr[4] = htole32(0x20080227);
                
                return 32;
        }
#ifndef USMB2_FEATURE_NTLM
        if (cmd == 3) {
                /* NTLMSSP_AUTH */
                ptr[0] = cmd;
                /* flags qqq trim this down */
                *(uint32_t *)&ptr[0x34] = htole32(0x20088817);
                
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
        uint8_t *ptr = &usmb2->buf[4 + 64];

        cmd = 1;

 again:
#ifdef USMB2_FEATURE_NTLM
        if (cmd == 3) {
                len = ntlm_generate_auth(usmb2, usmb2->username, usmb2->password);
                memset(usmb2->buf, 0, 4 + 64 + 24);
        } else
#endif /* USMB2_FEATURE_NTLM */
        {
                memset(usmb2->buf, 0, sizeof(usmb2->buf));
                len = create_ntlmssp_blob(usmb2, cmd);
        }
        memcpy(&usmb2->buf[4 + 64 + 24], "NTLMSSP", 8);

        /*
         * Command header
         */
        /* struct size (16 bits), Flags=0 */
        ptr[0] = 0x19;
        /* buffer offset and buffer length */
        ptr[12] = 0x58;
        *(uint16_t *)&ptr[14] = htole16(len);

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

/* Writes name to ptr in UCS2 and returns its length in bytes */
static int usmb2_put_name(uint8_t *ptr, const char *name)
{
#ifdef USMB2_FEATURE_UNICODE
        return utf8_to_utf16(name, (uint16_t *)ptr) * 2;
#else /* USMB2_FEATURE_UNICODE */
        int len = 0;

        while (*name) {
                ptr[len] = *name++;
                len += 2;
        }
        return len;
#endif /* USMB2_FEATURE_UNICODE */
}

/* TREE CONNECT */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc)
{
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        int len;

        /*
         * Command header
         */
        /* struct size (16 bits) */
        ptr[0] = 0x09;
        /* unc offset */
        ptr[4] = 0x48;
        /* unc length in bytes. i.e. 2 times the number of ucs2 characters */
        len = usmb2_put_name(&usmb2->buf[4 + 0x48], unc);
        *(uint16_t *)&ptr[6] = htole16(len);

        if (usmb2_build_request(usmb2,
                                CMD_TREE_CONNECT, 8 + len, 16,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return 0;
}

/* CREATE. Returns the file id in a buffer of size bytes, or NULL.
 * del is the third byte of the desired access and the second byte of the
 * create options, for DELETE and DELETE_ON_CLOSE.
 */
static uint8_t *usmb2_create(struct usmb2_context *usmb2, const char *name,
                             uint8_t da, uint8_t di, uint8_t co, uint8_t fa,
                             uint16_t del, int size)
{
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        int len;

        /*
         * Command header
         */
        /* struct size (16 bits) */
        ptr[0] = 0x39;
        /* impersonation level 2 */
        ptr[4] = 0x02;
        /* desired access */
        ptr[24] = da;
        ptr[26] = del;
        /* file attributes */
        ptr[28] = fa;
        /* share access : READ, WRITE */
        ptr[32] = 0x03;
        /* create disposition */
        ptr[36] = di;
        /* create options */
        ptr[40] = co;
        ptr[41] = del >> 8;
        /* name offset */
        ptr[44] = 0x78;
        len = usmb2_put_name(&usmb2->buf[4 + 0x78], name);
        /* name length in bytes. i.e. 2 times the number of ucs2 characters */
        *(uint16_t *)&ptr[46] = htole16(len);

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

#ifdef USMB2_FEATURE_OPENDIR
        return usmb2_create(usmb2, name, da, di, co, fa, 0,
                            (mode & O_DIRECTORY) ? 16 + MAX_DIR_SIZE : 16);
#else
        return usmb2_create(usmb2, name, da, di, co, fa, 0, 16);
#endif
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
 *
 * The directory handle is the FileId, 16 bytes, then where the next entry is
 * counting from the end of the FileId, 4 bytes, 0 when we need to ask the
 * server for more, then MAX_DIR_SIZE - 4 bytes of QUERY_DIRECTORY reply.
 */
uint8_t *usmb2_readdir(struct usmb2_context *usmb2, uint8_t *dh)
{
        uint8_t *ptr, *de;
        unsigned int pos, next, len, i;
        
        if (!*(uint32_t *)&dh[16]) {
                ptr = usmb2_cmd_hdr(usmb2);
                /*
                 * Command header
                 */
                /* struct size (16 bits) */
                ptr[0] = 0x21;
                /* FILE_DIRECTORY_INFORMATION */
                ptr[2] = 0x01;
                /* FileId, after the file index which is 0 */
                memcpy(&ptr[8], dh, 16);
                /* FileNameOffset */
                ptr[24] = 0x60;
                /* FileNameLength */
                ptr[26] = 0x02;
                /* OutputBufferLength */
                *(uint32_t *)&ptr[28] = htole32(MAX_DIR_SIZE - 4);
                /* FileName */
                ptr[32] = '*';
                
                if (usmb2_build_request(usmb2,
                                        CMD_QUERYDIR, 40, 8,
                                        NULL, 0, NULL, 0)) {
                        return NULL;
                }
                
                memcpy(&dh[16 + 4], &usmb2->buf[8], le32toh(*(uint32_t *)&usmb2->buf[4]));
                *(uint32_t *)&dh[16] = 4;
        }
        pos = le32toh(*(uint32_t *)&dh[16]);
        de = &dh[16 + pos];
        next = le32toh(*(uint32_t *)de);
        /* Where the next entry is, or 0 to read more from the server */
        *(uint32_t *)&dh[16] = next ? pos + next : 0;

        /* file name length, then the file name */
        len = le32toh(*(uint32_t *)&de[0x3c]) >> 1;
        ptr = &de[0x40];
#ifdef USMB2_FEATURE_UNICODE
        i = utf16_to_utf8((uint16_t *)ptr, len);
#else /* USMB2_FEATURE_UNICODE */
        for(i = 0; i < len; i++) {
                /* No unicode support so assume the world is 7-bit ASCII clean */
                ptr[i] = ptr[i * 2];
        }
#endif /* USMB2_FEATURE_UNICODE */
        ptr[i] = 0;
        return de;
}

#endif /* USMB2_FEATURE_OPENDIR */


int32_t usmb2_prw(struct usmb2_context *usmb2, int cmd, uint8_t *fid, uint8_t *rbuf, uint8_t *wbuf, int count, uint64_t offset)
{
        uint32_t u32;
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) */
        ptr[0] = 0x31;
        if (cmd == CMD_WRITE) {
                /* data offset */
                ptr[2] = 0x70;
        }
        /* length */
        *(uint32_t *)&ptr[4] = htole32(count);
        /* offset */
        *(uint64_t *)&ptr[8] = htole64(offset);
        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(&ptr[16], fid, 16);

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
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) */
        ptr[0] = 0x18;
        /* flags: POSTQUERY_ATTRIB */
        ptr[2] = 0x01;
        /* fid */
        memcpy(&ptr[8], fid, 16);

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

        usmb2_cmd_hdr(usmb2);
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
        *(uint16_t *)&usmb2->buf[4 + 0x60 + 16] = htole16(len);
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
        uint8_t *ptr = usmb2_cmd_hdr(usmb2);
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)&ptr[0] = htole32(0x05010029);
        /* output buffer length */
        *(uint32_t *)&ptr[4] = htole32(0x0000ffff);
        /* input buffer offset */
        ptr[8] = 0x68;
        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(&ptr[24], fid, 16);

        if (usmb2_build_request(usmb2,
                                CMD_QUERYINFO, 40, 8,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return le32toh(*(uint32_t *)&usmb2->buf[8 + 8]);
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
