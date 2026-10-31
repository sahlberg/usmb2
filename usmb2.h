/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _USMB2_H_
#define _USMB2_H_

#include <stdint.h>

#if defined(Z80)
#define O_DIRECTORY 0x1000
#ifndef USMB2_FEATURE_TINY_TCP
#define USMB2_FEATURE_TINY_TCP
#endif
#endif

#define STATUS_END_OF_FILE       0xC0000011

/*
 * Defines to enable features in usmb2:
 * USMB2_FEATURE_WRITE : Adds support to write to files.
 * USMB2_FEATURE_NTLM  : Adds support for NTLMv2
 * USMB2_FEATURE_OPENDIR : Adds support for opendir/readdir
 * USMB2_FEATURE_UNICODE : Adds support for unicode share and filenames
 * USMB2_FEATURE_TINY_TCP : Talks to the server through the tiny TCP/IP stack
 *                          in z80/ instead of the sockets API. Always on for
 *                          Z80.
 * USMB2_FEATURE_STAT  : Adds usmb2_stat()
 * USMB2_FEATURE_MKDIR : Adds usmb2_mkdir()
 * USMB2_FEATURE_UNLINK : Adds usmb2_unlink() and usmb2_rmdir()
 * USMB2_FEATURE_RENAME : Adds usmb2_rename()
 * The ones below USMB2_FEATURE_UNICODE need, and enable, USMB2_FEATURE_CLOSE.
 */
#if defined(USMB2_FEATURE_STAT) || defined(USMB2_FEATURE_MKDIR) || \
    defined(USMB2_FEATURE_UNLINK) || defined(USMB2_FEATURE_RENAME)
#ifndef USMB2_FEATURE_CLOSE
#define USMB2_FEATURE_CLOSE
#endif
#endif
   
/* The largest buffer we need is for SMB2_CREATE as this PDU contains the full name
 * of the file being opened in UCS2, 2 bytes per character.
 *   4 bytes SPL
 *  64 bytes SMB2 header
 *  56 bytes CREATE request header
 * ... and the remaining bytes for the filename being opened.
 */
#define USMB2_SIZE 512

struct usmb2_context {
        int fd;
        char username[32];
        char password[32];
        uint64_t message_id;
        uint64_t session_id;
        uint32_t tree_id;
        uint8_t buf[USMB2_SIZE];
};

#ifdef USMB2_FEATURE_TINY_TCP
/* The TCP connection to the server, see z80/README.tcpip. Set it after
 * tcp_connect() and before usmb2_init_context(), which then does not use ip.
 */
extern struct tcp_context *usmb2_tcp;
#endif

struct usmb2_context *usmb2_init_context(uint32_t ip, char *username, char *password);

/* Connect to a share. The unc must be of the form \\ip-address\share-name
 * On success it will fill in tree id in the usmb2 context.
 */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc);

/* Open a file. Unicode is out of scope for a tiny-smb2 clients so the filenames you use better
 * be clean 7-bit ASCII.
 * TODO: currently only support O_RDONLY.  Need to add O_RDWR support.
 *
 * There is no close command. Just stop using the file handle and let the server deal with
 * orhpaned open files. It is not like on the type of devices we are targeting will be able to
 * open very many files so that it becomes an issue anyway.
 */
uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode);

int32_t usmb2_prw(struct usmb2_context *usmb2, int cmd, uint8_t *fid, uint8_t *rbuf, uint8_t *wbuf, int count, uint64_t offset);
int32_t usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint64_t offset);
int32_t usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint64_t offset);
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid);

uint8_t *usmb2_opendir(struct usmb2_context *usmb2, const char *name);
uint8_t *usmb2_readdir(struct usmb2_context *usmb2, uint8_t *dh);

#ifdef USMB2_FEATURE_CLOSE
int usmb2_close(struct usmb2_context *usmb2, uint8_t *fid);
#define usmb2_closedir(u, f) usmb2_close(u, f)
#else /* USMB2_FEATURE_CLOSE */
#define usmb2_close(u,f) free(f)
#define usmb2_closedir(u,f) free(f)
#endif /* USMB2_FEATURE_CLOSE */

#ifdef USMB2_FEATURE_STAT
/* Fills in st with the file's [MS-FSCC] 2.4.29 FileNetworkOpenInformation,
 * 56 bytes in little-endian. Works for files and directories.
 */
int usmb2_stat(struct usmb2_context *usmb2, const char *name, uint8_t *st);
#endif /* USMB2_FEATURE_STAT */

#ifdef USMB2_FEATURE_MKDIR
/* Creates a directory. Fails if it already exists. */
int usmb2_mkdir(struct usmb2_context *usmb2, const char *name);
#endif /* USMB2_FEATURE_MKDIR */

#ifdef USMB2_FEATURE_UNLINK
/* Deletes a file (co 0x40) or an empty directory (co 0x01) */
int usmb2_delete(struct usmb2_context *usmb2, const char *name, uint8_t co);
#define usmb2_unlink(u, n) usmb2_delete(u, n, 0x40)
#define usmb2_rmdir(u, n) usmb2_delete(u, n, 0x01)
#endif /* USMB2_FEATURE_UNLINK */

#ifdef USMB2_FEATURE_RENAME
/* Renames a file or directory. newname is a path from the root of the share.
 * Fails if newname already exists.
 */
int usmb2_rename(struct usmb2_context *usmb2, const char *oldname, const char *newname);
#endif /* USMB2_FEATURE_RENAME */

#endif /* !_USMB2_H_ */
