/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__) && !defined(_IOP)
#include <poll.h>
#endif
#include <stdint.h>
#include <stdio.h>
#if defined(_IOP)
#include "ps2iop-compat.h"
#else
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>

#include "usmb2.h"

#define MAXBUF 16 * 1024 * 1024
uint8_t buf[MAXBUF];
uint32_t pos;

int main(int argc, char *argv[])
{
        uint8_t *fh, *dh, *de;
        int rc = 0;
        struct usmb2_context *usmb2;
        
        //usmb2 = usmb2_init_context(htonl(0x0a0a0a0b), "Administrator", "otto1234$$$$"); // 10.10.10.11
        usmb2 = usmb2_init_context(htonl(0xc0a87c65), "Administrator", "otto1234$$$$"); /* 192.168.124.101 */
        printf("usmb2:%p (%ld bytes)\n", usmb2, sizeof(*usmb2));

        /* Map the share */
        //if (usmb2_treeconnect(usmb2, "\\\\10.10.10.11\\SNAP-1")) {
        if (usmb2_treeconnect(usmb2, "\\\\192.168.124.101\\Share")) {
                printf("failed to map share\n");
                return -1;
        }

        /* Open a directory */
        dh = usmb2_opendir(usmb2, "");
        if (dh == NULL) {
		printf("usmb2_opendir failed\n");
		return -1;
        }
        /*
         * de is a directory entry in [MS-FSCC] 2.4.10 FileDirectoryInformation format
         * except filename is returned as nul-terminated 7-bit ASCII string.
         * All fields are in little-endian.
         */
        while((de = usmb2_readdir(usmb2, dh))) {
                printf("%s %12lld %s\n", (de[0x38]&0x10)?"DIRECTORY ":"FILE      ", (long long)le64toh(*(uint64_t *)&de[0x28]), &de[0x40]);
        }                
        usmb2_close(usmb2, dh);
        
        /* Open the file */
        fh = usmb2_open(usmb2, "hello.txt", O_RDONLY);
        if (fh == NULL) {
		printf("usmb2_open failed\n");
		return -1;
        }
        
        usmb2_pread(usmb2, fh, buf, 30, 0);
        printf("BUF: %s\n", buf);
        usmb2_pread(usmb2, fh, buf, 30, 2);
        printf("BUF: %s\n", buf);
        printf("Size: %d bytes\n", usmb2_size(usmb2, fh));
        usmb2_close(usmb2, fh);
        
	return rc;
}
