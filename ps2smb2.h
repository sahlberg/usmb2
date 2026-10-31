/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * devctl interface of the smb: device in usmb2man.irx.
 * The same as the one of libsmb2's smb2man.irx.
 */
#ifndef __PS2SMB2_H__
#define __PS2SMB2_H__

#define SMB2_DEVCTL_CONNECT        0xC0DE0001
#define SMB2_DEVCTL_DISCONNECT_ALL 0xC0DE0002

/*
 * SMB2_DEVCTL_CONNECT connects to the share in url, smb://<ip-address>/<share>,
 * and shows it as smb:/<name>.
 */
#define SMB2_MAX_NAME_LEN 32
typedef struct {
        char name[SMB2_MAX_NAME_LEN];
        char username[32];
        char password[32];
        char url[256];
} smb2Connect_in_t;

typedef struct {
        void *ctx;
} smb2Connect_out_t;

#endif /* __PS2SMB2_H__ */
