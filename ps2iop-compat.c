// PS2SDK
#include "errno.h"
#include "intrman.h"
#include "iomanX.h"
#include "irx.h"
#include "loadcore.h"
#include "stdio.h"
#include "sysclib.h"
#include "sysmem.h"
// usmb2
#include "ps2iop-compat.h"
#include "usmb2.h"

#define MODNAME "usmb2"
#define VER_MAJOR 1
#define VER_MINOR 1

IRX_ID(MODNAME, VER_MAJOR, VER_MINOR);

static int SMB2_dummy(void)
{
    printf("%s\n", __FUNCTION__);
    return -EIO;
}

static int SMB2_deinit(iop_device_t* dev)
{
    printf("%s\n", __FUNCTION__);
    return 0;
}

static int SMB2_init(iop_device_t* dev)
{
    printf("%s\n", __FUNCTION__);
    return 0;
}

static struct usmb2_context* usmb2 = NULL;
static int SMB2_open(iop_file_t* f, const char* filename, int flags, int mode)
{
    printf("%s(%s)\n", __FUNCTION__, filename);

    f->privdata = usmb2_open(usmb2, filename, O_RDONLY);
    if (f->privdata == NULL) {
        printf("%s: failed to open file\n", __FUNCTION__);
        return -EINVAL;
    }

    return 0;
}

static int SMB2_close(iop_file_t* f)
{
    printf("%s\n", __FUNCTION__);

    usmb2_close(usmb2, f->privdata);

    return 0;
}

static int SMB2_read(iop_file_t* f, void* buf, int size)
{
    // printf("%s\n", __FUNCTION__);

    return usmb2_pread(usmb2, f->privdata, buf, size, /*FIXME!*/ 0);
}

static iop_device_ops_t smb2man_ops = {
    &SMB2_init,
    &SMB2_deinit,
    (void*)&SMB2_dummy,
    &SMB2_open,
    &SMB2_close,
    &SMB2_read,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy,
    (void*)&SMB2_dummy
};

static iop_device_t smb2dev = {
    "smb",
    IOP_DT_FS | IOP_DT_FSEXT,
    1,
    "SMB",
    &smb2man_ops
};

int _start(int argc, char* argv[])
{
    DelDrv(smb2dev.name);
    if (AddDrv((iop_device_t*)&smb2dev))
        return MODULE_NO_RESIDENT_END;

    return MODULE_RESIDENT_END;
}

void* malloc(int size)
{
    void* result;
    int OldState;

    CpuSuspendIntr(&OldState);
    result = AllocSysMemory(ALLOC_FIRST, size, NULL);
    CpuResumeIntr(OldState);

    return result;
}

void free(void* ptr)
{
    int OldState;

    CpuSuspendIntr(&OldState);
    FreeSysMemory(ptr);
    CpuResumeIntr(OldState);
}

void* calloc(size_t nmemb, size_t size)
{
    size_t s = nmemb * size;
    void* ptr;

    ptr = malloc(s);
    memset(ptr, 0, s);

    return ptr;
}

char* strdup(const char* s)
{
    char* str;
    int len;

    len = strlen(s) + 1;
    str = malloc(len);
    if (str == NULL) {
#ifndef _IOP
        errno = ENOMEM;
#endif /* !_IOP */
        return NULL;
    }
    memcpy(str, s, len + 1);
    return str;
}
