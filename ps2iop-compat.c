// PS2SDK
#include "errno.h"
#include "intrman.h"
#include "sysclib.h"
#include "sysmem.h"
// usmb2
#include "ps2iop-compat.h"

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
