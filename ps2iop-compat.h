#ifndef PS2IOP_COMPAT_H
#define PS2IOP_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#define O_DIRECTORY O_DIROPEN

#define htole16(x) (x)
#define le16toh(x) (x)
#define htole32(x) (x)
#define le32toh(x) (x)
#define htole64(x) (x)
#define le64toh(x) (x)

#ifdef USMB2_FEATURE_TINY_TCP
/* The tiny stack in z80/ instead of LWIP */
/* Not __builtin_bswap32(), that is a libgcc call on the IOP */
#define htons(x) ((uint16_t)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define ntohs(x) htons(x)
#define htonl(x) ((uint32_t)((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | \
                             (((x) >> 8) & 0xff00) | (((x) >> 24) & 0xff)))
#define ntohl(x) htonl(x)
#else
#include <ps2ip.h>

#define write(a, b, c) lwip_send(a, b, c, 0)
#define read(a, b, c) lwip_recv(a, b, c, 0)
#define close(a) lwip_close(a)
#endif

void* malloc(int size);
void free(void* ptr);
void* calloc(size_t nmemb, size_t size);
char* strdup(const char* s);

#endif
