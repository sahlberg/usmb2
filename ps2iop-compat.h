#ifndef PS2IOP_COMPAT_H
#define PS2IOP_COMPAT_H

#include <ps2ip.h>
#include <stdint.h>

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN LITTLE_ENDIAN
#endif

#define O_DIRECTORY O_DIROPEN

#define be16toh(x) PP_NTOHS(x)
#define htobe16(x) PP_HTONS(x)
#define htole16(x) (x)
#define le16toh(x) (x)

#define be32toh(x) PP_NTOHL(x)
#define htobe32(x) PP_HTONL(x)
#define htole32(x) (x)
#define le32toh(x) (x)

#define htobe64(x) be64toh(x)
#define htole64(x) (x)
#define le64toh(x) (x)

#define write(a, b, c) lwip_send(a, b, c, 0)
#define read(a, b, c) lwip_recv(a, b, c, 0)

void* malloc(int size);
void free(void* ptr);
void* calloc(size_t nmemb, size_t size);
char* strdup(const char* s);

#endif
