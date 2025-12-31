/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _IP_H_
#define _IP_H_

#include <stdint.h>

#define IP_ICMP 1
#define IP_TCP  6
#define IP_UDP 17

/* ip hdr + tcp hdr + smb2 hdr + 512 bytes of payload */
#define IP_MAX_SIZE (20+32+64+512)

uint16_t csum(uint16_t *ptr, int nbytes);
uint8_t *ip_buffer(int offset);

void ip_build_and_send(uint32_t src, uint32_t dst, uint16_t total_len, uint8_t proto);

#endif /*_IP_H_ */
