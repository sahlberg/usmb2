/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _ICMP_H_
#define _ICMP_H_

#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY    0
#define ICMP_TYPE_ECHO          8

int icmp_echo_request(uint32_t src, uint32_t dst);

#endif /*_ICMP_H_ */
