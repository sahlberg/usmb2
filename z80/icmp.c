/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#include <stdio.h>
#include <string.h>
#include "ip.h"
#include "icmp.h"
#include "slip.h"

int icmp_echo_request(uint32_t src, uint32_t dst)
{
        uint8_t *ptr = ip_buffer(20);
        uint16_t cs;
        int len;

        memset(ptr, 0, 64);
        ptr[0] = ICMP_TYPE_ECHO;
        
        cs = csum((uint16_t *)&ptr[0], 64);
        memcpy(&ptr[2], &cs, 2); 
        ip_build_and_send(src, dst, 20 + 16, IP_ICMP);

        ptr = ip_buffer(0);
        len = recv_packet(ptr, IP_MAX_SIZE);
        if (len < 28) {
                return -1;
        }
        if (ptr[0] != 0x45) {
                return -1;
        }
        if (ptr[9] != IP_ICMP) {
                return -1;
        }
        if (ptr[20] != ICMP_TYPE_ECHO_REPLY) {
                return -1;
        }

        return 0;
}

