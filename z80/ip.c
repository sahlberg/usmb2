/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#include <stdio.h>
#include <string.h>
#include "ip.h"
#include "slip.h"

uint8_t pkt[IP_MAX_SIZE];

uint16_t id = 1;

uint16_t csum(uint16_t *ptr, int nbytes) 
{
	uint32_t sum;
	uint16_t oddbyte;
	uint16_t answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte=0;
		*((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (uint16_t)~sum;
	
	return(answer);
}

#define htons(x) ((x<<8)|(x>>8))

void ip_build_and_send(uint32_t src, uint32_t dst, uint16_t total_len, uint8_t proto)
{
        uint16_t cs, tl;

        memset(pkt, 0, 20);
        pkt[0] = 0x45;
        tl = htons(total_len);
        memcpy(&pkt[2], &tl, 2);
        memcpy(&pkt[4], &id, 2); id++;
        pkt[8] = 64;
        pkt[9] = proto;
        memcpy(&pkt[12], &src, 4); 
        memcpy(&pkt[16], &dst, 4); 

        cs = csum((uint16_t *)&pkt[0], 20);
        memcpy(&pkt[10], &cs, 2); 
        send_packet(pkt, total_len);
}

uint8_t *ip_buffer(int offset)
{
        return &pkt[offset];
}

