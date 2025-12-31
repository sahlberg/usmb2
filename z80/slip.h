/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* SLIP  From RFC1055 */
#ifndef _SLIP_H_
#define _SLIP_H_

#include <stdint.h>

int slip_init(int baud_rate, int parity);
void send_packet(uint8_t *p, int len);
int recv_packet(uint8_t *p, int len);

#endif /*_SLIP_H_ */
