/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

int tcp_connect(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port);
int tcp_send(uint8_t *data, int len);
int tcp_recv(void);

uint8_t *tcp_buffer(void);

#endif /*_TCP_H_ */
