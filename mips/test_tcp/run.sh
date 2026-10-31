#!/bin/sh
# C side: tcp.c + ip.c, asm side: tcp.S + ip.S
CEXTRA=z80/ip.c AEXTRA=ip.S TFLAGS="-I/u/z80 -DRS232_TPS=100" EXTRA_CFLAGS=-DRS232_TPS=100 \
exec "$(dirname "$0")/../common/difftest.sh" test_tcp z80/tcp.c tcp.S \
	-Dtcp_send=c_tcp_send -Dtcp_recv=c_tcp_recv -Dtcp_recv_timeout=c_tcp_recv_timeout \
	-Dtcp_connect=c_tcp_connect -Dtcp_rx_buffer=c_tcp_rx_buffer -Dtcp_tx_buffer=c_tcp_tx_buffer \
	-Dcsum=c_csum -Dip_build_and_send=c_ip_build_and_send -Dip_buffer=c_ip_buffer
