#!/bin/sh
# usmb2.c as Neutrino builds it: TINY_TCP, REASSEMBLY, NTLM
EXTRA_CFLAGS="-DRS232_TPS=100 -DUSMB2_FEATURE_TINY_TCP -DUSMB2_FEATURE_REASSEMBLY -I/u/z80" TFLAGS= \
exec "$(dirname "$0")/../common/difftest.sh" test_usmb2 usmb2.c usmb2.S \
	-Dusmb2_init_context=c_usmb2_init_context -Dusmb2_negotiateprotocol=c_usmb2_negotiateprotocol \
	-Dusmb2_sessionsetup=c_usmb2_sessionsetup -Dusmb2_treeconnect=c_usmb2_treeconnect \
	-Dusmb2_open=c_usmb2_open -Dusmb2_prw=c_usmb2_prw -Dusmb2_pread=c_usmb2_pread \
	-Dusmb2_size=c_usmb2_size -Dusmb2_tcp=c_usmb2_tcp \
	-Dtcp_send=c_tcp_send -Dtcp_recv=c_tcp_recv -Dtcp_rx_buffer=c_tcp_rx_buffer -Dtcp_tx_buffer=c_tcp_tx_buffer \
	-Dntlm_generate_auth=c_ntlm_generate_auth -Dcalloc=c_calloc -Dfree=c_free
