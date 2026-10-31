#!/bin/sh
TFLAGS=-I/u/z80 exec "$(dirname "$0")/../common/difftest.sh" test_ip z80/ip.c ip.S \
	-Dcsum=c_csum -Dip_build_and_send=c_ip_build_and_send -Dip_buffer=c_ip_buffer
