#!/bin/sh
# Needs Neutrino's smap.h and mstack.h: NEUTRINO is its checkout.
NEUTRINO=${NEUTRINO:-$(cd "$(dirname "$0")/../../.." && pwd)/PS2/neutrino-smb}
PODMAN_ARGS="-v $NEUTRINO/iop:/nio:ro,z" EXTRA_CFLAGS="-I/nio/smap/include -I/nio/ministack/include -DRS232_TPS=100" \
TFLAGS=-I/u/z80 exec "$(dirname "$0")/../common/difftest.sh" test_ps2smap z80/ps2smap.c ps2smap.S \
	-Dps2smap_init=c_ps2smap_init -Dps2smap_set_port=c_ps2smap_set_port \
	-Dsend_packet=c_send_packet -Drecv_packet=c_recv_packet
