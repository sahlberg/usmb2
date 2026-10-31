#!/bin/sh
# C side: hmac-md5.c + md5.c, asm side: hmac-md5.S + md5.S
CEXTRA=md5.c AEXTRA=md5.S exec "$(dirname "$0")/../common/difftest.sh" test_hmac hmac-md5.c hmac-md5.S \
	-Dhmac_md5=c_hmac_md5 -Dk_pad=c_k_pad \
	-Dmd5Init=c_md5Init -Dmd5Update=c_md5Update -Dmd5Finalize=c_md5Finalize \
	-Dmd5Step=c_md5Step -DrotateLeft=c_rotateLeft
