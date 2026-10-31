#!/bin/sh
# C side: ntlm.c + md4c.c + hmac-md5.c + md5.c, asm side: the four .S files.
# TargetInfos up to 300 bytes: ntlm.c handles 100+ bytes since 628f242.
set -e
CEXTRA="md4c.c hmac-md5.c md5.c" AEXTRA="md4c.S hmac-md5.S md5.S" TFLAGS=-DMAXTI=300 \
exec "$(dirname "$0")/../common/difftest.sh" test_ntlm ntlm.c ntlm.S \
	-Dntlm_generate_auth=c_ntlm_generate_auth -DMD4Init=c_MD4Init -DMD4Update=c_MD4Update -DMD4Final=c_MD4Final \
	-Dhmac_md5=c_hmac_md5 -Dk_pad=c_k_pad -Dmd5Init=c_md5Init -Dmd5Update=c_md5Update -Dmd5Finalize=c_md5Finalize \
	-Dmd5Step=c_md5Step -DrotateLeft=c_rotateLeft
