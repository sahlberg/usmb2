#!/bin/sh
# C side: ntlm.c + md4c.c + hmac-md5.c + md5.c, asm side: the four .S files.
# 1. against ntlm.c itself, with TargetInfos it handles: <= 96 bytes (see ntlm.S)
# 2. against ntlm-ref.c, ntlm.c with ntlm.S's fixes, with TargetInfos up to 300 bytes
set -e
D=$(cd "$(dirname "$0")" && pwd)
python3 -I "$D/mkref.py" "$D/../../ntlm.c" "$D/ntlm-ref.c"
R="-Dntlm_generate_auth=c_ntlm_generate_auth -DMD4Init=c_MD4Init -DMD4Update=c_MD4Update -DMD4Final=c_MD4Final
 -Dhmac_md5=c_hmac_md5 -Dk_pad=c_k_pad -Dmd5Init=c_md5Init -Dmd5Update=c_md5Update -Dmd5Finalize=c_md5Finalize
 -Dmd5Step=c_md5Step -DrotateLeft=c_rotateLeft"
export CEXTRA="md4c.c hmac-md5.c md5.c" AEXTRA="md4c.S hmac-md5.S md5.S"
TFLAGS=-DMAXTI=96 "$D/../common/difftest.sh" test_ntlm ntlm.c ntlm.S $R
echo '== against ntlm-ref.c, long TargetInfos'
TFLAGS=-DMAXTI=300 "$D/../common/difftest.sh" test_ntlm mips/test_ntlm/ntlm-ref.c ntlm.S $R | grep -v '^ \|^=='
