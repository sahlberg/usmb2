#!/bin/sh
# Differential test: C ntlm.c vs asm ntlm.asm, real C crypto linked in both.
set -e
cd "$(dirname "$0")"
export PATH=/data/sahlberg/z88dk/bin:$PATH ZCCCFG=/data/sahlberg/z88dk/lib/config
I="-I../../.. -I../.."; D="-DZ80 -DUSMB2_FEATURE_NTLM"
CRYPTO="../../../md4c.c ../../../md5.c ../../../hmac-md5.c"
zcc +test -vn $I $D test.c $CRYPTO ../../../ntlm.c -o tc.bin -lndos
zcc +test -vn $I $D test.c $CRYPTO ../ntlm.asm     -o ta.bin -lndos
z88dk-ticks -mz80 tc.bin | grep -v Ticks > out_c.txt
z88dk-ticks -mz80 ta.bin | grep -v Ticks > out_a.txt
ls -l tc.bin ta.bin
grep RET out_c.txt | tr '\n' ' '; echo
cmp out_c.txt out_a.txt && echo "IDENTICAL ($(wc -l < out_c.txt) lines)"
