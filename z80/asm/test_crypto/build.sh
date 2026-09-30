#!/bin/sh
# Build and run the differential harness with the C and the asm crypto.
export PATH=/data/sahlberg/z88dk/bin:$PATH ZCCCFG=/data/sahlberg/z88dk/lib/config
set -e
cd "$(dirname "$0")"
U=../../..
zcc +test -vn -I$U -DZ80 -DUSMB2_FEATURE_NTLM t.c $U/md4c.c $U/md5.c $U/hmac-md5.c -o tc.bin -lndos -m
zcc +test -vn -I$U -DZ80 -DUSMB2_FEATURE_NTLM t.c ../crypto.asm -o ta.bin -lndos -m
z88dk-ticks -mz80 -counter 20000000000 tc.bin | tee ticks_c.txt | grep -v -e "^Ticks:" -e "^$" > out_c.txt
z88dk-ticks -mz80 -counter 20000000000 ta.bin | tee ticks_asm.txt | grep -v -e "^Ticks:" -e "^$" > out_asm.txt
python3 ref.py > out_py.txt
ls -l tc.bin ta.bin
wc -l out_c.txt out_asm.txt out_py.txt
cmp out_c.txt out_asm.txt && echo "C == ASM"
cmp out_c.txt out_py.txt && echo "C == python"
