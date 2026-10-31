#!/bin/sh
# Build the md5 differential test in the ps2max/dev container, run it under qemu-mipsel.
set -e
cd "$(dirname "$0")"
TOP=$(cd ../.. && pwd)
IMG=${IMG:-docker.io/ps2max/dev:v20260228}
# the same flags Neutrino uses for the IOP modules
IOPFLAGS="-D_IOP -fno-builtin -G0 -Os -msoft-float -mno-explicit-relocs -mno-check-zero-division -DUSMB2_FEATURE_NTLM"
podman run --rm -v "$TOP":/u:Z -w /u/mips/test_md5 "$IMG" sh -c "
set -e
CC=mipsel-none-elf-gcc
\$CC $IOPFLAGS -I/u -c /u/md5.c -o md5-c.o
\$CC $IOPFLAGS -I/u -c ../md5.S -o md5-asm.o
\$CC $IOPFLAGS -I/u -c /u/md5.c -o md5-ren.o -Dmd5Init=c_md5Init -Dmd5Update=c_md5Update -Dmd5Finalize=c_md5Finalize -Dmd5Step=c_md5Step -DrotateLeft=c_rotateLeft
\$CC $IOPFLAGS -ffreestanding -I/u -c t.c -o t.o
\$CC -nostdlib -static -Wl,-e,__start -Wl,--no-warn-rwx-segments ../common/start.S t.o md5-ren.o md5-asm.o -o t
mipsel-none-elf-objdump -d md5-asm.o > md5-asm.dis
echo '== size (text data bss): C, then asm'
mipsel-none-elf-size md5-c.o md5-asm.o
"
python3 -I ../common/hazard.py md5-asm.dis && echo 'hazards: none'
qemu-mipsel-static ./t
