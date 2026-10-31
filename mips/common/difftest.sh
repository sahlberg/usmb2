#!/bin/sh
# Differential test of one usmb2 C file against its mips/*.S replacement.
#   difftest.sh <test dir> <C file, relative to usmb2/> <asm file, relative to mips/> <rename -D flags...>
# Builds in the ps2max/dev container with Neutrino's IOP flags, checks the asm
# for R3000 hazards, prints both sizes and runs <test dir>/t.c under qemu-mipsel.
set -e
T=$1 CSRC=$2 ASRC=$3; shift 3
RENAME="$*"
MIPS=$(cd "$(dirname "$0")/.." && pwd)
TOP=$(cd "$MIPS/.." && pwd)
IMG=${IMG:-docker.io/ps2max/dev:v20260228}
B=$(basename "$CSRC" .c)
# the same flags Neutrino uses for the IOP modules
IOPFLAGS="-D_IOP -fno-builtin -G0 -Os -msoft-float -mno-explicit-relocs -mno-check-zero-division -DUSMB2_FEATURE_NTLM ${EXTRA_CFLAGS}"
podman run --rm -v "$TOP":/u:Z -w "/u/mips/$T" "$IMG" sh -c "
set -e
CC=mipsel-none-elf-gcc
\$CC $IOPFLAGS -I/u -c /u/$CSRC -o $B-c.o
\$CC $IOPFLAGS -I/u -c ../$ASRC -o $B-asm.o
\$CC $IOPFLAGS -I/u -c /u/$CSRC -o $B-ren.o $RENAME
\$CC $IOPFLAGS -ffreestanding -I/u -c t.c -o t.o
\$CC -nostdlib -static -Wl,-e,__start -Wl,--no-warn-rwx-segments ../common/start.S t.o $B-ren.o $B-asm.o -o t
mipsel-none-elf-objdump -d $B-asm.o > $B-asm.dis
echo '== size (text data bss): C, then asm'
mipsel-none-elf-size $B-c.o $B-asm.o
"
cd "$MIPS/$T"
python3 -I ../common/hazard.py "$B-asm.dis" && echo 'hazards: none'
qemu-mipsel-static ./t
