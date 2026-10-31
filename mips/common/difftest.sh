#!/bin/sh
# Differential test of one usmb2 C file against its mips/*.S replacement.
#   difftest.sh <test dir> <C file, relative to usmb2/> <asm file, relative to mips/> <rename -D flags...>
# CEXTRA: more C files (relative to usmb2/) linked into the C side, with the same renames.
# AEXTRA: more asm files (relative to mips/) linked into the asm side.
# TFLAGS: extra flags for t.c.
# PODMAN_ARGS: more podman options, such as -v for headers from elsewhere.
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
IOPFLAGS="-I/usr/local/ps2dev/ps2sdk/iop/include -I/usr/local/ps2dev/ps2sdk/common/include -D_IOP -fno-builtin -G0 -Os -msoft-float -mno-explicit-relocs -mno-check-zero-division -DUSMB2_FEATURE_NTLM ${EXTRA_CFLAGS}"
podman run --rm $PODMAN_ARGS -v "$TOP":/u:Z -w "/u/mips/$T" "$IMG" sh -c "
set -e
CC=mipsel-none-elf-gcc
\$CC $IOPFLAGS -I/u -c /u/$CSRC -o $B-c.o
\$CC $IOPFLAGS -Wa,--fatal-warnings -I/u -c ../$ASRC -o $B-asm.o
\$CC $IOPFLAGS -I/u -c /u/$CSRC -o $B-ren.o $RENAME
X=
for f in $CEXTRA; do \$CC $IOPFLAGS -I/u -c /u/\$f -o x-c-\$(basename \$f).o $RENAME; X=\"\$X x-c-\$(basename \$f).o\"; done
for f in $AEXTRA; do \$CC $IOPFLAGS -Wa,--fatal-warnings -I/u -c ../\$f -o x-a-\$(basename \$f).o; X=\"\$X x-a-\$(basename \$f).o\"; done
\$CC $IOPFLAGS -ffreestanding -I/u ${TFLAGS} -c t.c -o t.o
\$CC -nostdlib -static -Wl,-e,__start -Wl,--no-warn-rwx-segments ../common/start.S t.o $B-ren.o $B-asm.o \$X -o t
mipsel-none-elf-objdump -d -z t > t.dis
echo '== bytes of code + data (.text .rodata .data .bss, not .MIPS.abiflags): C, then asm'
for o in $B-c.o $B-asm.o; do
	mipsel-none-elf-size -A \$o | awk -v o=\$o '\$1 ~ /^\\.(text|rodata|rdata|data|sdata|bss|sbss)/ { n += \$2 } END { printf \"%6d  %s\\n\", n, o }'
done
"
cd "$MIPS/$T"
# checked on the linked program, so that jal targets in other files resolve
python3 -I ../common/hazard.py t.dis && echo 'hazards: none'
qemu-mipsel-static ./t
