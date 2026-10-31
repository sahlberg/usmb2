#!/bin/sh
# Against ps2iop-compat.c with ps2iop-compat.S's two fixes (see there), made by mkref.py.
# ps2iop-compat.c itself is 268 bytes, the fixes make that 280.
set -e
D=$(cd "$(dirname "$0")" && pwd)
python3 -I "$D/mkref.py" "$D/../../ps2iop-compat.c" "$D/compat-ref.c"
exec "$D/../common/difftest.sh" test_compat mips/test_compat/compat-ref.c ps2iop-compat.S \
	-Dmalloc=c_malloc -Dfree=c_free -Dcalloc=c_calloc -Dstrdup=c_strdup
