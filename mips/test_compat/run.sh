#!/bin/sh
exec "$(dirname "$0")/../common/difftest.sh" test_compat ps2iop-compat.c ps2iop-compat.S \
	-Dmalloc=c_malloc -Dfree=c_free -Dcalloc=c_calloc -Dstrdup=c_strdup
