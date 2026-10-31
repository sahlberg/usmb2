#!/bin/sh
exec "$(dirname "$0")/../common/difftest.sh" test_md4 md4c.c md4c.S \
	-DMD4Init=c_MD4Init -DMD4Update=c_MD4Update -DMD4Final=c_MD4Final
