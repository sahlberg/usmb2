#!/bin/sh
exec "$(dirname "$0")/../common/difftest.sh" test_md5 md5.c md5.S \
	-Dmd5Init=c_md5Init -Dmd5Update=c_md5Update -Dmd5Finalize=c_md5Finalize \
	-Dmd5Step=c_md5Step -DrotateLeft=c_rotateLeft
