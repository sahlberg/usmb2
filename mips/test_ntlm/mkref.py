#!/usr/bin/python3 -I
"""ntlm-ref.c: ntlm.c with the two fixes ntlm.S has, so that long TargetInfos can be compared too:
a 16-bit TargetInfo length, memmove instead of memcpy, and the server challenge
copied after the TargetInfo instead of before it."""
import sys
s = open(sys.argv[1]).read()
def sub(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)
sub("char NTOWFv2[16], z = 0;", "char NTOWFv2[16]; uint16_t z = 0;")
chal = "        memcpy(&usmb2->buf[4 + 64 + 24 + ntlm_response_offset + 8], &usmb2->buf[ntlmssp_in_offset + 24], 8);\n"
sub(chal, "")
sub("        memcpy(&usmb2->buf[offset], target_info, z);\n", "        memcpy(&usmb2->buf[offset], target_info, z);\n" + chal)
s = s.replace("memcpy(", "memmove(")
s = s.replace("MD4Update((MD4_CTX *)&usmb2->buf[0], &z, 1);", "MD4Update((MD4_CTX *)&usmb2->buf[0], (unsigned char *)&z, 1);")
open(sys.argv[2], "w").write(s)
