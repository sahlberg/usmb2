#!/usr/bin/python3 -I
"""compat-ref.c: ps2iop-compat.c with the two fixes ps2iop-compat.S has"""
import sys
s = open(sys.argv[1]).read()
def sub(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)
sub("    ptr = malloc(s);\n    memset(ptr, 0, s);\n", "    ptr = malloc(s);\n    if (ptr) memset(ptr, 0, s);\n")
sub("    memcpy(str, s, len + 1);\n", "    memcpy(str, s, len);\n")
open(sys.argv[2], "w").write(s)
