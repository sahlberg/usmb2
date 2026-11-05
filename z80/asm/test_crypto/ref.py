#!/usr/bin/env python3
# Independent host reference for the harness output (t.c).
import struct, hashlib, hmac

M = 0xffffffff
rol = lambda x, n: ((x << n) | (x >> (32 - n))) & M

def md4_compress(st, blk):
    x = struct.unpack('<16I', blk)
    a, b, c, d = st
    F = lambda x, y, z: (x & y) | (~x & z)
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)
    H = lambda x, y, z: x ^ y ^ z
    for i in range(16):
        s = [3, 7, 11, 19][i % 4]
        a = rol((a + F(b, c, d) + x[i]) & M, s); a, b, c, d = d, a, b, c
    for i in range(16):
        s = [3, 5, 9, 13][i % 4]; k = (i % 4) * 4 + i // 4
        a = rol((a + G(b, c, d) + x[k] + 0x5a827999) & M, s); a, b, c, d = d, a, b, c
    for i in range(16):
        s = [3, 9, 11, 15][i % 4]; k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
        a = rol((a + H(b, c, d) + x[k] + 0x6ed9eba1) & M, s); a, b, c, d = d, a, b, c
    return [(p + q) & M for p, q in zip(st, (a, b, c, d))]

import math
K = [int(abs(math.sin(i + 1)) * 2**32) & M for i in range(64)]
S5 = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]
def md5_compress(st, blk):
    x = struct.unpack('<16I', blk)
    a, b, c, d = st
    for i in range(64):
        r = i // 16
        if r == 0: f = (b & c) | (~b & d); j = i
        elif r == 1: f = (b & d) | (c & ~d); j = (5 * i + 1) % 16
        elif r == 2: f = b ^ c ^ d; j = (3 * i + 5) % 16
        else: f = c ^ (b | (~d & M)); j = (7 * i) % 16
        f &= M
        a, b, c, d = d, (b + rol((a + f + K[i] + x[j]) & M, S5[r * 4 + i % 4])) & M, b, c
    return [(p + q) & M for p, q in zip(st, (a, b, c, d))]

IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
def pad(n):
    return b'\x80' + b'\0' * ((55 - n) % 64) + struct.pack('<Q', (n * 8) & (2**64 - 1))
def run(comp, msg):
    m = msg + pad(len(msg)); st = IV[:]
    for i in range(0, len(m), 64): st = comp(st, m[i:i + 64])
    return struct.pack('<4I', *st), len(m) - len(msg)

def md4(m):
    d, p = run(md4_compress, m)
    return d.hex() + ' ' + d.hex() + struct.pack('<Q', (len(m) + p) * 8).hex()
def md5(m):
    d, p = run(md5_compress, m)
    assert d == hashlib.md5(m).digest()
    return d.hex() + ' ' + d.hex()

pat = bytes(((i * 37 + (i >> 3) * 11 + 5) & 255) for i in range(260))
vec = [b"", b"a", b"abc", b"message digest", b"abcdefghijklmnopqrstuvwxyz",
       b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
       b"1234567890" * 8]
print("MD4 vectors")
for v in vec: print(md4(v))
print("MD5 vectors")
for v in vec: print(md5(v))
print("MD4 lengths")
for n in range(201):
    for _ in range(3 + (n % 8 == 0)): print(n, md4(pat[:n]))
print("MD5 lengths")
for n in range(201):
    for _ in range(3 + (n % 8 == 0)): print(n, md5(pat[:n]))
print("md5Step")
print(struct.pack('<4I', *md5_compress([0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210], pat[:64])).hex())

def up(t0):
    return b''.join(bytes([c - 32 if 97 <= c <= 122 else c, 0]) for c in t0)
def hm(t0, t1, t2, key):
    return hmac.new(key, up(t0 or b'') + (t1 or b'') + (t2 or b''), 'md5').digest()
print("HMAC RFC2104")
print(hm(None, b"Hi There", None, b'\x0b' * 16).hex())
print(hm(None, b"what do ya want for nothing?", None, b"Jefe").hex())
print(hm(None, b'\xdd' * 50, None, b'\xaa' * 16).hex())
print("HMAC combos")
key = bytes(((i * 13 + 7) & 255) for i in range(80))
for j in range(66):
    print("k%d %s" % (j, hm(b"UserName_az@[`{AZ~", pat[:j * 3], pat[17:17 + j], key[:min(j, 64)]).hex()))
print(hm(b"", None, None, key[:16]).hex())
print(hm(None, None, None, b"").hex())
print(hm(b"Administrator", None, b"WORKGROUP", key[:16]).hex())
print(hm(b"x", b"", None, key[:64]).hex())
print(hm(b"\x80\xe1\xff\x7fmIxEd", pat[:119], pat[3:4], key[:16]).hex())
print("NTLM pattern")
pw = b"Passw0rd"
nt = bytes.fromhex(md4(b''.join(bytes([c, 0]) for c in pw))[:32])
print(nt.hex())
ntowf = hm(b"user", None, b"D\0o\0m\0", nt)
print(ntowf.hex())
b = bytearray(600)
for i in range(300): b[200 + i] = (i ^ 0x3c) & 255
d = hm(None, bytes(b[208:358]), None, ntowf)
b[200:216] = d
print(bytes(b[200:224]).hex())
# digest aliases key: the outer pass reads the key after the inner digest overwrote it
inner = hashlib.md5(bytes(k ^ 0x36 for k in ntowf + b'\0' * 48) + up(b"a")).digest()
print(hashlib.md5(bytes(k ^ 0x5c for k in inner + b'\0' * 48) + inner).hexdigest())
print("done")
