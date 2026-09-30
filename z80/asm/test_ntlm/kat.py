# Known-answer check: recompute NTLMv2 NTProofStr on host from parsed output.
import hmac, hashlib, struct, sys
def md4(m):
    rl=lambda x,n:((x<<n)|(x>>(32-n)))&0xffffffff
    ml=len(m)*8; m+=b'\x80'; m+=b'\0'*((56-len(m))%64); m+=struct.pack('<Q',ml)
    a,b,c,d=0x67452301,0xefcdab89,0x98badcfe,0x10325476
    for i in range(0,len(m),64):
        X=struct.unpack('<16I',m[i:i+64]); A,B,C,D=a,b,c,d
        F=lambda x,y,z:(x&y)|(~x&z); G=lambda x,y,z:(x&y)|(x&z)|(y&z); H=lambda x,y,z:x^y^z
        for k in range(16):
            s=[3,7,11,19][k%4]; A=rl((A+F(B,C,D)+X[k])&0xffffffff,s); A,B,C,D=D,A,B,C
        for k in range(16):
            s=[3,5,9,13][k%4]; j=[0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15][k]
            A=rl((A+G(B,C,D)+X[j]+0x5a827999)&0xffffffff,s); A,B,C,D=D,A,B,C
        for k in range(16):
            s=[3,9,11,15][k%4]; j=[0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15][k]
            A=rl((A+H(B,C,D)+X[j]+0x6ed9eba1)&0xffffffff,s); A,B,C,D=D,A,B,C
        a,b,c,d=[(x+y)&0xffffffff for x,y in zip((a,b,c,d),(A,B,C,D))]
    return struct.pack('<4I',a,b,c,d)
assert md4(b'abc').hex()=='a448017aaf21d8525fc10ae87aa6729d'
cases=[("WG","admin","password"),("MYDOMAIN","Administrator",""),("D","u","p"),
 ("LONGDOMAINNAME123","user1","0123456789012345678901234567890"),
 ("WORKGROUP","MixedCaseUser","Secr3t!"),("X","a","bb"),("ACME","john.doe","hunter2hunter2hunter2hunter2")]
blocks=open(sys.argv[1]).read().split('RET=')[1:]
ok=0
for (dom,user,pw),blk in zip(cases,blocks):
    lines=blk.split('\n'); ret=int(lines[0]); buf=bytes.fromhex(''.join(lines[1:17]))
    n=buf[92:]
    ntlen,=struct.unpack_from('<H',n,20); ntoff,=struct.unpack_from('<I',n,24)
    nt1=md4(pw.encode('utf-16le'))
    nt2=hmac.new(nt1,user.upper().encode('utf-16le')+dom.encode('utf-16le'),hashlib.md5).digest()
    resp=n[ntoff:ntoff+ntlen]
    chal=bytes(range(0x10,0x18))
    proof=hmac.new(nt2,chal+resp[16:],hashlib.md5).digest()
    good = proof==resp[:16] and ret==ntoff+ntlen
    print(dom,user,'OK' if good else 'FAIL'); ok+=good
print(ok,'/',len(cases))
