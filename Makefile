

all: ps2-usmb2-cat

usmb2.o: usmb2.c usmb2.h
	gcc -Os -c usmb2.c -o usmb2.o -DUSMB2_FEATURE_OPENDIR -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM

md4c.o: md4c.c md4.h
	gcc -Os -c md4c.c -o md4c.o -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM

md5.o: md5.c md5.h
	gcc -Os -c md5.c -o md5.o -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM

hmac-md5.o: hmac-md5.c hmac-md5.h
	gcc -Os -g -c hmac-md5.c -o hmac-md5.o -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM

ntlm.o: ntlm.c ntlm.h md4.h
	gcc -g -Os -c ntlm.c -o ntlm.o -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM

ps2-usmb2-cat: ps2-usmb2-cat.o usmb2.o ntlm.o ntlm.o md4c.o hmac-md5.o md5.o
	gcc ps2-usmb2-cat.o usmb2.o ntlm.o hmac-md5.o md5.o md4c.o -o ps2-usmb2-cat
