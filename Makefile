FEATURES = -DUSMB2_FEATURE_OPENDIR -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM -DUSMB2_FEATURE_UNICODE -DUSMB2_FEATURE_CLOSE

all: ps2-usmb2-cat

usmb2.o: usmb2.c usmb2.h unicode.h
	gcc -Os -c usmb2.c -o usmb2.o $(FEATURES)

unicode.o: unicode.c
	gcc -Os -c unicode.c -o unicode.o $(FEATURES)

md4c.o: md4c.c md4.h
	gcc -Os -c md4c.c -o md4c.o $(FEATURES)

md5.o: md5.c md5.h
	gcc -Os -c md5.c -o md5.o $(FEATURES)

hmac-md5.o: hmac-md5.c hmac-md5.h md5.h
	gcc -Os -g -c hmac-md5.c -o hmac-md5.o $(FEATURES)

ntlm.o: ntlm.c ntlm.h md4.h hmac-md5.h md5.h
	gcc -g -Os -c ntlm.c -o ntlm.o $(FEATURES)

ps2-usmb2-cat.o: ps2-usmb2-cat.c usmb2.h
	gcc -g -Os -c ps2-usmb2-cat.c -o ps2-usmb2-cat.o $(FEATURES)

ps2-usmb2-cat: ps2-usmb2-cat.o usmb2.o unicode.o ntlm.o ntlm.o md4c.o hmac-md5.o md5.o
	gcc ps2-usmb2-cat.o usmb2.o unicode.o ntlm.o hmac-md5.o md5.o md4c.o -o ps2-usmb2-cat
