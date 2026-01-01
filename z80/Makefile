CFILESNET = icmp.c ip.c slip.c tcp.c
OFILESNET = $(CFILESNET:.c=.o)
CFILESSMB = ../hmac-md5.c ../md4c.c ../md5.o ../ntlm.c ../unicode.c ../usmb2.c
OFILESSMB = $(CFILESSMB:.c=.o)

PROGRAMS = ping.bin smb2-cat.bin

all: $(PROGRAMS)


smb2-cat.bin: smb2-cat.o $(OFILESNET) $(OFILESSMB)
	zcc +zx -o $@ smb2-cat.c -I.. $(OFILESNET) $(OFILESSMB) -lndos -lrs232if1 -create-app -DAMALLOC

ping.bin: ping.o $(OFILESNET)
	zcc +zx -o $@ ping.c $(OFILESNET) -lndos -lrs232if1 -create-app 

%.o: %.c
	zcc +zx -o $@ -c $^ -I.. -DUSMB2_FEATURE_CLOSE -DUSMB2_FEATURE_NTLM -DZ80

clean:
	$(RM) *.o ../*.o *.tap *.bin
