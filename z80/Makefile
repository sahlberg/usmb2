# Z80_ASM=1 links the IP, SLIP and TCP layers from the hand written
# ip-z80.asm / slip-z80.asm / tcp-z80.asm instead of from the compiler
# output for the matching .c file. See README.tcp-z80.
Z80_ASM      ?= 0
Z80_ASM_IP   ?= $(Z80_ASM)
Z80_ASM_SLIP ?= $(Z80_ASM)
Z80_ASM_TCP  ?= $(Z80_ASM)

IPOBJ   = $(if $(filter-out 0,$(Z80_ASM_IP)),ip-z80.o,ip.o)
SLIPOBJ = $(if $(filter-out 0,$(Z80_ASM_SLIP)),slip-z80.o,slip.o)
TCPOBJ  = $(if $(filter-out 0,$(Z80_ASM_TCP)),tcp-z80.o,tcp.o)

OFILESNET = icmp.o $(IPOBJ) $(SLIPOBJ) $(TCPOBJ)
CFILESSMB = ../hmac-md5.c ../md4c.c ../md5.o ../ntlm.c ../unicode.c ../usmb2.c
OFILESSMB = $(CFILESSMB:.c=.o)

PROGRAMS = ping.bin smb2-cat.bin

all: $(PROGRAMS)


smb2-cat.bin: smb2-cat.o $(OFILESNET) $(OFILESSMB)
	zcc +zx -o $@ smb2-cat.c -I.. $(OFILESNET) $(OFILESSMB) -lndos -lrs232if1 -create-app -DZ80 -DUSMB2_FEATURE_CLOSE -DAMALLOC -DRS232_TPS=80

# usmb2 and the tiny stack on a Linux host, on raw sockets instead of SLIP.
# See raw.c for what it needs to run.
HOSTCFILES = smb2-cat-host.c raw.c ip.c tcp.c ../usmb2.c ../ntlm.c ../md4c.c \
	../md5.c ../hmac-md5.c
smb2-cat-host: $(HOSTCFILES)
	gcc -Wall -O2 -I.. -I. -DUSMB2_FEATURE_TINY_TCP -DUSMB2_FEATURE_NTLM \
		-DUSMB2_FEATURE_OPENDIR -DUSMB2_FEATURE_REASSEMBLY -DRS232_TPS=100 \
		-o $@ $(HOSTCFILES)

ping.bin: ping.o $(OFILESNET)
	zcc +zx -o $@ ping.c $(OFILESNET) -lndos -lrs232if1 -create-app 

%.o: %.c
	zcc +zx -o $@ -c $^ -I.. -DUSMB2_FEATURE_CLOSE -DUSMB2_FEATURE_NTLM -DZ80 -DSLIP_ESC_00 -DRS232_TPS=80

ip-z80.o: ip-z80.asm
	zcc +zx -o $@ -c $<

slip-z80.o: slip-z80.asm
	zcc +zx -o $@ -c $< -Ca-DSLIP_ESC_00

tcp-z80.o: tcp-z80.asm
	zcc +zx -o $@ -c $< -Ca-DRS232_TPS=80

# Differential tests for the hand written layers.  Unlike the tests above
# these are Z80 programs: each one links the real stack twice, once from
# the .c file and once from the .asm, runs both under z88dk's z80
# simulator and checks that they emit the same bytes and return the same
# values.  Needs z88dk on the PATH, see the top of README.
#
# z88dk-ticks segfaults on a filename with no dot in it, hence the .bin.
test/ip-c.bin: test/test_ip.c ip.c ip.h
	zcc +test -I. -o $@ test/test_ip.c ip.c -create-app

test/ip-asm.bin: test/test_ip.c ip-z80.asm ip.h
	zcc +test -I. -o $@ test/test_ip.c ip-z80.asm -create-app

test/slip-c.bin: test/test_slip.c test/stub232.asm slip.c slip.h
	zcc +test -DSLIP_ESC_00 -I. -o $@ test/test_slip.c slip.c \
		test/stub232.asm -create-app

test/slip-asm.bin: test/test_slip.c test/stub232.asm slip-z80.asm slip.h
	zcc +test -DSLIP_ESC_00 -Ca-DSLIP_ESC_00 -I. -o $@ test/test_slip.c \
		slip-z80.asm test/stub232.asm -create-app

test/tcp-c.bin: test/test_tcp.c ip.c tcp.c tcp.h ip.h
	zcc +test -DRS232_TPS=80 -I. -o $@ test/test_tcp.c ip.c tcp.c -create-app

test/tcp-asm.bin: test/test_tcp.c ip.c tcp-z80.asm tcp.h ip.h
	zcc +test -DRS232_TPS=80 -I. -Ca-DRS232_TPS=80 -o $@ test/test_tcp.c \
		ip.c tcp-z80.asm -create-app

test/stack-c.bin: test/test_stack.c test/stub232.asm ip.c slip.c tcp.c tcp.h ip.h
	zcc +test -DRS232_TPS=80 -DSLIP_ESC_00 -I. -o $@ test/test_stack.c \
		ip.c slip.c tcp.c test/stub232.asm -create-app

test/stack-asm.bin: test/test_stack.c test/stub232.asm ip-z80.asm \
		    slip-z80.asm tcp-z80.asm tcp.h ip.h
	zcc +test -DRS232_TPS=80 -DSLIP_ESC_00 -Ca-DSLIP_ESC_00 \
		-Ca-DRS232_TPS=80 -I. -o $@ test/test_stack.c ip-z80.asm \
		slip-z80.asm tcp-z80.asm test/stub232.asm -create-app

test-stack: test/stack-c.bin test/stack-asm.bin
	z88dk-ticks test/stack-c.bin   | grep -v '^Ticks:' > test/stack-c.out
	z88dk-ticks test/stack-asm.bin | grep -v '^Ticks:' > test/stack-asm.out
	diff -u test/stack-c.out test/stack-asm.out
	@echo "the whole stack agrees, .c and .asm"

test-ip: test/ip-c.bin test/ip-asm.bin
	z88dk-ticks test/ip-c.bin   | grep -v '^Ticks:' > test/ip-c.out
	z88dk-ticks test/ip-asm.bin | grep -v '^Ticks:' > test/ip-asm.out
	diff -u test/ip-c.out test/ip-asm.out
	@echo "ip.c and ip-z80.asm agree"

test-slip: test/slip-c.bin test/slip-asm.bin
	z88dk-ticks test/slip-c.bin   | grep -v '^Ticks:' > test/slip-c.out
	z88dk-ticks test/slip-asm.bin | grep -v '^Ticks:' > test/slip-asm.out
	diff -u test/slip-c.out test/slip-asm.out
	@echo "slip.c and slip-z80.asm agree"

test-tcp: test/tcp-c.bin test/tcp-asm.bin
	z88dk-ticks test/tcp-c.bin   | grep -v '^Ticks:' > test/tcp-c.out
	z88dk-ticks test/tcp-asm.bin | grep -v '^Ticks:' > test/tcp-asm.out
	diff -u test/tcp-c.out test/tcp-asm.out
	@echo "tcp.c and tcp-z80.asm agree"

test-z80: test-ip test-slip test-tcp test-stack

clean:
	$(RM) *.o ../*.o *.tap *.bin smb2-cat-host test/*-c.bin test/*-asm.bin test/*-c.out test/*-asm.out

.PHONY: all clean test-ip test-slip test-tcp test-stack test-z80
