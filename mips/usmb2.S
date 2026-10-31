/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/*
 * usmb2.c for the PS2 IOP (MIPS-I, little endian, o32), size optimised, with
 * the features Neutrino builds it with: USMB2_FEATURE_TINY_TCP,
 * USMB2_FEATURE_REASSEMBLY and USMB2_FEATURE_NTLM, and nothing else.
 * Drop-in replacement for usmb2.c there; see usmb2.c for the protocol.
 *
 * Differences from usmb2.c:
 *  - The static helpers are folded into the request function, breq, which
 *    takes outdata, outdatacount, indata, indatacount in t4-t7, so send_pos
 *    and recv_pos are registers rather than variables.
 *  - The file id is copied with unaligned word loads/stores rather than
 *    memcpy, and buf is cleared with word stores rather than memset.
 *  - strcpy, calloc, free and, for the data, memcpy are still called.
 *
 * struct usmb2_context { int fd; char username[32]; char password[32];
 *	uint64_t message_id; uint64_t session_id; uint32_t tree_id; uint8_t buf[512]; }
 *	0, 4, 36, 72, 80, 88, 92; sizeof 608 (checked by the test)
 */
#ifdef USMB2_FEATURE_NTLM

	.set	noreorder

#define BUF		92
#define B_MID		(72 - BUF)	/* message_id, from buf */
#define B_SESS		(80 - BUF)
#define B_TREE		(88 - BUF)
#define SIZEOF_CTX	608
#define REASM		(4 + 64 + 16 + 2048)
#define T_PSIZE		8		/* tcp_context_t */
#define T_PKT		12
#define T_THS		28

#define CMD_NEGOTIATE	0
#define CMD_SESSSETUP	1
#define CMD_TREECONN	3
#define CMD_CREATE	5
#define CMD_READ	8
#define CMD_WRITE	9
#define CMD_QUERYINFO	16
#define MORE_PROCESSING	0xc0000016
#define STATUS_INTERNAL	0xc000020c

/* the frame of the public functions: 0-15 args, 20 s0, 24 s1, 28 ra */
#define PROLOGUE \
	addiu	$sp,$sp,-32; \
	sw	$ra,28($sp); \
	sw	$s0,20($sp); \
	sw	$s1,24($sp)

	.text

/* int usmb2_negotiateprotocol(struct usmb2_context *usmb2) */
	.globl	usmb2_negotiateprotocol
	.ent	usmb2_negotiateprotocol
usmb2_negotiateprotocol:
	PROLOGUE
	jal	clrbuf
	nop
	li	$t1,0x00010024		/* StructureSize 36, DialectCount 1 */
	sw	$t1,BUF + 4 + 64($a0)
	li	$t1,0xaa		/* ClientGuid */
	sb	$t1,BUF + 4 + 64 + 12($a0)
	li	$t1,0xbb
	sb	$t1,BUF + 4 + 64 + 27($a0)
	li	$t1,0x300		/* dialect 3.0 */
	sw	$t1,BUF + 4 + 64 + 36($a0)
	li	$a1,CMD_NEGOTIATE
	li	$a2,40
	jal	breq0
	li	$a3,64
	/* and on into .Lret_st */

/* the end of the public functions: v0 = status ? -1 : 0, and return */
.Lret_st:
	sltu	$v0,$zero,$v0
	subu	$v0,$zero,$v0
.Lret:	lw	$ra,28($sp)
	lw	$s0,20($sp)
	lw	$s1,24($sp)
	jr	$ra
	addiu	$sp,$sp,32
	.end	usmb2_negotiateprotocol

/* int usmb2_sessionsetup(struct usmb2_context *usmb2): s1 = NTLMSSP message type */
	.globl	usmb2_sessionsetup
	.ent	usmb2_sessionsetup
usmb2_sessionsetup:
	PROLOGUE
	move	$s0,$a0
	li	$s1,1
1:	xori	$t0,$s1,3
	bnez	$t0,2f
	move	$a0,$s0
	/* AUTHENTICATE, built by ntlm.c in place */
	addiu	$a1,$s0,4
	jal	ntlm_generate_auth
	addiu	$a2,$s0,36
	move	$a0,$s0
	jal	clrn			/* only up to the blob */
	li	$t1,4 + 64 + 24
	b	3f
	nop
2:	/* NEGOTIATE */
	jal	clrbuf
	nop
	li	$t0,1
	sb	$t0,BUF + 4 + 64 + 24 + 8($s0)
	li	$t0,0x20080227
	sw	$t0,BUF + 4 + 64 + 24 + 12($s0)
	li	$v0,32
3:	li	$t0,0x4d4c544e		/* "NTLMSSP" */
	sw	$t0,BUF + 4 + 64 + 24($s0)
	li	$t0,0x00505353
	sw	$t0,BUF + 4 + 64 + 24 + 4($s0)
	li	$t0,0x19		/* StructureSize 25 */
	sw	$t0,BUF + 4 + 64($s0)
	li	$t0,0x58		/* SecurityBufferOffset */
	sb	$t0,BUF + 4 + 64 + 12($s0)
	sh	$v0,BUF + 4 + 64 + 14($s0)
	addiu	$a2,$v0,24 + 7
	andi	$a2,$a2,0xfff8
	move	$a0,$s0
	li	$a1,CMD_SESSSETUP
	jal	breq0
	li	$a3,64
	li	$t0,MORE_PROCESSING
	bne	$v0,$t0,.Lret_st
	nop
	b	1b
	li	$s1,3
	.end	usmb2_sessionsetup

/* int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc) */
	.globl	usmb2_treeconnect
	.ent	usmb2_treeconnect
usmb2_treeconnect:
	PROLOGUE
	jal	clrbuf
	move	$s0,$a0
	li	$t0,0x09
	sb	$t0,BUF + 4 + 64($a0)
	li	$t0,0x48		/* PathOffset */
	sb	$t0,BUF + 4 + 64 + 4($a0)
	jal	putname
	addiu	$a0,$a0,BUF + 4 + 0x48
	sb	$v0,BUF + 4 + 64 + 6($s0)	/* PathLength */
	addiu	$a2,$v0,8
	move	$a0,$s0
	li	$a1,CMD_TREECONN
	jal	breq0
	li	$a3,16
	b	.Lret_st
	nop
	.end	usmb2_treeconnect

/* uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode) */
	.globl	usmb2_open
	.ent	usmb2_open
usmb2_open:
	PROLOGUE
	andi	$s1,$a2,0x0008		/* s1 = the size of the handle: 16, or 16 + 256 */
	beqz	$s1,1f
	li	$s1,16
	li	$s1,16 + 256
1:	jal	clrbuf
	move	$s0,$a0
	li	$t0,0x39
	sb	$t0,BUF + 4 + 64($a0)
	li	$t0,0x02		/* OplockLevel */
	sb	$t0,BUF + 4 + 64 + 4($a0)
	li	$t0,0x89		/* DesiredAccess */
	sb	$t0,BUF + 4 + 64 + 24($a0)
	li	$t0,0x03		/* CreateDisposition */
	sb	$t0,BUF + 4 + 64 + 32($a0)
	li	$t0,0x01
	sb	$t0,BUF + 4 + 64 + 36($a0)
	li	$t0,0x40		/* CreateOptions */
	sb	$t0,BUF + 4 + 64 + 40($a0)
	li	$t0,0x78		/* NameOffset */
	sb	$t0,BUF + 4 + 64 + 44($a0)
	jal	putname
	addiu	$a0,$a0,BUF + 4 + 0x78
	sb	$v0,BUF + 4 + 64 + 46($s0)	/* NameLength */
	addiu	$a2,$v0,0x38 + 8
	move	$a0,$s0
	li	$a1,CMD_CREATE
	jal	breq0
	li	$a3,88
	bnez	$v0,9f
	li	$a0,1
	jal	calloc
	move	$a1,$s1
	beqz	$v0,.Lret
	move	$s1,$v0
	move	$a0,$v0
	jal	cpy16			/* the file id */
	addiu	$a1,$s0,BUF + 64
	b	.Lret
	move	$v0,$s1
9:	b	.Lret
	move	$v0,$zero
	.end	usmb2_open

/* int32_t usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, uint64_t offset) */
	.globl	usmb2_pread
	.ent	usmb2_pread
usmb2_pread:
	lw	$t6,16($sp)		/* offset */
	lw	$t7,20($sp)
	move	$t5,$a3			/* count */
	move	$a3,$a2			/* rbuf */
	move	$a2,$a1			/* fid */
	li	$a1,CMD_READ
	b	prw
	move	$t4,$zero		/* wbuf */
	.end	usmb2_pread

/*
 * int32_t usmb2_prw(struct usmb2_context *usmb2, int cmd, uint8_t *fid, uint8_t *rbuf,
 *                   uint8_t *wbuf, int count, uint64_t offset)
 * prw: the same with wbuf, count, offset in t4, t5, t6/t7
 */
	.globl	usmb2_prw
	.ent	usmb2_prw
usmb2_prw:
	lw	$t4,16($sp)
	lw	$t5,20($sp)
	lw	$t6,24($sp)
	lw	$t7,28($sp)
prw:	PROLOGUE
	move	$s0,$a0
	jal	clrbuf
	move	$s1,$a1
	xori	$t0,$s1,CMD_WRITE
	sltiu	$t0,$t0,1
	subu	$t0,$zero,$t0		/* t0 = write ? -1 : 0 */
	lui	$t2,0x70		/* 0x70 in byte 2 for a write */
	and	$t2,$t2,$t0
	ori	$t2,$t2,0x31		/* StructureSize 49 */
	sw	$t2,BUF + 4 + 64($a0)
	sw	$t5,BUF + 4 + 64 + 4($a0)	/* Length */
	sw	$t6,BUF + 4 + 64 + 8($a0)	/* Offset */
	sw	$t7,BUF + 4 + 64 + 12($a0)
	xori	$t3,$s1,CMD_READ
	sltiu	$t3,$t3,1		/* t3 = read */
	subu	$t2,$zero,$t3
	and	$t7,$t5,$t2		/* indatacount = read ? count : 0 */
	and	$t5,$t5,$t0		/* outdatacount = write ? count : 0 */
	move	$t6,$a3			/* indata */
	move	$a1,$a2
	jal	cpy16			/* FileId; cpy16 leaves t2-t7 alone */
	addiu	$a0,$a0,BUF + 4 + 64 + 16
	sll	$a2,$t3,3
	addiu	$a2,$a2,48		/* 48, and 8 more for a read */
	move	$a0,$s0
	move	$a1,$s1
	jal	breq
	li	$a3,16
	bnez	$v0,.Lret
	nop
	b	.Lret
	lw	$v0,BUF + 4($s0)	/* DataLength */
	.end	usmb2_prw

/* int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid) */
	.globl	usmb2_size
	.ent	usmb2_size
usmb2_size:
	PROLOGUE
	move	$s0,$a0
	jal	clrbuf
	move	$s1,$a1
	li	$t0,0x05010029		/* QUERY_INFO: FILE_INFORMATION, FileStandardInformation */
	sw	$t0,BUF + 4 + 64($a0)
	li	$t0,0xffff		/* OutputBufferLength */
	sw	$t0,BUF + 4 + 64 + 4($a0)
	li	$t0,0x68
	sw	$t0,BUF + 4 + 64 + 8($a0)
	move	$a1,$s1
	jal	cpy16
	addiu	$a0,$a0,BUF + 4 + 64 + 24
	move	$a0,$s0
	li	$a1,CMD_QUERYINFO
	li	$a2,40
	jal	breq0
	li	$a3,8
	bnez	$v0,.Lret
	li	$v0,-1
	b	.Lret
	lw	$v0,BUF + 8 + 8($s0)	/* EndOfFile */
	.end	usmb2_size

/* struct usmb2_context *usmb2_init_context(uint32_t ip, char *username, char *password) */
	.globl	usmb2_init_context
	.ent	usmb2_init_context
usmb2_init_context:
	PROLOGUE
	move	$s0,$a1
	move	$s1,$a2
	li	$a0,1
	jal	calloc
	li	$a1,SIZEOF_CTX
	beqz	$v0,.Lret
	move	$a1,$s0
	move	$s0,$v0			/* s0 = usmb2 */
	jal	strcpy
	addiu	$a0,$v0,4
	move	$a1,$s1
	jal	strcpy
	addiu	$a0,$s0,36
	jal	usmb2_negotiateprotocol
	move	$a0,$s0
	bnez	$v0,9f
	nop
	jal	usmb2_sessionsetup
	move	$a0,$s0
	beqz	$v0,.Lret
	move	$v0,$s0
9:	jal	free
	move	$a0,$s0
	b	.Lret
	move	$v0,$zero
	.end	usmb2_init_context

/*
 * breq: usmb2_build_request(usmb2, command, commandoutcount, commandincount,
 *         outdata, outdatacount, indata, indatacount)
 * with a0-a3 as there and the other four in t4-t7; breq0 has those 0.
 * Returns the NT status of the reply.
 * s0 = buf, s1 = command, then the status, s2 = commandoutcount, then the
 * message id, s3 = commandincount, s4 = outdata, then the length in reasm,
 * then where we are in reasm, s5 = outdatacount, then the spl,
 * s6 = indata, s7 = indatacount
 */
	.ent	breq
breq0:	move	$t4,$zero
	move	$t5,$zero
	move	$t6,$zero
	move	$t7,$zero
breq:	addiu	$sp,$sp,-56
	sw	$ra,52($sp)
	sw	$s0,20($sp)
	sw	$s1,24($sp)
	sw	$s2,28($sp)
	sw	$s3,32($sp)
	sw	$s4,36($sp)
	sw	$s5,40($sp)
	sw	$s6,44($sp)
	sw	$s7,48($sp)
	addiu	$s0,$a0,BUF
	move	$s1,$a1
	move	$s2,$a2
	move	$s3,$a3
	move	$s4,$t4
	move	$s5,$t5
	move	$s6,$t6
	move	$s7,$t7
	/* the SPL and the SMB2 header */
	addiu	$a0,$s2,64
	jal	bswap
	addu	$a0,$a0,$s5
	sw	$v0,0($s0)
	li	$t0,0x424d53fe		/* 0xfe "SMB" */
	sw	$t0,4($s0)
	sltu	$t0,$zero,$s1
	sll	$t0,$t0,16
	ori	$t0,$t0,0x40		/* StructureSize 64, CreditCharge 1 but for NEGOTIATE */
	sw	$t0,8($s0)
	lui	$t0,1			/* Command, CreditRequest 1 */
	addu	$t0,$t0,$s1
	sw	$t0,16($s0)
	lw	$t0,B_MID($s0)		/* MessageId = message_id++, 32 bits of it */
	lw	$t1,B_MID + 4($s0)
	sw	$zero,32($s0)
	sw	$t0,28($s0)
	addiu	$t2,$t0,1
	sltu	$t3,$t2,$t0
	addu	$t1,$t1,$t3
	sw	$t2,B_MID($s0)
	sw	$t1,B_MID + 4($s0)
	lw	$t1,B_TREE($s0)
	lw	$t2,B_SESS($s0)
	lw	$t3,B_SESS + 4($s0)
	sw	$t1,40($s0)
	sw	$t2,44($s0)
	sw	$t3,48($s0)

	/* into the TCP payload: outdata, or buf as usmb2.c does, then the header */
	la	$t9,usmb2_tcp
	lw	$t9,0($t9)
	move	$a1,$s0
	lw	$t9,T_PKT($t9)
	beqz	$s4,1f
	addiu	$a0,$s2,40 + 4 + 64
	move	$a1,$s4
1:	addu	$a0,$a0,$t9
	jal	memcpy
	move	$a2,$s5
	la	$t9,usmb2_tcp
	lw	$t9,0($t9)
	nop
	lw	$a0,T_PKT($t9)
	move	$a1,$s0
	addiu	$a2,$s2,4 + 64
	jal	memcpy
	addiu	$a0,$a0,40
	la	$t9,usmb2_tcp
	lw	$a0,0($t9)
	addiu	$a1,$s2,4 + 64
	addu	$a1,$a1,$s5
	move	$a2,$zero
	jal	tcp_send		/* tcp_send(usmb2_tcp, send_pos, NULL, REASM): window open */
	li	$a3,REASM
	lw	$t0,B_MID($s0)
	move	$s4,$zero
	addiu	$s2,$t0,-1		/* s2 = this message id */

	/* the reply, reassembled from its segments in reasm */
.Lrecv:	la	$t9,usmb2_tcp
	lw	$a0,0($t9)
	nop
	lhu	$a1,T_PSIZE($a0)
	jal	tcp_recv
	nop
	bltz	$v0,.Lbfail
	nop
	beqz	$v0,.Lrecv
	addu	$t0,$s4,$v0
	sltiu	$t0,$t0,REASM + 1
	beqz	$t0,.Lbfail
	move	$s5,$v0
	la	$t9,usmb2_tcp
	lw	$t9,0($t9)
	la	$a0,reasm
	lw	$a1,T_PKT($t9)		/* tcp_rx_buffer() */
	lbu	$t1,T_THS($t9)
	addu	$a0,$a0,$s4
	addiu	$a1,$a1,20
	addu	$a1,$a1,$t1
	jal	memcpy
	move	$a2,$v0
	addu	$s4,$s4,$s5
	slti	$t0,$s4,4
	bnez	$t0,.Lrecv
	nop
	la	$t9,reasm
	lw	$a0,0($t9)
	jal	bswap
	nop
	sltiu	$t0,$v0,REASM - 4 + 1
	beqz	$t0,.Lbfail
	move	$s5,$v0			/* s5 = spl */
	addiu	$t0,$v0,4
	slt	$t0,$s4,$t0
	bnez	$t0,.Lrecv		/* not all of it yet */
	nop
	la	$t9,reasm
	lw	$t0,28($t9)		/* its MessageId */
	move	$s4,$zero
	bne	$t0,$s2,.Lrecv		/* not the reply to this request */
	nop

	la	$s4,reasm + 4		/* s4 = where we are in reasm */
	move	$a0,$s0
	move	$a1,$s4
	jal	memcpy
	li	$a2,64
	addiu	$s4,$s4,64
	addiu	$s5,$s5,-64
	xori	$t0,$s1,CMD_SESSSETUP
	bnez	$t0,2f
	xori	$t0,$s1,CMD_TREECONN
	lw	$t1,0x28($s0)		/* SessionId */
	lw	$t2,0x2c($s0)
	sw	$t1,B_SESS($s0)
	sw	$t2,B_SESS + 4($s0)
2:	lw	$t1,0x24($s0)		/* TreeId */
	bnez	$t0,3f
	lw	$s1,8($s0)		/* s1 = Status */
	sw	$t1,B_TREE($s0)
3:	sltu	$t0,$s5,$s3		/* the command, at most spl */
	beqz	$t0,4f
	nop
	move	$s3,$s5
4:	move	$a0,$s0
	move	$a1,$s4
	jal	memcpy
	move	$a2,$s3
	addu	$s4,$s4,$s3
	beqz	$s6,5f
	subu	$s5,$s5,$s3
	sltu	$t0,$s5,$s7		/* the data, at most what is left */
	beqz	$t0,6f
	nop
	move	$s7,$s5
6:	move	$a0,$s6
	move	$a1,$s4
	jal	memcpy
	move	$a2,$s7
	addu	$s4,$s4,$s7
	subu	$s5,$s5,$s7
5:	/* and the rest after the command, a buffer full at a time, as usmb2.c */
	beqz	$s5,8f
	li	$t0,512
	subu	$a2,$t0,$s3
	sltu	$t0,$s5,$a2
	beqz	$t0,7f
	addu	$a0,$s0,$s3
	move	$a2,$s5
7:	move	$a1,$s4
	addu	$s4,$s4,$a2
	jal	memcpy
	subu	$s5,$s5,$a2
	b	5b
	nop
8:	b	.Lbret
	move	$v0,$s1
.Lbfail:
	li	$v0,STATUS_INTERNAL
.Lbret:	lw	$ra,52($sp)
	lw	$s0,20($sp)
	lw	$s1,24($sp)
	lw	$s2,28($sp)
	lw	$s3,32($sp)
	lw	$s4,36($sp)
	lw	$s5,40($sp)
	lw	$s6,44($sp)
	lw	$s7,48($sp)
	jr	$ra
	addiu	$sp,$sp,56
	.end	breq

/* clrbuf: zero usmb2->buf, a0 = usmb2; clrn: its first t1 bytes. Clobbers t0, t1. */
	.ent	clrbuf
clrbuf:	li	$t1,512
clrn:	addiu	$t0,$a0,BUF
	addu	$t1,$t0,$t1
1:	addiu	$t0,$t0,4
	bne	$t0,$t1,1b
	sw	$zero,-4($t0)
	jr	$ra
	nop
	.end	clrbuf

/* putname: a1 = ASCII name to UTF-16LE at a0 (the high bytes are already 0); v0 = its length */
	.ent	putname
putname:
	move	$v0,$a0
1:	lbu	$t0,0($a1)
	addiu	$a1,$a1,1
	beqz	$t0,2f
	nop
	sb	$t0,0($a0)
	b	1b
	addiu	$a0,$a0,2
2:	jr	$ra
	subu	$v0,$a0,$v0
	.end	putname

/* cpy16: copy the 16-byte file id at a1 to a0, either unaligned. Clobbers t0, t1. */
	.ent	cpy16
cpy16:	lwr	$t0,0($a1)
	lwl	$t0,3($a1)
	lwr	$t1,4($a1)
	lwl	$t1,7($a1)
	swr	$t0,0($a0)
	swl	$t0,3($a0)
	swr	$t1,4($a0)
	swl	$t1,7($a0)
	lwr	$t0,8($a1)
	lwl	$t0,11($a1)
	lwr	$t1,12($a1)
	lwl	$t1,15($a1)
	swr	$t0,8($a0)
	swl	$t0,11($a0)
	swr	$t1,12($a0)
	jr	$ra
	swl	$t1,15($a0)
	.end	cpy16

/* v0 = a0 with its bytes swapped round; clobbers t0 */
	.ent	bswap
bswap:	sll	$v0,$a0,24
	srl	$t0,$a0,24
	or	$v0,$v0,$t0
	andi	$t0,$a0,0xff00
	sll	$t0,$t0,8
	or	$v0,$v0,$t0
	srl	$t0,$a0,8
	andi	$t0,$t0,0xff00
	jr	$ra
	or	$v0,$v0,$t0
	.end	bswap

	.globl	usmb2_tcp
	.bss
	.align	2
usmb2_tcp:
	.space	4
reasm:	.space	REASM

#endif /* USMB2_FEATURE_NTLM */
