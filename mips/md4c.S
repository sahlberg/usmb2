/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/* DO NOT EDIT. GENERATED. The C sources are canonical. */
/*
 * MD4 (RFC1320) for the PS2 IOP (MIPS-I, little endian, o32), size optimised.
 * Derived from the RSA Data Security, Inc. MD4 Message-Digest Algorithm.
 * Drop-in replacement for md4c.c: MD4Init, MD4Update, MD4Final.
 *
 * Differences from md4c.c that no caller can see:
 *  - count[] is only kept modulo 2^32 bits: count[1] stays 0, which is the
 *    same as md4c.c for anything shorter than 512 MB.
 *  - MD4Final does not add the padding to count[], and the bytes of
 *    buffer[] that hold no pending input can differ from md4c.c.
 *  - context and digest must be 4-byte aligned. usmb2's ntlm.c passes
 *    &usmb2->buf[0] and &usmb2->buf[96].
 *
 * typedef struct { uint32_t state[4]; uint32_t count[2]; uint8_t buffer[64]; } MD4_CTX;
 *                           0                  16                 24
 */
#ifdef USMB2_FEATURE_NTLM

	.set	noreorder
	.set	noat

	.text

/* void MD4Init(MD4_CTX *context) */
	.globl	MD4Init
	.ent	MD4Init
MD4Init:
	li	$t0,0x67452301
	li	$t1,0xefcdab89
	nor	$t2,$t0,$zero		/* 0x98badcfe */
	nor	$t3,$t1,$zero		/* 0x10325476 */
	sw	$t0,0($a0)
	sw	$t1,4($a0)
	sw	$t2,8($a0)
	sw	$t3,12($a0)
	sw	$zero,16($a0)
	jr	$ra
	sw	$zero,20($a0)
	.end	MD4Init

/* void MD4Update(MD4_CTX *context, unsigned char *input, unsigned int inputLen) */
	.globl	MD4Update
	.ent	MD4Update
MD4Update:
	lw	$t0,16($a0)		/* count[0], in bits */
	move	$v1,$ra			/* md4_block leaves a0-a3, v1 alone */
	sll	$t1,$a2,3
	addu	$t1,$t0,$t1
	sw	$t1,16($a0)
	srl	$a3,$t0,3
	beqz	$a2,2f
	andi	$a3,$a3,63		/* a3 = offset in buffer */
1:	lbu	$t0,0($a1)
	addu	$t1,$a0,$a3
	sb	$t0,24($t1)
	addiu	$a3,$a3,1
	andi	$a3,$a3,63
	bnez	$a3,3f
	addiu	$a2,$a2,-1
	jal	.Lblock1
	lw	$t0,0($a0)		/* first instruction of md4_block */
3:	bnez	$a2,1b
	addiu	$a1,$a1,1
2:	jr	$v1
	nop
	.end	MD4Update

/* void MD4Final(unsigned char digest[16], MD4_CTX *context) */
	.globl	MD4Final
	.ent	MD4Final
MD4Final:
	move	$a2,$a0			/* a2 = digest */
	move	$a0,$a1			/* a0 = context, as md4_block wants it */
	lw	$a3,16($a0)
	move	$v1,$ra
	li	$a1,0x80		/* pad byte: 0x80, then zeros */
	srl	$a3,$a3,3
	andi	$a3,$a3,63
1:	addu	$t1,$a0,$a3
	sb	$a1,24($t1)
	addiu	$a3,$a3,1
	andi	$a3,$a3,63
	bnez	$a3,3f
	move	$a1,$zero
	jal	.Lblock1
	lw	$t0,0($a0)
3:	xori	$t1,$a3,56
	bnez	$t1,1b
	lw	$t0,16($a0)		/* length in bits, from before the padding */
	sw	$zero,24+60($a0)
	sw	$t0,24+56($a0)
	jal	.Lblock1
	lw	$t0,0($a0)
	sw	$t0,0($a2)		/* digest = state, already little endian */
	sw	$t1,4($a2)
	sw	$t2,8($a2)
	jr	$v1
	sw	$t3,12($a2)
	.end	MD4Final

/*
 * md4_block: one 64-byte block, state += MD4(buffer).
 * In: a0 = context. Clobbers t0-t9, v0, at; keeps a0-a3, v1.
 * Out: t0-t3 = the new state[0..3].
 * Callers put the first instruction in their jal delay slot and jal .Lblock1.
 *
 * t0-t3 = A B C D, t4 = round i, t5 = &md4_tab, t6 = this group's 4 shifts
 * (one per byte), t7 = this group's constant
 */
	.ent	md4_block
md4_block:
	lw	$t0,0($a0)
.Lblock1:
	lw	$t1,4($a0)
	lw	$t2,8($a0)
	lw	$t3,12($a0)
	la	$t5,md4_tab
	move	$t4,$zero
.Lround:
	andi	$at,$t4,15
	bnez	$at,1f
	srl	$t9,$t4,4		/* group */
	sll	$t8,$t9,3
	addu	$t8,$t8,$t5
	lw	$t6,48($t8)		/* new group: shifts and constant */
	lw	$t7,52($t8)
1:	addu	$t8,$t5,$t4
	lbu	$t8,0($t8)		/* j * 4 */
	beqz	$t9,.LF
	xor	$v0,$t2,$t3
	addiu	$t9,$t9,-1
	bnez	$t9,.LE			/* H = B ^ C ^ D */
	xor	$v0,$v0,$t1
	or	$v0,$t1,$t2		/* G = (B & C) | (D & (B | C)) */
	and	$v0,$v0,$t3
	and	$t9,$t1,$t2
	b	.LE
	or	$v0,$v0,$t9
.LF:	and	$v0,$v0,$t1		/* F = D ^ (B & (C ^ D)) */
	xor	$v0,$v0,$t3
.LE:	addu	$t9,$a0,$t8
	lw	$t9,24($t9)		/* x[j] */
	addu	$v0,$v0,$t0
	addu	$v0,$v0,$t7
	addu	$v0,$v0,$t9
	andi	$at,$t4,3
	sll	$at,$at,3
	srlv	$at,$t6,$at		/* shift in the low 5 bits */
	sllv	$t8,$v0,$at		/* rotate left */
	subu	$at,$zero,$at
	srlv	$at,$v0,$at
	or	$v0,$t8,$at
	move	$t0,$t3
	move	$t3,$t2
	move	$t2,$t1
	addiu	$t4,$t4,1
	slti	$t9,$t4,48
	bnez	$t9,.Lround
	move	$t1,$v0

	lw	$t4,0($a0)
	lw	$t5,4($a0)
	lw	$t6,8($a0)
	lw	$t7,12($a0)
	addu	$t0,$t0,$t4
	addu	$t1,$t1,$t5
	addu	$t2,$t2,$t6
	addu	$t3,$t3,$t7
	sw	$t0,0($a0)
	sw	$t1,4($a0)
	sw	$t2,8($a0)
	jr	$ra
	sw	$t3,12($a0)
	.end	md4_block

	.rdata
	.align	2
md4_tab:
/* x[] index * 4 for each of the 48 rounds */
	.byte	 0*4,  1*4,  2*4,  3*4,  4*4,  5*4,  6*4,  7*4
	.byte	 8*4,  9*4, 10*4, 11*4, 12*4, 13*4, 14*4, 15*4
	.byte	 0*4,  4*4,  8*4, 12*4,  1*4,  5*4,  9*4, 13*4
	.byte	 2*4,  6*4, 10*4, 14*4,  3*4,  7*4, 11*4, 15*4
	.byte	 0*4,  8*4,  4*4, 12*4,  2*4, 10*4,  6*4, 14*4
	.byte	 1*4,  9*4,  5*4, 13*4,  3*4, 11*4,  7*4, 15*4
/* per group of 16 rounds: the 4 shifts, then the constant */
	.byte	3, 7, 11, 19
	.word	0
	.byte	3, 5, 9, 13
	.word	0x5a827999
	.byte	3, 9, 11, 15
	.word	0x6ed9eba1

#endif /* USMB2_FEATURE_NTLM */
