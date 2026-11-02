/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/* DO NOT EDIT. GENERATED. The C sources are canonical. */
/*
 * MD5 for the PS2 IOP (MIPS-I, little endian, o32), size optimised.
 * Drop-in replacement for md5.c: md5Init, md5Update, md5Finalize.
 *
 * Differences from md5.c that no caller can see:
 *  - md5Step and rotateLeft are not exported; nothing outside md5.c uses them.
 *  - md5Finalize leaves the length words in ctx->input[56..63]; md5.c leaves
 *    the bytes that were there before. Only ctx->input[0..15] (the digest)
 *    is meant to be read after md5Finalize.
 *  - ctx must be 4-byte aligned, as it already must be for md5.c.
 *
 * struct MD5Context { uint32_t size; uint32_t buffer[4]; uint8_t input[64]; }
 *                     0                4                   20
 */
#ifdef USMB2_FEATURE_NTLM

	.set	noreorder
	.set	noat

	.text

/* void md5Init(struct MD5Context *ctx) */
	.globl	md5Init
	.ent	md5Init
md5Init:
	li	$t0,0x67452301
	li	$t1,0xefcdab89
	nor	$t2,$t0,$zero		/* 0x98badcfe */
	nor	$t3,$t1,$zero		/* 0x10325476 */
	sw	$zero,0($a0)
	sw	$t0,4($a0)
	sw	$t1,8($a0)
	sw	$t2,12($a0)
	jr	$ra
	sw	$t3,16($a0)
	.end	md5Init

/* void md5Update(struct MD5Context *ctx, uint8_t *in, size_t len) */
	.globl	md5Update
	.ent	md5Update
md5Update:
	lw	$t0,0($a0)
	move	$v1,$ra			/* md5_block leaves a0-a3, v1 alone */
	addu	$t1,$t0,$a2
	sw	$t1,0($a0)
	beqz	$a2,2f
	andi	$a3,$t0,63		/* a3 = offset in ctx->input */
1:	lbu	$t0,0($a1)
	addu	$t1,$a0,$a3
	sb	$t0,20($t1)
	addiu	$a3,$a3,1
	andi	$a3,$a3,63
	bnez	$a3,3f
	addiu	$a2,$a2,-1
	jal	.Lblock1
	lw	$t0,4($a0)		/* first instruction of md5_block */
3:	bnez	$a2,1b
	addiu	$a1,$a1,1
2:	jr	$v1
	nop
	.end	md5Update

/* void md5Finalize(struct MD5Context *ctx) */
	.globl	md5Finalize
	.ent	md5Finalize
md5Finalize:
	lw	$a2,0($a0)		/* size, not changed by the padding */
	move	$v1,$ra
	li	$a1,0x80		/* pad byte: 0x80, then zeros */
	andi	$a3,$a2,63
1:	addu	$t1,$a0,$a3
	sb	$a1,20($t1)
	addiu	$a3,$a3,1
	andi	$a3,$a3,63
	bnez	$a3,3f
	move	$a1,$zero
	jal	.Lblock1
	lw	$t0,4($a0)
3:	xori	$t1,$a3,56
	bnez	$t1,1b
	sll	$t0,$a2,3		/* length in bits */
	sw	$t0,76($a0)
	sw	$zero,80($a0)
	jal	.Lblock1
	lw	$t0,4($a0)
	sw	$t0,20($a0)		/* digest = buffer, already little endian */
	sw	$t1,24($a0)
	sw	$t2,28($a0)
	jr	$v1
	sw	$t3,32($a0)
	.end	md5Finalize

/*
 * md5_block: one 64-byte block, ctx->buffer += MD5(ctx->input).
 * In: a0 = ctx. Clobbers t0-t9, v0, at; keeps a0-a3, v1.
 * Out: t0-t3 = the new ctx->buffer[0..3].
 * Callers put the first instruction in their jal delay slot and jal .Lblock1.
 *
 * t0-t3 = A B C D, t4 = round i, t5 = &md5_K, t6 = j*4, t7 = j step*4
 */
	.ent	md5_block
md5_block:
	lw	$t0,4($a0)
.Lblock1:
	lw	$t1,8($a0)
	lw	$t2,12($a0)
	lw	$t3,16($a0)
	la	$t5,md5_K
	move	$t4,$zero
.Lround:
	srl	$t8,$t4,1
	andi	$t8,$t8,0x18
	addu	$t8,$t8,$t5		/* t8 + 256 = this group's record */
	andi	$at,$t4,15
	bnez	$at,1f
	andi	$at,$t4,3
	lbu	$t6,256+4($t8)		/* new group: first j and j step */
	lbu	$t7,256+5($t8)
1:	addu	$at,$at,$t8
	lbu	$at,256($at)		/* at = shift */
	srl	$t9,$t4,4		/* group */
	beqz	$t9,.LF
	xor	$v0,$t2,$t3
	addiu	$t9,$t9,-2
	bltz	$t9,.LG
	xor	$v0,$t1,$t2
	beqz	$t9,.LE			/* H = B ^ C ^ D */
	xor	$v0,$v0,$t3
	nor	$v0,$t3,$zero		/* I = C ^ (B | ~D) */
	or	$v0,$v0,$t1
	b	.LE
	xor	$v0,$v0,$t2
.LG:	and	$v0,$v0,$t3		/* G = C ^ (D & (B ^ C)) */
	b	.LE
	xor	$v0,$v0,$t2
.LF:	and	$v0,$v0,$t1		/* F = D ^ (B & (C ^ D)) */
	xor	$v0,$v0,$t3
.LE:	sll	$t9,$t4,2
	addu	$t9,$t9,$t5
	lw	$t9,0($t9)		/* K[i] */
	addu	$t8,$a0,$t6
	lw	$t8,20($t8)		/* input[j] */
	addu	$v0,$v0,$t0
	addu	$v0,$v0,$t9
	addu	$v0,$v0,$t8
	sllv	$t8,$v0,$at		/* rotate left */
	subu	$at,$zero,$at
	srlv	$at,$v0,$at
	or	$v0,$t8,$at
	addu	$v0,$v0,$t1
	move	$t0,$t3
	move	$t3,$t2
	move	$t2,$t1
	addu	$t6,$t6,$t7
	andi	$t6,$t6,60
	addiu	$t4,$t4,1
	slti	$t9,$t4,64
	bnez	$t9,.Lround
	move	$t1,$v0

	lw	$t4,4($a0)
	lw	$t5,8($a0)
	lw	$t6,12($a0)
	lw	$t7,16($a0)
	addu	$t0,$t0,$t4
	addu	$t1,$t1,$t5
	addu	$t2,$t2,$t6
	addu	$t3,$t3,$t7
	sw	$t0,4($a0)
	sw	$t1,8($a0)
	sw	$t2,12($a0)
	jr	$ra
	sw	$t3,16($a0)
	.end	md5_block

	.rdata
	.align	2
md5_K:
	.word	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
	.word	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
	.word	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
	.word	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
	.word	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa
	.word	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
	.word	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed
	.word	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
	.word	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
	.word	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
	.word	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05
	.word	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
	.word	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
	.word	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
	.word	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
	.word	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
/* per group of 16 rounds: 4 shifts, first j * 4, j step * 4, 2 pad */
	.byte	7, 12, 17, 22,  0*4, 1*4, 0, 0
	.byte	5,  9, 14, 20,  1*4, 5*4, 0, 0
	.byte	4, 11, 16, 23,  5*4, 3*4, 0, 0
	.byte	6, 10, 15, 21,  0*4, 7*4, 0, 0

#endif /* USMB2_FEATURE_NTLM */
