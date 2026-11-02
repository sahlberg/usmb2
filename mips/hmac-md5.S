/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/* DO NOT EDIT. GENERATED. The C sources are canonical. */
/*
 * HMAC-MD5 (RFC2104) for the PS2 IOP (MIPS-I, little endian, o32), size optimised.
 * Drop-in replacement for hmac-md5.c, on md5Init/md5Update/md5Finalize.
 *
 * void hmac_md5(struct MD5Context *ctx,
 *               unsigned char *text0,			   nul-terminated, hashed as uppercase UCS2
 *               unsigned char *text1, int text1_len,
 *               unsigned char *text2, int text2_len,
 *               unsigned char *key, unsigned int key_len,
 *               unsigned char *digest);
 *
 * Differences from hmac-md5.c:
 *  - No k_pad[] buffer: after md5Init ctx->input is empty, so the padded key
 *    is built in ctx->input and hashed with md5Update(ctx, ctx->input, 64).
 *    This also needs no stack for it, nor memset/memmove/memcpy/toupper.
 *  - text1/text2 are not tested for NULL: a NULL text must have length 0,
 *    and an update of length 0 does nothing. ntlm.c passes NULL, 0.
 *  - text0 bytes >= 0x80 are hashed with a high byte of 0, as on hosts
 *    with an unsigned toupper(); the IOP's signed char _toupper() made
 *    that 0xff. ASCII user names hash the same either way.
 *  - key_len must be at most 64, as it already had to be.
 *
 * The two passes are one loop: the second is the first with
 * text0 = NULL, text1 = digest, text1_len = 16, text2_len = 0 and pad 0x5c.
 */
#ifdef USMB2_FEATURE_NTLM

	.set	noreorder

/* frame: 16 tmp for text0 chars, 20 s2, 24 s1, 28 s0, 32 ra; caller's args from 40 */
#define F_TMP	16
#define A_TEXT1	(40 + 8)
#define A_LEN1	(40 + 12)
#define A_TEXT2	(40 + 16)
#define A_LEN2	(40 + 20)
#define A_KEY	(40 + 24)
#define A_KLEN	(40 + 28)
#define A_DIG	(40 + 32)

	.text
	.globl	hmac_md5
	.ent	hmac_md5
hmac_md5:
	addiu	$sp,$sp,-40
	sw	$ra,32($sp)
	sw	$s0,28($sp)
	sw	$s1,24($sp)
	sw	$s2,20($sp)
	sw	$a2,A_TEXT1($sp)
	sw	$a3,A_LEN1($sp)
	move	$s0,$a0			/* s0 = ctx */
	move	$s2,$a1			/* s2 = text0 */
	li	$s1,0x36		/* s1 = pad byte */
.Lpass:
	jal	md5Init
	move	$a0,$s0

	/* ctx->input[i] = (i < key_len ? key[i] : 0) ^ pad, i = 0..63 */
	lw	$t1,A_KEY($sp)
	lw	$t2,A_KLEN($sp)
	move	$t0,$zero
	move	$t4,$t1
1:	sltu	$t3,$t0,$t2
	beqz	$t3,2f
	move	$t5,$zero
	lbu	$t5,0($t4)
2:	addu	$t6,$s0,$t0
	xor	$t5,$t5,$s1
	sb	$t5,20($t6)
	addiu	$t0,$t0,1
	slti	$t3,$t0,64
	bnez	$t3,1b
	addu	$t4,$t1,$t0
	addiu	$a1,$s0,20
	jal	upd
	li	$a2,64

	/* text0 as uppercase UCS2 */
	beqz	$s2,4f
	nop
	lbu	$t0,0($s2)
.Lt0next:
	addiu	$s2,$s2,1
	beqz	$t0,4f
	addiu	$t1,$t0,-'a'
	sltiu	$t1,$t1,26
	sll	$t1,$t1,5
	subu	$t0,$t0,$t1
	sh	$t0,F_TMP($sp)
	addiu	$a1,$sp,F_TMP
	jal	upd
	li	$a2,2
	b	.Lt0next		/* into the loop after its first load */
	lbu	$t0,0($s2)

4:	lw	$a1,A_TEXT1($sp)
	jal	upd
	lw	$a2,A_LEN1($sp)
	lw	$a1,A_TEXT2($sp)
	jal	upd
	lw	$a2,A_LEN2($sp)
	jal	md5Finalize
	move	$a0,$s0

	/* memcpy(digest, ctx->input, 16), digest may be unaligned */
	lw	$t0,A_DIG($sp)
	move	$t1,$zero
	move	$t2,$s0
5:	lbu	$t2,20($t2)
	addu	$t3,$t0,$t1
	addiu	$t1,$t1,1
	sb	$t2,0($t3)
	slti	$t4,$t1,16
	bnez	$t4,5b
	addu	$t2,$s0,$t1

	xori	$t0,$s1,0x5c
	beqz	$t0,6f			/* that was the outer pass */
	li	$s1,0x5c
	move	$s2,$zero		/* inner pass done: hash 16 bytes of digest */
	lw	$t0,A_DIG($sp)
	li	$t1,16
	sw	$t1,A_LEN1($sp)
	sw	$t0,A_TEXT1($sp)
	b	.Lpass
	sw	$zero,A_LEN2($sp)

6:	lw	$ra,32($sp)
	lw	$s0,28($sp)
	lw	$s1,24($sp)
	lw	$s2,20($sp)
	jr	$ra
	addiu	$sp,$sp,40

/* md5Update(ctx, a1, a2) */
upd:	j	md5Update
	move	$a0,$s0
	.end	hmac_md5

#endif /* USMB2_FEATURE_NTLM */
