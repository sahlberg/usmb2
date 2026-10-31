/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/*
 * NTLMv2 AUTHENTICATE message for the PS2 IOP (MIPS-I, little endian, o32),
 * size optimised. Drop-in replacement for ntlm.c, see there for the layout
 * of usmb2->buf before and after.
 *
 * int ntlm_generate_auth(struct usmb2_context *usmb2, char *username, char *password);
 *
 * Differences from ntlm.c:
 *  - The response is filled in from the top down, so every source is read
 *    before it is overwritten, and all copies run from the end backwards
 *    (every destination is above its source). This gives the same result
 *    as ntlm.c's order and memmoves, also for a TargetInfo of 100+ bytes.
 *  - The UTF-16 password is built in place in the MD4 context's buffer and
 *    hashed with one MD4Update, so the password must be at most 32
 *    characters (usmb2->password[32] holds at most 31).
 *  - It needs no strlen/memcpy/memset.
 * Everything else in usmb2->buf comes out the same, except the scratch
 * bytes of the MD4 and MD5 contexts in buf[0..91] that md4c.S and md5.S
 * leave differently; usmb2.c does not read them.
 */
#ifdef USMB2_FEATURE_NTLM

	.set	noreorder

#define BUF	92		/* offsetof(struct usmb2_context, buf), checked by the test */
#define OUT	(4 + 64 + 24)	/* where the NTLMSSP blob goes in buf */

/* frame: 0-35 args for hmac_md5, 36-51 NTOWFv2, 52-72 s0-s5, 76 ra */
#define F_NTOWF	36
#define F_SIZE	80

	.text
	.globl	ntlm_generate_auth
	.ent	ntlm_generate_auth
ntlm_generate_auth:
	addiu	$sp,$sp,-F_SIZE
	sw	$ra,76($sp)
	sw	$s0,52($sp)
	sw	$s1,56($sp)
	sw	$s2,60($sp)
	sw	$s3,64($sp)
	sw	$s4,68($sp)
	sw	$s5,72($sp)
	addiu	$s0,$a0,BUF		/* s0 = buf */
	move	$s1,$a1			/* s1 = username */
	move	$s2,$a2			/* s2 = password */

	lhu	$t0,4($s0)		/* SecurityBufferOffset */
	move	$t4,$s1
	addiu	$t0,$t0,-64
	andi	$t0,$t0,0xffff
	addu	$t7,$s0,$t0		/* t7 = incoming NTLMSSP CHALLENGE */
	lhu	$s4,12($t7)		/* s4 = TargetName length */
	lw	$t2,16($t7)
	lw	$t3,44($t7)
	addu	$t2,$t7,$t2		/* t2 = TargetName */
	addu	$t3,$t7,$t3		/* t3 = TargetInfo */

1:	lbu	$t5,0($t4)		/* t6 = user_name_len = 2 * strlen(username) */
	addiu	$t4,$t4,1
	bnez	$t5,1b
	subu	$t6,$t4,$s1
	addiu	$t6,$t6,-1
	sll	$t6,$t6,1
	addiu	$s3,$s4,72
	addu	$s3,$s3,$t6		/* s3 = ntlm_response_offset */
	addu	$t8,$s0,$s3		/* t8 = buf + ntlm_response_offset */

	/* t9 = length of the TargetInfo AvPairs, without the EndOfList */
	move	$t9,$zero
2:	addu	$t0,$t3,$t9
	lhu	$t1,0($t0)
	lhu	$t0,2($t0)
	beqz	$t1,3f
	addiu	$t0,$t0,4
	b	2b
	addu	$t9,$t9,$t0
3:
	/*
	 * Fill in the response from the top down, so that each source in the
	 * CHALLENGE is read before anything lands on it.
	 * After the AvPairs: TargetName as "cifs/<TargetName>", then EndOfList.
	 */
	addu	$v0,$t8,$t9
	addiu	$v0,$v0,OUT+44
	li	$t0,9
	sh	$t0,0($v0)
	addiu	$t0,$s4,10
	sh	$t0,2($v0)
	addiu	$a0,$v0,4
	la	$a1,cifs
	jal	cpy
	li	$a2,10
	move	$a1,$t2
	jal	cpy
	move	$a2,$s4
	sh	$zero,0($v0)		/* EndOfList and 4 bytes of padding */
	sh	$zero,2($v0)
	sh	$zero,4($v0)
	sh	$zero,6($v0)
	addiu	$s5,$v0,8		/* s5 = end of the message */
	/* the AvPairs from the server */
	addiu	$a0,$t8,OUT+44
	move	$a1,$t3
	jal	cpy
	move	$a2,$t9
	/* temp: resp types 0x0101, 6 zero, timestamp 0, client challenge 0x01 * 8, 4 zero */
	addiu	$a0,$t8,OUT+16
	la	$a1,temp
	jal	cpy
	li	$a2,28
	/* the server challenge, just before temp */
	addiu	$a0,$t8,OUT+8
	addiu	$a1,$t7,24
	jal	cpy
	li	$a2,8

	/* DomainName goes at offset 72 in the NTLMSSP blob */
	addiu	$a0,$s0,OUT+72
	move	$a1,$t2
	jal	cpy
	move	$a2,$s4
	sh	$s4,OUT+28($s0)
	sh	$s4,OUT+30($s0)
	li	$t0,72
	sw	$t0,OUT+32($s0)

	/* NtChallengeResponse */
	subu	$t0,$s5,$t8
	addiu	$t0,$t0,-OUT
	sh	$t0,OUT+20($s0)
	sh	$t0,OUT+22($s0)
	sw	$s3,OUT+24($s0)

	/* UserName, as UTF-16 right after DomainName */
	addu	$a0,$s0,$s4
	addiu	$a0,$a0,OUT+72
	jal	utf16
	move	$a1,$s1
	sh	$t6,OUT+36($s0)
	sh	$t6,OUT+38($s0)
	addiu	$t0,$s4,72
	sw	$t0,OUT+40($s0)
	sw	$zero,OUT+44($s0)	/* Workstation and EncryptedRandomSessionKey */
	sw	$zero,OUT+48($s0)
	sw	$zero,OUT+52($s0)
	li	$t0,0x20088037		/* NegotiateFlags */
	sw	$t0,OUT+56($s0)
	sw	$zero,OUT+60($s0)	/* Version */
	sw	$zero,OUT+64($s0)

	/* NTOWFv1 = MD4(UTF-16 password), the MD4 context at buf[0], the hash at buf[96] */
	jal	MD4Init
	move	$a0,$s0
	addiu	$a0,$s0,24		/* build it in ctx->buffer, then update from there */
	jal	utf16
	move	$a1,$s2
	addiu	$a1,$s0,24
	subu	$a2,$v0,$a1
	jal	MD4Update
	move	$a0,$s0
	addiu	$a0,$s0,96
	jal	MD4Final
	move	$a1,$s0

	/* NTOWFv2 = HMAC_MD5(NTOWFv1, UPPER(username) . DomainName) */
	addiu	$t0,$s0,OUT+72
	sw	$t0,16($sp)
	sw	$s4,20($sp)
	addiu	$t0,$s0,96
	sw	$t0,24($sp)
	li	$t1,16
	sw	$t1,28($sp)
	addiu	$t0,$sp,F_NTOWF
	sw	$t0,32($sp)
	move	$a0,$s0
	move	$a1,$s1
	move	$a2,$zero
	jal	hmac_md5
	move	$a3,$zero

	/* NTProofStr = HMAC_MD5(NTOWFv2, ServerChallenge . temp), over the start of temp */
	addu	$t2,$s0,$s3
	sw	$zero,16($sp)
	sw	$zero,20($sp)
	addiu	$t0,$sp,F_NTOWF
	sw	$t0,24($sp)
	li	$t1,16
	sw	$t1,28($sp)
	addiu	$t0,$t2,OUT
	sw	$t0,32($sp)
	move	$a0,$s0
	move	$a1,$zero
	addiu	$a2,$t2,OUT+8
	subu	$a3,$s5,$t2
	jal	hmac_md5
	addiu	$a3,$a3,-(OUT+8)

	/* the first 20 bytes of the NTLMSSP blob: "NTLMSSP\0" is still there, type 3 */
	li	$t0,3
	sw	$t0,OUT+8($s0)
	sw	$zero,OUT+12($s0)
	sw	$zero,OUT+16($s0)

	subu	$v0,$s5,$s0
	addiu	$v0,$v0,-OUT
	lw	$ra,76($sp)
	lw	$s0,52($sp)
	lw	$s1,56($sp)
	lw	$s2,60($sp)
	lw	$s3,64($sp)
	lw	$s4,68($sp)
	lw	$s5,72($sp)
	jr	$ra
	addiu	$sp,$sp,F_SIZE

/*
 * cpy: copy a2 bytes from a1 to a0, from the end backwards (the
 * destinations here are all above their sources). Returns v0 = a0 = a0 + a2.
 * Clobbers t0, t1, a2.
 */
cpy:	beqz	$a2,9f
	addu	$v0,$a0,$a2
1:	addiu	$a2,$a2,-1
	addu	$t0,$a1,$a2
	lbu	$t0,0($t0)
	addu	$t1,$a0,$a2
	bnez	$a2,1b
	sb	$t0,0($t1)
9:	jr	$ra
	move	$a0,$v0

/*
 * utf16: a1 = ASCII string to UTF-16LE at a0, without the terminator.
 * Returns v0 = the end. Clobbers t0, a0, a1, and the byte at v0 + 1:
 * for the UserName that is in the NTProofStr, written later; for the
 * password it is in the MD4 buffer, which MD4Final pads over.
 */
utf16:	lbu	$t0,0($a1)
	addiu	$a1,$a1,1
	beqz	$t0,1f
	sb	$zero,1($a0)
	sb	$t0,0($a0)
	b	utf16
	addiu	$a0,$a0,2
1:	jr	$ra
	move	$v0,$a0
	.end	ntlm_generate_auth

	.rdata
temp:	.byte	1, 1, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1
	.byte	0, 0, 0, 0
cifs:	.byte	'c', 0, 'i', 0, 'f', 0, 's', 0, '/', 0

#endif /* USMB2_FEATURE_NTLM */
