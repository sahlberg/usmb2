/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/*
 * The IPv4 layer of the tiny TCP/IP stack (z80/ip.c) for the PS2 IOP
 * (MIPS-I, little endian, o32), size optimised. Drop-in replacement for ip.c.
 *
 * Differences from ip.c:
 *  - ip->pkt must be 4-byte aligned: the header is written with word
 *    stores. Neutrino's smb_conn.c gives it tcp_buf, which is aligned(4).
 *  - csum() only clobbers v0, t0, t1, a0, a1; ip_build_and_send relies on it.
 *
 * typedef struct ip_context { uint32_t saddr; uint32_t daddr; uint16_t pkt_size;
 *                             0                4                8
 *                             uint16_t id; uint8_t *pkt; } ip_context_t;
 *                             10           12
 */
	.set	noreorder

	.text

/* uint16_t csum(uint16_t *ptr, int nbytes): ptr 2-byte aligned */
	.globl	csum
	.ent	csum
csum:	b	2f
	move	$v0,$zero
1:	lhu	$t0,0($a0)
	addiu	$a1,$a1,-2
	addiu	$a0,$a0,2
	addu	$v0,$v0,$t0
2:	slti	$t0,$a1,2
	beqz	$t0,1b
	xori	$t1,$a1,1
	bnez	$t1,3f			/* no odd byte */
	nop
	lbu	$t0,0($a0)
	nop
	addu	$v0,$v0,$t0
3:	srl	$t0,$v0,16
	andi	$v0,$v0,0xffff
	addu	$v0,$v0,$t0
	srl	$t0,$v0,16
	addu	$v0,$v0,$t0
	nor	$v0,$v0,$zero
	jr	$ra
	andi	$v0,$v0,0xffff
	.end	csum

/* void ip_build_and_send(ip_context_t *ip, uint16_t total_len, uint8_t proto) */
	.globl	ip_build_and_send
	.ent	ip_build_and_send
ip_build_and_send:
	lw	$t2,12($a0)		/* t2 = pkt */
	lhu	$t1,10($a0)		/* id */
	srl	$t0,$a1,8
	sll	$t0,$t0,16
	sll	$t3,$a1,24
	or	$t0,$t0,$t3
	ori	$t0,$t0,0x45		/* version/IHL, TOS 0, total length big endian */
	sw	$t0,0($t2)
	sw	$t1,4($t2)		/* id as it is, flags/fragment 0 */
	addiu	$t1,$t1,1
	sh	$t1,10($a0)
	sll	$t0,$a2,8
	ori	$t0,$t0,64
	sw	$t0,8($t2)		/* TTL 64, protocol, checksum 0 for now */
	lw	$t0,0($a0)
	lw	$t1,4($a0)
	sw	$t0,12($t2)		/* saddr, daddr */
	sw	$t1,16($t2)
	move	$t3,$a1
	move	$t9,$ra
	move	$a0,$t2
	jal	csum
	li	$a1,20
	sh	$v0,10($t2)
	move	$a0,$t2
	move	$a1,$t3
	j	send_packet		/* send_packet(pkt, total_len) */
	move	$ra,$t9
	.end	ip_build_and_send

/* uint8_t *ip_buffer(ip_context_t *ip, int offset) */
	.globl	ip_buffer
	.ent	ip_buffer
ip_buffer:
	lw	$v0,12($a0)
	jr	$ra
	addu	$v0,$v0,$a1
	.end	ip_buffer
