/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/* DO NOT EDIT. GENERATED. The C sources are canonical. */
/*
 * The TCP layer of the tiny TCP/IP stack (z80/tcp.c) for the PS2 IOP
 * (MIPS-I, little endian, o32), size optimised. Drop-in replacement for
 * tcp.c as Neutrino builds it (not __Z88DK: the SYN has the MSS option).
 * See tcp.c for what the functions do and why.
 *
 * Differences from tcp.c:
 *  - ip->pkt must be 4-byte aligned, as for ip.S: the headers are written
 *    and the ports compared with word accesses.
 *  - It needs ip.S's csum(), which only clobbers v0, t0, t1, a0, a1.
 *  - No memset/memcpy/memcmp.
 *
 * typedef struct tcp_context { ip_context_t ip;	 0: saddr, 4: daddr, 8: pkt_size, 12: pkt
 *	uint16_t dst_port; uint16_t src_port;		16, 18, network order
 *	uint32_t seq; uint32_t ack; uint8_t ths; }	20, 24, 28
 */
	.set	noreorder

#ifndef RS232_TPS
#define RS232_TPS 100
#endif
#define EAGAIN	11		/* the IOP's errno.h, checked by the test */
#define ERESET	20		/* tcp.h */

#define T_SADDR	0
#define T_DADDR	4
#define T_PSIZE	8
#define T_PKT	12
#define T_PORTS	16
#define T_SRCP	18
#define T_SEQ	20
#define T_ACK	24
#define T_THS	28

	.text

/*
 * int tcp_send(tcp_context_t *tcp, int len, uint8_t *data, int window)
 * s0 = tcp, s1 = len, s2 = data, s3 = window, s4 = seq on entry, s5 = retries
 */
	.globl	tcp_send
	.ent	tcp_send
tcp_send:
	addiu	$sp,$sp,-48
	sw	$ra,44($sp)
	sw	$s0,20($sp)
	sw	$s1,24($sp)
	sw	$s2,28($sp)
	sw	$s3,32($sp)
	sw	$s4,36($sp)
	sw	$s5,40($sp)
	move	$s0,$a0
	move	$s1,$a1
	move	$s2,$a2
	move	$s3,$a3
	lw	$s4,T_SEQ($a0)
	move	$s5,$zero
.Lagain:
	lw	$t8,T_PKT($s0)
	/* the payload, when there is one to copy */
	beqz	$s2,2f
	move	$t0,$zero
1:	slt	$t1,$t0,$s1
	beqz	$t1,2f
	addu	$t2,$s2,$t0
	lbu	$t2,0($t2)
	addu	$t3,$t8,$t0
	addiu	$t0,$t0,1
	b	1b
	sb	$t2,40($t3)
2:	addiu	$t8,$t8,20		/* t8 = TCP header */
	lw	$t0,T_PORTS($s0)	/* the ports, swapped round: src then dst */
	lw	$a0,T_SEQ($s0)
	sll	$t1,$t0,16
	srl	$t0,$t0,16
	or	$t0,$t0,$t1
	jal	bswap
	sw	$t0,0($t8)
	lw	$a0,T_ACK($s0)
	jal	bswap
	sw	$v0,4($t8)
	sw	$v0,8($t8)
	jal	bswap
	andi	$a0,$s3,0xffff		/* t2 = htons(window) << 16 */
	move	$t2,$v0
	lw	$t0,T_SEQ($s0)
	li	$t4,20			/* t4 = TCP header length */
	xori	$t0,$t0,1
	bnez	$t0,3f
	ori	$t3,$t2,(0x10 << 8) | 0x50	/* ACK */
	/* SYN, with an MSS option for segments that fit in our buffer */
	lhu	$a0,T_PSIZE($s0)
	li	$t4,24
	addiu	$a0,$a0,-40
	jal	bswap
	andi	$a0,$a0,0xffff
	ori	$v0,$v0,0x0402
	sw	$v0,20($t8)
	b	4f
	ori	$t3,$t2,(0x02 << 8) | 0x60
3:	bnez	$s1,4f
	ori	$t3,$t3,(0x08 << 8)	/* ACK|PSH with data */
	ori	$t3,$t2,(0x10 << 8) | 0x50
4:	sw	$t3,12($t8)
	sw	$zero,16($t8)		/* checksum and urgent pointer */
	/* the pseudo header, ip_build_and_send() writes over it */
	lw	$t0,T_SADDR($s0)
	lw	$t1,T_DADDR($s0)
	sw	$t0,-12($t8)
	sw	$t1,-8($t8)
	addu	$a0,$t4,$s1
	jal	bswap
	andi	$a0,$a0,0xffff
	ori	$v0,$v0,(6 << 8)	/* zero, IP_TCP, length */
	sw	$v0,-4($t8)
	addiu	$a0,$t8,-12
	addiu	$a1,$t4,12
	jal	csum
	addu	$a1,$a1,$s1
	sh	$v0,16($t8)
	move	$a0,$s0
	addiu	$a1,$t4,20
	addu	$a1,$a1,$s1
	jal	ip_build_and_send
	li	$a2,6

	/* no ACK to wait for: not a SYN and no data, or data with the window open */
	lw	$t0,T_SEQ($s0)
	move	$a0,$s0
	sltiu	$t0,$t0,2
	or	$t1,$t0,$s1
	beqz	$t1,.Lsret0
	sltu	$t1,$zero,$s3
	sltu	$t2,$zero,$s1
	and	$t1,$t1,$t2
	bnez	$t1,.Lsret0
	move	$a1,$zero
	jal	tcp_recv_timeout
	li	$a2,RS232_TPS
	li	$t0,-EAGAIN
	beq	$v0,$t0,5f
	lw	$t1,T_SEQ($s0)
	bltz	$v0,.Lsret
	addu	$t2,$s4,$s1
	sltu	$t1,$t1,$t2		/* has the peer taken all of it? */
	beqz	$t1,.Lsret0
	nop
5:	/* a tcp_tx_buffer() payload cannot be sent again, see tcp.c */
	sltiu	$t0,$s2,1
	sltu	$t1,$zero,$s1
	and	$t0,$t0,$t1
	bnez	$t0,.Lsretm1
	slti	$t0,$s5,5
	bnez	$t0,.Lagain
	addiu	$s5,$s5,1
.Lsretm1:
	b	.Lsret
	li	$v0,-1
.Lsret0:
	move	$v0,$zero
.Lsret:	lw	$ra,44($sp)
	lw	$s0,20($sp)
	lw	$s1,24($sp)
	lw	$s2,28($sp)
	lw	$s3,32($sp)
	lw	$s4,36($sp)
	lw	$s5,40($sp)
	jr	$ra
	addiu	$sp,$sp,48
	.end	tcp_send

/* int tcp_recv(tcp_context_t *tcp, int len) */
	.globl	tcp_recv
	.ent	tcp_recv
tcp_recv:
	li	$a2,RS232_TPS
	.end	tcp_recv		/* and on into tcp_recv_timeout */

/*
 * int tcp_recv_timeout(tcp_context_t *tcp, int len, int to)
 * s0 = tcp, s1 = length of the packet, s2 = to, s3 = its seq
 */
	.globl	tcp_recv_timeout
	.ent	tcp_recv_timeout
tcp_recv_timeout:
	addiu	$sp,$sp,-40
	sw	$ra,36($sp)
	sw	$s0,20($sp)
	sw	$s1,24($sp)
	sw	$s2,28($sp)
	sw	$s3,32($sp)
	move	$s0,$a0
	lhu	$t0,T_PSIZE($a0)
	move	$s2,$a2
	addiu	$t0,$t0,-44
	slt	$t1,$t0,$a1
	beqz	$t1,1f
	move	$a3,$a1
	move	$a3,$t0
1:	beqz	$a3,.Lrecv		/* we want data: open the window first */
	move	$a1,$zero
	jal	tcp_send
	move	$a2,$zero
.Lrecv:
	lw	$a0,T_PKT($s0)
	lhu	$a1,T_PSIZE($s0)
	jal	recv_packet
	move	$a2,$s2
	bltz	$v0,.Lrret
	lw	$t9,T_PKT($s0)		/* t9 = IP header */
	move	$s1,$v0
	slti	$t0,$v0,20 + 20
	bnez	$t0,.Lreagain
	lbu	$t0,0($t9)
	lbu	$t1,9($t9)
	xori	$t0,$t0,0x45
	bnez	$t0,.Lreagain
	xori	$t1,$t1,6		/* IP_TCP */
	bnez	$t1,.Lreagain
	lw	$t0,T_PORTS($s0)
	lw	$t1,20($t9)		/* its src/dst ports are our dst/src */
	lbu	$t2,20 + 13($t9)	/* t2 = flags */
	bne	$t0,$t1,.Lreagain
	andi	$t3,$t2,0x04		/* RST */
	bnez	$t3,.Lrreset
	lbu	$t3,20 + 12($t9)
	lw	$a0,20 + 4($t9)
	srl	$t3,$t3,2
	jal	bswap
	sb	$t3,T_THS($s0)
	lw	$a0,20 + 8($t9)
	jal	bswap
	move	$s3,$v0			/* s3 = seq, then v0 = ack */
	lw	$t0,T_SEQ($s0)
	lw	$t4,T_ACK($s0)
	xori	$t1,$t0,1
	bnez	$t1,2f
	xori	$t1,$v0,2
	/* the SYN-ACK: ACK it straight away */
	bnez	$t1,.Lrreset
	andi	$t2,$t2,0x02		/* SYN */
	beqz	$t2,.Lrretm1
	addiu	$t3,$s3,1
	sw	$v0,T_SEQ($s0)
	jal	send0
	sw	$t3,T_ACK($s0)
	b	.Lrret
	move	$v0,$zero

2:	lbu	$t5,T_THS($s0)
	addiu	$t6,$s3,1
	bne	$t6,$t4,3f
	addiu	$t7,$t5,20		/* t7 = 20 + ths */
	beq	$s1,$t7,.Lrecv		/* a zero window probe: ignore it */
3:	sltu	$t6,$t0,$v0		/* data got ACKed: advance seq */
	beqz	$t6,4f
	slt	$t6,$t7,$s1
	sw	$v0,T_SEQ($s0)
4:	beqz	$t6,.Lrlen		/* no data */
	nop
	bne	$s3,$t4,.Lrack0		/* not the next data in sequence */
	slti	$t6,$s1,20 + 20 + 1
	bnez	$t6,5f
	subu	$t6,$s1,$t7
	addu	$t4,$t4,$t6
	sw	$t4,T_ACK($s0)
5:	jal	send0			/* ACK it and close the window */
	nop
.Lrlen:	lbu	$t0,T_THS($s0)
	addiu	$v0,$s1,-20
	b	.Lrret
	subu	$v0,$v0,$t0
.Lrack0:
	jal	send0
	nop
	b	.Lrret
	move	$v0,$zero
.Lrretm1:
	b	.Lrret
	li	$v0,-1
.Lrreset:
	b	.Lrret
	li	$v0,-ERESET
.Lreagain:
	li	$v0,-EAGAIN
.Lrret:	lw	$ra,36($sp)
	lw	$s0,20($sp)
	lw	$s1,24($sp)
	lw	$s2,28($sp)
	lw	$s3,32($sp)
	jr	$ra
	addiu	$sp,$sp,40

/* tcp_send(s0, 0, NULL, 0) */
send0:	move	$a0,$s0
	move	$a1,$zero
	move	$a2,$zero
	j	tcp_send
	move	$a3,$zero
	.end	tcp_recv_timeout

/* int tcp_connect(tcp_context_t *tcp) */
	.globl	tcp_connect
	.ent	tcp_connect
tcp_connect:
	addiu	$sp,$sp,-32
	sw	$ra,28($sp)
	sw	$s0,20($sp)
	sw	$s1,24($sp)
	move	$s0,$a0
	sb	$zero,T_THS($a0)
	li	$s1,5
1:	li	$t0,1
	sw	$t0,T_SEQ($s0)
	sw	$zero,T_ACK($s0)
	move	$a0,$s0
	move	$a1,$zero
	move	$a2,$zero
	jal	tcp_send
	li	$a3,1
	bgez	$v0,2f
	lw	$t0,T_PKT($s0)
	lhu	$t1,T_SRCP($s0)
	lhu	$t0,20 + 16($t0)	/* the checksum makes a random increment */
	addiu	$s1,$s1,-1
	addu	$t1,$t1,$t0
	bnez	$s1,1b
	sh	$t1,T_SRCP($s0)
	li	$v0,-1
2:	lw	$ra,28($sp)
	lw	$s0,20($sp)
	lw	$s1,24($sp)
	jr	$ra
	addiu	$sp,$sp,32
	.end	tcp_connect

/* uint8_t *tcp_rx_buffer(tcp_context_t *tcp) */
	.globl	tcp_rx_buffer
	.ent	tcp_rx_buffer
tcp_rx_buffer:
	lw	$v0,T_PKT($a0)
	lbu	$t0,T_THS($a0)
	addiu	$v0,$v0,20
	jr	$ra
	addu	$v0,$v0,$t0
	.end	tcp_rx_buffer

/* uint8_t *tcp_tx_buffer(tcp_context_t *tcp) */
	.globl	tcp_tx_buffer
	.ent	tcp_tx_buffer
tcp_tx_buffer:
	lw	$v0,T_PKT($a0)
	jr	$ra
	addiu	$v0,$v0,20 + 20
	.end	tcp_tx_buffer

/* v0 = a0 with its bytes swapped round; clobbers t0 only. bswap(x & 0xffff) = htons(x) << 16 */
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
