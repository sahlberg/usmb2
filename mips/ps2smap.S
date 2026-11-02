/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/* DO NOT EDIT. GENERATED. The C sources are canonical. */
/*
 * The link layer of the tiny stack on Neutrino's smap.irx and ministack.irx
 * (z80/ps2smap.c) for the PS2 IOP (MIPS-I, little endian, o32), size
 * optimised. Drop-in replacement for ps2smap.c; see there for how it works.
 *
 * Differences from ps2smap.c:
 *  - All of its state is one block in .bss, reached from one base register.
 *    "No event flag yet" is evf == 0 instead of -1, so nothing needs .data;
 *    the kernel's event flag ids are positive.
 *  - rx_tcp() stores the slot's length before the FIFO read instead of
 *    after it; recv_packet() reads it only once rx_head has moved on.
 *  - send_packet() needs p 4-byte aligned, as ip.S's packets are.
 */
	.set	noreorder

#ifndef RS232_TPS
#define RS232_TPS 100
#endif
#define EAGAIN		11
#define ETH_HDR		14
#define FRAME_SIZE	1516		/* a 1514 byte frame, rounded up to 4 */
#define SLOT		(4 + FRAME_SIZE)	/* uint16_t len, 2 pad, frame */
#define EF_RX		1
#define EF_TIMEOUT	2

/* the state, from V */
#define V_EVF		0
#define V_HEAD		4		/* rx_head, rx_tail: modulo 2 * 2 slots */
#define V_TAIL		8
#define V_IP		12		/* host order */
#define V_MASK		16
#define V_GW		20
#define V_PORT		24		/* const uint16_t *, network order */
#define V_RX		28		/* 2 slots */
#define V_TX		(V_RX + 2 * SLOT)
#define V_SIZE		(V_TX + FRAME_SIZE)

	.text

/*
 * static int rx_tcp(const uint8_t *hdr, uint16_t hdr_len), from ministack:
 * queue the frame if it is for our port and there is room. Always -1.
 */
	.ent	rx_tcp
rx_tcp:	lbu	$t0,ETH_HDR($a0)
	la	$t9,V
	andi	$t0,$t0,0x0f
	sll	$t0,$t0,2		/* t0 = IP header length */
	addiu	$t1,$t0,ETH_HDR + 4
	slt	$t1,$a1,$t1
	bnez	$t1,9f
	addu	$t2,$a0,$t0
	lw	$t3,V_PORT($t9)		/* only the destination port, the stack checks the rest */
	lbu	$t4,ETH_HDR + 2($t2)
	lbu	$t5,ETH_HDR + 3($t2)
	lhu	$t3,0($t3)
	sll	$t5,$t5,8
	or	$t4,$t4,$t5
	bne	$t4,$t3,9f
	lbu	$t4,ETH_HDR + 2($a0)	/* t4 = IP total length */
	lbu	$t5,ETH_HDR + 3($a0)
	sll	$t4,$t4,8
	or	$t4,$t4,$t5
	sltiu	$t6,$t4,FRAME_SIZE - ETH_HDR + 1
	beqz	$t6,9f
	lw	$t6,V_HEAD($t9)
	lw	$t7,V_TAIL($t9)
	nop
	subu	$t8,$t6,$t7
	andi	$t8,$t8,3
	xori	$t8,$t8,2
	beqz	$t8,9f			/* full: TCP resends it */
	andi	$t8,$t6,1
	subu	$t8,$zero,$t8
	andi	$t8,$t8,SLOT		/* t8 = offset of slot rx_head % 2 */
	addiu	$sp,$sp,-24
	sw	$ra,20($sp)
	sw	$s0,16($sp)
	move	$s0,$t9
	addu	$a1,$t9,$t8
	sh	$t4,V_RX($a1)
	addiu	$a1,$a1,V_RX + 4
	addiu	$a2,$t4,ETH_HDR + 3
	srl	$a2,$a2,2
	sll	$a2,$a2,2
	jal	smap_fifo_read		/* smap_fifo_read(0, frame, (ETH_HDR + len + 3) & ~3) */
	move	$a0,$zero
	lw	$t0,V_HEAD($s0)
	lw	$a0,V_EVF($s0)
	addiu	$t0,$t0,1
	andi	$t0,$t0,3
	sw	$t0,V_HEAD($s0)
	jal	SetEventFlag
	li	$a1,EF_RX
	lw	$ra,20($sp)
	lw	$s0,16($sp)
	addiu	$sp,$sp,24
9:	jr	$ra			/* -1 lets the driver skip to the end of the frame */
	li	$v0,-1
	.end	rx_tcp

/* int ps2smap_init(uint32_t ip, uint32_t mask, uint32_t gw) */
	.globl	ps2smap_init
	.ent	ps2smap_init
ps2smap_init:
	la	$t9,V
	sw	$a0,V_IP($t9)
	sw	$a1,V_MASK($t9)
	sw	$a2,V_GW($t9)
	lw	$t0,V_EVF($t9)
	addiu	$sp,$sp,-32
	bgtz	$t0,1f
	sw	$ra,28($sp)
	sw	$zero,16($sp)		/* iop_event_t ev = { 0, 0, 0 } */
	sw	$zero,20($sp)
	sw	$zero,24($sp)
	jal	CreateEventFlag
	addiu	$a0,$sp,16
	la	$t9,V
	bltz	$v0,2f
	sw	$v0,V_EVF($t9)
1:	la	$a0,rx_tcp
	jal	ip_set_tcp_handler
	nop
	b	3f
	move	$v0,$zero
2:	li	$v0,-1
3:	lw	$ra,28($sp)
	nop
	jr	$ra
	addiu	$sp,$sp,32
	.end	ps2smap_init

/* void ps2smap_set_port(const uint16_t *port) */
	.globl	ps2smap_set_port
	.ent	ps2smap_set_port
ps2smap_set_port:
	la	$t9,V
	sw	$a0,V_PORT($t9)
	sw	$zero,V_HEAD($t9)
	jr	$ra
	sw	$zero,V_TAIL($t9)
	.end	ps2smap_set_port

/* void send_packet(uint8_t *p, int len): p is an IP packet */
	.globl	send_packet
	.ent	send_packet
send_packet:
	slti	$t0,$a1,FRAME_SIZE - ETH_HDR + 1
	beqz	$t0,9f
	lbu	$t0,16($a0)		/* destination, host order */
	lbu	$t1,17($a0)
	lbu	$t2,18($a0)
	lbu	$t3,19($a0)
	sll	$t0,$t0,24
	sll	$t1,$t1,16
	sll	$t2,$t2,8
	or	$t0,$t0,$t1
	or	$t0,$t0,$t2
	or	$t0,$t0,$t3
	addiu	$sp,$sp,-32
	sw	$ra,28($sp)
	sw	$s0,16($sp)
	sw	$s1,20($sp)
	sw	$s2,24($sp)
	move	$s0,$a0
	move	$s1,$a1
	la	$s2,V
	lw	$t1,V_IP($s2)
	lw	$t2,V_MASK($s2)
	xor	$t1,$t1,$t0
	and	$t1,$t1,$t2
	beqz	$t1,1f			/* in our subnet */
	move	$a0,$t0
	lw	$a0,V_GW($s2)		/* or through the gateway */
1:	jal	arp_resolve		/* arp_resolve(dst, tx): the destination MAC */
	addiu	$a1,$s2,V_TX
	bnez	$v0,8f
	nop
	jal	SMAPGetMACAddress
	addiu	$a0,$s2,V_TX + 6
	li	$t0,0x0008		/* IPv4 */
	sh	$t0,V_TX + 12($s2)
	addiu	$a0,$s2,V_TX + ETH_HDR
	move	$a1,$s0
	jal	memcpy
	move	$a2,$s1
	addiu	$a0,$s2,V_TX		/* smap_transmit(tx, ETH_HDR + len, NULL, 0) */
	addiu	$a1,$s1,ETH_HDR
	andi	$a1,$a1,0xffff
	move	$a2,$zero
	move	$a3,$zero
	lw	$ra,28($sp)
	lw	$s0,16($sp)
	lw	$s1,20($sp)
	lw	$s2,24($sp)
	j	smap_transmit
	addiu	$sp,$sp,32
8:	lw	$ra,28($sp)
	lw	$s0,16($sp)
	lw	$s1,20($sp)
	lw	$s2,24($sp)
	addiu	$sp,$sp,32
9:	jr	$ra
	nop
	.end	send_packet

/* static unsigned int timeout_cb(void *arg): the alarm, 0 for no rerun */
	.ent	timeout_cb
timeout_cb:
	addiu	$sp,$sp,-24
	sw	$ra,20($sp)
	la	$t9,V
	lw	$a0,V_EVF($t9)
	jal	iSetEventFlag
	li	$a1,EF_TIMEOUT
	lw	$ra,20($sp)
	move	$v0,$zero
	jr	$ra
	addiu	$sp,$sp,24
	.end	timeout_cb

/*
 * int recv_packet(uint8_t *p, int len, int to)
 * Waits up to to / RS232_TPS seconds for a packet, -EAGAIN if none.
 * frame: 16 clock, 24 bits, 28 s0 = p, 32 s1 = len, 36 s2 = V, 40 ra
 */
	.globl	recv_packet
	.ent	recv_packet
recv_packet:
	addiu	$sp,$sp,-48
	sw	$ra,40($sp)
	sw	$s0,28($sp)
	sw	$s1,32($sp)
	sw	$s2,36($sp)
	move	$s0,$a0
	move	$s1,$a1
	la	$s2,V
	lw	$t0,V_TAIL($s2)
	lw	$t1,V_HEAD($s2)
	nop
	bne	$t0,$t1,.Lhave
	nop
	blez	$a2,.Leagain
	sw	$a2,48 + 8($sp)		/* to, in its home slot */
	lw	$a0,V_EVF($s2)		/* the queue is the truth, the flag only wakes us up */
	jal	ClearEventFlag
	move	$a1,$zero
	lw	$t0,V_TAIL($s2)
	lw	$t1,V_HEAD($s2)
	lw	$a0,48 + 8($sp)
	bne	$t0,$t1,1f
	li	$t0,1000000 / RS232_TPS
	mult	$a0,$t0
	mflo	$a0
	jal	USec2SysClock
	addiu	$a1,$sp,16
	addiu	$a0,$sp,16
	la	$a1,timeout_cb
	jal	SetAlarm
	move	$a2,$zero
	lw	$a0,V_EVF($s2)
	li	$a1,EF_RX | EF_TIMEOUT
	li	$a2,1			/* WEF_OR */
	jal	WaitEventFlag
	addiu	$a3,$sp,24
	la	$a0,timeout_cb
	jal	CancelAlarm
	move	$a1,$zero
1:	lw	$t0,V_TAIL($s2)
	lw	$t1,V_HEAD($s2)
	nop
	beq	$t0,$t1,.Leagain
.Lhave:	andi	$t1,$t0,1		/* the slot rx_tail % 2 */
	subu	$t1,$zero,$t1
	andi	$t1,$t1,SLOT
	addu	$t1,$s2,$t1
	lhu	$t2,V_RX($t1)
	move	$a0,$s0
	slt	$t3,$t2,$s1
	beqz	$t3,2f
	addiu	$a1,$t1,V_RX + 4 + ETH_HDR
	move	$s1,$t2
2:	jal	memcpy
	move	$a2,$s1
	lw	$t0,V_TAIL($s2)
	move	$v0,$s1
	addiu	$t0,$t0,1
	andi	$t0,$t0,3
	b	.Lret
	sw	$t0,V_TAIL($s2)
.Leagain:
	li	$v0,-EAGAIN
.Lret:	lw	$ra,40($sp)
	lw	$s0,28($sp)
	lw	$s1,32($sp)
	lw	$s2,36($sp)
	jr	$ra
	addiu	$sp,$sp,48
	.end	recv_packet

	.bss
	.align	2
V:	.space	V_SIZE
