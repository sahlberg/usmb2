/* -*-  mode:asm; tab-width:8; indent-tabs-mode:t;  -*- */
/*
 * ps2iop-compat.c for the PS2 IOP (MIPS-I, little endian, o32), size
 * optimised: malloc/free/calloc/strdup on the IOP's sysmem, with interrupts
 * suspended around AllocSysMemory and FreeSysMemory.
 *
 * Differences from ps2iop-compat.c:
 *  - calloc() does not memset() when the allocation failed; ps2iop-compat.c
 *    cleared size bytes at address 0 then.
 *  - strdup() copies strlen() + 1 bytes; ps2iop-compat.c copied one more,
 *    past the end of what it had allocated.
 */
	.set	noreorder

#define ALLOC_FIRST	0

	.text

/* void *malloc(int size) */
	.globl	malloc
	.ent	malloc
malloc:	move	$a1,$a0
	move	$a0,$zero		/* ALLOC_FIRST */
	la	$t8,AllocSysMemory
	b	intr_call		/* AllocSysMemory(ALLOC_FIRST, size, NULL) */
	move	$a2,$zero
	.end	malloc

/* void free(void *ptr) */
	.globl	free
	.ent	free
free:	la	$t8,FreeSysMemory	/* FreeSysMemory(ptr) */
	/* and on into intr_call */

/* intr_call: v0 = t8(a0, a1, a2) with interrupts suspended */
intr_call:
	addiu	$sp,$sp,-40
	sw	$ra,36($sp)
	sw	$a0,16($sp)
	sw	$a1,20($sp)
	sw	$a2,24($sp)
	sw	$t8,28($sp)
	jal	CpuSuspendIntr
	addiu	$a0,$sp,32		/* &OldState */
	lw	$t8,28($sp)
	lw	$a0,16($sp)
	lw	$a1,20($sp)
	lw	$a2,24($sp)
	jalr	$t8
	nop
	lw	$a0,32($sp)
	jal	CpuResumeIntr
	sw	$v0,16($sp)
	lw	$v0,16($sp)
	lw	$ra,36($sp)
	nop
	jr	$ra
	addiu	$sp,$sp,40
	.end	free

/* void *calloc(size_t nmemb, size_t size) */
	.globl	calloc
	.ent	calloc
calloc:	multu	$a0,$a1
	addiu	$sp,$sp,-32
	sw	$ra,28($sp)
	mflo	$a0
	jal	malloc
	sw	$a0,20($sp)
	beqz	$v0,1f			/* no memset(NULL, ...) */
	move	$a0,$v0
	move	$a1,$zero
	lw	$a2,20($sp)
	jal	memset
	sw	$v0,16($sp)
	lw	$v0,16($sp)
1:	lw	$ra,28($sp)
	nop
	jr	$ra
	addiu	$sp,$sp,32
	.end	calloc

/* char *strdup(const char *s) */
	.globl	strdup
	.ent	strdup
strdup:	addiu	$sp,$sp,-32
	sw	$ra,28($sp)
	jal	strlen
	sw	$a0,20($sp)
	addiu	$a0,$v0,1
	jal	malloc
	sw	$a0,24($sp)
	beqz	$v0,1f
	move	$a0,$v0
	lw	$a1,20($sp)
	lw	$a2,24($sp)
	jal	memcpy			/* the string and its terminator */
	sw	$v0,16($sp)
	lw	$v0,16($sp)
1:	lw	$ra,28($sp)
	nop
	jr	$ra
	addiu	$sp,$sp,32
	.end	strdup
