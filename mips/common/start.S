/* Bare start for running MIPS-I test programs under qemu-mipsel (Linux o32 syscalls). */
	.set	noreorder
	.text
	.globl	__start
__start:
	jal	main
	nop
	move	$a0,$v0
	li	$v0,4001	/* exit */
	syscall
	nop

	.globl	sys_write
sys_write:			/* sys_write(fd, buf, len) */
	li	$v0,4004
	syscall
	jr	$ra
	nop
