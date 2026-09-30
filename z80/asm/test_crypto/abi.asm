;* * * * *  Small-C/Plus z88dk * * * * *
;  Version: 24219-85e0f836ee-20251229
;
;	Reconstructed for z80 Module Assembler
;
;	Module compile time: Fri Sep 25 17:57:22 2026


	C_LINE	0,"abi.c"

	MODULE	abi_c


	INCLUDE "z80_crt0.hdr"


	C_LINE	1,"abi.c"
	C_LINE	2,"abi.c"
	SECTION	code_compiler

; Function g flags 0x00000200 __smallc 
; int g()
	C_LINE	2,"abi.c::g::0::0"
._g
	ld	hl,1	;const
	push	hl
	ld	l,2
	push	hl
	ld	hl,3	;const
	push	hl
	call	_f
	pop	bc
	pop	bc
	pop	bc
	ld	hl,0	;const
	ret


	SECTION	bss_compiler
	SECTION	code_compiler
; --- Start of Optimiser additions ---


; --- Start of Static Variables ---

	SECTION	bss_compiler
	SECTION	code_compiler


; --- Start of Scope Defns ---

	GLOBAL	_f
	GLOBAL	_g


; --- End of Scope Defns ---


; --- End of Compilation ---
