; DO NOT EDIT. GENERATED. The C sources are canonical.
; crypto.asm - MD4 (RFC1320), MD5 (RFC1321) and HMAC-MD5 (RFC2104) for
; usmb2 NTLM auth.  Hand-written, size-optimised Z80 replacement for
; md4c.c, md5.c and hmac-md5.c.  sccz80 calling convention (args pushed
; left to right, caller pops).  IX/IY preserved.
;
; Struct layouts are identical to the C versions:
;   MD4_CTX           : state[4] @0, count[2] (bits) @16, buffer[64] @24
;   struct MD5Context : size (bytes) @0, buffer[4] @4, input[64] @20
;
; Shared design: one round engine does both MD4 (48 steps, "counter"
; 16..63) and MD5 (64 steps, counter 64..127).  Round R = counter>>4
; (1..3 MD4, 4..7 MD5) selects boolean function, message index
; schedule, shift table row and additive constant.  The A,B,C,D words
; live in a stack region; each step computes the new B in place of A and
; then moves the frame pointer IX down by one word, copying D in as the
; new A, so no word shuffling is needed.  Messages are absorbed one byte
; at a time.

	SECTION	code_compiler

	PUBLIC	_MD4Init, _MD4Update, _MD4Final
	PUBLIC	_md5Init, _md5Update, _md5Finalize, _md5Step
	PUBLIC	_hmac_md5

;------------------------------------------------------------------
; void md5Init(struct MD5Context *ctx)
_md5Init:
	pop	bc
	pop	hl
	push	hl
	push	bc
init5:				; HL = ctx
	ld	b,4
	call	zero
iv:				; store IV 01 23 .. ef fe dc .. 10 at HL
	ld	a,1
iv1:	ld	(hl),a
	inc	hl
	add	a,$22
	jr	nc,iv1
	ld	a,$fe
iv2:	ld	(hl),a
	inc	hl
	sub	$22
	jr	nc,iv2
	ret

; void MD4Init(MD4_CTX *ctx)
_MD4Init:
	pop	bc
	pop	hl
	push	hl
	push	bc
	call	iv
	ld	b,8
zero:	ld	(hl),0
	inc	hl
	djnz	zero
	ret

;------------------------------------------------------------------
; void md5Update(ctx, uint8_t *input, size_t len)
; void MD4Update(ctx, unsigned char *input, unsigned int len)
_md5Update:
	ld	bc,absorb5
	jr	updpub
_MD4Update:
	ld	bc,absorb4
updpub:
	push	ix
	push	bc
	pop	ix
	ld	hl,4
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	inc	hl
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	inc	hl
	ld	a,(hl)
	inc	hl
	ld	h,(hl)
	ld	l,a
updix:	call	updr
	pop	ix
	ret

; HL = ctx, DE = data, BC = len, IX = absorb routine
updr:	ld	a,b
	or	c
	ret	z
	push	bc
	push	de
	push	hl
	ld	a,(de)
	ld	e,a
	call	jpix
	pop	hl
	pop	de
	pop	bc
	inc	de
	dec	bc
	jr	updr
jpix:	jp	(ix)

;------------------------------------------------------------------
; absorb one byte.  In: HL = ctx, E = byte.
; Out: A = new block index (0..63).  Clobbers all but IX.
absorb5:
	ld	a,(hl)
	and	63
	ld	d,a
	push	hl
	ld	b,4
a5i:	inc	(hl)
	jr	nz,a5d
	inc	hl
	djnz	a5i
a5d:	pop	hl
	inc	hl
	inc	hl
	inc	hl
	inc	hl			; state = ctx+4
	ld	bc,$1040		; input = state+16, engine mode MD5
	jr	atail

absorb4:
	push	hl
	ld	bc,16
	add	hl,bc			; count
	inc	hl
	ld	a,(hl)
	dec	hl
	rra
	ld	a,(hl)
	rra
	rra
	rra
	and	63			; (count >> 3) & 63
	ld	d,a
	ld	a,(hl)
	add	a,8
	ld	(hl),a
	jr	nc,a4d
	ld	b,7
a4i:	inc	hl
	inc	(hl)
	jr	nz,a4d
	djnz	a4i
a4d:	pop	hl			; state = ctx
	ld	bc,$1810		; buffer = state+24, engine mode MD4
atail:				; HL=state D=idx E=byte B=buf offset C=mode
	ld	a,d
	add	a,b
	push	hl
	call	addHLA
	ld	(hl),e
	pop	hl
	ld	a,d
	inc	a
	and	63
	ret	nz
	push	hl
	ld	a,b
	call	addHLA
	ex	de,hl			; DE = block
	pop	hl			; HL = state
	ld	a,c
	jp	engine			; returns A = 0

;------------------------------------------------------------------
; padding + length.  HL = ctx, IX = absorb routine, 8 length bytes at
; caller's SP.  Returns HL = ctx.
fin:
	ld	e,$80
fpl:	push	hl
	call	jpix
	pop	hl
	ld	e,0
	cp	56
	jr	nz,fpl
	ex	de,hl
	ld	hl,2
	add	hl,sp
	ex	de,hl
	ld	bc,8
	jr	updr

; void MD4Final(unsigned char digest[16], MD4_CTX *ctx)
_MD4Final:
	pop	bc
	pop	hl			; ctx
	pop	de			; digest
	push	de
	push	hl
	push	bc
	push	ix
	ld	ix,absorb4
	push	de
	ld	bc,23
	add	hl,bc
	ld	b,4
m4c:	ld	d,(hl)			; push copy of count[] (bits)
	dec	hl
	ld	e,(hl)
	dec	hl
	push	de
	djnz	m4c
	ld	bc,-15
	add	hl,bc			; ctx
	call	fin			; HL = ctx = state
	pop	af
	pop	af
	pop	af
	pop	af
	pop	de			; digest
	ld	bc,16
	ldir
	pop	ix
	ret

; void md5Finalize(struct MD5Context *ctx)
_md5Finalize:
	pop	bc
	pop	hl
	push	hl
	push	bc
fin5:				; HL = ctx.  Returns HL = ctx->input
	push	ix
	ld	ix,absorb5
	push	hl
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	inc	hl
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	push	bc
	push	de			; original size, restored at the end
	ex	de,hl
	ld	a,3
f5s:	add	hl,hl
	rl	c
	rl	b
	dec	a
	jr	nz,f5s
	ld	d,a
	ld	e,a
	push	de
	push	de
	push	bc
	push	hl			; (uint32)(size*8), 0
	ld	hl,12
	add	hl,sp
	ld	a,(hl)
	inc	hl
	ld	h,(hl)
	ld	l,a			; ctx
	call	fin
	pop	af
	pop	af
	pop	af
	pop	af
	pop	de
	pop	bc
	pop	af
	ld	(hl),e
	inc	hl
	ld	(hl),d
	inc	hl
	ld	(hl),c
	inc	hl
	ld	(hl),b
	inc	hl			; buffer[]
	push	hl
	ld	bc,16
	add	hl,bc
	ex	de,hl
	pop	hl
	ldir				; input[0..15] = digest
	pop	ix
	ret

;------------------------------------------------------------------
; void md5Step(uint32_t *buffer, uint32_t *input)
_md5Step:
	pop	bc
	pop	de			; input
	pop	hl			; buffer
	push	hl
	push	de
	push	bc
	ld	a,64
; engine: HL = state, DE = block, A = 16 (MD4) or 64 (MD5).
; Returns A = 0.  Preserves IX.  Uses ~280 bytes of stack.
engine:
	push	ix
	ld	ix,-272
	add	ix,sp
	ld	sp,ix
	ld	ix,256
	add	ix,sp			; A,B,C,D frame (walks down)
	push	hl			; state
	push	de			; block (top of stack)
	push	ix
	pop	de
	ld	bc,16
	ldir
	ld	c,a			; C = step counter
step:
	and	a
	ex	af,af'			; carry chain lives in F'
	ld	b,4
	push	ix
stf:	ld	hl,fntab-1
	call	callR			; A = f(B,C,D) byte
	ld	e,a
	ex	af,af'
	ld	a,e
	adc	a,(ix+0)
	ld	(ix+0),a
	ex	af,af'
	inc	ix
	djnz	stf
	pop	ix
	ld	hl,jtab-1
	call	callR			; A = message word index
	and	15
	add	a,a
	add	a,a
	pop	hl
	push	hl
	call	addHLA
	call	addA			; a += X[j]
	ld	a,c
	sub	64
	jr	nc,stk
	call	getR
	add	a,63
stk:	ld	l,a
	ld	h,0
	add	hl,hl
	add	hl,hl
	ld	de,Ktab
	add	hl,de
	call	addA			; a += K
	ld	a,c			; (R << 2) | (c & 3)
	rrca
	rrca
	xor	c
	and	$1c
	xor	c
	and	$1f
	ld	hl,Stab-4
	call	addHLA
	ld	b,(hl)
str:	push	ix			; rotate left one bit, B times
	pop	hl
	ld	a,(ix+3)
	rla
	ld	e,4
str2:	rl	(hl)
	inc	hl
	dec	e
	jr	nz,str2
	djnz	str
	bit	6,c			; HL = &b
	call	nz,addA			; MD5: a += b
	ld	b,4
stc:	dec	ix			; new frame: A' = D
	ld	a,(ix+16)
	ld	(ix+0),a
	djnz	stc
	inc	c
	ld	a,c
	and	$3f
	jp	nz,step
	pop	de
	pop	de			; state
	push	ix
	pop	hl
	ld	c,4
sta:	call	add32
	dec	c
	jr	nz,sta
	ld	hl,272
	add	hl,sp
	ld	sp,hl
	pop	ix
	xor	a
	ret

; HL = table-1, 7 offsets (relative to table-1); jump to entry R with
; A = counter & 15
callR:	push	hl
	call	getR
	call	addHLA
	ld	a,(hl)
	pop	hl
	call	addHLA
	ld	a,c
	and	15
	jp	(hl)

getR:	ld	a,c
	rrca
	rrca
	rrca
	rrca
	and	7
	ret

addHLA:	add	a,l
	ld	l,a
	ret	nc
	inc	h
	ret

; (IX) += (HL), 32 bit
addA:	push	ix
	pop	de
; (DE) += (HL), 32 bit; HL,DE += 4
add32:	ld	b,4
	and	a
a32:	ld	a,(de)
	adc	a,(hl)
	ld	(de),a
	inc	hl
	inc	de
	djnz	a32
	ret

; boolean functions, IX -> byte of A;  b = ix+4, c = ix+8, d = ix+12
fntab:	defb	fF-fntab+1, fG4-fntab+1, fH-fntab+1, fF-fntab+1
	defb	fG5-fntab+1, fH-fntab+1, fI-fntab+1
fG4:	ld	a,(ix+12)		; maj = d ^ ((d^b) & (d^c))
	xor	(ix+4)
	ld	d,a
	ld	a,(ix+12)
	xor	(ix+8)
	and	d
	jr	t12
fH:	ld	a,(ix+4)		; b ^ c ^ d
	xor	(ix+8)
	jr	t12
fF:	ld	a,(ix+8)		; d ^ (b & (c ^ d))
	xor	(ix+12)
	and	(ix+4)
t12:	xor	(ix+12)
	ret
fG5:	ld	a,(ix+4)		; c ^ (d & (b ^ c))
	xor	(ix+8)
	and	(ix+12)
	jr	t8
fI:	ld	a,(ix+12)		; c ^ (b | ~d)
	cpl
	or	(ix+4)
t8:	xor	(ix+8)
	ret

; message index schedules, A = k (0..15) -> A (low nibble used)
jtab:	defb	jI-jtab+1, jR2-jtab+1, jRv-jtab+1, jI-jtab+1
	defb	j5-jtab+1, j3-jtab+1, j7-jtab+1
jR2:	ld	d,a			; rotate 4-bit k by 2
	rlca
	rlca
	rlca
	rlca
	or	d
	rrca
	rrca
jI:	ret
jRv:	ld	d,a			; bit-reverse 4-bit k
	ld	b,4
jrv:	rr	d
	rla
	djnz	jrv
	ret
j5:	ld	d,a			; 5k+1
	add	a,a
	add	a,a
	add	a,d
	inc	a
	ret
j3:	ld	d,a			; 3k+5
	add	a,a
	add	a,d
	add	a,5
	ret
j7:	ld	d,a			; 7k
	add	a,a
	add	a,a
	add	a,a
	sub	d
	ret

;------------------------------------------------------------------
; void hmac_md5(ctx, text0, text1, text1_len, text2, text2_len,
;               key, key_len, digest)
; frame: digest ix+4, key_len ix+6, key ix+8, text2_len ix+10,
;        text2 ix+12, text1_len ix+14, text1 ix+16, text0 ix+18, ctx ix+20
_hmac_md5:
	push	ix
	ld	ix,0
	add	ix,sp
	ld	a,$36
	call	hstart
	ld	e,(ix+18)
	ld	d,(ix+19)
	ld	a,d
	or	e
	jr	z,ht0d
ht0:	ld	a,(de)
	or	a
	jr	z,ht0d
	cp	'a'
	jr	c,ht0u
	cp	'z'+1
	jr	nc,ht0u
	and	$df
ht0u:	push	de
	call	abs1
	xor	a
	call	abs1
	pop	de
	inc	de
	jr	ht0
ht0d:	ld	e,(ix+16)
	ld	d,(ix+17)
	ld	c,(ix+14)
	ld	b,(ix+15)
	call	hupd
	ld	e,(ix+12)
	ld	d,(ix+13)
	ld	c,(ix+10)
	ld	b,(ix+11)
	call	hupd
	call	hfin
	ld	a,$5c
	call	hstart
	ld	e,(ix+4)
	ld	d,(ix+5)
	ld	bc,16
	call	hupd
	call	hfin
	pop	ix
	ret

hupd:	ld	a,d			; DE = data (skip if NULL), BC = len
	or	e
	ret	z
	call	hctx
	push	ix
	ld	ix,absorb5
	jp	updix

hctx:	ld	l,(ix+20)
	ld	h,(ix+21)
	ret

abs1:	ld	e,a
	call	hctx
	jp	absorb5

hstart:				; A = pad byte: md5Init + 64 key^pad bytes
	push	af
	call	hctx
	call	init5
	pop	bc			; B = pad
	ld	c,0			; C = i
	ld	l,(ix+8)
	ld	h,(ix+9)		; key
hsl:	push	bc
	push	hl
	ld	a,c
	cp	(ix+6)
	ld	a,0
	jr	nc,hsn
	ld	a,(hl)
hsn:	xor	b
	call	abs1
	pop	hl
	pop	bc
	inc	hl
	inc	c
	bit	6,c
	jr	z,hsl
	ret

hfin:	call	hctx
	call	fin5
	ld	e,(ix+4)
	ld	d,(ix+5)
	ld	bc,16
	ldir
	ret

;------------------------------------------------------------------
	SECTION	rodata_compiler

; shift amounts: MD4 rounds 1-3, MD5 rounds 1-4
Stab:	defb	3,7,11,19, 3,5,9,13, 3,9,11,15
	defb	7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21

Ktab:	defq	$d76aa478, $e8c7b756, $242070db, $c1bdceee
	defq	$f57c0faf, $4787c62a, $a8304613, $fd469501
	defq	$698098d8, $8b44f7af, $ffff5bb1, $895cd7be
	defq	$6b901122, $fd987193, $a679438e, $49b40821
	defq	$f61e2562, $c040b340, $265e5a51, $e9b6c7aa
	defq	$d62f105d, $02441453, $d8a1e681, $e7d3fbc8
	defq	$21e1cde6, $c33707d6, $f4d50d87, $455a14ed
	defq	$a9e3e905, $fcefa3f8, $676f02d9, $8d2a4c8a
	defq	$fffa3942, $8771f681, $6d9d6122, $fde5380c
	defq	$a4beea44, $4bdecfa9, $f6bb4b60, $bebfbc70
	defq	$289b7ec6, $eaa127fa, $d4ef3085, $04881d05
	defq	$d9d4d039, $e6db99e5, $1fa27cf8, $c4ac5665
	defq	$f4292244, $432aff97, $ab9423a7, $fc93a039
	defq	$655b59c3, $8f0ccc92, $ffeff47d, $85845dd1
	defq	$6fa87e4f, $fe2ce6e0, $a3014314, $4e0811a1
	defq	$f7537e82, $bd3af235, $2ad7d2bb, $eb86d391
	; MD4 round constants (Ktab index 64..66 = 63+R)
	defq	0, $5a827999, $6ed9eba1
