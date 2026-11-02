; DO NOT EDIT. GENERATED. The C sources are canonical.
; -----------------------------------------------------------------------------
; unicode.asm - hand-written, size-optimized Z80 rewrite of unicode.c
;
;   int utf8_to_utf16(const char *utf8, uint16_t *utf16);
;   int utf16_to_utf8(const uint16_t *utf16, int utf16_len);
;
; sccz80 ABI: args pushed left-to-right (last arg at SP+2 on entry), caller
; pops, int result in HL.  IX/IY preserved; AF,BC,DE,HL and the alternate
; register set are clobbered.
;
; Behaviour (return value and output memory) is identical to the sccz80 build
; of unicode.c for all inputs, including invalid UTF-8, unpaired surrogates and
; the in-place (overlapping) UTF-16 -> UTF-8 conversion: every code unit is read
; completely (lead + trail) before any byte of its encoding is written, as in C.
; -----------------------------------------------------------------------------

        SECTION code_compiler

        PUBLIC  _utf8_to_utf16
        PUBLIC  _utf16_to_utf8

; =============================================================================
; utf8_to_utf16
;   main:  DE = utf8 src, C:H:L = code point (24 bit), B = counter
;   alt:   HL' = utf16 dst, DE' = utf16 start, BC' scratch
; =============================================================================
_utf8_to_utf16:
        exx
        pop     af
        pop     hl              ; HL' = utf16
        pop     de              ; utf8
        push    de
        push    hl
        push    af
        push    de
        ld      d,h
        ld      e,l             ; DE' = start
        exx
        pop     de              ; DE = utf8
u8loop:
        ld      a,(de)          ; lead byte
        inc     de
        ld      l,a
        ld      h,0
        cp      0x80
        jr      c,u8one         ; 7-bit ascii
        cp      0xc2
        jr      c,u8err         ; 10xxxxxx, or overlong 2-byte (C0/C1)
        cp      0xf8
        jr      nc,u8err        ; 5+ leading ones
        ld      bc,0xfeff       ; B = -2, C = mask
u8cnt:  inc     b               ; count leading ones: B = n-1
        srl     c               ; C = 0x7f >> n
        add     a,a
        jr      c,u8cnt
        ld      a,l
        and     c
        ld      l,a             ; HL = lead & (0x7f >> n)
        ld      c,h             ; top byte = 0
        push    bc              ; save B = n-1
u8cont: ld      a,(de)
        inc     de
        rlca                    ; must be 10xxxxxx
        jr      nc,u8errp
        add     a,a
        jr      c,u8errp        ; A = xxxxxx10 (bit 1 = sentinel)
        add     a,a
u8sh:   adc     hl,hl           ; cp = cp << 6 | (c & 0x3f)
        rl      c
        add     a,a
        jr      nz,u8sh
        djnz    u8cont
        ld      a,c             ; A = cp >> 16
        pop     bc              ; B = n-1
        or      a
        jr      z,u8sm          ; only n = 4 can reach >= 0x10000
        cp      0x11
        jr      nc,u8err        ; > 0x10ffff
        push    hl
        add     a,0x5f          ; 0x60 | ((cp - 0x10000) >> 16)
        scf
        rra
        rr      h
        scf
        rra
        rr      h
        ld      l,h
        ld      h,a             ; 0xd800 | ((cp - 0x10000) >> 10)
        call    u8wr
        pop     hl
        ld      a,h
        and     3
        or      0xdc
        ld      h,a             ; 0xdc00 | (cp & 0x3ff)
        jr      u8one
u8sm:   dec     b
        jr      z,u8one         ; n = 2: always valid here
        djnz    u8err           ; n = 4 and < 0x10000: overlong
        ld      a,h             ; n = 3
        cp      0x08
        jr      c,u8err         ; < 0x800: overlong
        sub     0xd8
        cp      0x08
        jr      c,u8err         ; surrogate range
u8one:  call    u8wr
        ld      a,h
        or      l
        jr      nz,u8loop       ; stop after writing the terminating NUL
        exx
        sbc     hl,de           ; carry is clear here
        srl     h
        rr      l
        dec     hl              ; (units written) - 1
        ret
u8errp: pop     bc
u8err:  ld      hl,-1
        ret

; write HL to (HL'), HL' += 2
u8wr:   push    hl
        exx
        pop     bc
        ld      (hl),c
        inc     hl
        ld      (hl),b
        inc     hl
        exx
        ret

; =============================================================================
; utf16_to_utf8 (in place)
;   main:  HL = bit source (code unit), DE = utf8 dst, BC scratch
;   alt:   HL' = utf16 src, BC' = utf16 end, DE' scratch
;   stack: start (for the return value)
; Bytes are produced by shifting bits out of HL into A; A starts with a
; sentinel bit + the UTF-8 prefix, the byte is complete when the sentinel
; drops into carry.
; =============================================================================
_utf16_to_utf8:
        pop     af
        pop     bc              ; len
        pop     de              ; utf16
        push    de
        push    bc
        push    af
        push    de              ; start
        ld      h,d
        ld      l,e
        add     hl,bc
        add     hl,bc           ; end = utf16 + len
        push    de
        push    hl
        exx
        pop     bc              ; BC' = end
        pop     hl              ; HL' = src
        jr      u16chk          ; (alt bank active, DE = dst = src)
u16asc: ld      a,l
        ld      (de),a
        inc     de
u16loop:
        exx
u16chk: or      a
        sbc     hl,bc
        add     hl,bc
        jr      nc,u16done      ; src >= end (unsigned, as the C)
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        inc     hl
        push    de
        exx
        pop     hl              ; HL = code unit
        ld      a,l
        and     0x80
        or      h
        jr      z,u16asc        ; < 0x80
        ld      a,h
        cp      0x08
        jr      c,u16b2         ; < 0x800
        sub     0xd8
        cp      0x08
        jr      nc,u16b3        ; not a surrogate
        cp      0x04
        jr      nc,u16repl      ; lone trailing surrogate
        exx                     ; leading surrogate
        or      a
        sbc     hl,bc
        add     hl,bc
        jr      nc,u16replx     ; at end of input
        ld      e,(hl)
        inc     hl
        ld      a,(hl)
        inc     hl
        sub     0xdc
        cp      0x04
        jr      nc,u16replx2    ; not a trailing surrogate: don't consume
        ld      d,a
        push    de              ; trail[9:8], trail[7:0]
        exx
        pop     bc
        ld      a,l
        add     a,a
        add     a,a
        or      b
        ld      b,a             ; BC = lead[1:0] trail[9:0] (low 12 bits)
        ld      a,l
        add     a,0x40
        ld      l,a
        ld      a,h
        adc     a,0x18          ; 0xf0 | (u >> 8), u = (lead & 0x3ff) + 0x40
        ld      (de),a
        inc     de
        ld      h,l
        call    put6            ; 0x80 | u[7:2]
        ld      h,b
        ld      l,c
        ld      a,6
        jr      u16sh4
u16replx2:
        dec     hl
        dec     hl
u16replx:
        exx
u16repl:
        ld      hl,0xfffd       ; replacement char, encoded as 3 bytes
u16b3:  ld      a,0x1e          ; 1110xxxx
        call    put
        ld      a,6
        jr      u16b2x
u16b2:  ld      a,0x07          ; 110xxxxx (bit 11 is 0)
u16sh4: add     hl,hl
        add     hl,hl
        add     hl,hl
        add     hl,hl
u16b2x: call    put
        call    put6
        jr      u16loop
u16done:
        exx
        pop     hl              ; start
        ex      de,hl
        sbc     hl,de           ; carry is clear here
        ret

put6:   ld      a,6             ; 10xxxxxx
put:    add     hl,hl
        rla
        jr      nc,put
        ld      (de),a
        inc     de
        ret
