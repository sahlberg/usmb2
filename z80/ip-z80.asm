; DO NOT EDIT. GENERATED. The C sources are canonical.
;
; Hand written Z80 replacement for the code sccz80 generates from ip.c.
;
; ip.c stays in the tree and is the specification: this file must behave
; exactly like it.  test/test_ip.c runs both under z88dk-ticks and diffs
; the result, so keep the two in step.  See README.tcp-z80 for the general
; approach and for the IX hazard.
;
; The two things that make the compiler output four times this size:
;
;  * csum() accumulates into a uint32_t, so every word of the packet costs
;    an l_long_add through a stack temporary.  Here the carry is folded
;    back into a 16 bit accumulator as it happens -- the end around carry
;    of RFC 1071 -- which is the same one's complement sum with no 32 bit
;    arithmetic at all.
;  * ip_build_and_send() reaches every field of ip_context_t through
;    l_gint / l_glong and writes the header with 2 and 4 byte memcpy()s.
;    Here HL walks the packet from byte 0 to byte 19 once, and saddr and
;    daddr are adjacent in the struct so one LDIR does both.
;
; Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
; Same MIT licence as the rest of the tree, see ip.c.
;

        MODULE  ip_c

        PUBLIC  _csum
        PUBLIC  _ip_build_and_send
        PUBLIC  _ip_buffer

        EXTERN  _send_packet

; ip_context_t
        defc    o_saddr = 0             ; uint32_t
        defc    o_daddr = 4             ; uint32_t
        defc    o_size  = 8             ; uint16_t pkt_size
        defc    o_id    = 10            ; uint16_t
        defc    o_pkt   = 12            ; uint8_t *

        SECTION code_compiler

;
; uint16_t csum(uint16_t *ptr, int nbytes) __smallc
;
;   sp+2 nbytes, sp+4 ptr
;
; ip.c sums into a uint32_t and folds the two halves together at the end.
; Adding the carry straight back into the 16 bit accumulator gives the
; same answer -- both are the sum modulo 65535 -- and needs no long
; arithmetic.  It cannot overflow: to leave 0xffff in the accumulator
; *and* produce a carry the addition would have to reach 0x1ffff, and the
; largest possible is 0xffff + 0xffff = 0x1fffe.
;
_csum:
        ld      hl,2
        add     hl,sp
        ld      c,(hl)
        inc     hl
        ld      b,(hl)                  ; bc = nbytes
        inc     hl
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a                     ; hl = ptr

        ld      a,c
        and     1
        push    af                      ; is there a trailing odd byte?
        srl     b
        rr      c                       ; bc = whole words

        ld      de,0                    ; the sum
        ld      a,b
        or      c
        jr      z,csum_odd
csum_loop:
        ld      a,e
        add     a,(hl)
        ld      e,a
        inc     hl
        ld      a,d
        adc     a,(hl)
        ld      d,a
        inc     hl
        jr      nc,csum_next
        inc     de                      ; end around carry
csum_next:
        dec     bc
        ld      a,b
        or      c
        jr      nz,csum_loop

csum_odd:
        pop     af
        or      a
        jr      z,csum_done
        ld      a,e                     ; oddbyte is the low half only
        add     a,(hl)
        ld      e,a
        ld      a,d
        adc     a,0
        ld      d,a
        jr      nc,csum_done
        inc     de
csum_done:
        ld      a,d
        cpl
        ld      h,a
        ld      a,e
        cpl
        ld      l,a
        ret

;
; void ip_build_and_send(ip_context_t *ip, uint16_t total_len, uint8_t proto)
; __smallc
;
;   ix+4 proto, ix+6 total_len, ix+8 ip, ix-2/-1 pkt
;
_ip_build_and_send:
        push    ix
        ld      ix,0
        add     ix,sp

        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_pkt
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl                      ; ix-2 = pkt

        xor     a                       ; memset(pkt, 0, 20)
        ld      b,20
ibs_zero:
        ld      (hl),a
        inc     hl
        djnz    ibs_zero

        ld      l,(ix-2)
        ld      h,(ix-1)
        ld      (hl),0x45               ; pkt[0]
        inc     hl
        inc     hl
        ld      a,(ix+7)                ; pkt[2..3] = htons(total_len)
        ld      (hl),a
        inc     hl
        ld      a,(ix+6)
        ld      (hl),a
        inc     hl                      ; hl = pkt+4

        ex      de,hl
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_id
        add     hl,bc
        ldi
        ldi                             ; pkt[4..5] = ip->id
        dec     hl
        dec     hl
        inc     (hl)                    ; ip->id++
        jr      nz,ibs_id
        inc     hl
        inc     (hl)
ibs_id:
        ex      de,hl                   ; hl = pkt+6
        inc     hl
        inc     hl
        ld      (hl),64                 ; pkt[8]
        inc     hl
        ld      a,(ix+4)
        ld      (hl),a                  ; pkt[9] = proto
        ld      bc,3
        add     hl,bc                   ; hl = pkt+12

        ex      de,hl
        ld      l,(ix+8)
        ld      h,(ix+9)                ; saddr and daddr are adjacent
        ld      bc,8
        ldir                            ; pkt[12..19]

        push    ix                      ; csum() may be the C one, which
        ld      l,(ix-2)                ; comes back with IX destroyed
        ld      h,(ix-1)
        push    hl
        ld      hl,20
        push    hl
        call    _csum
        pop     bc
        pop     bc
        pop     ix

        ld      e,(ix-2)
        ld      d,(ix-1)
        ex      de,hl                   ; hl = pkt, de = cs
        ld      bc,10
        add     hl,bc
        ld      (hl),e                  ; pkt[10..11]
        inc     hl
        ld      (hl),d

        push    ix
        ld      l,(ix-2)
        ld      h,(ix-1)
        push    hl
        ld      l,(ix+6)
        ld      h,(ix+7)
        push    hl
        call    _send_packet
        pop     bc
        pop     bc
        pop     ix

        ld      sp,ix
        pop     ix
        ret

;
; uint8_t *ip_buffer(ip_context_t *ip, int offset) __smallc
;
_ip_buffer:
        pop     bc                      ; return address
        pop     de                      ; offset
        pop     hl                      ; ip
        push    hl
        push    de
        push    bc
        ld      bc,o_pkt
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        add     hl,de
        ret
