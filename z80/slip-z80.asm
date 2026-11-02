; DO NOT EDIT. GENERATED. The C sources are canonical.
;
; Hand written Z80 replacement for the code sccz80 generates from slip.c.
;
; slip.c stays in the tree and is the specification: this file must behave
; exactly like it.  test/test_slip.c runs both under z88dk-ticks and diffs
; the result, so keep the two in step.  See README.tcp-z80 for the general
; approach.
;
; Both loops here have the same shape: everything that has to survive a
; call into the Interface 1 ROM has to live somewhere that call does not
; touch.  rs232_put() and rs232_get() destroy AF, BC, DE and HL -- they are
; the ROM's own BCHAN-OUT / BCHAN-IN, which use all of them -- and leave
; only IX and IY alone.  sccz80 solves that by spilling to the stack and
; reloading through l_gintNsp on every access.  send_packet() keeps its
; pointer in IX instead and only reloads the counter; recv_packet() keeps
; its four pieces of state in file statics, which is safe because nothing
; re-enters it.
;
; Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
; Same MIT licence as the rest of the tree, see slip.c.
;

        MODULE  slip_c

        PUBLIC  _slip_init
        PUBLIC  _send_packet
        PUBLIC  _recv_packet

        EXTERN  rs232_init
        EXTERN  rs232_params
        EXTERN  rs232_put
        EXTERN  rs232_get

        defc    EAGAIN  = 15            ; errno.h

        defc    END     = 0xc0
        defc    ESC     = 0xdb
        defc    ESC_END = 0xdc
        defc    ESC_ESC = 0xdd
; The FUSE Interface 1 workaround, see slip.c.  Must match slip-tun.
        defc    ZER     = 0x00
        defc    ESC_ZER = 0xde

        SECTION code_compiler

;
; int slip_init(int baud_rate, int parity) __smallc
;
;   sp+2 parity, sp+4 baud_rate
;
_slip_init:
        call    rs232_init
        ld      a,l
        and     a
        jr      nz,si_fail
        ld      hl,2
        add     hl,sp
        ld      a,(hl)                  ; (uint8_t)parity
        inc     hl
        inc     hl
        ld      l,(hl)                  ; (uint8_t)baud_rate
        ld      h,0
        push    hl
        ld      l,a
        push    hl
        call    rs232_params
        pop     bc
        pop     bc
        ld      a,l
        and     a
        jr      nz,si_fail
        ld      hl,0
        ret
si_fail:
        ld      hl,-1
        ret

;
; void send_packet(uint8_t *p, int len) __smallc
;
;   sp+4 len, sp+6 p    (after the push ix)
;
; IX walks the packet; len is the only thing that has to go back to the
; stack across each rs232_put().
;
_send_packet:
        push    ix
        ld      hl,6
        add     hl,sp
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl
        pop     ix                      ; ix = p
        ld      l,END
        call    rs232_put

sp_loop:
        ld      hl,4
        add     hl,sp
        ld      e,(hl)
        inc     hl
        ld      d,(hl)                  ; de = len
        ld      a,d
        or      e
        jr      z,sp_done               ; while (len--)
        dec     de
        ld      (hl),d
        dec     hl
        ld      (hl),e

        ld      a,(ix+0)
        inc     ix
        cp      END
        jr      z,sp_is_end
        cp      ESC
        jr      z,sp_is_esc
IFDEF SLIP_ESC_00
        or      a
        jr      z,sp_is_zer
ENDIF
        ld      l,a
        call    rs232_put
        jr      sp_loop

sp_is_end:
        ld      a,ESC_END
        jr      sp_escape
sp_is_esc:
        ld      a,ESC_ESC
IFDEF SLIP_ESC_00
        jr      sp_escape
sp_is_zer:
        ld      a,ESC_ZER
ENDIF
sp_escape:
        push    af
        ld      l,ESC
        call    rs232_put
        pop     af
        ld      l,a
        call    rs232_put
        jr      sp_loop

sp_done:
        ld      l,END
        call    rs232_put
        pop     ix
        ret

;
; int recv_packet(uint8_t *p, int len, int to) __smallc
;
;   sp+2 to, sp+4 len, sp+6 p
;
; rp_left is len - received, so the "received < len" test is just a test
; for zero, and rp_ptr is &p[received], so the store needs no indexing.
; rp_c has to be zeroed on entry the way slip.c's "uint8_t c = 0" is: a
; timed out rs232_get() does not write to it, and a leftover END from the
; previous packet would otherwise end the wait loop immediately.
;
_recv_packet:
        xor     a
        ld      (rp_c),a
        ld      hl,0
        ld      (rp_recv),hl
        ld      hl,2
        add     hl,sp
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ld      (rp_to),de
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ld      (rp_left),de
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ld      (rp_ptr),de

        ; while (--to) { rs232_get(&c); if (c == END) break; }
rp_wait:
        ld      hl,(rp_to)
        dec     hl
        ld      (rp_to),hl
        ld      a,h
        or      l
        jr      z,rp_eagain
        ld      hl,rp_c
        call    rs232_get
        ld      a,(rp_c)
        cp      END
        jr      nz,rp_wait

rp_main:
        ld      hl,rp_c
        call    rs232_get
        ld      a,(rp_c)
        cp      END
        jr      z,rp_end
        cp      ESC
        jr      nz,rp_store

        ld      hl,rp_c
        call    rs232_get
        ld      a,(rp_c)
        cp      ESC_END
        ld      a,END
        jr      z,rp_store
        ld      a,(rp_c)
        cp      ESC_ESC
        ld      a,ESC
        jr      z,rp_store
IFDEF SLIP_ESC_00
        ld      a,(rp_c)
        cp      ESC_ZER
        ld      a,ZER
        jr      z,rp_store
ENDIF
        jr      rp_main                 ; unknown escape, drop it

rp_end:
        ld      hl,(rp_recv)
        ld      a,h
        or      l
        jr      z,rp_main               ; nothing yet, that was a leading END
        ret

; a = the byte to store.  if (received < len) p[received++] = a;
rp_store:
        ld      b,a
        ld      hl,(rp_left)
        ld      a,h
        or      l
        jr      z,rp_main               ; no room left, drop it
        dec     hl
        ld      (rp_left),hl
        ld      hl,(rp_recv)
        inc     hl
        ld      (rp_recv),hl
        ld      hl,(rp_ptr)
        ld      (hl),b
        inc     hl
        ld      (rp_ptr),hl
        jr      rp_main

rp_eagain:
        ld      hl,-EAGAIN
        ret

        SECTION bss_compiler

rp_c:
        defs    1
rp_to:
        defs    2
rp_left:
        defs    2
rp_recv:
        defs    2
rp_ptr:
        defs    2
