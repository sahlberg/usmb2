;
; Interface 1 RS-232 stubs for test/test_slip.c.
;
; The +test target has no rs232 library, so these provide the four entry
; points slip.c / slip-z80.asm call, with the calling conventions the real
; ones use (see z88dk libsrc/target/zx/classic/rs232/if1/), and forward to
; plain C functions in the test.
;
        MODULE  stub232

        PUBLIC  rs232_init
        PUBLIC  rs232_params
        PUBLIC  rs232_put
        PUBLIC  rs232_get

        EXTERN  _mock_init
        EXTERN  _mock_params
        EXTERN  _mock_put
        EXTERN  _mock_get

        SECTION code_compiler

; uint8_t rs232_init(void) -- result in hl
rs232_init:
        jp      _mock_init

; uint8_t rs232_params(uint8_t param, uint8_t parity) __smallc
;   sp+2 parity, sp+4 param
rs232_params:
        ld      hl,4
        add     hl,sp
        ld      c,(hl)
        inc     hl
        ld      b,(hl)
        push    bc                      ; param
        ld      hl,4
        add     hl,sp                   ; sp moved, so this is parity now
        ld      c,(hl)
        inc     hl
        ld      b,(hl)
        push    bc                      ; parity
        call    _mock_params
        pop     bc
        pop     bc
        ret

; uint8_t rs232_put(uint8_t c) __z88dk_fastcall -- c in l
rs232_put:
        ld      h,0
        push    hl
        call    _mock_put
        pop     bc
        ld      hl,0                    ; RS_ERR_OK
        ret

; uint8_t rs232_get(uint8_t *c) __z88dk_fastcall -- pointer in hl.
; mock_get() returns the byte, or a negative value for "no data", in
; which case the real routine leaves *c alone.
rs232_get:
        push    hl
        call    _mock_get
        pop     de
        bit     7,h
        jr      nz,rg_nodata
        ld      a,l
        ld      (de),a
        ld      hl,0                    ; RS_ERR_OK
        ret
rg_nodata:
        ld      hl,4                    ; RS_ERR_NO_DATA
        ret
