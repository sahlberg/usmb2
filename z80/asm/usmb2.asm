;; usmb2.asm - hand written, size optimised Z80 implementation of usmb2.c
;; (Z80 build).  Drop-in replacement at the sccz80 C ABI level.
;;
;; Build:  z88dk-z80asm -DUSMB2_FEATURE_xxx ... usmb2.asm
;;    or:  zcc +zx -c usmb2.asm -Ca-DUSMB2_FEATURE_xxx ...
;; Feature switches (same as the C): USMB2_FEATURE_WRITE, USMB2_FEATURE_OPENDIR,
;; USMB2_FEATURE_UNICODE, USMB2_FEATURE_CLOSE, USMB2_FEATURE_NTLM
;;
;; sccz80 convention: args pushed left to right, caller pops, result in
;; HL / DEHL.  IX and IY are never touched.
;;
;; struct usmb2_context layout (unchanged):
;;   +0 fd, +2 username[32], +34 password[32], +66 message_id (u64),
;;   +74 session_id (u64), +82 tree_id (u32), +86 buf[512]
;; Internally we keep v_buf = &ctx->buf; the ids are at buf-20/-12/-4.
;;
;; Semantic narrowings (all impossible / meaningless for realistic input):
;;  N1 SPL of a request (64+commandoutcount+outdatacount) < 32768: the top
;;     two SPL bytes are sent as 00 00 (C would sign extend a negative int).
;;  N2 SPL of a reply < 65536 and >= 64: only the low 16 bits are used
;;     (the C keeps 32 bits, but the rx buffer is far smaller than 64K).
;;  N3 read/write count is 0..32767: bytes 2,3 of the 32-bit Length field
;;     are sent as 0 (C sign extends the int).
;;  N4 usmb2_prw() cmd is 0..255 (an SMB2 command): only its low byte is
;;     placed in the header; the high byte of the Command field stays 0.
;;  N5 readdir: the directory cursor dh[16..19], NextEntryOffset and
;;     FileNameLength are handled as 16-bit values (they are < 256 since the
;;     directory buffer is 256 bytes); dh[18..19] are therefore never
;;     written and stay 0 from the calloc() done by usmb2_open(O_DIRECTORY).
;;     (memcpy of the QUERY_DIRECTORY data uses 16 bits of OutputBufferLength
;;     exactly like the C, since size_t is 16 bit.)
;;  N6 message_id is incremented as a full 64-bit value but without a bound
;;     on the carry chain (it would only run past 8 bytes after 2^64 requests).
;;     The wire carries the low 32 bits zero-extended exactly as the C does.
;;  N7 the data buffer of a READ/WRITE (pread/pwrite buf, prw rbuf for READ,
;;     wbuf for WRITE) is never NULL.  (The C would skip the data for a NULL
;;     read buffer and send buf[] as "padding" for a NULL write buffer.)
;;  N8 the reply SPL is >= 64 (N2) - the SMB2 header copy is clamped like
;;     the other reads instead of reading past the reply.
;;  Known difference to the *compiled* C (a z88dk runtime bug, not a
;;  narrowing): sccz80 implements "current_mid = usmb2->message_id++" with
;;  l_i64_dec, which only borrows correctly when the low byte is not 0
;;  (it returns on NZ and walks the wrong way with dec hl).  So whenever the
;;  low byte of message_id is $ff (request #256, #512, ...) the C puts a
;;  wrong MessageId on the wire (e.g. $1ff instead of $ff).  This file sends
;;  the value the C source specifies.
;;  Implementation differences that are not observable:
;;   - malloc(16) for a file handle is done as calloc(1,16) (same size, fully
;;     overwritten afterwards), so malloc need not be linked.
;;   - the static send_pos/recv_pos are replaced by register walkers.
;;   - the header of a request is written directly (the C relies on the
;;     buffer being zeroed by the caller; so do we).

        SECTION code_compiler

        PUBLIC  _usmb2_init_context
        PUBLIC  _usmb2_tcp
        PUBLIC  _usmb2_negotiateprotocol
        PUBLIC  _usmb2_sessionsetup
        PUBLIC  _usmb2_treeconnect
        PUBLIC  _usmb2_open
        PUBLIC  _usmb2_prw
        PUBLIC  _usmb2_pread
        PUBLIC  _usmb2_size
IFDEF USMB2_FEATURE_WRITE
        PUBLIC  _usmb2_pwrite
ENDIF
IFDEF USMB2_FEATURE_OPENDIR
        PUBLIC  _usmb2_opendir
        PUBLIC  _usmb2_readdir
ENDIF
IFDEF USMB2_FEATURE_CLOSE
        PUBLIC  _usmb2_close
ENDIF

        EXTERN  _tcp_send, _tcp_recv, _tcp_rx_buffer, _tcp_tx_buffer
        EXTERN  calloc_callee, free_fastcall
IFDEF USMB2_FEATURE_NTLM
        EXTERN  _ntlm_generate_auth
ENDIF
IFDEF USMB2_FEATURE_UNICODE
        EXTERN  _utf8_to_utf16
IFDEF USMB2_FEATURE_OPENDIR
        EXTERN  _utf16_to_utf8
ENDIF
ENDIF

;; ---------------------------------------------------------------------------
;; struct usmb2_context *usmb2_init_context(uint32_t ip, char *user, char *pass)
_usmb2_init_context:
        call    ga4                 ; ARG+0 = pass, ARG+2 = user
        ld      hl,1
        push    hl
        ld      hl,598
        push    hl
        call    calloc_callee
        ld      a,h
        or      l
        ret     z
        push    hl
        ex      de,hl
        call    setctx                  ; DE preserved = ctx
        inc     de
        inc     de
        ld      hl,(ARG+2)
        call    scpy                    ; strcpy(ctx->username, user)
        pop     hl
        push    hl
        ld      de,34
        add     hl,de
        ex      de,hl
        ld      hl,(ARG)
        call    scpy                    ; strcpy(ctx->password, pass)
        call    neg_i
        call    z,ss_i
        pop     hl
        ret     z
        call    free_fastcall
        ld      hl,0
        ret

scpy:   ld      a,(hl)
        ld      (de),a
        inc     hl
        inc     de
        or      a
        jr      nz,scpy
        ret

;; ---------------------------------------------------------------------------
;; int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc)
_usmb2_treeconnect:
        call    ga4
        ld      hl,prog_tc
        call    prep                    ; DE = buf+73
        inc     de
        push    de                      ; buf+74
        inc     de
        inc     de
        ld      hl,(ARG)
        call    wcopy                   ; HL = 2*strlen
        pop     de
        ld      a,l
        ld      (de),a
        ld      bc,8
        add     hl,bc
        ld      b,h
        ld      c,l
        ld      de,3*256+16
        jr      br01

;; ascii -> ucs2: HL = src, DE = dst; returns HL = bytes written (2*strlen)
wcopy:  push    de
wc1:    ld      a,(hl)
        or      a
        jr      z,wc2
        ld      (de),a
        inc     hl
        inc     de
        inc     de
        jr      wc1
wc2:    pop     hl                      ; carry is clear here (or a)
        ex      de,hl
        sbc     hl,de
        ret

IFDEF USMB2_FEATURE_CLOSE
;; int usmb2_close(struct usmb2_context *usmb2, uint8_t *fid)
_usmb2_close:
        call    ga4
        ld      hl,prog_cl
        call    prep                    ; DE = buf+71
        ld      hl,5
        call    putfid
        ld      de,6*256+60
        ld      bc,24
        jr      br01
ENDIF

;; ---------------------------------------------------------------------------
;; int usmb2_negotiateprotocol(struct usmb2_context *usmb2)
_usmb2_negotiateprotocol:
        ld      bc,2
        call    getargs
neg_i:
        ld      hl,prog_neg
        call    prep
        ld      de,0*256+64             ; cmd 0, cic 64
        ld      bc,40
br01:   call    br
ret01:  ld      hl,0                    ; Z -> 0, NZ -> -1 (flags kept)
        ret     z
        dec     hl
        ret

;; ---------------------------------------------------------------------------
;; int usmb2_sessionsetup(struct usmb2_context *usmb2)
_usmb2_sessionsetup:
        ld      bc,2
        call    getargs
ss_i:
        ld      a,1
ss_round:                               ; A = NTLMSSP message type 1 / 3
IFDEF USMB2_FEATURE_NTLM
        cp      3
        jr      z,ss_ntlm
ENDIF
        push    af
        ld      hl,prog_ssA
        call    prep                    ; DE = buf+100
        pop     af
        ld      (de),a                  ; message type
        ld      hl,blob1
        ld      bc,32
IFNDEF USMB2_FEATURE_NTLM
        dec     a
        jr      z,ss_1
        ld      hl,blob3
        ld      c,72
ss_1:
ENDIF
        push    bc
        call    fill
        pop     hl                      ; len
ss_len:                                 ; HL = len of security blob
        ex      de,hl
        ld      a,82
        call    bufa
        ld      (hl),e
        inc     hl
        ld      (hl),d
        ld      hl,31
        add     hl,de
        ld      a,l
        and     $f8
        ld      c,a
        ld      b,h                     ; (24 + len + 7) & 0xfff8
        ld      de,1*256+64
        call    br
        jr      z,ret01
        ld      a,l                     ; STATUS_MORE_PROCESSING ?
        xor     $16
        or      h
        or      e
        jr      nz,ret01
        ld      a,d
        cp      $c0
        ld      a,3
        jr      z,ss_round
        jr      ret01

IFDEF USMB2_FEATURE_NTLM
ss_ntlm:
        ld      hl,(v_buf)
        ld      de,-86
        add     hl,de
        push    hl                      ; usmb2
        inc     hl
        inc     hl
        push    hl                      ; usmb2->username
        ld      de,32
        add     hl,de
        push    hl                      ; usmb2->password
        call    _ntlm_generate_auth
        pop     bc
        pop     bc
        pop     bc
        push    hl
        ld      bc,91
        ld      hl,prog_ssA
        call    prepn                   ; memset(buf,0,92) + header bits
        pop     hl
        jr      ss_len
ENDIF

;; ---------------------------------------------------------------------------
;; uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode)
IFDEF USMB2_FEATURE_OPENDIR
;; uint8_t *usmb2_opendir(struct usmb2_context *usmb2, const char *name)
_usmb2_opendir:
        ld      bc,4
        ld      de,ARG+2
        call    getargs_de              ; name -> ARG+2
        ld      hl,$1000
        ld      (ARG),hl                ; mode = O_RDONLY|O_DIRECTORY
        jr      open_i
ENDIF
_usmb2_open:
        ld      bc,6
        call    getargs                 ; ARG+0 = mode, ARG+2 = name
open_i:
        ld      hl,prog_open
        call    prep                    ; DE = buf+113
        inc     de
        push    de                      ; buf+114
IFDEF USMB2_FEATURE_WRITE
        ld      hl,(ARG)
        ld      a,l
        xor     2                       ; mode == O_RDWR
        or      h
        ld      hl,prog_rdwr
        call    z,fillbuf
ENDIF
IFDEF USMB2_FEATURE_OPENDIR
        ld      a,(ARG+1)
        and     $10                     ; mode & O_DIRECTORY
        ld      hl,prog_dir
        call    nz,fillbuf
ENDIF
        pop     de
        push    de
        ld      hl,10
        add     hl,de
        ex      de,hl                   ; DE = buf+124
        ld      hl,(ARG+2)
IFDEF USMB2_FEATURE_UNICODE
        push    hl
        push    de
        call    _utf8_to_utf16
        pop     bc
        pop     bc
        add     hl,hl
ELSE
        call    wcopy
ENDIF
        pop     de
        ld      a,l
        ld      (de),a                  ; name length
        ld      bc,64
        add     hl,bc
        ld      b,h
        ld      c,l
        ld      de,5*256+88
        call    br
        ld      hl,0
        ret     nz
        ld      l,1
        push    hl
        ld      l,16
        ld      a,(ARG+1)
        and     $10
        jr      z,op1
        ld      hl,16+256
op1:    push    hl
        call    calloc_callee
        ld      a,h
        or      l
        ret     z
        push    hl
        ex      de,hl
        ld      a,64
        call    bufa
        ld      bc,16
        ldir
        pop     hl
        ret

;; ---------------------------------------------------------------------------
IFDEF USMB2_FEATURE_OPENDIR
;; uint8_t *usmb2_readdir(struct usmb2_context *usmb2, uint8_t *dh)
_usmb2_readdir:
        call    ga4                 ; ARG = dh
        call    dh16
        ld      a,(hl)
        inc     hl
        or      (hl)
        jr      nz,rd_have
        ld      hl,prog_qd1
        call    prep                    ; DE = buf+71
        ld      hl,5
        call    putfid                  ; DE = buf+92
        ld      hl,prog_qd2
        call    fill
        ld      de,14*256+8
        ld      bc,40
        call    br
        ld      hl,0
        ret     nz
        call    dh16
        ld      (hl),4
        inc     hl
        inc     hl
        inc     hl
        inc     hl
        ex      de,hl                   ; DE = dh+20
        ld      a,4
        call    bufa
        ld      c,(hl)
        inc     hl
        ld      b,(hl)
        inc     hl
        inc     hl
        inc     hl                      ; buf+8
        call    copy
rd_have:
        call    dh16
        push    hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)                  ; DE = curr
        pop     hl
        push    hl
        add     hl,de                   ; HL = entry
        ld      c,(hl)
        inc     hl
        ld      b,(hl)                  ; BC = next
        dec     hl
        ex      de,hl
        ld      a,b
        or      c
        add     hl,bc                   ; curr + next
        jr      nz,rd1
        ld      h,a
        ld      l,a
rd1:    ex      (sp),hl                 ; HL = &dh[16]
        pop     bc
        ld      (hl),c
        inc     hl
        ld      (hl),b
        push    de                      ; entry
        ld      hl,$3c
        add     hl,de
        ld      c,(hl)
        inc     hl
        ld      b,(hl)
        inc     hl
        inc     hl
        inc     hl                      ; HL = name
        srl     b
        rr      c
IFDEF USMB2_FEATURE_UNICODE
        push    hl
        push    hl
        push    bc
        call    _utf16_to_utf8
        pop     bc
        pop     bc
        pop     de
        add     hl,de
        ld      (hl),0
ELSE
        ld      d,h
        ld      e,l
rd2:    ld      a,b
        or      c
        jr      z,rd3
        ld      a,(hl)
        ld      (de),a
        inc     hl
        inc     hl
        inc     de
        dec     bc
        jr      rd2
rd3:    ld      (de),a
ENDIF
        pop     hl
        ret

dh16:   ld      hl,(ARG)
        ld      de,16
        add     hl,de
        ret
ENDIF

;; int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
_usmb2_size:
        call    ga4
        ld      hl,prog_sz
        call    prep                    ; DE = buf+77
        ld      hl,15
        call    putfid
        ld      de,16*256+8
        ld      bc,40
        call    br
        ld      hl,-1
        ret     nz
        ld      a,16
        jr      bufa32                  ; int result = low word

;; ---------------------------------------------------------------------------
;; int32_t usmb2_prw(usmb2, int cmd, fid, rbuf, wbuf, int count, uint64_t off)
;; internal layout: ARG+0 off, ARG+8 count, ARG+10 data buffer, ARG+12 fid
_usmb2_prw:
        ld      bc,20
        call    getargs                 ; off,count,wbuf,rbuf,fid,cmd
        ld      a,(ARG+16)
        cp      9
        jr      z,prw1
        ld      hl,(ARG+12)
        ld      (ARG+10),hl             ; data buffer = rbuf unless WRITE
prw1:   ld      hl,(ARG+14)
        ld      (ARG+12),hl
        jr      prw_core
IFDEF USMB2_FEATURE_WRITE
;; int32_t usmb2_pwrite(usmb2, fid, buf, int count, uint64_t off)
_usmb2_pwrite:
        ld      a,9
        defb    $21                     ; ld hl,nn : skips "ld a,8"
ENDIF
;; int32_t usmb2_pread(usmb2, fid, buf, int count, uint64_t off)
_usmb2_pread:
        ld      a,8
        ld      bc,16
        call    getargs                 ; off,count,buf,fid  (A kept)
prw_core:
        push    af
        ld      hl,prog_rw
        call    prep                    ; DE = buf+69
        pop     af
        inc     de
        cp      9
        push    af
        jr      nz,prw2
        ld      a,$70
        ld      (de),a
prw2:   inc     de
        inc     de
        ld      hl,ARG+8
        ldi
        ldi                             ; count -> buf+72
        inc     de
        inc     de
        ld      hl,ARG
        ld      bc,8
        ldir                            ; offset -> buf+76
        ld      hl,(ARG+12)
        ld      c,16
        ldir                            ; fid -> buf+84
        pop     af
        ld      d,a
        ld      e,16
        ld      bc,48
        cp      8
        jr      nz,prw3
        ld      c,56
prw3:   call    br
        ret     nz
        ld      a,4
bufa32: call    bufa
ld32:   ld      e,(hl)
        inc     hl
        ld      d,(hl)
        inc     hl
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        ex      de,hl
        ret

;; ---------------------------------------------------------------------------
;; ===========================================================================
;; helpers

;; copy BC = nbytes of stack args (from SP+4) to DE (default ARG); the last
;; (deepest) word is the usmb2 context -> v_buf.  A is preserved.
ga4:    ld      bc,4
getargs:
        ld      de,ARG
getargs_de:
        ld      hl,4
        add     hl,sp
        ldir
        dec     hl
        ld      d,(hl)
        dec     hl
        ld      e,(hl)
setctx:                                 ; DE = ctx (preserved)
        ld      hl,86
        add     hl,de
        ld      (v_buf),hl
        ret

;; HL = buf + A
bufa:   ld      hl,(v_buf)
        add     a,l
        ld      l,a
        ret     nc
        inc     h
        ret

;; copy 16 bytes from the pointer in ARG to DE+HL; returns DE past it
putfid: add     hl,de
        ex      de,hl
        ld      hl,(ARG)
        ld      bc,16
        ldir
        ret

;; memset(buf, 0, 512) (prepn: BC = n-1 bytes) then run fill program HL
prep:   ld      bc,511
prepn:  push    hl
        ld      hl,(v_buf)
        ld      d,h
        ld      e,l
        ld      (hl),0
        inc     de
        ldir
        pop     hl
fillbuf:
        ld      de,(v_buf)
;; fill program: pairs (skip, value), skip counted from the byte after the
;; last one written; $ff terminates.  Returns DE = after last written byte.
fill:   ld      a,(hl)
        inc     hl
        inc     a
        ret     z
        dec     a
        add     a,e
        ld      e,a
        jr      nc,fill1
        inc     d
fill1:  ldi
        jr      fill

;; ---------------------------------------------------------------------------
;; br: build header, send request, wait for reply, parse it.
;; in: D = command, E = commandincount, BC = commandoutcount
;;     for command 9 (WRITE) the payload is ARG+10 (NULL -> buf), len ARG+8
;;     for command 8 (READ) the data goes to ARG+10 (if !NULL), len ARG+8
;; out: DEHL = status, Z iff status == 0
br:     ld      (v_cic),de              ; v_cic = E, v_cmd = D
        ld      hl,68
        add     hl,bc                   ; hdrlen = 4 + 64 + coc
        ld      bc,0
        ld      a,d
        cp      9
        jr      nz,br1
        ld      bc,(ARG+8)              ; outdatacount
br1:    push    hl
        add     hl,bc
        ex      (sp),hl                 ; [txlen]
        push    bc                      ; [odc]
        push    hl                      ; [hdrlen]
        add     hl,bc
        dec     hl
        dec     hl
        dec     hl
        dec     hl                      ; spl
        ex      de,hl
        ld      hl,(v_buf)
        inc     hl
        inc     hl
        ld      (hl),d
        inc     hl
        ld      (hl),e
        inc     hl
        ld      (hl),$fe
        inc     hl
        ld      (hl),'S'
        inc     hl
        ld      (hl),'M'
        inc     hl
        ld      (hl),'B'
        inc     hl
        ld      (hl),$40
        inc     hl
        inc     hl                      ; buf+10 credit charge
        ld      a,(v_cmd)
        or      a
        jr      z,br2
        ld      (hl),1
br2:    ld      bc,6
        add     hl,bc
        ld      (hl),a                  ; buf+16 command
        inc     hl
        inc     hl
        ld      (hl),1                  ; buf+18 credit request
        ld      c,33                    ; B = 0
        add     hl,bc
        ex      de,hl                   ; DE = buf+51
        ld      hl,-56
        add     hl,de                   ; HL = &session_id + 7
        ld      c,8
        lddr                            ; session -> buf+44..51
        ld      c,12
        add     hl,bc                   ; &tree_id + 3
        ld      c,4
        lddr                            ; tree -> buf+40..43
        ld      bc,-12
        add     hl,bc                   ; &message_id + 3
        ex      de,hl
        ld      c,-8 & $ff              ; BC = -8
        add     hl,bc
        ex      de,hl                   ; DE = buf+31
        ld      bc,4
        lddr                            ; mid (low 32 bits) -> buf+28..31
        inc     hl                      ; &message_id
br3:    inc     (hl)                    ; message_id++
        inc     hl
        jr      z,br3
        ;; transmit
        ld      hl,(_usmb2_tcp)
        push    hl
        call    _tcp_tx_buffer
        pop     bc
        ex      de,hl
        ld      hl,(v_buf)
        pop     bc                      ; hdrlen
        ldir
        pop     bc                      ; odc
        ld      hl,(ARG+10)             ; outdata (N7: never NULL)
        call    copy
        ld      hl,(_usmb2_tcp)
        ex      (sp),hl
        push    hl
        ld      hl,0
        push    hl
        push    hl                      ; tcp_send(usmb2_tcp, txlen, NULL, 0)
        call    _tcp_send
        pop     hl
        pop     hl
        pop     hl
        pop     hl
        ;; receive until the message id matches (or tcp_recv() < 0)
br5:    ld      hl,(_usmb2_tcp)
        push    hl
        ld      bc,8
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl                      ; tcp_recv(usmb2_tcp, ip.pkt_size)
        call    _tcp_recv
        pop     bc
        pop     bc
        bit     7,h
        jr      nz,br7
        ld      a,h
        or      l
        jr      z,br5
        call    rxbuf
        ld      de,28
        add     hl,de
        ex      de,hl
        ld      a,28
        call    bufa
        ld      b,4
br6:    ld      a,(de)
        cp      (hl)
        jr      nz,br5
        inc     hl
        inc     de
        djnz    br6
br7:    call    rxbuf
        inc     hl
        inc     hl
        ld      b,(hl)
        inc     hl
        ld      c,(hl)
        inc     hl                      ; BC = spl, HL = rx+4
        push    hl                      ; status is at rx+12
        ld      (v_R),bc
        ld      de,(v_buf)
        ld      bc,64
        call    rd                      ; SMB2 header -> buf
        ld      a,(v_cmd)
        push    hl                      ; HL = rx+68, DE = buf+64
        ld      bc,-28
        add     hl,bc                   ; rx+40: reply TreeId
        ex      de,hl
        ld      c,-68 & $ff             ; BC = -68
        add     hl,bc
        ex      de,hl                   ; DE = &tree_id
        ld      bc,4
        cp      3
        jr      z,br9                   ; TREE_CONNECT: tree id
        dec     a
        jr      nz,br10
        ld      c,11                    ; SESSION_SETUP: session id
        add     hl,bc                   ; rx+51
        dec     de                      ; &session_id + 7
        ld      c,8
        lddr
        jr      br10
br9:    ldir
br10:   pop     hl                      ; rx walker
        ld      de,(v_buf)
        ld      a,(v_cic)
        ld      c,a
        ld      b,0
        call    rd                      ; command header
        push    de
        ld      a,(v_cmd)
        cp      8
        jr      nz,br11
        ld      de,(ARG+10)             ; indata (N7: never NULL)
        ld      bc,(ARG+8)
        call    rd                      ; READ data
br11:   pop     de
        ld      bc,-1
        call    rd                      ; rest -> buf + cic
        pop     hl
        ld      de,8
        add     hl,de
        call    ld32
        ld      a,h
        or      l
        or      d
        or      e
        ret

;; read BC bytes (clamped to remaining R) from HL to DE
rd:     push    hl
        ld      hl,(v_R)
        or      a
        sbc     hl,bc
        jr      nc,rd_1
        add     hl,bc
        ld      b,h
        ld      c,l
        ld      hl,0
rd_1:   ld      (v_R),hl
        pop     hl
copy:   ld      a,b
        or      c
        ret     z
        ldir
        ret

;; ---------------------------------------------------------------------------
;; fill programs (skip, value)... $ff
prog_neg:   defb 68,$24, 1,1, 9,$aa, 14,$bb, 9,3, $ff
prog_ssA:   defb 68,$19, 11,$58, 11,'N', 0,'T', 0,'L', 0,'M', 0,'S', 0,'S', 0,'P', 0,0, $ff
blob1:      defb 4,$27, 0,2, 0,8, 0,$20, $ff
IFNDEF USMB2_FEATURE_NTLM
blob3:      defb 52,$17, 0,$88, 0,8, 0,$20, $ff
ENDIF
prog_tc:    defb 68,9, 3,$48, $ff
prog_open:  defb 68,$39, 3,2, 19,$89, 7,3, 3,1, 3,$40, 3,$78, $ff
IFDEF USMB2_FEATURE_WRITE
prog_rdwr:  defb 92,$8b, 11,3, $ff
ENDIF
IFDEF USMB2_FEATURE_OPENDIR
prog_dir:   defb 92,$81, 3,$10, 11,1, $ff
prog_qd1:   defb 68,$21, 1,1, $ff
prog_qd2:   defb 0,$60, 1,2, 1,$fc, 3,$2a, $ff
ENDIF
prog_sz:    defb 68,$29, 1,1, 0,5, 0,$ff, 0,$ff, 2,$68, $ff
IFDEF USMB2_FEATURE_CLOSE
prog_cl:    defb 68,$18, 1,1, $ff
ENDIF
prog_rw:    defb 68,$31, $ff

;; HL = tcp_rx_buffer(usmb2_tcp)
        SECTION code_compiler
rxbuf:  ld      hl,(_usmb2_tcp)
        push    hl
        call    _tcp_rx_buffer
        pop     bc
        ret

        SECTION bss_compiler
_usmb2_tcp:
        defs    2
ARG:    defs    20
v_buf:  defs    2
v_cic:  defs    1                       ; must be followed by v_cmd
v_cmd:  defs    1
v_R:    defs    2
