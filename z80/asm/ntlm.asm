; DO NOT EDIT. GENERATED. The C sources are canonical.
; -----------------------------------------------------------------------------
; ntlm.asm - hand-written, size-optimized Z80 rewrite of ntlm_generate_auth()
;
;   int ntlm_generate_auth(struct usmb2_context *usmb2,
;                          char *username, char *password);
;
; sccz80 ABI: args pushed left-to-right (usmb2 first, password last => password
; at SP+2 on entry).  Caller pops the arguments.  Return value (int) in HL.
;
; The C-ABI crypto helpers _MD4Init/_MD4Update/_MD4Final/_hmac_md5 are external
; black boxes with the standard sccz80 ABI (args pushed left-to-right, caller
; pops, void return).
;
; Byte-for-byte equivalent (buffer contents + return value) to the sccz80
; compilation of ntlm.c for all realistic CHALLENGE messages.
;
; Notes on narrowing vs the C source:
;  * 32-bit fields read from the buffer (target-name offset, target-info offset)
;    are used only as buffer offsets (< 512) so only the low 16 bits are read.
;  * The AvPair scan index 'z' is a signed char in C.  It is kept as an 8-bit
;    value here and sign-extended when used as an index / length, matching the C
;    exactly for realistic messages (target-info well under 128 bytes).
;  * ldir/fill loops are inlined; a shared docopy guards zero-length copies
;    (C memcpy(...,0) is a no-op; a raw ldir would copy 65536 bytes).
; -----------------------------------------------------------------------------

        SECTION code_compiler

        PUBLIC  _ntlm_generate_auth

        EXTERN  _MD4Init
        EXTERN  _MD4Update
        EXTERN  _MD4Final
        EXTERN  _hmac_md5

; struct usmb2_context: buf[] is at offset 86 (fd:2, username:32, password:32,
; message_id:8, session_id:8, tree_id:4 = 86).
BUFOFF          equ     86
; ntlmssp_out_offset = 4 + 64 + 24
OUTB            equ     92

; -----------------------------------------------------------------------------
_ntlm_generate_auth:
        ; --- fetch arguments -------------------------------------------------
        ld      hl,2
        add     hl,sp
        ld      e,(hl)
        inc     hl
        ld      d,(hl)          ; DE = password
        ld      (pwptr),de
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)          ; DE = username
        ld      (unptr),de
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)          ; DE = usmb2
        ld      hl,BUFOFF
        add     hl,de
        ld      (bufbase),hl    ; B = &usmb2->buf[0]

        ; --- ntlmssp_in_offset = le16(buf[4]) - 64 -------------------------
        ld      bc,4
        call    g16             ; DE = le16(buf[4])
        ld      hl,-64
        add     hl,de
        ld      (in_off),hl

        ; --- domain_name_len = le16(buf[in+12]) ----------------------------
        ld      hl,(in_off)
        ld      bc,12
        add     hl,bc
        ld      b,h
        ld      c,l
        call    g16
        ld      (dnl),de        ; domain_name_len

        ; --- domain_name = &buf[in + le32(buf[in+16])] ---------------------
        ld      hl,(in_off)
        ld      bc,16
        add     hl,bc
        ld      b,h
        ld      c,l
        call    g16             ; DE = target-name offset (low 16)
        ld      hl,(in_off)
        add     hl,de
        ld      de,(bufbase)
        add     hl,de
        ld      (dnp),hl        ; domain_name (original location)

        ; --- strlen(username)*2 --------------------------------------------
        ld      hl,(unptr)
        ld      bc,0
slp:
        ld      a,(hl)
        or      a
        jr      z,sldone
        inc     hl
        inc     bc
        jr      slp
sldone:
        ld      h,b
        ld      l,c
        add     hl,hl           ; *2
        ld      (unl),hl        ; user_name_len

        ; --- user_name_offset = domain_name_len + 72 -----------------------
        ld      hl,(dnl)
        ld      bc,72
        add     hl,bc
        ld      (uno),hl
        ; --- ntlm_response_offset = user_name_len + user_name_offset -------
        ld      de,(unl)
        add     hl,de
        ld      (nro),hl        ; ntlm_response_offset

        ; --- copy server challenge -----------------------------------------
        ; memcpy(&buf[92+nro+8], &buf[in+24], 8)
        ld      hl,(bufbase)
        ld      de,(in_off)
        add     hl,de
        ld      de,24
        add     hl,de           ; HL = src
        push    hl
        ld      de,OUTB+8
        call    bnro            ; HL = &buf[92+nro+8]
        ex      de,hl           ; DE = dst
        pop     hl              ; HL = src
        ld      bc,8
        call    docopy

        ; --- target_info = &buf[in + le32(buf[in+44])] ---------------------
        ld      hl,(in_off)
        ld      bc,44
        add     hl,bc
        ld      b,h
        ld      c,l
        call    g16             ; DE = target-info offset (low 16)
        ld      hl,(in_off)
        add     hl,de
        ld      de,(bufbase)
        add     hl,de
        ld      (tip),hl

        ; --- scan AvPairs to find length z (excluding EndOfList) ------------
        xor     a
        ld      (zb),a          ; z = 0
zlp:
        ld      a,(zb)
        ld      l,a
        rlca
        sbc     a,a
        ld      h,a             ; HL = sext(z)
        ld      de,(tip)
        add     hl,de           ; HL = &target_info[z]
        ld      e,(hl)
        inc     hl
        ld      d,(hl)          ; DE = at_type
        ld      a,d
        or      e
        jr      z,zdone
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)          ; DE = at_len
        ld      hl,4
        add     hl,de           ; HL = 4 + at_len
        ld      a,(zb)
        add     a,l             ; z = (char)(z + 4 + at_len)
        ld      (zb),a
        jr      zlp
zdone:

        ; --- offw = 92 + nro + 44 ; memcpy(&buf[offw], target_info, z) ------
        ld      hl,(nro)
        ld      de,OUTB+44
        add     hl,de
        ld      (offw),hl       ; offset 92+nro+44
        ld      b,h
        ld      c,l
        call    getp
        ex      de,hl           ; DE = dst
        ld      hl,(tip)        ; src
        ld      a,(zb)
        ld      c,a
        rlca
        sbc     a,a
        ld      b,a             ; BC = sext(z)
        call    docopy
        ; offw += z
        ld      hl,(offw)
        ld      a,(zb)
        ld      e,a
        rlca
        sbc     a,a
        ld      d,a             ; DE = sext(z)
        add     hl,de
        ld      (offw),hl

        ; --- append TargetName AvPair --------------------------------------
        ; type=9, len=10+domain_name_len
        ld      de,9
        call    emitw
        ld      hl,10
        ld      de,(dnl)
        add     hl,de
        ex      de,hl
        call    emitw
        ; "cifs/" as UCS2
        ld      de,'c'
        call    emitw
        ld      de,'i'
        call    emitw
        ld      de,'f'
        call    emitw
        ld      de,'s'
        call    emitw
        ld      de,'/'
        call    emitw
        ; memcpy(&buf[offw], domain_name, domain_name_len)
        ld      bc,(offw)
        call    getp
        ex      de,hl           ; DE = dst
        ld      hl,(dnp)        ; src
        ld      bc,(dnl)
        call    docopy
        ld      hl,(offw)
        ld      de,(dnl)
        add     hl,de
        ld      (offw),hl
        ; memset(&buf[offw], 0, 8)
        ld      bc,(offw)
        call    getp
        ld      b,8
        xor     a
        call    fillmem
        ; out_pdu_size = offw + 8
        ld      hl,(offw)
        ld      de,8
        add     hl,de
        ld      (outsz),hl

        ; --- domain name to output header ----------------------------------
        ; memcpy(&buf[164], domain_name, domain_name_len)
        ld      bc,OUTB+72
        call    getp
        ex      de,hl           ; DE = dst
        ld      hl,(dnp)        ; src (still original location)
        ld      bc,(dnl)
        call    docopy
        ; domain_name = &buf[164]
        ld      bc,OUTB+72
        call    getp
        ld      (dnp),hl
        ; length/offset fields
        ld      bc,OUTB+28
        ld      de,(dnl)
        call    p16
        ld      bc,OUTB+30
        ld      de,(dnl)
        call    p16
        ld      bc,OUTB+32
        ld      de,72
        call    p16
        ld      bc,OUTB+34
        ld      de,0
        call    p16

        ; --- NT Response length/offset -------------------------------------
        ; resp = out_pdu_size - 92 - nro
        ld      hl,(outsz)
        ld      de,(nro)
        or      a
        sbc     hl,de
        ld      de,OUTB
        or      a
        sbc     hl,de
        ld      (resp),hl
        ld      bc,OUTB+20
        ld      de,(resp)
        call    p16
        ld      bc,OUTB+22
        ld      de,(resp)
        call    p16
        ld      bc,OUTB+24
        ld      de,(nro)
        call    p16
        ld      bc,OUTB+26
        ld      de,0
        call    p16

        ; --- username as UCS2 ----------------------------------------------
        ld      a,(unl)         ; low byte of user_name_len (<=62)
        srl     a               ; character count
        or      a
        jr      z,undone
        ld      b,a             ; loop count
        ld      hl,(uno)
        ld      de,OUTB
        add     hl,de
        ld      de,(bufbase)
        add     hl,de
        ex      de,hl           ; DE = &buf[92+uno]
        ld      hl,(unptr)      ; src
unlp:
        ld      a,(hl)
        inc     hl
        ld      (de),a
        inc     de
        xor     a
        ld      (de),a
        inc     de
        djnz    unlp
undone:
        ld      bc,OUTB+36
        ld      de,(unl)
        call    p16
        ld      bc,OUTB+38
        ld      de,(unl)
        call    p16
        ld      bc,OUTB+40
        ld      de,(uno)
        call    p16
        ld      bc,OUTB+42
        ld      de,0
        call    p16

        ; --- host name / flags / version -----------------------------------
        ld      bc,OUTB+44
        call    getp
        ld      b,12
        xor     a
        call    fillmem         ; memset(&buf[92+44],0,12)
        ld      bc,OUTB+56
        ld      de,08037h
        call    p16
        ld      bc,OUTB+58
        ld      de,02008h
        call    p16             ; flags = 0x20088037
        ld      bc,OUTB+60
        call    getp
        ld      b,8
        xor     a
        call    fillmem         ; version = 0

        ; --- NTOWFv1 (MD4 of password as UCS2) -----------------------------
        ld      hl,(bufbase)
        push    hl
        call    _MD4Init
        pop     bc
pwlp:
        ld      hl,(pwptr)
        ld      a,(hl)
        or      a
        jr      z,pwdone
        ld      hl,(bufbase)
        push    hl
        ld      hl,(pwptr)
        push    hl
        ld      hl,1
        push    hl
        call    _MD4Update
        pop     bc
        pop     bc
        pop     bc
        ld      hl,(pwptr)
        inc     hl
        ld      (pwptr),hl
        ld      hl,(bufbase)
        push    hl
        ld      hl,zero
        push    hl
        ld      hl,1
        push    hl
        call    _MD4Update
        pop     bc
        pop     bc
        pop     bc
        jr      pwlp
pwdone:
        ; MD4Final(&buf[96], &buf[0])
        ld      bc,OUTB+4
        call    getp
        push    hl              ; digest
        ld      hl,(bufbase)
        push    hl              ; ctx
        call    _MD4Final
        pop     bc
        pop     bc

        ; --- NTOWFv2 = HMAC-MD5(NTOWFv1, upper(username) || domain) ---------
        ; hmac_md5(&buf[0], username, 0,0, domain_name, dnl, &buf[96],16, NTOWFv2)
        ld      hl,(bufbase)
        push    hl              ; ctx
        ld      hl,(unptr)
        push    hl              ; text0 = username
        ld      hl,0
        push    hl              ; text1 = NULL
        push    hl              ; text1_len = 0
        ld      hl,(dnp)
        push    hl              ; text2 = domain_name
        ld      hl,(dnl)
        push    hl              ; text2_len = domain_name_len
        ld      bc,OUTB+4
        call    getp
        push    hl              ; key = &buf[96]
        ld      hl,16
        push    hl              ; key_len = 16
        ld      hl,ntowf
        push    hl              ; digest = NTOWFv2
        call    _hmac_md5
        ld      hl,18
        add     hl,sp
        ld      sp,hl

        ; --- fill fixed parts of the ntlmv2 response -----------------------
        ; memset(&buf[92+nro+16],0,28)
        ld      de,OUTB+16
        call    bnro
        ld      b,28
        xor     a
        call    fillmem
        ; resp type 0x0101
        ld      de,OUTB+16
        call    bnro
        ld      (hl),1
        inc     hl
        ld      (hl),1
        ; client challenge = 8 * 0x01
        ld      de,OUTB+32
        call    bnro
        ld      b,8
        ld      a,1
        call    fillmem

        ; --- HMAC-MD5 over the response using NTOWFv2 ----------------------
        ; hmac_md5(&buf[0], 0, &buf[92+nro+8], resp-8, 0,0, NTOWFv2,16,
        ;          &buf[92+nro])
        ld      hl,(bufbase)
        push    hl              ; ctx
        ld      hl,0
        push    hl              ; text0 = NULL
        ld      de,OUTB+8
        call    bnro
        push    hl              ; text1 = &buf[92+nro+8]
        ld      hl,(resp)
        ld      de,-8
        add     hl,de
        push    hl              ; text1_len = resp - 8
        ld      hl,0
        push    hl              ; text2 = NULL
        push    hl              ; text2_len = 0
        ld      hl,ntowf
        push    hl              ; key = NTOWFv2
        ld      hl,16
        push    hl              ; key_len = 16
        ld      de,OUTB
        call    bnro
        push    hl              ; digest = &buf[92+nro]
        call    _hmac_md5
        ld      hl,18
        add     hl,sp
        ld      sp,hl

        ; --- first 20 bytes of the ntlmssp buffer --------------------------
        ; memset(&buf[100],0,12); buf[100]=3
        ld      bc,OUTB+8
        call    getp
        ld      b,12
        xor     a
        call    fillmem
        ld      bc,OUTB+8
        call    getp
        ld      (hl),3

        ; --- return out_pdu_size - 92 --------------------------------------
        ld      hl,(outsz)
        ld      de,-OUTB
        add     hl,de
        ret

; -----------------------------------------------------------------------------
; helpers
; -----------------------------------------------------------------------------
; getp: HL = bufbase + BC     (BC preserved, DE/A preserved)
getp:
        ld      hl,(bufbase)
        add     hl,bc
        ret

; g16: DE = le16(*(bufbase+BC))
g16:
        call    getp
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ret

; p16: store DE at (bufbase+BC)
p16:
        call    getp
        ld      (hl),e
        inc     hl
        ld      (hl),d
        ret

; emitw: store DE at buf[offw], offw += 2
emitw:
        ld      bc,(offw)
        call    p16
        ld      hl,(offw)
        inc     hl
        inc     hl
        ld      (offw),hl
        ret

; bnro: HL = bufbase + nro + DE
bnro:
        ld      hl,(nro)
        add     hl,de
        ld      de,(bufbase)
        add     hl,de
        ret

; docopy: copy BC bytes HL->DE (no-op if BC==0)
docopy:
        ld      a,b
        or      c
        ret     z
        ldir
        ret

; fillmem: store A into B bytes starting at HL
fillmem:
        ld      (hl),a
        inc     hl
        djnz    fillmem
        ret

; -----------------------------------------------------------------------------
        SECTION bss_compiler

bufbase:        defs    2
in_off:         defs    2
dnl:            defs    2
dnp:            defs    2
unl:            defs    2
uno:            defs    2
nro:            defs    2
outsz:          defs    2
tip:            defs    2
resp:           defs    2
offw:           defs    2
pwptr:          defs    2
unptr:          defs    2
zb:             defs    1
zero:           defs    1
ntowf:          defs    16
