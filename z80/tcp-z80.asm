; DO NOT EDIT. GENERATED. The C sources are canonical.
;
; Hand written Z80 replacement for the code sccz80 generates from tcp.c.
;
; tcp.c stays in the tree and is the specification: this file must behave
; exactly like it, down to the bytes it puts on the wire and the values it
; returns.  test/test_tcp.c runs both of them under z88dk-ticks and diffs
; the result, so keep the two in step.
;
; Why this is so much smaller than the compiler output:
;
;  * sccz80 reaches every struct field through the l_gint / l_pint /
;    l_glong / l_plong helpers and every argument through l_gintspsp.
;    Here IX is the frame pointer and the struct is walked with HL.
;  * ip_buffer() is a function call in tcp.c.  It is just ip->pkt + off.
;  * The header is assembled by copying, not by 2 byte memcpy()s:
;    saddr and daddr are adjacent in ip_context_t and go out with one LDIR,
;    the ports with LDIs, and htonl() is a 4 byte reversed copy instead of
;    a library call through a 32 bit temporary.
;  * The 32 bit sequence number compares are one 24 byte subroutine
;    instead of l_long_ult / l_long_ugt / l_long_eq / l_long_ne.
;
; IX is the frame pointer here, and it does NOT survive a call into
; compiler generated code: sccz80's l_long_add (reached from csum(), so
; also from ip_build_and_send()) returns with "pop ix / jp (ix)".  Every
; call to _csum, _ip_build_and_send and _recv_packet below therefore has a
; push ix before the arguments and a pop ix after the cleanup.  The
; entry points in this file save and restore IX themselves, so they are
; safe to call from anywhere and safe to call each other.
;
; Copyright 2026 Ronnie Sahlberg <ronniesahlberg@gmail.com>
; Same MIT licence as the rest of the tree, see tcp.c.
;

        MODULE  tcp_c

        PUBLIC  _tcp_send
        PUBLIC  _tcp_recv
        PUBLIC  _tcp_recv_timeout
        PUBLIC  _tcp_connect
        PUBLIC  _tcp_rx_buffer
        PUBLIC  _tcp_tx_buffer

        EXTERN  _csum
        EXTERN  _ip_build_and_send
        EXTERN  _recv_packet

; How many rs232_get() timeouts tcp_recv() waits.  Overridden with
; -Ca-DRS232_TPS=n, exactly like -DRS232_TPS=n is passed to the compiler.
IFNDEF RS232_TPS
        defc    RS232_TPS = 80
ENDIF

        defc    EAGAIN  = 15            ; errno.h
        defc    ERESET  = 20            ; tcp.h

        defc    IP_TCP  = 6

        defc    TCP_FIN = 0x01
        defc    TCP_SYN = 0x02
        defc    TCP_RST = 0x04
        defc    TCP_PSH = 0x08
        defc    TCP_ACK = 0x10

; ip_context_t, then the tcp_context_t fields that follow it.
        defc    o_saddr = 0             ; uint32_t
        defc    o_daddr = 4             ; uint32_t
        defc    o_size  = 8             ; uint16_t pkt_size
        defc    o_id    = 10            ; uint16_t
        defc    o_pkt   = 12            ; uint8_t *
        defc    o_dport = 14            ; uint16_t, network order
        defc    o_sport = 16            ; uint16_t, network order
        defc    o_seq   = 18            ; uint32_t
        defc    o_ack   = 22            ; uint32_t
        defc    o_ths   = 26            ; uint8_t

        SECTION code_compiler

;
; int tcp_send(tcp_context_t *tcp, int len, uint8_t *data, int window) __smallc
;
;   ix+4  window        ix-2/-1  hdr = tcp->pkt + 8, i.e. tcp.c's ptr - 12
;   ix+6  data          ix-3     sends left (1 + 5 retries)
;   ix+8  len           ix-8..-5 oseq + len, the seq that means "all acked"
;   ix+10 tcp
;
; hdr is the start of the pseudo header, so the whole thing tcp.c builds --
; 12 bytes of pseudo header, 20 of TCP header, then the payload -- is one
; run of memory from hdr onwards and every field is a small positive offset.
;
_tcp_send:
        push    ix
        ld      ix,0
        add     ix,sp

        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,o_pkt
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a                     ; hl = tcp->pkt
        ld      bc,8
        add     hl,bc
        push    hl                      ; ix-2 = hdr
        ld      h,6
        push    hl                      ; ix-3 = sends left

        ; oseq + len: the sequence number that means the peer has taken
        ; everything we are about to send.  len is only ever >= 0 here, so
        ; it is added unsigned rather than sign extended the way the C
        ; does it; a negative len would already have destroyed memory in
        ; the memcpy() below.
        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,o_seq
        add     hl,bc
        ld      c,(hl)
        inc     hl
        ld      b,(hl)                  ; bc = seq, low word
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)                  ; de = seq, high word
        ld      l,(ix+8)
        ld      h,(ix+9)
        add     hl,bc
        ex      de,hl                   ; de = low word + len, hl = high
        jr      nc,tcps_nocarry
        inc     hl
tcps_nocarry:
        push    hl                      ; ix-6/-5 = high word
        push    de                      ; ix-8/-7 = low word

; Retransmission point.  What gets re-sent is whatever is in the packet
; buffer, which recv_packet() has been writing into in the meantime; see
; tcps_retry at the bottom, and the caveat on tcp_tx_buffer() in tcp.c.
tcps_again:
        ; memset(ptr, 0, 20) plus the pseudo header, which is written in
        ; full below except for the zero byte at hdr+8.
        ld      l,(ix-2)
        ld      h,(ix-1)
        xor     a
        ld      b,32
tcps_zero:
        ld      (hl),a
        inc     hl
        djnz    tcps_zero               ; hl = hdr+32 = ptr+20

        ; if (data) memcpy(ptr + 20, data, len)
        ld      e,(ix+6)
        ld      d,(ix+7)
        ld      a,d
        or      e
        jr      z,tcps_nodata
        ld      c,(ix+8)
        ld      b,(ix+9)
        ld      a,b
        or      c
        jr      z,tcps_nodata           ; LDIR with BC=0 would copy 64K
        ex      de,hl
        ldir
tcps_nodata:

        ; pseudo header: saddr and daddr are adjacent, so one LDIR does both
        ld      e,(ix-2)
        ld      d,(ix-1)
        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,8
        ldir                            ; hdr+0..7, hl = tcp+8, de = hdr+8
        inc     de                      ; hdr+8 stays zero
        ld      a,IP_TCP
        ld      (de),a
        inc     de
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,20
        add     hl,bc                   ; htons(20 + len)
        ld      a,h
        ld      (de),a
        inc     de
        ld      a,l
        ld      (de),a
        inc     de                      ; de = hdr+12 = ptr[0]

        ; ports.  src_port goes out first but sits second in the struct.
        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,o_sport
        add     hl,bc
        ldi
        ldi                             ; ptr[0..1] = src_port
        dec     hl
        dec     hl
        dec     hl
        dec     hl
        ldi
        ldi                             ; ptr[2..3] = dst_port, hl = tcp+16

        ; htonl(seq) and htonl(ack)
        ld      bc,5
        add     hl,bc                   ; hl = &seq + 3
        call    revcpy4                 ; ptr[4..7], hl = &seq - 1
        ld      bc,8
        add     hl,bc                   ; hl = &ack + 3
        call    revcpy4                 ; ptr[8..11], hl = &seq + 3

        ld      a,0x50
        ld      (de),a
        inc     de                      ; ptr[12]

        ; flags.  hl still points at the top byte of tcp->seq.
        ld      a,(hl)
        dec     hl
        or      (hl)
        dec     hl
        or      (hl)
        dec     hl                      ; hl = &seq
        jr      nz,tcps_notsyn
        ld      a,(hl)
        dec     a
        jr      nz,tcps_notsyn
        ld      a,TCP_SYN               ; tcp->seq == 1
        jr      tcps_flags
tcps_notsyn:
        ld      a,(ix+8)
        or      (ix+9)
        ld      a,TCP_ACK
        jr      z,tcps_flags
        ld      a,TCP_ACK|TCP_PSH
tcps_flags:
        ld      (de),a
        inc     de                      ; ptr[13]

        ld      a,(ix+5)                ; htons(window)
        ld      (de),a
        inc     de
        ld      a,(ix+4)
        ld      (de),a                  ; ptr[14..15]

        ; cs = csum(ptr - 12, 12 + 20 + len)
        push    ix                      ; csum() does 32 bit maths, see above
        ld      l,(ix-2)
        ld      h,(ix-1)
        push    hl
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,32
        add     hl,bc
        push    hl
        call    _csum
        pop     bc
        pop     bc
        pop     ix
        ld      e,(ix-2)
        ld      d,(ix-1)
        ex      de,hl                   ; hl = hdr, de = cs
        ld      bc,28
        add     hl,bc
        ld      (hl),e
        inc     hl
        ld      (hl),d                  ; ptr[16..17]

        ; ip_build_and_send(&tcp->ip, 20 + 20 + len, IP_TCP)
        push    ix
        ld      l,(ix+10)
        ld      h,(ix+11)
        push    hl
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,40
        add     hl,bc
        push    hl
        ld      hl,IP_TCP
        push    hl
        call    _ip_build_and_send
        pop     bc
        pop     bc
        pop     bc
        pop     ix

        ; if (tcp->seq > 1 && len == 0) return 0;
        ld      a,(ix+8)
        or      (ix+9)
        jr      nz,tcps_wait
        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,o_seq
        add     hl,bc
        inc     hl
        ld      a,(hl)
        inc     hl
        or      (hl)
        inc     hl
        or      (hl)
        jr      nz,tcps_zero_rc         ; >= 65536, certainly > 1
        dec     hl
        dec     hl
        dec     hl
        ld      a,(hl)
        cp      2
        jr      nc,tcps_zero_rc

tcps_wait:
        ld      l,(ix+10)
        ld      h,(ix+11)
        push    hl
        ld      hl,0
        push    hl
        call    _tcp_recv
        pop     bc
        pop     bc

        ld      de,-EAGAIN
        or      a
        sbc     hl,de
        jr      z,tcps_retry
        add     hl,de                   ; rc back into hl
        bit     7,h
        jr      nz,tcps_exit            ; rc < 0, return rc

        ; Something came back, but was it an ACK of our data?  See the
        ; long comment on this test in tcp.c: answering "yes" when the
        ; peer has not taken the data deadlocks the connection.
        push    ix
        pop     de
        ld      hl,-8
        add     hl,de
        ex      de,hl                   ; de = &(oseq + len)
        ld      l,(ix+10)
        ld      h,(ix+11)
        ld      bc,o_seq
        add     hl,bc                   ; hl = &tcp->seq
        call    cmp32
        jr      c,tcps_retry            ; tcp->seq < oseq + len

tcps_zero_rc:
        ld      hl,0
tcps_exit:
        ld      sp,ix
        pop     ix
        ret

; Reached both when nothing came back and when what came back did not
; acknowledge the data.  A data argument gets copied in again on the way
; round, so it can be re-sent; a tcp_tx_buffer() payload cannot, and len
; is what tells those apart from the pure ACK and the SYN, which pass
; data == NULL with nothing to protect.  The SYN in particular has to
; keep its retransmissions.
tcps_retry:
        ld      a,(ix+6)
        or      (ix+7)
        jr      nz,tcps_countdown       ; data != NULL, copied in again
        ld      a,(ix+8)
        or      (ix+9)
        jr      nz,tcps_fail            ; tcp_tx_buffer() payload, gone
tcps_countdown:
        dec     (ix-3)
        jp      nz,tcps_again
tcps_fail:
        ld      hl,-1
        jr      tcps_exit

;
; Copy 4 bytes from (hl) downwards to (de) upwards -- htonl() of a value
; already in memory, without a 32 bit temporary.
;
revcpy4:
        ld      b,4
revcpy4_loop:
        ld      a,(hl)
        dec     hl
        ld      (de),a
        inc     de
        djnz    revcpy4_loop
        ret

;
; int tcp_recv(tcp_context_t *tcp, int len) __smallc
;
_tcp_recv:
        ld      hl,2
        add     hl,sp
        ld      c,(hl)
        inc     hl
        ld      b,(hl)                  ; bc = len
        inc     hl
        ld      e,(hl)
        inc     hl
        ld      d,(hl)                  ; de = tcp
        push    de
        push    bc
        ld      hl,RS232_TPS
        push    hl
        call    _tcp_recv_timeout
        pop     bc
        pop     bc
        pop     bc
        ret

;
; int tcp_recv_timeout(tcp_context_t *tcp, int len, int to) __smallc
;
;   ix+4 to    ix+6 len    ix+8 tcp
;
; seq, ack and ptr are file statics rather than stack locals.  tcp_send()
; can re-enter this function (tcp_send -> tcp_recv -> tcp_recv_timeout),
; but every use of the three is finished before the tcp_send() calls below
; are made, and the "goto again" path reloads all of them, so a nested call
; can never clobber a value an outer frame still needs.  len must stay on
; the frame: it is read again after the tcp_send() at the end.
;
_tcp_recv_timeout:
        push    ix
        ld      ix,0
        add     ix,sp

        ; if (len > tcp->ip.pkt_size - 44) len = tcp->ip.pkt_size - 44;
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_size
        add     hl,bc
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ld      hl,-44
        add     hl,de                   ; hl = limit
        ld      e,(ix+6)
        ld      d,(ix+7)                ; de = len
        push    hl
        or      a
        sbc     hl,de                   ; signed limit - len
        jp      pe,rt_clamp_ov
        jp      m,rt_clamp
        jr      rt_clamp_no
rt_clamp_ov:
        jp      p,rt_clamp
rt_clamp_no:
        pop     hl
        jr      rt_lenok
rt_clamp:
        pop     hl
        ld      (ix+6),l
        ld      (ix+7),h
rt_lenok:

        ; if (len) tcp_send(tcp, 0, NULL, len);
        ld      a,(ix+6)
        or      (ix+7)
        jr      z,rt_again
        ld      l,(ix+6)
        ld      h,(ix+7)
        call    rt_send

rt_again:
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_pkt
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        ld      (rt_ptr),hl             ; ptr = ip_buffer(&tcp->ip, 0)

        ; len = recv_packet(ptr, tcp->ip.pkt_size, to)
        push    ix
        push    hl
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_size
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl
        ld      l,(ix+4)
        ld      h,(ix+5)
        push    hl
        call    _recv_packet
        pop     bc
        pop     bc
        pop     bc
        pop     ix
        ld      (ix+6),l
        ld      (ix+7),h

        bit     7,h
        jp      nz,rt_exit              ; if (len < 0) return len;
        ld      de,20+20
        or      a
        sbc     hl,de
        jp      c,rt_eagain             ; if (len < 40) return -EAGAIN;

        ld      hl,(rt_ptr)
        ld      a,(hl)
        cp      0x45
        jp      nz,rt_eagain
        ld      bc,9
        add     hl,bc
        ld      a,(hl)
        cp      IP_TCP
        jp      nz,rt_eagain

        ; memcmp(&tcp->dst_port, &ptr[20], 4)
        ld      bc,11
        add     hl,bc                   ; hl = ptr+20
        ld      e,(ix+8)
        ld      d,(ix+9)
        ex      de,hl                   ; hl = tcp, de = ptr+20
        ld      bc,o_dport
        add     hl,bc
        ld      b,4
rt_ports:
        ld      a,(de)
        cp      (hl)
        jp      nz,rt_eagain
        inc     hl
        inc     de
        djnz    rt_ports

        ld      hl,(rt_ptr)
        ld      bc,20+13
        add     hl,bc
        ld      a,(hl)
        and     TCP_RST
        jp      nz,rt_ereset

        dec     hl                      ; ptr[20+12]
        ld      a,(hl)
        rrca
        rrca
        and     0x3f                    ; tcp->ths = ptr[20+12] >> 2
        ld      e,(ix+8)
        ld      d,(ix+9)
        ex      de,hl
        ld      bc,o_ths
        add     hl,bc
        ld      (hl),a

        ; seq = htonl(ptr[20+4]), ack = htonl(ptr[20+8]).  rt_ack sits
        ; immediately below rt_seq so both are one descending 8 byte copy.
        ld      hl,(rt_ptr)
        ld      bc,20+4
        add     hl,bc
        ld      de,rt_seq+3
        ld      b,8
rt_getseq:
        ld      a,(hl)
        inc     hl
        ld      (de),a
        dec     de
        djnz    rt_getseq

        ; if (tcp->seq == 1) -- still in the SYN handshake
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_seq
        add     hl,bc
        ld      a,(hl)
        cp      1
        jr      nz,rt_est
        inc     hl
        ld      a,(hl)
        inc     hl
        or      (hl)
        inc     hl
        or      (hl)
        jr      nz,rt_est

        ; if (ack != tcp->seq + 1) return -ERESET;
        ld      hl,rt_ack
        ld      a,(hl)
        cp      2
        jp      nz,rt_ereset
        inc     hl
        ld      a,(hl)
        inc     hl
        or      (hl)
        inc     hl
        or      (hl)
        jp      nz,rt_ereset

        ld      hl,(rt_ptr)
        ld      bc,20+13
        add     hl,bc
        ld      a,(hl)
        and     TCP_SYN
        jp      z,rt_ret_m1

        ld      e,(ix+8)
        ld      d,(ix+9)
        ld      hl,o_seq
        add     hl,de
        ex      de,hl                   ; de = &tcp->seq
        ld      hl,rt_ack
        ld      bc,4
        ldir                            ; tcp->seq = ack
        ld      hl,rt_seq
        ld      bc,4
        ldir                            ; tcp->ack = seq
        ld      hl,-4
        add     hl,de
        call    inc32                   ; tcp->ack = seq + 1
        ld      hl,0
        call    rt_send                 ; tcp_send(tcp, 0, NULL, 0)
        jp      rt_ret0

rt_est:
        ; if ((seq + 1 == tcp->ack) && (len == 20 + tcp->ths)) goto again;
        ld      hl,rt_seq
        ld      de,rt_tmp
        ld      bc,4
        ldir
        ld      hl,rt_tmp
        call    inc32
        ld      e,(ix+8)
        ld      d,(ix+9)
        ld      hl,o_ack
        add     hl,de
        ex      de,hl                   ; de = &tcp->ack
        ld      hl,rt_tmp
        call    cmp32
        jr      nz,rt_notprobe
        call    rt_hdrlen
        ld      e,(ix+6)
        ld      d,(ix+7)
        or      a
        sbc     hl,de
        jp      z,rt_again
rt_notprobe:

        ; if (tcp->seq < ack) tcp->seq = ack;
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_seq
        add     hl,bc
        ld      de,rt_ack
        call    cmp32
        jr      nc,rt_noadv
        ex      de,hl
        ld      bc,4
        ldir
rt_noadv:

        ; if (len > 20 + tcp->ths)
        call    rt_hdrlen
        ld      e,(ix+6)
        ld      d,(ix+7)
        or      a
        sbc     hl,de
        jr      nc,rt_done

        ; if (seq != tcp->ack) { tcp_send(tcp, 0, NULL, 0); return 0; }
        ; -- a retransmission, or after a segment we missed
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_ack
        add     hl,bc
        ex      de,hl                   ; de = &tcp->ack
        ld      hl,rt_seq
        call    cmp32
        jr      z,rt_inseq
        ld      hl,0
        call    rt_send                 ; ACK what we have
        jp      rt_ret0
rt_inseq:

        ; if (len > 20 + 20) tcp->ack += len - 20 - tcp->ths;
        ld      l,(ix+6)
        ld      h,(ix+7)
        ld      de,20+20
        or      a
        sbc     hl,de
        jr      z,rt_acked
        jr      c,rt_acked
        call    rt_delta
        ex      de,hl
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_ack
        add     hl,bc
        ld      a,(hl)
        add     a,e
        ld      (hl),a
        inc     hl
        ld      a,(hl)
        adc     a,d
        ld      (hl),a
        inc     hl
        ld      a,(hl)
        adc     a,0
        ld      (hl),a
        inc     hl
        ld      a,(hl)
        adc     a,0
        ld      (hl),a
rt_acked:
        ld      hl,0
        call    rt_send                 ; ACK it and close the window

rt_done:
        call    rt_delta                ; return len - 20 - tcp->ths;
        jr      rt_exit
rt_eagain:
        ld      hl,-EAGAIN
        jr      rt_exit
rt_ereset:
        ld      hl,-ERESET
        jr      rt_exit
rt_ret_m1:
        ld      hl,-1
        jr      rt_exit
rt_ret0:
        ld      hl,0
rt_exit:
        ld      sp,ix
        pop     ix
        ret

;
; tcp_send(tcp, 0, NULL, hl).  Used for the three window/ACK-only sends.
;
rt_send:
        ld      e,(ix+8)
        ld      d,(ix+9)
        ex      de,hl                   ; hl = tcp, de = window
        push    hl
        ld      hl,0
        push    hl
        push    hl
        push    de
        call    _tcp_send
        pop     bc
        pop     bc
        pop     bc
        pop     bc
        ret

; hl = 20 + tcp->ths
rt_hdrlen:
        ld      l,(ix+8)
        ld      h,(ix+9)
        ld      bc,o_ths
        add     hl,bc
        ld      l,(hl)
        ld      h,0
        ld      bc,20
        add     hl,bc
        ret

; hl = len - 20 - tcp->ths
rt_delta:
        call    rt_hdrlen
        ex      de,hl
        ld      l,(ix+6)
        ld      h,(ix+7)
        or      a
        sbc     hl,de
        ret

;
; int tcp_connect(tcp_context_t *tcp) __smallc
;
;   ix+4 tcp        ix-2/-1 ptr = tcp->pkt        ix-3 tries left
;
_tcp_connect:
        push    ix
        ld      ix,0
        add     ix,sp

        ld      l,(ix+4)
        ld      h,(ix+5)
        ld      bc,o_pkt
        add     hl,bc
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl                      ; ix-2 = ptr
        ld      h,5
        push    hl                      ; ix-3 = tries left

        ld      l,(ix+4)
        ld      h,(ix+5)
        ld      bc,o_ths
        add     hl,bc
        ld      (hl),0                  ; tcp->ths = 0

tc_loop:
        ld      l,(ix+4)
        ld      h,(ix+5)
        ld      bc,o_seq
        add     hl,bc
        ld      (hl),1                  ; tcp->seq = 1
        inc     hl
        ld      b,7
tc_zero:
        ld      (hl),0                  ; ...and tcp->ack = 0
        inc     hl
        djnz    tc_zero

        ld      l,(ix+4)
        ld      h,(ix+5)
        push    hl
        ld      hl,0
        push    hl
        push    hl
        inc     hl
        push    hl
        call    _tcp_send               ; tcp_send(tcp, 0, NULL, 1)
        pop     bc
        pop     bc
        pop     bc
        pop     bc
        bit     7,h
        jr      z,tc_exit               ; if (rc >= 0) return rc;

        ; tcp->src_port += checksum of the last packet + the R register
        ld      l,(ix-2)
        ld      h,(ix-1)
        ld      bc,20+16
        add     hl,bc
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        ld      h,0
        ld      a,r
        ld      l,a
        add     hl,de
        ex      de,hl
        ld      l,(ix+4)
        ld      h,(ix+5)
        ld      bc,o_sport
        add     hl,bc
        ld      a,(hl)
        add     a,e
        ld      (hl),a
        inc     hl
        ld      a,(hl)
        adc     a,d
        ld      (hl),a

        dec     (ix-3)
        jp      nz,tc_loop
        ld      hl,-1
tc_exit:
        ld      sp,ix
        pop     ix
        ret

;
; uint8_t *tcp_rx_buffer(tcp_context_t *tcp) __smallc
; uint8_t *tcp_tx_buffer(tcp_context_t *tcp) __smallc
;
_tcp_rx_buffer:
        call    tb_getptr
        ld      bc,o_ths
        add     hl,bc
        ld      l,(hl)
        ld      h,0
        add     hl,de
        ld      bc,20
        add     hl,bc
        ret

_tcp_tx_buffer:
        call    tb_getptr
        ex      de,hl
        ld      bc,20+20
        add     hl,bc
        ret

; hl = tcp, de = tcp->pkt.  Called, so the argument is at sp+4.
tb_getptr:
        ld      hl,4
        add     hl,sp
        ld      a,(hl)
        inc     hl
        ld      h,(hl)
        ld      l,a
        push    hl
        ld      bc,o_pkt
        add     hl,bc
        ld      e,(hl)
        inc     hl
        ld      d,(hl)
        pop     hl
        ret

;
; Two shared 32 bit primitives.  These replace l_long_eq / l_long_ne /
; l_long_ult / l_long_ugt / l_inclong / l_long_add.
;

; (hl)++ as a 32 bit little endian value.
inc32:
        ld      b,4
inc32_loop:
        inc     (hl)
        ret     nz
        inc     hl
        djnz    inc32_loop
        ret

; Compare the 32 bit little endian values at (hl) and (de).
; Z if equal, C if (hl) < (de) unsigned.  hl and de are preserved.
cmp32:
        push    hl
        push    de
        ld      bc,3
        add     hl,bc
        ex      de,hl
        add     hl,bc
        ex      de,hl                   ; point both at the top byte
        ld      b,4
cmp32_loop:
        ld      a,(de)
        ld      c,a
        ld      a,(hl)
        cp      c
        jr      nz,cmp32_done
        dec     hl
        dec     de
        djnz    cmp32_loop
cmp32_done:
        pop     de
        pop     hl
        ret

        SECTION bss_compiler

rt_ptr:
        defs    2
rt_tmp:
        defs    4
; rt_ack must stay immediately below rt_seq, see rt_getseq.
rt_ack:
        defs    4
rt_seq:
        defs    4
