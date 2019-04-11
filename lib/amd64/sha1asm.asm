;
; Sha1Asm.Asm
;
; Copyright (c) Microsoft Corporation.  All rights reserved.
;
;

;
;   This module implements the bulk processing of the FIPS 180-1 SHA message digest algorithm.
;   for the x64 processor architecture.
;
;   This implementation is derived from the 32-bit one, which in turn is derived
;   from an older one by Scott Field and Dan Shumow. 
;

include ksamd64.inc

        TITLE   sha1asm.asm

        ;
        ; The four round constants used by SHA-1
        ;
        
K0_19   EQU     05a827999H
K20_39  EQU     06ed9eba1H
K40_59  EQU     08f1bbcdcH
K60_79  EQU     0ca62c1d6H


;VOID
;SYMCRYPT_CALL
;SymCryptSha1AppendBlocks( _Inout_updates_( 5 )        PUINT32    H,
;                            _In_reads_bytes_( cbData )    PCBYTE    pbData,
;                                                     SIZE_T    cbData )
;

        ;
        ; This function allocates stack space, so it is not a LEAF function
        ; but a nested one.
        ;
        NESTED_ENTRY    SymCryptSha1AppendBlocksAsm, _TEXT
                
;
; To keep stack manipulations simple we define a structure and use that for all accesses.
;

SymCryptSha1AppendBlocksFrame struct  16, NONUNIQUE
;
; To keep the RSP aligned we need (8 mod 16) bytes of local stack space. 
; this is the case, so there is no need for a dummy location
;
Wbuf            dd      16 dup (?)
EndAddress      dq      ?
SaveR12         dq      ?
SaveR13         dq      ?
SaveR14         dq      ?
SaveR15         dq      ?
SaveRdi         dq      ?
SaveRsi         dq      ?
SaveRbp         dq      ?
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?
CallerP4Home    dq      ?

SymCryptSha1AppendBlocksFrame ends

        ;
        ; We use the W buffer extensively; this is a shorthand for the base address
        ;
W       equ     rsp+SymCryptSha1AppendBlocksFrame.Wbuf



        ;
        ; Set up our stack frame and save non-volatile registers
        ;
        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        push_reg        r15
        push_reg        r14
        push_reg        r13
        push_reg        r12
        alloc_stack     SymCryptSha1AppendBlocksFrame.SaveR12
        
        END_PROLOGUE

        ;
        ;Register allocation:
        ;
        ;5 registers for state
        ;2 scratch
        ;6 registers for W[t-1], W[t-2], W[t-3], W[t-14], W[t-15], W[t-16]
        ;1 for data pointer
        ;1 for H pointer
        ;
        ;
        ; To allow macro re-ordering of our registers we use symbolic names
        ; for the registers.
        ; s0-s4 are the 5 state registers. x1 and x2 are extra scratch registers.
        ; w0-w5 contain the W state cache
        ;
        ; Note: some other code puts the right value in the right register and
        ; has to be updated if this mapping is changed.
        ;
        ; a is in register (round   % 5)
        ; b is in register (round+4 % 5)
        ; c is in register (round+3 % 5)
        ; d is in register (round+2 % 5)
        ; e is in register (round+1 % 5)
        ; This way, if round is incremented we move a->b, b->c, c->d, d->e, and e->a
        ; For optimization the actual value of a is in scratch register x1 at the start of each round
        ;
        ; W[t- 1] is in register (round   % 6)
        ; W[t- 2] is in register (round+5 % 6)
        ; W[t- 3] is in register (round+4 % 6) (is loaded with W[t-13] in each round)
        ; W[t-14] is in register (round+3 % 6)
        ; W[t-15] is in register (round+2 % 6)
        ; W[t-16] is in register (round+1 % 6)
        ; If round is incremented the values all appear in their right place.
        
s0      EQU     eax
s1      EQU     ebx
s2      EQU     ecx
s3      EQU     edx
s4      EQU     esi

w0      EQU     r9d
w1      EQU     r10d
w2      EQU     r11d
w3      EQU     r12d
w4      EQU     r13d
w5      EQU     r14d

x1      EQU     ebp     ; screatch 1
x2      EQU     edi     ; scratch 2

dataPtr EQU     r8      ; Points to data buffer
HPtr    EQU     r15     ; Points to H


        ; At this point:
        ;       rcx = H
        ;       rdx = pbData
        ;       r8  = cbData
        ;
        ; compute the end address, address of byte after last block we will process
        ; This code ensures that we never exceed the data buffer we were given,
        ; although we silently round the cbData parameter down to the next
        ; multiple of 64.
        ; Do nothing if no blocks need to be processed.
        ;
        and     r8,NOT 3fh                      ; round down to multiple of 64
        jz      SymCryptSha1AppendBlocksDone
        add     r8,rdx                          ; pbData + (cbData & 0x3f)
        mov     [rsp+SymCryptSha1AppendBlocksFrame.EndAddress], r8

        mov     dataPtr,rdx
        mov     Hptr,rcx
                
        ;
        ; Load the H state, note that the a value lives in x1 at the round code boundary
        ;
        mov     x1,[Hptr   ]
        mov     s4,[Hptr+ 4]
        mov     s3,[Hptr+ 8]
        mov     s2,[Hptr+12]
        mov     s1,[Hptr+16]
        
        
SymCryptSha1AppendBlocksLoop:
        ;
        ; This is the main loop. We process 64 bytes in each iteration.
        ;
        ; Most of the code in the loop is generated through macros using parameters to
        ; rename the registers.
        ;
        
ROUND_CH_0_15   MACRO   round,sa,sb,sc,sd,se,wt,x1,x2
        ;
        ; Code for round 0-15.
        ; This code loads data from the data buffer & BSWAPs the data to get it into the
        ; right form.
        ;
        ; Parameters:
        ; round round number
        ; sa    register that will contain the a value
        ; sb    register that contains the b value
        ; sc    register that contains the c value
        ; sd    register that contains the d value
        ; se    register that contains the e value
        ; x1    scratch, contains the a value on entry
        ; x2    scratch register.
        ; wt    register loaded with Wt
        ; 
        ; We use the formula CH(b,c,d) = ((d ^ c) & b) ^ c which uses only one temp register.
        ; We start with the d value as that is the oldest value and available the first
        ;
        ; See FIPS 180-2 for our symbolic notation.
        ;
        mov     x2,sd                   ; x2 = d
        mov     wt,[dataPtr+4*round]    ; Fetch word from message
        mov     sa, x1                  ; put a in the correct register

        bswap   wt                      ; wt = Wt
        xor     x2,sc                   ; x2 = (d ^ c)
        rol     x1,5                    ; x1 = ROL(a,5)

        add     se,wt                   ; se = e + Wt
        and     x2,sb                   ; x2 = ((d ^ c) & b)
        mov     [W + 4*round],wt        ; Store in W buffer for future use
        ror     sb,2                    ; sb = ROL( b, 30 )

        add     se,x1                   ; se = e + Wt + ROL(a,5)
        xor     x2,sd                   ; x2 = ((d ^ c) & b) ^ d = CH(b,c,d)
        
        lea     x1,[se+x2+K0_19]        ; x1 = e + Wt + ROL(a,5) + Ch(b,c,d) + Kt
                
        ENDM

MSG_EXP         MACRO   round, se, wa, wb, wc
        ; round round number
        ; se    register of state to add expanded message word to
        ; wa    register of W[round-16], will be updated to contain W[round]
        ; wb    register of W[round-14]
        ; wc    register of W[round- 3], will be loaded with W[round-13]

        xor     wc, wb                          ; wc = W[t-3] ^ W[t-14]
        xor     wa,[W+4*((round-8) MOD 16)]     ; wa = W[t-16] ^ W[t-8]
        xor     wa, wc                          ; wa = W[t-16] ^ W[t-14] ^ W[t-8] ^ W[t-3]
        rol     wa,1                            ; wa = Wt
        IF      round LT (80 - 1)
                ; do not load wc with W[t-13] in the last round; it will not be needed
                mov     wc,[W+4*((round-13) MOD 16)]    ; wc = W[t-13]
        ENDIF
        add     se,wa                           ; re = e + Wt
        IF      round LT (80 - 8)
                ; don't store Wt in the last 8 rounds. The value would never be used
                mov     [W+4*(round MOD 16)], wa; Store Wt
        ENDIF
        ENDM

ROUND_CH        MACRO   round, sa, sb, sc, sd, se, wa, wb, wc, x1, x2
        ;
        ; See ROUND_CH_0_15 for most parameters.
        ; x1 and x2 are both scratch registers
        ; wa    register of W[round-16], will be updated to contain W[round]
        ; wb    register of W[round-14]
        ; wc    register of W[round- 3], will be loaded with W[round-13]
        ;
        
        xor     wc, wb                          ; wc = W[t-3] ^ W[t-14]
        xor     wa,[W+4*((round-8) MOD 16)]     ; wa = W[t-16] ^ W[t-8]
        xor     wa, wc                          ; wa = W[t-16] ^ W[t-14] ^ W[t-8] ^ W[t-3]
        rol     wa,1                            ; wa = Wt
        mov     wc,[W+4*((round-13) MOD 16)]    ; wc = W[t-13]
        add     se,wa                           ; re = e + Wt
        mov     [W+4*(round MOD 16)], wa        ; Store Wt
        
        mov     sa, x1                          ; put a in the correct register
        mov     x2,sd                           ; x2 = d
        rol     x1,5                            ; x1 = ROL(a,5)
        xor     x2,sc                           ; x2 = (d ^ c)
        add     se,x1                           ; re = e + Wt + ROL(a,5)
        and     x2,sb                           ; x2 = ((d ^ c) & b)
        ror     sb,2                            ; rb = ROL( b, 30 )
        xor     x2,sd                           ; x2 = ((d ^ c) & b) ^ d = CH(b,c,d)
        lea     x1,[se+x2+K0_19]                ; re = e + Wt + ROL(a,5) + Ch(b,c,d) + Kt
        ENDM

ROUND_PARITY    MACRO   round, sa, sb, sc, sd, se, wa, wb, wc, x1, x2, K
        ;
        ; See ROUND_CH for most parameters
        ; K is the round constant to use.
        ;
        ; The order of xorring the registers b, c, and d is driven by the data dependency graph.
        ; We start with d (the oldest) and then do b to unblock the subsequent rotate
        ;
        MSG_EXP         round, se, wa, wb, wc   ; re = e + Wt

        mov     sa,x1                           ; store a value in right register
        rol     x1,5                            ; x1 = ROL(a,5)
        add     se,x1                           ; re = e + Wt + ROL(a,5)
        
        mov     x2,sd                           ; x1 = d
        xor     x2,sb                           ; x1 = (d ^ b)
        xor     x2,sc                           ; x1 = (d ^ b ^ c) = Parity(b,c,d)
        ror     sb,2                            ; rb = ROL( b, 30 )
        lea     x1,[se+x2+K]                    ; re = e + ROL(a,5) + Parity(b,c,d) + Wt + Kt

                ENDM

ROUND_MAJ       MACRO   round, sa, sb, sc, sd, se, wa, wb, wc, x1, x2
        ;
        ; See above for parameter explanation
        ;
        MSG_EXP         round, se, wa, wb, wc   ; re = e + Wt
        
        mov     sa,x1                           ; store a value in right register
        rol     x1,5                            ; x1 = ROL(a,5)
        add     se,x1                           ; re = e + ROL(a,5)
        mov     x1,sd                           ; x1 = d
        or      x1,sc                           ; x1 = (d | c)
        and     x1,sb                           ; x1 = ((d | c) & b)

        mov     x2,sc                           ; x2 = c
        and     x2,sd                           ; x2 = (c & d)
        or      x1,x2                           ; x1 = ((d | c) & b) | (d & c) = MAJ(b,c,d)
        
        ror     sb,2                            ; rb = ROL( b, 30 )
        
        lea     x1,[se+x1+K40_59]               ; re = e + ROL(a,5) + Wt + Maj(b,c,d) + Kt
        ENDM


        ;
        ; With these macros we can now produce the actual code.
        ; Note the use of the % operator which evaluates the expression and yields the result as text.
        ; Together with the macros and the r<i> EQUs this provides us with automatic register renaming
        ; for each round.
        ;
        ; The first 16 rounds are more complicated as we need to use the right registers to load the msg in
        ; so we do those by hand
        ;
        ; W[t- 1] is in register (round   % 6)
        ; W[t- 2] is in register (round+5 % 6)
        ; W[t- 3] is in register (round+4 % 6) (is loaded with W[t-13] in each round)
        ; W[t-14] is in register (round+3 % 6)
        ; W[t-15] is in register (round+2 % 6)
        ; W[t-16] is in register (round+1 % 6)
        ;
        ROUND_CH_0_15    0, s0, s4, s3, s2, s1, w5, x1, x2      ;W[t-16] for t=16 is in w5
        ROUND_CH_0_15    1, s1, s0, s4, s3, s2, w0, x1, x2      ;W[t-15] for t=16 is in w0
        ROUND_CH_0_15    2, s2, s1, s0, s4, s3, w1, x1, x2      ;W[t-14] for t=16 is in w1
        ROUND_CH_0_15    3, s3, s2, s1, s0, s4, w3, x1, x2      ;
        ROUND_CH_0_15    4, s4, s3, s2, s1, s0, w4, x1, x2      ;
        ROUND_CH_0_15    5, s0, s4, s3, s2, s1, w3, x1, x2      ;
        ROUND_CH_0_15    6, s1, s0, s4, s3, s2, w4, x1, x2      ;
        ROUND_CH_0_15    7, s2, s1, s0, s4, s3, w3, x1, x2      ;
        ROUND_CH_0_15    8, s3, s2, s1, s0, s4, w4, x1, x2      ;
        ROUND_CH_0_15    9, s4, s3, s2, s1, s0, w3, x1, x2      ;
        ROUND_CH_0_15   10, s0, s4, s3, s2, s1, w4, x1, x2      ;
        ROUND_CH_0_15   11, s1, s0, s4, s3, s2, w3, x1, x2      ;
        ROUND_CH_0_15   12, s2, s1, s0, s4, s3, w4, x1, x2      ;
        ROUND_CH_0_15   13, s3, s2, s1, s0, s4, w2, x1, x2      ;W[t-3] for t=16 is in w2
        ROUND_CH_0_15   14, s4, s3, s2, s1, s0, w3, x1, x2      ;W[t-2] for t=16 is in w3
        ROUND_CH_0_15   15, s0, s4, s3, s2, s1, w4, x1, x2      ;W[t-1] for t=16 is in w4

        
        FOR     t, <16, 17, 18, 19>
          ROUND_CH      t, s%(t MOD 5), s%((t+4) MOD 5), s%((t+3) MOD 5), s%((t+2) MOD 5), s%((t+1) MOD 5), w%((t+1) MOD 6), w%((t+3) MOD 6), w%((t+4) MOD 6), x1, x2
        ENDM
        
        FOR     t, <20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39>
          ROUND_PARITY  t, s%(t MOD 5), s%((t+4) MOD 5), s%((t+3) MOD 5), s%((t+2) MOD 5), s%((t+1) MOD 5), w%((t+1) MOD 6), w%((t+3) MOD 6), w%((t+4) MOD 6), x1, x2, K20_39
        ENDM

        FOR     t, <40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59>
          ROUND_MAJ     t, s%(t MOD 5), s%((t+4) MOD 5), s%((t+3) MOD 5), s%((t+2) MOD 5), s%((t+1) MOD 5), w%((t+1) MOD 6), w%((t+3) MOD 6), w%((t+4) MOD 6), x1, x2
        ENDM

        FOR     t, <60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79>
          ROUND_PARITY  t, s%(t MOD 5), s%((t+4) MOD 5), s%((t+3) MOD 5), s%((t+2) MOD 5), s%((t+1) MOD 5), w%((t+1) MOD 6), w%((t+3) MOD 6), w%((t+4) MOD 6), x1, x2, K60_79
        ENDM
        
        ;
        ; Now we update the state, & the dataPtr
        ;
        add     x1,[Hptr   ]
        add     s4,[Hptr+ 4]
        add     dataPtr,64
        add     s3,[Hptr+ 8]
        add     s2,[Hptr+12]
        add     s1,[Hptr+16]
        
        mov     [Hptr   ], x1
        mov     [Hptr+ 4], s4
        cmp     dataPtr,[rsp+SymCryptSha1AppendBlocksFrame.EndAddress]  ; Loop terminating condition
        mov     [Hptr+ 8], s3
        mov     [Hptr+12], s2
        mov     [Hptr+16], s1

        jc      SymCryptSha1AppendBlocksLoop            ; Main loop
        
        ;
        ; We're done processing the blocks. The result is already in the state, so all we have to do
        ; is clean up.
        ;
        ; Wipe the W buffer
        ; The @@: label is an anonymous label. You can refer to the previous one using @B, which is easy to read.
        ;
        mov     rcx,64
        xor     rax,rax
@@:     sub     ecx,16
        mov     [rsp+rcx  ],rax
        mov     [rsp+rcx+8],rax
        jnz     @B
        
SymCryptSha1AppendBlocksDone:   


        add     rsp, SymCryptSha1AppendBlocksFrame.SaveR12

        BEGIN_EPILOGUE
        pop     r12
        pop     r13
        pop     r14
        pop     r15
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx

        ret
        
        NESTED_END      SymCryptSha1AppendBlocksAsm, _TEXT

END

