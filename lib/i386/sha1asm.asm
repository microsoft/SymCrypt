;
; Sha1Asm.Asm
;
; Copyright (c) Microsoft Corporation.  All rights reserved.
;
;

;
;   This module implements the bulk processing of the FIPS 180-1 SHA message digest algorithm.
;   for the x86 processor architecture.
;
;   This implementation is derived from an older one by Scott Field and
;   Dan Shumow. 
;     
;   This implementation is optimized for Intel Core and contemporary AMD CPUs.
;   Optimizations for pre-P3 Intel CPUs has been removed.
;


        TITLE   sha1asm.asm
        .486

_TEXT   SEGMENT PARA PUBLIC USE32 'CODE'
        ASSUME  CS:_TEXT, DS:FLAT, SS:FLAT

        PUBLIC  @SymCryptSha1AppendBlocksAsm@12

        ;
        ; The four round constants used by SHA-1
        ;
        
K0_19   EQU     05a827999H
K20_39  EQU     06ed9eba1H
K40_59  EQU     08f1bbcdcH
K60_79  EQU     0ca62c1d6H

        align   16

;VOID
;SYMCRYPT_CALL
;SymCryptSha1AppendBlocks( _Inout_updates_( 5 )        PUINT32    H,
;                            _In_reads_bytes_( cbData )    PCBYTE    pbData,
;                                                    SIZE_T    cbData )
;
@SymCryptSha1AppendBlocksAsm@12    PROC

;
; To keep stack manipulatins simple we define a structure and use that for all accesses.
;
SymCryptSha1AppendBlocksFrame struct  4, NONUNIQUE

Wbuf            dd      16 dup (?)
Hptr            dd      ?
pbData          dd      ?
BlockCount      dd      ?
SaveEdi         dd      ?
SaveEsi         dd      ?
SaveEbp         dd      ?
SaveEbx         dd      ?
ReturnAddress   dd      ?
CbData          dd      ?

SymCryptSha1AppendBlocksFrame ends

        ;
        ; We use the W buffer extensively; this is a shorthand for the base address
        ;
W       equ     esp+SymCryptSha1AppendBlocksFrame.Wbuf

        ;
        ; The .FPO provides debugging information for stack frames that do not use
        ; ebp as a base pointer.
        ; This stuff not well documented, 
        ; but here is the information I've gathered about the arguments to .FPO
        ; 
        ; In order:
        ; cdwLocals: Size of local variables, in DWords
        ; cdwParams: Size of parameters, in DWords. Given that this is all about
        ;            stack stuff, I'm assuming this is only about parameters passed
        ;            on the stack.
        ; cbProlog : Number of bytes in the prolog code. We sometimes interleaved the
        ;            prolog code with work for better performance. Most uses of
        ;            .FPO seem to set this value to 0.
        ;            The debugger seems to work if the prolog defined by this value
        ;            contains all the stack adjustments.
        ; cbRegs   : # registers saved in the prolog. 4 in our case
        ; fUseBP   : 0 if EBP is not used as base pointer, 1 if EBP is used as base pointer
        ; cbFrame  : Type of frame.
        ;            0 = FPO frame (no frame pointer)
        ;            1 = Trap frame (result of a CPU trap event)
        ;            2 = TSS frame
        ;
        ; Having looked at various occurrences of .FPO in the Windows code it
        ; seems to be used fairly sloppy, with lots of arguments left 0 even when
        ; they probably shouldn't be according to the spec.
        ;
        .FPO(23,1,3,4,0,0)      ; 3 byte prolog (covers esp ajustment only)
        
        ; At this point:
        ;       ecx = H
        ;       edx = pbData
        ;       [esp+4] = cbData

        ;
        ; Set up our stack frame and save non-volatile registers
        ;
        sub     esp,SymCryptSha1AppendBlocksFrame.ReturnAddress
        mov     [esp+SymCryptSha1AppendBlocksFrame.SaveEbp],ebp
        mov     [esp+SymCryptSha1AppendBlocksFrame.SaveEdi],edi
        mov     [esp+SymCryptSha1AppendBlocksFrame.SaveEsi],esi
        mov     [esp+SymCryptSha1AppendBlocksFrame.SaveEbx],ebx

        mov     [esp+SymCryptSha1AppendBlocksFrame.Hptr], ecx

        ;
        ; To allow macro re-ordering of our registers we use symbolic names
        ; for the registers.
        ; r0-r4 are the 5 state registers. x1 and x2 are extra scratch registers.
        ; Note: some prolog code puts the right value in the right register and
        ; has to be updated if this mapping is changed.
        ;
r0      EQU     eax
r1      EQU     ebx
r2      EQU     ecx
r3      EQU     edx
r4      EQU     esi
x1      EQU     ebp
x2      EQU     edi

        ;
        ; compute how many blocks we will process.
        ; This code ensures that we never exceed the data buffer we were given,
        ; although we silently round the cbData parameter down to the next
        ; multiple of 64.
        ; Do nothing if no blocks need to be processed.
        ;
        mov     eax,[esp+SymCryptSha1AppendBlocksFrame.CbData]
        shr     eax,6
        jz      SymCryptSha1AppendBlocksDone
        mov     [esp+SymCryptSha1AppendBlocksFrame.BlockCount], eax
        
        ;
        ; The data pointer goes into x1 = ebp at the start of our loop
        ;
        mov     ebp,edx

        ;
        ; Load the H state from [ecx], making sure we load the r2=ecx register
        ; last.
        ;
        mov     r0,[ecx   ]
        mov     r4,[ecx+ 4]
        mov     r3,[ecx+ 8]
        mov     r1,[ecx+16]
        mov     r2,[ecx+12]
        
        
SymCryptSha1AppendBlocksLoop:
        ;
        ; This is the main loop. We process 64 bytes in each iteration.
        ; invariant: ebp = pbData
        ;
        
        ;
        ; Most of the code in the loop is generated through macros using parameters to
        ; rename the registers.
        ; The macros get the register number passed as parameter. They use
        ; "r&<param>" to paste the number and the 'r' together and get the register
        ; name we defined above.
        ;
        
ROUND_CH_0_15   MACRO   round,ra,rb,rc,rd,re,x1,x2
        ;
        ; Code for round 0-15.
        ; This code loads data from the data buffer & BSWAPs the data to get it into the
        ; right form.
        ;
        ; Parameters:
        ; round round number
        ; ra    register number that contains the a value
        ; rb    register number that contains the b value
        ; rc    register number that contains the c value
        ; rd    register number that contains the d value
        ; re    register number that contains the e value
        ; x1    pointer to the input data
        ; x2    scratch register.
        ; 
        ; We use the formula CH(b,c,d) = ((d ^ c) & b) ^ c which uses only one temp register.
        ; We start with the d value as that is the oldest value and available the first
        ;
        ; See FIPS 180-2 for our symbolic notation.
        ;
        mov     x2,[x1+4*round]         ; Fetch word from message
        bswap   x2                      ; x2 = Wt
        add     r&re,x2                 ; re = e + Wt
        mov     [W + 4*round],x2        ; Store in W buffer for future use
        
        mov     x2,r&ra                 ; x2 = a
        rol     x2,5                    ; x2 = ROL(a,5)
        add     r&re,x2                 ; re = e + Wt + ROL(a,5)
        
        mov     x2,r&rd                 ; x2 = d
        xor     x2,r&rc                 ; x2 = (d ^ c)
        and     x2,r&rb                 ; x2 = ((d ^ c) & b)
        ror     r&rb,2                  ; rb = ROL( b, 30 )
        xor     x2,r&rd                 ; x2 = ((d ^ c) & b) ^ d = CH(b,c,d)
        lea     r&re,[r&re+x2+K0_19]    ; re = e + Wt + ROL(a,5) + Ch(b,c,d) + Kt
                
        ENDM

ROUND_CH        MACRO   round, ra, rb, rc, rd, re, x1, x2
        ;
        ; See ROUND_CH_0_15 for most parameters.
        ; x1 and x2 are both scratch registers
        ;
        mov     x2,[W+4*((round-16) MOD 16)]    ; x2 = W[t-16]
        mov     x1,r&ra                         ; x1 = a
        rol     x1,5                            ; x1 = ROL(a,5)
        xor     x2,[W+4*((round-14) MOD 16)]    ; x2 = W[t-16] ^ W[t-14]
        add     r&re,x1                         ; re = e + ROL(a,5)
        mov     x1,r&rd                         ; x1 = d
        xor     x2,[W+4*((round- 8) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8]
        xor     x1,r&rc                         ; x1 = (d ^ c)
        and     x1,r&rb                         ; x1 = ((d ^ c) & b)
        xor     x2,[W+4*((round- 3) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8] ^ W[t-3] 
        xor     x1,r&rd                         ; x1 = ((d ^ c) & b) ^ d = CH(b,c,d)
        rol     x2,1                            ; x2 = Wt
        mov     [W+4*((round-16) MOD 16)],x2    ; 
        add     r&re,x2                         ; re = e + ROL(a,5) + Wt
        ror     r&rb,2                          ; rb = ROL( b, 30 )
        lea     r&re,[r&re+x1+K0_19]            ; re = e + Wt + ROL(a,5) + Ch(b,c,d) + Kt
        ENDM

ROUND_PARITY    MACRO   round, ra, rb, rc, rd, re, x1, x2, K, store
        ;
        ; See ROUND_CH for most parameters
        ; K is the round constant to use.
        ; store is 1 if the Wt value should be stored, 0 otherwise
        ;  (used to avoid stores in the last few rounds)
        ;
        ; The order of xorring the registers b, c, and d is driven by the data dependency graph.
        ; We start with d (the oldest) and then do b to unblock the subsequent rotate
        ;
        mov     x2,[W+4*((round-16) MOD 16)]    ; x2 = W[t-16]
        mov     x1,r&ra                         ; x1 = a
        rol     x1,5                            ; x1 = ROL(a,5)
        xor     x2,[W+4*((round-14) MOD 16)]    ; x2 = W[t-16] ^ W[t-14]
        add     r&re,x1                         ; re = e + ROL(a,5)
        mov     x1,r&rd                         ; x1 = d
        xor     x2,[W+4*((round- 8) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8]
        xor     x1,r&rb                         ; x1 = (d ^ b)
        xor     x1,r&rc                         ; x1 = (d ^ b ^ c) = Parity(b,c,d)
        xor     x2,[W+4*((round- 3) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8] ^ W[t-3]
        rol     x2,1                            ; x2 = Wt
        add     r&re,x1                         ; re = e + ROL(a,5) + Parity(b,c,d)
        IF      store
                mov     [W+4*((round-16) MOD 16)],x2    ; 
        ENDIF
        ror     r&rb,2                          ; rb = ROL( b, 30 )
        lea     r&re,[r&re+x2+K]                ; re = e + ROL(a,5) + Parity(b,c,d) + Wt + Kt

                ENDM

ROUND_MAJ       MACRO   round, ra, rb, rc, rd, re, x1, x2
        ;
        ; See above for parameter explanation
        ;
        mov     x2,[W+4*((round-16) MOD 16)]    ; x2 = W[t-16]
        mov     x1,r&ra                         ; x1 = a
        rol     x1,5                            ; x1 = ROL(a,5)
        xor     x2,[W+4*((round-14) MOD 16)]    ; x2 = W[t-16] ^ W[t-14]
        add     r&re,x1                         ; re = e + ROL(a,5)
        mov     x1,r&rd                         ; x1 = d
        xor     x2,[W+4*((round- 8) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8]
        or      x1,r&rc                         ; x1 = (d | c)
        and     x1,r&rb                         ; x1 = ((d | c) & b)
        xor     x2,[W+4*((round- 3) MOD 16)]    ; x2 = W[t-16] ^ W[t-14] ^ W[t-8] ^ W[t-3] = Wt
        rol     x2,1                            ; x2 = Wt
        add     r&re,x2                         ; re = e + ROL(a,5) + Wt
        mov     [W+4*((round-16) MOD 16)],x2    ; 

        mov     x2,r&rc                         ; x2 = c
        and     x2,r&rd                         ; x2 = (c & d)
        or      x1,x2                           ; x1 = ((d | c) & b) | (d & c) = MAJ(b,c,d)
        
        ror     r&rb,2                          ; rb = ROL( b, 30 )
        
        lea     r&re,[r&re+x1+K40_59]           ; re = e + ROL(a,5) + Wt + Maj(b,c,d) + Kt
        ENDM

        ;
        ; With these macros we can now produce the actual code.
        ; Note the use of the % operator which evaluates the expression and yields the result as text.
        ; Together with the macros and the r<i> EQUs this provides us with automatic register renaming
        ; for each round.
        ;
        FOR     t, <0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>
                ROUND_CH_0_15   t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2
        ENDM
        
        ;
        ; For the rest of the computation we need the extra register, so we update the data pointer and store it.
        ;
        add     ebp,64
        mov     [esp+SymCryptSha1AppendBlocksFrame.pbData], ebp
        
        FOR     t, <16, 17, 18, 19>
                ROUND_CH        t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2
        ENDM
        
        FOR     t, <20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39>
                ROUND_PARITY    t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2, K20_39, 1
        ENDM

        FOR     t, <40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59>
                ROUND_MAJ       t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2
        ENDM

        FOR     t, <60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76>
                ROUND_PARITY    t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2, K60_79, 1
        ENDM
        
        ;
        ; The last three rounds do not need to store their Wt in the W buffer as that value will never get used.
        ;
        FOR     t, <77, 78, 79>
                ROUND_PARITY    t, %(t MOD 5), %((t + 4) MOD 5), %((t + 3) MOD 5), %((t + 2) MOD 5), %((t + 1) MOD 5), x1, x2, K60_79, 0
        ENDM
        
        ;
        ; Now we update the state
        ;
        mov     x2,[esp+SymCryptSha1AppendBlocksFrame.Hptr]
        add     r0,[x2   ]
        add     r4,[x2+ 4]
        add     r3,[x2+ 8]
        add     r2,[x2+12]
        add     r1,[x2+16]
        
        mov     [x2   ], r0
        mov     [x2+ 4], r4
        mov     [x2+ 8], r3
        mov     [x2+12], r2
        mov     [x2+16], r1

        ;
        ; See if we have more data to process, and load the data pointer register again
        ;
        dec     [esp+SymCryptSha1AppendBlocksFrame.BlockCount]
        mov     ebp, [esp+SymCryptSha1AppendBlocksFrame.pbData]
        jnz     SymCryptSha1AppendBlocksLoop
        
        ;
        ; We're done processing the blocks. The result is already in the state, so all we have to do
        ; is clean up.
        ;
        ; Wipe the W buffer
        ; The @@: label is an anonymous label. You can refer to the previous one using @B, which is easy to read.
        ;
        mov     ecx,8
        xor     eax,eax
@@:     dec     ecx
        mov     [esp+8*ecx],eax
        mov     [esp+8*ecx+4],eax
        jnz     @B
        
SymCryptSha1AppendBlocksDone:   
        ;
        ; Restore non-volatile regisers & stackpointer
        ;
        mov     ebp,[esp+SymCryptSha1AppendBlocksFrame.SaveEbp]
        mov     edi,[esp+SymCryptSha1AppendBlocksFrame.SaveEdi]
        mov     esi,[esp+SymCryptSha1AppendBlocksFrame.SaveEsi]
        mov     ebx,[esp+SymCryptSha1AppendBlocksFrame.SaveEbx]
        add     esp,SymCryptSha1AppendBlocksFrame.ReturnAddress
        
        ret     4
        
@SymCryptSha1AppendBlocksAsm@12    ENDP
_TEXT           ENDS

END

