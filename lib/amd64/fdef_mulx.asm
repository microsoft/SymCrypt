;
;  fdef_asm.asm   Assembler code for large integer arithmetic in the default data format
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.

include ksamd64.inc

include ..\inc\symcrypt_version.inc
include symcrypt_magic.inc



include C_asm_shared.inc

; A digit consists of 8 words of 64 bits each
    
;The MULX/ADCX/ADOX instructions greatly speed up multi-precision arithmetic.
;A set of MULX + ADCX + ADOX can implement a single 64x64->128 plus two 64-bit additions in a single clock cycle (throughput)
;However, that speed puts pressure on other parts of the system.
;
;The code size for these three instructions is 18 cycles, whereas the pre-decoder on Broadwell reportedly can only 
; load 16 bytes per cycle.
;That means the pre-decoder need 9 cycles per 8 multiplications, plus one for the per-row-of-8 overhead, meaning we need 10
;cycles for 8 multiplications. Except that I have measured the 18 bytes as taking 1 cycle each, so the decoder must have a
; higher bandwidth.
;
;If we keep the code size small enough to fit in the uop cache, then the pre-decoder bottleneck goes away which should save us
;8 cycles per 512x512 multiplication. 
;
;Code size for 512x512 is 64 multiplications at 18 bytes each = 36 cache lines of 32 bytes which need 72 uop cache lines that
;each contain up to 6 uops. (Each 32-byte code cache line contains 7 or so uops, so the 6 uops per uop cache line isn't enough.)
;The total uop cache is 256 lines, so we could fit 3+ copies of the 512x512 code.
;
;But we need the following:
;- A core 512x512 multiplication in a loop
;- Either zero the 8 carry registers up front (3 cycles), or have a separate 512x512 multiplication that sets up the carry registers.
;    This latter is less code, alleviating the decoder bottleneck a bit.
;- A 512x512 multiplication that computes the Montgovery multipliers in-line
;- Code for squaring using MULX/ADX.
;
;The 512x512 unrolling is really necessary to get the performance; using 256x256 adds more overhead that we could gain back from the 
;uop cache, and it uses more computations and will in general be slower.
;
;The full modexp loop also contains things like masked copies, ScsTable, etc. 
;All in all, I don't see how we can keep all this inside the uop cache. 
;Therefore, we will ignore the uop cache and optimize the code without it. 
;
;Basic bottlenecks:
;- Pre-decoder at 16 bytes/cycle (turns out to be more...)
;- Decoder which can decode 1-1-1-1, 2-1-1, 3-1 (although some sources claim it doesn't) and 4 per cycle
;- One source claims that mulx takes 2 uops, and mulx with memory argument 3 uops which would limit the decoder throughput to
;   require 2 cycles per mulx(mem)/adox/adcx triplet. 
;
; We have verified experimentally that on Broadwell, a sequence of 1024 triples of (MULX w/ memory operand, adox, adcx) runs
; at 1 cycle per triple. As this code is too large for the uop cache, the pre-decoders and decoders are fast enough.
; Adding a fourth instruction to the tuple makes it run at 2 cycles/tuple. 
; This is consistent with:
; - Pre-decoder is able to process at least 18 bytes per cycle
; - Mulx is 1 uop, Mulx + memory read is 2 uops
; - Decoder can produce 4 uops per cycle.
;
;Basic multiplication operation:
;
;    We have one set of macros that do 8 words times 1 word, leaving 8 words carry in registers
;    8 of these 8x1 multiplications in sequence forms an 8x8, which is the inner loop body
;    (First iteration is slightly differently and done first outside the loop)
;    The inner loop iterates this to get an 8n * 8 multiplication
;    The outer loop iterates this to get an 8n * 8m multiplication
;
;    Our bottleneck seems to be the pre-decoder which can only run 16 bytes of code each clock cycle.
;    (The uop cache is too small to hold our square+multiply+montgomery reduction code.)
;    Thus we don't use zero-output and then multiply-and-add, but rather have separate copies
;    of the code for the first iteration to do multiply-without-add as that cuts down on the total amount of code
;    we need, and with that reduces the pre-decoder usage.
;

MULADD18        MACRO    R0, R1, R2, R3, R4, R5, R6, R7, pD, pA, pB, T0, T1
        ; R0:R[7:1]:D[0] = A[7:0] * B[0] + D[0] + R[7:0]
        ; Pre: Cy = Ov = 0
        ; Post: Cy = Ov = 0

        mov     rdx, [pB]
        adox    R0, [pD]

        mulx    T1, T0, [pA + 0 * 8]
        adcx    R0, T0
        adox    R1, T1

        mulx    T1, T0, [pA + 1 * 8]
        adcx    R1, T0
        adox    R2, T1

        mulx    T1, T0, [pA + 2 * 8]
        adcx    R2, T0
        adox    R3, T1

        mulx    T1, T0, [pA + 3 * 8]
        adcx    R3, T0
        adox    R4, T1

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R4, T0
        adox    R5, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R5, T0
        adox    R6, T1

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R6, T0
        adox    R7, T1

        mulx    T1, T0, [pA + 7 * 8]
        adcx    R7, T0
        mov     [pD], R0

        mov     R0, 0
        adcx    R0, R0
        adox    R0, T1

    ENDM        ; MULADD18


MULADD88        MACRO   R0, R1, R2, R3, R4, R5, R6, R7, pD, pA, pB, T0, T1
        ; pre & post: Cy = Ov = 0
        ; R[7-0]:D[7-0] = A[7:0] * B[7:0] + R[7:0] + D[7:0]
        ; rdx is volatile

        MULADD18    R0, R1, R2, R3, R4, R5, R6, R7, pD     , pA, pB     , T0, T1
        MULADD18    R1, R2, R3, R4, R5, R6, R7, R0, pD +  8, pA, pB +  8, T0, T1
        MULADD18    R2, R3, R4, R5, R6, R7, R0, R1, pD + 16, pA, pB + 16, T0, T1
        MULADD18    R3, R4, R5, R6, R7, R0, R1, R2, pD + 24, pA, pB + 24, T0, T1
        MULADD18    R4, R5, R6, R7, R0, R1, R2, R3, pD + 32, pA, pB + 32, T0, T1
        MULADD18    R5, R6, R7, R0, R1, R2, R3, R4, pD + 40, pA, pB + 40, T0, T1
        MULADD18    R6, R7, R0, R1, R2, R3, R4, R5, pD + 48, pA, pB + 48, T0, T1
        MULADD18    R7, R0, R1, R2, R3, R4, R5, R6, pD + 56, pA, pB + 56, T0, T1

    ENDM    ;MULADD88

HALF_SQUARE_NODIAG8      MACRO   R0, R1, R2, R3, R4, R5, R6, R7, pD, pA, T0, T1
        ; pre & post: Cy = Ov = 0
        ; R[7-0]:D[7-0] = D[7:0] + (A[0:7]^2 - \sum_{i=0}^7 (A[i] * 2^{64*i}) )/2 
        ; This is the component of the square that needs to be doubled, and then the diagonals added
        ; rdx is volatile

        ; Note that Dst[0] is not changed by this macro

        mov     rdx, [pA + 0 * 8]           ; rdx = A0
        mov     R1, [pD + 1 * 8]
        mov     R2, [pD + 2 * 8]
        mov     R3, [pD + 3 * 8]
        mov     R4, [pD + 4 * 8]
        mov     R5, [pD + 5 * 8]
        mov     R6, [pD + 6 * 8]
        mov     R7, [pD + 7 * 8]
        xor     R0, R0
        
        mulx    T1, T0, [pA + 1 * 8]
        adcx    R1, T0
        adox    R2, T1

        mulx    T1, T0, [pA + 2 * 8]
        adcx    R2, T0
        adox    R3, T1

        mulx    T1, T0, [pA + 3 * 8]
        adcx    R3, T0
        adox    R4, T1

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R4, T0
        adox    R5, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R5, T0
        adox    R6, T1

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R6, T0
        adox    R7, T1

        mulx    T1, T0, [pA + 7 * 8]
        adcx    R7, T0
        mov     [pD + 1 * 8], R1

        adcx    R0, R0
        adox    R0, T1
        mov     [pD + 2 * 8], R2
        mov     rdx, [pA + 1 * 8]       ; rdx = A1

        ;=======

        mulx    T1, T0, [pA + 2 * 8]
        adcx    R3, T0
        adox    R4, T1

        mulx    T1, T0, [pA + 3 * 8]
        adcx    R4, T0
        adox    R5, T1

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R5, T0
        adox    R6, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R6, T0
        adox    R7, T1

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R7, T0
        adox    R0, T1

        mov     rdx, [pA + 7 * 8]       ; rdx = A7
        mov     R1, 0
        mov     R2, 0
        mov     [pD + 3 * 8], R3

        mulx    T1, T0, [pA + 1 * 8]
        adcx    R0, T0
        adox    R1, T1                  ; doesn't produce Ov as T1 <= 0xff..fe and R1=0

        mulx    T1, T0, [pA + 2 * 8]
        adcx    R1, T0                  
        mov     [pD + 4 * 8], R4

        adcx    R2, T1
        mov     rdx, [pA + 2 * 8]       ;rdx = A2

        ;======

        mulx    T1, T0, [pA + 3 * 8]
        adcx    R5, T0
        adox    R6, T1

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R6, T0
        adox    R7, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R7, T0
        adox    R0, T1

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R0, T0
        adox    R1, T1

        mov     rdx, [pA + 4 * 8]       ; rdx = A4
        mov     R3, 0
        mov     R4, 0

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R1, T0
        adox    R2, T1

        mulx    T1,T0, [pA + 6 * 8]
        adcx    R2, T0
        adox    R3, T1                  ; doesn't produce Ov as T1 <= 0xff..fe and R3=0

        mov     rdx, [pA + 5 * 8]       ;rdx = A5
        mov     [pD + 5 * 8], R5

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R3, T0
        adcx    R4, T1

        mov     rdx, [pA + 3 * 8]       ;rdx = A3
        mov     [pD + 6 * 8], R6

        ;======

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R7, T0
        adox    R0, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R0, T0
        adox    R1, T1

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R1, T0
        adox    R2, T1

        mulx    T1, T0, [pA + 7 * 8]
        adcx    R2, T0
        adox    R3, T1

        mov     rdx, [pA + 7 * 8]       ;rdx = A7
        mov     R5, 0
        mov     R6, 0
        mov     [pD + 7 * 8], R7

        mulx    T1, T0, [pA + 4 * 8]
        adcx    R3, T0
        adox    R4, T1

        mulx    T1, T0, [pA + 5 * 8]
        adcx    R4, T0
        adox    R5, T1                  ; doesn't produce Ov as T1 <= 0xff..fe and R5=0

        mulx    T1, T0, [pA + 6 * 8]
        adcx    R5, T0
        adcx    R6, T1

        xor     R7, R7

    ENDM
    
MONTGOMERY18    MACRO   R0, R1, R2, R3, R4, R5, R6, R7, modInv, pMod, pMont, T0, T1
    ; Mont[0] = (modinv * R0 mod 2^64) 
    ; R0:R[7:1]:<phantom> = Mont[0] * Mod[7:0] + R[7:0]
    ; Pre: -
    ; Post: -
        mov     rdx, R0
        imul    rdx, modInv

        mov     [pMont], rdx

        xor     T0, T0      ; Reset Cy = Ov = 0

        mulx    T1, T0, [pMod + 0 * 8]
        adcx    R0, T0                          ; R0 = 0 here, but it produces a carry unless R0=0 at the start
        adox    R1, T1

        mulx    T1, T0, [pMod + 1 * 8]
        adcx    R1, T0
        adox    R2, T1

        mulx    T1, T0, [pMod + 2 * 8]
        adcx    R2, T0
        adox    R3, T1

        mulx    T1, T0, [pMod + 3 * 8]
        adcx    R3, T0
        adox    R4, T1

        mulx    T1, T0, [pMod + 4 * 8]
        adcx    R4, T0
        adox    R5, T1

        mulx    T1, T0, [pMod + 5 * 8]
        adcx    R5, T0
        adox    R6, T1

        mulx    T1, T0, [pMod + 6 * 8]
        adcx    R6, T0
        adox    R7, T1

        mulx    T1, T0, [pMod + 7 * 8]
        adcx    R7, T0

        ; R0 = 0 here due to our modinv invariant...

        adcx    R0, R0
        adox    R0, T1

    ENDM

ZEROREG     MACRO   R
        xor     R,R
    ENDM

ZEROREG_8   MACRO   R0, R1, R2, R3, R4, R5, R6, R7
        ZEROREG R0
        ZEROREG R1
        ZEROREG R2
        ZEROREG R3
        ZEROREG R4
        ZEROREG R5
        ZEROREG R6
        ZEROREG R7
    ENDM

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul(
;    _In_reads_(nWords1)             PCUINT32    pSrc1,
;                                    UINT32      nDigits1,
;    _In_reads_(nWords2)             PCUINT32    pSrc2,
;                                    UINT32      nDigits2,
;    _Out_writes_(nWords1 + nWords2) PUINT32     pDst )

SymCryptFdefRawMulMulx_Frame struct
        SavedRbp        dq  ?
        SavedRbx        dq  ?
        SavedRsi        dq  ?
        SavedRdi        dq  ?
        SavedR15        dq  ?
        SavedR14        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        returnaddress   dq  ?
        pSrc1Home       dq  ?
        nDigits1Home    dq  ?
        pSrc2Home       dq  ?
        nDigits2Home    dq  ?
        pDst            dq  ?

SymCryptFdefRawMulMulx_Frame        ends

        NESTED_ENTRY    SymCryptFdefRawMulMulx, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp
        
        END_PROLOGUE

        mov             [rsp + SymCryptFdefRawMulMulx_Frame.pSrc1Home], rcx
        mov             [rsp + SymCryptFdefRawMulMulx_Frame.nDigits1Home], rdx
        mov             [rsp + SymCryptFdefRawMulMulx_Frame.pSrc2Home], r8
        mov             [rsp + SymCryptFdefRawMulMulx_Frame.nDigits2Home], r9

        ; rcx = pSrc1
        ; rdx = nDigits1
        ; r8 = pSrc2
        ; r9 = nDigits2
        ; pDst on stack

        ; pSrc1/Digits1 = outer loop
        ; pSrc2/Digits2 = inner loop

        ; First we wipe nDigits2 of the result (size of in)
        mov         rbx,[rsp + SymCryptFdefRawMulMulx_Frame.pDst]
        mov         rdi, rbx

        ; Wipe destination for nDigit2 blocks
        xorps       xmm0,xmm0               ; Zero register for 16-byte wipes
        mov         rax, r9

SymCryptFdefRawMulMulxWipeLoop:
        movaps      [rbx],xmm0
        movaps      [rbx+16],xmm0           ; Wipe 32 bytes
        movaps      [rbx+32],xmm0           ; Wipe 32 bytes
        movaps      [rbx+48],xmm0           ; Wipe 32 bytes
        add         rbx, 64
        sub         rax, 1
        jnz         SymCryptFdefRawMulMulxWipeLoop


SymCryptFdefRawMulxOuterLoop:

        ZEROREG_8   rsi, rbp, r10, r11, r12, r13, r14, r15      ; Leaves Cy = Ov = 0

SymCryptFdefRawMulMulxInnerLoop:

        ; Register allocation in loops:
        ; rsi, rbp, r10, r11, r12, r13, r14, r15    8-word carry 
        ; rax, rbx                                  temps for multiplication
        ; rcx, r8                                   pSrc1, pSrc2 running pointers
        ; r9                                        inner loop counter
        ; rdx                                       fixed input reg for multiplication
        ; rdi                                       Destination running pointer inner loop
        ; rsp[pDst]                                 Destination running pointer outer loop
        ; rsp[nDigits1]                             outer loop counter

        MULADD88  rsi, rbp, r10, r11, r12, r13, r14, r15, rdi, rcx, r8, rax, rbx

        add     r8, 64              ; Src2 ptr
        add     rdi, 64

        sub     r9d, 1                              ; sets Cy = Ov = 0 because r9 < 2^32 / 64
        jnz     SymCryptFdefRawMulMulxInnerLoop

        ; Write the 8-word carry-out to the destination
        mov     [rdi + 0*8], rsi
        mov     [rdi + 1*8], rbp
        mov     [rdi + 2*8], r10
        mov     [rdi + 3*8], r11
        mov     [rdi + 4*8], r12
        mov     [rdi + 5*8], r13
        mov     [rdi + 6*8], r14
        mov     [rdi + 7*8], r15

        ; set up for next iteration
        ; reset rdi & increment
        mov     rdi, [rsp + SymCryptFdefRawMulMulx_Frame.pDst]
        add     rdi, 64
        mov     [rsp + SymCryptFdefRawMulMulx_Frame.pDst], rdi

        ; reload pSrc2/nDigits2
        mov     r9, [rsp + SymCryptFdefRawMulMulx_Frame.nDigits2Home]
        mov     r8, [rsp + SymCryptFdefRawMulMulx_Frame.pSrc2Home]

        ; update PSrc1
        add     rcx, 64

        ; nDigits1 loop counter
        mov     rax, [rsp + SymCryptFdefRawMulMulx_Frame.nDigits1Home]
        sub     rax, 1                              ; leaves Cy = Ov = 0 because nDigits1 < 2^32 / 64
        mov     [rsp + SymCryptFdefRawMulMulx_Frame.nDigits1Home], rax

        jnz     SymCryptFdefRawMulxOuterLoop

        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret
               
    NESTED_END      SymCryptFdefRawMulMulx, _TEXT

; VOID
; SYMCRYPT_CALL
; SymCryptFdefRawSquare(
;   _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
;                                                       UINT32      nDigits,
;   _Out_writes_(2*nWords)                              PUINT32     pDst )

SymCryptFdefRawSquareMulx_Frame struct

        SavedRbp        dq  ?
        SavedRbx        dq  ?
        SavedRsi        dq  ?
        SavedRdi        dq  ?
        SavedR15        dq  ?
        SavedR14        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        returnaddress   dq  ?
        pSrcHome        dq  ?

        ; Two 32-bit local variables, in the space of one normal 64-bit stack slot
        nDigitsHome     dd  ?       ; 32 bits, original argument to function
        nextNDigits     dd  ?       ; 32 bits; number of digits to do in the next sequence of inner loops.

        pDstHome        dq  ?
        pDstPtr         dq  ?       ; pDst running pointer outer loop (This is the 4th argument stack slot which is always available.)

SymCryptFdefRawSquareMulx_Frame        ends

        NESTED_ENTRY    SymCryptFdefRawSquareMulx, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp

        END_PROLOGUE

        ; rcx = pSrc
        ; rdx = nDigits
        ; r8 = pDst

        ; Save parameters for phase 2
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.pSrcHome], rcx
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.nDigitsHome], edx
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.pDstHome], r8

        ; Initialize our local variables
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.nextNDigits], edx
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.pDstPtr], r8

        mov         r9d, edx                ; rdx is used in the multiplications...

        ; Wipe destination for nDigits blocks

        xor         rax, rax
        mov         rbx, r8
        ; we'll use the edx digit counter destructively...

SymCryptFdefRawSquareMulxWipeLoop:
        ; we use 8-byte writes as we will be reading this very soon in 8-byte chunks, and this way the store-load 
        ; forwarding works 
        mov         [rbx     ], rax
        mov         [rbx +  8], rax
        mov         [rbx + 16], rax
        mov         [rbx + 24], rax
        mov         [rbx + 32], rax
        mov         [rbx + 40], rax
        mov         [rbx + 48], rax
        mov         [rbx + 56], rax
        add         rbx, 64
        sub         edx, 1
        jnz         SymCryptFdefRawSquareMulxWipeLoop

        ; Cy = Ov = 0 here because the last 'sub edx,1' yielded 0

SymCryptFdefRawSquareMulxOuterLoop:

        HALF_SQUARE_NODIAG8 rsi, rbp, r10, r11, r12, r13, r14, r15,  r8, rcx, rax, rbx

        sub     r9d, 1
        jz      SymCryptFdefRawSquareMulxPhase2     ; end of phase 1

        lea     rdi, [rcx + 64]
        lea     r8, [r8 + 64]

SymCryptFdefRawSquareMulxInnerLoop:
        ; rsi, rbp, r10, r11, r12, r13, r14, r15    8-word carry 
        ; rax, rbx                                  temps for multiplication
        ; rcx                                       pSrc running pointer outer loop
        ; r8                                        pDst running pointer inner loop
        ; r9d                                       inner loop nDigit counter
        ; rdx                                       fixed input reg for multiplication
        ; rdi                                       pSrc running pointer inner loop

        ; rsp[pSrc]                                 pSrc (used for final pass)
        ; rsp[nDigits]                              nDigits (used for final pass)
        ; rsp[pDst]                                 pDst (used for final pass)
        ; rsp[nextNDigits]                          # inner loop blocks in next outer loop iteration
        ; rsp[pDstPtr]                              pDst running pointer outer loop
            
        MULADD88    rsi, rbp, r10, r11, r12, r13, r14, r15, r8, rcx, rdi, rax, rbx

        add     r8, 64                 
        add     rdi, 64

        sub     r9d, 1                  ; Sets Cy = Ov = 0 because r9d < 2^32 / bits_per_digit
        jnz     SymCryptFdefRawSquareMulxInnerLoop

        ; Write the 8-word carry-out to the destination
        mov     [r8 + 0*8], rsi
        mov     [r8 + 1*8], rbp
        mov     [r8 + 2*8], r10
        mov     [r8 + 3*8], r11
        mov     [r8 + 4*8], r12
        mov     [r8 + 5*8], r13
        mov     [r8 + 6*8], r14
        mov     [r8 + 7*8], r15

        add     rcx, 64

        mov     r8, [rsp + SymCryptFdefRawSquareMulx_Frame.pDstPtr]
        add     r8, 128                             ; Shift output ptr by 2 digits
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.pDstPtr], r8

        mov     r9d, [rsp + SymCryptFdefRawSquareMulx_Frame.nextNDigits]
        sub     r9d, 1
        mov     [rsp + SymCryptFdefRawSquareMulx_Frame.nextNDigits], r9d

        jmp     SymCryptFdefRawSquareMulxOuterLoop


SymCryptFdefRawSquareMulxPhase2:
        ; Cy = Ov = 0 because last 'sub r9d, 1' resulted in 0

        ; Write the 8-word carry-out to the destination
        mov     [r8 +  8*8], rsi
        mov     [r8 +  9*8], rbp
        mov     [r8 + 10*8], r10
        mov     [r8 + 11*8], r11
        mov     [r8 + 12*8], r12
        mov     [r8 + 13*8], r13
        mov     [r8 + 14*8], r14
        mov     [r8 + 15*8], r15

        ; Compute diagonals, and add double the result so far

        mov     rcx, [rsp + SymCryptFdefRawSquareMulx_Frame.pSrcHome]
        mov     r9d, [rsp + SymCryptFdefRawSquareMulx_Frame.nDigitsHome]
        mov     r8, [rsp + SymCryptFdefRawSquareMulx_Frame.pDstHome]

        ; We can't keep the carries in Cy and Ov because there is no way to do a loop counter
        ; without touching the Ov flag.
        ; So we set the Ov carry in rsi, and retain a zero in rdi
        xor     esi, esi
        xor     edi, edi

SymCryptFdefRawSquareMulxDiagonalsLoop:
        ; Cy = carry in
        ; esi = carry in (1 bit)
        ; Ov = 0

SYMCRYPT_SQUARE_DIAG    MACRO   index
        mov     rdx, [rcx + 8 * index]
        mov     r10, [r8 + 16 * index]
        mov     r11, [r8 + 16 * index + 8]
        mulx    rbx, rax, rdx
        adcx    rax, r10
        adox    rax, r10
        adcx    rbx, r11
        adox    rbx, r11
        mov     [r8 + 16 * index], rax
        mov     [r8 + 16 * index + 8], rbx
    ENDM

        ; First word is different to handle the carry
        ; SYMCRYPT_SQUARE_DIAG    0 
        mov     rdx, [rcx]
        mov     r10, [r8]
        mov     r11, [r8 + 8]
        mulx    rbx, rax, rdx
        adcx    rax, rsi            ; add both carries
        adcx    rbx, rdi            ; rdi = 0; now Cy = 0 because result of multiply <= ff..fe00..01

        adcx    rax, r10
        adox    rax, r10
        adcx    rbx, r11
        adox    rbx, r11
        mov     [r8 ], rax
        mov     [r8 + 8], rbx

        SYMCRYPT_SQUARE_DIAG    1
        SYMCRYPT_SQUARE_DIAG    2
        SYMCRYPT_SQUARE_DIAG    3
        SYMCRYPT_SQUARE_DIAG    4
        SYMCRYPT_SQUARE_DIAG    5
        SYMCRYPT_SQUARE_DIAG    6
        SYMCRYPT_SQUARE_DIAG    7

        ; Move the Ov flag into esi
        mov     esi, edi
        adox    esi, edi

        ; There is no way to do a loop counter without overwriting the Ov flag
        ; Even the 'dec' instruction touches it, and LAHF/SAHF doesn't load/store the Ov flag.
        ; We can't push/pop efl in a function body

        lea     rcx, [rcx + 64]
        lea     r8, [r8 + 128]
        dec     r9d     
        jnz     SymCryptFdefRawSquareMulxDiagonalsLoop


        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret

        NESTED_END      SymCryptFdefRawSquareMulx, _TEXT





;VOID
;SymCryptFdefMontgomeryReduce(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

SymCryptFdefMontgomeryReduceMulx_Frame struct

        SavedRbp        dq  ?
        SavedRbx        dq  ?
        SavedRsi        dq  ?
        SavedRdi        dq  ?
        SavedR15        dq  ?
        SavedR14        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        returnaddress   dq  ?

        pmModHome       dq  ?
        pSrcHome        dq  ?
        pDstHome        dq  ?

        ; two 4-byte variables in P4Home
        CntOuter        dd  ?       ; outer loop counter
        HighCarry       dd  ?

SymCryptFdefMontgomeryReduceMulx_Frame        ends


        NESTED_ENTRY    SymCryptFdefMontgomeryReduceMulx, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp
        
        END_PROLOGUE

        ; rcx = pmMod
        ; rdx = pSrc = scratch buffer
        ; r8 = pDst

        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pmModHome], rcx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome], rdx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pDstHome], r8

        mov     r8, rdx

        mov     eax, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter], eax
        ; CntOuter = nDigits

        xor     ebx, ebx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry], ebx
        ; HighCarry = 0

SymCryptFdefMontgomeryReduceMulxOuterLoop:
        ; rcx = pmMod
        ; r8 = pSrc = tmp buffer that we will reduce
        mov     rsi, [r8 + 0 * 8]        
        mov     rbp, [r8 + 1 * 8]        
        mov     r10, [r8 + 2 * 8]        
        mov     r11, [r8 + 3 * 8]        
        mov     r12, [r8 + 4 * 8]        
        mov     r13, [r8 + 5 * 8]        
        mov     r14, [r8 + 6 * 8]        
        mov     r15, [r8 + 7 * 8]        

        mov     rdi, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64
        mov     r9d, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        ; r8 = value to reduce
        ; rsi - r15= r8[0..7]
        ; rcx = modulus value
        ; rdi = modinv

        MONTGOMERY18    rsi, rbp, r10, r11, r12, r13, r14, r15,  rdi, rcx, r8 + 0 * 8, rax, rbx
        MONTGOMERY18    rbp, r10, r11, r12, r13, r14, r15, rsi,  rdi, rcx, r8 + 1 * 8, rax, rbx
        MONTGOMERY18    r10, r11, r12, r13, r14, r15, rsi, rbp,  rdi, rcx, r8 + 2 * 8, rax, rbx
        MONTGOMERY18    r11, r12, r13, r14, r15, rsi, rbp, r10,  rdi, rcx, r8 + 3 * 8, rax, rbx
        MONTGOMERY18    r12, r13, r14, r15, rsi, rbp, r10, r11,  rdi, rcx, r8 + 4 * 8, rax, rbx
        MONTGOMERY18    r13, r14, r15, rsi, rbp, r10, r11, r12,  rdi, rcx, r8 + 5 * 8, rax, rbx
        MONTGOMERY18    r14, r15, rsi, rbp, r10, r11, r12, r13,  rdi, rcx, r8 + 6 * 8, rax, rbx
        MONTGOMERY18    r15, rsi, rbp, r10, r11, r12, r13, r14,  rdi, rcx, r8 + 7 * 8, rax, rbx

        ; rsi .. r15 = carry from multiply-add
        ; r8[0..7] = Montgomery factors

        mov     rdi, r8         ; factor to multiply by
        add     rcx, 64
        add     r8, 64

        sub     r9d, 1
        jz      SymCryptFdefMontgomeryReduceMulxInnerLoopDone

SymCryptFdefMontgomeryReduceMulxInnerLoop:
        
        ; rsi, rbp, r10, r11, r12, r13, r14, r15    8-word carry 
        ; rax, rbx                                  temps for multiplication
        ; rcx                                       running pointer pMod inner loop 
        ; r8                                        running pointer pSrc inner loop
        ; rdi                                       Montgomery factors for this row
        ; r9                                        loop ctr
        ; rdx                                       fixed input reg for multiplication

        MULADD88    rsi, rbp, r10, r11, r12, r13, r14, r15,  r8, rcx, rdi, rax, rbx
            ; pre & post: Cy = Ov = 0
            ; R[7-0]:D[7-0] = A[7:0] * B[7:0] + R[7:0] + D[7:0]
            ; rdx is volatile

        add     rcx, 64
        add     r8, 64
        sub     r9d, 1
        jnz     SymCryptFdefMontgomeryReduceMulxInnerLoop    


SymCryptFdefMontgomeryReduceMulxInnerLoopDone:

        ; We have an 8-word carry here, which we need to add to the in-memory buffer and retain a carry
        ; We also saved a 1-bit carry from the previous outer loop
        xor     edx, edx
        mov     eax, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry]
        ; move carry into Cy flag
        neg     eax

        ; We do this in separate instructions to help the instruction decoder build up a lead...
        mov     rax, [r8 + 0 * 8]
        adc     rax, rsi
        mov     [r8 + 0 * 8], rax

        mov     rbx, [r8 + 1 * 8]
        adc     rbx, rbp
        mov     [r8 + 1 * 8], rbx

        mov     rax, [r8 + 2 * 8]
        adc     rax, r10
        mov     [r8 + 2 * 8], rax

        mov     rbx, [r8 + 3 * 8]
        adc     rbx, r11
        mov     [r8 + 3 * 8], rbx

        mov     rax, [r8 + 4 * 8]
        adc     rax, r12
        mov     [r8 + 4 * 8], rax

        mov     rbx, [r8 + 5 * 8]
        adc     rbx, r13
        mov     [r8 + 5 * 8], rbx

        mov     rax, [r8 + 6 * 8]
        adc     rax, r14
        mov     [r8 + 6 * 8], rax

        mov     rbx, [r8 + 7 * 8]
        adc     rbx, r15
        mov     [r8 + 7 * 8], rbx
        
        adc     edx, edx                ; edx = carry
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry], edx

        mov     r8, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome]
        add     r8, 64
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome], r8

        mov     rcx, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pmModHome]

        mov     eax, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter]
        sub     eax, 1
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter], eax

        jnz     SymCryptFdefMontgomeryReduceMulxOuterloop

        ; edx = output carry

        mov     esi, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        mov     rdi, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pDstHome]

        ; r8 = result buffer pointer
        ; esi = # digits
        ; rcx = modulus value
        ; rdi = Dst

        ; copy these values for the maked copy loop
        mov     r9d, esi    ; nDigits
        mov     r10, r8     ; result buffer
        mov     rbp, rdi    ; destination pointer

        ; pDst = Reduction result - Modulus

SymCryptFdefMontgomeryReduceMulxSubLoop:
        mov     rax,[r8 + 0 * 8]
        sbb     rax,[rcx + 0 * 8]
        mov     [rdi + 0 * 8], rax

        mov     rbx,[r8 + 1 * 8]
        sbb     rbx,[rcx + 1 * 8]
        mov     [rdi + 1 * 8], rbx

        mov     rax,[r8 + 2 * 8]
        sbb     rax,[rcx + 2 * 8]
        mov     [rdi + 2 * 8], rax

        mov     rbx,[r8 + 3 * 8]
        sbb     rbx,[rcx + 3 * 8]
        mov     [rdi + 3 * 8], rbx

        mov     rax,[r8 + 4 * 8]
        sbb     rax,[rcx + 4 * 8]
        mov     [rdi + 4 * 8], rax

        mov     rbx,[r8 + 5 * 8]
        sbb     rbx,[rcx + 5 * 8]
        mov     [rdi + 5 * 8], rbx

        mov     rax,[r8 + 6 * 8]
        sbb     rax,[rcx + 6 * 8]
        mov     [rdi + 6 * 8], rax

        mov     rbx,[r8 + 7 * 8]
        sbb     rbx,[rcx + 7 * 8]
        mov     [rdi + 7 * 8], rbx

        lea     r8, [r8 + 64]
        lea     rcx, [rcx + 64]
        lea     rdi, [rdi + 64]
        dec     esi
        jnz     SymCryptFdefMontgomeryReduceMulxSubLoop

        ; now a masked copy from the reduction buffer to the destination.
        ; copy if high carry = 0 and Cy = 1
        sbb     edx, 0
        ; edx = copy mask, ff...ff  if copy, 0 of no copy

        movd    xmm0, edx           ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff    
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask

SymCryptFdefMontgomeryReduceMulxMaskedCopyLoop:
        movdqa  xmm2, [r10 + 0 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 0 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 0 * 16], xmm2

        movdqa  xmm2, [r10 + 1 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 1 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 1 * 16], xmm2

        movdqa  xmm2, [r10 + 2 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 2 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 2 * 16], xmm2

        movdqa  xmm2, [r10 + 3 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 3 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 3 * 16], xmm2

        ; Move on to the next digit

        add     r10, 64
        add     rbp, 64
        sub     r9d, 1
        jnz     SymCryptFdefMontgomeryReduceMulxMaskedCopyLoop

        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret

        NESTED_END      SymCryptFdefMontgomeryReduceMulx, _TEXT

; --------------------------------
; 1024-bit size specific functions
; --------------------------------

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul(
;    _In_reads_(nWords1)             PCUINT32    pSrc1,
;    _In_reads_(nWords2)             PCUINT32    pSrc2,
;                                    UINT32      nDigits,
;    _Out_writes_(nWords1 + nWords2) PUINT32     pDst )

        NESTED_ENTRY    SymCryptFdefRawMulMulx1024, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp
        
        END_PROLOGUE

        ; First we wipe nDigits2 of the result (size of in)
        mov         rbx, r9
        mov         rdi, r9

        mov         r9, r8
        mov         r8, rdx

        ; rcx = pSrc1
        ; r8 = pSrc2
        ; r9 = nDigits

        ; Wipe destination for nDigit2 blocks
        xorps       xmm0,xmm0               ; Zero register for 16-byte wipes

        movaps      [rbx],xmm0
        movaps      [rbx+16],xmm0           ; Wipe 32 bytes
        movaps      [rbx+32],xmm0           ; Wipe 32 bytes
        movaps      [rbx+48],xmm0           ; Wipe 32 bytes

        movaps      [rbx+64],xmm0
        movaps      [rbx+80],xmm0           ; Wipe 32 bytes
        movaps      [rbx+96],xmm0           ; Wipe 32 bytes
        movaps      [rbx+112],xmm0          ; Wipe 32 bytes

        ; Digit 1 from src2

        ZEROREG_8   rsi, rbp, r10, r11, r12, r13, r14, r15      ; Leaves Cy = Ov = 0

        MULADD88  rsi, rbp, r10, r11, r12, r13, r14, r15, rdi, rcx, r8, rax, rbx

        add     r8, 64              ; Src2 ptr
        add     rdi, 64
        xor     rax, rax            ; sets Cy = Ov = 0

        MULADD88  rsi, rbp, r10, r11, r12, r13, r14, r15, rdi, rcx, r8, rax, rbx

        add     rdi, 64

        ; Write the 8-word carry-out to the destination
        mov     [rdi + 0*8], rsi
        mov     [rdi + 1*8], rbp
        mov     [rdi + 2*8], r10
        mov     [rdi + 3*8], r11
        mov     [rdi + 4*8], r12
        mov     [rdi + 5*8], r13
        mov     [rdi + 6*8], r14
        mov     [rdi + 7*8], r15

        ; Digit 2 from src2

        ; set up

        ; Mov rdi one digit back
        sub     rdi, 64

        ; reload pSrc2
        sub     r8, 64

        ; update PSrc1
        add     rcx, 64

        ZEROREG_8   rsi, rbp, r10, r11, r12, r13, r14, r15      ; Leaves Cy = Ov = 0

        MULADD88  rsi, rbp, r10, r11, r12, r13, r14, r15, rdi, rcx, r8, rax, rbx

        add     r8, 64              ; Src2 ptr
        add     rdi, 64
        xor     rax, rax            ; sets Cy = Ov = 0

        MULADD88  rsi, rbp, r10, r11, r12, r13, r14, r15, rdi, rcx, r8, rax, rbx

        add     rdi, 64

        ; Write the 8-word carry-out to the destination
        mov     [rdi + 0*8], rsi
        mov     [rdi + 1*8], rbp
        mov     [rdi + 2*8], r10
        mov     [rdi + 3*8], r11
        mov     [rdi + 4*8], r12
        mov     [rdi + 5*8], r13
        mov     [rdi + 6*8], r14
        mov     [rdi + 7*8], r15

        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret
               
    NESTED_END      SymCryptFdefRawMulMulx1024, _TEXT

; VOID
; SYMCRYPT_CALL
; SymCryptFdefRawSquare(
;   _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
;                                                       UINT32      nDigits,
;   _Out_writes_(2*nWords)                              PUINT32     pDst )

        NESTED_ENTRY    SymCryptFdefRawSquareMulx1024, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp

        END_PROLOGUE

        ; rcx = pSrc
        ; rdx = nDigits     // (ignored)
        ; r8 = pDst

        ; Save parameters for phase 2
        mov     r9, r8                  ; pDst

        ; Wipe destination for nDigits blocks

        xor     rax, rax
        mov     rbx, r8
        ; we'll use the edx digit counter destructively...

        ; Wipe destination
        xorps       xmm0,xmm0               ; Zero register for 16-byte wipes

        movaps      [rbx],xmm0
        movaps      [rbx+16],xmm0           ; Wipe 32 bytes
        movaps      [rbx+32],xmm0           ; Wipe 32 bytes
        movaps      [rbx+48],xmm0           ; Wipe 32 bytes

        movaps      [rbx+64],xmm0
        movaps      [rbx+80],xmm0           ; Wipe 32 bytes
        movaps      [rbx+96],xmm0           ; Wipe 32 bytes
        movaps      [rbx+112],xmm0          ; Wipe 32 bytes

        ; Cy = Ov = 0 here

        HALF_SQUARE_NODIAG8 rsi, rbp, r10, r11, r12, r13, r14, r15,  r8, rcx, rax, rbx

        lea     rdi, [rcx + 64]
        lea     r8, [r8 + 64]

        ; rsi, rbp, r10, r11, r12, r13, r14, r15    8-word carry 
        ; rax, rbx                                  temps for multiplication
        ; rcx                                       pSrc running pointer outer loop
        ; r8                                        pDst running pointer inner loop
        ; rdx                                       fixed input reg for multiplication
        ; rdi                                       pSrc running pointer inner loop

        ; rsp[pSrc]                                 pSrc (used for final pass)
        ; rsp[nDigits]                              nDigits (used for final pass)
        ; rsp[pDst]                                 pDst (used for final pass)
        ; rsp[nextNDigits]                          # inner loop blocks in next outer loop iteration
        ; rsp[pDstPtr]                              pDst running pointer outer loop
            
        MULADD88    rsi, rbp, r10, r11, r12, r13, r14, r15, r8, rcx, rdi, rax, rbx

        add     r8, 64                 
        add     rdi, 64

        ; Write the 8-word carry-out to the destination
        mov     [r8 + 0*8], rsi
        mov     [r8 + 1*8], rbp
        mov     [r8 + 2*8], r10
        mov     [r8 + 3*8], r11
        mov     [r8 + 4*8], r12
        mov     [r8 + 5*8], r13
        mov     [r8 + 6*8], r14
        mov     [r8 + 7*8], r15

        add     rcx, 64

        ; r8 which is the destination pointer is shifted here by 2 digits

        xor     rax, rax                        ; Sets Cy = Ov = 0 

        HALF_SQUARE_NODIAG8 rsi, rbp, r10, r11, r12, r13, r14, r15,  r8, rcx, rax, rbx

        ; Cy = Ov = 0 because last 'sub r9d, 1' resulted in 0

        ; Write the 8-word carry-out to the destination
        mov     [r8 +  8*8], rsi
        mov     [r8 +  9*8], rbp
        mov     [r8 + 10*8], r10
        mov     [r8 + 11*8], r11
        mov     [r8 + 12*8], r12
        mov     [r8 + 13*8], r13
        mov     [r8 + 14*8], r14
        mov     [r8 + 15*8], r15

        ; Compute diagonals, and add double the result so far

        sub     rdi, 128                    ; Revert rdi back to pSrcHome
        mov     rcx, rdi
        mov     r8, r9

        xor     rax, rax                    ; Sets Cy = Ov = 0 

        SYMCRYPT_SQUARE_DIAG    0
        SYMCRYPT_SQUARE_DIAG    1
        SYMCRYPT_SQUARE_DIAG    2
        SYMCRYPT_SQUARE_DIAG    3
        SYMCRYPT_SQUARE_DIAG    4
        SYMCRYPT_SQUARE_DIAG    5
        SYMCRYPT_SQUARE_DIAG    6
        SYMCRYPT_SQUARE_DIAG    7

        SYMCRYPT_SQUARE_DIAG    8
        SYMCRYPT_SQUARE_DIAG    9
        SYMCRYPT_SQUARE_DIAG   10
        SYMCRYPT_SQUARE_DIAG   11
        SYMCRYPT_SQUARE_DIAG   12
        SYMCRYPT_SQUARE_DIAG   13
        SYMCRYPT_SQUARE_DIAG   14
        SYMCRYPT_SQUARE_DIAG   15

        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret

        NESTED_END      SymCryptFdefRawSquareMulx1024, _TEXT

;VOID
;SymCryptFdefMontgomeryReduce(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

        NESTED_ENTRY    SymCryptFdefMontgomeryReduceMulx1024, _TEXT

        ; We need all the registers
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rdi
        push_reg        rsi
        push_reg        rbx
        push_reg        rbp
        
        END_PROLOGUE

        ; rcx = pmMod
        ; rdx = pSrc = scratch buffer
        ; r8 = pDst

        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pmModHome], rcx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome], rdx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pDstHome], r8

        mov     r8, rdx

        mov     eax, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter], eax
        ; CntOuter = nDigits

        xor     ebx, ebx
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry], ebx
        ; HighCarry = 0

SymCryptFdefMontgomeryReduceMulx1024OuterLoop:
        ; rcx = pmMod
        ; r8 = pSrc = tmp buffer that we will reduce
        mov     rsi, [r8 + 0 * 8]        
        mov     rbp, [r8 + 1 * 8]        
        mov     r10, [r8 + 2 * 8]        
        mov     r11, [r8 + 3 * 8]        
        mov     r12, [r8 + 4 * 8]        
        mov     r13, [r8 + 5 * 8]        
        mov     r14, [r8 + 6 * 8]        
        mov     r15, [r8 + 7 * 8]        

        mov     rdi, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64
        mov     r9d, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        ; r8 = value to reduce
        ; rsi - r15= r8[0..7]
        ; rcx = modulus value
        ; rdi = modinv

        MONTGOMERY18    rsi, rbp, r10, r11, r12, r13, r14, r15,  rdi, rcx, r8 + 0 * 8, rax, rbx
        MONTGOMERY18    rbp, r10, r11, r12, r13, r14, r15, rsi,  rdi, rcx, r8 + 1 * 8, rax, rbx
        MONTGOMERY18    r10, r11, r12, r13, r14, r15, rsi, rbp,  rdi, rcx, r8 + 2 * 8, rax, rbx
        MONTGOMERY18    r11, r12, r13, r14, r15, rsi, rbp, r10,  rdi, rcx, r8 + 3 * 8, rax, rbx
        MONTGOMERY18    r12, r13, r14, r15, rsi, rbp, r10, r11,  rdi, rcx, r8 + 4 * 8, rax, rbx
        MONTGOMERY18    r13, r14, r15, rsi, rbp, r10, r11, r12,  rdi, rcx, r8 + 5 * 8, rax, rbx
        MONTGOMERY18    r14, r15, rsi, rbp, r10, r11, r12, r13,  rdi, rcx, r8 + 6 * 8, rax, rbx
        MONTGOMERY18    r15, rsi, rbp, r10, r11, r12, r13, r14,  rdi, rcx, r8 + 7 * 8, rax, rbx

        ; rsi .. r15 = carry from multiply-add
        ; r8[0..7] = Montgomery factors

        mov     rdi, r8         ; factor to multiply by
        add     rcx, 64
        add     r8, 64
        
        ; rsi, rbp, r10, r11, r12, r13, r14, r15    8-word carry 
        ; rax, rbx                                  temps for multiplication
        ; rcx                                       running pointer pMod inner loop 
        ; r8                                        running pointer pSrc inner loop
        ; rdi                                       Montgomery factors for this row
        ; r9                                        loop ctr
        ; rdx                                       fixed input reg for multiplication

        MULADD88    rsi, rbp, r10, r11, r12, r13, r14, r15,  r8, rcx, rdi, rax, rbx
            ; pre & post: Cy = Ov = 0
            ; R[7-0]:D[7-0] = A[7:0] * B[7:0] + R[7:0] + D[7:0]
            ; rdx is volatile

        add     rcx, 64
        add     r8, 64

        ; We have an 8-word carry here, which we need to add to the in-memory buffer and retain a carry
        ; We also saved a 1-bit carry from the previous outer loop
        xor     edx, edx
        mov     eax, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry]
        ; move carry into Cy flag
        neg     eax

        ; We do this in separate instructions to help the instruction decoder build up a lead...
        mov     rax, [r8 + 0 * 8]
        adc     rax, rsi
        mov     [r8 + 0 * 8], rax

        mov     rbx, [r8 + 1 * 8]
        adc     rbx, rbp
        mov     [r8 + 1 * 8], rbx

        mov     rax, [r8 + 2 * 8]
        adc     rax, r10
        mov     [r8 + 2 * 8], rax

        mov     rbx, [r8 + 3 * 8]
        adc     rbx, r11
        mov     [r8 + 3 * 8], rbx

        mov     rax, [r8 + 4 * 8]
        adc     rax, r12
        mov     [r8 + 4 * 8], rax

        mov     rbx, [r8 + 5 * 8]
        adc     rbx, r13
        mov     [r8 + 5 * 8], rbx

        mov     rax, [r8 + 6 * 8]
        adc     rax, r14
        mov     [r8 + 6 * 8], rax

        mov     rbx, [r8 + 7 * 8]
        adc     rbx, r15
        mov     [r8 + 7 * 8], rbx
        
        adc     edx, edx                ; edx = carry
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.HighCarry], edx

        mov     r8, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome]
        add     r8, 64
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pSrcHome], r8

        mov     rcx, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pmModHome]

        mov     eax, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter]
        sub     eax, 1
        mov     [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.CntOuter], eax

        jnz     SymCryptFdefMontgomeryReduceMulx1024Outerloop

        ; edx = output carry

        mov     esi, [rcx + SymCryptModulusNdigitsOffsetAmd64]
        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        mov     rdi, [rsp + SymCryptFdefMontgomeryReduceMulx_Frame.pDstHome]

        ; r8 = result buffer pointer
        ; esi = # digits
        ; rcx = modulus value
        ; rdi = Dst

        ; copy these values for the maked copy loop
        mov     r9d, esi    ; nDigits
        mov     r10, r8     ; result buffer
        mov     rbp, rdi    ; destination pointer

        ; pDst = Reduction result - Modulus

        mov     rax,[r8 + 0 * 8]
        sbb     rax,[rcx + 0 * 8]
        mov     [rdi + 0 * 8], rax

        mov     rbx,[r8 + 1 * 8]
        sbb     rbx,[rcx + 1 * 8]
        mov     [rdi + 1 * 8], rbx

        mov     rax,[r8 + 2 * 8]
        sbb     rax,[rcx + 2 * 8]
        mov     [rdi + 2 * 8], rax

        mov     rbx,[r8 + 3 * 8]
        sbb     rbx,[rcx + 3 * 8]
        mov     [rdi + 3 * 8], rbx

        mov     rax,[r8 + 4 * 8]
        sbb     rax,[rcx + 4 * 8]
        mov     [rdi + 4 * 8], rax

        mov     rbx,[r8 + 5 * 8]
        sbb     rbx,[rcx + 5 * 8]
        mov     [rdi + 5 * 8], rbx

        mov     rax,[r8 + 6 * 8]
        sbb     rax,[rcx + 6 * 8]
        mov     [rdi + 6 * 8], rax

        mov     rbx,[r8 + 7 * 8]
        sbb     rbx,[rcx + 7 * 8]
        mov     [rdi + 7 * 8], rbx

        mov     rax,[r8 + 8 * 8]
        sbb     rax,[rcx + 8 * 8]
        mov     [rdi + 8 * 8], rax

        mov     rbx,[r8 + 9 * 8]
        sbb     rbx,[rcx + 9 * 8]
        mov     [rdi + 9 * 8], rbx

        mov     rax,[r8 + 10 * 8]
        sbb     rax,[rcx + 10 * 8]
        mov     [rdi + 10 * 8], rax

        mov     rbx,[r8 + 11 * 8]
        sbb     rbx,[rcx + 11 * 8]
        mov     [rdi + 11 * 8], rbx

        mov     rax,[r8 + 12 * 8]
        sbb     rax,[rcx + 12 * 8]
        mov     [rdi + 12 * 8], rax

        mov     rbx,[r8 + 13 * 8]
        sbb     rbx,[rcx + 13 * 8]
        mov     [rdi + 13 * 8], rbx

        mov     rax,[r8 + 14 * 8]
        sbb     rax,[rcx + 14 * 8]
        mov     [rdi + 14 * 8], rax

        mov     rbx,[r8 + 15 * 8]
        sbb     rbx,[rcx + 15 * 8]
        mov     [rdi + 15 * 8], rbx


        ; now a masked copy from the reduction buffer to the destination.
        ; copy if high carry = 0 and Cy = 1
        sbb     edx, 0
        ; edx = copy mask, ff...ff  if copy, 0 of no copy

        movd    xmm0, edx           ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff    
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask


        movdqa  xmm2, [r10 + 0 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 0 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 0 * 16], xmm2

        movdqa  xmm2, [r10 + 1 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 1 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 1 * 16], xmm2

        movdqa  xmm2, [r10 + 2 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 2 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 2 * 16], xmm2

        movdqa  xmm2, [r10 + 3 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 3 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 3 * 16], xmm2

        movdqa  xmm2, [r10 + 4 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 4 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 4 * 16], xmm2

        movdqa  xmm2, [r10 + 5 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 5 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 5 * 16], xmm2

        movdqa  xmm2, [r10 + 6 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 6 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 6 * 16], xmm2

        movdqa  xmm2, [r10 + 7 * 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rbp + 7 * 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          
        pand    xmm3, xmm1           
        por     xmm2, xmm3
        movdqa  [rbp + 7 * 16], xmm2


        BEGIN_EPILOGUE

        pop     rbp
        pop     rbx
        pop     rsi
        pop     rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12    
        ret

        NESTED_END      SymCryptFdefMontgomeryReduceMulx1024, _TEXT


;=============================================================================
; test code 

MULX_TEST_1 MACRO
        mulx    rax, rcx, [r8 + 8]
        adcx    r10, rcx
        adox    r11, rax
    ENDM

MULX_TEST_4  MACRO
        MULX_TEST_1
        MULX_TEST_1
        MULX_TEST_1
        MULX_TEST_1
    ENDM

MULX_TEST_16  MACRO
        MULX_TEST_4
        MULX_TEST_4
        MULX_TEST_4
        MULX_TEST_4
    ENDM

MULX_TEST_64  MACRO
        MULX_TEST_16
        MULX_TEST_16
        MULX_TEST_16
        MULX_TEST_16
    ENDM

MULX_TEST_256  MACRO
        MULX_TEST_64
        MULX_TEST_64
        MULX_TEST_64
        MULX_TEST_64
    ENDM

MULX_TEST_1024  MACRO
        MULX_TEST_256
        MULX_TEST_256
        MULX_TEST_256
        MULX_TEST_256
    ENDM

        LEAF_ENTRY  SymCryptTestMulx, _TEXT

        mov r8, rsp

        MULX_TEST_1024

        ret
        LEAF_END    SymCryptTestMulx, _TEXT



        end
