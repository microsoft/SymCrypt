;
;  fdef_asm.asm   Assembler code for large integer arithmetic in the default data format
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;

include ksamd64.inc

include symcrypt_version.inc
include symcrypt_magic.inc



include C_asm_shared.inc

include fdef_mul_macros.asm

        altentry SymCryptFdefMontgomerReduce256AsmInternal


;UINT32
;SYMCRYPT_CALL
;SymCryptFdefRawAdd(
;    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
;    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
;                                                                UINT32      nDigits,
;                                                                UINT32      mask );

        LEAF_ENTRY SymCryptFdefRawAddAsm, _TEXT

        ; rcx = Src1
        ; rdx = Src2
        ; r8 = Dst
        ; r9 = nDigits
        
        add     r9d, r9d        ; loop over each half digit
        xor     rax, rax
        xor     r10, r10

SymCryptFdefRawAddAsmLoop:
        ; carry is in the carry flag
        mov     rax,[rcx]
        adc     rax,[rdx]
        mov     [r8],rax

        mov     rax,[rcx + 8]
        adc     rax,[rdx + 8]
        mov     [r8 + 8], rax
        
        mov     rax,[rcx + 16]
        adc     rax,[rdx + 16]
        mov     [r8 + 16], rax
        
        mov     rax,[rcx + 24]
        adc     rax,[rdx + 24]
        mov     [r8 + 24], rax
        
        lea     rcx, [rcx + 32]
        lea     rdx, [rdx + 32]
        lea     r8,  [r8  + 32]
        dec     r9d
        jnz     SymCryptFdefRawAddAsmLoop

        mov     rax, r10
        adc     rax, r10
                
        ret
        
        LEAF_END SymCryptFdefRawAddAsm, _TEXT


;UINT32
;SYMCRYPT_CALL
;SymCryptFdefRawSub(
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
;    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
;                                                            UINT32      nDigits )

        LEAF_ENTRY SymCryptFdefRawSubAsm, _TEXT

        ; rcx = Src1
        ; rdx = Src2
        ; r8 = Dst
        ; r9 = nDigits
        
        add     r9d, r9d        ; loop over each half digit
        xor     rax, rax
        xor     r10, r10

SymCryptFdefRawSubAsmLoop:
        ; carry is in the carry flag
        mov     rax,[rcx]
        sbb     rax,[rdx]
        mov     [r8],rax

        mov     rax,[rcx + 8]
        sbb     rax,[rdx + 8]
        mov     [r8 + 8], rax
        
        mov     rax,[rcx + 16]
        sbb     rax,[rdx + 16]
        mov     [r8 + 16], rax
        
        mov     rax,[rcx + 24]
        sbb     rax,[rdx + 24]
        mov     [r8 + 24], rax
        
        lea     rcx, [rcx + 32]
        lea     rdx, [rdx + 32]
        lea     r8,  [r8  + 32]
        dec     r9d
        jnz     SymCryptFdefRawSubAsmLoop

        mov     rax, r10
        adc     rax, r10
                
        ret
        
        LEAF_END SymCryptFdefRawSubAsm, _TEXT



;VOID
;SYMCRYPT_CALL
;SymCryptFdefMaskedCopy(
;    _In_reads_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )      PCBYTE      pbSrc,
;    _InOut_writes_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )  PBYTE       pbDst,
;                                                                UINT32      nDigits,
;                                                                UINT32      mask )

    LEAF_ENTRY  SymCryptFdefMaskedCopyAsm, _TEXT

        add     r8d, r8d            ; loop over half digits

        movd    xmm0, r9d           ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff    
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask

SymCryptFdefMaskedCopyAsmLoop:
        movdqa  xmm2, [rcx]         ; xmm2 = pSrc[0]
        movdqa  xmm3, [rdx]         ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [rdx], xmm2

        movdqa  xmm2, [rcx + 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [rdx + 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [rdx + 16], xmm2

        ; Move on to the next digit

        add     rcx, 32
        add     rdx, 32
        sub     r8d, 1
        jnz     SymCryptFdefMaskedCopyAsmLoop
        ret

        LEAF_END SymCryptFdefMaskedCopyAsm, _TEXT

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul(
;    _In_reads_(nWords1)             PCUINT32    pSrc1,
;                                    UINT32      nDigits1,
;    _In_reads_(nWords2)             PCUINT32    pSrc2,
;                                    UINT32      nDigits2,
;    _Out_writes_(nWords1 + nWords2) PUINT32     pDst )

SymCryptFdefRawMulAsm_Frame struct
        SavedRdi        dq  ?
        SavedRsi        dq  ?
        SavedR15        dq  ?
        SavedR14        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        SavedRbx        dq  ?
        returnaddress   dq  ?
        Arg1Home        dq  ?
        Arg2Home        dq  ?
        Arg3Home        dq  ?
        Arg4Home        dq  ?
        pDst            dq  ?

SymCryptFdefRawMulAsm_Frame        ends

        NESTED_ENTRY    SymCryptFdefRawMulAsm, _TEXT

        rex_push_reg    rbx
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rsi
        push_reg        rdi

        END_PROLOGUE

        ; Basic structure:
        ;   for each word in Src1:
        ;       Dst += Src2 * word
        ; Register assignments
        ; 
        ; rax = tmp for mul
        ; rbx = word from Src1 to multiply with
        ; rcx = pSrc1  (updated in outer loop)
        ; rdx = tmp for mul
        ; rsi = inner loop pointer into pSrc2
        ; rdi = inner loop pointer into pDst
        ; r8 = pSrc2
        ; r9 = nDigits2
        ; r10 = pDst (incremented in outer loop)
        ; r11 = # words left from Src1 to process
        ; r12 = carry for even words (64 bits)
        ; r13 = inner loop counter
        ; r15 = carry for odd words (64 bits)

        mov     r11, rdx            ; nDigits1
        shl     r11, 3              ; nDigits1 * 8 = # words in Src1 to process
        mov     r10, [rsp + SymCryptFdefRawMulAsm_Frame.pDst ]

        ; Outer loop invariant established: rcx, r8, r9, r10


        mov     rsi, r8             ; rsi = pSrc2
        mov     rdi, r10            ; rdi = pDst + outer loop ctr
        mov     rbx, [rcx]          ; mulword
        xor     r12, r12
        mov     r13, r9

        ; First inner loop overwrites Dst, which avoids adding the current Dst value

        ALIGN   16

SymCryptFdefRawMulAsmLoop1:
        MULT_SINGLEADD_128 0, rsi, rdi
        MULT_SINGLEADD_128 2, rsi, rdi
        MULT_SINGLEADD_128 4, rsi, rdi
        MULT_SINGLEADD_128 6, rsi, rdi

        lea     rsi,[rsi + 64]
        lea     rdi,[rdi + 64]

        dec     r13
        jnz     SymCryptFdefRawMulAsmLoop1

        mov     [rdi], r12              ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1

        ALIGN   16

SymCryptFdefRawMulAsmLoopOuter:

        add     rcx, 8                  ; move to next word of pSrc1
        add     r10, 8                  ; move Dst pointer one word over
        mov     rbx, [rcx]
        mov     rsi, r8
        mov     rdi, r10
        xor     r12, r12
        mov     r13, r9

        ALIGN   16

SymCryptFdefRawMulAsmLoop2:
        MULT_DOUBLEADD_128 0, rsi, rdi
        MULT_DOUBLEADD_128 2, rsi, rdi
        MULT_DOUBLEADD_128 4, rsi, rdi
        MULT_DOUBLEADD_128 6, rsi, rdi

        lea     rsi,[rsi + 64]
        lea     rdi,[rdi + 64]

        dec     r13
        jnz     SymCryptFdefRawMulAsmLoop2

        mov     [rdi], r12          ; write next word. (stays within Dst buffer)

        sub     r11, 1
        jnz     SymCryptFdefRawMulAsmLoopOuter

        BEGIN_EPILOGUE

        pop     rdi
        pop     rsi
        pop     r15
        pop     r14
        pop     r13
        pop     r12      
        pop     rbx
        ret
               
    NESTED_END      SymCryptFdefRawMulAsm, _TEXT

; VOID
; SYMCRYPT_CALL
; SymCryptFdefRawSquareAsm(
;   _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
;                                                       UINT32      nDigits,
;   _Out_writes_(2*nWords)                              PUINT32     pDst )

SymCryptFdefRawSquareAsm_Frame struct

        SavedRcx        dq  ?
        SavedRdi        dq  ?
        SavedRsi        dq  ?
        SavedR15        dq  ?
        SavedR14        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        SavedRbx        dq  ?
        returnaddress   dq  ?
        Arg1Home        dq  ?
        Arg2Home        dq  ?
        Arg3Home        dq  ?

SymCryptFdefRawSquareAsm_Frame        ends

        NESTED_ENTRY    SymCryptFdefRawSquareAsm, _TEXT

        rex_push_reg    rbx
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rsi
        push_reg        rdi
        push_reg        rcx

        END_PROLOGUE

        ; Register assignments
        ;
        ; rax = tmp for mul
        ; rbx = word from Src to multiply with
        ; rcx = outer loop pointer into pSrc
        ; rdx = tmp for mul
        ; rsi = inner loop pointer into pSrc
        ; rdi = inner loop pointer into pDst
        ; r8 = pDst (constant)
        ; r9 = nDigits (constant)
        ; r10 = outer loop pointer into pDst
        ; r11 = outer loop counter of #words left
        ; r12 = carry for even words (64 bits)
        ; r13 = inner loop counter of #words left
        ; r14 = cyclic counter that specifies on which branch we jump into
        ; r15 = carry for odd words (64 bits)

        mov     r9,  rdx            ; nDigits

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; First Pass - Addition of the cross products x_i*x_j with i!=j
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;
        ; At the beginning of each inner loop we will jump over the
        ; words that don't need processing. The decision of the jump
        ; will be based on the cyclic counter r14.
        ;
        ; For the first pass we loop over **half** digits since having a smaller
        ; number of jumps (i.e. 4) is actually faster than having 8 jumps.
        ;
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     r11, rdx            ; nDigits
        shl     r11, 3              ; r11 = outer #words
        mov     r10, r8             ; r10 = outer pDst

        mov     rsi, rcx            ; rsi = inner pSrc
        mov     rdi, r10            ; rdi = inner pDst

        ; Initial inner loop overwrites Dst, which avoids adding the current Dst value

        mov     rbx, [rcx]          ; mulword

        xor     r12, r12            ; carry = 0
        xor     r15, r15            ; carry = 0

        mov     r13, r11            ; r13 = inner #words
        mov     [rdi], r12          ; Write 0 in the first word

        ; Skip over the first word
        jmp     SymCryptFdefRawSquareAsmInnerLoopInit_Word1

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoopInit_Word0:
        SQR_SINGLEADD_64 0, rsi, rdi, r12, r15

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoopInit_Word1:
        SQR_SINGLEADD_64 1, rsi, rdi, r15, r12

        SQR_SINGLEADD_64 2, rsi, rdi, r12, r15

        SQR_SINGLEADD_64 3, rsi, rdi, r15, r12

        lea     rsi, [rsi + 32]
        lea     rdi, [rdi + 32]
        sub     r13, 4
        jnz     SymCryptFdefRawSquareAsmInnerLoopInit_Word0

        mov     [rdi], r12              ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1                  ; Counter for the outer loop
        mov     r14, 1                  ; Cyclic counter r14 = 1

        ALIGN   16
SymCryptFdefRawSquareAsmLoopOuter:

        add     r10, 8                  ; move Dst pointer 1 word over

        mov     rsi, rcx                ; rsi = inner pSrc
        mov     rdi, r10                ; rdi = inner pDst

        mov     rbx, [rcx + 8*r14]      ; Get the next mulword

        inc     r14b                    ; Increment the cyclic counter by 1

        mov     r13, r11                ; # of words for the inner loop
        add     r13, 2
        and     r13, 0FFFFFFFFFFFFFFFCh ; Zero out the 2 lower bits

        xor     r12, r12                ; carry = 0
        xor     r15, r15                ; carry = 0

        ; Logic to find the correct jump
        cmp     r14b, 3
        je      SymCryptFdefRawSquareAsmInnerLoop_Word3
        cmp     r14b, 2
        je      SymCryptFdefRawSquareAsmInnerLoop_Word2
        cmp     r14b, 1
        je      SymCryptFdefRawSquareAsmInnerLoop_Word1

        ; The following instructions are only executed when r14b == 4
        xor     r14b, r14b              ; Set it to 0 for the next iteration

        add     rcx, 32                 ; move pSrc 4 words over
        add     r10, 32                 ; move destination 4 words over

        mov     rsi, rcx                ; rsi = inner pSrc
        mov     rdi, r10                ; rdi = inner pDst

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoop_Word0:
        SQR_DOUBLEADD_64 0, rsi, rdi, r12, r15

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoop_Word1:
        SQR_DOUBLEADD_64 1, rsi, rdi, r15, r12

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoop_Word2:
        SQR_DOUBLEADD_64 2, rsi, rdi, r12, r15

        ALIGN   16
SymCryptFdefRawSquareAsmInnerLoop_Word3:
        SQR_DOUBLEADD_64 3, rsi, rdi, r15, r12

        lea     rsi, [rsi + 32]
        lea     rdi, [rdi + 32]
        sub     r13, 4
        jnz     SymCryptFdefRawSquareAsmInnerLoop_Word0

        mov     [rdi], r12          ; write next word. (stays within Dst buffer)

        dec     r11
        cmp     r11, 1
        jne     SymCryptFdefRawSquareAsmLoopOuter

        xor     rdx, rdx
        mov     [r10 + 40], rdx     ; Final word = 0


        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Second Pass - Shifting all results 1 bit left
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     r11, r9             ; nDigits
        mov     rdi, r8             ; pDst pointer
        shl     r11, 1              ; 2*nDigits

        ALIGN   16
SymCryptFdefRawSquareAsmSecondPass:
        SQR_SHIFT_LEFT 0
        SQR_SHIFT_LEFT 1
        SQR_SHIFT_LEFT 2
        SQR_SHIFT_LEFT 3

        SQR_SHIFT_LEFT 4
        SQR_SHIFT_LEFT 5
        SQR_SHIFT_LEFT 6
        SQR_SHIFT_LEFT 7

        lea     rdi, [rdi + 64]
        dec     r11
        jnz     SymCryptFdefRawSquareAsmSecondPass

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Third Pass - Adding the squares on the even columns and propagating the sum
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     rsi, [rsp + SymCryptFdefRawSquareAsm_Frame.SavedRcx]
        mov     rdi, r8             ; rdi = pDst

        xor     r12, r12

SymCryptFdefRawSquareAsmThirdPass:
        SQR_DIAGONAL_PROP 0
        SQR_DIAGONAL_PROP 1
        SQR_DIAGONAL_PROP 2
        SQR_DIAGONAL_PROP 3
        SQR_DIAGONAL_PROP 4
        SQR_DIAGONAL_PROP 5
        SQR_DIAGONAL_PROP 6
        SQR_DIAGONAL_PROP 7

        add     rsi, 64             ; One digit up
        add     rdi, 128            ; Two digits up
        sub     r9, 1
        jnz     SymCryptFdefRawSquareAsmThirdPass

        BEGIN_EPILOGUE

        pop     rcx
        pop     rdi
        pop     rsi
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret

    NESTED_END      SymCryptFdefRawSquareAsm, _TEXT


;VOID
;SymCryptFdefMontgomeryReduceAsm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

        NESTED_ENTRY    SymCryptFdefMontgomeryReduceAsm, _TEXT

        rex_push_reg    rbx 
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15
        push_reg        rsi
        push_reg        rdi
        push_reg        rbp
        
        END_PROLOGUE

        mov     r11, rdx        ; r11 = pSrc
        mov     ebp, [rcx + SymCryptModulusNdigitsOffsetAmd64]                  ; nDigits
        mov     r13, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64

        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        mov     edi, ebp        ; outer loop counter
        shl     edi, 3          ; edi is in words

        xor     r14d, r14d

        ; General register allocations
        ; rax = multiply result
        ; rbx = multiplier in inner loop
        ; rcx = pointer to modulus value
        ; rdx = multiply result
        ; rsi = loop counter
        ; rdi = loop counter
        ; rbp = nDigits
        ; r8 = pDst
        ; r9 = running pointer in Src
        ; r10 = running pointer in Mod
        ; r11 = pSrc (updated in outer loop)
        ; r12 = carry
        ; r13 = pmMod->tm.montgomery.inv64
        ; r14 = carry out from last word of previous loop iteration

        ALIGN   16

SymCryptFdefMontgomeryReduceAsmOuterLoop:

        ; start decoder with a few simple instructions, including at least one that requires
        ; a uop execution and is on the critical path

        mov     rbx, [r11]                      ; fetch word of Src we want to set to zero
        mov     r10, r11
        mov     r9, rcx

        imul    rbx, r13                        ; lower word is same for signed & unsigned multiply

        mov     esi, ebp
        xor     r12d, r12d

        ALIGN   16

SymCryptFdefMontgomeryReduceAsmInnerloop:
        ; rax = mul scratch
        ; rbx = multiplier
        ; rcx = pointer to modulus value
        ; rdx = mul scratch
        ; edi = outer loop counter (words)
        ; esi = inner loop counter (digits)
        ; r9  = running ptr to modulus
        ; r10 = running ptr to input/scratch
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        MULT_DOUBLEADD_128 0, r9, r10
        MULT_DOUBLEADD_128 2, r9, r10
        MULT_DOUBLEADD_128 4, r9, r10
        MULT_DOUBLEADD_128 6, r9, r10

        lea     r9,[r9 + 64]
        lea     r10,[r10 + 64]

        dec     esi
        jnz     SymCryptFdefMontgomeryReduceAsmInnerloop

        add     r12, r14
        mov     r14d, 0
        adc     r14, 0
        add     r12, [r10]
        adc     r14, 0
        mov     [r10], r12

        lea     r11,[r11 + 8]

        dec     edi
        jnz     SymCryptFdefMontgomeryReduceAsmOuterLoop

        ;
        ; Most of the work is done; now all that is left is subtract the modulus if it is smaller than the result
        ; 

        ; First we compute the pSrc result minus the modulus into the destination
        mov     esi, ebp        ; loop ctr
        mov     r10, r11        ; pSrc
        mov     r9, rcx         ; pMod
        mov     r12, r8         ; pDst

        ; Cy = 0 because the last 'sub edi,1' resulted in 0

        ALIGN   16

SymCryptFdefMontgomeryReduceAsmSubLoop:
        mov     rax,[r10]
        sbb     rax,[r9]
        mov     [r12], rax

        mov     rax,[r10 + 8]
        sbb     rax,[r9 + 8]
        mov     [r12 + 8], rax

        mov     rax,[r10 + 16]
        sbb     rax,[r9 + 16]
        mov     [r12 + 16], rax

        mov     rax,[r10 + 24]
        sbb     rax,[r9 + 24]
        mov     [r12 + 24], rax

        mov     rax,[r10 + 32]
        sbb     rax,[r9 + 32]
        mov     [r12 + 32], rax

        mov     rax,[r10 + 40]
        sbb     rax,[r9 + 40]
        mov     [r12 + 40], rax

        mov     rax,[r10 + 48]
        sbb     rax,[r9 + 48]
        mov     [r12 + 48], rax

        mov     rax,[r10 + 56]
        sbb     rax,[r9 + 56]
        mov     [r12 + 56], rax

        lea     r10,[r10 + 64]
        lea     r9,[r9 + 64]
        lea     r12,[r12 + 64]

        dec     esi
        jnz     SymCryptFdefMontgomeryReduceAsmSubLoop

        ; Finally a masked copy form pSrc to pDst 
        ; copy if: r14 == 0 && Cy = 1
        sbb     r14d, 0

        movd    xmm0, r14d          ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff    
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask

        ALIGN   16

SymCryptFdefMontgomeryReduceAsmMaskedCopyLoop:
        movdqa  xmm2, [r11]         ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8]          ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [r8], xmm2

        movdqa  xmm2, [r11 + 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [r8  + 16], xmm2

        movdqa  xmm2, [r11 + 32]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8 + 32]     ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [r8 + 32], xmm2

        movdqa  xmm2, [r11 + 48]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 48]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ; 
        por     xmm2, xmm3
        movdqa  [r8  + 48], xmm2

        ; Move on to the next digit
        lea     r11,[r11 + 64]
        lea     r8,[r8 + 64]

        dec     ebp
        jnz     SymCryptFdefMontgomeryReduceAsmMaskedCopyLoop

        BEGIN_EPILOGUE

        pop     rbp
        pop     rdi
        pop     rsi
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret
               
    NESTED_END      SymCryptFdefMontgomeryReduceAsm, _TEXT


; --------------------------------
; 256-bit size specific functions
; --------------------------------

;VOID
;SYMCRYPT_CALL
;SymCryptFdefModAdd256(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
;    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
;    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
;    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
;                                    SIZE_T                  cbScratch );

        NESTED_ENTRY    SymCryptFdefModAdd256Asm, _TEXT

        push_reg    r12
        push_reg    r13
        push_reg    r14
        push_reg    rbx

        END_PROLOGUE

        ; rcx = pmMod
        ; rdx = peSrc1
        ; r8  = peSrc2
        ; r9  = peDst

        ; compute Src1 + Src2 into (rax, rbx, r10, r11) with carry out mask in r12

        mov     rax, [rdx]
        add     rax, [r8 ]
        mov     rbx, [rdx + 8]
        adc     rbx, [r8  + 8]
        mov     r10, [rdx + 16]
        adc     r10, [r8  + 16]
        mov     r11, [rdx + 24]
        adc     r11, [r8  + 24]
        sbb     r12, r12                  ; r12 = carry out mask

        ; rdx, r8: free

        ; Compute sum - Mod into (rdx, r8, r13, r14) = sum - modulus, rcx = carry out mask

        add     rcx, SymCryptModulusValueOffsetAmd64

        mov     rdx, rax
        sub     rdx, [rcx]
        mov     r8,  rbx
        sbb     r8,  [rcx + 8]
        mov     r13, r10
        sbb     r13, [rcx + 16]
        mov     r14, r11
        sbb     r14, [rcx + 24]

        sbb     rcx, rcx                 ; rcx = carry out mask

        ; Choose between the two
        ; addition carry = 1, then subtraction carry = 1 and we pick the 2nd result.
        ; addition carry = 0 and subtraction carry = 0: pick 2nd result
        ; addition carry = 0 and subtraction carry = 1: pick first result

        xor     rcx, r12            ; 0 = 2nd result, 1 = first result               
        
        xor     rax, rdx
        xor     rbx, r8
        xor     r10, r13
        xor     r11, r14            

        and     rax, rcx
        and     rbx, rcx
        and     r10, rcx
        and     r11, rcx

        xor     rdx, rax
        xor     r8 , rbx
        xor     r13, r10
        xor     r14, r11

        mov     [r9 +  0], rdx
        mov     [r9 +  8], r8 
        mov     [r9 + 16], r13
        mov     [r9 + 24], r14

        BEGIN_EPILOGUE

        pop     rbx
        pop     r14
        pop     r13
        pop     r12
        ret

        NESTED_END      SymCryptFdefModAdd256Asm, _TEXT



        NESTED_ENTRY    SymCryptFdefModSub256Asm, _TEXT

        push_reg    r12
        push_reg    r13
        push_reg    rbx

        END_PROLOGUE

        ; rcx = pmMod
        ; rdx = peSrc1
        ; r8  = peSrc2
        ; r9  = peDst

        ; compute Src1 - Src2 into (rax, rbx, r10, r11) with carry out mask in r12

        mov     rax, [rdx]
        sub     rax, [r8 ]
        mov     rbx, [rdx + 8]
        sbb     rbx, [r8  + 8]
        mov     r10, [rdx + 16]
        sbb     r10, [r8  + 16]
        mov     r11, [rdx + 24]
        sbb     r11, [r8  + 24]
        sbb     r12, r12                  ; r12 = carry out mask

        ; rdx, r8: free

        ; Load Mod into into (rdx, r8, r13, rcx)

        add     rcx, SymCryptModulusValueOffsetAmd64

        mov     rdx, [rcx]
        mov     r8,  [rcx + 8]
        mov     r13, [rcx + 16]
        mov     rcx, [rcx + 24]

        ; Mask the value to be added to zero if there was no underflow
        and     rdx, r12
        and     r8 , r12
        and     r13, r12
        and     rcx, r12

        ; Add the (masked) modulus
        add     rax, rdx
        adc     rbx, r8
        adc     r10, r13
        adc     r11, rcx

        mov     [r9 +  0], rax
        mov     [r9 +  8], rbx
        mov     [r9 + 16], r10
        mov     [r9 + 24], r11

        BEGIN_EPILOGUE

        pop     rbx
        pop     r13
        pop     r12
        ret

        NESTED_END      SymCryptFdefModSub256Asm, _TEXT

;=================================================
; Multiplication
;

;VOID
;SYMCRYPT_CALL
;SymCryptFdefModMulMontgomery256Asm(
;    _In_                            PCSYMCRYPT_MODULUS      pMod,
;    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
;    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
;    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
;    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
;                                    SIZE_T                  cbScratch );

        NESTED_ENTRY    SymCryptFdefModMulMontgomery256Asm, _TEXT

        MULT_COMMON_PROLOGUE        ; saves all registers

        mov     rsi, rdx            ; we need rdx for the multiplication

        ; rcx = pMod
        ; rsi = pSrc1
        ; r8 = pSrc2
        ; r9 = pDst

        ; First we compute the product. The result will be in 8 registers
        ;       rdi, rbp, r10, r11, r12, r13, r14, r15

        mov     rbx, [rsi]
        xor     r10, r10
        xor     r11, r11
        xor     r12, r12

        mov     rax, [r8]
        mul     rbx
        mov     rdi, rax
        mov     rbp, rdx

        mov     rax, [r8 + 8]
        mul     rbx
        add     rbp, rax
        adc     r10, rdx

        mov     rax, [r8 + 16]
        mul     rbx
        add     r10, rax
        adc     r11, rdx

        mov     rax, [r8 + 24]
        mul     rbx
        add     r11, rax
        adc     r12, rdx

        ; Second row
        mov     rbx, [rsi + 8]
        MUL14   rbx, r8, rbp, r10, r11, r12, r15
        mov     r13, rdx

        ; third row
        mov     rbx, [rsi + 16]
        MUL14   rbx, r8, r10, r11, r12, r13, r15
        mov     r14, rdx

        ; fourth row
        mov     rbx, [rsi + 24]
        MUL14   rbx, r8, r11, r12, r13, r14, r15
        mov     r15, rdx


        ALTERNATE_ENTRY     SymCryptFdefMontgomerReduce256AsmInternal
        ; Invariant:
        ;   common prologue used
        ;   256-bit result in (rdi, rbp, r10, r11, r12, r13, r14, r15)
        ;   rcx = pmMod
        ;   r9 = peDst

        mov     r8, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]      ; inv64
        add     rcx, SymCryptModulusValueOffsetAmd64

        mov     rbx, rdi
        imul    rbx, r8             ; lower word is the same for signed & unsigned multiply; rbx = multiplicand for first row
        MUL14   rbx, rcx, rdi, rbp, r10, r11, rdi
        mov     rdi, rdx            ; Save the out carries in (eventually) (rdi, rbp, r10, r11)

        mov     rbx, rbp
        imul    rbx, r8
        MUL14   rbx, rcx, rbp, r10, r11, r12, rbp
        mov     rbp, rdx            ; Save the out carries in (eventually) (rdi, rbp, r10, r11)

        mov     rbx, r10
        imul    rbx, r8
        MUL14   rbx, rcx, r10, r11, r12, r13, r10
        mov     r10, rdx

        mov     rbx, r11
        imul    rbx, r8
        MUL14   rbx, rcx, r11, r12, r13, r14, r11
        ; mov   r11, rdx

        add     r12, rdi
        adc     r13, rbp
        adc     r14, r10
        adc     r15, rdx

        sbb     rbx, rbx        ; Carry out from final addition in mask form
    
        ; reduced value in (r12, r13, r14, r15, -rbx), and it is less than 2*Modulus

        mov     rdi, r12
        sub     rdi, [rcx]
        mov     rbp,  r13
        sbb     rbp,  [rcx + 8]
        mov     r10, r14
        sbb     r10, [rcx + 16]
        mov     r11, r15
        sbb     r11, [rcx + 24]

        sbb     rcx, rcx                 ; rcx = carry out mask

        ; Choose between the two
        ; addition carry = 1, then subtraction carry = 1 and we pick the 2nd result.
        ; addition carry = 0 and subtraction carry = 0: pick 2nd result
        ; addition carry = 0 and subtraction carry = 1: pick first result

        xor     rcx, rbx            ; 0 = 2nd result, 1 = first result               
        
        xor     r12, rdi
        xor     r13, rbp
        xor     r14, r10
        xor     r15, r11            

        and     r12, rcx
        and     r13, rcx
        and     r14, rcx
        and     r15, rcx

        xor     rdi, r12
        xor     rbp, r13
        xor     r10, r14
        xor     r11, r15

        mov     [r9 +  0], rdi
        mov     [r9 +  8], rbp
        mov     [r9 + 16], r10
        mov     [r9 + 24], r11

        MULT_COMMON_EPILOGUE

        NESTED_END      SymCryptFdefModMulMontgomery256Asm, _TEXT


;VOID
;SYMCRYPT_CALL
;SymCryptFdefMontgomeryReduce256Asm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst );

        NESTED_ENTRY    SymCryptFdefMontgomeryReduce256Asm, _TEXT

        MULT_COMMON_PROLOGUE        ; saves all registers

        mov     r9, r8
        mov     rdi, [rdx +  0]
        mov     rbp, [rdx +  8]
        mov     r10, [rdx + 16]
        mov     r11, [rdx + 24]
        mov     r12, [rdx + 32]
        mov     r13, [rdx + 40]
        mov     r14, [rdx + 48]
        mov     r15, [rdx + 56]


        ; Normal code doesn't jump from the body of one function to the body of another function.
        ; Here we have ensured that our stack frames are identical, so it is safe.
        ; We just have to convince the other system components that this works...

        ; Use conditional jump so that stack unwinder doesn't think it is an epilogue
        test    rsp,rsp
        jne     SymCryptFdefMontgomerReduce256AsmInternal       ; jumps always

        int     3       ; Dummy instruction because the debugger seems to have an off-by-one
                        ; error and still see the (wrong) epilogue when on the JNE instruction
                        ; Best guess: the debugger starts the stack trace *after* the current instruction

        ; And then we need a dummy epilogue to keep the assembler happy
        BEGIN_EPILOGUE
        ret

        NESTED_END      SymCryptFdefMontgomeryReduce256Asm, _TEXT


;VOID 
;SYMCRYPT_CALL 
;SymCryptFdefModSquareMontgomery256(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
;    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
;    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
;                                    SIZE_T                  cbScratch )

        NESTED_ENTRY    SymCryptFdefModSquareMontgomery256Asm, _TEXT

        MULT_COMMON_PROLOGUE


        ;  Result in   rdi, rbp, r10, r11, r12, r13, r14, r15

        mov     rsi, rdx        ; free up rdx for multiplication
        mov     r9, r8          ; need this later anyway

        ; rcx = pmMod
        ; rsi = Src
        ; r9 = pDst

        mov     rbx, [rsi]
        xor     r11, r11
        xor     r12, r12
        xor     r13, r13
        xor     r14, r14

        ; First we compute all the terms that need doubling

        mov     rax, [rsi + 8]
        mul     rbx
        mov     rbp, rax
        mov     r10, rdx

        mov     rax, [rsi + 16]
        mul     rbx
        add     r10, rax
        adc     r11, rdx

        mov     rax, [rsi + 24]
        mul     rbx
        add     r11, rax
        adc     r12, rdx

        mov     rbx, [rsi + 8]
        mov     rax, [rsi + 16]
        mul     rbx
        add     r11, rax
        adc     rdx, 0
        mov     r15, rdx

        mov     rax, [rsi + 24]
        mul     rbx
        add     r12, rax
        adc     rdx, 0
        add     r12, r15
        adc     r13, rdx

        mov     rbx, [rsi + 16]
        mov     rax, [rsi + 24]
        mul     rbx
        add     r13, rax
        adc     r14, rdx        ; no overflow from this
       
        ; double these terms
        xor     r15, r15

        add     rbp, rbp
        adc     r10, r10
        adc     r11, r11
        adc     r12, r12
        adc     r13, r13
        adc     r14, r14
        adc     r15, 0

        mov     rax, [rsi]
        mul     rax
        mov     rdi, rax
        mov     rbx, rdx

        mov     rax, [rsi + 8]
        mul     rax

        add     rbp, rbx
        adc     r10, rax
        adc     r11, rdx
        sbb     r8, r8          ; -carry

        mov     rax, [rsi + 16]
        mul     rax

        add     r8, r8
        adc     r12, rax
        adc     r13, rdx
        sbb     r8, r8

        mov     rax, [rsi + 24]
        mul     rax
        add     r8, r8
        adc     r14, rax
        adc     r15, rdx

        ; See SymCryptFdefMontgomeryReduce256Asm for a discussion of this strange epilogue sequence
        test    rsp,rsp
        jne     SymCryptFdefMontgomerReduce256AsmInternal       ; jumps always

        int     3

        BEGIN_EPILOGUE
        ret

        NESTED_END      SymCryptFdefModSquareMontgomery256Asm, _TEXT

; --------------------------------
; 512-bit size specific functions
; --------------------------------

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul512Asm(
;    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc1,
;    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc2,
;                                                        UINT32      nDigits,
;    _Out_writes_(2*nWords)                              PUINT32     pDst );
        NESTED_ENTRY    SymCryptFdefRawMul512Asm, _TEXT

        MULT_COMMON_PROLOGUE        ; saves all registers

        ; Basic structure:
        ;   for each word in Src1:
        ;       Dst += Src2 * word
        ; Register assignments
        ; 
        ; rax = tmp for mul
        ; rbx = word from Src1 to multiply with
        ; rcx = pSrc1  (updated in outer loop)
        ; rdx = tmp for mul
        ; rsi = pSrc2 (constant)
        ; rdi = pDst (incremented in outer loop)
        ; r8  = nDigits (constant)
        ; r9  = pDst (constant)
        ; r11 = # words left from Src1 to process
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        mov     r11, r8             ; nDigits
        shl     r11, 3              ; nDigits * 8 = # words in Src1 to process

        mov     rsi, rdx            ; rsi = pSrc2
        mov     rdi, r9             ; rdi = pDst
        mov     rbx, [rcx]          ; mulword

        xor     r12, r12            ; carry

        ; First inner loop overwrites Dst, which avoids adding the current Dst value
        MULT_SINGLEADD_128 0, rsi, rdi
        MULT_SINGLEADD_128 2, rsi, rdi
        MULT_SINGLEADD_128 4, rsi, rdi
        MULT_SINGLEADD_128 6, rsi, rdi

        mov     [rdi + 64], r12     ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1

        ALIGN   16

SymCryptFdefRawMul512AsmLoopOuter:

        lea     rcx, [rcx + 8]      ; move to next word of pSrc1
        lea     rdi, [rdi + 8]      ; move Dst pointer one word over

        mov     rbx, [rcx]          ; mulword

        xor     r12, r12            ; carry

        MULT_DOUBLEADD_128 0, rsi, rdi
        MULT_DOUBLEADD_128 2, rsi, rdi
        MULT_DOUBLEADD_128 4, rsi, rdi
        MULT_DOUBLEADD_128 6, rsi, rdi

        mov     [rdi + 64], r12    ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1
        jnz     SymCryptFdefRawMul512AsmLoopOuter

        MULT_COMMON_EPILOGUE
               
        NESTED_END      SymCryptFdefRawMul512Asm, _TEXT

; VOID
; SYMCRYPT_CALL
; SymCryptFdefRawSquareAsm(
;   _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
;                                                       UINT32      nDigits,
;   _Out_writes_(2*nWords)                              PUINT32     pDst )
        NESTED_ENTRY    SymCryptFdefRawSquare512Asm, _TEXT

        MULT_COMMON_PROLOGUE

        ; Register assignments
        ;
        ; rax = tmp for mul
        ; rbx = word from Src to multiply with
        ; rcx = outer loop pointer into pSrc
        ; rdx = tmp for mul
        ; rsi = inner loop pointer into pSrc
        ; rdi = inner loop pointer into pDst
        ; r8 = pDst (constant)
        ; r9 = nDigits (constant)
        ; r10 = outer loop pointer into pDst
        ; r11 = outer loop counter of #words left
        ; r12 = carry for even words (64 bits)
        ; r13 = inner loop counter of #words left
        ; r14 = pSrc (constant)
        ; r15 = carry for odd words (64 bits)

        mov     r9,  rdx            ; nDigits
        mov     r14, rcx            ; saving pSrc

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; First Pass - Addition of the cross products x_i*x_j with i!=j
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     r11, rdx            ; nDigits
        shl     r11, 3              ; r11 = outer #words
        mov     r10, r8             ; r10 = outer pDst

        mov     rsi, rcx            ; rsi = inner pSrc
        mov     rdi, r10            ; rdi = inner pDst

        ; Initial inner loop overwrites Dst, which avoids adding the current Dst value
        ; 7 iterations
        xor     r15, r15            ; carry = 0 (for "odd" iterations set only the r15 carry)
        mov     rbx, [rcx]          ; mulword
        mov     [rdi], r15          ; Write 0 in the first word

        SQR_SINGLEADD_64 1, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 2, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 3, rsi, rdi, r15, r12

        SQR_SINGLEADD_64 4, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 5, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 6, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 7, rsi, rdi, r15, r12

        mov     [rdi + 8*8], r12    ; write last word, cannot overflow because Dst is at least 2 digits long
        add     r10, 8              ; Skip over the first word

        ; 6 iterations
        xor     r12, r12            ; carry = 0 (for "even" iterations set only the r12 carry)
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        SQR_DOUBLEADD_64_4 2
        mov     [rdi + 6*8], r12

        ; 5 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12  ; Notice the dst_carry is r12 since all the "double" macros have r12 as src_carry
        SQR_DOUBLEADD_64_4 1
        mov     [rdi + 5*8], r12

        ; 4 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_4 0
        mov     [rdi + 4*8], r12

        ; 3 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_2 1
        mov     [rdi + 3*8], r12

        ; 2 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        mov     [rdi + 2*8], r12

        ; 1 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        mov     [rdi + 8], r12

        xor     rdx, rdx
        mov     [rdi + 16], rdx     ; Final word = 0


        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Second Pass - Shifting all results 1 bit left
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     r11, r9             ; nDigits
        mov     rdi, r8             ; pDst pointer
        shl     r11, 1              ; 2*nDigits

        ALIGN   16
SymCryptFdefRawSquare512AsmSecondPass:
        SQR_SHIFT_LEFT 0
        SQR_SHIFT_LEFT 1
        SQR_SHIFT_LEFT 2
        SQR_SHIFT_LEFT 3

        SQR_SHIFT_LEFT 4
        SQR_SHIFT_LEFT 5
        SQR_SHIFT_LEFT 6
        SQR_SHIFT_LEFT 7

        lea     rdi, [rdi + 64]
        dec     r11
        jnz     SymCryptFdefRawSquare512AsmSecondPass

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Third Pass - Adding the squares on the even columns and propagating the sum
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     rsi, r14            ; rsi = pSrc
        mov     rdi, r8             ; rdi = pDst

        xor     r12, r12

        SQR_DIAGONAL_PROP 0
        SQR_DIAGONAL_PROP 1
        SQR_DIAGONAL_PROP 2
        SQR_DIAGONAL_PROP 3
        SQR_DIAGONAL_PROP 4
        SQR_DIAGONAL_PROP 5
        SQR_DIAGONAL_PROP 6
        SQR_DIAGONAL_PROP 7

        MULT_COMMON_EPILOGUE

        NESTED_END      SymCryptFdefRawSquare512Asm, _TEXT

;VOID
;SymCryptFdefMontgomeryReduce512Asm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

        NESTED_ENTRY    SymCryptFdefMontgomeryReduce512Asm, _TEXT

        MULT_COMMON_PROLOGUE

        mov     r11, rdx        ; r11 = pSrc
        mov     ebp, [rcx + SymCryptModulusNdigitsOffsetAmd64]                  ; nDigits
        mov     r13, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64

        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        mov     edi, ebp        ; outer loop counter
        shl     edi, 3          ; edi is in words

        xor     r14d, r14d

        ; General register allocations
        ; rax = multiply result
        ; rbx = multiplier in inner loop
        ; rcx = pointer to modulus value
        ; rdx = multiply result
        ; rsi = loop counter
        ; rdi = loop counter
        ; rbp = nDigits
        ; r8 = pDst
        ; r9 = running pointer in Src
        ; r10 = running pointer in Mod
        ; r11 = pSrc (updated in outer loop)
        ; r12 = carry
        ; r13 = pmMod->tm.montgomery.inv64
        ; r14 = carry out from last word of previous loop iteration

        ALIGN   16

SymCryptFdefMontgomeryReduce512AsmOuterLoop:

        ; start decoder with a few simple instructions, including at least one that requires
        ; a uop execution and is on the critical path

        mov     rbx, [r11]                      ; fetch word of Src we want to set to zero
        mov     r10, r11
        mov     r9, rcx

        imul    rbx, r13                        ; lower word is same for signed & unsigned multiply

        mov     esi, ebp
        xor     r12d, r12d

        ; rax = mul scratch
        ; rbx = multiplier
        ; rcx = pointer to modulus value
        ; rdx = mul scratch
        ; edi = outer loop counter (words)
        ; esi = inner loop counter (digits)
        ; r9  = running ptr to modulus
        ; r10 = running ptr to input/scratch
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        MULT_DOUBLEADD_128 0, r9, r10
        MULT_DOUBLEADD_128 2, r9, r10
        MULT_DOUBLEADD_128 4, r9, r10
        MULT_DOUBLEADD_128 6, r9, r10

        lea     r10,[r10 + 64]

        add     r12, r14
        mov     r14d, 0
        adc     r14, 0
        add     r12, [r10]
        adc     r14, 0
        mov     [r10], r12

        lea     r11,[r11 + 8]

        dec     edi
        jnz     SymCryptFdefMontgomeryReduce512AsmOuterLoop

        ;
        ; Most of the work is done; now all that is left is subtract the modulus if it is smaller than the result
        ; 

        ; First we compute the pSrc result minus the modulus into the destination
        mov     esi, ebp        ; loop ctr
        mov     r10, r11        ; pSrc
        mov     r9, rcx         ; pMod
        mov     r12, r8         ; pDst

        ; Cy = 0 because the last 'sub edi,1' resulted in 0
        mov     rax,[r10]
        sbb     rax,[r9]
        mov     [r12], rax

        mov     rax,[r10 + 8]
        sbb     rax,[r9 + 8]
        mov     [r12 + 8], rax

        mov     rax,[r10 + 16]
        sbb     rax,[r9 + 16]
        mov     [r12 + 16], rax

        mov     rax,[r10 + 24]
        sbb     rax,[r9 + 24]
        mov     [r12 + 24], rax

        mov     rax,[r10 + 32]
        sbb     rax,[r9 + 32]
        mov     [r12 + 32], rax

        mov     rax,[r10 + 40]
        sbb     rax,[r9 + 40]
        mov     [r12 + 40], rax

        mov     rax,[r10 + 48]
        sbb     rax,[r9 + 48]
        mov     [r12 + 48], rax

        mov     rax,[r10 + 56]
        sbb     rax,[r9 + 56]
        mov     [r12 + 56], rax

        lea     r10,[r10 + 64]
        lea     r9,[r9 + 64]
        lea     r12,[r12 + 64]

        ; Finally a masked copy form pSrc to pDst 
        ; copy if: r14 == 0 && Cy = 1
        sbb     r14d, 0

        movd    xmm0, r14d          ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask

        ALIGN   16

SymCryptFdefMontgomeryReduce512AsmMaskedCopyLoop:
        movdqa  xmm2, [r11]         ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8]          ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8], xmm2

        movdqa  xmm2, [r11 + 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8  + 16], xmm2

        movdqa  xmm2, [r11 + 32]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8 + 32]     ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8 + 32], xmm2

        movdqa  xmm2, [r11 + 48]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 48]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8  + 48], xmm2

        ; Move on to the next digit
        lea     r11,[r11 + 64]
        lea     r8,[r8 + 64]

        dec     ebp
        jnz     SymCryptFdefMontgomeryReduce512AsmMaskedCopyLoop

        MULT_COMMON_EPILOGUE

        NESTED_END      SymCryptFdefMontgomeryReduce512Asm, _TEXT


; --------------------------------
; 1024-bit size specific functions
; --------------------------------

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul1024Asm(
;    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc1,
;    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc2,
;                                                        UINT32      nDigits,
;    _Out_writes_(2*nWords)                              PUINT32     pDst );
        NESTED_ENTRY    SymCryptFdefRawMul1024Asm, _TEXT

        MULT_COMMON_PROLOGUE        ; saves all registers

        ; Basic structure:
        ;   for each word in Src1:
        ;       Dst += Src2 * word
        ; Register assignments
        ; 
        ; rax = tmp for mul
        ; rbx = word from Src1 to multiply with
        ; rcx = pSrc1  (updated in outer loop)
        ; rdx = tmp for mul
        ; rsi = pSrc2 (constant)
        ; rdi = pDst (incremented in outer loop)
        ; r8  = nDigits (constant)
        ; r9  = pDst (constant)
        ; r11 = # words left from Src1 to process
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        mov     r11, r8             ; nDigits
        shl     r11, 3              ; nDigits * 8 = # words in Src1 to process

        mov     rsi, rdx            ; rsi = pSrc2
        mov     rdi, r9             ; rdi = pDst
        mov     rbx, [rcx]          ; mulword

        xor     r12, r12            ; carry

        ; First inner loop overwrites Dst, which avoids adding the current Dst value
        MULT_SINGLEADD_128 0, rsi, rdi
        MULT_SINGLEADD_128 2, rsi, rdi
        MULT_SINGLEADD_128 4, rsi, rdi
        MULT_SINGLEADD_128 6, rsi, rdi

        MULT_SINGLEADD_128 8, rsi, rdi
        MULT_SINGLEADD_128 10, rsi, rdi
        MULT_SINGLEADD_128 12, rsi, rdi
        MULT_SINGLEADD_128 14, rsi, rdi

        mov     [rdi + 128], r12    ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1

        ALIGN   16

SymCryptFdefRawMul1024AsmLoopOuter:

        lea     rcx, [rcx + 8]      ; move to next word of pSrc1
        lea     rdi, [rdi + 8]      ; move Dst pointer one word over

        mov     rbx, [rcx]          ; mulword

        xor     r12, r12            ; carry

        MULT_DOUBLEADD_128 0, rsi, rdi
        MULT_DOUBLEADD_128 2, rsi, rdi
        MULT_DOUBLEADD_128 4, rsi, rdi
        MULT_DOUBLEADD_128 6, rsi, rdi

        MULT_DOUBLEADD_128 8, rsi, rdi
        MULT_DOUBLEADD_128 10, rsi, rdi
        MULT_DOUBLEADD_128 12, rsi, rdi
        MULT_DOUBLEADD_128 14, rsi, rdi

        mov     [rdi + 128], r12    ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11, 1
        jnz     SymCryptFdefRawMul1024AsmLoopOuter

        MULT_COMMON_EPILOGUE
               
        NESTED_END      SymCryptFdefRawMul1024Asm, _TEXT

; VOID
; SYMCRYPT_CALL
; SymCryptFdefRawSquareAsm(
;   _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
;                                                       UINT32      nDigits,
;   _Out_writes_(2*nWords)                              PUINT32     pDst )
        NESTED_ENTRY    SymCryptFdefRawSquare1024Asm, _TEXT

        MULT_COMMON_PROLOGUE

        ; Register assignments
        ;
        ; rax = tmp for mul
        ; rbx = word from Src to multiply with
        ; rcx = outer loop pointer into pSrc
        ; rdx = tmp for mul
        ; rsi = inner loop pointer into pSrc
        ; rdi = inner loop pointer into pDst
        ; r8 = pDst (constant)
        ; r9 = nDigits (constant)
        ; r10 = outer loop pointer into pDst
        ; r11 = outer loop counter of #words left
        ; r12 = carry for even words (64 bits)
        ; r13 = inner loop counter of #words left
        ; r14 = pSrc (constant)
        ; r15 = carry for odd words (64 bits)

        mov     r9,  rdx            ; nDigits
        mov     r14, rcx            ; saving pSrc

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; First Pass - Addition of the cross products x_i*x_j with i!=j
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     r11, rdx            ; nDigits
        shl     r11, 3              ; r11 = outer #words
        mov     r10, r8             ; r10 = outer pDst

        mov     rsi, rcx            ; rsi = inner pSrc
        mov     rdi, r10            ; rdi = inner pDst

        ; Initial inner loop overwrites Dst, which avoids adding the current Dst value

        ; 15 iterations
        xor     r15, r15            ; carry = 0 (for "odd" iterations set only the r15 carry)
        mov     rbx, [rcx]          ; mulword
        mov     [rdi], r15          ; Write 0 in the first word

        SQR_SINGLEADD_64 1, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 2, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 3, rsi, rdi, r15, r12

        SQR_SINGLEADD_64 4, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 5, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 6, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 7, rsi, rdi, r15, r12

        SQR_SINGLEADD_64 8, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 9, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 10, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 11, rsi, rdi, r15, r12

        SQR_SINGLEADD_64 12, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 13, rsi, rdi, r15, r12
        SQR_SINGLEADD_64 14, rsi, rdi, r12, r15
        SQR_SINGLEADD_64 15, rsi, rdi, r15, r12

        mov     [rdi + 16*8], r12       ; write last word, cannot overflow because Dst is at least 2 digits long
        add     r10, 8                  ; Skip over the first word

        ; 14 iterations (adding the current Dst value)
        xor     r12, r12            ; carry = 0 (for "even" iterations set only the r12 carry)
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        SQR_DOUBLEADD_64_4 2
        SQR_DOUBLEADD_64_8 6
        mov     [rdi + 14*8], r12

        ; 13 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12  ; Notice the dst_carry is r12 since all the "double" macros have r12 as src_carry
        SQR_DOUBLEADD_64_4 1
        SQR_DOUBLEADD_64_8 5
        mov     [rdi + 13*8], r12

        ; 12 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_4 0
        SQR_DOUBLEADD_64_8 4
        mov     [rdi + 12*8], r12

        ; 11 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_2 1
        SQR_DOUBLEADD_64_8 3
        mov     [rdi + 11*8], r12

        ; 10 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        SQR_DOUBLEADD_64_8 2
        mov     [rdi + 10*8], r12


        ; 9 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_8 1
        mov     [rdi + 9*8], r12

        ; 8 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_8 0
        mov     [rdi + 8*8], r12

        ; 7 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_2 1
        SQR_DOUBLEADD_64_4 3
        mov     [rdi + 7*8], r12

        ; 6 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        SQR_DOUBLEADD_64_4 2
        mov     [rdi + 6*8], r12

        ; 5 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_4 1
        mov     [rdi + 5*8], r12

        ; 4 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_4 0
        mov     [rdi + 4*8], r12

        ; 3 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        SQR_DOUBLEADD_64_2 1
        mov     [rdi + 3*8], r12

        ; 2 iterations
        xor     r12, r12
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64_2 0
        mov     [rdi + 2*8], r12

        ; 1 iterations
        xor     r15, r15
        SQR_SIZE_SPECIFIC_INIT
        SQR_DOUBLEADD_64 0, rsi, rdi, r15, r12
        mov     [rdi + 8], r12

        xor     rdx, rdx
        mov     [rdi + 16], rdx     ; Final word = 0


        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Second Pass - Shifting all results 1 bit left
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        xor rax, rax                ; carry flag = 0
        ; mov     r11, r9             ; nDigits
        mov     rdi, r8             ; pDst pointer
        ; shl     r11, 1              ; 2*nDigits

        ; ALIGN   16
; SymCryptFdefRawSquare1024AsmSecondPass:
        SQR_SHIFT_LEFT 0
        SQR_SHIFT_LEFT 1
        SQR_SHIFT_LEFT 2
        SQR_SHIFT_LEFT 3

        SQR_SHIFT_LEFT 4
        SQR_SHIFT_LEFT 5
        SQR_SHIFT_LEFT 6
        SQR_SHIFT_LEFT 7

        SQR_SHIFT_LEFT 8
        SQR_SHIFT_LEFT 9
        SQR_SHIFT_LEFT 10
        SQR_SHIFT_LEFT 11

        SQR_SHIFT_LEFT 12
        SQR_SHIFT_LEFT 13
        SQR_SHIFT_LEFT 14
        SQR_SHIFT_LEFT 15

        SQR_SHIFT_LEFT 16
        SQR_SHIFT_LEFT 17
        SQR_SHIFT_LEFT 18
        SQR_SHIFT_LEFT 19

        SQR_SHIFT_LEFT 20
        SQR_SHIFT_LEFT 21
        SQR_SHIFT_LEFT 22
        SQR_SHIFT_LEFT 23

        SQR_SHIFT_LEFT 24
        SQR_SHIFT_LEFT 25
        SQR_SHIFT_LEFT 26
        SQR_SHIFT_LEFT 27

        SQR_SHIFT_LEFT 28
        SQR_SHIFT_LEFT 29
        SQR_SHIFT_LEFT 30
        SQR_SHIFT_LEFT 31

        ; lea     rdi, [rdi + 64]
        ; dec     r11
        ; jnz     SymCryptFdefRawSquare1024AsmSecondPass

        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Third Pass - Adding the squares on the even columns and propagating the sum
        ; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     rsi, r14            ; rsi = pSrc
        mov     rdi, r8             ; rdi = pDst

        xor     r12, r12

        SQR_DIAGONAL_PROP 0
        SQR_DIAGONAL_PROP 1
        SQR_DIAGONAL_PROP 2
        SQR_DIAGONAL_PROP 3
        SQR_DIAGONAL_PROP 4
        SQR_DIAGONAL_PROP 5
        SQR_DIAGONAL_PROP 6
        SQR_DIAGONAL_PROP 7

        SQR_DIAGONAL_PROP 8
        SQR_DIAGONAL_PROP 9
        SQR_DIAGONAL_PROP 10
        SQR_DIAGONAL_PROP 11
        SQR_DIAGONAL_PROP 12
        SQR_DIAGONAL_PROP 13
        SQR_DIAGONAL_PROP 14
        SQR_DIAGONAL_PROP 15

        MULT_COMMON_EPILOGUE

        NESTED_END      SymCryptFdefRawSquare1024Asm, _TEXT

;VOID
;SymCryptFdefMontgomeryReduce1024Asm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

        NESTED_ENTRY    SymCryptFdefMontgomeryReduce1024Asm, _TEXT

        MULT_COMMON_PROLOGUE

        mov     r11, rdx        ; r11 = pSrc
        mov     ebp, [rcx + SymCryptModulusNdigitsOffsetAmd64]                  ; nDigits
        mov     r13, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64

        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        mov     edi, ebp        ; outer loop counter
        shl     edi, 3          ; edi is in words

        xor     r14d, r14d

        ; General register allocations
        ; rax = multiply result
        ; rbx = multiplier in inner loop
        ; rcx = pointer to modulus value
        ; rdx = multiply result
        ; rsi = loop counter
        ; rdi = loop counter
        ; rbp = nDigits
        ; r8 = pDst
        ; r9 = running pointer in Src
        ; r10 = running pointer in Mod
        ; r11 = pSrc (updated in outer loop)
        ; r12 = carry
        ; r13 = pmMod->tm.montgomery.inv64
        ; r14 = carry out from last word of previous loop iteration

        ALIGN   16

SymCryptFdefMontgomeryReduce1024AsmOuterLoop:

        ; start decoder with a few simple instructions, including at least one that requires
        ; a uop execution and is on the critical path

        mov     rbx, [r11]                      ; fetch word of Src we want to set to zero
        mov     r10, r11
        mov     r9, rcx

        imul    rbx, r13                        ; lower word is same for signed & unsigned multiply

        mov     esi, ebp
        xor     r12d, r12d

        ; rax = mul scratch
        ; rbx = multiplier
        ; rcx = pointer to modulus value
        ; rdx = mul scratch
        ; edi = outer loop counter (words)
        ; esi = inner loop counter (digits)
        ; r9  = running ptr to modulus
        ; r10 = running ptr to input/scratch
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        MULT_DOUBLEADD_128 0, r9, r10
        MULT_DOUBLEADD_128 2, r9, r10
        MULT_DOUBLEADD_128 4, r9, r10
        MULT_DOUBLEADD_128 6, r9, r10

        MULT_DOUBLEADD_128 8, r9, r10
        MULT_DOUBLEADD_128 10, r9, r10
        MULT_DOUBLEADD_128 12, r9, r10
        MULT_DOUBLEADD_128 14, r9, r10

        lea     r10,[r10 + 128]

        add     r12, r14
        mov     r14d, 0
        adc     r14, 0
        add     r12, [r10]
        adc     r14, 0
        mov     [r10], r12

        lea     r11,[r11 + 8]

        dec     edi
        jnz     SymCryptFdefMontgomeryReduce1024AsmOuterLoop

        ;
        ; Most of the work is done; now all that is left is subtract the modulus if it is smaller than the result
        ; 

        ; First we compute the pSrc result minus the modulus into the destination
        mov     esi, ebp        ; loop ctr
        mov     r10, r11        ; pSrc
        mov     r9, rcx         ; pMod
        mov     r12, r8         ; pDst

        ; Cy = 0 because the last 'sub edi,1' resulted in 0

        ALIGN   16

SymCryptFdefMontgomeryReduce1024AsmSubLoop:
        mov     rax,[r10]
        sbb     rax,[r9]
        mov     [r12], rax

        mov     rax,[r10 + 8]
        sbb     rax,[r9 + 8]
        mov     [r12 + 8], rax

        mov     rax,[r10 + 16]
        sbb     rax,[r9 + 16]
        mov     [r12 + 16], rax

        mov     rax,[r10 + 24]
        sbb     rax,[r9 + 24]
        mov     [r12 + 24], rax

        mov     rax,[r10 + 32]
        sbb     rax,[r9 + 32]
        mov     [r12 + 32], rax

        mov     rax,[r10 + 40]
        sbb     rax,[r9 + 40]
        mov     [r12 + 40], rax

        mov     rax,[r10 + 48]
        sbb     rax,[r9 + 48]
        mov     [r12 + 48], rax

        mov     rax,[r10 + 56]
        sbb     rax,[r9 + 56]
        mov     [r12 + 56], rax

        lea     r10,[r10 + 64]
        lea     r9,[r9 + 64]
        lea     r12,[r12 + 64]

        dec     esi
        jnz     SymCryptFdefMontgomeryReduce1024AsmSubLoop

        ; Finally a masked copy form pSrc to pDst 
        ; copy if: r14 == 0 && Cy = 1
        sbb     r14d, 0

        movd    xmm0, r14d          ; xmm0[0] = mask
        pcmpeqd xmm1, xmm1          ; xmm1 = ff...ff
        pshufd  xmm0, xmm0, 0       ; xmm0[0..3] = mask
        pxor    xmm1, xmm0          ; xmm1 = not Mask

        ALIGN   16

SymCryptFdefMontgomeryReduce1024AsmMaskedCopyLoop:
        movdqa  xmm2, [r11]         ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8]          ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8], xmm2

        movdqa  xmm2, [r11 + 16]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 16]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8  + 16], xmm2

        movdqa  xmm2, [r11 + 32]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8 + 32]     ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8 + 32], xmm2

        movdqa  xmm2, [r11 + 48]    ; xmm2 = pSrc[0]
        movdqa  xmm3, [r8  + 48]    ; xmm3 = pDst[0]
        pand    xmm2, xmm0          ;
        pand    xmm3, xmm1          ;
        por     xmm2, xmm3
        movdqa  [r8  + 48], xmm2

        ; Move on to the next digit
        lea     r11,[r11 + 64]
        lea     r8,[r8 + 64]

        dec     ebp
        jnz     SymCryptFdefMontgomeryReduce1024AsmMaskedCopyLoop

        MULT_COMMON_EPILOGUE

        NESTED_END      SymCryptFdefMontgomeryReduce1024Asm, _TEXT

        end
