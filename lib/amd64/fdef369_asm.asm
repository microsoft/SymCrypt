;
;  fdef_369asm.asm   Assembler code for large integer arithmetic in the default data format
;
; This file contains alternative routines that are used for modular computations
; where the modulus is 257-384 or 513-576 bits long.
; (Currently on ARM64 it is also used for 0-192-bit moduli but not on AMD64)
;
; The immediate advantage is that it improves EC performance on 384, and 521-bit curves.
;
; Most of this code is a direct copy of the default code.
; AMD64 digits are now 512 bits.
; We read the 'ndigit' value. If it is 1 digit, the values are 6 64-bit words, if it is 2 the values
; are 9 64-bit words. As we compute in groups of 3, our loop counters are one more than nDigit
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;

include ksamd64.inc

include ..\inc\symcrypt_version.inc
include symcrypt_magic.inc



include C_asm_shared.inc

; A digit consists of 4 words of 64 bits each

;UINT32
;SYMCRYPT_CALL
;SymCryptFdef369RawAddAsm(
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
;    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
;                                                            UINT32      nDigits );

        LEAF_ENTRY SymCryptFdef369RawAddAsm, _TEXT

        ; rcx = Src1
        ; rdx = Src2
        ; r8 = Dst
        ; r9 = nDigits
        
        add     r9, 1
        xor     rax, rax
        xor     r10, r10

        ; Cy = 0

SymCryptFdef369RawAddAsmLoop:
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
        
        lea     rcx, [rcx + 24]
        lea     rdx, [rdx + 24]
        lea     r8,  [r8  + 24]
        dec     r9d
        jnz     SymCryptFdef369RawAddAsmLoop

        mov     rax, r10
        adc     rax, r10
                
        ret
        
        LEAF_END SymCryptFdef369RawAddAsm, _TEXT


;UINT32
;SYMCRYPT_CALL
;SymCryptFdefRawSubAsm(
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
;    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
;                                                            UINT32      nDigits );

        LEAF_ENTRY SymCryptFdef369RawSubAsm, _TEXT

        ; rcx = Src1
        ; rdx = Src2
        ; r8 = Dst
        ; r9 = nDigits
 
        add     r9, 1
        xor     rax, rax
        xor     r10, r10

SymCryptFdef369RawSubAsmLoop:
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
        
        lea     rcx, [rcx + 24]
        lea     rdx, [rdx + 24]
        lea     r8,  [r8  + 24]
        dec     r9d
        jnz     SymCryptFdef369RawSubAsmLoop

        mov     rax, r10
        adc     rax, r10
                
        ret
        
        LEAF_END SymCryptFdef369RawSubAsm, _TEXT



;VOID
;SYMCRYPT_CALL
;SymCryptFdefMaskedCopy(
;    _In_reads_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )      PCBYTE      pbSrc,
;    _InOut_writes_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )  PBYTE       pbDst,
;                                                                UINT32      nDigits,
;                                                                UINT32      mask )

    LEAF_ENTRY  SymCryptFdef369MaskedCopyAsm, _TEXT

        add     r8d, 1
        movsxd  r9, r9d     

SymCryptFdef369MaskedCopyAsmLoop:
        mov     rax, [rcx]
        mov     r10, [rdx]
        xor     rax, r10
        and     rax, r9
        xor     rax, r10
        mov     [rdx], rax

        mov     rax, [rcx + 8]
        mov     r10, [rdx + 8]
        xor     rax, r10
        and     rax, r9
        xor     rax, r10
        mov     [rdx + 8], rax

        mov     rax, [rcx + 16]
        mov     r10, [rdx + 16]
        xor     rax, r10
        and     rax, r9
        xor     rax, r10
        mov     [rdx + 16], rax

        ; Move on to the next digit

        add     rcx, 24
        add     rdx, 24
        sub     r8d, 1
        jnz     SymCryptFdef369MaskedCopyAsmLoop
        ret

        LEAF_END SymCryptFdef369MaskedCopyAsm, _TEXT

;VOID
;SYMCRYPT_CALL
;SymCryptFdefRawMul(
;    _In_reads_(nWords1)             PCUINT32    pSrc1,
;                                    UINT32      nDigits1,
;    _In_reads_(nWords2)             PCUINT32    pSrc2,
;                                    UINT32      nDigits2,
;    _Out_writes_(nWords1 + nWords2) PUINT32     pDst )

SymCryptFdef369RawMulAsm_Frame struct
        SavedRbx        dq  ?
        SavedRdi        dq  ?
        SavedRsi        dq  ?
        SavedR13        dq  ?
        SavedR12        dq  ?
        returnaddress   dq  ?
        Arg1Home        dq  ?
        Arg2Home        dq  ?
        Arg3Home        dq  ?
        Arg4Home        dq  ?
        pDst            dq  ?

SymCryptFdef369RawMulAsm_Frame        ends

        NESTED_ENTRY    SymCryptFdef369RawMulAsm, _TEXT

        rex_push_reg    rbx
        push_reg        r12
        push_reg        r13
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
        ; r12 = carry
        ; r13 = inner loop counter


        add     edx, 1
        add     r9d, 1
        lea     r11d, [edx + 2*edx]  ; nDigits1 * 3 = # words in Src1 to process
        mov     r10, [rsp + SymCryptFdef369RawMulAsm_Frame.pDst ]

        ; Outer loop invariant established: rcx, r8, r9, r10


        mov     rsi, r8             ; rsi = pSrc2
        mov     rdi, r10            ; rdi = pDst + outer loop ctr
        mov     rbx, [rcx]          ; mulword
        xor     r12, r12
        mov     r13d, r9d

        ; First inner loop overwrites Dst, which avoids adding the current Dst value

SymCryptFdef369RawMulAsmLoop1:
        mov     rax, [rsi]
        mul     rbx
        add     rax, r12
        adc     rdx, 0
        mov     [rdi], rax
        mov     r12, rdx

        mov     rax, [rsi + 8]
        mul     rbx
        add     rax, r12
        adc     rdx, 0
        mov     [rdi + 8], rax
        mov     r12, rdx

        mov     rax, [rsi + 16]
        mul     rbx
        add     rax, r12
        adc     rdx, 0
        mov     [rdi + 16], rax
        mov     r12, rdx

        add     rsi, 24
        add     rdi, 24
        sub     r13d,1
        jnz     SymCryptFdef369RawMulAsmLoop1

        mov     [rdi], rdx              ; write last word, cannot overflow because Dst is at least 2 digits long

        sub     r11d, 1

SymCryptFdef369RawMulAsmLoopOuter:

        add     rcx, 8                  ; move to next word of pSrc1
        add     r10, 8                  ; move Dst pointer one word over
        mov     rbx, [rcx]
        mov     rsi, r8
        mov     rdi, r10
        xor     r12, r12
        mov     r13d, r9d

SymCryptFdef369RawMulAsmLoop2:
        mov     rax, [rsi]
        mul     rbx
        add     rax, [rdi]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [rdi], rax
        mov     r12, rdx

        mov     rax, [rsi + 8]
        mul     rbx
        add     rax, [rdi + 8]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [rdi + 8], rax
        mov     r12, rdx

        mov     rax, [rsi + 16]
        mul     rbx
        add     rax, [rdi + 16]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [rdi + 16], rax
        mov     r12, rdx

        add     rsi, 24
        add     rdi, 24
        sub     r13d,1
        jnz     SymCryptFdef369RawMulAsmLoop2

        mov     [rdi], rdx          ; write next word. (stays within Dst buffer)

        sub     r11d, 1
        jnz     SymCryptFdef369RawMulAsmLoopOuter

        BEGIN_EPILOGUE

        pop     rdi
        pop     rsi
        pop     r13
        pop     r12
        pop     rbx
        ret
               
    NESTED_END      SymCryptFdef369RawMulAsm, _TEXT






;VOID
;SymCryptFdefMontgomeryReduceAsm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )

        NESTED_ENTRY    SymCryptFdef369MontgomeryReduceAsm, _TEXT

        rex_push_reg    rbx
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        rsi
        push_reg        rdi
        push_reg        rbp
        
        END_PROLOGUE

        mov     r11, rdx        ; r11 = pSrc
        mov     ebp, [rcx + SymCryptModulusNdigitsOffsetAmd64]                  ; nDigits
        add     ebp, 1
        mov     r13, [rcx + SymCryptModulusMontgomeryInv64OffsetAmd64]          ; inv64

        lea     rcx, [rcx + SymCryptModulusValueOffsetAmd64]                    ; modulus value

        lea     edi, [ebp + 2*ebp]  ; outer loop counter, in words

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


SymCryptFdef369MontgomeryReduceAsmOuterLoop:

        ; start decoder with a few simple instructions, including at least one that requires
        ; a uop execution and is on the critical path

        mov     rbx, [r11]                      ; fetch word of Src we want to set to zero
        mov     r10, r11
        mov     r9, rcx

        imul    rbx, r13                        ; lower word is same for signed & unsigned multiply

        mov     esi, ebp
        xor     r12d, r12d

SymCryptFdef369MontgomeryReduceAsmInnerloop:
        ; rax = mul scratch
        ; rbx = multiplier
        ; rcx = pointer to modulus value
        ; rdx = mul scratch
        ; edi = outer loop counter (words)
        ; esi = inner loop counter (digits)
        ; r9  = running ptr to modulus
        ; r10 = running ptr to input/scratch
        ; r12 = carry (64 bits)

        mov     rax, [r9]
        mul     rbx
        add     rax, [r10]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [r10], rax
        mov     r12, rdx

        mov     rax, [r9 + 8]
        mul     rbx
        add     rax, [r10 + 8]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [r10 + 8], rax
        mov     r12, rdx

        mov     rax, [r9 + 16]
        mul     rbx
        add     rax, [r10 + 16]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [r10 + 16], rax
        mov     r12, rdx

        add     r9, 24
        add     r10, 24
        sub     esi,1
        jnz     SymCryptFdef369MontgomeryReduceAsmInnerloop

        add     r12, r14
        mov     r14d, 0
        adc     r14, 0
        add     r12, [r10]
        adc     r14, 0
        mov     [r10], r12

        add     r11, 8

        sub     edi, 1
        jnz     SymCryptFdef369MontgomeryReduceAsmOuterLoop

        ;
        ; Most of the work is done; now all that is left is subtract the modulus if it is smaller than the result
        ; 

        ; First we compute the pSrc result minus the modulus into the destination
        mov     esi, ebp        ; loop ctr
        mov     r10, r11        ; pSrc
        mov     r9, rcx         ; pMod
        mov     r12, r8         ; pDst

        ; Cy = 0 because the last 'sub edi,1' resulted in 0

SymCryptFdef369MontgomeryReduceAsmSubLoop:
        mov     rax,[r10]
        sbb     rax,[r9]
        mov     [r12], rax

        mov     rax,[r10 + 8]
        sbb     rax,[r9 + 8]
        mov     [r12 + 8], rax

        mov     rax,[r10 + 16]
        sbb     rax,[r9 + 16]
        mov     [r12 + 16], rax

        lea     r10,[r10+24]
        lea     r9, [r9 +24]
        lea     r12,[r12+24]
        dec     esi
        jnz     SymCryptFdef369MontgomeryReduceAsmSubLoop

        ; Finally a masked copy form pSrc to pDst 
        ; copy if: r14 == 0 && Cy = 1
        sbb     r14, 0              ; mask (64 bits)


SymCryptFdef369MontgomeryReduceAsmMaskedCopyLoop:
        mov     rax, [r11]
        mov     rsi, [r8]
        xor     rax, rsi
        and     rax, r14
        xor     rax, rsi
        mov     [r8], rax

        mov     rax, [r11 + 8]
        mov     rsi, [r8 + 8]
        xor     rax, rsi
        and     rax, r14
        xor     rax, rsi
        mov     [r8 + 8], rax

        mov     rax, [r11 + 16]
        mov     rsi, [r8 + 16]
        xor     rax, rsi
        and     rax, r14
        xor     rax, rsi
        mov     [r8 + 16], rax

        ; Move on to the next digit

        add     r11, 24
        add     r8, 24
        sub     ebp, 1
        jnz     SymCryptFdef369MontgomeryReduceAsmMaskedCopyLoop

        BEGIN_EPILOGUE

        pop     rbp
        pop     rdi
        pop     rsi
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret
               
    NESTED_END      SymCryptFdef369MontgomeryReduceAsm, _TEXT

        end

