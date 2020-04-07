;
;  fdef_369asm.asm   Assembler code for large integer arithmetic in the default data format
;
; This file contains alternative routines that pretend that each digit is only 3 words.
; This gets used if the number is 1, 2, 3, 5, 6, or 9 digits long.
; The immediate advantage is that it improves EC performance on 192, 384, and 521-bit curves.
;
; Most of this code is a direct copy of the default code.
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;

#include "ksarm64.h"

#include "symcrypt_version.inc"
#include "symcrypt_magic.inc"

#include "C_asm_shared.inc"

; A digit consists of 3 words of 64 bits each

;UINT32
;SYMCRYPT_CALL
; SymCryptFdef369RawAdd(
;   _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
;   _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
;   _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
;                                                           UINT32      nDigits );
;
; Initial inputs to registers:
;       pSrc1       -> x0
;       pSrc2       -> x1
;       pDst        -> x2
;       nDigits     -> x3

    LEAF_ENTRY A64NAME(SymCryptFdef369RawAddAsm)

    neg     x3, x3                  ; negate the digit count
    ands    x4, x4, x4              ; Zero the carry flag

SymCryptFdef369RawAddAsmLoop
    add     x3, x3, #1              ; Increment the digit count by one
    ; carry is in the carry flag

    ldp     x4, x6, [x0], #16       ; Load two words of pSrc1
    ldp     x5, x7, [x1], #16       ; Load two words of pSrc2
    adcs    x4, x4, x5
    adcs    x6, x6, x7
    stp     x4, x6, [x2], #16       ; Store the result in the destination

    ldr     x4, [x0], #8
    ldr     x5, [x1], #8
    adcs    x4, x4, x5
    str     x4, [x2], #8

    cbnz    x3, SymCryptFdef369RawAddAsmLoop

    csetcs  x0                      ; Set the return value equal to the carry

    ret

    LEAF_END A64NAME(SymCryptFdef369RawAddAsm)

;UINT32
;SYMCRYPT_CALL
;SymCryptFdef369RawSub(
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
;    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
;    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
;                                                            UINT32      nDigits )
;
; Initial inputs to registers:
;       pSrc1       -> x0
;       pSrc2       -> x1
;       pDst        -> x2
;       nDigits     -> x3

    LEAF_ENTRY A64NAME(SymCryptFdef369RawSubAsm)

    neg     x3, x3                  ; negate the digit count
    subs    x4, x4, x4              ; Set the carry flag (i.e. no borrow)

SymCryptFdef369RawSubAsmLoop
    add     x3, x3, #1              ; Increment the digit count by one
    ; borrow is in the carry flag (flipped)

    ldp     x4, x6, [x0], #16       ; Load two words of pSrc1
    ldp     x5, x7, [x1], #16       ; Load two words of pSrc2
    sbcs    x4, x4, x5
    sbcs    x6, x6, x7
    stp     x4, x6, [x2], #16       ; Store the result in the destination

    ldr     x4, [x0], #8
    ldr     x5, [x1], #8
    sbcs    x4, x4, x5
    str     x4, [x2], #8

    cbnz    x3, SymCryptFdef369RawSubAsmLoop

    csetcc  x0                      ; If the carry is clear (borrow), set the return value to 1

    ret

    LEAF_END A64NAME(SymCryptFdef369RawSubAsm)

;VOID
;SYMCRYPT_CALL
;SymCryptFdef369MaskedCopy(
;    _In_reads_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )      PCBYTE      pbSrc,
;    _InOut_writes_bytes_( nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )  PBYTE       pbDst,
;                                                                UINT32      nDigits,
;                                                                UINT32      mask )

    LEAF_ENTRY A64NAME(SymCryptFdef369MaskedCopyAsm)

    neg     x2, x2                  ; negate the digit count
    subs    x4, XZR, x3             ; If (x3 > 0) clear the carry flag (i.e. borrow)

SymCryptFdef369MaskedCopyAsmLoop
    add     x2, x2, #1              ; Increment the digit count by one

    ldp     x4, x6, [x0], #16       ; Load two words of the source
    ldp     x5, x7, [x1]            ; Load two words of the destination
    cselcc  x4, x4, x5              ; If the carry is clear, select the source operands
    cselcc  x6, x6, x7
    stp     x4, x6, [x1], #16       ; Store the two words in the destination

    ldr     x4, [x0], #8
    ldr     x5, [x1]
    cselcc  x4, x4, x5
    str     x4, [x1], #8

    cbnz    x2, SymCryptFdef369MaskedCopyAsmLoop

    ; Done, no return value

    ret

    LEAF_END A64NAME(SymCryptFdef369MaskedCopyAsm)

;VOID
;SYMCRYPT_CALL
;SymCryptFdef369RawMul(
;    _In_reads_(nWords1)             PCUINT32    pSrc1,
;                                    UINT32      nDigits1,
;    _In_reads_(nWords2)             PCUINT32    pSrc2,
;                                    UINT32      nDigits2,
;    _Out_writes_(nWords1 + nWords2) PUINT32     pDst )
;
; Initial inputs to registers:
;       pSrc1       -> x0
;       nDigits1    -> x1
;       pSrc2       -> x2
;       nDigits2    -> x3
;       pDst        -> x4
;
; Basic structure:
;   for each word in Src1:
;       Dst += Src2 * word
;
; Register assignments
;       x0  = pSrc1 (moving forward one word every outer loop)
;       x1  = negated word count of pSrc1
;       x2  = pSrc2 (moving forward one *digit* every inner loop)
;       x3  = negated digit count of pSrc2 and pDst
;       x4  = pDst (moving forward one *digit* every inner loop)
;       x5  = Stored pDst (moving forward one word every outer loop)
;       x6  = Current word loaded from pSrc1
;       x8, x9   = Current words loaded in pairs from pSrc2
;       x10, x11 = Current words loaded in pairs from pDst
;       x12, x15 = "128-bit" sliding register to hold the result of multiplies
;       x16 = Stored pSrc2
;       x17 = Stored negated digit count of pSrc2
; Note x13, x14 are reserved in ARM64EC and thus are not used


    LEAF_ENTRY A64NAME(SymCryptFdef369RawMulAsm)

    add     x1, x1, x1, LSL #1          ; Calculate word count (x1 * 3)

    neg     x1, x1                      ; negate nWords1
    neg     x3, x3                      ; negate nDigits2

    mov     x5, x4                      ; store pDst
    mov     x16, x2                     ; store pSrc2
    mov     x17, x3                     ; store -nDigits2 for later

    ;
    ; First iteration of main loop (no adding of previous values from pDst)
    ;
    ands    x15, x15, XZR               ; Clearing the carry flag and setting x15 = 0
    ldr     x6, [x0]                    ; load the first word from pSrc1

SymCryptFdef369RawMulAsmLoopInner1
    add     x3, x3, #1                  ; move one digit up

    ldp     x8, x9, [x2], #16           ; load 2 words from pSrc2

    mul     x12, x6, x8                 ; Bits <63:0> of pSrc1[0]*pSrc2[j]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x8                 ; Bits <127:64> of pSrc1[0]*pSrc2[j]
    str     x12, [x4], #8               ; Store to destination

    mul     x12, x6, x9                 ; Bits <63:0> of pSrc1[0]*pSrc2[j+1]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x9                 ; Bits <127:64> of pSrc1[0]*pSrc2[j+1]
    str     x12, [x4], #8               ; Store to destination

    ldr     x8, [x2], #8

    mul     x12, x6, x8                 ; Bits <63:0> of pSrc1[0]*pSrc2[j+2]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x8                 ; Bits <127:64> of pSrc1[0]*pSrc2[j+2]
    str     x12, [x4], #8               ; Store to destination
    
    cbnz    x3, SymCryptFdef369RawMulAsmLoopInner1

    adc     x15, x15, XZR               ; Store the next word into the destination (with the carry if any)
    str     x15, [x4]

    add     x1, x1, #1                  ; move one word up
    add     x0, x0, #8                  ; move start of pSrc1 one word up
    add     x5, x5, #8                  ; move start of pDst one word up

    ;
    ; MAIN LOOP
    ;
SymCryptFdef369RawMulAsmLoopOuter
    mov     x3, x17                     ; set -nDigits2
    mov     x2, x16                     ; set pSrc2
    mov     x4, x5                      ; set pDst

    ands    x15, x15, XZR               ; Clearing the carry flag and setting x15 = 0
    ldr     x6, [x0]                    ; load the next word from pSrc1

SymCryptFdef369RawMulAsmLoopInner
    add     x3, x3, #1                  ; move one digit up

    ldp     x8, x9, [x2], #16           ; load 2 words from pSrc2
    ldp     x10, x11, [x4]              ; load 2 words from pDst

    mul     x12, x6, x8                 ; Bits <63:0> of pSrc1[i]*pSrc2[j]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x8                 ; Bits <127:64> of pSrc1[i]*pSrc2[j]
    adc     x15, x15, XZR               ; Add the carry if any and don't update the flags
                                        ; Note: this cannot overflow as the maximum for <x15:x12> is (2^64-1)(2^64-1)+(2^64-1)+1 = 2^128 - 2^64 + 1
    adds    x12, x12, x10               ; add the word from the destination and update the flags (this can overflow)
    str     x12, [x4], #8               ; Store to destination

    mul     x12, x6, x9                 ; Bits <63:0> of pSrc1[i]*pSrc2[j+1]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x9                 ; Bits <127:64> of pSrc1[i]*pSrc2[j+1]
    adc     x15, x15, XZR               ; Add the carry if any and don't update the flags
    adds    x12, x12, x11               ; add the word from the destination and update the flags (this can overflow)
    str     x12, [x4], #8               ; Store to destination

    ldr     x8, [x2], #8
    ldr     x10, [x4]

    mul     x12, x6, x8                 ; Bits <63:0> of pSrc1[i]*pSrc2[j+2]
    adcs    x12, x12, x15               ; Adding the previous word (if there was a carry from the last addition it is added)
    umulh   x15, x6, x8                 ; Bits <127:64> of pSrc1[i]*pSrc2[j+2]
    adc     x15, x15, XZR               ; Add the carry if any and don't update the flags
    adds    x12, x12, x10               ; add the word from the destination and update the flags (this can overflow)
    str     x12, [x4], #8               ; Store to destination

    cbnz    x3, SymCryptFdef369RawMulAsmLoopInner

    adc     x15, x15, XZR               ; Store the next word into the destination (with the carry if any)
    str     x15, [x4]

    adds    x1, x1, #1                  ; move one word up
    add     x0, x0, #8                  ; move start of pSrc1 one word up
    add     x5, x5, #8                  ; move start of pDst one word up

    bne     SymCryptFdef369RawMulAsmLoopOuter

    ; Done, no return value

    ret

    LEAF_END A64NAME(SymCryptFdef369RawMulAsm)

;VOID
;SymCryptFdef369MontgomeryReduceAsm(
;    _In_                            PCSYMCRYPT_MODULUS      pmMod,
;    _In_                            PUINT32                 pSrc,
;    _Out_                           PUINT32                 pDst )
;
; Initial inputs to registers:
;       pmMod       -> x0
;       pSrc        -> x1
;       pDst        -> x2
;
; Register assignments
;       x0  = pMod (moving forward one *digit* every inner loop)
;       x1  = pSrc (moving forward one *digit* every inner loop)
;       x2  = pDst (used only in the end for subtract / result)
;       x3  = negated digit count of pSrc and pMod
;       x4  = negated word count of pSrc
;       x5  = Inv64 of the modulus
;       x6  = m = pSrc[i]*Inv64
;       x7  = hc = high carry variable
;       x8, x9   = Current words loaded in pairs from pSrc
;       x10, x11 = Current words loaded in pairs from pMod
;       x12, x15 = c variable = "128-bit" sliding register to hold the result of multiplies
;       x16 = Temporary intermediate result
;       x17 = Stored negated digit count of pSrc
;       x19 = Stored pMod pointer
;       x20 = Stored pSrc pointer (moving forward one word every outer loop)
; Note x13, x14 are reserved in ARM64EC and thus are not used

    NESTED_ENTRY SymCryptFdef369MontgomeryReduceAsm
    PROLOG_SAVE_REG_PAIR fp, lr, #-32!  ; allocate 32 bytes of stack; store FP/LR
    PROLOG_SAVE_REG_PAIR x19, x20, #16  ; free up x19/x20

    ldr     w3, [x0, #SymCryptModulusNdigitsOffsetArm64]            ; # of Digits
    ldr     x5, [x0, #SymCryptModulusMontgomeryInv64OffsetArm64]    ; Inv64 of modulus
    add     x0, x0, #SymCryptModulusValueOffsetArm64                ; pMod

    add     x4, x3, x3, LSL #1          ; Calculate word count (x3 * 3)

    neg     x3, x3                      ; Negate the digit count
    neg     x4, x4                      ; Negate the word count

    mov     x17, x3                     ; Store the digit count for later
    mov     x19, x0                     ; Store the pMod pointer
    mov     x20, x1                     ; Store the pSrc pointer

    ands    x7, x7, XZR                 ; Set hc to 0

    ;
    ; Main loop
    ;
SymCryptFdef369MontgomeryReduceAsmOuter
    ldr     x8, [x1]                    ; Load 1 word from pSrc
    mul     x6, x8, x5                  ; <63:0> bits of pSrc[i]*Inv64 = m

    ands    x12, x12, XZR               ; Set c to 0
    ands    x15, x15, XZR               ; Set c to 0

SymCryptFdef369MontgomeryReduceAsmInner
    ldp     x10, x11, [x0], #16         ; pMod[j]
    ldp     x8, x9, [x1]                ; pSrc[j]

    mul     x16, x6, x10                ; <63:0> of pMod[j]*m
    adds    x16, x16, x8                ; Adding pSrc[j]
    umulh   x15, x6, x10                ; <127:64> of pMod[j]*m
    adc     x15, x15, XZR               ; Add the carry if any (***)
    adds    x12, x12, x16               ; Add the lower bits of c
    adc     x15, x15, XZR               ; Add the carry if any (***)
    ; ***: These cannot produce extra carry as the maximum is
    ;      (2^64 - 1)*(2^64-1) + 2^64-1 + 2^64-1 = 2^128 - 1
    str     x12, [x1], #8               ; pSrc[j] = (UINT64) c
    mov     x12, x15                    ; c >>= 64

    mul     x16, x6, x11                ; <63:0> of pMod[j]*m
    adds    x16, x16, x9                ; Adding pSrc[j]
    umulh   x15, x6, x11                ; <127:64> of pMod[j]*m
    adc     x15, x15, XZR               ; Add the carry if any (***)
    adds    x12, x12, x16               ; Add the lower bits of c
    adc     x15, x15, XZR               ; Add the carry if any (***)
    str     x12, [x1], #8               ; pSrc[j] = (UINT64) c
    mov     x12, x15                    ; c >>= 64

    ldr     x10, [x0], #8               ; pMod[j]
    ldr     x8, [x1]                    ; pSrc[j]

    mul     x16, x6, x10                ; <63:0> of pMod[j]*m
    adds    x16, x16, x8                ; Adding pSrc[j]
    umulh   x15, x6, x10                ; <127:64> of pMod[j]*m
    adc     x15, x15, XZR               ; Add the carry if any (***)
    adds    x12, x12, x16               ; Add the lower bits of c
    adc     x15, x15, XZR               ; Add the carry if any (***)
    str     x12, [x1], #8               ; pSrc[j] = (UINT64) c
    mov     x12, x15                    ; c >>= 64

    adds    x3, x3, #1                  ; Move one digit up
    bne     SymCryptFdef369MontgomeryReduceAsmInner

    ldr     x8, [x1]                    ; pSrc[nWords]
    adds    x12, x12, x8                ; c + pSrc[nWords]
    adc     x15, XZR, XZR               ; Add the carry if any

    adds    x12, x12, x7                ; c + pSrc[nWords] + hc
    adc     x7, x15, XZR                ; Add the carry if any and store into hc

    str     x12, [x1]                   ; pSrc[nWords] = c

    adds    x4, x4, #1                  ; Move one word up

    add     x20, x20, #8                ; Move stored pSrc pointer one word up
    mov     x0, x19                     ; Restore pMod pointer
    mov     x1, x20                     ; Restore pSrc pointer

    mov     x3, x17                     ; Restore the digit counter

    bne     SymCryptFdef369MontgomeryReduceAsmOuter

    ;
    ; Subtraction
    ;

    mov     x16, x2                 ; Store pDst pointer

    ; Prepare the pointers for subtract
    mov     x0, x20                 ; pSrc
    mov     x1, x19                 ; pMod

    mov     x10, x7                 ; x10 = hc
    mov     x3, x17                 ; Restore the digit counter
    subs    x4, x4, x4              ; Set the carry flag (i.e. no borrow)

SymCryptFdef369MontgomeryReduceRawSubAsmLoop
    add     x3, x3, #1              ; Increment the digit count by one
    ; borrow is in the carry flag (flipped)

    ldp     x4, x6, [x0], #16       ; Load two words of pSrc1
    ldp     x5, x7, [x1], #16       ; Load two words of pSrc2
    sbcs    x4, x4, x5
    sbcs    x6, x6, x7
    stp     x4, x6, [x2], #16       ; Store the result in the destination

    ldr     x4, [x0], #8
    ldr     x5, [x1], #8
    sbcs    x4, x4, x5
    str     x4, [x2], #8

    cbnz    x3, SymCryptFdef369MontgomeryReduceRawSubAsmLoop

    csetcc  x0                      ; If the carry is clear (borrow), set the return value to 1

    orr     x11, x10, x0            ; x11 = hc|d

    ; Prepare the pointers for masked copy
    mov     x0, x20                 ; pSrc
    mov     x1, x16                 ; pDst

    mov     x2, x17                 ; Restore the digit counter
    subs    x4, x10, x11            ; If (x11 > x10) clear the carry flag (i.e. borrow)

SymCryptFdef369MontgomeryReduceMaskedCopyAsmLoop
    add     x2, x2, #1              ; Increment the digit count by one

    ldp     x4, x6, [x0], #16       ; Load two words of the source
    ldp     x5, x7, [x1]            ; Load two words of the destination
    cselcc  x4, x4, x5              ; If the carry is clear, select the source operands
    cselcc  x6, x6, x7
    stp     x4, x6, [x1], #16       ; Store the two words in the destination

    ldr     x4, [x0], #8
    ldr     x5, [x1]
    cselcc  x4, x4, x5
    str     x4, [x1], #8

    cbnz    x2, SymCryptFdef369MontgomeryReduceMaskedCopyAsmLoop

    ; Done, no return value

    EPILOG_RESTORE_REG_PAIR x19, x20, #16
    EPILOG_RESTORE_REG_PAIR fp, lr, #32!
    EPILOG_RETURN

    NESTED_END SymCryptFdef369MontgomeryReduceAsm

    END

