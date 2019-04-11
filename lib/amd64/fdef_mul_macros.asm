;
; Macros for the multiplication routines in amd64
;

; General multiplication

MULT_SINGLEADD_128   MACRO   index, src_reg, dst_reg
        ; rax = mul scratch
        ; rbx = multiplier
        ; rdx = mul scratch
        ; src_reg = running ptr to input
        ; dst_reg = running ptr to output/scratch
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        mov     rax, [src_reg + 8*index]
        mul     rbx
        mov     r15, rdx
        add     rax, r12
        mov     [dst_reg + 8*index], rax
        adc     r15, 0

        mov     rax, [src_reg + 8*(index+1)]
        mul     rbx
        mov     r12, rdx
        add     rax, r15
        mov     [dst_reg + 8*(index+1)], rax
        adc     r12, 0

    ENDM

MULT_DOUBLEADD_128   MACRO   index, src_reg, dst_reg
        ; rax = mul scratch
        ; rbx = multiplier
        ; rdx = mul scratch
        ; src_reg = running ptr to input
        ; dst_reg = running ptr to output/scratch
        ; r12 = carry for even words (64 bits)
        ; r15 = carry for odd words (64 bits)

        mov     rax, [src_reg + 8*index]
        mul     rbx
        mov     r15, rdx
        add     rax, [dst_reg + 8*index]
        adc     r15, 0
        add     rax, r12
        mov     [dst_reg + 8*index], rax
        adc     r15, 0

        mov     rax, [src_reg + 8*(index+1)]
        mul     rbx
        mov     r12, rdx
        add     rax, [dst_reg + 8*(index+1)]
        adc     r12, 0
        add     rax, r15
        mov     [dst_reg + 8*(index+1)], rax
        adc     r12, 0

    ENDM

; Squaring

SQR_SINGLEADD_64   MACRO   index, src_reg, dst_reg, src_carry, dst_carry
        ; rax = mul scratch
        ; rbx = multiplier
        ; rdx = mul scratch
        ; src_reg = running ptr to input
        ; dst_reg = running ptr to output/scratch
        ; src_carry = input carry
        ; dst_carry = output carry

        mov     rax, [src_reg + 8*index]
        mul     rbx
        mov     dst_carry, rdx
        add     rax, src_carry
        mov     [dst_reg + 8*index], rax
        adc     dst_carry, 0

    ENDM

SQR_DOUBLEADD_64   MACRO   index, src_reg, dst_reg, src_carry, dst_carry
        ; rax = mul scratch
        ; rbx = multiplier
        ; rdx = mul scratch
        ; src_reg = running ptr to input
        ; dst_reg = running ptr to output/scratch
        ; src_carry = input carry
        ; dst_carry = output carry

        mov     rax, [src_reg + 8*index]
        mul     rbx
        mov     dst_carry, rdx
        add     rax, [dst_reg + 8*index]
        adc     dst_carry, 0
        add     rax, src_carry
        mov     [dst_reg + 8*index], rax
        adc     dst_carry, 0

    ENDM

SQR_SHIFT_LEFT MACRO index
        mov     rax, [rdi + 8*index]
        adc     rax, rax            ; Shift let and add the carry
        mov     [rdi + 8*index], rax
    ENDM

SQR_DIAGONAL_PROP MACRO index
        ;;;;;;;;;;;;;;;;;;;;;;;;
        ; Calculating the square
        mov     rax, [rsi + 8*index]    ; mulword
        mul     rax                     ; m^2

        ; Adding the square to the even column
        add     rax, [rdi + 16*index]
        adc     rdx, 0
        add     rax, r12
        adc     rdx, 0
        mov     [rdi + 16*index], rax

        ; Propagating the sum to the next column
        mov     rax, rdx
        xor     rdx, rdx

        add     rax, [rdi + 16*index + 8]
        adc     rdx, 0
        mov     [rdi + 16*index + 8], rax
        mov     r12, rdx
    ENDM

; Size-specific macros
; A common prologue & epilogue between several functions allows jumping between them...

MULT_COMMON_PROLOGUE    MACRO
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
    ENDM

MULT_COMMON_EPILOGUE    MACRO
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
    ENDM


MUL14   MACRO   Mult, pA, R0, R1, R2, R3, Cy
        ; (R0, R1, R2, R3, rdx) = Mult * (A0..3) + (R0, R1, R2, R3)
        ; Cy, rax = scratch

        mov     rax, [pA]
        mul     Mult
        add     R0, rax
        adc     rdx, 0
        mov     Cy, rdx

        mov     rax, [pA + 8]
        mul     Mult
        add     R1, rax
        adc     rdx, 0
        add     R1, Cy
        adc     rdx, 0
        mov     Cy, rdx

        mov     rax, [pA + 16]
        mul     Mult
        add     R2, rax
        adc     rdx, 0
        add     R2, Cy
        adc     rdx, 0
        mov     Cy, rdx

        mov     rax, [pA + 24]
        mul     Mult
        add     R3, rax
        adc     rdx, 0
        add     R3, Cy
        adc     rdx, 0

    ENDM

; Macros for size-specific squaring

SQR_DOUBLEADD_64_2  MACRO index
        SQR_DOUBLEADD_64    (index),     rsi, rdi, r12, r15
        SQR_DOUBLEADD_64    (index + 1), rsi, rdi, r15, r12
    ENDM

SQR_DOUBLEADD_64_4  MACRO index
        SQR_DOUBLEADD_64_2  (index)
        SQR_DOUBLEADD_64_2  (index + 2)
    ENDM

SQR_DOUBLEADD_64_8  MACRO index
        SQR_DOUBLEADD_64_4  (index)
        SQR_DOUBLEADD_64_4  (index + 4)
    ENDM

SQR_SIZE_SPECIFIC_INIT MACRO
        lea     rcx, [rcx + 8]          ; move Src pointer 1 word over
        lea     r10, [r10 + 16]         ; move Dst pointer 2 words over

        mov     rsi, rcx                ; rsi = inner pSrc
        mov     rdi, r10                ; rdi = inner pDst

        mov     rbx, [rcx]              ; Get the next mulword
        lea     rsi, [rsi + 8]          ; move Src pointer 1 word over
    ENDM