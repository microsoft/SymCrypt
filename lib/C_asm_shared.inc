;/*
; C_asm_shared.inc  file to synchronize C and Asm information
; Copyright (c) Microsoft Corporation.  All rights reserved.

; This is a file that compiles both in C and ASM to define values in a way that is guaranteed to be the same on both sides.
; We use this to define the structure offsets that the ASM code uses.
; By having equivalent C constants we can add checks to the C code to ensure they are correct.
;
; This is an ugly hack, but it works :-)
; 
; Due to the fact that the ARM assemblers use the C precompiler
; the C files have to redefine EQU to nothing before including this file.
; */


;const SIZE_T
SymCryptModulusNdigitsOffsetAmd64           EQU     4;

; const SIZE_T
SymCryptModulusMontgomeryInv64OffsetAmd64   EQU     32;

; const SIZE_T
SymCryptModulusValueOffsetAmd64             EQU     128;




;const SIZE_T
SymCryptModulusNdigitsOffsetX86             EQU     4;

; const SIZE_T
SymCryptModulusMontgomeryInv64OffsetX86     EQU     24;

; const SIZE_T
SymCryptModulusValueOffsetX86               EQU     96;




;const SIZE_T
SymCryptModulusNdigitsOffsetArm64           EQU     4;

; const SIZE_T
SymCryptModulusMontgomeryInv64OffsetArm64   EQU     32;

; const SIZE_T
SymCryptModulusValueOffsetArm64             EQU     128;




;const SIZE_T
SymCryptModulusNdigitsOffsetArm             EQU     4;

; const SIZE_T
SymCryptModulusMontgomeryInv64OffsetArm     EQU     24;

; const SIZE_T
SymCryptModulusValueOffsetArm               EQU     96;




; /*
    IF 0
; */
#undef EQU

#if SYMCRYPT_CPU_AMD64
#define SYMCRYPT_CHECK_ASM_OFFSETS \
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusNdigitsOffsetAmd64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, nDigits ) );\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusMontgomeryInv64OffsetAmd64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, tm.montgomery.inv64 ));\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusValueOffsetAmd64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor.Int.ti.fdef.uint32 ));\

#elif SYMCRYPT_CPU_X86
#define SYMCRYPT_CHECK_ASM_OFFSETS \
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusNdigitsOffsetX86, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, nDigits ) );\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusMontgomeryInv64OffsetX86, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, tm.montgomery.inv64 ));\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusValueOffsetX86, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor.Int.ti.fdef.uint32 ));\

#elif SYMCRYPT_CPU_ARM64
#define SYMCRYPT_CHECK_ASM_OFFSETS \
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusNdigitsOffsetArm64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, nDigits ) );\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusMontgomeryInv64OffsetArm64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, tm.montgomery.inv64 ));\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusValueOffsetArm64, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor.Int.ti.fdef.uint32 ));\

#elif SYMCRYPT_CPU_ARM
#define SYMCRYPT_CHECK_ASM_OFFSETS \
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusNdigitsOffsetArm, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, nDigits ) );\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusMontgomeryInv64OffsetArm, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, tm.montgomery.inv64 ));\
    SYMCRYPT_CHECK_ASM_OFFSET( SymCryptModulusValueOffsetArm, SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor.Int.ti.fdef.uint32 ));\
  
#endif // CPU_*

#if !defined( SYMCRYPT_CHECK_ASM_OFFSETS)
#define SYMCRYPT_CHECK_ASM_OFFSETS
#endif


; /*
    ENDIF
; */