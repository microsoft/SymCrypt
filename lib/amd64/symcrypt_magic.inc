;
; SymCrypt_magic.inc
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; Include file to define the support macros for the Magic field
;

        extern  SymCryptFatal:NEAR


SYMCRYPT_MAGIC_FIELD    MACRO

        if      DBG
        magic   dq      ?
        endif
        
                        ENDM

SYMCRYPT_CODE_VERSION   EQU     ((SYMCRYPT_CODE_VERSION_RELEASE SHL 16) OR SYMCRYPT_CODE_VERSION_PRIVATE )
SYMCRYPT_MAGIC_CONSTANT EQU     ('S1mv' + SYMCRYPT_CODE_VERSION)

SYMCRYPT_CHECK_MAGIC    MACRO   ptr, struct_name

        if      DBG

        mov     rax, [ptr + struct_name.magic]
        sub     rax, ptr
        cmp     rax, SYMCRYPT_MAGIC_CONSTANT
        jz      @F
        mov     ecx, 'magc'
        call    SymCryptFatal
@@:
        endif

        ENDM
        

