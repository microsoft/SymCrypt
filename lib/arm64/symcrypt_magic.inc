;
; SymCrypt_magic.inc
; Copyright (c) Microsoft Corporation.  All rights reserved.
;
; Include file to define the support macros for the Magic field
;

        IMPORT  SymCryptFatal

#define SYMCRYPT_CODE_VERSION   (SYMCRYPT_CODE_VERSION_RELEASE * 65536 + SYMCRYPT_CODE_VERSION_PRIVATE)
#define SYMCRYPT_MAGIC_CONSTANT (0x53316d76 + SYMCRYPT_CODE_VERSION)

        MACRO
        SYMCRYPT_CHECK_MAGIC $temp1, $temp2, $ptr, $offset

#if DBG

        ldr     $temp1, [$ptr, #$offset]
        subs    $temp1, $temp1, $ptr
        mov32   $temp2, SYMCRYPT_MAGIC_CONSTANT
        cmp     $temp1, $temp2
        beq     %F1
        mov32   r0, 0x6d616763     ; 'magc'
        bl      SymCryptFatal
1
#endif

        MEND
