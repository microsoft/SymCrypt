        TTL  "SymCryptWipe"
;++
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; Secure wipe
;
;--

#include "ksarm64.h"
#include "symcrypt_name_mangling.inc"

        TEXTAREA

        EXTERN  ARM64EC_NAME_MANGLE(memset)

        SUBT  "SymCryptWipe"
;VOID
;SYMCRYPT_CALL
;SymCryptWipe( _Out_writes_bytes_( cbData )   PVOID  pbData,
;                                       SIZE_T cbData )


        LEAF_ENTRY ARM64EC_NAME_MANGLE(SymCryptWipeAsm)

        ; we just jump to memset.
        ; this is enough to stop the compiler optimizing the memset away.

        mov     x2, x1
        mov     x1, #0
        b       ARM64EC_NAME_MANGLE(memset)

        LEAF_END ARM64EC_NAME_MANGLE(SymCryptWipeAsm)



        END
