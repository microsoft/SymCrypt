;
; savevectors.asm
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;

include ksamd64.inc

        TITLE   savevectors.asm

;VOID SYMCRYPT_CALL SymCryptEnvKmTestSaveYmmRegistersAsm( __m256i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvKmTestRestoreYmmRegistersAsm( __m256i * buffer );

        LEAF_ENTRY      SymCryptEnvKmTestSaveYmmRegistersAsm, _TEXT

        add     rcx, 31
        and     rcx, NOT 31

        vmovaps [rcx+  0 * 32 ], ymm0
        vmovaps [rcx+  1 * 32 ], ymm1
        vmovaps [rcx+  2 * 32 ], ymm2
        vmovaps [rcx+  3 * 32 ], ymm3
        vmovaps [rcx+  4 * 32 ], ymm4
        vmovaps [rcx+  5 * 32 ], ymm5
        vmovaps [rcx+  6 * 32 ], ymm6
        vmovaps [rcx+  7 * 32 ], ymm7
        vmovaps [rcx+  8 * 32 ], ymm8
        vmovaps [rcx+  9 * 32 ], ymm9
        vmovaps [rcx+ 10 * 32 ], ymm10
        vmovaps [rcx+ 11 * 32 ], ymm11
        vmovaps [rcx+ 12 * 32 ], ymm12
        vmovaps [rcx+ 13 * 32 ], ymm13
        vmovaps [rcx+ 14 * 32 ], ymm14
        vmovaps [rcx+ 15 * 32 ], ymm15

        ret

        LEAF_END        SymCryptEnvKmTestSaveYmmRegistersAsm, _TEXT

        LEAF_ENTRY      SymCryptEnvKmTestRestoreYmmRegistersAsm, _TEXT

        add     rcx, 31
        and     rcx, NOT 31

        vmovaps ymm0 , [rcx+  0 * 32 ]
        vmovaps ymm1 , [rcx+  1 * 32 ]
        vmovaps ymm2 , [rcx+  2 * 32 ]
        vmovaps ymm3 , [rcx+  3 * 32 ]
        vmovaps ymm4 , [rcx+  4 * 32 ]
        vmovaps ymm5 , [rcx+  5 * 32 ]
        vmovaps ymm6 , [rcx+  6 * 32 ]
        vmovaps ymm7 , [rcx+  7 * 32 ]
        vmovaps ymm8 , [rcx+  8 * 32 ]
        vmovaps ymm9 , [rcx+  9 * 32 ]
        vmovaps ymm10, [rcx+ 10 * 32 ]
        vmovaps ymm11, [rcx+ 11 * 32 ]
        vmovaps ymm12, [rcx+ 12 * 32 ]
        vmovaps ymm13, [rcx+ 13 * 32 ]
        vmovaps ymm14, [rcx+ 14 * 32 ]
        vmovaps ymm15, [rcx+ 15 * 32 ]

        ret

        LEAF_END        SymCryptEnvKmTestRestoreYmmRegistersAsm, _TEXT

END
