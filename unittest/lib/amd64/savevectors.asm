;
; savevectors.asm
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;

include ksamd64.inc

        TITLE   savevectors.asm

;VOID SYMCRYPT_CALL SymCryptEnvUmSaveXmmRegistersAsm( __m128i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvUmRestoreXmmRegistersAsm( __m128i * buffer );

        LEAF_ENTRY      SymCryptEnvUmSaveXmmRegistersAsm, _TEXT

        add     rcx, 15
        and     rcx, NOT 15

        movaps [rcx+  0 * 16 ], xmm0
        movaps [rcx+  1 * 16 ], xmm1
        movaps [rcx+  2 * 16 ], xmm2
        movaps [rcx+  3 * 16 ], xmm3
        movaps [rcx+  4 * 16 ], xmm4
        movaps [rcx+  5 * 16 ], xmm5
        movaps [rcx+  6 * 16 ], xmm6
        movaps [rcx+  7 * 16 ], xmm7
        movaps [rcx+  8 * 16 ], xmm8
        movaps [rcx+  9 * 16 ], xmm9
        movaps [rcx+ 10 * 16 ], xmm10
        movaps [rcx+ 11 * 16 ], xmm11
        movaps [rcx+ 12 * 16 ], xmm12
        movaps [rcx+ 13 * 16 ], xmm13
        movaps [rcx+ 14 * 16 ], xmm14
        movaps [rcx+ 15 * 16 ], xmm15

        ret

        LEAF_END        SymCryptEnvUmSaveXmmRegistersAsm, _TEXT
       
        LEAF_ENTRY      SymCryptEnvUmRestoreXmmRegistersAsm, _TEXT

        add     rcx, 15
        and     rcx, NOT 15

        movaps xmm0 , [rcx+  0 * 16 ]
        movaps xmm1 , [rcx+  1 * 16 ]
        movaps xmm2 , [rcx+  2 * 16 ]
        movaps xmm3 , [rcx+  3 * 16 ]
        movaps xmm4 , [rcx+  4 * 16 ]
        movaps xmm5 , [rcx+  5 * 16 ]
        movaps xmm6 , [rcx+  6 * 16 ]
        movaps xmm7 , [rcx+  7 * 16 ]
        movaps xmm8 , [rcx+  8 * 16 ]
        movaps xmm9 , [rcx+  9 * 16 ]
        movaps xmm10, [rcx+ 10 * 16 ]
        movaps xmm11, [rcx+ 11 * 16 ]
        movaps xmm12, [rcx+ 12 * 16 ]
        movaps xmm13, [rcx+ 13 * 16 ]
        movaps xmm14, [rcx+ 14 * 16 ]
        movaps xmm15, [rcx+ 15 * 16 ]

        ret

        LEAF_END        SymCryptEnvUmRestoreXmmRegistersAsm, _TEXT
       
;VOID SYMCRYPT_CALL SymCryptEnvUmSaveYmmRegistersAsm( __m256i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvUmRestoreYmmRegistersAsm( __m256i * buffer );

        LEAF_ENTRY      SymCryptEnvUmSaveYmmRegistersAsm, _TEXT

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

        LEAF_END        SymCryptEnvUmSaveYmmRegistersAsm, _TEXT
       
        LEAF_ENTRY      SymCryptEnvUmRestoreYmmRegistersAsm, _TEXT

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

        LEAF_END        SymCryptEnvUmRestoreYmmRegistersAsm, _TEXT

END
