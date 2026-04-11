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

;VOID SYMCRYPT_CALL SymCryptEnvKmTestSaveZmmRegistersAsm( __m512i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvKmTestRestoreZmmRegistersAsm( __m512i * buffer );

        LEAF_ENTRY      SymCryptEnvKmTestSaveZmmRegistersAsm, _TEXT

        add     rcx, 63
        and     rcx, NOT 63

        vmovaps [rcx+  0 * 64 ], zmm0
        vmovaps [rcx+  1 * 64 ], zmm1
        vmovaps [rcx+  2 * 64 ], zmm2
        vmovaps [rcx+  3 * 64 ], zmm3
        vmovaps [rcx+  4 * 64 ], zmm4
        vmovaps [rcx+  5 * 64 ], zmm5
        vmovaps [rcx+  6 * 64 ], zmm6
        vmovaps [rcx+  7 * 64 ], zmm7
        vmovaps [rcx+  8 * 64 ], zmm8
        vmovaps [rcx+  9 * 64 ], zmm9
        vmovaps [rcx+ 10 * 64 ], zmm10
        vmovaps [rcx+ 11 * 64 ], zmm11
        vmovaps [rcx+ 12 * 64 ], zmm12
        vmovaps [rcx+ 13 * 64 ], zmm13
        vmovaps [rcx+ 14 * 64 ], zmm14
        vmovaps [rcx+ 15 * 64 ], zmm15
        vmovaps [rcx+ 16 * 64 ], zmm16
        vmovaps [rcx+ 17 * 64 ], zmm17
        vmovaps [rcx+ 18 * 64 ], zmm18
        vmovaps [rcx+ 19 * 64 ], zmm19
        vmovaps [rcx+ 20 * 64 ], zmm20
        vmovaps [rcx+ 21 * 64 ], zmm21
        vmovaps [rcx+ 22 * 64 ], zmm22
        vmovaps [rcx+ 23 * 64 ], zmm23
        vmovaps [rcx+ 24 * 64 ], zmm24
        vmovaps [rcx+ 25 * 64 ], zmm25
        vmovaps [rcx+ 26 * 64 ], zmm26
        vmovaps [rcx+ 27 * 64 ], zmm27
        vmovaps [rcx+ 28 * 64 ], zmm28
        vmovaps [rcx+ 29 * 64 ], zmm29
        vmovaps [rcx+ 30 * 64 ], zmm30
        vmovaps [rcx+ 31 * 64 ], zmm31

        kmovq rax, k0
        mov   [rcx+ 32 * 64 + 0 * 8], rax
        kmovq rax, k1
        mov   [rcx+ 32 * 64 + 1 * 8], rax
        kmovq rax, k2
        mov   [rcx+ 32 * 64 + 2 * 8], rax
        kmovq rax, k3
        mov   [rcx+ 32 * 64 + 3 * 8], rax
        kmovq rax, k4
        mov   [rcx+ 32 * 64 + 4 * 8], rax
        kmovq rax, k5
        mov   [rcx+ 32 * 64 + 5 * 8], rax
        kmovq rax, k6
        mov   [rcx+ 32 * 64 + 6 * 8], rax
        kmovq rax, k7
        mov   [rcx+ 32 * 64 + 7 * 8], rax

        ret

        LEAF_END        SymCryptEnvKmTestSaveZmmRegistersAsm, _TEXT

        LEAF_ENTRY      SymCryptEnvKmTestRestoreZmmRegistersAsm, _TEXT

        add     rcx, 63
        and     rcx, NOT 63

        vmovaps zmm0 , [rcx+  0 * 64 ]
        vmovaps zmm1 , [rcx+  1 * 64 ]
        vmovaps zmm2 , [rcx+  2 * 64 ]
        vmovaps zmm3 , [rcx+  3 * 64 ]
        vmovaps zmm4 , [rcx+  4 * 64 ]
        vmovaps zmm5 , [rcx+  5 * 64 ]
        vmovaps zmm6 , [rcx+  6 * 64 ]
        vmovaps zmm7 , [rcx+  7 * 64 ]
        vmovaps zmm8 , [rcx+  8 * 64 ]
        vmovaps zmm9 , [rcx+  9 * 64 ]
        vmovaps zmm10, [rcx+ 10 * 64 ]
        vmovaps zmm11, [rcx+ 11 * 64 ]
        vmovaps zmm12, [rcx+ 12 * 64 ]
        vmovaps zmm13, [rcx+ 13 * 64 ]
        vmovaps zmm14, [rcx+ 14 * 64 ]
        vmovaps zmm15, [rcx+ 15 * 64 ]
        vmovaps zmm16, [rcx+ 16 * 64 ]
        vmovaps zmm17, [rcx+ 17 * 64 ]
        vmovaps zmm18, [rcx+ 18 * 64 ]
        vmovaps zmm19, [rcx+ 19 * 64 ]
        vmovaps zmm20, [rcx+ 20 * 64 ]
        vmovaps zmm21, [rcx+ 21 * 64 ]
        vmovaps zmm22, [rcx+ 22 * 64 ]
        vmovaps zmm23, [rcx+ 23 * 64 ]
        vmovaps zmm24, [rcx+ 24 * 64 ]
        vmovaps zmm25, [rcx+ 25 * 64 ]
        vmovaps zmm26, [rcx+ 26 * 64 ]
        vmovaps zmm27, [rcx+ 27 * 64 ]
        vmovaps zmm28, [rcx+ 28 * 64 ]
        vmovaps zmm29, [rcx+ 29 * 64 ]
        vmovaps zmm30, [rcx+ 30 * 64 ]
        vmovaps zmm31, [rcx+ 31 * 64 ]

        mov   rax, [rcx+ 32 * 64 + 0 * 8]
        kmovq k0, rax
        mov   rax, [rcx+ 32 * 64 + 1 * 8]
        kmovq k1, rax
        mov   rax, [rcx+ 32 * 64 + 2 * 8]
        kmovq k2, rax
        mov   rax, [rcx+ 32 * 64 + 3 * 8]
        kmovq k3, rax
        mov   rax, [rcx+ 32 * 64 + 4 * 8]
        kmovq k4, rax
        mov   rax, [rcx+ 32 * 64 + 5 * 8]
        kmovq k5, rax
        mov   rax, [rcx+ 32 * 64 + 6 * 8]
        kmovq k6, rax
        mov   rax, [rcx+ 32 * 64 + 7 * 8]
        kmovq k7, rax

        ret

        LEAF_END        SymCryptEnvKmTestRestoreZmmRegistersAsm, _TEXT

END
