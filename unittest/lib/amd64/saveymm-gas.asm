#
# saveymm-gas.asm
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#
.intel_syntax noprefix

.text

#VOID SYMCRYPT_CALL SymCryptEnvUmSaveYmmRegistersAsm( __m256i * buffer );
#VOID SYMCRYPT_CALL SymCryptEnvUmRestoreYmmRegistersAsm( __m256i * buffer );

.global SymCryptEnvUmSaveYmmRegistersAsm
SymCryptEnvUmSaveYmmRegistersAsm:

        # LEAF_ENTRY      SymCryptEnvUmSaveYmmRegistersAsm, _TEXT

        add     rdi, 31
        and     rdi, NOT 31

        vmovaps [rdi+  0 * 32 ], ymm0
        vmovaps [rdi+  1 * 32 ], ymm1
        vmovaps [rdi+  2 * 32 ], ymm2
        vmovaps [rdi+  3 * 32 ], ymm3
        vmovaps [rdi+  4 * 32 ], ymm4
        vmovaps [rdi+  5 * 32 ], ymm5
        vmovaps [rdi+  6 * 32 ], ymm6
        vmovaps [rdi+  7 * 32 ], ymm7
        vmovaps [rdi+  8 * 32 ], ymm8
        vmovaps [rdi+  9 * 32 ], ymm9
        vmovaps [rdi+ 10 * 32 ], ymm10
        vmovaps [rdi+ 11 * 32 ], ymm11
        vmovaps [rdi+ 12 * 32 ], ymm12
        vmovaps [rdi+ 13 * 32 ], ymm13
        vmovaps [rdi+ 14 * 32 ], ymm14
        vmovaps [rdi+ 15 * 32 ], ymm15

        ret

        # LEAF_END        SymCryptEnvUmSaveYmmRegistersAsm, _TEXT

.global SymCryptEnvUmRestoreYmmRegistersAsm
SymCryptEnvUmRestoreYmmRegistersAsm:

        # LEAF_ENTRY      SymCryptEnvUmRestoreYmmRegistersAsm, _TEXT

        add     rdi, 31
        and     rdi, NOT 31

        vmovaps ymm0 , [rdi+  0 * 32 ]
        vmovaps ymm1 , [rdi+  1 * 32 ]
        vmovaps ymm2 , [rdi+  2 * 32 ]
        vmovaps ymm3 , [rdi+  3 * 32 ]
        vmovaps ymm4 , [rdi+  4 * 32 ]
        vmovaps ymm5 , [rdi+  5 * 32 ]
        vmovaps ymm6 , [rdi+  6 * 32 ]
        vmovaps ymm7 , [rdi+  7 * 32 ]
        vmovaps ymm8 , [rdi+  8 * 32 ]
        vmovaps ymm9 , [rdi+  9 * 32 ]
        vmovaps ymm10, [rdi+ 10 * 32 ]
        vmovaps ymm11, [rdi+ 11 * 32 ]
        vmovaps ymm12, [rdi+ 12 * 32 ]
        vmovaps ymm13, [rdi+ 13 * 32 ]
        vmovaps ymm14, [rdi+ 14 * 32 ]
        vmovaps ymm15, [rdi+ 15 * 32 ]

        ret

        # LEAF_END        SymCryptEnvUmRestoreYmmRegistersAsm, _TEXT

# END

