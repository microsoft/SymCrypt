#
# savezmm-gas.asm
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#
.intel_syntax noprefix

.text

#VOID SYMCRYPT_CALL SymCryptEnvUmSaveZmmRegistersAsm( __m512i * buffer );
#VOID SYMCRYPT_CALL SymCryptEnvUmRestoreZmmRegistersAsm( __m512i * buffer );

.global SymCryptEnvUmSaveZmmRegistersAsm
SymCryptEnvUmSaveZmmRegistersAsm:

        # LEAF_ENTRY      SymCryptEnvUmSaveZmmRegistersAsm, _TEXT

        add     rdi, 63
        and     rdi, NOT 63

        vmovaps [rdi+  0 * 64 ], zmm0
        vmovaps [rdi+  1 * 64 ], zmm1
        vmovaps [rdi+  2 * 64 ], zmm2
        vmovaps [rdi+  3 * 64 ], zmm3
        vmovaps [rdi+  4 * 64 ], zmm4
        vmovaps [rdi+  5 * 64 ], zmm5
        vmovaps [rdi+  6 * 64 ], zmm6
        vmovaps [rdi+  7 * 64 ], zmm7
        vmovaps [rdi+  8 * 64 ], zmm8
        vmovaps [rdi+  9 * 64 ], zmm9
        vmovaps [rdi+ 10 * 64 ], zmm10
        vmovaps [rdi+ 11 * 64 ], zmm11
        vmovaps [rdi+ 12 * 64 ], zmm12
        vmovaps [rdi+ 13 * 64 ], zmm13
        vmovaps [rdi+ 14 * 64 ], zmm14
        vmovaps [rdi+ 15 * 64 ], zmm15
        vmovaps [rdi+ 16 * 64 ], zmm16
        vmovaps [rdi+ 17 * 64 ], zmm17
        vmovaps [rdi+ 18 * 64 ], zmm18
        vmovaps [rdi+ 19 * 64 ], zmm19
        vmovaps [rdi+ 20 * 64 ], zmm20
        vmovaps [rdi+ 21 * 64 ], zmm21
        vmovaps [rdi+ 22 * 64 ], zmm22
        vmovaps [rdi+ 23 * 64 ], zmm23
        vmovaps [rdi+ 24 * 64 ], zmm24
        vmovaps [rdi+ 25 * 64 ], zmm25
        vmovaps [rdi+ 26 * 64 ], zmm26
        vmovaps [rdi+ 27 * 64 ], zmm27
        vmovaps [rdi+ 28 * 64 ], zmm28
        vmovaps [rdi+ 29 * 64 ], zmm29
        vmovaps [rdi+ 30 * 64 ], zmm30
        vmovaps [rdi+ 31 * 64 ], zmm31

        kmovq [rdi+ 32 * 64 + 0 * 8], k0
        kmovq [rdi+ 32 * 64 + 1 * 8], k1
        kmovq [rdi+ 32 * 64 + 2 * 8], k2
        kmovq [rdi+ 32 * 64 + 3 * 8], k3
        kmovq [rdi+ 32 * 64 + 4 * 8], k4
        kmovq [rdi+ 32 * 64 + 5 * 8], k5
        kmovq [rdi+ 32 * 64 + 6 * 8], k6
        kmovq [rdi+ 32 * 64 + 7 * 8], k7

        ret

        # LEAF_END        SymCryptEnvUmSaveZmmRegistersAsm, _TEXT

.global SymCryptEnvUmRestoreZmmRegistersAsm
SymCryptEnvUmRestoreZmmRegistersAsm:

        # LEAF_ENTRY      SymCryptEnvUmRestoreZmmRegistersAsm, _TEXT

        add     rdi, 63
        and     rdi, NOT 63

        vmovaps zmm0 , [rdi+  0 * 64 ]
        vmovaps zmm1 , [rdi+  1 * 64 ]
        vmovaps zmm2 , [rdi+  2 * 64 ]
        vmovaps zmm3 , [rdi+  3 * 64 ]
        vmovaps zmm4 , [rdi+  4 * 64 ]
        vmovaps zmm5 , [rdi+  5 * 64 ]
        vmovaps zmm6 , [rdi+  6 * 64 ]
        vmovaps zmm7 , [rdi+  7 * 64 ]
        vmovaps zmm8 , [rdi+  8 * 64 ]
        vmovaps zmm9 , [rdi+  9 * 64 ]
        vmovaps zmm10, [rdi+ 10 * 64 ]
        vmovaps zmm11, [rdi+ 11 * 64 ]
        vmovaps zmm12, [rdi+ 12 * 64 ]
        vmovaps zmm13, [rdi+ 13 * 64 ]
        vmovaps zmm14, [rdi+ 14 * 64 ]
        vmovaps zmm15, [rdi+ 15 * 64 ]
        vmovaps zmm16, [rdi+ 16 * 64 ]
        vmovaps zmm17, [rdi+ 17 * 64 ]
        vmovaps zmm18, [rdi+ 18 * 64 ]
        vmovaps zmm19, [rdi+ 19 * 64 ]
        vmovaps zmm20, [rdi+ 20 * 64 ]
        vmovaps zmm21, [rdi+ 21 * 64 ]
        vmovaps zmm22, [rdi+ 22 * 64 ]
        vmovaps zmm23, [rdi+ 23 * 64 ]
        vmovaps zmm24, [rdi+ 24 * 64 ]
        vmovaps zmm25, [rdi+ 25 * 64 ]
        vmovaps zmm26, [rdi+ 26 * 64 ]
        vmovaps zmm27, [rdi+ 27 * 64 ]
        vmovaps zmm28, [rdi+ 28 * 64 ]
        vmovaps zmm29, [rdi+ 29 * 64 ]
        vmovaps zmm30, [rdi+ 30 * 64 ]
        vmovaps zmm31, [rdi+ 31 * 64 ]

        kmovq k0, [rdi+ 32 * 64 + 0 * 8]
        kmovq k1, [rdi+ 32 * 64 + 1 * 8]
        kmovq k2, [rdi+ 32 * 64 + 2 * 8]
        kmovq k3, [rdi+ 32 * 64 + 3 * 8]
        kmovq k4, [rdi+ 32 * 64 + 4 * 8]
        kmovq k5, [rdi+ 32 * 64 + 5 * 8]
        kmovq k6, [rdi+ 32 * 64 + 6 * 8]
        kmovq k7, [rdi+ 32 * 64 + 7 * 8]

        ret

        # LEAF_END        SymCryptEnvUmRestoreZmmRegistersAsm, _TEXT

# END
