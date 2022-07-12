;
; savevectors.asm
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; Routines for saving and restoring XMM and YMM registers.
;

        TITLE   savevectors.asm


        .686
        .xmm

_TEXT   SEGMENT PARA PUBLIC USE32 'CODE'
        ASSUME  CS:_TEXT, DS:FLAT, SS:FLAT

        PUBLIC  @SymCryptEnvUmSaveXmmRegistersAsm@4
        PUBLIC  @SymCryptEnvUmRestoreXmmRegistersAsm@4
        PUBLIC  @SymCryptEnvUmSaveYmmRegistersAsm@4
        PUBLIC  @SymCryptEnvUmRestoreYmmRegistersAsm@4
        

;VOID SYMCRYPT_CALL SymCryptEnvUmSaveXmmRegistersAsm( __m128i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvUmRestoreXmmRegistersAsm( __m128i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvUmSaveYmmRegistersAsm( __m256i * buffer );
;VOID SYMCRYPT_CALL SymCryptEnvUmRestoreYmmRegistersAsm( __m256i * buffer );

@SymCryptEnvUmSaveXmmRegistersAsm@4    PROC

        ;
        ; The .FPO provides debugging information for stack frames that do not use
        ; ebp as a base pointer.
        ; This stuff not well documented, 
        ; but here is the information I've gathered about the arguments to .FPO
        ; 
        ; In order:
        ; cdwLocals: Size of local variables, in DWords
        ; cdwParams: Size of parameters, in DWords. Given that this is all about
        ;            stack stuff, I'm assuming this is only about parameters passed
        ;            on the stack.
        ; cbProlog : Number of bytes in the prolog code. We sometimes interleaved the
        ;            prolog code with work for better performance. Most uses of
        ;            .FPO seem to set this value to 0.
        ;            The debugger seems to work if the prolog defined by this value
        ;            contains all the stack adjustments.
        ; cbRegs   : # registers saved in the prolog. 4 in our case
        ; fUseBP   : 0 if EBP is not used as base pointer, 1 if EBP is used as base pointer
        ; cbFrame  : Type of frame.
        ;            0 = FPO frame (no frame pointer)
        ;            1 = Trap frame (result of a CPU trap event)
        ;            2 = TSS frame
        ;
        ; Having looked at various occurrences of .FPO in the Windows code it
        ; seems to be used fairly sloppy, with lots of arguments left 0 even when
        ; they probably shouldn't be according to the spec.
        ;
        .FPO(0,0,0,0,0,0)
        
        ; ecx = buffer

        ;
        ; First we align ecx to the next multiple of 16. The buffer is defined to have 16*9 bytes so we have enough room
        ;
        add     ecx, 15
        and     ecx, NOT 15

        movaps  [ecx    ], xmm0
        movaps  [ecx+ 16], xmm1
        movaps  [ecx+ 32], xmm2
        movaps  [ecx+ 48], xmm3
        movaps  [ecx+ 64], xmm4
        movaps  [ecx+ 80], xmm5
        movaps  [ecx+ 96], xmm6
        movaps  [ecx+112], xmm7

        ret
        
@SymCryptEnvUmSaveXmmRegistersAsm@4    ENDP

@SymCryptEnvUmRestoreXmmRegistersAsm@4    PROC

        
        ; ecx = buffer

        ;
        ; First we align ecx to the next multiple of 16. The buffer is defined to have 16*9 bytes so we have enough room
        ;
        add     ecx, 15
        and     ecx, NOT 15

        movaps  xmm0, [ecx    ]
        movaps  xmm1, [ecx+ 16]
        movaps  xmm2, [ecx+ 32]
        movaps  xmm3, [ecx+ 48]
        movaps  xmm4, [ecx+ 64]
        movaps  xmm5, [ecx+ 80]
        movaps  xmm6, [ecx+ 96]
        movaps  xmm7, [ecx+112]

        ret
        
@SymCryptEnvUmRestoreXmmRegistersAsm@4    ENDP

@SymCryptEnvUmSaveYmmRegistersAsm@4    PROC

        ;
        ; The .FPO provides debugging information for stack frames that do not use
        ; ebp as a base pointer.
        ; This stuff not well documented, 
        ; but here is the information I've gathered about the arguments to .FPO
        ; 
        ; In order:
        ; cdwLocals: Size of local variables, in DWords
        ; cdwParams: Size of parameters, in DWords. Given that this is all about
        ;            stack stuff, I'm assuming this is only about parameters passed
        ;            on the stack.
        ; cbProlog : Number of bytes in the prolog code. We sometimes interleaved the
        ;            prolog code with work for better performance. Most uses of
        ;            .FPO seem to set this value to 0.
        ;            The debugger seems to work if the prolog defined by this value
        ;            contains all the stack adjustments.
        ; cbRegs   : # registers saved in the prolog. 4 in our case
        ; fUseBP   : 0 if EBP is not used as base pointer, 1 if EBP is used as base pointer
        ; cbFrame  : Type of frame.
        ;            0 = FPO frame (no frame pointer)
        ;            1 = Trap frame (result of a CPU trap event)
        ;            2 = TSS frame
        ;
        ; Having looked at various occurrences of .FPO in the Windows code it
        ; seems to be used fairly sloppy, with lots of arguments left 0 even when
        ; they probably shouldn't be according to the spec.
        ;
        .FPO(0,0,0,0,0,0)
        
        ; ecx = buffer

        ;
        ; First we align ecx to the next multiple of 16. The buffer is defined to have 16*9 bytes so we have enough room
        ;
        add     ecx, 31
        and     ecx, NOT 31

        vmovaps [ecx+ 0 * 32 ], ymm0
        vmovaps [ecx+ 1 * 32 ], ymm1
        vmovaps [ecx+ 2 * 32 ], ymm2
        vmovaps [ecx+ 3 * 32 ], ymm3
        vmovaps [ecx+ 4 * 32 ], ymm4
        vmovaps [ecx+ 5 * 32 ], ymm5
        vmovaps [ecx+ 6 * 32 ], ymm6
        vmovaps [ecx+ 7 * 32 ], ymm7

        ret
        
@SymCryptEnvUmSaveYmmRegistersAsm@4    ENDP

@SymCryptEnvUmRestoreYmmRegistersAsm@4    PROC

        
        ; ecx = buffer

        ;
        ; First we align ecx to the next multiple of 16. The buffer is defined to have 16*9 bytes so we have enough room
        ;
        add     ecx, 31
        and     ecx, NOT 31

        vmovaps ymm0, [ecx + 0 * 32 ]
        vmovaps ymm1, [ecx + 1 * 32 ]
        vmovaps ymm2, [ecx + 2 * 32 ]
        vmovaps ymm3, [ecx + 3 * 32 ]
        vmovaps ymm4, [ecx + 4 * 32 ]
        vmovaps ymm5, [ecx + 5 * 32 ]
        vmovaps ymm6, [ecx + 6 * 32 ]
        vmovaps ymm7, [ecx + 7 * 32 ]

        ret
        
@SymCryptEnvUmRestoreYmmRegistersAsm@4    ENDP

_TEXT           ENDS

END

