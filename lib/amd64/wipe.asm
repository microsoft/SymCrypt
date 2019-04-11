;
; Wipe.asm
;
; Copyright (c) Microsoft Corporation.  All rights reserved.
;

include ksamd64.inc

        TITLE   wipe.asm

;VOID
;SYMCRYPT_CALL
;SymCryptWipe( _Out_writes_bytes_( cbData )   PVOID  pbData,
;                                       SIZE_T cbData )

        ;
        ; This function allocates no stack space, calls no functions, and does not save
        ; any non-volatile registers. Thusm it is a LEAF function
        ;
        LEAF_ENTRY      SymCryptWipeAsm, _TEXT

        ; rcx = pbData
        ; rdx = cbData

        ;       
        ; This function will handle any alignment of pbData and any size, but it is optimized for 
        ; the case where the start and end of the buffer are 16-aligned.
        ; 16 is the natural stack alignment on AMD64, and structures can be designed to be a multiple
        ; of 16 long without adding too much slack. 
        ; The cost of non-alignment is relatively low, in the order of 5 cycles or so
        ;

        xorps   xmm0,xmm0               ; Zero register for 16-byte wipes
        cmp     rdx,16
        jb      SymCryptWipeAsmSmall    ; if cbData < 16, this is a rare case
        
        test    rcx,15
        jnz     SymCryptWipeAsmUnAligned; if data pointer is unaligned, we jump to the code that aligns the pointer
                                        ; For well-optimized callers the aligned case is the common one, and that is
                                        ; the fall-through.
        
SymCryptWipeAsmAligned:
        ;
        ; Here rcx is aligned, and rdx contains the # bytes left to wipe, and rdx >= 16
        ;
        ; Our loop wipes in 32-byte increments; we always wipe the first 16 bytes if
        ; and increment the pbData pointer if cbData is 16 mod 32
        ; This avoids a conditional jump and is faster.
        ;
        test    rdx,16                  
        movaps  [rcx],xmm0              ; it is safe to always wipe as cbData >= 16   
        lea     r8,[rcx+16]             
        cmovnz  rcx,r8                  ; only increment pbData if cbData = 16 mod 32
        
        sub     rdx,32                  ; see if we have >= 32 bytes to wipe
        jc      SymCryptWipeAsmTailOptional ; if not, wipe tail, or nothing if cbData = 0 mod 16
        
        align   16
        
SymCryptWipeAsmLoop:
        movaps  [rcx],xmm0
        movaps  [rcx+16],xmm0           ; Wipe 32 bytes
        add     rcx,32
        sub     rdx,32               
        jnc     SymCryptWipeAsmLoop
        
SymCryptWipeAsmTailOptional:
        ; only the lower 4 bits of rdx are valid, we have subtracted too much already.
        ; The wipe was at least 16 bytes, so we can just wipe the tail in one instruction
        
        and     edx,15
        jnz     SymCryptWipeAsmTail
        ret
        
SymCryptWipeAsmTail:
        ; This code appears also below at the end of the unaligned wiping routine
        ; but making the jnz jump further is slower and we only duplicate 4 instructions.
        xor     eax,eax
        mov     [rcx+rdx-16],rax
        mov     [rcx+rdx-8],rax       
        ret

        align   4
SymCryptWipeAsmUnaligned:

        ;
        ; At this point we know that cbData(rdx) >= 16 and pbData(rcx) is unaligned. 
        ; We can wipe 16 bytes and move to an aligned position
        ; 
        xor     eax,eax
        mov     [rcx],rax
        mov     [rcx+8],rax
        
        mov     eax,ecx                 ; 
        neg     eax                     ; lower 4 bits of eax = # bytes to wipe to reach alignment
        and     eax,15
        add     rcx,rax
        sub     rdx,rax

        ;
        ; If rdx > 16, go to the aligned wiping loop
        ;        
        cmp     rdx,16
        jae      SymCryptWipeAsmAligned  ; if cbData >= 16, do aligned wipes
        
        ;
        ; We have <= 16 bytes to wipe, and we know that the full wipe region was at least 16 bytes.
        ; We just wipe the last 16 bytes completely.
        ;
        xor     eax,eax
        mov     [rcx+rdx-16],rax
        mov     [rcx+rdx-8],rax       
        ret
        

        align   8
SymCryptWipeAsmSmall:
        ; rcx = pbData, possibly unaligned
        ; rdx = cbData; rdx < 16
        ;
        ; With speculative execution attacks, the cost of a jump table is prohibitive.
        ; We use a compare ladder for 5 cases:
        ;       8-15 bytes
        ;       4-7 bytes
        ;       2-3 bytes
        ;       1 byte
        ;       0 bytes
        
        xor     eax,eax

        cmp     edx, 8
        jb      SymCryptWipeAsmSmallLessThan8

        ; wipe 8-15 bytes using two possibly overlapping writes
        mov     [rcx], rax
        mov     [rcx + rdx - 8], rax
        ret

SymCryptWipeAsmSmallLessThan8:
        cmp     edx, 4
        jb      SymCryptWipeAsmSmallLessThan4

        ; wipe 4-7 bytes
        mov     [rcx], eax
        mov     [rcx + rdx - 4], eax
        ret

SymCryptWipeAsmSmallLessThan4:
        cmp     edx, 2
        jb      SymCryptWipeAsmSmallLessThan2

        ; wipe 2-3 bytes
         mov    [rcx], ax
         mov    [rcx + rdx - 2], ax
         ret

SymCryptWipeAsmSmallLessThan2:
        or      edx, edx
        jz      SymCryptWipeAsmSmallDone

        ; wipe 1 byte
        mov     [rcx], al

SymCryptWipeAsmSmallDone:

        ret                 

        LEAF_END        SymCryptWipeAsm, _TEXT
       
END

