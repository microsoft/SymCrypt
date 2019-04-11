;
;  AesAsm.asm   Assembler code for fast AES on the amd64
;
; Copyright (c) Microsoft Corporation.  All rights reserved.
;
; This code is derived from the AesFast implemenation that
; Niels Ferguson wrote from scratch for BitLocker during Vista.
; That code is still in RSA32.
;

include ksamd64.inc

include ..\inc\symcrypt_version.inc
include symcrypt_magic.inc

        TITLE   "Advanced Encryption Standard (AES)"

USE_BLOCK_FUNCTION      EQU     1               ; Set to 1 to use block function, 0 to use block macro

;
; Structure definition that mirrors the SYMCRYPT_AES_EXPANDED_KEY structure.
;

N_ROUND_KEYS_IN_AESKEY    EQU     29        

SYMCRYPT_AES_EXPANDED_KEY struct
        RoundKey        dq      2*N_ROUND_KEYS_IN_AESKEY dup (?)        ;
        lastEncRoundKey dq      ?                                       ; pointer to last enc round key
        lastDecRoundKey dq      ?                                       ; pointer to last dec round key

        SYMCRYPT_MAGIC_FIELD
        
SYMCRYPT_AES_EXPANDED_KEY ends        


        extern  SymCryptAesSboxMatrixMult:DWORD
        extern  SymCryptAesInvSboxMatrixMult:DWORD
;        extern  SymCryptAesSbox:BYTE                           ; Not used
        extern  SymCryptAesInvSbox:BYTE

;
; Shorthand for the 4 tables we will use
; We always use r11 to point to the (inv) SboxMatrixMult tables
;
SMM0    EQU     r11
SMM1    EQU     r11 + 0400h
SMM2    EQU     r11 + 0800h
SMM3    EQU     r11 + 0c00h

ISMM0   EQU     r11
ISMM1   EQU     r11 + 0400h
ISMM2   EQU     r11 + 0800h
ISMM3   EQU     r11 + 0c00h




ENC_MIX MACRO   keyptr
        ;
        ; Perform the unkeyed mixing function for encryption
        ; plus a key addition from the key pointer
        ;
        ; input:block is in     eax, ebx, ecx, edx;  r11 points to AesSboxMatrixMult
        ; New state ends up in  eax, ebx, ecx, edx
        ; Used registers:       esi, edi, ebp, r8

        ;
        ; We can use the e<xx> registers for the movzx as the
        ; upper 32 bits are automatically set to 0. This saves
        ; prefix bytes
        ;
        ; We use 32-bit registers to store the state. 
        ; We tried using 64-bit registers, but the extra shifts
        ; cost too much. 
        ; Using 32-bit throughout makes the key xor more expensive
        ; but we avoid having to combine the 32-bit halves into
        ; 64 bit.
        ;

        movzx   esi,al
        mov     esi,[SMM0 + 4 * rsi]
        movzx   edi,ah
        shr     eax,16
        mov     r8d,[SMM1 + 4 * rdi]
        movzx   ebp,al
        mov     ebp,[SMM2 + 4 * rbp]
        movzx   edi,ah
        mov     edi,[SMM3 + 4 * rdi]
        
        movzx   eax,bl
        xor     edi,[SMM0 + 4 * rax]
        movzx   eax,bh
        shr     ebx,16
        xor     esi,[SMM1 + 4 * rax]
        movzx   eax,bl
        xor     r8d,[SMM2 + 4 * rax]
        movzx   eax,bh
        xor     ebp,[SMM3 + 4 * rax]

        movzx   eax,cl
        xor     ebp,[SMM0 + 4 * rax]
        movzx   ebx,ch
        shr     ecx,16
        xor     edi,[SMM1 + 4 * rbx]
        movzx   eax,cl
        xor     esi,[SMM2 + 4 * rax]
        movzx   ebx,ch
        xor     r8d,[SMM3 + 4 * rbx] 

        movzx   eax,dl
        xor     r8d,[SMM0 + 4 * rax]
        movzx   ebx,dh
        shr     edx,16
        xor     ebp,[SMM1 + 4 * rbx]
        movzx   eax,dl
        xor     edi,[SMM2 + 4 * rax]
        movzx   ebx,dh
        xor     esi,[SMM3 + 4 * rbx] 

        mov     eax, [keyptr]
        mov     ebx, [keyptr + 4]
        xor     eax, esi
        mov     ecx, [keyptr + 8]
        xor     ebx, edi
        mov     edx, [keyptr + 12]
        xor     ecx, ebp
        xor     edx, r8d

        ENDM


DEC_MIX MACRO   keyptr
        ;
        ; Perform the unkeyed mixing function for decryption
        ;
        ; input:block is in      eax, ebx, ecx, edx
        ;       r11 points to AesInvSboxMatrixMult
        ; New state ends up in   esi, edi, ebp, r8d

        movzx   esi,al
        mov     esi,[ISMM0 + 4 * rsi]
        movzx   edi,ah
        shr     eax,16
        mov     edi,[ISMM1 + 4 * rdi]
        movzx   ebp,al
        mov     ebp,[ISMM2 + 4 * rbp]
        movzx   eax,ah
        mov     r8d,[ISMM3 + 4 * rax]
        
        movzx   eax,bl
        xor     edi,[ISMM0 + 4 * rax]
        movzx   eax,bh
        shr     ebx,16
        xor     ebp,[ISMM1 + 4 * rax]
        movzx   eax,bl
        xor     r8d,[ISMM2 + 4 * rax]
        movzx   eax,bh
        xor     esi,[ISMM3 + 4 * rax]

        movzx   eax,cl
        xor     ebp,[ISMM0 + 4 * rax]
        movzx   ebx,ch
        shr     ecx,16
        xor     r8d,[ISMM1 + 4 * rbx]
        movzx   eax,cl
        xor     esi,[ISMM2 + 4 * rax]
        movzx   ebx,ch
        xor     edi,[ISMM3 + 4 * rbx] 

        movzx   eax,dl
        xor     r8d,[ISMM0 + 4 * rax]
        movzx   ebx,dh
        shr     edx,16
        xor     esi,[ISMM1 + 4 * rbx]
        movzx   eax,dl
        xor     edi,[ISMM2 + 4 * rax]
        movzx   ebx,dh
        xor     ebp,[ISMM3 + 4 * rbx] 

        mov     eax, [keyptr]
        mov     ebx, [keyptr + 4]
        xor     eax, esi
        mov     ecx, [keyptr + 8]
        xor     ebx, edi
        mov     edx, [keyptr + 12]
        xor     ecx, ebp
        xor     edx, r8d

        ENDM



AES_ENCRYPT_MACRO     MACRO
        ;
        ; Plaintext in eax, ebx, ecx, edx
        ; r9 points to first round key to use (modified)
        ; r10 is last key to use (unchanged)
        ; r11 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;
        ; This macro is free to unroll the cipher completely, or to use a loop
        ; over r9
        ;

        ;
        ; xor in first round key
        ;        
        xor     eax,[r9]
        xor     ebx,[r9+4]
        xor     ecx,[r9+8]
        xor     edx,[r9+12]

        ENC_MIX r9+16
        
        ENC_MIX r9+32
        
        ENC_MIX r9+48
        
        ENC_MIX r9+64
        
        ENC_MIX r9+80
        
        ENC_MIX r9+96

        add     r9,160
        
        ENC_MIX r9-48
        
        ;align   16
        
@@:
        ; Block is eax, ebx, ecx, edx
        ; r9-16 points to next round key

        ENC_MIX r9-32

        ENC_MIX r9-16
        
        cmp     r9,r10
        lea     r9,[r9+32]      
        jc      @B

        ;
        ; Now for the final round
        ; We use the fact that SboxMatrixMult[0] table is also
        ; an Sbox table if you use the second element of each entry.
        ;
        ; Result is in esi, edi, ebp, r8d 
        ; 

        movzx   esi,al
        movzx   esi,byte ptr[r11 + 1 + 4*rsi]
        movzx   edi,ah
        shr     eax,16
        movzx   r8d,byte ptr[r11 + 1 + 4*rdi]
        movzx   ebp,al
        shl     r8d,8
        movzx   ebp,byte ptr[r11 + 1 + 4*rbp]
        shl     ebp,16
        movzx   edi,ah
        movzx   edi,byte ptr[r11 + 1 + 4*rdi]
        shl     edi,24

        movzx   eax,bl
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        or      edi,eax
        movzx   eax,bh
        shr     ebx,16
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        shl     eax,8
        or      esi,eax
        movzx   eax,bl
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        movzx   ebx,bh
        shl     eax,16
        movzx   ebx,byte ptr[r11 + 1 + 4*rbx]
        or      r8d,eax
        shl     ebx,24
        or      ebp,ebx

        movzx   eax,cl
        movzx   ebx,ch
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        shr     ecx,16
        movzx   ebx,byte ptr[r11 + 1 + 4*rbx]
        shl     ebx,8
        or      ebp,eax
        or      edi,ebx
        movzx   eax,cl
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        movzx   ebx,ch
        movzx   ebx,byte ptr[r11 + 1 + 4*rbx]
        shl     eax,16
        shl     ebx,24
        or      esi,eax
        or      r8d,ebx
        
        movzx   eax,dl
        movzx   ebx,dh
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        shr     edx,16
        movzx   ebx,byte ptr[r11 + 1 + 4*rbx]
        shl     ebx,8
        or      r8d,eax
        or      ebp,ebx
        movzx   eax,dl
        movzx   eax,byte ptr[r11 + 1 + 4*rax]
        movzx   ebx,dh
        movzx   ebx,byte ptr[r11 + 1 + 4*rbx]
        shl     eax,16
        shl     ebx,24
        or      edi,eax
        or      esi,ebx

        ;
        ; xor in final round key
        ;        
        
        xor     r8d,[r10+12]
        xor     esi,[r10]
        xor     edi,[r10+4]
        xor     ebp,[r10+8]
        
        ENDM

AES_DECRYPT_MACRO     MACRO
        ;
        ; Ciphertext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to InvSboxMatrixMult (unchanged)
        ; r12 points to InvSbox (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;


        ;
        ; xor in first round key
        ;        
        xor     eax,[r9]
        xor     ebx,[r9+4]
        xor     ecx,[r9+8]
        xor     edx,[r9+12]
        
        DEC_MIX r9+16
        
        DEC_MIX r9+32
        
        DEC_MIX r9+48
        
        DEC_MIX r9+64
        
        DEC_MIX r9+80
        
        DEC_MIX r9+96

        add     r9,160
        
        DEC_MIX r9-48
        
        ;align   16
        
@@:
        ; Block is eax, ebx, ecx, edx
        ; r9-32 points to next round key

        DEC_MIX r9-32

        DEC_MIX r9-16
        
        cmp     r9,r10
        lea     r9,[r9+32]      
        jc      @B

        ;
        ; Now for the final round
        ; Result is in esi, edi, ebp, r8d 
        ; 

        movzx   esi,al
        movzx   esi,byte ptr[r12 + rsi]
        movzx   edi,ah
        shr     eax,16
        movzx   edi,byte ptr[r12 + rdi]
        movzx   ebp,al
        shl     edi,8
        movzx   ebp,byte ptr[r12 + rbp]
        shl     ebp,16
        movzx   eax,ah
        movzx   r8d,byte ptr[r12 + rax]
        shl     r8d,24

        movzx   eax,bl
        movzx   eax,byte ptr[r12 + rax]
        or      edi,eax
        movzx   eax,bh
        shr     ebx,16
        movzx   eax,byte ptr[r12 + rax]
        shl     eax,8
        or      ebp,eax
        movzx   eax,bl
        movzx   eax,byte ptr[r12 + rax]
        movzx   ebx,bh
        shl     eax,16
        movzx   ebx,byte ptr[r12 + rbx]
        or      r8d,eax
        shl     ebx,24
        or      esi,ebx

        movzx   eax,cl
        movzx   ebx,ch
        movzx   eax,byte ptr[r12 + rax]
        shr     ecx,16
        movzx   ebx,byte ptr[r12 + rbx]
        shl     ebx,8
        or      ebp,eax
        or      r8d,ebx
        movzx   eax,cl
        movzx   eax,byte ptr[r12 + rax]
        movzx   ebx,ch
        movzx   ebx,byte ptr[r12 + rbx]
        shl     eax,16
        shl     ebx,24
        or      esi,eax
        or      edi,ebx
        
        movzx   eax,dl
        movzx   ebx,dh
        movzx   eax,byte ptr[r12 + rax]
        shr     edx,16
        movzx   ebx,byte ptr[r12 + rbx]
        shl     ebx,8
        or      r8d,eax
        or      esi,ebx
        movzx   eax,dl
        movzx   eax,byte ptr[r12 + rax]
        movzx   ebx,dh
        movzx   ebx,byte ptr[r12 + rbx]
        shl     eax,16
        shl     ebx,24
        or      edi,eax
        or      ebp,ebx

        ;
        ; xor in final round key
        ;        
        
        xor     esi,[r10]
        xor     edi,[r10+4]
        xor     ebp,[r10+8]
        xor     r8d,[r10+12]

        ENDM

if 0
AES_ENCRYPT_XMM MACRO
        ; xmm0 contains the plaintext
        ; rcx points to first round key to use
        ; r10 is last key to use (unchanged)
        ; Ciphertext ends up in xmm0
        ;

        ;
        ; xor in first round key; round keys are 16-aligned on amd64
        ;
        pxor    xmm0,[rcx]
        aesenc  xmm0,[rcx+16]
        
        aesenc  xmm0,[rcx+32]
        aesenc  xmm0,[rcx+48]
        aesenc  xmm0,[rcx+64]
        aesenc  xmm0,[rcx+80]
        aesenc  xmm0,[rcx+96]
        aesenc  xmm0,[rcx+112]        
        add     rcx, 128

@@:
        ; r9 points to next round key

        aesenc  xmm0, [rcx]
        aesenc  xmm0, [rcx+16]
        
        add     rcx, 32
        cmp     rcx,r10
        jc      @B

        ;
        ; Now for the final round
        ;
        aesenclast      xmm0, [r10]
       
        ENDM


AES_DECRYPT_XMM MACRO
        ; xmm0 contains the ciphertext
        ; rcx points to first round key to use
        ; r10 is last key to use (unchanged)
        ; Plaintext ends up in xmm0
        ;

        ;
        ; xor in first round key; round keys are 16-aligned on amd64
        ;
        pxor    xmm0,[rcx]
        aesdec  xmm0,[rcx+16]

        aesdec  xmm0,[rcx+32]
        aesdec  xmm0,[rcx+48]
        aesdec  xmm0,[rcx+64]
        aesdec  xmm0,[rcx+80]
        aesdec  xmm0,[rcx+96]
        aesdec  xmm0,[rcx+112]        
        add     rcx, 128

@@:
        ; r9 points to next round key

        aesdec  xmm0, [rcx]
        aesdec  xmm0, [rcx+16]
        
        add     rcx, 32
        cmp     rcx,r10
        jc      @B

        ;
        ; Now for the final round
        ;
        aesdeclast      xmm0, [r10]
       
       
        ENDM
endif
        
        IF      USE_BLOCK_FUNCTION

        ;
        ; We use a block function, the AES_ENCRYPT macro merely calls the function
        ;

AES_ENCRYPT     MACRO
        call    SymCryptAesEncryptAsmInternal
        ENDM

AES_DECRYPT     MACRO
        call    SYmCryptAesDecryptAsmInternal
        ENDM

;========================================
;               SymCryptAesEncryptAsmInternal
;
;               Internal AES encryption routine with modified calling convention.
;       This function has the exact same calling convention as the AES_ENCRYPT_MACRO


        LEAF_ENTRY SymCryptAesEncryptAsmInternal, _TEXT

        AES_ENCRYPT_MACRO

        ret
        
        LEAF_END SymCryptAesEncryptAsmInternal, _TEXT


;========================================
;       SymCryptAesDecryptAsmInternal
;
;       Internal AES encryption routine with modified calling convention.
;       This function has the exact same calling convention as the AES_DECRYPT_MACRO
;


        LEAF_ENTRY SymCryptAesDecryptAsmInternal, _TEXT

        AES_DECRYPT_MACRO
        
        ret
        
        LEAF_END SymCryptAesDecryptAsmInternal, _TEXT


        ELSE

        ;
        ; No block function, use the macro directly
        ;

AES_ENCRYPT     MACRO
        AES_ENCRYPT_MACRO
        ENDM

AES_DECRYPT     MACRO
        AES_DECRYPT_MACRO
        ENDM

        ENDIF



;
;VOID
;SYMCRYPT_CALL
;SymCryptAesEncrypt( _In_                                   PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;                    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_LEN )  PCBYTE                      pbPlaintext,
;                    _Out_writes_bytes_( SYMCRYPT_AES_BLOCK_LEN ) PBYTE                       pbCiphertext );
;

SymCryptAesEncryptFrame struct

SaveRdi         dq      ?
SaveRsi         dq      ?
SaveRbp         dq      ?
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?
CallerP4Home    dq      ?

SymCryptAesEncryptFrame ends

        NESTED_ENTRY    SymCryptAesEncryptAsm, _TEXT

        ;
        ; Prologue
        ; Pushes are as fast as stores and smaller, so we use those
        ;
        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY
        
        ;
        ; At this point the stack is not properly aligned, but as we only call our own internal function 
        ; with a modified calling convention this is not a problem. (Interrupt routines can deal with 
        ; unaligned stack, and the stack _will_ be aligned during the actual AES work.)
        ; 
        
        
        ; Parameters passed:
        ; rcx = pExpandedKey
        ; rdx = pbPlaintext
        ; r8 = pbCiphertext
        ;

        mov     r10, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        mov     r9, rcx

        mov     [rsp + SymCryptAesEncryptFrame.CallerP3Home], r8

        ;
        ; Load the plaintext
        ;
        mov     eax,[rdx     ]
        mov     ebx,[rdx +  4]
        mov     ecx,[rdx +  8]
        mov     edx,[rdx + 12]
        
        lea     r11,[SymCryptAesSboxMatrixMult]
        
        AES_ENCRYPT
        ;
        ; Plaintext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;

        mov     rdx,[rsp + SymCryptAesEncryptFrame.CallerP3Home]
        mov     [rdx     ], esi
        mov     [rdx +  4], edi
        mov     [rdx +  8], ebp
        mov     [rdx + 12], r8d

SymCryptAesEncryptAsmDone:

        BEGIN_EPILOGUE

        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret


        NESTED_END      SymCryptAesEncryptAsm, _TEXT


;
;VOID
;SYMCRYPT_CALL
;SymCryptAesDecrypt( _In_                                   PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;                    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_LEN )  PCBYTE                      pbCiphertext,
;                    _Out_writes_bytes_( SYMCRYPT_AES_BLOCK_LEN ) PBYTE                       pbPlaintext );
;


        NESTED_ENTRY    SymCryptAesDecryptAsm, _TEXT

SymCryptAesDecryptFrame struct

SaveR12                 dq      ?
SaveRdi                 dq      ?
SaveRsi                 dq      ?
SaveRbp                 dq      ?
SaveRbx                 dq      ?
ReturnAddress           dq      ?
pExpandedKeyHome        dq      ?
pbCiphertextHome        dq      ?
pbPlaintextHome         dq      ?
CallerP4Home            dq      ?

SymCryptAesDecryptFrame ends
        ;
        ; Prologue
        ; Pushes are as fast as stores and smaller, so we use those
        ;
        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        push_reg        r12
        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY
        
        ;
        ; At this point the stack is not properly aligned, but as we only call our own internal function 
        ; with a modified calling convention this is not a problem. (Interrupt routines can deal with 
        ; unaligned stack, and the stack _will_ be aligned during the actual AES work.)
        ; 
        
        
        ; Parameters passed:
        ; rcx = pExpandedKey
        ; rdx = pbCiphertext
        ; r8  = pbPlaintext
        ;
        
        mov     r9,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        mov     r10,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastDecRoundKey]

        mov     [rsp + SymCryptAesDecryptFrame.pbCiphertextHome], r8
        
        mov     eax,[rdx]
        mov     ebx,[rdx+4]
        mov     ecx,[rdx+8]
        mov     edx,[rdx+12]
        

        lea     r11,[SymCryptAesInvSboxMatrixMult]
        lea     r12,[SymCryptAesInvSbox]
        
        AES_DECRYPT
        ; Ciphertext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to InvSboxMatrixMult (unchanged)
        ; r12 points to InvSbox (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d

        mov     rdx,[rsp + SymCryptAesDecryptFrame.pbCiphertextHome]  ; retrieve bpPlaintext 
        mov     [rdx],esi
        mov     [rdx+4],edi
        mov     [rdx+8],ebp
        mov     [rdx+12],r8d

SymCryptAesDecryptAsmDone:

        BEGIN_EPILOGUE

        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

        NESTED_END      SymCryptAesDecryptAsm, _TEXT



;VOID
;SYMCRYPT_CALL
;SymCryptAesCbcEncrypt( 
;    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
;    _In_reads_bytes_( cbData )                   PCBYTE                      pbSrc,
;    _Out_writes_bytes_( cbData )                  PBYTE                       pbDst,
;                                            SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCbcEncryptAsm, _TEXT

AesCbcEncryptFrame struct

SaveR15         dq      ?
SaveR14         dq      ?
SaveR13         dq      ?
SaveR12         dq      ?
SaveRdi         dq      ?
SaveRsi         dq      ?
SaveRbp         dq      ?
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?
CallerP4Home    dq      ?
cbData          dq      ?

AesCbcEncryptFrame ends

        ;
        ; rcx = pExpandedKey
        ; rdx = pbChainingValue
        ; r8 = pbSrc
        ; r9 = pbDst
        ; [rsp+28] = cbData

        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15

        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        mov     r15,[rsp + AesCbcEncryptFrame.cbData]

        mov     [rsp + AesCbcEncryptFrame.CallerP2Home], rdx    ; save pbChainingValue
        
        mov     r13, r8                 ; r13 = pbSrc

        
        and     r15, NOT 15
        jz      SymCryptAesCbcEncryptNoData
        
        add     r15, r8

        mov     r14, r9                 ; r14 = pbDst
        
        mov     r10,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]   ; r10 = last enc round key
        
        ;
        ; Load the chaining state from pbChainingValue
        ;
        mov     esi,[rdx]
        mov     edi,[rdx+4]
        mov     ebp,[rdx+8]
        mov     r8d,[rdx+12]


        mov     r12,rcx                 ; r12 = first round key to use

        lea     r11,[SymCryptAesSboxMatrixMult]


        align   16
SymCryptAesCbcEncryptAsmLoop:   
        ; Loop register setup
        ; r10 = last round key to use
        ; r12 = first round key to use
        ; r13 = pbSrc
        ; r14 = pbDst
        ; r15 = pbSrcEnd
        
        ; chaining state in (esi,edi,ebp,r8d)

        mov     eax, [r13]
        mov     r9, r12
        mov     ebx, [r13+4]
        xor     eax, esi
        mov     ecx, [r13+8]
        xor     ebx, edi
        xor     ecx, ebp
        mov     edx, [r13+12]
        xor     edx, r8d
        
        add     r13, 16


        AES_ENCRYPT
        ;
        ; Plaintext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;

        mov     [r14], esi
        mov     [r14+4], edi
        mov     [r14+8], ebp
        mov     [r14+12], r8d

        add     r14, 16

        cmp     r13, r15
        
        jb      SymCryptAesCbcEncryptAsmLoop


        ;
        ; Update the chaining value
        ;
        mov     rdx,[rsp + AesCbcEncryptFrame.CallerP2Home]
        mov     [rdx], esi
        mov     [rdx+4], edi
        mov     [rdx+8], ebp
        mov     [rdx+12], r8d

SymCryptAesCbcEncryptNoData:
SymCryptAesCbcEncryptDone:

        BEGIN_EPILOGUE

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

        NESTED_END      SymCryptAesCbcEncryptAsm, _TEXT



;VOID
;SYMCRYPT_CALL
;SymCryptAesCbcDecrypt( 
;    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
;    _In_reads_bytes_( cbData )                   PCBYTE                      pbSrc,
;    _Out_writes_bytes_( cbData )                  PBYTE                       pbDst,
;                                            SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCbcDecryptAsm, _TEXT

AesCbcDecryptFrame struct

SaveR15         dq      ?
SaveR14         dq      ?
SaveR13         dq      ?
SaveR12         dq      ?
SaveRdi         dq      ?
SaveRsi         dq      ?
SaveRbp         dq      ?
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?       ;Tmp1
CallerP2Home    dq      ?       ;pbChainingValue
CallerP3Home    dq      ?       ;pbSrc
CallerP4Home    dq      ?       ;Tmp2
cbData          dq      ?

AesCbcDecryptFrame ends

        ;
        ; rcx = pExpandedKey
        ; rdx = pbChainingValue
        ; r8 = pbSrc
        ; r9 = pbDst
        ; [rsp+28] = cbData

        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15

        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        mov     r14,[rsp + AesCbcDecryptFrame.cbData]

        and     r14, NOT 15
        jz      SymCryptAesCbcDecryptNoData

        mov     r13,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        mov     r10,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastDecRoundKey]   

        mov     [rsp + AesCbcDecryptFrame.CallerP2Home], rdx    ;pbChainingValue
        mov     [rsp + AesCbcDecryptFrame.CallerP3Home], r8     ;pbSrc
        sub     r14, 16
        
        lea     r15,[r9 + r14]          ; r15 = pbDst pointed to last block
        add     r14, r8                 ; r14 = pbSrc pointed to last block

        lea     r11,[SymCryptAesInvSboxMatrixMult]
        lea     r12,[SymCryptAesInvSbox]

        ;
        ; Load last ciphertext block & save on stack (we need to put it in the pbChaining buffer later)
        ;
        mov     eax,[r14]
        mov     ebx,[r14+4]
        mov     ecx,[r14+8]
        mov     edx,[r14+12]
        
        mov     dword ptr [rsp + AesCbcDecryptFrame.CallerP1Home], eax
        mov     dword ptr [rsp + AesCbcDecryptFrame.CallerP1Home+4], ebx
        mov     dword ptr [rsp + AesCbcDecryptFrame.CallerP4Home], ecx
        mov     dword ptr [rsp + AesCbcDecryptFrame.CallerP4Home+4], edx

        jmp     SymCryptAesCbcDecryptAsmLoopEntry

        align   16
        
SymCryptAesCbcDecryptAsmLoop:   
        ; Loop register setup
        ; r13 = first round key to use
        ; r14 = pbSrc
        ; r15 = pbDst
        ; [callerP3Home] = pbSrcStart
        
        ; current ciphertext block (esi,edi,ebp,r8d)

        mov     eax,[r14-16]
        mov     ebx,[r14-12]
        xor     esi,eax
        mov     ecx,[r14-8]
        xor     edi,ebx
        mov     [r15],esi
        mov     edx,[r14-4]
        xor     ebp,ecx
        mov     [r15+4],edi
        xor     r8d,edx
        mov     [r15+8],ebp
        mov     [r15+12],r8d
        
        sub     r14,16
        sub     r15,16

SymCryptAesCbcDecryptAsmLoopEntry:

        mov     r9, r13

        AES_DECRYPT
        ;
        ; Ciphertext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to InvSboxMatrixMult (unchanged)
        ; r12 points to InvSbox (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;
        
        cmp     r14, [rsp + AesCbcDecryptFrame.CallerP3Home]    ; pbSrc
        ja      SymCryptAesCbcDecryptAsmLoop

        mov     rbx,[rsp + AesCbcDecryptFrame.CallerP2Home]     ; pbChainingValue
        xor     esi,[rbx]
        xor     edi,[rbx+4]
        xor     ebp,[rbx+8]
        xor     r8d,[rbx+12]
        
        mov     [r15], esi
        mov     [r15+4], edi
        mov     [r15+8], ebp
        mov     [r15+12], r8d

        ;
        ; Update the chaining value to the last ciphertext block
        ;
        mov     rax,[rsp + AesCbcDecryptFrame.CallerP1Home]
        mov     rcx,[rsp + AesCbcDecryptFrame.CallerP4Home]
        mov     [rbx], rax
        mov     [rbx+8], rcx

SymCryptAesCbcDecryptNoData:

        BEGIN_EPILOGUE

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

        NESTED_END      SymCryptAesCbcDecryptAsm, _TEXT



;VOID
;SYMCRYPT_CALL
;SymCryptAesCtrMsb64( 
;    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
;    _In_reads_bytes_( cbData )                   PCBYTE                      pbSrc,
;    _Out_writes_bytes_( cbData )                  PBYTE                       pbDst,
;                                            SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCtrMsb64Asm, _TEXT

AesCtrMsb64Frame struct

SaveR15         dq      ?
SaveR14         dq      ?
SaveR13         dq      ?
SaveR12         dq      ?
SaveRdi         dq      ?
SaveRsi         dq      ?
SaveRbp         dq      ?
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?   ; used to store the first  half of the chaining state
CallerP4Home    dq      ?   ; used to store the second half of the chaining state
cbData          dq      ?

AesCtrMsb64Frame ends

        ;
        ; rcx = pExpandedKey
        ; rdx = pbChainingValue
        ; r8 = pbSrc
        ; r9 = pbDst
        ; [rsp+28] = cbData

        rex_push_reg    rbx
        push_reg        rbp
        push_reg        rsi
        push_reg        rdi
        push_reg        r12
        push_reg        r13
        push_reg        r14
        push_reg        r15

        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        mov     r14,[rsp + AesCtrMsb64Frame.cbData]
        and     r14, NOT 15                     ; only deal with whole # blocks
        jz      SymCryptAesCtrMsb64NoData

        add     r14, r8     ; cbData + pbSrc = pbSrcEnd

        mov     [rsp + AesCtrMsb64Frame.CallerP2Home], rdx              ; save pbChainingState
        mov     r12, rcx                                                ; r12 = first round key to use
        mov     r10,[rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]   ; r10 = last enc round key
        
        mov     r13, r8     ; pbSrc
        mov     r15, r9     ; pbDst

        lea     r11,[SymCryptAesSboxMatrixMult]

        ; 
        ; Load the chaining state
        ;
        mov     rax, [rdx +  0]
        mov     rcx, [rdx +  8]

        ;
        ; Store it in our local copy (we have no register free to keep pbChainingState in)
        ;
        mov     [rsp + AesCtrMsb64Frame.CallerP3Home + 0], rax
        mov     [rsp + AesCtrMSb64Frame.CallerP3Home + 8], rcx

        ;
        ; Move to the right registers
        ;
        mov     rbx, rax
        mov     rdx, rcx
        shr     rbx, 32
        shr     rdx, 32

        align   16
SymCryptAesCtrMsb64AsmLoop:   
        ; Loop invariant
        ; Current chaining state is in (eax, ebx, ecx, edx)
        ; r10 = last round key to use
        ; r11 = SboxMatrixMult
        ; r12 = first round key to use
        ; r13 = pbSrc
        ; r14 = pbSrcEnd
        ; r15 = pbDst
        ; [rsp + CallerP3Home] = 16 bytes chaining state block
    
        mov     r9, r12

        AES_ENCRYPT
        ;
        ; Plaintext in eax, ebx, ecx, edx
        ; r9 points to first round key to use
        ; r10 is last key to use (unchanged)
        ; r11 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in esi, edi, ebp, r8d
        ;

        ; To improve latency, we FIRST 
        ; load the chaining state, increment the counter, and write it back.
        ; leave the state in the (eax, ebx, ecx, edx) registers

        mov     eax,dword ptr [rsp + AesCtrMsb64Frame.CallerP3Home + 0]
        mov     ebx,dword ptr [rsp + AesCtrMsb64Frame.CallerP3Home + 4]
        mov     rcx,[rsp + AesCtrMsb64Frame.CallerP3Home + 8 ]
        bswap   rcx
        add     rcx, 1
        bswap   rcx
        mov     [rsp + AesCtrMsb64Frame.CallerP3Home + 8], rcx
        mov     rdx, rcx
        shr     rdx, 32

        ; THEN we process the XOR of the key stream with the data
        ; This order is faster as we need to have the chaining state done
        ; before we can proceed, but there are no dependencies on the data result
        ; So we can loop back to the beginning while the data stream read/writes are
        ; still in flight.
        ;
        ; xor with the source stream

        xor     esi,[r13 + 0 ]
        xor     edi,[r13 + 4 ]
        xor     ebp,[r13 + 8 ]
        xor     r8d,[r13 + 12]

        ; store at the destination

        mov     [r15 + 0], esi
        mov     [r15 + 4], edi
        mov     [r15 + 8], ebp
        mov     [r15 + 12], r8d

        add     r13, 16     ; pbSrc += 16
        add     r15, 16     ; pbDst += 16

        cmp     r13, r14
        
        jb      SymCryptAesCtrMsb64AsmLoop

        ;
        ; Copy back the chaining value; we only modified the last 8 bytes, so that is all we copy
        ;
        mov     rsi,[rsp + AesCtrMsb64Frame.CallerP2Home]   ; pbChainingState
        mov     [rsi + 8], ecx
        mov     [rsi + 12], edx

        ;
        ; Wipe the chaining value on stack
        ;
        xor     rax, rax
        mov     [rsp + AesCtrMsb64Frame.CallerP3Home], rax
        mov     [rsp + AesCtrMsb64Frame.CallerP4Home], rax

SymCryptAesCtrMsb64NoData:

        BEGIN_EPILOGUE

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

        NESTED_END      SymCryptAesCtrMsb64Asm, _TEXT


if 0
        LEAF_ENTRY    SymCryptAesEncryptXmm, _TEXT
        ;
        ; rcx = expanded key
        ; rdx = pbSrc
        ; r8 = pbDst

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        movups  xmm0,[rdx]
        mov     r10, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        
        
        AES_ENCRYPT_XMM
        ; xmm0 contains the plaintext
        ; rcx points to first round key to use
        ; r10 is last key to use (unchanged)
        
        movups  [r8],xmm0

        ret
        
        LEAF_END      SymCryptAesEncryptXmm, _TEXT
endif

if 0

        LEAF_ENTRY    SymCryptAesDecryptXmm, _TEXT
        ;
        ; rcx = expanded key
        ; rdx = pbSrc
        ; r8 = pbDst

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        movups  xmm0,[rdx]
        mov     r10, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastDecRoundKey]
        mov     rcx, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        
        
        AES_DECRYPT_XMM
        ; xmm0 contains the plaintext
        ; rcx points to first round key to use
        ; r10 is last key to use (unchanged)
        
        movups  [r8],xmm0

        ret
        
        LEAF_END      SymCryptAesDecryptXmm, _TEXT
endif

if 0

        LEAF_ENTRY      SymCryptAesCbcEncryptXmm, _TEXT
;VOID
;SYMCRYPT_CALL
;SymCryptAesCbcEncrypt( 
;    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
;    _In_reads_bytes_( cbData )                   PCBYTE                      pbSrc,
;    _Out_writes_bytes_( cbData )                  PBYTE                       pbDst,
;                                            SIZE_T                      cbData );

SymCryptAesCbcEncryptXmmFrame struct

ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?
CallerP4Home    dq      ?
cbData          dq      ?

SymCryptAesCbcEncryptXmmFrame ends

        ; rcx = expanded key
        ; rdx = pbChainingValue
        ; r8 = pbSrc
        ; r9 = pbDst

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY
        
        mov     rax,[rsp + SymCryptAesCbcEncryptXmmFrame.cbData]
        mov     r11,rcx                 ; first round key
        and     rax, NOT 15
        jz      SymCryptAesCbcEncryptXmmDone

        ; [rsp + 40] = cbData

        mov     r10, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]

        add     rax, r8                 ; rax = pbSrcEnd
        
        movups  xmm0,[rdx]

SymCryptAesCbcEncryptAsmXmmLoop:
        movups  xmm1,[r8]
        add     r8,16
        
        pxor    xmm0,xmm1
        
        mov     rcx, r11

        AES_ENCRYPT_XMM
        ; xmm0 contains the plaintext
        ; rcx points to first round key to use
        ; r10 is last key to use (unchanged)
        ; Ciphertext ends up in xmm0

        movups  [r9],xmm0
        add     r9, 16
        cmp     r8, rax
        jb      SymCryptAesCbcEncryptAsmXmmLoop

        movups  [rdx],xmm0

SymCryptAesCbcEncryptXmmDone:

        ret
        
        LEAF_END        SymCryptAesCbcEncryptXmm, _TEXT

endif

if 0    ; Replaced with C code using intrinics.

        LEAF_ENTRY      SymCryptAesDecryptXmm4, _TEXT
        ; decrypt xmm0-3 
        ; Registers used: xmm4
        ; rcx = first key, r10 = last key
        ; rcx is destroyed

        movaps  xmm4,[rcx]
        lea     rcx, [rcx+16]
        pxor    xmm0, xmm4
        pxor    xmm1, xmm4
        pxor    xmm2, xmm4
        pxor    xmm3, xmm4

@@:     movaps  xmm4,[rcx]
        add     rcx,16
        aesdec  xmm0, xmm4
        aesdec  xmm1, xmm4
        aesdec  xmm2, xmm4
        aesdec  xmm3, xmm4

        cmp     rcx, r10
        jc      @B

        movaps  xmm4,[r10]
        
        aesdeclast      xmm0, xmm4
        aesdeclast      xmm1, xmm4
        aesdeclast      xmm2, xmm4
        aesdeclast      xmm3, xmm4
       
        ret     

        LEAF_END        SymCryptAesDecryptXmm4, _TEXT



        NESTED_ENTRY    SymCryptAesCbcDecryptXmm, _TEXT
;VOID
;SYMCRYPT_CALL
;SymCryptAesCbcDecrypt( 
;    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;    _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
;    _In_reads_bytes_( cbData )                   PCBYTE                      pbSrc,
;    _Out_writes_bytes_( cbData )                  PBYTE                       pbDst,
;                                            SIZE_T                      cbData )

SymCryptAesCbcDecryptXmmFrame struct

SaveXmm9        dq      2 dup (?)
SaveXmm8        dq      2 dup (?)
SaveXmm7        dq      2 dup (?)
SaveXmm6        dq      2 dup (?)
SaveRbx         dq      ?
ReturnAddress   dq      ?
CallerP1Home    dq      ?
CallerP2Home    dq      ?
CallerP3Home    dq      ?
CallerP4Home    dq      ?
cbData          dq      ?

SymCryptAesCbcDecryptXmmFrame ends


        rex_push_reg    rbx
        alloc_stack     SymCryptAesCbcDecryptXmmFrame.SaveRbx
        save_xmm128     xmm6, oword ptr SymCryptAesCbcDecryptXmmFrame.SaveXmm6
        save_xmm128     xmm7, oword ptr SymCryptAesCbcDecryptXmmFrame.SaveXmm7
        save_xmm128     xmm8, oword ptr SymCryptAesCbcDecryptXmmFrame.SaveXmm8
        save_xmm128     xmm9, oword ptr SymCryptAesCbcDecryptXmmFrame.SaveXmm9

        END_PROLOGUE

        SYMCRYPT_CHECK_MAGIC    rcx, SYMCRYPT_AES_EXPANDED_KEY

        ; rcx = key
        ; rdx = chaining value
        ; r8 = pbSrc
        ; r9 = pbDst
        ; [rsp + cbData] = cbData

        mov     rbx,[rsp + SymCryptAesCbcDecryptXmmFrame.cbData]
        and     rbx, NOT 15
        jz      SymCryptAesCbcDecryptXmmNoData
        

        xor     rax, rax                ; offset into buffers
        
        mov     r10, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastDecRoundKey]
        mov     r11, [rcx + SYMCRYPT_AES_EXPANDED_KEY.lastEncRoundKey]
        
        movups  xmm5, [rdx]             ; load IV


        sub     rbx, 64                 ; cbData - 64
        jc      SymCryptAesCbcDecryptXmmPartial
        
SymCryptAesCbcDecryptXmm4Loop:
        ;
        ; xmm5 = IV
        ; r8 = pbSrc
        ; r9 = pbDst
        ; rax = offset into buffer; we will process bytes rax..rax+63 in this iteration
        ; rbx = cbData - 64
        ; rax <= rbx
        ; 

        movups  xmm0,[r8 + rax]
        movups  xmm1,[r8 + rax + 16]
        movaps  xmm6, xmm0
        movups  xmm2,[r8 + rax + 32]
        movaps  xmm7, xmm1
        movups  xmm3,[r8 + rax + 48]
        movaps  xmm8, xmm2
        movaps  xmm9, xmm3

        mov     rcx, r11
        call    SymCryptAesDecryptXmm4  ; decrypt xmm0-3 using xmm4.  rcx = first key, r10 = last key

        pxor    xmm0, xmm5
        pxor    xmm1, xmm6
        movups  [r9 + rax], xmm0
        pxor    xmm2, xmm7
        movups  [r9 + rax + 16], xmm1
        pxor    xmm3, xmm8
        movups  [r9 + rax + 32], xmm2
        movups  [r9 + rax + 48], xmm3
        
        movaps  xmm5, xmm9

        add     rax,64
        cmp     rax,rbx
        jbe     SymCryptAesCbcDecryptXmm4Loop

        test    rbx,63
        jz      SymCryptAesCbcDecryptXmmDone    ; cbData was a multiple of 64, no partial block

        sub     rbx, rax                        ; rbx = bytes left - 64

SymCryptAesCbcDecryptXmmPartial:
        ;
        ; r8 = pbSrc
        ; r9 = pbDst
        ; rax = current offset 
        ; rbx = # bytes left to do - 64, # bytes left is nonzero
        ;
        
        movups  xmm0,[r8+rax]
        movaps  xmm6,xmm0
        cmp     rbx,16 - 64
        jz      SymCryptAesCbcDecryptXmmPartialLoadDone

        movups  xmm1,[r8+rax+16]
        movaps  xmm7,xmm1
        cmp     rbx,32 - 64
        jz      SymCRyptAesCbcDecryptXmmPartialLoadDone

        movups  xmm2,[r8+rax+32]
        movaps  xmm8, xmm2

SymCryptAesCbcDecryptXmmPartialLoadDone:

        mov     rcx,r11
        call    SymCryptAesDecryptXmm4

        pxor    xmm0, xmm5
        movups  [r9 + rax], xmm0
        movaps  xmm5, xmm6
        cmp     rbx, 16 - 64
        jz      SymCryptAesCbcDecryptXmmDone

        pxor    xmm1, xmm6
        movups  [r9 + rax + 16], xmm1
        movaps  xmm5, xmm7
        cmp     rbx, 32 - 64
        jz      SymCryptAesCbcDecryptXmmDone

        pxor    xmm2, xmm7
        movups  [r9 + rax + 32], xmm2
        movaps  xmm5, xmm8

SymCryptAesCbcDecryptXmmDone:
        movups  [rdx], xmm5

SymCryptAesCbcDecryptXmmNoData:

        movaps  xmm6, oword ptr [rsp + SymCryptAesCbcDecryptXmmFrame.SaveXmm6]
        movaps  xmm7, oword ptr [rsp + SymCryptAesCbcDecryptXmmFrame.SaveXmm7]
        movaps  xmm8, oword ptr [rsp + SymCryptAesCbcDecryptXmmFrame.SaveXmm8]
        movaps  xmm9, oword ptr [rsp + SymCryptAesCbcDecryptXmmFrame.SaveXmm9]

        add     rsp,SymCryptAesCbcDecryptXmmFrame.SaveRbx

        BEGIN_EPILOGUE

        pop     rbx
        ret
        
        NESTED_END      SymCryptAesCbcDecryptXmm, _TEXT

endif

if 0    ; No longer used; replaced with C code using intrinsics that can be inlined.
;
;VOID
;SymCryptAes4SboxXmm( _In_reads_bytes_(4) PCBYTE pIn, _Out_writes_bytes_(4) PBYTE pOut );
;
        LEAF_ENTRY SymCryptAes4SboxXmm, _TEXT
        ;
        ;rcx points to source 
        ;rdx points to destination
        ;
        ;We only use volatile registers so we do not have to save any registers.
        ;

        mov     eax,[rcx]       ; Use a register to avoid alignment issues
        movd    xmm0, eax

        movsldup        xmm0, xmm0      ; copy [31:0] to [63:32]
        aeskeygenassist xmm0, xmm0, 0

        movd    eax, xmm0
        mov     [rdx], eax

        ret

        LEAF_END SymCryptAes4SboxXmm, _TEXT


;
;VOID
;AesCreateDecryptionRoundKeyXmm( _In_reads_bytes_(16) PCBYTE pEncryptionRoundKey, 
;                                _Out_writes_bytes_(16) PBYTE pDecryptionRoundKey );
;
        LEAF_ENTRY      SymCryptAesCreateDecryptionRoundKeyXmm, _TEXT
        ;rcx points to source
        ;rdx points to destination

        movups  xmm0,[rcx]
        aesimc  xmm0, xmm0
        movups  [rdx], xmm0
        ret

        LEAF_END        SymCryptAesCreateDecryptionRoundKeyXmm, _TEXT

endif

        end

