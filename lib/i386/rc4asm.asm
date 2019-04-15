;
;     rc4asm.asm
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
;       RC4 implementation in x86 assembler
;       This is a new RC4 implementation for SymCrypt.
;       It is NOT based on the existing one in RSA32.lib.
;


        TITLE   "RC4"
        .586P

_TEXT   SEGMENT PARA PUBLIC USE32 'CODE'
        ASSUME  CS:_TEXT, DS:FLAT, SS:FLAT

include <..\..\inc\symcrypt_version.inc>
include symcrypt_magic.inc

;
; Structure definition that mirrors the SYMCRYPT_RC4_STATE struct
;
        
RC4_STATE struct
        S               db      256 dup (?)
        i               db      ?
        j               db      ?

        SYMCRYPT_MAGIC_FIELD
        
RC4_STATE ends

        
        PUBLIC  @SymCryptRc4InitAsm@12
        PUBLIC  @SymCryptRc4CryptAsm@16


BEFORE_PROC     MACRO
        ;
        ; Our current x86 compiler inserts 5 0xcc bytes before every function
        ; and starts every function with a 2-byte NOP.
        ; This supports hot-patching.
        ;
        DB      5 dup (0cch)
                ENDM


; The .FPO provides debugging information.
; This stuff not well documented, 
; but here is the information I've gathered about the arguments to .FPO
; 
; In order:
; cdwLocals: Size of local variables, in DWords
; cdwParams: Size of parameters, in DWords. Given that this is all about
;            stack stuff, I'm assuming this is only about parameters passed
;            on the stack.
; cbProlog : Number of bytes in the prolog code. We have interleaved the
;            prolog code with work for better performance. Most uses of
;            .FPO seem to set this value to 0 anyway, which is what we
;            will do.
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



        BEFORE_PROC
        
@SymCryptRc4InitAsm@12   PROC
;VOID
;SYMCRYPT_CALL
;SymCryptRc4InitAsm( 
;    _Out_                   PSYMCRYPT_RC4_STATE pState,
;    _In_reads_bytes_( cbKey )    PCBYTE              pbKey,
;    _In_                    SIZE_T              cbKey );
;
; NOTE: Unlike the SymCryptRc4Init function 
; this function does not check the cbKey validity, and does not return an error code.
; Currently we don't have the error code values symbolically in the asm environment.
; We use an inlined function to generate the errors instead, and call this function
; only when there are no errors.
;

Rc4InitFrame struct  4, NONUNIQUE

pbKey           dd      ?
SaveEdi         dd      ?
SaveEsi         dd      ?
SaveEbp         dd      ?
SaveEbx         dd      ?
ReturnAddress   dd      ?
cbKey           dd      ?

Rc4InitFrame ends

        .FPO(5,1,0,4,0,0)

        ; ecx = pState
        ; edx = pKey
        ; [esp + 4] = cbKey

        ;
        ; Set up stack frame, and initialize pbKey
        ;
        mov     edi,edi         ; 2-byte NOP for hot-patching
        
        push    ebx
        push    ebp
        push    esi
        push    edi
        push    edx

        ;
        ; Initialize S[i] = i
        ;
        lea     esi,[ecx + 100h]
        mov     edi,ecx
        
        mov     eax,03020100h
        mov     ebx,04040404h

@@:
        mov     [edi],eax
        add     eax,ebx
        mov     [edi+4],eax
        add     eax,ebx
        mov     [edi+8],eax
        add     eax,ebx
        mov     [edi+12],eax
        add     eax,ebx
        add     edi,16
        cmp     edi,esi
        jb      @B


        mov     ebp,edx         
        xor     ebx,ebx         ; j = 0
        xor     esi,esi         ; i = 0 
        mov     edi,[esp + Rc4InitFrame.cbKey]  
        add     edi, edx        ; edi = pbKey + cbKey
        
SymCryptRc4InitMainLoop:
        ; Registers:
        ; eax = Tmp1
        ; ebx = j
        ; ecx = S
        ; edx = Tmp2
        ; esi = i       
        ; edi = keyLimit        ; just beyond the key
        ; ebp = pKey    ; pointer to current key byte

        movzx   edx,byte ptr[ebp]       ; get key byte
        add     ebx,edx                 ; j += key byte
        movzx   eax,byte ptr[ecx + esi] ; get S[i]
        add     ebx,eax                 ; j += S[i]
        
        and     ebx,0ffh

        movzx   edx,byte ptr [ecx + ebx]; get S[j]
        mov     byte ptr[ecx + ebx], al ; update S[j]
        mov     byte ptr[ecx + esi], dl ; update S[i]

        add     ebp,1                   ; increment key pointer modulo key length
        cmp     ebp,edi
        jb      @F
        mov     ebp,[esp + Rc4InitFrame.pbKey]
@@:

        add     esi,1                   ; increment i
        cmp     esi,100h
        jb      SymCryptRc4InitMainLoop

        mov     word ptr [ecx + RC4_STATE.i], 1 ; i = 1; j = 0

        add     esp,4
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        ret     4

        
@SymCryptRc4InitAsm@12   ENDP




        BEFORE_PROC

@SymCryptRc4CryptAsm@16         PROC
;VOID
;SYMCRYPT_CALL
;SymCryptRc4Crypt( 
;    _Inout_                 PSYMCRYPT_RC4_STATE pState,
;    _In_reads_bytes_( cbData )   PCBYTE              pbSrc,
;    _Out_writes_bytes_( cbData )  PBYTE               pbDst,
;    _In_                    SIZE_T              cbData )

Rc4CryptFrame struct  4, NONUNIQUE
pbEndDst        dd      ?
SaveEdi         dd      ?
SaveEsi         dd      ?
SaveEbp         dd      ?
SaveEbx         dd      ?
ReturnAddress   dd      ?
pbDst           dd      ?
cbData          dd      ?

Rc4CryptFrame ends

        .FPO(5,2,0,4,0,0)


        mov     edi,edi

        push    ebx
        push    ebp
        push    esi
        push    edi
        sub     esp,4

        SYMCRYPT_CHECK_MAGIC    ecx, RC4_STATE

        mov     eax,[esp + Rc4CryptFrame.cbData]
        test    eax,eax
        jz      Rc4CryptDoNothing

        mov     ebp,[esp + Rc4CryptFrame.pbDst]
        add     eax,ebp
        mov     [esp + Rc4CryptFrame.pbEndDst], eax
        
        mov     edi, edx
        movzx   edx,[ecx + RC4_STATE.i]
        movzx   esi,[ecx + RC4_STATE.j]

        ;
        ; Further perf improvements are possible.
        ; Instead of encrypting byte-by-byte, we can collect 4 bytes of the key
        ; stream in a register, and then encrypt 4 bytes at a time.
        ; This reduces the # memory operations we do per byte.
        ; Ideally this is done with aligned operations, either
        ; aligning to pbSrc, pbDst, or to i (which removes the need to increment i every time).
        ; 

@@:     
        ; eax   Ti
        ; ebx   Tj
        ; ecx   S
        ; edx   i
        ; esi   j
        ; edi   pSrc
        ; ebp   pDst

        movzx   eax, byte ptr[ecx + edx]        ; Ti = S[i]
        
        ;add    esi, eax
        ;and    esi, 0ffh
        lea     ebx, [esi + eax]
        movzx   esi, bl                         ; j += Ti
        
        movzx   ebx, byte ptr[ecx + esi]        ; Tj = S[j]
        mov     [ecx + edx], bl                 ; S[i] = Tj
        mov     [ecx + esi], al                 ; S[j] = Ti
        
        ;add    eax,ebx
        ;and    eax,0ffh
        lea     eax,[eax + ebx]                 
        movzx   eax,al                          ; Ti = Ti + Tj
        
        mov     al,[ecx + eax]                  ; Til = S[Ti]

        ;add    edx, 1
        ;and    0ffh
        lea     edx,[edx + 1]
        movzx   edx,dl                          ; i += 1
        
        xor     al,[edi]
        add     edi,1
        mov     [ebp],al
        add     ebp, 1

        cmp     ebp,[esp + Rc4CryptFrame.pbEndDst]
        jb      @B

        mov     eax, esi
        mov     [ecx + RC4_STATE.i], dl
        mov     [ecx + RC4_STATE.j], al

Rc4CryptDoNothing:
        
        add     esp,4
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        ret     8


@SymCryptRc4CryptAsm@16         ENDP
        


_TEXT   ENDS
        
        END
