;/*
; SymCrypt_version.inc
; Copyright (c) Microsoft Corporation.  All rights reserved.
;
; This is the file that contains the SymCrypt version information. It is updated by the build system 
; so that each version of the library has a unique version number.
; 
; THIS FILE IS INCLUDED BOTH IN C AND ASSEMBLER CODE
; which is why the layout is strange.
; The first line is ";/_*" (without the _) 
; which is an assembler comment, and the start of a C comment.
; (In C an extra semicolon is allowed.)
; (The extra _ is added above to not break compilers who violate the C standard and 
; allow nested slash-star comments.)
; Below we have separate areas where the C and ASM version numbers are defined.
; These should always be the same.
;
; The API version is intended to change when we change the API behavior in a way that
; breaks backward compatibility. Currently this value is not used.
;
; The release version is incremented for every 'release' build. 
; For private builds between releases the private version number is incremented.
;

SYMCRYPT_API_VERSION    EQU     1

SYMCRYPT_CODE_VERSION_RELEASE   EQU     86
SYMCRYPT_CODE_VERSION_PRIVATE   EQU     0


        if      0               ; Start an area that the assembler ignores
;*/                             // End of C comment, the C compiler will read the lines below

#define SYMCRYPT_API_VERSION    1

#define SYMCRYPT_CODE_VERSION_RELEASE   86
#define SYMCRYPT_CODE_VERSION_PRIVATE   0

;/*                             ; Switch back into a C comment so that we can close the IF
        endif
;*/     
