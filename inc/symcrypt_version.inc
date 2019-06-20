;/*
; SymCrypt_version.inc
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; This is the file that contains the SymCrypt version information.
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
; In previous releases we had a numbering system with  major/minor version number.
; This worked well with the sequential servicing imposed by SourceDepot. 
; With the switch to Git this no longer works due to having multiple branches.
; We move to having the version here only specify the API and minor version number
; These will NOT be changed for every build. The API version only changes when there are
; changes to the API in symcrypt.h. (Note: symcrypt_low_level.h is not stable and can change
; at any time.) The minor version is changed at regular intervals, but not necesarilly at
; every build of the library.
;
; Separate from these numbers the build system includes information about the branch,
; last commit, build time, etc.
;
; The API numbering starts at 100 to avoid number conficts with the old system.
;


SYMCRYPT_CODE_VERSION_API       EQU     100
SYMCRYPT_CODE_VERSION_MINOR     EQU     3


        if      0               ; Start an area that the assembler ignores
;*/                             // End of C comment, the C compiler will read the lines below

#define SYMCRYPT_CODE_VERSION_API       100
#define SYMCRYPT_CODE_VERSION_MINOR     3

;/*                             ; Switch back into a C comment so that we can close the IF
        endif
;*/     
