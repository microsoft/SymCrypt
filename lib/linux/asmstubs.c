//
// asmstubs.c
// Temporary forwarders for ASM implementations which we don't yet support with GCC/LLVM on Arm64
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "../precomp.h"

VOID
SYMCRYPT_CALL
SymCryptWipeAsm( _Out_writes_bytes_( cbData ) PVOID pbData, SIZE_T cbData )
{
    volatile BYTE * p = (volatile BYTE *) pbData;
    SIZE_T i;

    for( i=0; i<cbData; i++ ){
        p[i] = 0;
    }

}

VOID
SYMCRYPT_CALL
SymCryptFdefMaskedCopyC(
    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
                                                                UINT32      nDigits,
                                                                UINT32      mask );

VOID
SYMCRYPT_CALL
SymCryptFdefMaskedCopyAsm(
    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
                                                                UINT32      nDigits,
                                                                UINT32      mask )
{
    SymCryptFdefMaskedCopyC( pbSrc, pbDst, nDigits, mask );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefRawAddC(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawAddAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits )
{
    return SymCryptFdefRawAddC( pSrc1, pSrc2, pDst, nDigits );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefRawSubC(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawSubAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits )
{
    return SymCryptFdefRawSubC( pSrc1, pSrc2, pDst, nDigits );
}

VOID
SYMCRYPT_CALL
SymCryptFdefRawMulC(
    _In_reads_(nWords1)             PCUINT32    pSrc1,
                                    UINT32      nDigits1,
    _In_reads_(nWords2)             PCUINT32    pSrc2,
                                    UINT32      nDigits2,
    _Out_writes_(nWords1 + nWords2) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMulAsm(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)   PCUINT32    pSrc1,
                                                        UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc2,
                                                        UINT32      nDigits2,
    _Out_writes_(nWords1 + nWords2)                     PUINT32     pDst )
{
    SymCryptFdefRawMulC( pSrc1, nDigits1, pSrc2, nDigits2, pDst );
}

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquareC(
    _In_reads_(nWords)              PCUINT32    pSrc,
                                    UINT32      nDigits,
    _Out_writes_(2*nWords)          PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquareAsm(
    _In_reads_(nDgigits*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc,
                                                        UINT32      nDigits,
    _Out_writes_(2*nWords)                              PUINT32     pDst )
{
    SymCryptFdefRawSquareC( pSrc, nDigits, pDst );
}

VOID
SymCryptFdefMontgomeryReduceC(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduceAsm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst )
{
    SymCryptFdefMontgomeryReduceC( pmMod, pSrc, pDst );
}
