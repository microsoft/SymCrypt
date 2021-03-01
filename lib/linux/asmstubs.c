//
// asmstubs.c
// Temporary forwarders for ASM implementations which we don't yet support with GCC/LLVM
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "../precomp.h"

extern const SYMCRYPT_BLOCKCIPHER SymCryptAesBlockCipherNoOpt;

VOID
SYMCRYPT_CALL
SymCryptAesEncryptAsm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_(SYMCRYPT_AES_BLOCK_SIZE)     PCBYTE                      pbSrc,
    _Out_writes_(SYMCRYPT_AES_BLOCK_SIZE)   PBYTE                       pbDst )
{
    SymCryptAesEncryptC( pExpandedKey, pbSrc, pbDst );
}

VOID
SYMCRYPT_CALL
SymCryptAesDecryptAsm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_(SYMCRYPT_AES_BLOCK_SIZE)     PCBYTE                      pbSrc,
    _Out_writes_(SYMCRYPT_AES_BLOCK_SIZE)   PBYTE                       pbDst )
{
    SymCryptAesDecryptC( pExpandedKey, pbSrc, pbDst );
}

VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SymCryptCbcEncrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SymCryptCbcDecrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Asm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE ); // keep Prefast happy
    SymCryptCtrMsb64( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

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
SymCryptFdefRawMulMulx(
    _In_reads_(nDgigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)   PCUINT32    pSrc1,
                                                        UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)    PCUINT32    pSrc2,
                                                        UINT32      nDigits2,
    _Out_writes_(nWords1 + nWords2)                     PUINT32     pDst )
{
    SymCryptFdefRawMulC( pSrc1, nDigits1, pSrc2, nDigits2, pDst );
}

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
SymCryptFdefRawSquareMulx(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)         PCUINT32    pSrc,
                                                            UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PUINT32     pDst )
{
    SymCryptFdefRawSquareC( pSrc, nDigits, pDst );
}

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
SymCryptFdefMontgomeryReduceMulx(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst )
{
    SymCryptFdefMontgomeryReduceC( pmMod, pSrc, pDst );
}

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduceAsm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst )
{
    SymCryptFdefMontgomeryReduceC( pmMod, pSrc, pDst );
}