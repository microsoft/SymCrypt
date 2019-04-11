//
// aes-default.c   code for AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This is the interface for the default AES implementation.
// On each platform, this is the fastest AES implementation irrespective of code size.
// It uses assembler, XMM, or any other trick.
//


#include "precomp.h"

//
// Virtual table for generic functions
// This allows us to default to generic implementations for some modes without pulling in all the
// dedicated functions.
// We use this when we cannot use the optimized implementations for some reason.
//
const SYMCRYPT_BLOCKCIPHER SymCryptAesBlockCipherNoOpt = {
    &SymCryptAesExpandKey,
#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_ARM
    &SymCryptAesEncryptAsm,
    &SymCryptAesDecryptAsm,
#else
    &SymCryptAesEncryptC,
    &SymCryptAesDecryptC,
#endif
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,                
    NULL,                   // PSYMCRYPT_BLOCKCIPHER_CRYPT_XTS     xtsEncFunc;
    NULL,                   // PSYMCRYPT_BLOCKCIPHER_CRYPT_XTS     xtsDecFunc;

    SYMCRYPT_AES_BLOCK_SIZE,         
    sizeof( SYMCRYPT_AES_EXPANDED_KEY ),
};

VOID
SYMCRYPT_CALL
SymCryptAes4Sbox( _In_reads_(4) PCBYTE pIn, _Out_writes_(4) PBYTE pOut, BOOL UseSimd )
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    if( UseSimd )
    {
        SymCryptAes4SboxXmm( pIn, pOut );
    } else {
        SymCryptAes4SboxC( pIn, pOut );
    }
#elif SYMCRYPT_CPU_ARM64
    if( UseSimd )
    {
        SymCryptAes4SboxNeon( pIn, pOut );
    } else {
        SymCryptAes4SboxC( pIn, pOut );
    }
#else
    UNREFERENCED_PARAMETER( UseSimd );
    SymCryptAes4SboxC( pIn, pOut );         // never use XMM on SaveXmm arch, save/restore overhead is too large.
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKey( 
    _In_reads_(16)      PCBYTE  pEncryptionRoundKey, 
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey,
                        BOOL    UseSimd )
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    if( UseSimd )
    {
        SymCryptAesCreateDecryptionRoundKeyXmm( pEncryptionRoundKey, pDecryptionRoundKey );
    } else {
        SymCryptAesCreateDecryptionRoundKeyC( pEncryptionRoundKey, pDecryptionRoundKey );
    }
#elif SYMCRYPT_CPU_ARM64
    if( UseSimd )
    {
        SymCryptAesCreateDecryptionRoundKeyNeon( pEncryptionRoundKey, pDecryptionRoundKey );
    } else {
        SymCryptAesCreateDecryptionRoundKeyC( pEncryptionRoundKey, pDecryptionRoundKey );
    }
#else
    UNREFERENCED_PARAMETER( UseSimd );
    SymCryptAesCreateDecryptionRoundKeyC( pEncryptionRoundKey, pDecryptionRoundKey );   // never use XMM on SaveXmm arch, save/restore overhead is too large.
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesEncrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_(SYMCRYPT_AES_BLOCK_SIZE)     PCBYTE                      pbSrc,
    _Out_writes_(SYMCRYPT_AES_BLOCK_SIZE)   PBYTE                       pbDst )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesEncryptXmm( pExpandedKey, pbSrc, pbDst );
    } else {
        SymCryptAesEncryptAsm( pExpandedKey, pbSrc, pbDst );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptAesEncryptXmm( pExpandedKey, pbSrc, pbDst );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesEncryptAsm( pExpandedKey, pbSrc, pbDst );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptAesEncryptAsm( pExpandedKey, pbSrc, pbDst );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesEncryptNeon( pExpandedKey, pbSrc, pbDst );
    } else {
        SymCryptAesEncryptC( pExpandedKey, pbSrc, pbDst );
    }
#else
    SymCryptAesEncryptC( pExpandedKey, pbSrc, pbDst );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesDecrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_(SYMCRYPT_AES_BLOCK_SIZE)     PCBYTE                      pbSrc,
    _Out_writes_(SYMCRYPT_AES_BLOCK_SIZE)   PBYTE                       pbDst )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesDecryptXmm( pExpandedKey, pbSrc, pbDst );
    } else {
        SymCryptAesDecryptAsm( pExpandedKey, pbSrc, pbDst );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptAesDecryptXmm( pExpandedKey, pbSrc, pbDst );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesDecryptAsm( pExpandedKey, pbSrc, pbDst );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptAesDecryptAsm( pExpandedKey, pbSrc, pbDst );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesDecryptNeon( pExpandedKey, pbSrc, pbDst );
    } else {
        SymCryptAesDecryptC( pExpandedKey, pbSrc, pbDst );
    }
#else
    SymCryptAesDecryptC( pExpandedKey, pbSrc, pbDst );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesCbcEncrypt( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesCbcEncryptXmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptAesCbcEncryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
            SymCryptAesCbcEncryptXmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
            SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesCbcEncryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptAesCbcEncryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesCbcEncryptNeon( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptCbcEncrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#else
    SymCryptCbcEncrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesCbcDecrypt( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesCbcDecryptXmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptAesCbcDecryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
            SymCryptAesCbcDecryptXmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
            SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesCbcDecryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptAesCbcDecryptAsm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesCbcDecryptNeon( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptCbcDecrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }
#else
    SymCryptCbcDecrypt( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesEcbEncrypt( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesEcbEncryptXmm( pExpandedKey, pbSrc, pbDst, cbData );
    } else {
        SymCryptAesEcbEncryptAsm( pExpandedKey, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptAesEcbEncryptXmm( pExpandedKey, pbSrc, pbDst, cbData );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesEcbEncryptAsm( pExpandedKey, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptAesEcbEncryptAsm( pExpandedKey, pbSrc, pbDst, cbData );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesEcbEncryptNeon( pExpandedKey, pbSrc, pbDst, cbData );
    } else {
        SymCryptAesEcbEncryptC( pExpandedKey, pbSrc, pbDst, cbData );
    }
#else
    SymCryptAesEcbEncryptC( pExpandedKey, pbSrc, pbDst, cbData );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesEcbDecrypt( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SIZE_T cbToDo = cbData & ~(SYMCRYPT_AES_BLOCK_SIZE - 1);
    SIZE_T i;

    //
    // This loop condition is slightly strange.
    // If I use i < cbToDo (which is correct) then Prefast complains about buffer overflows.
    // Even using SYMCRYPT_ASSERT which does an _Analysis_assume_ I can't fix the Prefast issue.
    // The +15 in the code is slightly slower but it solves the Prefast issue.
    //

    for( i=0; (i+SYMCRYPT_AES_BLOCK_SIZE-1) < cbToDo; i+= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptAesDecrypt( pExpandedKey, pbSrc + i, pbDst + i );
    }
}

VOID
SYMCRYPT_CALL
SymCryptAesCbcMac(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbData,
                                                SIZE_T                      cbData )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesCbcMacXmm( pExpandedKey, pbChainingValue, pbData, cbData );
    } else {
        SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE );
        SymCryptCbcMac( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptAesCbcMacXmm( pExpandedKey, pbChainingValue, pbData, cbData );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE );
        SymCryptCbcMac( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData );
    }
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesCbcMacNeon( pExpandedKey, pbChainingValue, pbData, cbData );
    } else {
        SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE );
        SymCryptCbcMac( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData );
    }
#else
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE );
    SymCryptCbcMac( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        SymCryptAesCtrMsb64Xmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptAesCtrMsb64Asm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }

#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptAesCtrMsb64Xmm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptAesCtrMsb64Asm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }

#elif SYMCRYPT_CPU_ARM
    SymCryptAesCtrMsb64Asm( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );

#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptAesCtrMsb64Neon( pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    } else {
        SymCryptCtrMsb64( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
    }

#else
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE );        // keep Prefast happy
    SymCryptCtrMsb64( &SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
#endif
}


PSYMCRYPT_BLOCKCIPHER_CRYPT_XTS
SYMCRYPT_CALL
SymCryptXtsAesGetBlockEncFunc( )
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        return &SymCryptXtsAesEncryptDataUnitXmm;
    }
    else
    {
        return &SymCryptXtsAesEncryptDataUnitC;
    }
#else
    return &SymCryptXtsAesEncryptDataUnitC;
#endif
}

PSYMCRYPT_BLOCKCIPHER_CRYPT_XTS
SYMCRYPT_CALL
SymCryptXtsAesGetBlockDecFunc( )
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) )
    {
        return &SymCryptXtsAesDecryptDataUnitXmm;
    }
    else
    {
        return &SymCryptXtsAesDecryptDataUnitC;
    }
#else
    return &SymCryptXtsAesDecryptDataUnitC;
#endif
}

