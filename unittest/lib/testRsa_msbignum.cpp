//
// MsBignum implementation classes for the RSA functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testRsa.h"

//
// MsBignum - RawEncrypt
//

/*
template<> VOID algImpTestRsaRandFunction< ImpMsBignum, AlgRsaEncRaw >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm );
// Same as the one for SymCrypt
 */

template<> VOID algImpTestRsaQueryFunction< ImpMsBignum, AlgRsaEncRaw >(
            UINT32          keySize,
            PBYTE           pkKey,
            PBYTE           pbSrc,
            SIZE_T          cbSrc,
            PBYTE           pbDst,
            SIZE_T          cbDst,
            PBYTE           pbExtra,
            SIZE_T          cbExtra,
            PSYMCRYPT_HASH  pHashAlgorithm )
{
    bigctx_t bignumCtx = { 0 };
    BOOL success = TRUE;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( cbSrc );
    UNREFERENCED_PARAMETER( cbDst );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    success = rsa_encryption(
            (PRSA_PRIVATE_KEY) pkKey,
            pbSrc,
            pbDst,
            &bignumCtx );
    CHECK( success, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpMsBignum, AlgRsaEncRaw >(
            UINT32          keySize,
            PBYTE           pkKey,
            PBYTE           pbSrc,
            SIZE_T          cbSrc,
            PBYTE           pbDst,
            SIZE_T          cbDst,
            PBYTE           pbExtra,
            SIZE_T          cbExtra,
            PSYMCRYPT_HASH  pHashAlgorithm )
{
    bigctx_t bignumCtx = { 0 };
    BOOL success = TRUE;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( cbSrc );
    UNREFERENCED_PARAMETER( cbDst );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    success = rsa_decryption(
            (PRSA_PRIVATE_KEY) pkKey,
            pbDst,                          // The ciphertext is in the destination buffer originally
            pbDst,
            &bignumCtx );
    CHECK( success, "?" );

    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Raw failed");
}

template<>FunctionalRsaImp<ImpMsBignum, AlgRsaEncRaw>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncRaw>;         // Notice the ImpSc implementation
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpMsBignum, AlgRsaEncRaw>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpMsBignum, AlgRsaEncRaw>;
}

template<>
FunctionalRsaImp<ImpMsBignum, AlgRsaEncRaw>::~FunctionalRsaImp()
{
}
