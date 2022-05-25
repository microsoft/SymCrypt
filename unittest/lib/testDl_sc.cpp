//
// SymCrypt implementation classes for the DL functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testInterop.h"

template<> VOID algImpTestInteropGenerateKeyEntry< ImpSc >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pkSymCryptKey = NULL;

    // Group (Use the nBitsOfQSet value)
    pDlgroup = SymCryptDlgroupAllocate( pKE->nBitsOfP, pKE->nBitsOfQSet );
    CHECK( pDlgroup != NULL, "?" );

    // Generate according to the FIPS standard specified
    scError = SymCryptDlgroupGenerate( pKE->pHashAlgorithm, pKE->eFipsStandard, pDlgroup );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pGroups[IMPSC_INDEX] = (PBYTE) pDlgroup;

    // Dsa keys
    pkSymCryptKey = SymCryptDlkeyAllocate( pDlgroup );
    CHECK( pkSymCryptKey != NULL, "?" );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pkSymCryptKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pKeysDsa[IMPSC_INDEX] = (PBYTE) pkSymCryptKey;

    // First Dh key
    pkSymCryptKey = SymCryptDlkeyAllocate( pDlgroup );
    CHECK( pkSymCryptKey != NULL, "?" );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS, pkSymCryptKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pKeysDhA[IMPSC_INDEX] = (PBYTE) pkSymCryptKey;

    // Second Dh key
    pkSymCryptKey = SymCryptDlkeyAllocate( pDlgroup );
    CHECK( pkSymCryptKey != NULL, "?" );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS, pkSymCryptKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pKeysDhB[IMPSC_INDEX] = (PBYTE) pkSymCryptKey;
}

template<> VOID algImpTestInteropFillKeyEntryBuffers< ImpSc >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH pHashAlgorithm = NULL;

    CHECK(pKE->pGroups[IMPSC_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhA[IMPSC_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhB[IMPSC_INDEX]!=NULL, "?");

    // Export the group parameters
    scError = SymCryptDlgroupGetValue(
                    (PCSYMCRYPT_DLGROUP) pKE->pGroups[IMPSC_INDEX],
                    pKE->rbPrimeP,
                    pKE->cbPrimeP,
                    pKE->rbPrimeQ,
                    pKE->cbPrimeQ,
                    pKE->rbGenG,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    &pHashAlgorithm,
                    pKE->rbSeed,
                    pKE->cbPrimeQ,
                    &(pKE->dwGenCounter) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( pHashAlgorithm==pKE->pHashAlgorithm, "?" );

    // Export the key values from Dh key A
    scError = SymCryptDlkeyGetValue(
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhA[IMPSC_INDEX],
                    pKE->rbPrivateKeyA,
                    pKE->cbPrimeQ,
                    pKE->rbPublicKeyA,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0);
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Export the key values from Dh key B (and set it's size)
    pKE->cbPrivateKeyB = SymCryptDlkeySizeofPrivateKey( (PCSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX] );
    scError = SymCryptDlkeyGetValue(
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX],
                    pKE->rbPrivateKeyB,
                    pKE->cbPrivateKeyB,
                    pKE->rbPublicKeyB,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0);
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<> VOID algImpTestInteropImportKeyEntryBuffers< ImpSc >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pkDlkey = NULL;

    CHECK(pKE->pGroups[IMPSC_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDsa[IMPSC_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhA[IMPSC_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhB[IMPSC_INDEX]==NULL, "?");

    pDlgroup = SymCryptDlgroupAllocate( pKE->nBitsOfP, pKE->nBitsOfQSet );
    CHECK( pDlgroup != NULL, "?" );

    scError = SymCryptDlgroupSetValue(
                    pKE->rbPrimeP,
                    pKE->cbPrimeP,
                    pKE->rbPrimeQ,
                    pKE->cbPrimeQ,
                    pKE->rbGenG,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pKE->pHashAlgorithm,
                    pKE->rbSeed,
                    pKE->cbPrimeQ,
                    pKE->dwGenCounter,
                    pKE->eFipsStandard,
                    pDlgroup );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pGroups[IMPSC_INDEX] = (PBYTE) pDlgroup;

    pkDlkey = SymCryptDlkeyAllocate( pDlgroup );
    CHECK( pkDlkey != NULL, "?" );

    scError = SymCryptDlkeySetValue(
                    pKE->rbPrivateKeyA,
                    pKE->cbPrimeQ,
                    pKE->rbPublicKeyA,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pkDlkey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pKeysDhA[IMPSC_INDEX] = (PBYTE) pkDlkey;
    pKE->pKeysDsa[IMPSC_INDEX] = pKE->pKeysDhA[IMPSC_INDEX];

    pkDlkey = SymCryptDlkeyAllocate( pDlgroup );
    CHECK( pkDlkey != NULL, "?" );

    scError = SymCryptDlkeySetValue(
                    pKE->rbPrivateKeyB,
                    pKE->cbPrivateKeyB,
                    pKE->rbPublicKeyB,
                    pKE->cbPrimeP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pkDlkey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pKE->pKeysDhB[IMPSC_INDEX] = (PBYTE) pkDlkey;
}

template<> VOID algImpTestInteropCleanKeyEntry< ImpSc >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    CHECK(pKE->pGroups[IMPSC_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDsa[IMPSC_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhA[IMPSC_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhB[IMPSC_INDEX]!=NULL, "?");

    SymCryptDlkeyFree((PSYMCRYPT_DLKEY) pKE->pKeysDsa[IMPSC_INDEX] );
    // SymCryptDlkeyFree((PSYMCRYPT_DLKEY) pKE->pKeysDhA[IMPSC_INDEX] );  // Same as the above
    SymCryptDlkeyFree((PSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX] );
    SymCryptDlgroupFree( (PSYMCRYPT_DLGROUP) pKE->pGroups[IMPSC_INDEX] );
}

//
// SymCrypt - DsaSign
//
template<> VOID algImpTestInteropRandFunction< ImpSc, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T*         pcbBufferA,
            PBYTE           pbBufferB,
            SIZE_T*         pcbBufferB,
            PBYTE           pbBufferC,
            SIZE_T*         pcbBufferC,
            PCSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PTEST_DL_KEYENTRY pDlKeyEntry = (PTEST_DL_KEYENTRY) pKeyEntry;

    PCSYMCRYPT_HASH scHash = NULL;
    SIZE_T cbHash = 0;

    UNREFERENCED_PARAMETER( pbBufferB );
    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( pcbBufferC );

    // Pick a hash algorithm that matches the size of Q
    // (MsBignum Requirements)
    if (pDlKeyEntry->nBitsOfQ==8*SYMCRYPT_SHA1_RESULT_SIZE)
    {
        scHash = SymCryptSha1Algorithm;
    }
    else if (pDlKeyEntry->nBitsOfQ==8*SYMCRYPT_SHA256_RESULT_SIZE)
    {
        scHash = SymCryptSha256Algorithm;
    }
    else
    {
        CHECK( FALSE, "Can't find a proper hash algorithm for MsBignum" );
    }
    cbHash = SymCryptHashResultSize( scHash );

    // Set a random message / hash value
    // (Assuming that the hash algorithms are PRFs this
    // should give the same distribution)
    scError = SymCryptCallbackRandom( pbBufferA, cbHash );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    *pcbBufferA = cbHash;
    *pcbBufferB = 2*((pDlKeyEntry->nBitsOfQ+7)/8);

    *ppHashAlgorithm = scHash;
}

template<> VOID algImpTestInteropQueryFunction< ImpSc, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PTEST_DL_KEYENTRY pDlKeyEntry = (PTEST_DL_KEYENTRY) pKeyEntry;

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptDsaSign(
                    (PCSYMCRYPT_DLKEY) (pDlKeyEntry->pKeysDsa[IMPSC_INDEX]),
                    pbBufferA,
                    cbBufferA,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pbBufferB,
                    cbBufferB );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaSign failed." );
}

template<> VOID algImpTestInteropReplyFunction< ImpSc, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PTEST_DL_KEYENTRY pDlKeyEntry = (PTEST_DL_KEYENTRY) pKeyEntry;

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptDsaVerify(
                    (PCSYMCRYPT_DLKEY) (pDlKeyEntry->pKeysDsa[IMPSC_INDEX]),
                    pbBufferA,
                    cbBufferA,
                    pbBufferB,
                    cbBufferB,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaVerify failed." );
}

template<>FunctionalInteropImp<ImpSc, AlgDsaSign>::FunctionalInteropImp()
{
    m_RandFunction      = &algImpTestInteropRandFunction <ImpSc, AlgDsaSign>;
    m_QueryFunction     = &algImpTestInteropQueryFunction <ImpSc, AlgDsaSign>;
    m_ReplyFunction     = &algImpTestInteropReplyFunction <ImpSc, AlgDsaSign>;
}

template<>
FunctionalInteropImp<ImpSc, AlgDsaSign>::~FunctionalInteropImp()
{
}

//
// SymCrypt - Dh
//
template<> VOID algImpTestInteropRandFunction< ImpSc, AlgDh >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T*         pcbBufferA,
            PBYTE           pbBufferB,
            SIZE_T*         pcbBufferB,
            PBYTE           pbBufferC,
            SIZE_T*         pcbBufferC,
            PCSYMCRYPT_HASH* ppHashAlgorithm )
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    UNREFERENCED_PARAMETER( pbBufferA );
    UNREFERENCED_PARAMETER( pbBufferB );
    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( ppHashAlgorithm );

    // No randomizing needed for DH just set the sizes
    // Cng also needs bufferC for scratch

    *pcbBufferA = SymCryptDlkeySizeofPublicKey( (PCSYMCRYPT_DLKEY) pKE->pKeysDhA[IMPSC_INDEX] );
    *pcbBufferB = SymCryptDlkeySizeofPublicKey( (PCSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX] );
    *pcbBufferC = *pcbBufferA;

    CHECK(*pcbBufferA == *pcbBufferB, "?");
}

template<> VOID algImpTestInteropQueryFunction< ImpSc, AlgDh >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    UNREFERENCED_PARAMETER( pbBufferB );
    UNREFERENCED_PARAMETER( cbBufferB );
    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    // Private key A and Public key B (it will be opposire on the reply)

    scError = SymCryptDhSecretAgreement(
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhA[IMPSC_INDEX],
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX],
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pbBufferA,
                    cbBufferA );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed." );
}

template<> VOID algImpTestInteropReplyFunction< ImpSc, AlgDh >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    // Private key B and Public key A

    scError = SymCryptDhSecretAgreement(
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhB[IMPSC_INDEX],
                    (PCSYMCRYPT_DLKEY) pKE->pKeysDhA[IMPSC_INDEX],
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pbBufferB,
                    cbBufferB );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed." );

    CHECK( SymCryptEqual( pbBufferA, pbBufferB, cbBufferA ), "SymCryptDhSecretAgreement produced different DH secret");
}

template<>FunctionalInteropImp<ImpSc, AlgDh>::FunctionalInteropImp()
{
    m_RandFunction      = &algImpTestInteropRandFunction <ImpSc, AlgDh>;
    m_QueryFunction     = &algImpTestInteropQueryFunction <ImpSc, AlgDh>;
    m_ReplyFunction     = &algImpTestInteropReplyFunction <ImpSc, AlgDh>;
}

template<>
FunctionalInteropImp<ImpSc, AlgDh>::~FunctionalInteropImp()
{
}