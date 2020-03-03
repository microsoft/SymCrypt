//
// Cng implementation classes for the RSA functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testRsa.h"

//
// Cng - RawEncrypt
//

/*
template<> VOID algImpTestRsaRandFunction< ImpCng, AlgRsaEncRaw >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm );
// Same as the one for SymCrypt
 */

template<> VOID algImpTestRsaQueryFunction< ImpCng, AlgRsaEncRaw >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptEncrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbSrc,
                (ULONG) cbSrc,
                NULL,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_NONE );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpCng, AlgRsaEncRaw >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptDecrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbDst,                          // The ciphertext is in the destination buffer originally
                (ULONG) cbDst,
                NULL,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_NONE );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    CHECK( cbTmp == keySize, "?" );
    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Raw failed");
}

template<>FunctionalRsaImp<ImpCng, AlgRsaEncRaw>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncRaw>;         // Notice the ImpSc implementation
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpCng, AlgRsaEncRaw>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpCng, AlgRsaEncRaw>;
}

template<>
FunctionalRsaImp<ImpCng, AlgRsaEncRaw>::~FunctionalRsaImp()
{
}

//
// Cng - Pkcs1Encrypt
//

/*
template<> VOID algImpTestRsaRandFunction< ImpCng, AlgRsaEncPkcs1 >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm );
// Same as the one for SymCrypt
 */

template<> VOID algImpTestRsaQueryFunction< ImpCng, AlgRsaEncPkcs1 >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptEncrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbSrc,
                (ULONG) cbSrc,
                NULL,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpCng, AlgRsaEncPkcs1 >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptDecrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbDst,                          // The ciphertext is in the destination buffer originally
                (ULONG) cbDst,
                NULL,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    CHECK( cbTmp == cbSrc, "?" );
    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Pkcs1 failed");
}

template<>FunctionalRsaImp<ImpCng, AlgRsaEncPkcs1>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncPkcs1>;         // Notice the ImpSc implementation
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpCng, AlgRsaEncPkcs1>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpCng, AlgRsaEncPkcs1>;
}

template<>
FunctionalRsaImp<ImpCng, AlgRsaEncPkcs1>::~FunctionalRsaImp()
{
}

//
// Cng - OaepEncrypt
//

/*
template<> VOID algImpTestRsaRandFunction< ImpCng, AlgRsaEncOaep >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm );
// Same as the one for SymCrypt
 */

template<> VOID algImpTestRsaQueryFunction< ImpCng, AlgRsaEncOaep >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    BCRYPT_OAEP_PADDING_INFO paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( keySize );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );
    paddingInfo.pbLabel = pbExtra;
    paddingInfo.cbLabel = (ULONG) cbExtra;

    ntStatus = BCryptEncrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbSrc,
                (ULONG) cbSrc,
                (VOID *) &paddingInfo,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpCng, AlgRsaEncOaep >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbTmp = 0;

    BCRYPT_OAEP_PADDING_INFO paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( keySize );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );
    paddingInfo.pbLabel = pbExtra;
    paddingInfo.cbLabel = (ULONG) cbExtra;

    ntStatus = BCryptDecrypt(
                (BCRYPT_KEY_HANDLE) pkKey,
                pbDst,                          // The ciphertext is in the destination buffer originally
                (ULONG) cbDst,
                (VOID *) &paddingInfo,
                NULL,
                0,
                pbDst,
                (ULONG) cbDst,
                &cbTmp,
                BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    CHECK( cbTmp == cbSrc, "?" );
    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Oaep failed");
}

template<>FunctionalRsaImp<ImpCng, AlgRsaEncOaep>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncOaep>;         // Notice the ImpSc implementation
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpCng, AlgRsaEncOaep>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpCng, AlgRsaEncOaep>;
}

template<>
FunctionalRsaImp<ImpCng, AlgRsaEncOaep>::~FunctionalRsaImp()
{
}

//
// Cng - Pkcs1Sign
//

// ******* This rand function is different than SymCrypt's since CNG
// always picks the first OID in the list
template<> VOID algImpTestRsaRandFunction< ImpCng, AlgRsaSignPkcs1 >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    BCRYPT_OID_LIST* pOidList = NULL;
    SIZE_T cbOidList = 0;

    SIZE_T nOid = 0;

    PSYMCRYPT_HASH scHash = NULL;
    SIZE_T cbHash = 0;

    UNREFERENCED_PARAMETER( pbExtra );

    // Pick a random hash algorithm of the appropriate size
    // Unfortunately we have to get the OIDs' size
    pOidList = (BCRYPT_OID_LIST*)pbExtra;
    do
    {
        scHash = testRsaRandomHash();
        cbHash = SymCryptHashResultSize( scHash );

        // Let's not allocate new memory for the OIDs.
        // Instead try to put it in pbExtra which we know
        // it is of size TEST_RSA_MAX_NUMOF_BYTES.
        // If the OID list is bigger, testRsaGetCngOidList
        // will fatal out.
        testRsaGetCngOidList( scHash, pbExtra, TEST_RSA_MAX_NUMOF_BYTES, &cbOidList);

        // ******* Always use 0 here as CNG signing always picks the first OID
        nOid = 0;
    }
    while ( keySize < cbHash + pOidList->pOIDs[nOid].cbOID + TEST_RSA_PKCS1_SIGN_LESS_BYTES );

    // Store the OID's index in cbExtra
    *pcbExtra = nOid;

    // Set a random message / hash value
    // (Assuming that the hash algorithms are PRFs this
    // should give the same distribution)
    scError = SymCryptCallbackRandom( pbSrc, cbHash );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    *pcbSrc = cbHash;
    *pcbDst = keySize;

    *ppHashAlgorithm = scHash;
}

template<> VOID algImpTestRsaQueryFunction< ImpCng, AlgRsaSignPkcs1 >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbSignature = 0;

    BCRYPT_PKCS1_PADDING_INFO  paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );

    ntStatus = BCryptSignHash(
                (BCRYPT_KEY_HANDLE) pkKey,
                &paddingInfo,
                pbSrc,
                (ULONG) cbSrc,
                pbDst,
                (ULONG) cbDst,
                &cbSignature,
                BCRYPT_PAD_PKCS1);

    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbSignature == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpCng, AlgRsaSignPkcs1 >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;

    BCRYPT_PKCS1_PADDING_INFO  paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );

    ntStatus = BCryptVerifySignature(
                (BCRYPT_KEY_HANDLE) pkKey,
                &paddingInfo,
                pbSrc,
                (ULONG) cbSrc,
                pbDst,
                (ULONG) cbDst,
                BCRYPT_PAD_PKCS1);
    CHECK( ntStatus == STATUS_SUCCESS, "Signing verification for RSA PKCS1 failed." );
}

template<>FunctionalRsaImp<ImpCng, AlgRsaSignPkcs1>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpCng, AlgRsaSignPkcs1>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpCng, AlgRsaSignPkcs1>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpCng, AlgRsaSignPkcs1>;
}

template<>
FunctionalRsaImp<ImpCng, AlgRsaSignPkcs1>::~FunctionalRsaImp()
{
}


//
// Cng - PssSign
//
/*
template<> VOID algImpTestRsaRandFunction< ImpCng, AlgRsaSignPss >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
// Same as the one for SymCrypt
*/

template<> VOID algImpTestRsaQueryFunction< ImpCng, AlgRsaSignPss >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbSignature = 0;

    BCRYPT_PSS_PADDING_INFO  paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( pbExtra );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );
    paddingInfo.cbSalt = (ULONG) cbExtra;

    ntStatus = BCryptSignHash(
                (BCRYPT_KEY_HANDLE) pkKey,
                &paddingInfo,
                pbSrc,
                (ULONG) cbSrc,
                pbDst,
                (ULONG) cbDst,
                &cbSignature,
                BCRYPT_PAD_PSS);

    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbSignature == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpCng, AlgRsaSignPss >(
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
    NTSTATUS ntStatus = STATUS_SUCCESS;

    BCRYPT_PSS_PADDING_INFO  paddingInfo = { 0 };

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );

    paddingInfo.pszAlgId = testRsaScToCngHash( pHashAlgorithm );
    paddingInfo.cbSalt = (ULONG) cbExtra;

    ntStatus = BCryptVerifySignature(
                (BCRYPT_KEY_HANDLE) pkKey,
                &paddingInfo,
                pbSrc,
                (ULONG) cbSrc,
                pbDst,
                (ULONG) cbDst,
                BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "Signing verification for RSA PSS failed." );
}

template<>FunctionalRsaImp<ImpCng, AlgRsaSignPss>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaSignPss>;         // Notice the ImpSc implementation
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpCng, AlgRsaSignPss>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpCng, AlgRsaSignPss>;
}

template<>
FunctionalRsaImp<ImpCng, AlgRsaSignPss>::~FunctionalRsaImp()
{
}