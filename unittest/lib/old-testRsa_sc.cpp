//
// SymCrypt implementation classes for the RSA functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testRsa.h"

//
// SymCrypt - RawEncrypt
//
template<> VOID algImpTestRsaRandFunction< ImpSc, AlgRsaEncRaw >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbPlainTextSize = 0;

    UINT32 dwModulusBitSize = 0;
    UINT32 dwZeroBits = 0;

    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( ppHashAlgorithm );

    // Get the bitsize of the modulus
    dwModulusBitSize = (UINT32) *pcbExtra;
    CHECK3( (dwModulusBitSize + 7)/8 == keySize, "Modulus bitsize does not agree in EncRaw rand %d.", dwModulusBitSize);
    dwZeroBits = keySize*8 + 1 - dwModulusBitSize;      // It goes from 1 to 8

    // Pick a random plaintext size
    cbPlainTextSize = g_rng.sizet( 1, keySize + 1 );

    // Pad the top bytes with zeros
    // (since all EncRaw implementations use MSB_FIRST for decryption)
    for (SIZE_T i=0; i < keySize - cbPlainTextSize; i++)
    {
        pbSrc[i] = 0;
    }

    // Fill the rest of the plaintext with a random message
    scError = SymCryptCallbackRandom( &pbSrc[keySize - cbPlainTextSize], (UINT32) cbPlainTextSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Zero out the top bits of the top byte
    pbSrc[keySize - cbPlainTextSize] &= (BYTE)(0xff >> dwZeroBits);

    *pcbSrc = keySize;
    *pcbDst = keySize;
} 

template<> VOID algImpTestRsaQueryFunction< ImpSc, AlgRsaEncRaw >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptRsaRawEncrypt(
            (PSYMCRYPT_RSAKEY) pkKey,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpSc, AlgRsaEncRaw >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptRsaRawDecrypt(
            (PSYMCRYPT_RSAKEY) pkKey,
            pbDst,                          // The ciphertext is in the destination buffer originally
            cbDst,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Raw failed");
}

template<>FunctionalRsaImp<ImpSc, AlgRsaEncRaw>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncRaw>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpSc, AlgRsaEncRaw>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpSc, AlgRsaEncRaw>;
}

template<>
FunctionalRsaImp<ImpSc, AlgRsaEncRaw>::~FunctionalRsaImp()
{
}

//
// SymCrypt - Pkcs1Encrypt
//
template<> VOID algImpTestRsaRandFunction< ImpSc, AlgRsaEncPkcs1 >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbPlainTextSize = 0;

    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( pcbExtra );
    UNREFERENCED_PARAMETER( ppHashAlgorithm );

    // The size of the message can be up to
    // keySize - 11 for PKCS1.
    cbPlainTextSize = g_rng.sizet( 1, keySize - TEST_RSA_PKCS1_ENC_LESS_BYTES + 1 );

    scError = SymCryptCallbackRandom( pbSrc, (UINT32) cbPlainTextSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Notice that by removing the padding the output
    // plaintext size can be checked for correctness
    // in the reply function.
    *pcbSrc = cbPlainTextSize;
    *pcbDst = keySize;
} 

template<> VOID algImpTestRsaQueryFunction< ImpSc, AlgRsaEncPkcs1 >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbTmp = 0;

    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptRsaPkcs1Encrypt(
            (PSYMCRYPT_RSAKEY) pkKey,
            pbSrc,
            cbSrc,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbDst,
            cbDst,
            &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbTmp == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpSc, AlgRsaEncPkcs1 >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbTmp = 0;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pHashAlgorithm );
    UNREFERENCED_PARAMETER( pbExtra );
    UNREFERENCED_PARAMETER( cbExtra );

    // The ciphertext is in the destination buffer

    scError = SymCryptRsaPkcs1Decrypt(
            (PSYMCRYPT_RSAKEY) pkKey,
            pbDst,                          // The ciphertext is in the destination buffer originally
            cbDst,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbDst,
            &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    CHECK( cbTmp == cbSrc, "?" );
    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Pkcs1 failed");
}

template<>FunctionalRsaImp<ImpSc, AlgRsaEncPkcs1>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncPkcs1>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpSc, AlgRsaEncPkcs1>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpSc, AlgRsaEncPkcs1>;
}

template<>
FunctionalRsaImp<ImpSc, AlgRsaEncPkcs1>::~FunctionalRsaImp()
{
}

//
// SymCrypt - OaepEncrypt
//
template<> VOID algImpTestRsaRandFunction< ImpSc, AlgRsaEncOaep >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbPlainTextSize = 0;
    SIZE_T cbLabelSize = 0;
    PSYMCRYPT_HASH scHash = NULL;

    // Pick a random hash algorithm of the appropriate size
    do
    {
        scHash = testRsaRandomHash();
    }
    while ( keySize <= TEST_RSA_OAEP_LESS_BYTES(SymCryptHashResultSize( scHash )) );

    cbPlainTextSize = g_rng.sizet( 1, keySize - TEST_RSA_OAEP_LESS_BYTES(SymCryptHashResultSize( scHash )) + 1 );

    scError = SymCryptCallbackRandom( pbSrc, (UINT32) cbPlainTextSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Notice that by removing the padding the output
    // plaintext size can be checked for correctness
    // in the reply function.
    *pcbSrc = cbPlainTextSize;
    *pcbDst = keySize;

    // Random label
    cbLabelSize = g_rng.sizet( 1, keySize + 1 );
    scError = SymCryptCallbackRandom( pbExtra, (UINT32) cbLabelSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    *pcbExtra = cbLabelSize;

    // Hash algorithm
    *ppHashAlgorithm = scHash;
} 

template<> VOID algImpTestRsaQueryFunction< ImpSc, AlgRsaEncOaep >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbTmp = 0;

    scError = SymCryptRsaOaepEncrypt(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbSrc,
                cbSrc,
                pHashAlgorithm,
                pbExtra,
                cbExtra,
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pbDst,
                cbDst,
                &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbTmp == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpSc, AlgRsaEncOaep >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbTmp = 0;

    UNREFERENCED_PARAMETER( keySize );

    scError = SymCryptRsaOaepDecrypt(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbDst,                          // The ciphertext is in the destination buffer originally
                cbDst,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pHashAlgorithm,
                pbExtra,
                cbExtra,
                0,
                pbDst,
                cbDst,
                &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    CHECK( cbTmp == cbSrc, "?" );
    CHECK( SymCryptEqual( pbSrc, pbDst, cbSrc ), "Decryption RSA Pkcs1 failed");
}

template<>FunctionalRsaImp<ImpSc, AlgRsaEncOaep>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaEncOaep>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpSc, AlgRsaEncOaep>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpSc, AlgRsaEncOaep>;
}

template<>
FunctionalRsaImp<ImpSc, AlgRsaEncOaep>::~FunctionalRsaImp()
{
}

//
// SymCrypt - Pkcs1Sign
//
template<> VOID algImpTestRsaRandFunction< ImpSc, AlgRsaSignPkcs1 >(
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

        // Pick a random OID from the list
        nOid = g_rng.sizet(0, pOidList->dwOIDCount);
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

template<> VOID algImpTestRsaQueryFunction< ImpSc, AlgRsaSignPkcs1 >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    BCRYPT_OID_LIST* pOidList = (BCRYPT_OID_LIST*) pbExtra;

    // This is the OID that should be put in front of the list
    SIZE_T nOid = cbExtra;

    // The following works because BCRYPT_OID is the same as SYMCRYPT_OID
    PSYMCRYPT_OID pScOids = (PSYMCRYPT_OID) &(pOidList->pOIDs[nOid]);

    SIZE_T cbSignature = 0;

    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptRsaPkcs1Sign(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbSrc,
                cbSrc,
                pScOids,
                pOidList->dwOIDCount - nOid,    // Number of OIDs that are left
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pbDst,
                cbDst,
                &cbSignature );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Sign failed with 0x%x", scError );
    CHECK( cbSignature == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpSc, AlgRsaSignPkcs1 >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    BCRYPT_OID_LIST* pOidList = (BCRYPT_OID_LIST*) pbExtra;

    // Start the list at the OID before the one we used (or equal)
    SIZE_T nOid = g_rng.sizet(0, cbExtra + 1);

    // The following works because BCRYPT_OID is the same as SYMCRYPT_OID
    PSYMCRYPT_OID pScOids = (PSYMCRYPT_OID) &(pOidList->pOIDs[nOid]);

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    scError = SymCryptRsaPkcs1Verify(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbSrc,
                cbSrc,
                pbDst,
                cbDst,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pScOids,
                pOidList->dwOIDCount - nOid,    // Number of OIDs that are left
                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Signing verification for RSA PKCS1 failed." );
}

template<>FunctionalRsaImp<ImpSc, AlgRsaSignPkcs1>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaSignPkcs1>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpSc, AlgRsaSignPkcs1>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpSc, AlgRsaSignPkcs1>;
}

template<>
FunctionalRsaImp<ImpSc, AlgRsaSignPkcs1>::~FunctionalRsaImp()
{
}


//
// SymCrypt - PssSign
//
template<> VOID algImpTestRsaRandFunction< ImpSc, AlgRsaSignPss >(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbSaltSize = 0;
    SIZE_T cbHash = 0;
    PSYMCRYPT_HASH scHash = NULL;

    UINT32 dwEmLen = 0;

    UNREFERENCED_PARAMETER( pbExtra );

    // Calculate emLen = ceil((nBitsOfModulus-1)/8) (c.f. rfc3447)
    dwEmLen = (UINT32)*pcbExtra;
    dwEmLen = (dwEmLen - 1 + 7)/8;
    CHECK( (dwEmLen < keySize + 1) && (dwEmLen > keySize - 2), "?");

    // Pick a random hash algorithm of the appropriate size
    // If the limit is tight the salt will be 0 bytes.
    do
    {
        scHash = testRsaRandomHash();
        cbHash = SymCryptHashResultSize( scHash );
    }
    while ( dwEmLen < cbHash + TEST_RSA_PSS_LESS_BYTES );

    // Pick a random salt size (or 0)
    if (dwEmLen == cbHash + TEST_RSA_PSS_LESS_BYTES)
    {
        cbSaltSize = 0;
    }
    else
    {
        cbSaltSize = g_rng.sizet( 1, dwEmLen - cbHash - TEST_RSA_PSS_LESS_BYTES + 1);
    }

    // Set a random message / hash value
    // (Assuming that the hash algorithms are PRFs this
    // should give the same distribution)
    scError = SymCryptCallbackRandom( pbSrc, cbHash );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    *pcbSrc = cbHash;
    *pcbDst = keySize;

    *pcbExtra = cbSaltSize;

    *ppHashAlgorithm = scHash;
} 

template<> VOID algImpTestRsaQueryFunction< ImpSc, AlgRsaSignPss >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbSignature = 0;

    UNREFERENCED_PARAMETER( pbExtra );

    scError = SymCryptRsaPssSign(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbSrc,
                cbSrc,
                pHashAlgorithm,
                cbExtra,
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pbDst,
                cbDst,
                &cbSignature );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbSignature == keySize, "?" );
}

template<> VOID algImpTestRsaReplyFunction< ImpSc, AlgRsaSignPss >(
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
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    UNREFERENCED_PARAMETER( keySize );
    UNREFERENCED_PARAMETER( pbExtra );

    scError = SymCryptRsaPssVerify(
                (PSYMCRYPT_RSAKEY) pkKey,
                pbSrc,
                cbSrc,
                pbDst,
                cbDst,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pHashAlgorithm,
                cbExtra,
                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Signing verification for RSA PSS failed." );
}

template<>FunctionalRsaImp<ImpSc, AlgRsaSignPss>::FunctionalRsaImp()
{
    m_funcRandFunction      = &algImpTestRsaRandFunction <ImpSc, AlgRsaSignPss>;
    m_funcQueryFunction     = &algImpTestRsaQueryFunction <ImpSc, AlgRsaSignPss>;
    m_funcReplyFunction     = &algImpTestRsaReplyFunction <ImpSc, AlgRsaSignPss>;
}

template<>
FunctionalRsaImp<ImpSc, AlgRsaSignPss>::~FunctionalRsaImp()
{
}
