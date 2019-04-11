//
// MsBignum implementation classes for the DL functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testInterop.h"

#define TEST_DL_MSBIGNUM_MAX_GROUPSIZE      (256)

DSAMethodEnum testDlMsBignum_ScFipsVersionToDsaMethodEnum( SYMCRYPT_DLGROUP_FIPS fipsVersion )
{
    switch (fipsVersion)
    {
        case (SYMCRYPT_DLGROUP_FIPS_186_2):
            return FIPS_186_2;
            break;
        case (SYMCRYPT_DLGROUP_FIPS_186_3):
            return FIPS_186_3;
            break;
        default:
            CHECK(FALSE, "?");
            return FIPS_186_2;
            break;
    }
}

template<> VOID algImpTestInteropGenerateKeyEntry< ImpMsBignum >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    BOOL success = FALSE;
    BYTE rgbDigest[SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };        // Maximum digest size
    bigctx_t bignumCtx = { 0 };
    hash_function_context HashFunctionCtx = { 0 };
    dsa_other_info_tc other = { DSA_exponentiator_default };    // This will be used for both DSA and DH keys
    dsa_fullkey_t * pDsaFullKey = NULL;
    dsa_dwkey_t * pdwDsaKey = NULL;
    dh_fullkey_t * pDhFullKey = NULL;
    dh_dwkey_t * pdwDhKey = NULL;

    digit_t * pTemporary = NULL;

    DSAMethodEnum eFipsStandard = testDlMsBignum_ScFipsVersionToDsaMethodEnum(pKE->eFipsStandard);

    // Initialize the hash function context
    if (pKE->pHashAlgorithm != NULL)
    {
        testInteropScToHashContext(
            pKE->pHashAlgorithm,
            rgbDigest,
            &HashFunctionCtx);
    }
    else
    {
        testInteropScToHashContext(
            SymCryptSha1Algorithm,
            rgbDigest,
            &HashFunctionCtx);
    }

    // Allocate Dsa key
    pDsaFullKey = (dsa_fullkey_t *)SymCryptCallbackAlloc(sizeof(dsa_fullkey_t));
    pdwDsaKey = (dsa_dwkey_t *)SymCryptCallbackAlloc(sizeof(dsa_dwkey_t));
    CHECK((pDsaFullKey!=NULL) && (pdwDsaKey!=NULL), "?");

    // Group and DSA key
    success = DSA_key_generation_ex(
                    eFipsStandard,
                    &HashFunctionCtx,
                    pKE->nBitsOfP,
                    pKE->nBitsOfQ,
                    &other,
                    pDsaFullKey,
                    pdwDsaKey,
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pGroups[IMPMSBIGNUM_INDEX] = NULL;
    pKE->pKeysDsa[IMPMSBIGNUM_INDEX] = (PBYTE) pDsaFullKey;

    // First DH key
    // Allocate a new pdwkey and copy the original one
    pdwDhKey = (dh_dwkey_t *)SymCryptCallbackAlloc(sizeof(dh_dwkey_t));
    CHECK((pdwDhKey!=NULL), "?");

    CHECK(sizeof(dh_dwkey_t)==sizeof(dsa_dwkey_t), "?");
    memcpy( pdwDhKey, pDsaFullKey->pdwkey, sizeof(dh_dwkey_t));

    // Allocate a new full key
    pDhFullKey = (dh_fullkey_t *)SymCryptCallbackAlloc(sizeof(dh_fullkey_t));
    CHECK((pDhFullKey!=NULL), "?");

    // Create the first DH key (with the same public and private parts)
    success = DH_build_fullkey(
                    FIPS_186_3,     // Only this is supported for DH
                    &HashFunctionCtx,
                    pdwDhKey,
                    &other,
                    pDhFullKey,
                    FALSE,          // No verify for this as we might have used 186_2
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pKeysDhA[IMPMSBIGNUM_INDEX] = (PBYTE) pDhFullKey;

    // Second DH key
    // Allocate a new pdwkey and copy the original one
    pdwDhKey = (dh_dwkey_t *)SymCryptCallbackAlloc(sizeof(dh_dwkey_t));
    CHECK((pdwDhKey!=NULL), "?");

    CHECK(sizeof(dh_dwkey_t)==sizeof(dsa_dwkey_t), "?");
    memcpy( pdwDhKey, pDsaFullKey->pdwkey, sizeof(dh_dwkey_t));

    // Erase private and public keys and S,C
    SymCryptWipe((PBYTE)&pdwDhKey->x[0], (2*DSA_P_MAXDWORDS+DSA_Q_MAXDWORDS+1)*sizeof(DWORD));

    // Allocate a new full key
    pDhFullKey = (dh_fullkey_t *)SymCryptCallbackAlloc(sizeof(dh_fullkey_t));
    CHECK((pDhFullKey!=NULL), "?");

    // Create the second DH key
    success = DH_build_fullkey(
                    FIPS_186_3,     // Only this is supported for DH
                    &HashFunctionCtx,
                    pdwDhKey,
                    &other,
                    pDhFullKey,
                    FALSE,          // No verify for this as we might have used 186_2
                    &bignumCtx);
    CHECK( success, "?" );

    // Allocate temp memory
    pTemporary = (digit_t *)SymCryptCallbackAlloc(3*DH_P_MAXDIGITS*sizeof(digit_t));
    CHECK( pTemporary!=NULL, "?" );

    // Create new private and public keys
    success = DH_gen_x_and_y(
                    TRUE,           // Use Q
                    &other,
                    pDhFullKey,
                    pdwDhKey,
                    pTemporary,
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pKeysDhB[IMPMSBIGNUM_INDEX] = (PBYTE) pDhFullKey;

    SymCryptWipe((PBYTE)pTemporary, 3*DH_P_MAXDIGITS*sizeof(digit_t));
    SymCryptCallbackFree((PBYTE)pTemporary);

}

template<> VOID algImpTestInteropFillKeyEntryBuffers< ImpMsBignum >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    dh_dwkey_t * pdwDhKey = NULL;
    dh_fullkey_t * pDhFullKey = NULL;

    CHECK(pKE->pKeysDhA[IMPMSBIGNUM_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhB[IMPMSBIGNUM_INDEX]!=NULL, "?");

    pDhFullKey = (dh_fullkey_t*) pKE->pKeysDhA[IMPMSBIGNUM_INDEX];
    pdwDhKey = pDhFullKey->pdwkey;

    // Export the group parameters
    CHECK( (pdwDhKey->nbitp+7)/8==pKE->cbPrimeP, "?" );
    CHECK( (pdwDhKey->nbitq+7)/8==pKE->cbPrimeQ, "?" );
    CHECK( (pdwDhKey->nbitx+7)/8==pKE->cbPrimeQ, "?" );

    testInteropReverseMemCopy( pKE->rbPrimeP, (PBYTE)pdwDhKey->p, pKE->cbPrimeP );
    testInteropReverseMemCopy( pKE->rbPrimeQ, (PBYTE)pdwDhKey->q, pKE->cbPrimeQ );
    testInteropReverseMemCopy( pKE->rbGenG, (PBYTE)pdwDhKey->g, pKE->cbPrimeP );

    // Seed and gen counter (the hash algorithm is not stored in msbignum)
    testInteropReverseMemCopy( pKE->rbSeed, (PBYTE)pdwDhKey->S, pKE->cbPrimeQ );
    pKE->dwGenCounter = pdwDhKey->C;

    // Export the key parameters of key A
    testInteropReverseMemCopy( pKE->rbPrivateKeyA, (PBYTE)pdwDhKey->x, pKE->cbPrimeQ );
    testInteropReverseMemCopy( pKE->rbPublicKeyA, (PBYTE)pdwDhKey->y, pKE->cbPrimeP );

    pDhFullKey = (dh_fullkey_t*) pKE->pKeysDhB[IMPMSBIGNUM_INDEX];
    pdwDhKey = pDhFullKey->pdwkey;

    // Export the key parameters of key B (and set it's size)
    CHECK( (pdwDhKey->nbitx+7)/8==pKE->cbPrimeQ, "?" );
    pKE->cbPrivateKeyB = pKE->cbPrimeQ;
    testInteropReverseMemCopy( pKE->rbPrivateKeyB, (PBYTE)pdwDhKey->x, pKE->cbPrimeQ );
    testInteropReverseMemCopy( pKE->rbPublicKeyB, (PBYTE)pdwDhKey->y, pKE->cbPrimeP );
}

template<> VOID algImpTestInteropImportKeyEntryBuffers< ImpMsBignum >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    BOOL success = FALSE;
    BYTE rgbDigest[SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };        // Maximum digest size
    bigctx_t bignumCtx = { 0 };
    hash_function_context HashFunctionCtx = { 0 };
    dsa_other_info_tc other = { DSA_exponentiator_default };    // This will be used for both DSA and DH keys
    dsa_fullkey_t * pDsaFullKey = NULL;
    dsa_dwkey_t * pdwDsaKey = NULL;
    dh_fullkey_t * pDhFullKey = NULL;
    dh_dwkey_t * pdwDhKey = NULL;

    DSAMethodEnum eFipsStandard = testDlMsBignum_ScFipsVersionToDsaMethodEnum(pKE->eFipsStandard);

    CHECK(pKE->pGroups[IMPMSBIGNUM_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDsa[IMPMSBIGNUM_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhA[IMPMSBIGNUM_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhB[IMPMSBIGNUM_INDEX]==NULL, "?");

    // Initialize the hash function context
    if (pKE->pHashAlgorithm != NULL)
    {
        testInteropScToHashContext(
            pKE->pHashAlgorithm,
            rgbDigest,
            &HashFunctionCtx);
    }
    else
    {
        testInteropScToHashContext(
            SymCryptSha1Algorithm,
            rgbDigest,
            &HashFunctionCtx);
    }

    // Allocate Dsa key
    pDsaFullKey = (dsa_fullkey_t *)SymCryptCallbackAlloc(sizeof(dsa_fullkey_t));
    pdwDsaKey = (dsa_dwkey_t *)SymCryptCallbackAlloc(sizeof(dsa_dwkey_t));
    CHECK((pDsaFullKey!=NULL) && (pdwDsaKey!=NULL), "?");

    // Wipe the new pdwkey
    SymCryptWipe((PBYTE)pdwDsaKey, sizeof(dsa_dwkey_t));

    // Set what we know
    pdwDsaKey->nbitp = pKE->nBitsOfP;
    pdwDsaKey->nbitq = pKE->nBitsOfQ;
    pdwDsaKey->nbitx = pdwDsaKey->nbitq;      // We have Q sized private keys for the first keys

    // Build the pdwkey by copying buffers
    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->p, pKE->rbPrimeP, pKE->cbPrimeP );
    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->q, pKE->rbPrimeQ, pKE->cbPrimeQ );
    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->g, pKE->rbGenG, pKE->cbPrimeP );

    // Seed and gen counter
    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->S, pKE->rbSeed, pKE->cbPrimeQ );
    pdwDsaKey->C = pKE->dwGenCounter;

    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->x, pKE->rbPrivateKeyA, pKE->cbPrimeQ );
    testInteropReverseMemCopy( (PBYTE)pdwDsaKey->y, pKE->rbPublicKeyA, pKE->cbPrimeP );

    // Create the DSA key
    success = DSA_build_fullkey_ex(
                    eFipsStandard,
                    &HashFunctionCtx,
                    pdwDsaKey,
                    &other,
                    pDsaFullKey,
                    TRUE,          // Verify!
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pGroups[IMPMSBIGNUM_INDEX] = NULL;
    pKE->pKeysDsa[IMPMSBIGNUM_INDEX] = (PBYTE) pDsaFullKey;

    // First DH key
    // Allocate a new pdwkey and copy the original one
    pdwDhKey = (dh_dwkey_t *)SymCryptCallbackAlloc(sizeof(dh_dwkey_t));
    CHECK((pdwDhKey!=NULL), "?");

    CHECK(sizeof(dh_dwkey_t)==sizeof(dsa_dwkey_t), "?");
    memcpy( pdwDhKey, pDsaFullKey->pdwkey, sizeof(dh_dwkey_t));

    // Allocate a new full key
    pDhFullKey = (dh_fullkey_t *)SymCryptCallbackAlloc(sizeof(dh_fullkey_t));
    CHECK((pDhFullKey!=NULL), "?");

    // Create the first DH key (with the same public and private parts)
    success = DH_build_fullkey(
                    FIPS_186_3,     // Only this is supported for DH
                    &HashFunctionCtx,
                    pdwDhKey,
                    &other,
                    pDhFullKey,
                    FALSE,          // No verify for this as we might have used 186_2
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pKeysDhA[IMPMSBIGNUM_INDEX] = (PBYTE) pDhFullKey;

    // Second DH key
    // Allocate a new pdwkey and copy the original one
    pdwDhKey = (dh_dwkey_t *)SymCryptCallbackAlloc(sizeof(dh_dwkey_t));
    CHECK((pdwDhKey!=NULL), "?");

    CHECK(sizeof(dh_dwkey_t)==sizeof(dsa_dwkey_t), "?");
    memcpy( pdwDhKey, pDsaFullKey->pdwkey, sizeof(dh_dwkey_t));

    // Erase private and public keys and S,C
    SymCryptWipe((PBYTE)&pdwDhKey->x[0], (2*DSA_P_MAXDWORDS+DSA_Q_MAXDWORDS+1)*sizeof(DWORD));

    // Set the new parameters
    pdwDsaKey->nbitx = 8*pKE->cbPrivateKeyB;      // We might have bigger keys
    testInteropReverseMemCopy( (PBYTE)pdwDhKey->x, pKE->rbPrivateKeyB, pKE->cbPrivateKeyB );
    testInteropReverseMemCopy( (PBYTE)pdwDhKey->y, pKE->rbPublicKeyB, pKE->cbPrimeP );

    // Allocate a new full key
    pDhFullKey = (dh_fullkey_t *)SymCryptCallbackAlloc(sizeof(dh_fullkey_t));
    CHECK((pDhFullKey!=NULL), "?");

    // Create the second DH key
    success = DH_build_fullkey(
                    FIPS_186_3,     // Only this is supported for DH
                    &HashFunctionCtx,
                    pdwDhKey,
                    &other,
                    pDhFullKey,
                    FALSE,          // No verify for this as we might have used 186_2
                    &bignumCtx);
    CHECK( success, "?" );

    pKE->pKeysDhB[IMPMSBIGNUM_INDEX] = (PBYTE) pDhFullKey;
}

template<> VOID algImpTestInteropCleanKeyEntry< ImpMsBignum >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    // MsBignum
    bigctx_t bignumCtx = { 0 };
    dsa_fullkey_t * pfullkey = NULL;
    dsa_dwkey_t * pdwkey = NULL;

    CHECK(pKE->pKeysDsa[IMPMSBIGNUM_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhA[IMPMSBIGNUM_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhB[IMPMSBIGNUM_INDEX]!=NULL, "?");

    // Dsa key
    pfullkey = (dsa_fullkey_t*)pKE->pKeysDsa[IMPMSBIGNUM_INDEX];
    pdwkey = pfullkey->pdwkey;

    DSA_unbuild_fullkey( pfullkey, &bignumCtx);

    SymCryptWipe( (PBYTE)pfullkey, sizeof(dsa_fullkey_t) );
    SymCryptCallbackFree( (PBYTE)pfullkey );

    SymCryptWipe( (PBYTE)pdwkey, sizeof(dsa_dwkey_t) );
    SymCryptCallbackFree( (PBYTE)pdwkey );

    // Dh key A
    pfullkey = (dsa_fullkey_t*)pKE->pKeysDhA[IMPMSBIGNUM_INDEX];
    pdwkey = pfullkey->pdwkey;

    DH_unbuild_fullkey( pfullkey, &bignumCtx);

    SymCryptWipe( (PBYTE)pfullkey, sizeof(dsa_fullkey_t) );
    SymCryptCallbackFree( (PBYTE)pfullkey );

    SymCryptWipe( (PBYTE)pdwkey, sizeof(dsa_dwkey_t) );
    SymCryptCallbackFree( (PBYTE)pdwkey );

    // Dh key B
    pfullkey = (dsa_fullkey_t*)pKE->pKeysDhB[IMPMSBIGNUM_INDEX];
    pdwkey = pfullkey->pdwkey;

    DH_unbuild_fullkey( pfullkey, &bignumCtx);

    SymCryptWipe( (PBYTE)pfullkey, sizeof(dsa_fullkey_t) );
    SymCryptCallbackFree( (PBYTE)pfullkey );

    SymCryptWipe( (PBYTE)pdwkey, sizeof(dsa_dwkey_t) );
    SymCryptCallbackFree( (PBYTE)pdwkey );
}

//
// MsBignum - DsaSign
//

/*
template<> VOID algImpTestInteropRandFunction< ImpMsBignum, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T*         pcbBufferA,
            PBYTE           pbBufferB,
            SIZE_T*         pcbBufferB,
            PBYTE           pbBufferC,
            SIZE_T*         pcbBufferC,
            PCSYMCRYPT_HASH* ppHashAlgorithm );
// Same as the one for SymCrypt
 */

template<> VOID algImpTestInteropQueryFunction< ImpMsBignum, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    PTEST_DL_KEYENTRY pDlKeyEntry = (PTEST_DL_KEYENTRY) pKeyEntry;

    bigctx_t bignumCtx = { 0 };
    BOOL success = TRUE;
    dsa_signature_t bgSignature = { 0 };
    BYTE rgbHash[TEST_DL_MSBIGNUM_MAX_GROUPSIZE] = { 0 };

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    CHECK( (cbBufferA<=TEST_DL_MSBIGNUM_MAX_GROUPSIZE) &&
           (2*cbBufferA == cbBufferB),
           "MsBignum DSA_sign_ex size restrictions failed");

    // since the hash is passed in as a big endian we need to
    // byte reverse before computing the signature.
    testInteropReverseMemCopy( rgbHash, pbBufferA, cbBufferA );

    success = DSA_sign_ex(
                    (DWORDC*) rgbHash,
                    (DWORDC) cbBufferA/sizeof(DWORD),
                    (dsa_fullkey_tc*) (pDlKeyEntry->pKeysDsa[IMPMSBIGNUM_INDEX]),
                    &bgSignature,
                    &bignumCtx );
    CHECK( success, "DSA_sign_ex failed" );

    // Copy the R and S into buffer B
    testInteropReverseMemCopy( pbBufferB, (PBYTE) &bgSignature.r[0], cbBufferB/2 );
    testInteropReverseMemCopy( pbBufferB+cbBufferB/2, (PBYTE) &bgSignature.s[0], cbBufferB/2 );
}

template<> VOID algImpTestInteropReplyFunction< ImpMsBignum, AlgDsaSign >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    PTEST_DL_KEYENTRY pDlKeyEntry = (PTEST_DL_KEYENTRY) pKeyEntry;

    bigctx_t bignumCtx = { 0 };
    BOOL success = TRUE;
    BOOL bVerified = FALSE;
    dsa_signature_t bgSignature = { 0 };
    BYTE rgbHash[TEST_DL_MSBIGNUM_MAX_GROUPSIZE] = { 0 };

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    CHECK( (cbBufferA<=TEST_DL_MSBIGNUM_MAX_GROUPSIZE) &&
           (2*cbBufferA == cbBufferB),
           "MsBignum DSA_sign_ex size restrictions failed");

    // since the hash is passed in as a big endian we need to
    // byte reverse before computing the signature.
    testInteropReverseMemCopy( rgbHash, pbBufferA, cbBufferA );

    // Copy buffer B into the R and S of the signature
    testInteropReverseMemCopy( (PBYTE) &bgSignature.r[0], pbBufferB, cbBufferB/2 );
    testInteropReverseMemCopy( (PBYTE) &bgSignature.s[0], pbBufferB+cbBufferB/2, cbBufferB/2 );

    success = DSA_signature_verification_ex(
                    (DWORDC*) rgbHash,
                    (DWORDC) cbBufferA/sizeof(DWORD),
                    (dsa_fullkey_tc*) (pDlKeyEntry->pKeysDsa[IMPMSBIGNUM_INDEX]),
                    &bgSignature,
                    &bVerified,
                    &bignumCtx );
    CHECK( success, "DSA_signature_verification_ex failed" );
    CHECK( bVerified, "DSA_signature_verification_ex returned invalid signature");
}

template<>FunctionalInteropImp<ImpMsBignum, AlgDsaSign>::FunctionalInteropImp()
{
    m_RandFunction      = &algImpTestInteropRandFunction <ImpSc, AlgDsaSign>;         // Notice the ImpSc implementation
    m_QueryFunction     = &algImpTestInteropQueryFunction <ImpMsBignum, AlgDsaSign>;
    m_ReplyFunction     = &algImpTestInteropReplyFunction <ImpMsBignum, AlgDsaSign>;
}

template<>
FunctionalInteropImp<ImpMsBignum, AlgDsaSign>::~FunctionalInteropImp()
{
}
