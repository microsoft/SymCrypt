//
// MsBignum implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#if INCLUDE_IMPL_MSBIGNUM

#include "testInterop.h"

#define SCRATCH_BUF_OFFSET  (1 << 15)
#define SCRATCH_BUF_SIZE    (1 << 15)

char * ImpMsBignum::name = "MsBignum";

bigctx_t g_BignumCtx = { 0 };

// Functions needed for MsBignum hashes (see pfnHash type)
BOOL
WINAPI
SHA1Hash(
    __in_bcount( cbData )   const unsigned char* pbData,
                            unsigned int   cbData,
    __out_bcount( SYMCRYPT_SHA1_RESULT_SIZE )
                            unsigned char*  pbResult )
{
    SymCryptSha1( (PCBYTE)pbData,cbData,(PBYTE)pbResult);
    return TRUE;

}

BOOL
WINAPI
SHA256Hash(
    __in_bcount( cbData )   const unsigned char* pbData,
                            unsigned int   cbData,
    __out_bcount( SYMCRYPT_SHA256_RESULT_SIZE )
                            unsigned char*  pbResult )
{
    SymCryptSha256( (PCBYTE)pbData,cbData,(PBYTE)pbResult);
    return TRUE;
}

HASHALG_DATA g_HashAlgs[] = {
    { SymCryptMd5Algorithm ,    "MD5",      BCRYPT_MD5_ALGORITHM,       NULL        },
    { SymCryptSha1Algorithm,    "SHA1",     BCRYPT_SHA1_ALGORITHM,      SHA1Hash   },
    { SymCryptSha256Algorithm,  "SHA256",   BCRYPT_SHA256_ALGORITHM,    SHA256Hash },
    { SymCryptSha384Algorithm,  "SHA384",   BCRYPT_SHA384_ALGORITHM,    NULL },
    { SymCryptSha512Algorithm,  "SHA512",   BCRYPT_SHA512_ALGORITHM,    NULL },
};

// RSA algorithms

// Table with the RSA keys' sizes and the actual keys
struct {
    SIZE_T                      keySize;
    BOOL                        fInitialized;
    RSA_PRIVATE_KEY             rsakey;
} g_precomputedBignumRsaKeys[] = {
    {  32, FALSE, { 0 } },
    {  64, FALSE, { 0 } },
    { 128, FALSE, { 0 } },
    { 256, FALSE, { 0 } },
    { 384, FALSE, { 0 } },
    { 512, FALSE, { 0 } },
    {1024, FALSE, { 0 } },
};

void
SetupBignumRsaKey( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;

    BOOLEAN bFound = FALSE;
    BOOL success = FALSE;

    big_prime_search_stat_t stats = { 0 };

    for( i=0; i < ARRAY_SIZE(g_precomputedBignumRsaKeys); i++ )
    {
        if ( keySize == g_precomputedBignumRsaKeys[i].keySize )
        {
            bFound = TRUE;

            if ( g_precomputedBignumRsaKeys[i].fInitialized == FALSE )
            {
                success = rsa_construction(
                                ((DWORDREGC)keySize) * 8,
                                &(g_precomputedBignumRsaKeys[i].rsakey),
                                NULL,
                                0,
                                &stats,
                                &g_BignumCtx);

                CHECK( success, "?" );

                g_precomputedBignumRsaKeys[i].fInitialized = TRUE;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((PRSA_PRIVATE_KEY *) buf1) = &(g_precomputedBignumRsaKeys[i].rsakey);
}

void
msbignum_RsaKeyPerf( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BOOL success = FALSE;

    BYTE rbResult[1024] = { 0 };

    SetupBignumRsaKey( buf1, keySize );

    buf2[0] = 0;
    scError = SymCryptCallbackRandom( buf2 + 1, keySize - 1 );  // Don't fill it up so that it is smaller than the modulus
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    success = rsa_encryption(
            *((PRSA_PRIVATE_KEY *) buf1),
            buf2,
            buf3,
            &g_BignumCtx );
    CHECK( success, "?" );

    success = rsa_decryption(
            *((PRSA_PRIVATE_KEY *) buf1),
            buf3,
            rbResult,
            &g_BignumCtx );
    CHECK( success, "?" );

    CHECK( memcmp(buf2, rbResult, keySize) == 0, "?" );
}

// Rsa Encryption

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msbignum_RsaKeyPerf( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    rsa_encryption(
            *((PRSA_PRIVATE_KEY *) buf1),
            buf2,
            buf3,
            &g_BignumCtx );
}

template<>
VOID
algImpDecryptPerfFunction< ImpMsBignum, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    rsa_decryption(
            *((PRSA_PRIVATE_KEY *) buf1),
            buf3,
            buf2 + dataSize,
            &g_BignumCtx );
}

template<>
RsaEncImp<ImpMsBignum, AlgRsaEncRaw>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgRsaEncRaw>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpMsBignum, AlgRsaEncRaw>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgRsaEncRaw>;

    SymCryptWipe( (PBYTE) &state.key, sizeof( state.key ) );
}

template<>
RsaEncImp<ImpMsBignum, AlgRsaEncRaw>::~RsaEncImp()
{
    if( state.key.diglen_pubexp != 0 )
    {
        rsa_destruction( &state.key, &g_BignumCtx );
        SymCryptWipe( (PBYTE) &state.key, sizeof( state.key ) );
    }
}

template<>
NTSTATUS
RsaEncImp<ImpMsBignum, AlgRsaEncRaw>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    BYTE buf[8];
    BOOL res;

    if( state.key.diglen_pubexp != 0 )
    {
        rsa_destruction( &state.key, &g_BignumCtx );
        SymCryptWipe( (PBYTE) &state.key, sizeof( state.key ) );
    }

    if( pcKeyBlob == NULL )
    {
        // Used to clear out any keys
        goto cleanup;
    }

    SYMCRYPT_STORE_MSBFIRST64( buf, pcKeyBlob->u64PubExp );

    state.cbKey = pcKeyBlob->cbModulus;
    res = rsa_import(   buf, 8,
                        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
                        &pcKeyBlob->abPrime1[0], pcKeyBlob->cbPrime1,
                        &pcKeyBlob->abPrime2[0], pcKeyBlob->cbPrime2,
                        &state.key,
                        TRUE,
                        &g_BignumCtx );
    CHECK( res, "Failed to import key" );

cleanup:
    return STATUS_SUCCESS;
}

template<>
NTSTATUS 
RsaEncImp<ImpMsBignum, AlgRsaEncRaw>::encrypt(
    _In_reads_( cbMsg )             PCBYTE  pbMsg, 
                                    SIZE_T  cbMsg,
                                    PCSTR   pcstrHashAlgName,
                                    PCBYTE  pbLabel,
                                    SIZE_T  cbLabel,
    _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                    SIZE_T  cbCiphertext )
{
    BOOL success;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    CHECK( cbMsg == state.cbKey, "Wrong message size" );
    CHECK( cbCiphertext == state.cbKey, "Wrong ciphertext size" );

    success = rsa_encryption(
            &state.key,
            pbMsg,
            pbCiphertext,
            &g_BignumCtx );
    CHECK( success, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpMsBignum, AlgRsaEncRaw>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    BOOL success;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    CHECK( cbCiphertext == state.cbKey, "Wrong ciphertext size" );
    CHECK( cbMsg >= state.cbKey, "Output buffer too small" );

    success = rsa_decryption(
            &state.key,
            pbCiphertext,
            pbMsg,
            &g_BignumCtx );
    CHECK( success, "?" );

    *pcbMsg = state.cbKey;

    return STATUS_SUCCESS;
}

// Rsa Decryption

/*
template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgRsaDecRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msbignum_RsaKeyPerf( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgRsaDecRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgRsaDecRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    rsa_decryption(
            *((PRSA_PRIVATE_KEY *) buf1),
            buf3,
            buf2,
            &g_BignumCtx );
}


template<>
RsaImp<ImpMsBignum, AlgRsaDecRaw>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgRsaDecRaw>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgRsaDecRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgRsaDecRaw>;
}

template<>
RsaImp<ImpMsBignum, AlgRsaDecRaw>::~RsaImp()
{
}
*/

//============================

// Table with the Bignum DSA and DH keys
struct {
    SIZE_T          keySize;        // Always equal to cbPrimeP
    DWORD           cbPrimeQ;
    BOOLEAN         fInitialized;

    dsa_fullkey_t   m_DsaFullKey;
    dsa_dwkey_t     m_DsaDwKey;
    dh_fullkey_t    m_DhFullKey;
    dh_dwkey_t      m_DhDwKey;
} g_precomputedBignumDlGroups[] = {
    {  64, 20, FALSE, {0}, {0}, {0}, {0} },
    { 128, 32, FALSE, {0}, {0}, {0}, {0} },
    { 256, 32, FALSE, {0}, {0}, {0}, {0} },
};

// Hash algorithms translations
VOID testInteropScToHashContext( PCSYMCRYPT_HASH pHashAlgorithm, PBYTE rgbDigest, hash_function_context* pHashFunCxt)
{
    pHashFunCxt->dwVersion = HASH_FUNCTION_STRUCTURE_VERSION;
    pHashFunCxt->pvContext = NULL;
    pHashFunCxt->pdwDigest = (PDWORD)rgbDigest;

    if (pHashAlgorithm == NULL)
    {
        CHECK( FALSE, "NULL hash algorithm\n");
    }
    else
    {
        for(UINT32 i=0; i<TEST_INTEROP_NUMOF_HASHALGS; i++)
        {
            if (pHashAlgorithm == g_HashAlgs[i].pHashAlgorithm)
            {
                pHashFunCxt->pfHash = g_HashAlgs[i].msBignumHashFunc;
                pHashFunCxt->cbDigest = (DWORD)SymCryptHashResultSize(pHashAlgorithm);
                return;
            }
        }

        CHECK( FALSE, "NULL hash algorithm\n");
    }
}

void
SetupBignumDlGroup( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bFound = FALSE;
    PBYTE* pPtrs = (PBYTE*) buf1;

    // DSA and DH generation parameters
    BOOL success = FALSE;
    DSAMethodEnum eFipsStandard = FIPS_186_3;                   // Always the latest
    BYTE rgbDigest[SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };
    hash_function_context HashFunctionCtx = { 0 };
    dsa_other_info_tc other = { DSA_exponentiator_default };

    for( i=0; i < ARRAY_SIZE(g_precomputedBignumDlGroups); i++ )
    {
        if ( keySize == g_precomputedBignumDlGroups[i].keySize )
        {
            bFound = TRUE;

            if ( g_precomputedBignumDlGroups[i].fInitialized == FALSE )
            {
                // Initialize the hash_function_context with SHA256
                // This hash is safe for all our sizes
                testInteropScToHashContext(
                    SymCryptSha256Algorithm,
                    rgbDigest,
                    &HashFunctionCtx);

                // DSA
                success = DSA_key_generation_ex(
                            eFipsStandard,
                            &HashFunctionCtx,
                            8*((DWORD)g_precomputedBignumDlGroups[i].keySize),
                            8*g_precomputedBignumDlGroups[i].cbPrimeQ,
                            &other,
                            &g_precomputedBignumDlGroups[i].m_DsaFullKey,
                            &g_precomputedBignumDlGroups[i].m_DsaDwKey,
                            &g_BignumCtx);
                CHECK( success, "?" );

                // // DH
                // success = DH_key_generation(
                            // eFipsStandard,
                            // &HashFunctionCtx,
                            // 8*((DWORD)g_precomputedBignumDlGroups[i].keySize),
                            // 8*g_precomputedBignumDlGroups[i].cbPrimeQ,
                            // &other,
                            // &g_precomputedBignumDlGroups[i].m_DhFullKey,
                            // &g_precomputedBignumDlGroups[i].m_DhDwKey,
                            // &g_BignumCtx);
                // CHECK( success, "?" );

                g_precomputedBignumDlGroups[i].fInitialized = TRUE;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    pPtrs[0] = (PBYTE) &g_precomputedBignumDlGroups[i].m_DsaFullKey;
    pPtrs[1] = (PBYTE) &g_precomputedBignumDlGroups[i].m_DsaDwKey;
    // pPtrs[2] = (PBYTE) &g_precomputedBignumDlGroups[i].m_DhFullKey;
    // pPtrs[3] = (PBYTE) &g_precomputedBignumDlGroups[i].m_DhDwKey;
}

void
SetupBignumDsaAndDh( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BOOL success = FALSE;
    BOOL bValidSignature = FALSE;

    // Set a random message of size equal to the size of Q (take it from the DwKey)
    scError = SymCryptCallbackRandom( buf2, ((((dsa_dwkey_t**)buf1)[1])->nbitq)/8 ) ;
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Verify that DSA can work
    success = DSA_sign_ex(
                    (DWORDC*) buf2,
                    ((((dsa_dwkey_t**)buf1)[1])->nbitq)/32,     // # of DWORDS
                    ((dsa_fullkey_tc**)buf1)[0],
                    (dsa_signature_t*) buf3,                    // Set the valid signature in buf3
                    &g_BignumCtx);
    CHECK( success, "?" );

    // Verify the signature to make sure everything is ok
    success = DSA_signature_verification_ex(
                    (DWORDC*) buf2,
                    ((((dsa_dwkey_t**)buf1)[1])->nbitq)/32,     // # of DWORDS
                    ((dsa_fullkey_tc **)buf1)[0],
                    (dsa_signature_t*) buf3,
                    &bValidSignature,
                    &g_BignumCtx );
    CHECK( success, "DSA_signature_verification_ex failed" );
    CHECK( bValidSignature, "DSA_signature_verification_ex returned invalid signature");
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumDlGroup( buf1, keySize );
    SetupBignumDsaAndDh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    DSA_sign_ex(
            (DWORDC*) buf2,
            ((((dsa_dwkey_t**)buf1)[1])->nbitq)/32,     // # of DWORDS
            ((dsa_fullkey_tc**)buf1)[0],
            (dsa_signature_t*) buf3,                    // Set the valid signature in buf3
            &g_BignumCtx);
}

template<>
DlImp<ImpMsBignum, AlgDsaSign>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgDsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgDsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgDsaSign>;
}

template<>
DlImp<ImpMsBignum, AlgDsaSign>::~DlImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumDlGroup( buf1, keySize );
    SetupBignumDsaAndDh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BOOL bValidSignature;

    UNREFERENCED_PARAMETER( dataSize );

    DSA_signature_verification_ex(
            (DWORDC*) buf2,
            ((((dsa_dwkey_t**)buf1)[1])->nbitq)/32,     // # of DWORDS
            ((dsa_fullkey_tc **)buf1)[0],
            (dsa_signature_t*) buf3,
            &bValidSignature,
            &g_BignumCtx );
}

template<>
DlImp<ImpMsBignum, AlgDsaVerify>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgDsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgDsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgDsaVerify>;
}

template<>
DlImp<ImpMsBignum, AlgDsaVerify>::~DlImp()
{
}


//=======================================


// Global table with the bignum curves
typedef struct _BIGNUM_CURVE_ENTRY {
    BOOLEAN     fInitialized;
    ecurve_t    Curve;
} BIGNUM_CURVE_ENTRY;

BIGNUM_CURVE_ENTRY g_BignumCurves[ARRAY_SIZE(g_exKeyToCurve)] = { 0 };

ECURVE_TYPE_ENUM
getCurveBignumType( _In_ PCSYMCRYPT_ECURVE_PARAMS pParams )
{
    switch (pParams->type)
    {
    case (SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS):
        return ECURVE_SHORT_WEIERSTRASS;
    case (SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS):
        return ECURVE_TWISTED_EDWARDS;
    case (SYMCRYPT_ECURVE_TYPE_MONTGOMERY):
        return ECURVE_CURVE_25519;  // Bignum has only this Montgomery curve
    default:
        CHECK( FALSE, "?" );
        return ECURVE_NULL;
    }
}

void
SetupBignumCurves( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bKeyFound = FALSE;
    PCSYMCRYPT_ECURVE_PARAMS pParams = NULL;

    ECURVE_TYPE_ENUM BignumCurveType = ECURVE_SHORT_WEIERSTRASS;

    for( i=0; i < ARRAY_SIZE(g_exKeyToCurve); i++ )
    {
        if ( keySize == g_exKeyToCurve[i].exKeyParam )
        {
            bKeyFound = TRUE;
            break;
        }
    }

    CHECK( bKeyFound, "?" );

    if (!g_BignumCurves[i].fInitialized)
    {
        pParams =  g_exKeyToCurve[i].pParams;

        BignumCurveType = getCurveBignumType(pParams);

        CHECK(
            ecc_initialize_prime_curve(
                    pParams->cbFieldLength * 8,
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS),                                    // P
                    pParams->cbFieldLength,
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + pParams->cbFieldLength,           // A
                    pParams->cbFieldLength,
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 2 * pParams->cbFieldLength,       // B
                    pParams->cbFieldLength,
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 5 * pParams->cbFieldLength,       // n: Our structure has order at the end,
                    pParams->cbSubgroupOrder,                                                           //while the function signature has it 3rd.
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 3 * pParams->cbFieldLength,       // Gx
                    pParams->cbFieldLength,
                    (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 4 * pParams->cbFieldLength,       // Gy
                    pParams->cbFieldLength,
                    BIG_ENDIAN,
                    BignumCurveType,
                    &g_BignumCurves[i].Curve,
                    &g_BignumCtx  ),
            "?" );

        g_BignumCurves[i].fInitialized = TRUE;
    }

    *((ecurve_t **) buf1) = &g_BignumCurves[i].Curve;
}

void
SetupBignumCurvePoints( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    BYTE     buf[2048];     // For the random scalar

    ecurve_t *pCurve = *((ecurve_t **) buf1);
    multi_exponent_t *pMulti = (multi_exponent_t *)buf2;

    UINT32 ndScalar = (UINT32) pCurve->lnggorder;
    UINT32 cbScalar = ndScalar*sizeof(digit_t);

    CHECK( cbScalar <= sizeof( buf ), "?" );
    GENRANDOM( buf, cbScalar );

    // Prepare the multi point
    pMulti->pbase = pCurve->generator;
    pMulti->pexponent = (digit_tc *)((PBYTE)buf2 + sizeof(multi_exponent_t));    // We will store the point at the end of buf2
    pMulti->lng_bits = cbScalar * 8;
    pMulti->lng_pexp_alloc = ndScalar;
    pMulti->offset_bits = 0;

    // Compare the random scalar with the group order and copy the remainder if bigger
    if ( compare_same( (digit_t *) buf, pCurve->gorder, ndScalar ) > 0 )
    {
        if (!divide( (digit_t *) buf, ndScalar, pCurve->gorder, ndScalar, reciprocal_1_NULL, digit_NULL, (digit_t *) ((PBYTE)buf2 + sizeof(multi_exponent_t)), &g_BignumCtx))
        {
            CHECK( FALSE, "Bignum division failed" );
        }
    }
    else
    {
        memcpy( buf2 + sizeof(multi_exponent_t), buf, cbScalar);
    }

    if (!ecc_point_multiplication(
            (multi_exponent_t *) buf2,
            1,
            (digit_t *) buf3,
            *((ecurve_t **) buf1),
            &g_BignumCtx))
    {
        CHECK( FALSE, "Bignum ecc_point_multiplication failed" );
    }

    if ( (pCurve->curveType != ECURVE_CURVE_25519) &&   // Curve 25519 does not have on_curve function
         ( !ecc_point_on_curve(
            (digit_t *) buf3,
            *((ecurve_t **) buf1),
            &g_BignumCtx )) )
    {
        CHECK( FALSE, "Bignum ec point not on curve" );
    }
}


#define MSGHASH_SIZE    (512/8)
void
SetupBignumEcdsa( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    ecurve_t *pCurve = *((ecurve_t **) buf1);

    BOOL bValidSignature = FALSE;

    // Buf2 will hold pointers to the private exponent, the public key and the MsgHash and the data after the pointers
    digit_t ** pPtrs = ((digit_t **) buf2);
    pPtrs[0] = (digit_t *)((PBYTE)buf2 + 32);
    pPtrs[1] = (digit_t *)((PBYTE)buf2 + 32 + pCurve->lnggorder * RADIX_BYTES);
    pPtrs[2] = (digit_t *)((PBYTE)buf2 + 32 + pCurve->lnggorder * RADIX_BYTES + 2*pCurve->fdesc->elng * RADIX_BYTES);

    CHECK( 32 + pCurve->lnggorder * RADIX_BYTES + 2*pCurve->fdesc->elng * RADIX_BYTES + MSGHASH_SIZE < SCRATCH_BUF_SIZE, "ECKEY and hash cannot fit into scratch buffer" );

    if (!ecdsa_key_pair(
            pCurve,
            pPtrs[0],
            pPtrs[1],
            &g_BignumCtx ))
    {
        CHECK( FALSE, "Bignum ecdsa_key_pair failed");
    }

    GENRANDOM( (PBYTE)pPtrs[2], MSGHASH_SIZE );

    // Buf3 will hold pointers to the two signature digits
    digit_t ** pSigs = ((digit_t **) buf3);
    pSigs[0] = (digit_t *)((PBYTE)buf3 + 16);
    pSigs[1] = (digit_t *)((PBYTE)buf3 + 16 + pCurve->lnggorder * RADIX_BYTES);

    if (!ecsp_dsa(
            *((ecurve_t **) buf1),
            ((digit_t **) buf2)[0],
            (PBYTE)(((digit_t **) buf2)[2]),
            MSGHASH_SIZE,
            ((digit_t **) buf3)[0],
            ((digit_t **) buf3)[1],
            &g_BignumCtx ))
    {
        CHECK( FALSE, "Bignum ecsp_dsa failed");
    }

    // Verify the signature to make sure everything is ok
    if (!ecvp_dsa(
            *((ecurve_t **) buf1),
            ((digit_t **) buf2)[1],
            (PBYTE)(((digit_t **) buf2)[2]),
            MSGHASH_SIZE,
            ((digit_t **) buf3)[0],
            ((digit_t **) buf3)[1],
            &bValidSignature,
            &g_BignumCtx))
    {
        CHECK( FALSE, "Bignum ecvp_dsa failed");
    }

    CHECK( bValidSignature, "Bignum signature verification failed");
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bKeyFound = FALSE;

    UNREFERENCED_PARAMETER( buf3 );

    for( i=0; i < ARRAY_SIZE(g_exKeyToCurve); i++ )
    {
        if ( keySize == g_exKeyToCurve[i].exKeyParam )
        {
            bKeyFound = TRUE;
            break;
        }
    }

    CHECK( bKeyFound, "?" );

    *((PCSYMCRYPT_ECURVE_PARAMS *) buf1) = g_exKeyToCurve[i].pParams;

    *((ECURVE_TYPE_ENUM *) buf2) = getCurveBignumType(g_exKeyToCurve[i].pParams);;
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    // Do they free the curve in bignum?
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    PCSYMCRYPT_ECURVE_PARAMS pParams = *((PCSYMCRYPT_ECURVE_PARAMS *) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    ecc_initialize_prime_curve(
                pParams->cbFieldLength * 8,
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS),                                    // P
                pParams->cbFieldLength,
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + pParams->cbFieldLength,           // A
                pParams->cbFieldLength,
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 2 * pParams->cbFieldLength,       // B
                pParams->cbFieldLength,
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 5 * pParams->cbFieldLength,       // n: Our structure has order at the end,
                pParams->cbSubgroupOrder,                                                           //while the function signature has it 3rd.
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 3 * pParams->cbFieldLength,       // Gx
                pParams->cbFieldLength,
                (PBYTE)pParams + sizeof(SYMCRYPT_ECURVE_PARAMS) + 4 * pParams->cbFieldLength,       // Gy
                pParams->cbFieldLength,
                BIG_ENDIAN,
                *((ECURVE_TYPE_ENUM *) buf2),
                (ecurve_t *) buf3,
                &g_BignumCtx);
}


template<>
EccImp<ImpMsBignum, AlgEcurveAllocate>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcurveAllocate>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcurveAllocate>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcurveAllocate>;
}

template<>
EccImp<ImpMsBignum, AlgEcurveAllocate>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumCurves( buf1, keySize );
    SetupBignumCurvePoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    ecc_point_is_identity(
        (digit_t *) buf3,
        *((ecurve_t **) buf1),
        &g_BignumCtx );
}


template<>
EccImp<ImpMsBignum, AlgEcpointIsZero>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcpointIsZero>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcpointIsZero>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcpointIsZero>;
}

template<>
EccImp<ImpMsBignum, AlgEcpointIsZero>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumCurves( buf1, keySize );
    SetupBignumCurvePoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    ecc_point_on_curve(
        (digit_t *) buf3,
        *((ecurve_t **) buf1),
        &g_BignumCtx );
}


template<>
EccImp<ImpMsBignum, AlgEcpointOnCurve>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcpointOnCurve>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcpointOnCurve>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcpointOnCurve>;
}

template<>
EccImp<ImpMsBignum, AlgEcpointOnCurve>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumCurves( buf1, keySize );
    SetupBignumCurvePoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ecc_point_multiplication(
            (multi_exponent_t *) buf2,
            1,
            (digit_t *) buf3,
            *((ecurve_t **) buf1),
            &g_BignumCtx);
}


template<>
EccImp<ImpMsBignum, AlgEcpointScalarMul>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcpointScalarMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcpointScalarMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcpointScalarMul>;
}

template<>
EccImp<ImpMsBignum, AlgEcpointScalarMul>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumCurves( buf1, keySize );
    SetupBignumEcdsa( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ecsp_dsa(
        *((ecurve_t **) buf1),
        ((digit_t **) buf2)[0],
        (PBYTE)(((digit_t **) buf2)[2]),
        MSGHASH_SIZE,
        ((digit_t **) buf3)[0],
        ((digit_t **) buf3)[1],
        &g_BignumCtx );
}


template<>
EccImp<ImpMsBignum, AlgEcdsaSign>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcdsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcdsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcdsaSign>;
}

template<>
EccImp<ImpMsBignum, AlgEcdsaSign>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupBignumCurves( buf1, keySize );
    SetupBignumEcdsa( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BOOL bValidSignature;

    UNREFERENCED_PARAMETER( dataSize );

    ecvp_dsa(
            *((ecurve_t **) buf1),
            ((digit_t **) buf2)[1],
            (PBYTE)(((digit_t **) buf2)[2]),
            MSGHASH_SIZE,
            ((digit_t **) buf3)[0],
            ((digit_t **) buf3)[1],
            &bValidSignature,
            &g_BignumCtx);
}


template<>
EccImp<ImpMsBignum, AlgEcdsaVerify>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgEcdsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgEcdsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgEcdsaVerify>;
}

template<>
EccImp<ImpMsBignum, AlgEcdsaVerify>::~EccImp()
{
}



//============================

//
// SetupModulus
// Initializes a modulus of the desired keysize & features 
// 
// *((PSYMCRYPT_MODULUS *) buf1) will contain a pointer to the modulus, which is also in buf1.
// buf3 is used as scratch
//
VOID
msBignumSetupModulus( PBYTE buf1, PBYTE buf3, SIZE_T keySize )
{
    digit_t digitBuf[256];

    mp_modulus_t * pMod;

    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    UINT32 keyFlags = (UINT32) keySize & 0xff000000;
    
    UINT32 nDigits = BITS_TO_DIGITS( 8 * keyBytes );

    CHECK( nDigits <= sizeof( digitBuf ), "value too large" );

    pMod = (mp_modulus_t *) (buf1 + 64);
    CHECK( endian_bytes_to_digits( getPerfTestModulus( (UINT32) keySize ), BIG_ENDIAN, digitBuf, 8 * keyBytes, &g_BignumCtx ), "?" );

    if( keyFlags == PERF_KEY_PUB_ODD || keyFlags == PERF_KEY_PUB_PM || keyFlags == PERF_KEY_PUB_NIST )
    {
        // Key is known to be odd, we can use select_arithmetic which uses FROM_RIGHT reduction
        CHECK( create_modulus_select_arithmetic( digitBuf, nDigits, pMod, &g_BignumCtx ), "?" );
    } else {
        // Key might be even, use FROM_LEFT
        CHECK( create_modulus( digitBuf, nDigits, FROM_LEFT, pMod, &g_BignumCtx ), "?" );
    }

    *((mp_modulus_t **) buf1) = pMod;

    UNREFERENCED_PARAMETER( buf3 );
}

// 
// cleanupModulus
//
VOID
msBignumCleanupModulus( PBYTE buf1, PBYTE buf3 )
{
    uncreate_modulus( *((mp_modulus_t **) buf1), &g_BignumCtx );

    UNREFERENCED_PARAMETER( buf3 );
}


//
// setupModOperations
// Initializes a modulus in buf1, two modular values in buf2, and one modular value in buf3.
// The modular values in buf2 are set to random values
//
void
msBignumSetupModOperations( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];

    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    
    CHECK( 3 * keyBytes <= sizeof( buf ), "?" );
    GENRANDOM( buf, (3*keyBytes) );
    
    msBignumSetupModulus( buf1, buf3, keySize );
    //mp_modulus_t * pMod = *((mp_modulus_t **) buf1);

    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);
    UINT32 nDigits = (UINT32) pmodulo->length;

    CHECK( nDigits == BITS_TO_DIGITS( 8 * keyBytes ), "?" );

    digit_t ** pPtrs = ((digit_t **) buf2);
    pPtrs[0] = (digit_t *) (buf2 + 64);
    pPtrs[1] = (digit_t *) (buf2 + 64) + nDigits;
    pPtrs[2] = (digit_t *) (buf2 + 64) + 2*nDigits;

    ((digit_t **) buf3)[0] = (digit_t *)(buf3 + 64);

    CHECK( endian_bytes_to_digits( buf            , LITTLE_ENDIAN, pPtrs[0], 8 * keyBytes, &g_BignumCtx ), "?" );
    CHECK( endian_bytes_to_digits( buf +   nDigits, LITTLE_ENDIAN, pPtrs[1], 8 * keyBytes, &g_BignumCtx ), "?" );
    CHECK( endian_bytes_to_digits( buf + 2*nDigits, LITTLE_ENDIAN, pPtrs[2], 8 * keyBytes, &g_BignumCtx ), "?" );

    CHECK( to_modular( pPtrs[0], nDigits, pPtrs[0], pmodulo, &g_BignumCtx ), "?" );
    CHECK( to_modular( pPtrs[1], nDigits, pPtrs[1], pmodulo, &g_BignumCtx ), "?" );
}


void
msBignumCleanupModOperations( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModulus( buf1, buf3 );
    UNREFERENCED_PARAMETER( buf2 );
}


template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msBignumSetupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModOperations( buf1, buf2, buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    mod_add( ((digit_t **) buf2)[0], ((digit_t **) buf2)[1], (digit_t *) buf3, pmodulo, &g_BignumCtx );
}

template<>
ArithImp<ImpMsBignum, AlgModAdd>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgModAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgModAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgModAdd>;
}

template<>
ArithImp<ImpMsBignum, AlgModAdd>::~ArithImp()
{
}


template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msBignumSetupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModOperations( buf1, buf2, buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    mod_sub( ((digit_t **) buf2)[0], ((digit_t **) buf2)[1], (digit_t *) buf3, pmodulo, &g_BignumCtx );
}

template<>
ArithImp<ImpMsBignum, AlgModSub>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgModSub>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgModSub>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgModSub>;
}

template<>
ArithImp<ImpMsBignum, AlgModSub>::~ArithImp()
{
}



template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msBignumSetupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModOperations( buf1, buf2, buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    mod_mul( ((digit_t **) buf2)[0], ((digit_t **) buf2)[1], (digit_t *) buf3, pmodulo, (digit_t *) (buf3 + SCRATCH_BUF_OFFSET), &g_BignumCtx );
}

template<>
ArithImp<ImpMsBignum, AlgModMul>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgModMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgModMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgModMul>;
}

template<>
ArithImp<ImpMsBignum, AlgModMul>::~ArithImp()
{
}


template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msBignumSetupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModOperations( buf1, buf2, buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    mod_mul( ((digit_t **) buf2)[0], ((digit_t **) buf2)[0], (digit_t *) buf3, pmodulo, (digit_t *) (buf3 + SCRATCH_BUF_OFFSET), &g_BignumCtx );
}

template<>
ArithImp<ImpMsBignum, AlgModSquare>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgModSquare>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgModSquare>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgModSquare>;
}

template<>
ArithImp<ImpMsBignum, AlgModSquare>::~ArithImp()
{
}





template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    msBignumSetupModOperations( buf1, buf2, buf3, keySize );

    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);
    mp_setbit( ((digit_t **) buf2)[1], pmodulo->length * RADIX_BITS - 1, 1, &g_BignumCtx );
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    msBignumCleanupModOperations( buf1, buf2, buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpMsBignum, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    mp_modulus_t * pmodulo = *((mp_modulus_t **) buf1);

    UNREFERENCED_PARAMETER( dataSize );

    CHECK3( modular_exponentiation( ((digit_t **) buf2)[0], ((digit_t **) buf2)[2], pmodulo->length, (digit_t *) buf3, pmodulo, &g_BignumCtx ), "Failure in modexp %d", pmodulo->length );
}


template<>
ArithImp<ImpMsBignum, AlgModExp>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgModExp>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgModExp>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgModExp>;
}

template<>
ArithImp<ImpMsBignum, AlgModExp>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpMsBignum, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    bigctx_t bigCtx = {0};
    UINT32 nElements = 32;

    mp_scrambled_t * pTable = (mp_scrambled_t *) buf1;

    mp_scrambled_setup( pTable, (digit_t *) buf2, nElements, (UINT32) keySize / sizeof( digit_t ), &bigCtx );

    for( UINT32 i=0; i<nElements; i++ )
    {
        GENRANDOM( buf3, (UINT32) keySize );
        mp_scrambled_store( pTable, i, (digit_t *) buf3, &bigCtx );
    }
}

template<>
VOID
algImpCleanPerfFunction<ImpMsBignum,AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpMsBignum, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    bigctx_t bigCtx = {0};
    mp_scrambled_t * pTable = (mp_scrambled_t *) buf1;

    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );

    mp_scrambled_fetch( pTable, 7, (digit_t *) buf3, &bigCtx );
}


template<>
ArithImp<ImpMsBignum, AlgScsTable>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpMsBignum, AlgScsTable>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpMsBignum, AlgScsTable>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpMsBignum, AlgScsTable>;
}

template<>
ArithImp<ImpMsBignum, AlgScsTable>::~ArithImp()
{
}

VOID
addMsBignumAlgs()
{
    addImplementationToGlobalList<RsaEncImp<ImpMsBignum, AlgRsaEncRaw>>();

    addImplementationToGlobalList<DlImp<ImpMsBignum, AlgDsaSign>>();
    addImplementationToGlobalList<DlImp<ImpMsBignum, AlgDsaVerify>>();

    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcurveAllocate>>();
    
    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcpointIsZero>>();
    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcpointOnCurve>>();
    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcpointScalarMul>>();

    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcdsaSign>>();
    addImplementationToGlobalList<EccImp<ImpMsBignum, AlgEcdsaVerify>>();

    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgModExp>>();
    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgModAdd>>();
    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgModSub>>();
    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgModMul>>();
    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgModSquare>>();
    addImplementationToGlobalList<ArithImp<ImpMsBignum, AlgScsTable>>();
}

#endif // INCLUDE_IMPL_MSBIGNUM





