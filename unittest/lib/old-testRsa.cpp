//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testRsa.h"

// Table with bitisizes for the mmoduli.
// The -1 entries will be substituted with random values.
// The boolean value specifies the "uneven-sized primes"
// generation routine that picks two primes of different
// sizes.
TEST_RSA_BITSIZEENTRY g_BitSizeEntries[] = {
    { (UINT32)(-1), FALSE },
    { (UINT32)(-1), FALSE },
    { (UINT32)(-1), FALSE },
    { (UINT32)(-1), TRUE  },
    { (UINT32)(-1), TRUE  },
    { (UINT32)(-1), TRUE  },
    {  889, FALSE },         // 1 mod 8
    { 1024, FALSE },
    { 2048, FALSE },
};

#define TEST_RSA_KEYSIZES               (ARRAY_SIZE(g_BitSizeEntries))
#define TEST_RSA_NUMOF_ENTRIES          (TEST_RSA_KEYSIZES * TEST_RSA_NUMOF_IMPS)
#define TEST_RSA_NUMOF_RANDOM_TRIES     (20)

char * g_ImplNames[] = {
    ImpSc::name,
    ImpMsBignum::name,
    ImpCng::name,
};

// List with all the RSA keys
TEST_RSA_KEYENTRY g_KeyEntries[TEST_RSA_NUMOF_ENTRIES] = { 0 };

// List with all the functional RSA implementations
AlgorithmImplementationVector g_AlgList;

// Translation algorithm from the implementation to its index:
//      SymCrypt => 0
//      MsBignum => 1
//      Cng      => 2
UINT32 ImplToInd( AlgorithmImplementation * pImpl )
{
    if ( pImpl->m_implementationName == ImpSc::name )
    {
        return 0;
    }
    else if ( pImpl->m_implementationName == ImpMsBignum::name )
    {
        return 1;
    }
    else if ( pImpl->m_implementationName == ImpCng::name )
    {
        return 2;
    }
    else
    {
        CHECK( FALSE, "TestRsa: Unknown implementation\n");
        return (UINT32)(-1);
    }
}

LPCWSTR testRsaScToCngHash( PSYMCRYPT_HASH pHashAlgorithm )
{
    if (pHashAlgorithm == SymCryptMd5Algorithm)
    {
        return BCRYPT_MD5_ALGORITHM;
    }
    else if (pHashAlgorithm == SymCryptSha1Algorithm)
    {
        return BCRYPT_SHA1_ALGORITHM;
    }
    else if (pHashAlgorithm == SymCryptSha256Algorithm)
    {
        return BCRYPT_SHA256_ALGORITHM;
    }
    else if (pHashAlgorithm == SymCryptSha384Algorithm)
    {
        return BCRYPT_SHA384_ALGORITHM;
    }
    else if (pHashAlgorithm == SymCryptSha512Algorithm)
    {
        return BCRYPT_SHA512_ALGORITHM;
    }
    {
        CHECK( FALSE, "?" );
        return NULL;
    }
}

PSYMCRYPT_HASH testRsaRandomHash()
{
    BYTE rand = 0;

    do
    {
        rand = g_rng.byte() & 0x07;
    }
    while (rand > 4);

    switch (rand)
    {
        case 0:
            return (PSYMCRYPT_HASH) SymCryptMd5Algorithm;
            break;
        case 1:
            return (PSYMCRYPT_HASH) SymCryptSha1Algorithm;
            break;
        case 2:
            return (PSYMCRYPT_HASH) SymCryptSha256Algorithm;
            break;
        case 3:
            return (PSYMCRYPT_HASH) SymCryptSha384Algorithm;
            break;
        case 4:
            return (PSYMCRYPT_HASH) SymCryptSha512Algorithm;
            break;
        default:
            CHECK(FALSE, "?");
            return NULL;
    }
}

// The following function queries the OID list from Cng.
// This is needed for the Pkcs1 Signing tests on SymCrypt side.
VOID testRsaGetCngOidList(
    PSYMCRYPT_HASH  pHashAlgorithm,
    PBYTE           pbOut,
    SIZE_T          cbOut,
    SIZE_T *        pcbOut )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    ULONG cbTmp = 0;

    ntStatus = BCryptOpenAlgorithmProvider( &hAlg, testRsaScToCngHash(pHashAlgorithm), MS_PRIMITIVE_PROVIDER, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptGetProperty( hAlg, BCRYPT_HASH_OID_LIST, pbOut, (ULONG) cbOut, &cbTmp, 0);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    *pcbOut = cbTmp;
}

PBYTE
testRsaGenerateOneKey( UINT32 iSize, UINT32 iImpl )
{
    PBYTE pRes = NULL;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
    PSYMCRYPT_RSAKEY pkSymCryptKey = NULL;

    BOOL success = FALSE;
    bigctx_t bignumCtx = { 0 };
    big_prime_search_stat_t stats = { 0 };
    PRSA_PRIVATE_KEY pkMsBignumKey = NULL;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    switch( iImpl )
    {
        // SymCrypt
        case 0:
        {
            rsaParams.version = 1;
            rsaParams.nBitsOfModulus = g_BitSizeEntries[iSize].nBitsOfModulus;
            rsaParams.nPrimes = 2;
            rsaParams.nPubExp = 1;

            pkSymCryptKey = SymCryptRsakeyAllocate( &rsaParams, 0 );
            CHECK( pkSymCryptKey != NULL, "?" );

            // pick a random pubexp size
            SIZE_T nPubBits = g_rng.sizet( 2, 33 ); // **** fix 33->65 when CNG can handle it... 2 .. 64
            CHECK( nPubBits <= 64, "?" );

            // Generate an odd public exponent 
            UINT64 pubExp;
            ntStatus = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, (PBYTE)&pubExp, sizeof( pubExp ), 0 );
            CHECK( NT_SUCCESS(ntStatus), "?" );
            pubExp >>= (64 - nPubBits);
            pubExp |= (UINT64)1 << (nPubBits - 1);
            pubExp |= 1;

            scError = SymCryptRsakeyGenerate( pkSymCryptKey, &pubExp, 1, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

            pRes = (PBYTE) pkSymCryptKey;

            break;
        }
        // MsBignum
        case 1:
            pkMsBignumKey = (PRSA_PRIVATE_KEY) SymCryptCallbackAlloc(sizeof(RSA_PRIVATE_KEY));
            CHECK( pkMsBignumKey != NULL, "?" );

            success = rsa_construction(
                            (DWORDREGC)g_BitSizeEntries[iSize].nBitsOfModulus,
                            pkMsBignumKey,
                            NULL,
                            0,
                            &stats,
                            &bignumCtx);
            CHECK( success, "?" );

            pRes = (PBYTE) pkMsBignumKey;

            break;

        // Cng
        case 2:
            ntStatus = BCryptOpenAlgorithmProvider(
                            &hAlg,
                            BCRYPT_RSA_ALGORITHM,
                            MS_PRIMITIVE_PROVIDER,
                            0 );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );

            ntStatus = BCryptGenerateKeyPair(
                            hAlg,
                            &hKey,
                            g_BitSizeEntries[iSize].nBitsOfModulus,
                            0 );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );

            ntStatus = BCryptFinalizeKeyPair(
                            hKey,
                            0 );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );

            ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );

            pRes = (PBYTE) hKey;

            break;

        default:
            CHECK3(FALSE, "TestRsa: Unknown implementation %d\n", iImpl);
    }

    return pRes;
}

VOID
testRsaGenerateFunkyKey(
    UINT32  iSize,
    UINT32  nBitsOfPrime1,
    UINT32  nBitsOfPrime2,
    PBYTE   pbModulus,
    PUINT32 pcbModulus,
    PBYTE   pbPubExp,
    PUINT32 pcbPubExp,
    PBYTE   pbPrime1,
    PUINT32 pcbPrime1,
    PBYTE   pbPrime2,
    PUINT32 pcbPrime2 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PBYTE pbScratch = NULL;
    UINT32 cbScratch = 0;
    PBYTE pbScratchInternal = NULL;
    UINT32 cbScratchInternal = 0;

    UINT32 ndModulus = 0;
    UINT32 ndPrime1 = 0;
    UINT32 ndPrime2 = 0;

    UINT32 cbModulus = 0;
    UINT32 cbPrime1 = 0;
    UINT32 cbPrime2 = 0;

    // Set the public exponent to the default 65537
    UINT64 pubExp = (1 << 16) + 1;

    PSYMCRYPT_INT piModulus = NULL;
    PSYMCRYPT_INT piPrime1 = NULL;
    PSYMCRYPT_INT piPrime2 = NULL;

    PSYMCRYPT_INT piLow = NULL;
    PSYMCRYPT_INT piHigh = NULL;

    UINT32 nBitsOfModulus = g_BitSizeEntries[iSize].nBitsOfModulus;

    // Calculate the needed sizes
    ndPrime1 = SymCryptDigitsFromBits( nBitsOfPrime1 );
    ndPrime2 = SymCryptDigitsFromBits( nBitsOfPrime2 );
    ndModulus = ndPrime1 + ndPrime2;

    cbModulus = SymCryptSizeofIntFromDigits(ndModulus);
    cbPrime1 = SymCryptSizeofIntFromDigits(ndPrime1);
    cbPrime2 = SymCryptSizeofIntFromDigits(ndPrime2);

    // Calculate scratch space
    cbScratch = 3*cbModulus + cbPrime1 + cbPrime2 +
                SYMCRYPT_MAX(SYMCRYPT_SCRATCH_BYTES_FOR_INT_PRIME_GEN(ndModulus),
                    SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(ndModulus));

    // Allocate
    pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );
    CHECK(pbScratch!=NULL,"?");

    // Create objects
    pbScratchInternal = pbScratch;
    cbScratchInternal = cbScratch;

    piModulus = SymCryptIntCreate( pbScratchInternal, cbModulus, ndModulus );
    pbScratchInternal += cbModulus;
    cbScratchInternal -= cbModulus;
    piLow = SymCryptIntCreate( pbScratchInternal, cbModulus, ndModulus );
    pbScratchInternal += cbModulus;
    cbScratchInternal -= cbModulus;
    piHigh = SymCryptIntCreate( pbScratchInternal, cbModulus, ndModulus );
    pbScratchInternal += cbModulus;
    cbScratchInternal -= cbModulus;
    piPrime1 = SymCryptIntCreate( pbScratchInternal, cbPrime1, ndPrime1 );
    pbScratchInternal += cbPrime1;
    cbScratchInternal -= cbPrime1;
    piPrime2 = SymCryptIntCreate( pbScratchInternal, cbPrime2, ndPrime2 );
    pbScratchInternal += cbPrime2;
    cbScratchInternal -= cbPrime2;

    do
    {
        SymCryptIntSetValueUint32( 1, piLow );
        SymCryptIntMulPow2( piLow, nBitsOfPrime1 - 1, piLow );

        SymCryptIntSetValueUint32( 1, piHigh );
        SymCryptIntMulPow2( piHigh, nBitsOfPrime1, piHigh );
        SymCryptIntSubUint32( piHigh, 1, piHigh );

        scError = SymCryptIntGenerateRandomPrime(
                            piLow,
                            piHigh,
                            &pubExp,
                            1,
                            100*nBitsOfPrime1,
                            0,
                            piPrime1,
                            pbScratchInternal,
                            cbScratchInternal );
        CHECK(scError==SYMCRYPT_NO_ERROR, "Prime1 generation failed");

        SymCryptIntSetValueUint32( 1, piLow );
        SymCryptIntMulPow2( piLow, nBitsOfPrime2 - 1, piLow );

        SymCryptIntSetValueUint32( 1, piHigh );
        SymCryptIntMulPow2( piHigh, nBitsOfPrime2, piHigh );
        SymCryptIntSubUint32( piHigh, 1, piHigh );

        scError = SymCryptIntGenerateRandomPrime(
                            piLow,
                            piHigh,
                            &pubExp,
                            1,
                            100*nBitsOfPrime2,
                            0,
                            piPrime2,
                            pbScratchInternal,
                            cbScratchInternal );
        CHECK(scError==SYMCRYPT_NO_ERROR, "Prime2 generation failed");

        SymCryptIntMulMixedSize(
                            piPrime1,
                            piPrime2,
                            piModulus,
                            pbScratchInternal,
                            cbScratchInternal );
        CHECK(scError==SYMCRYPT_NO_ERROR, "Modulus multiplication failed");
    }
    while (SymCryptIntBitsizeOfValue(piModulus)!=nBitsOfModulus);

    *pcbModulus = (nBitsOfModulus+7)/8;
    scError = SymCryptIntGetValue( piModulus, pbModulus, *pcbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    *pcbPrime1 = (nBitsOfPrime1+7)/8;
    scError = SymCryptIntGetValue( piPrime1, pbPrime1, *pcbPrime1, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    *pcbPrime2 = (nBitsOfPrime2+7)/8;
    scError = SymCryptIntGetValue( piPrime2, pbPrime2, *pcbPrime2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    *pcbPubExp = SymCryptUint64Bytesize( pubExp );
    SymCryptStoreMsbFirstUint64( pubExp, pbPubExp, *pcbPubExp );

    SymCryptWipe( pbScratch, cbScratch );
    SymCryptCallbackFree( pbScratch );
}

VOID
testRsaExportOneKey(
    UINT32  iSize,
    UINT32  iImpl,
    PBYTE   pbModulus,
    PUINT32 pcbModulus,
    PBYTE   pbPubExp,
    PUINT32 pcbPubExp,
    PBYTE   pbPrime1,
    PUINT32 pcbPrime1,
    PBYTE   pbPrime2,
    PUINT32 pcbPrime2 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
    PSYMCRYPT_RSAKEY pkSymCryptKey = NULL;
    PBYTE ppPrimes[] = { NULL, NULL, };
    SIZE_T pcbPrimes[] = { 0, 0, };
    UINT64 pubExp;
    UINT32 cbPubExp;

    BOOL success = FALSE;
    bigctx_t bignumCtx = { 0 };
    PRSA_PRIVATE_KEY pkMsBignumKey = NULL;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_RSAKEY_BLOB * pRsaKeyBlob = NULL;

    BYTE rbKeyBlob[ 3*TEST_RSA_MAX_NUMOF_BYTES + sizeof( BCRYPT_RSAKEY_BLOB ) ] = { 0 };
    UINT32 cbKeyBlob = 0;
    UINT32 cbTmp = 0;

    switch (iImpl)
    {
        // SymCrypt
        case 0:
            pkSymCryptKey = (PSYMCRYPT_RSAKEY) g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImpl ].pKeys[iImpl];

            // Get the sizes
            *pcbModulus = SymCryptRsakeySizeofModulus( pkSymCryptKey );
            *pcbPrime1 = SymCryptRsakeySizeofPrime( pkSymCryptKey, 0 );
            *pcbPrime2 = SymCryptRsakeySizeofPrime( pkSymCryptKey, 1 );
            cbKeyBlob = *pcbModulus + *pcbPrime1 + *pcbPrime2;

            // CHECK( cbModulus <= sizeof( rbModulus ), "?" );
            // CHECK( cbPubExp <= sizeof( rbPubExp ), "?" );
            // CHECK( cbPrime1 <= sizeof( rbPrime1 ), "?" );
            // CHECK( cbPrime2 <= sizeof( rbPrime2 ), "?" );

            // CHECK( *pcbModulus + *pcbPubExp + *pcbPrime1 + *pcbPrime2 == cbKeyBlob, "?" );

            ppPrimes[0]  = &rbKeyBlob[*pcbModulus];
            ppPrimes[1]  = &rbKeyBlob[*pcbModulus + *pcbPrime1];
            pcbPrimes[0] = *pcbPrime1;
            pcbPrimes[1] = *pcbPrime2;

            // Export
            CHECK( cbKeyBlob <= sizeof( rbKeyBlob ), "?" );
            scError = SymCryptRsakeyGetValue(
                            pkSymCryptKey,
                            rbKeyBlob,
                            *pcbModulus,
                            &pubExp,
                            1,
                            ppPrimes,
                            pcbPrimes,
                            2,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                            0 );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

            // Fill each individual buffer
            cbTmp = 0;

            memcpy( pbModulus, &rbKeyBlob[cbTmp], *pcbModulus ); cbTmp += *pcbModulus;

            cbPubExp = SymCryptUint64Bytesize( pubExp );
            scError = SymCryptStoreMsbFirstUint64( pubExp, pbPubExp, cbPubExp );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
            *pcbPubExp = cbPubExp;

            memcpy( pbPrime1,  &rbKeyBlob[cbTmp], *pcbPrime1  ); cbTmp += *pcbPrime1;
            memcpy( pbPrime2,  &rbKeyBlob[cbTmp], *pcbPrime2  );

            break;

        // MsBignum
        case 1:
            pkMsBignumKey = (PRSA_PRIVATE_KEY) g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImpl ].pKeys[iImpl];

            // Get the sizes
            success = rsa_export_sizes(
                            (DWORD *)pcbPubExp,
                            (DWORD *)pcbModulus,
                            (DWORD *)pcbPrime1,
                            (DWORD *)pcbPrime2,
                            pkMsBignumKey,
                            &bignumCtx);
            CHECK( success, "?" );

            cbKeyBlob = *pcbPubExp + *pcbModulus + *pcbPrime1 + *pcbPrime2;

            // CHECK( cbModulus <= sizeof( rbModulus ), "?" );
            // CHECK( cbPubExp <= sizeof( rbPubExp ), "?" );
            // CHECK( cbPrime1 <= sizeof( rbPrime1 ), "?" );
            // CHECK( cbPrime2 <= sizeof( rbPrime2 ), "?" );

            // Export
            success = rsa_export(
                        pbPubExp, *pcbPubExp,
                        pbModulus, *pcbModulus,
                        pbPrime1, *pcbPrime1,
                        pbPrime2, *pcbPrime2,
                        pkMsBignumKey,
                        TRUE,
                        &bignumCtx );
            CHECK( success, "?" );

            break;

        // Cng
        case 2:
            hKey = (BCRYPT_KEY_HANDLE) g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImpl ].pKeys[iImpl];

            // Export
            ntStatus = BCryptExportKey(
                        hKey,
                        NULL,       // Export key
                        BCRYPT_RSAPRIVATE_BLOB,
                        (PUCHAR) rbKeyBlob,
                        sizeof( rbKeyBlob ),
                        (ULONG*) &cbKeyBlob,
                        0 );
            CHECK3( ntStatus == STATUS_SUCCESS, "BCryptExportKey failed with 0x%x", ntStatus );

            // Get the sizes
            pRsaKeyBlob = (BCRYPT_RSAKEY_BLOB *) &rbKeyBlob[0];
            *pcbPubExp = pRsaKeyBlob->cbPublicExp;
            *pcbModulus = pRsaKeyBlob->cbModulus;
            *pcbPrime1 = pRsaKeyBlob->cbPrime1;
            *pcbPrime2 = pRsaKeyBlob->cbPrime2;
            cbKeyBlob = *pcbPubExp + *pcbModulus + *pcbPrime1 + *pcbPrime2;

            // CHECK( cbModulus <= sizeof( rbModulus ), "?" );
            // CHECK( cbPubExp <= sizeof( rbPubExp ), "?" );
            // CHECK( cbPrime1 <= sizeof( rbPrime1 ), "?" );
            // CHECK( cbPrime2 <= sizeof( rbPrime2 ), "?" );

            // Fill each individual buffer
            cbTmp = sizeof(BCRYPT_RSAKEY_BLOB);

            memcpy( pbPubExp,  &rbKeyBlob[cbTmp], *pcbPubExp  ); cbTmp += *pcbPubExp;            
            memcpy( pbModulus, &rbKeyBlob[cbTmp], *pcbModulus ); cbTmp += *pcbModulus;
            memcpy( pbPrime1,  &rbKeyBlob[cbTmp], *pcbPrime1  ); cbTmp += *pcbPrime1;
            memcpy( pbPrime2,  &rbKeyBlob[cbTmp], *pcbPrime2  );

            break;

        default:
            CHECK3(FALSE, "TestRsa: Unknown implementation %d\n", iImpl);
    }
}

PBYTE
testRsaImportOneKey(
    UINT32  iSize,
    UINT32  iImpl,
    PBYTE   pbModulus,
    UINT32  cbModulus,
    PBYTE   pbPubExp,
    UINT32  cbPubExp,
    PBYTE   pbPrime1,
    UINT32  cbPrime1,
    PBYTE   pbPrime2,
    UINT32  cbPrime2 )
{
    PBYTE pRes = NULL;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
    PSYMCRYPT_RSAKEY pkSymCryptKey = NULL;
    UINT64 pubExp;
    PCBYTE ppPrimes[] = { NULL, NULL, };
    SIZE_T pcbPrimes[] = { 0, 0, };

    BOOL success = FALSE;
    bigctx_t bignumCtx = { 0 };
    PRSA_PRIVATE_KEY pkMsBignumKey = NULL;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_RSAKEY_BLOB * pRsaKeyBlob = NULL;

    BYTE rbKeyBlob[ 3*TEST_RSA_MAX_NUMOF_BYTES + sizeof( BCRYPT_RSAKEY_BLOB ) ] = { 0 };
    UINT32 cbKeyBlob = 0;

    UINT32 cbTmp = 0;

    switch (iImpl)
    {
        // SymCrypt
        case 0:
            // Allocate
            rsaParams.version = 1;
            rsaParams.nBitsOfModulus = g_BitSizeEntries[iSize].nBitsOfModulus;
            rsaParams.nPrimes = 2;
            rsaParams.nPubExp = 1;

            pkSymCryptKey = SymCryptRsakeyAllocate( &rsaParams, 0 );
            CHECK( pkSymCryptKey != NULL, "?" );

            ppPrimes[0] = pbPrime1;
            ppPrimes[1] = pbPrime2;
            pcbPrimes[0] = cbPrime1;
            pcbPrimes[1] = cbPrime2;

            scError = SymCryptLoadMsbFirstUint64( pbPubExp, cbPubExp, &pubExp );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

            // Import
            scError = SymCryptRsakeySetValue(
                            pbModulus,
                            cbModulus,
                            &pubExp,
                            1,
                            ppPrimes,
                            pcbPrimes,
                            2,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                            SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
                            pkSymCryptKey );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

            pRes = (PBYTE) pkSymCryptKey;

            break;

        // MsBignum
        case 1:
            // Allocate
            pkMsBignumKey = (PRSA_PRIVATE_KEY) SymCryptCallbackAlloc(sizeof(RSA_PRIVATE_KEY));
            CHECK( pkMsBignumKey != NULL, "?" );

            // Import
            success = rsa_import(
                        pbPubExp, cbPubExp,
                        pbModulus, cbModulus,
                        pbPrime1, cbPrime1,
                        pbPrime2, cbPrime2,
                        pkMsBignumKey,
                        TRUE,
                        &bignumCtx);
            CHECK( success, "Bignum failed to import RSA key" );

            pRes = (PBYTE) pkMsBignumKey;

            break;

        // Cng
        case 2:
            ntStatus = BCryptOpenAlgorithmProvider(
                            &hAlg,
                            BCRYPT_RSA_ALGORITHM,
                            MS_PRIMITIVE_PROVIDER,
                            0 );
            CHECK3( ntStatus == STATUS_SUCCESS, "BCryptOpenAlgorithmProvider with 0x%x", ntStatus );

            // Fix BCRYPT_RSAKEY_BLOB
            pRsaKeyBlob = (BCRYPT_RSAKEY_BLOB *) &rbKeyBlob[0];
            pRsaKeyBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
            pRsaKeyBlob->BitLength = g_BitSizeEntries[iSize].nBitsOfModulus;
            pRsaKeyBlob->cbPublicExp = cbPubExp;
            pRsaKeyBlob->cbModulus = cbModulus;
            pRsaKeyBlob->cbPrime1 = cbPrime1;
            pRsaKeyBlob->cbPrime2 = cbPrime2;

            CHECK( sizeof(BCRYPT_RSAKEY_BLOB) + cbPubExp + cbModulus + cbPrime1 + cbPrime2 <= sizeof(rbKeyBlob), "?" );

            // Set the values
            cbTmp = sizeof(BCRYPT_RSAKEY_BLOB);

            memcpy( &rbKeyBlob[cbTmp], pbPubExp,  cbPubExp  ); cbTmp += cbPubExp;
            memcpy( &rbKeyBlob[cbTmp], pbModulus, cbModulus ); cbTmp += cbModulus;
            memcpy( &rbKeyBlob[cbTmp], pbPrime1,  cbPrime1  ); cbTmp += cbPrime1;
            memcpy( &rbKeyBlob[cbTmp], pbPrime2,  cbPrime2  ); cbTmp += cbPrime2;

            cbKeyBlob = cbTmp;

            // Import the key
            ntStatus = BCryptImportKeyPair(
                            hAlg,
                            NULL,       // Import key
                            BCRYPT_RSAPRIVATE_BLOB,
                            &hKey,
                            rbKeyBlob,
                            cbKeyBlob,
                            0 );
            CHECK3( ntStatus == STATUS_SUCCESS, "BCryptImportKeyPair failed with 0x%x", ntStatus );

            ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );

            pRes = (PBYTE) hKey;

            break;
        default:
            CHECK3(FALSE, "TestRsa: Unknown implementation %d\n", iImpl);
    }

    return pRes;
}

VOID
testRsaGenerateKeys()
{
    // Buffers that hold all the parameters
    // These should be filled by the export function
    BYTE rbModulus[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };       UINT32 cbModulus = 0;
    BYTE rbPubExp[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };        UINT32 cbPubExp = 0;
    BYTE rbPrime1[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };        UINT32 cbPrime1 = 0;
    BYTE rbPrime2[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };        UINT32 cbPrime2 = 0;

    UINT32 nBitsOfPrime1 = 0;
    UINT32 nBitsOfPrime2 = 0;

    vprint( g_verbose, "\n");

    // Allocating the keys
    for ( UINT32 iSize = 0; iSize<TEST_RSA_KEYSIZES; iSize++ )
    {
        for( UINT32 iImplFrom = 0; iImplFrom<TEST_RSA_NUMOF_IMPS; iImplFrom++ )
        {
            g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].bitSize = g_BitSizeEntries[iSize].nBitsOfModulus;
            g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].keySize = (g_BitSizeEntries[iSize].nBitsOfModulus + 7)/8;

            // ** If the implementation iImplFrom is Cng generate a key only if the bitsize is divided by 64.
            //    Otherwise copy the pointers from the SymCrypt generated entry.
            if ((iImplFrom == 2) && (g_BitSizeEntries[iSize].nBitsOfModulus % 64 != 0))
            {
                vprint( g_verbose,  "    > KeyGen (Copy) -- Bitsize: %d Impl: %s\n", g_BitSizeEntries[iSize].nBitsOfModulus, g_ImplNames[iImplFrom] );

                for( UINT32 iImplTo = 0; iImplTo<TEST_RSA_NUMOF_IMPS; iImplTo++ )
                {
                    g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].pKeys[iImplTo] = g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS ].pKeys[iImplTo];
                }
            }
            else
            {
                if (g_BitSizeEntries[iSize].fUneqSizedPrimes)
                {
                    // Pick random prime sizes
                    nBitsOfPrime1 = (UINT32) g_rng.sizet(TEST_RSA_MIN_NUMOF_PRIME_BITS,  g_BitSizeEntries[iSize].nBitsOfModulus-TEST_RSA_MIN_NUMOF_PRIME_BITS);
                    nBitsOfPrime2 = g_BitSizeEntries[iSize].nBitsOfModulus - nBitsOfPrime1 + 1;

                    vprint( g_verbose,  "    > KeyGen (Uneq) -- Bitsize: %d (%d,%d) Impl: %s\n",
                                g_BitSizeEntries[iSize].nBitsOfModulus, 
                                nBitsOfPrime1,
                                nBitsOfPrime2,
                                g_ImplNames[iImplFrom] );

                    // Generate random funky parameters (in SymCrypt)
                    testRsaGenerateFunkyKey(iSize, nBitsOfPrime1, nBitsOfPrime2, rbModulus, &cbModulus, rbPubExp, &cbPubExp, rbPrime1, &cbPrime1, rbPrime2, &cbPrime2);

                    // Import this key into the required implementation
                    g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].pKeys[iImplFrom] = 
                                testRsaImportOneKey(iSize, iImplFrom, rbModulus, cbModulus, rbPubExp, cbPubExp, rbPrime1, cbPrime1, rbPrime2, cbPrime2);
                }
                else
                {
                    vprint( g_verbose,  "    > KeyGen (Proper) -- Bitsize: %d Impl: %s\n", g_BitSizeEntries[iSize].nBitsOfModulus, g_ImplNames[iImplFrom] );
                    // Generate one key
                    g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].pKeys[iImplFrom] = testRsaGenerateOneKey(iSize,iImplFrom);
                }

                // Export the key
                testRsaExportOneKey(iSize, iImplFrom, rbModulus, &cbModulus, rbPubExp, &cbPubExp, rbPrime1, &cbPrime1, rbPrime2, &cbPrime2);

                // Convert it to other implementations
                for (UINT32 iImplTo = 0; iImplTo<TEST_RSA_NUMOF_IMPS; iImplTo++)
                {
                    if (iImplFrom != iImplTo)
                    {
                        vprint( g_verbose,  "    >>>> Convert to: %s\n", g_ImplNames[iImplTo] );
                        g_KeyEntries[ iSize*TEST_RSA_NUMOF_IMPS + iImplFrom ].pKeys[iImplTo] = 
                            testRsaImportOneKey(iSize, iImplTo, rbModulus, cbModulus, rbPubExp, cbPubExp, rbPrime1, cbPrime1, rbPrime2, cbPrime2);
                    }
                }
            }
        }
    }
}

VOID
testRsaCleanKeys()
{

    // MsBignum
    BOOL success = FALSE;
    bigctx_t bignumCtx = { 0 };

    for (UINT32 i = 0; i<TEST_RSA_NUMOF_ENTRIES; i++)
    {
        // First, check every third line if the Cng key wasn't generated
        // but was copied from the SymCrypt line. If yes then skip
        // the freeing.
        if ( (i%3 == 2) && (g_KeyEntries[i].pKeys[0] == g_KeyEntries[i-2].pKeys[0]) )
        {
            continue;
        }

        if (g_KeyEntries[i].pKeys[0] != NULL)
        {
            SymCryptRsakeyFree( (PSYMCRYPT_RSAKEY) g_KeyEntries[i].pKeys[0] );
        }

        if (g_KeyEntries[i].pKeys[1] != NULL)
        {
            success = rsa_destruction( (RSA_PRIVATE_KEY *)g_KeyEntries[i].pKeys[1], &bignumCtx);
            CHECK( success, "?" );

            SymCryptWipe( g_KeyEntries[i].pKeys[1], sizeof(RSA_PRIVATE_KEY) );
            SymCryptCallbackFree( g_KeyEntries[i].pKeys[1] );
        }

        if (g_KeyEntries[i].pKeys[2] != NULL)
        {
            NTSTATUS ntStatus = STATUS_SUCCESS;
            ntStatus = BCryptDestroyKey( (BCRYPT_KEY_HANDLE) g_KeyEntries[i].pKeys[2] );
            CHECK( ntStatus == STATUS_SUCCESS, "?" );
        }
    }
}

VOID
testRsaPopulateAlgorithms()
{
    // The order specifies the order of the from implementations

    addImplementationToList<FunctionalRsaImp<ImpSc, AlgRsaEncRaw>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpMsBignum, AlgRsaEncRaw>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpCng, AlgRsaEncRaw>>(&g_AlgList);

    addImplementationToList<FunctionalRsaImp<ImpSc, AlgRsaEncPkcs1>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpCng, AlgRsaEncPkcs1>>(&g_AlgList);

    addImplementationToList<FunctionalRsaImp<ImpSc, AlgRsaEncOaep>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpCng, AlgRsaEncOaep>>(&g_AlgList);

    addImplementationToList<FunctionalRsaImp<ImpSc, AlgRsaSignPkcs1>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpCng, AlgRsaSignPkcs1>>(&g_AlgList);

    addImplementationToList<FunctionalRsaImp<ImpSc, AlgRsaSignPss>>(&g_AlgList);
    addImplementationToList<FunctionalRsaImp<ImpCng, AlgRsaSignPss>>(&g_AlgList);
}

VOID testRsaRunAlgs()
{
    BYTE    rbInput[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbInput = 0;

    BYTE    rbOutput[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbOutput = 0;

    BYTE    rbExtra[TEST_RSA_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbExtra = 0;

    PSYMCRYPT_HASH pHashAlgorithm = NULL;

    FuncRandFn randFunc = NULL;
    FuncDataFn queryFn = NULL;      // Encryption/Sign function
    FuncDataFn replyFn = NULL;      // Decryption/Verify function

    UINT32 iImplFrom = 0;
    UINT32 iImplTo = 0;

    vprint( g_verbose, "\n");

    for( std::vector<AlgorithmImplementation *>::iterator i = g_AlgList.begin(); i != g_AlgList.end(); i++ )
    {
        iImplFrom = ImplToInd( *i );

        vprint( g_verbose,  "    > Algorithm: %s From: %s\n", (*i)->m_algorithmName.c_str(), g_ImplNames[iImplFrom] );

        randFunc = ((FunctionalRsaImplementation *)(*i))->m_funcRandFunction;
        CHECK( randFunc != NULL, "TestRsa: No randomizing function.\n");

        queryFn = ((FunctionalRsaImplementation *)(*i))->m_funcQueryFunction;
        CHECK( queryFn != NULL, "TestRsa: No encryption / signing function.\n");

        for( std::vector<AlgorithmImplementation *>::iterator j = g_AlgList.begin(); j != g_AlgList.end(); j++ )
        {
            // Run tests if the algorithms are the same and at least one implementation is SymCrypt
            if (( (*i)->m_algorithmName == (*j)->m_algorithmName ) &&
                ( ((*i)->m_implementationName == ImpSc::name) || ((*j)->m_implementationName == ImpSc::name) ))
            {
                // If the algorithm is sign PKCS1 and the verifying implementation is CNG then
                // there is a bug in CNG's verification code in the case of small key, big hash algorithm,
                // and second OID in the list (e.g. 732 bits / SHA512 / 2nd OID of size 0xb bytes).
                // Then the first OID in the list with size 0xd bytes overflows the buffer and CNG
                // aborts (erroneously) the verification without checking the second OID. Therefore
                // we skip the scenario SymCrypt Signing => Cng Verification.
                if ( ((*i)->m_algorithmName == AlgRsaSignPkcs1::name) &&
                     ((*i)->m_implementationName == ImpSc::name) &&
                     ((*j)->m_implementationName == ImpCng::name) )
                {
                    continue;
                }

                iImplTo = ImplToInd( *j );

                replyFn = ((FunctionalRsaImplementation *)(*j))->m_funcReplyFunction;
                CHECK( replyFn != NULL, "TestRsa: No decryption/verify function.\n");

                vprint( g_verbose,  "    >>>> To: %s\n", g_ImplNames[iImplTo] );

                for (UINT32 entry = 0; entry < TEST_RSA_NUMOF_ENTRIES; entry++)
                {
                    // If the algorithm is sign PSS and the bitsize is not a multiple of 8, then
                    // Cng cannot process it (due to the Cng PSS padding accepting only byte aligned values).
                    // In these cases skip the tests.
                    if ( ((*i)->m_algorithmName == AlgRsaSignPss::name) &&
                         (g_KeyEntries[entry].bitSize % 8 != 0) &&
                         ( ((*i)->m_implementationName == ImpCng::name) || ((*j)->m_implementationName == ImpCng::name) ) )
                    {
                        continue;
                    }

                    for (UINT32 nTries = 0; nTries<TEST_RSA_NUMOF_RANDOM_TRIES; nTries++)
                    {
                        // For all algorithm pass in the bitsize of the modulus in cbExtra.
                        // Currently, raw encrypt and sign PSS use it:
                        // For raw encrypt the randomizing function can create an input that is at the edge of the
                        // modulus' bits.
                        // For PSS sign it can pick a salt size that is at the edge of the available buffer.
                        cbExtra = g_KeyEntries[entry].bitSize;

                        (*randFunc)(
                            g_KeyEntries[entry].keySize,
                            rbInput,
                            &cbInput,
                            &cbOutput,
                            rbExtra,
                            &cbExtra,
                            &pHashAlgorithm );

                        (*queryFn)(
                            g_KeyEntries[entry].keySize,
                            g_KeyEntries[entry].pKeys[iImplFrom],
                            rbInput,
                            cbInput,
                            rbOutput,
                            cbOutput,
                            rbExtra,
                            cbExtra,
                            pHashAlgorithm );

                        (*replyFn)(
                            g_KeyEntries[entry].keySize,
                            g_KeyEntries[entry].pKeys[iImplTo],
                            rbInput,
                            cbInput,
                            rbOutput,
                            cbOutput,
                            rbExtra,
                            cbExtra,
                            pHashAlgorithm );

                        (*i)->m_nResults ++;
                    }
                }
            }
        }
    }
}

VOID testRsaPrintResults()
{
    iprint("\n    Total Verified Interop Samples\n    ==============================\n");
    iprint("    %12s/%-8s   %s\n", "Algorithm", "FromImpl", "#");
    for( std::vector<AlgorithmImplementation *>::iterator i = g_AlgList.begin(); i != g_AlgList.end(); i++ )
    {
        iprint( "    %12s/%-8s : %llu\n", (*i)->m_algorithmName.c_str(), (*i)->m_implementationName.c_str(), (*i)->m_nResults );
    }
}

VOID
testRsaPkcs1Errors()
{
    // We check various PKCS1 padding errors 
    SYMCRYPT_ERROR scError;
    SYMCRYPT_RSA_PARAMS params;
    PSYMCRYPT_RSAKEY pKey;

    BYTE paddedData[256];
    BYTE ciphertext[256];
    BYTE res[256];
    SIZE_T cbRes;
    BYTE b;
    UINT32 i;

    UINT32 cbitModulus = 512 + g_rng.uint32() % 1024;
    UINT32 cbModulus = (cbitModulus + 7) / 8;

    // Create a 2048-bit key
    params.version = 1;
    params.nBitsOfModulus = cbitModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( pKey != 0, "?" );

    scError = SymCryptRsakeyGenerate( pKey, 0, 0, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating pkcs1 key" );

    for( i=0; i<sizeof( paddedData ); i++ )
    {
        do {
            paddedData[i] = g_rng.byte();
        } while( paddedData[i] == 0 );
    }

    paddedData[0] = 0;
    paddedData[1] = 2;
    paddedData[cbModulus - 1] = 0;

    scError = SymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_NO_ERROR && cbRes == 0, "?" );

    // Test first byte not zero
    if( cbitModulus % 8 != 1 )
    {
        // Setting the first byte to 1 might now work if the modulus starts with 0x01, 0x00, ...
        paddedData[0]++;
        scError = SymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
        paddedData[0]--;
    }

    // pick random nonzero b
    do{ b = g_rng.byte(); } while( b==0 );

    // Test second byte not 2
    paddedData[1] ^= b;    
    scError = SymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
    paddedData[1] ^= b;    

    // Test no zero byte 
    paddedData[cbModulus - 1] ^= b;
    scError = SymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
    paddedData[cbModulus - 1] ^= b;

    // Set each subsequent byte to 0 and check result
    for( UINT32 i = 2; i < cbModulus; i++ )
    {
        b = paddedData[ i ];
        paddedData[i] = 0;
        scError = SymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
        if( i <= 9 )
        {
            CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "No error when pkcs1 padding is too short" );
        } else {
            CHECK5( scError == SYMCRYPT_NO_ERROR && cbRes == cbModulus - i - 1, "Wrong length %d %d %d", cbModulus, i, cbRes );

            // Now check for the buffer-too-small error
            scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbRes, &cbRes );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
            if( cbRes > 0 )
            {
                scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbRes-1, &cbRes );
                CHECK( scError == SYMCRYPT_BUFFER_TOO_SMALL, "No buffer-too-small error message" );
            }

            cbRes = 1<<30;  // Big value to check that cbRes is actually being written to.
            scError = SymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, NULL, g_rng.byte(), &cbRes );
            CHECK( scError == SYMCRYPT_NO_ERROR && cbRes == cbModulus - i - 1, "Error when querying PKCS1 decryption length" );
        }

        paddedData[i] = b;
    }

//cleanup:
    SymCryptRsakeyFree( pKey );
    pKey = NULL;

}

VOID testRsa()
{
    static BOOL hasRun = FALSE;

    INT64 nAllocs = 0;

    if( hasRun )
    {
        return;
    }
    hasRun = TRUE;

    // Skip if there is no Rsa* algorithm to test.
    if( !isAlgorithmPresent( "Rsa", TRUE ) )
    {
        return;
    }

    iprint( "    RSA\n" );

    // Set the random bitsizes
    for (UINT32 i=0; i<TEST_RSA_KEYSIZES; i++)
    {
        if (g_BitSizeEntries[i].nBitsOfModulus == (UINT32)(-1))
        {
#define TEST_RSA_BIT_ALIGN    (1)
            g_BitSizeEntries[i].nBitsOfModulus = TEST_RSA_BIT_ALIGN*((UINT32)g_rng.sizet(TEST_RSA_MIN_NUMOF_BYTES*8/TEST_RSA_BIT_ALIGN, TEST_RSA_MAX_NUMOF_BYTES*8/TEST_RSA_BIT_ALIGN));
        }
    }

    nAllocs = g_nAllocs;

    CHECK( g_nOutstandingCheckedAllocs == 0, "Memory leak" );
    CHECK( g_nOutstandingCheckedAllocsMsBignum == 0, "Memory leak MsBignum" );

    testRsaGenerateKeys();

    testRsaPopulateAlgorithms();

    testRsaRunAlgs();

    testRsaCleanKeys();

    CHECK3( g_nOutstandingCheckedAllocs == 0, "Memory leak, %d outstanding", (unsigned) g_nOutstandingCheckedAllocs );
    CHECK3( g_nOutstandingCheckedAllocsMsBignum == 0, "Memory leak MsBignum, %d outstanding", (unsigned) g_nOutstandingCheckedAllocsMsBignum );

    testRsaPrintResults();

    testRsaPkcs1Errors();
    
    iprint( "\n" );
}
