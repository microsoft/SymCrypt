//
// CNG implementation classes for the DL functional tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testInterop.h"

// Maximum sizes of DSA and DH key blob (blobs passed around always contain **private** info)
#define TEST_DL_MAX_SIZEOF_DSA_BLOB         (SYMCRYPT_MAX(sizeof(BCRYPT_DSA_KEY_BLOB)+4*TEST_DL_MAX_NUMOF_BYTES, sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 5*TEST_DL_MAX_NUMOF_BYTES))
#define TEST_DL_MAX_SIZEOF_DH_BLOB          (sizeof(BCRYPT_DH_KEY_BLOB)+4*TEST_DL_MAX_NUMOF_BYTES)
#define TEST_DL_MAX_SIZEOF_DH_PARAMS        (sizeof(BCRYPT_DH_PARAMETER_HEADER)+2*TEST_DL_MAX_NUMOF_BYTES)

#define TEST_DL_DSA_V1_GROUPSIZE            (20)

VOID testDlCng_DsaToDhBlob(
            UINT32  nBitsOfP,
    _In_    PBYTE   pbDsaBlob,
    _Out_   PBYTE   pbDhBlob,       // Buffer of size TEST_DL_MAX_SIZEOF_DH_BLOB
    _Out_   SIZE_T* pcbDhBlob )
{
    BCRYPT_DSA_KEY_BLOB * pDsaKeyBlobV1 = NULL;
    BCRYPT_DSA_KEY_BLOB_V2 * pDsaKeyBlobV2 = NULL;
    BCRYPT_DH_KEY_BLOB * pDhKeyBlob = NULL;

    SIZE_T cbSrc = 0;
    SIZE_T cbDst = 0;

    pDhKeyBlob = (BCRYPT_DH_KEY_BLOB*) &pbDhBlob[0];
    SymCryptWipe( pbDhBlob, TEST_DL_MAX_SIZEOF_DH_BLOB );

    if (nBitsOfP>1024)
    {
        pDsaKeyBlobV2 = (BCRYPT_DSA_KEY_BLOB_V2 *) &pbDsaBlob[0];

        CHECK( sizeof(BCRYPT_DH_KEY_BLOB)+4*pDsaKeyBlobV2->cbKey <= TEST_DL_MAX_SIZEOF_DH_BLOB, "?" );

        // Fill the parameters
        pDhKeyBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
        pDhKeyBlob->cbKey = pDsaKeyBlobV2->cbKey;

        // Move the pointers
        cbSrc = sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 2*pDsaKeyBlobV2->cbGroupSize;      // Skip the seed and Q
        cbDst = sizeof(BCRYPT_DH_KEY_BLOB);

        // Copy prime P, G, and the public key with one call
        memcpy( &pbDhBlob[cbDst], &pbDsaBlob[cbSrc], 3*pDhKeyBlob->cbKey ); cbSrc += 3*pDhKeyBlob->cbKey; cbDst += 3*pDhKeyBlob->cbKey;

        // Copy the private key in the correct position (0's in front)
        CHECK(pDsaKeyBlobV2->cbKey >= pDsaKeyBlobV2->cbGroupSize, "?");
        cbDst += (pDsaKeyBlobV2->cbKey - pDsaKeyBlobV2->cbGroupSize);

        memcpy( &pbDhBlob[cbDst], &pbDsaBlob[cbSrc], pDsaKeyBlobV2->cbGroupSize ); cbSrc += pDsaKeyBlobV2->cbGroupSize; cbDst += pDsaKeyBlobV2->cbGroupSize;
    }
    else
    {
        pDsaKeyBlobV1 = (BCRYPT_DSA_KEY_BLOB *) &pbDsaBlob[0];

        CHECK( sizeof(BCRYPT_DH_KEY_BLOB)+4*pDsaKeyBlobV1->cbKey <= TEST_DL_MAX_SIZEOF_DH_BLOB, "?" );

        // Fill the parameters
        pDhKeyBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
        pDhKeyBlob->cbKey = pDsaKeyBlobV1->cbKey;

        // Move the pointers
        cbSrc = sizeof(BCRYPT_DSA_KEY_BLOB);
        cbDst = sizeof(BCRYPT_DH_KEY_BLOB);

        // Copy prime P, G, and the public key with one call
        memcpy( &pbDhBlob[cbDst], &pbDsaBlob[cbSrc], 3*pDhKeyBlob->cbKey ); cbSrc += 3*pDhKeyBlob->cbKey; cbDst += 3*pDhKeyBlob->cbKey;

        // Copy the private key in the correct position (0's in front)
        CHECK(pDsaKeyBlobV1->cbKey >= TEST_DL_DSA_V1_GROUPSIZE, "?");
        cbDst += (pDsaKeyBlobV1->cbKey - TEST_DL_DSA_V1_GROUPSIZE);

        memcpy( &pbDhBlob[cbDst], &pbDsaBlob[cbSrc], TEST_DL_DSA_V1_GROUPSIZE ); cbSrc += TEST_DL_DSA_V1_GROUPSIZE; cbDst += TEST_DL_DSA_V1_GROUPSIZE;
    }

    *pcbDhBlob = cbDst;
}

VOID testDlCng_DsaToDhParams(
            UINT32  nBitsOfP,
    _In_    PBYTE   pbDsaBlob,
    _Out_   PBYTE   pbDhParams,    // Buffer of size TEST_DL_MAX_SIZEOF_DH_PARAMS
    _Out_   SIZE_T* pcbDhParams )
{
    BCRYPT_DSA_KEY_BLOB * pDsaKeyBlobV1 = NULL;
    BCRYPT_DSA_KEY_BLOB_V2 * pDsaKeyBlobV2 = NULL;
    BCRYPT_DH_PARAMETER_HEADER * pDhParams = NULL;

    SIZE_T cbSrc = 0;
    SIZE_T cbDst = 0;

    pDhParams = (BCRYPT_DH_PARAMETER_HEADER*) &pbDhParams[0];
    SymCryptWipe( pbDhParams, TEST_DL_MAX_SIZEOF_DH_PARAMS );

    if (nBitsOfP>1024)
    {
        pDsaKeyBlobV2 = (BCRYPT_DSA_KEY_BLOB_V2 *) &pbDsaBlob[0];

        CHECK( sizeof(BCRYPT_DH_PARAMETER_HEADER)+2*pDsaKeyBlobV2->cbKey <= TEST_DL_MAX_SIZEOF_DH_PARAMS, "?" );

        // Fill the parameters
        pDhParams->cbLength = sizeof(BCRYPT_DH_PARAMETER_HEADER)+2*pDsaKeyBlobV2->cbKey;
        pDhParams->cbKeyLength = pDsaKeyBlobV2->cbKey;
        pDhParams->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

        // Move the pointers
        cbSrc = sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 2*pDsaKeyBlobV2->cbGroupSize;      // Skip the seed and Q
        cbDst = sizeof(BCRYPT_DH_PARAMETER_HEADER);

        // Copy prime P, G with one call
        memcpy( &pbDhParams[cbDst], &pbDsaBlob[cbSrc], 2*pDhParams->cbKeyLength ); cbSrc += 2*pDhParams->cbKeyLength; cbDst += 2*pDhParams->cbKeyLength;
    }
    else
    {
        pDsaKeyBlobV1 = (BCRYPT_DSA_KEY_BLOB *) &pbDsaBlob[0];

        CHECK( sizeof(BCRYPT_DH_PARAMETER_HEADER)+2*pDsaKeyBlobV1->cbKey <= TEST_DL_MAX_SIZEOF_DH_PARAMS, "?" );

        // Fill the parameters
        pDhParams->cbLength = sizeof(BCRYPT_DH_PARAMETER_HEADER)+2*pDsaKeyBlobV1->cbKey;
        pDhParams->cbKeyLength = pDsaKeyBlobV1->cbKey;
        pDhParams->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

        // Move the pointers
        cbSrc = sizeof(BCRYPT_DSA_KEY_BLOB);
        cbDst = sizeof(BCRYPT_DH_PARAMETER_HEADER);

        // Copy prime P, G with one call
        memcpy( &pbDhParams[cbDst], &pbDsaBlob[cbSrc], 2*pDhParams->cbKeyLength ); cbSrc += 2*pDhParams->cbKeyLength; cbDst += 2*pDhParams->cbKeyLength;
    }

    *pcbDhParams = cbDst;
}

PCSYMCRYPT_HASH testDlCng_HashAlgEnumToScHash( HASHALGORITHM_ENUM cngHash )
{
    switch (cngHash)
    {
        case (DSA_HASH_ALGORITHM_SHA1):
            return SymCryptSha1Algorithm;
            break;
        case (DSA_HASH_ALGORITHM_SHA256):
            return SymCryptSha256Algorithm;
            break;
        case (DSA_HASH_ALGORITHM_SHA512):
            return SymCryptSha512Algorithm;
            break;
        default:
            CHECK(FALSE, "?");
            return NULL;
            break;
    }
}

SYMCRYPT_DLGROUP_FIPS testDlCng_FipsVersionEnumToScFipsVersion( DSAFIPSVERSION_ENUM fipsVersion )
{
    switch (fipsVersion)
    {
        case (DSA_FIPS186_2):
            return SYMCRYPT_DLGROUP_FIPS_186_2;
            break;
        case (DSA_FIPS186_3):
            return SYMCRYPT_DLGROUP_FIPS_186_3;
            break;
        default:
            CHECK(FALSE, "?");
            return SYMCRYPT_DLGROUP_FIPS_186_2;
            break;
    }
}

template<> VOID algImpTestInteropGenerateKeyEntry< ImpCng >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BYTE rbDsaKeyBlob[ TEST_DL_MAX_SIZEOF_DSA_BLOB ] = { 0 };
    SIZE_T cbDsaKeyBlob = 0;

    BYTE rbDhKeyBlob[ TEST_DL_MAX_SIZEOF_DH_BLOB ] = { 0 };
    SIZE_T cbDhKeyBlob = 0;

    BYTE rbDhParams[ TEST_DL_MAX_SIZEOF_DH_PARAMS ] = { 0 };
    SIZE_T cbDhParams = 0;

    // DSA key
    ntStatus = BCryptOpenAlgorithmProvider(
                    &hAlg,
                    BCRYPT_DSA_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptGenerateKeyPair(
                    hAlg,
                    &hKey,
                    pKE->nBitsOfP,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptFinalizeKeyPair(
                    hKey,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    pKE->pGroups[IMPCNG_INDEX] = NULL;
    pKE->pKeysDsa[IMPCNG_INDEX] = (PBYTE) hKey;

    // Export the key we just created
    ntStatus = BCryptExportKey(
                hKey,
                NULL,       // Export key
                BCRYPT_DSA_PRIVATE_BLOB,
                (PUCHAR) rbDsaKeyBlob,
                sizeof( rbDsaKeyBlob ),
                (ULONG*) &cbDsaKeyBlob,
                0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptExportKey failed with 0x%x", ntStatus );

    // Convert it to DH blob
    testDlCng_DsaToDhBlob( pKE->nBitsOfP, rbDsaKeyBlob, rbDhKeyBlob, &cbDhKeyBlob );

    // DH key A
    ntStatus = BCryptOpenAlgorithmProvider(
                    &hAlg,
                    BCRYPT_DH_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptImportKeyPair(
                hAlg,
                NULL,
                BCRYPT_DH_PRIVATE_BLOB,
                &hKey,
                rbDhKeyBlob,
                (ULONG) cbDhKeyBlob,
                BCRYPT_NO_KEY_VALIDATION );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptImportKeyPair failed with 0x%x", ntStatus );

    pKE->pKeysDhA[IMPCNG_INDEX] = (PBYTE) hKey;

    // DH key B
    ntStatus = BCryptGenerateKeyPair(
                    hAlg,
                    &hKey,
                    pKE->nBitsOfP,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    // Get the parameters
    testDlCng_DsaToDhParams( pKE->nBitsOfP, rbDsaKeyBlob, rbDhParams, &cbDhParams );

    // Set the property
    ntStatus = BCryptSetProperty(
                    hKey,
                    BCRYPT_DH_PARAMETERS,
                    rbDhParams,
                    (ULONG) cbDhParams,
                    0);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptFinalizeKeyPair(
                    hKey,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    pKE->pKeysDhB[IMPCNG_INDEX] = (PBYTE) hKey;

    ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<> VOID algImpTestInteropFillKeyEntryBuffers< ImpCng >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    NTSTATUS ntStatus = STATUS_SUCCESS;

    BCRYPT_DSA_KEY_BLOB * pDsaKeyBlobV1 = NULL;
    BCRYPT_DSA_KEY_BLOB_V2 * pDsaKeyBlobV2 = NULL;

    BYTE rbKeyBlob[ TEST_DL_MAX_SIZEOF_DSA_BLOB ] = { 0 };
    UINT32 cbKeyBlob = 0;
    SIZE_T cbTmp = 0;

    BCRYPT_DH_KEY_BLOB * pDhKeyBlob = NULL;

    BYTE rbDhKeyBlob[ TEST_DL_MAX_SIZEOF_DH_BLOB ] = { 0 };
    UINT32 cbDhKeyBlob = 0;

    // Export the DSA key
    CHECK(pKE->pKeysDsa[IMPCNG_INDEX]!=NULL, "?");
    ntStatus = BCryptExportKey(
                (BCRYPT_KEY_HANDLE) pKE->pKeysDsa[IMPCNG_INDEX],
                NULL,       // Export key
                BCRYPT_DSA_PRIVATE_BLOB,
                (PUCHAR) rbKeyBlob,
                sizeof( rbKeyBlob ),
                (ULONG*) &cbKeyBlob,
                0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptExportKey failed with 0x%x", ntStatus );

    if (pKE->nBitsOfP>1024)
    {
        pDsaKeyBlobV2 = (BCRYPT_DSA_KEY_BLOB_V2 *) &rbKeyBlob[0];

        CHECK( pDsaKeyBlobV2->cbKey==pKE->cbPrimeP, "?" );
        CHECK( pDsaKeyBlobV2->cbGroupSize==pKE->cbPrimeQ, "?" );
        CHECK( pDsaKeyBlobV2->cbSeedLength==pKE->cbPrimeQ, "?" );
        CHECK( testDlCng_HashAlgEnumToScHash(pDsaKeyBlobV2->hashAlgorithm)==pKE->pHashAlgorithm, "?" );
        CHECK( testDlCng_FipsVersionEnumToScFipsVersion(pDsaKeyBlobV2->standardVersion)==pKE->eFipsStandard, "?" );

        // Get the gencounter
        testInteropReverseMemCopy((PBYTE)&(pKE->dwGenCounter), &(pDsaKeyBlobV2->Count[0]), sizeof(UINT32));

        // Fill each individual buffer
        cbTmp = sizeof(BCRYPT_DSA_KEY_BLOB_V2);

        memcpy( pKE->rbSeed,    &rbKeyBlob[cbTmp], pKE->cbPrimeQ ); cbTmp += pKE->cbPrimeQ;
        memcpy( pKE->rbPrimeQ,  &rbKeyBlob[cbTmp], pKE->cbPrimeQ ); cbTmp += pKE->cbPrimeQ;
        memcpy( pKE->rbPrimeP,  &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;
        memcpy( pKE->rbGenG,    &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;

        memcpy( pKE->rbPublicKeyA,  &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;
        memcpy( pKE->rbPrivateKeyA, &rbKeyBlob[cbTmp], pKE->cbPrimeQ ); cbTmp += pKE->cbPrimeQ;
    }
    else
    {
        pDsaKeyBlobV1 = (BCRYPT_DSA_KEY_BLOB *) &rbKeyBlob[0];

        CHECK( pDsaKeyBlobV1->cbKey==pKE->cbPrimeP, "?" );
        CHECK( TEST_DL_DSA_V1_GROUPSIZE==pKE->cbPrimeQ, "?" );                  // Hard-coded for V1 keys in CNG
        CHECK( NULL==pKE->pHashAlgorithm, "?" );                                // Hard-coded for V1 keys in CNG
        CHECK( SYMCRYPT_DLGROUP_FIPS_186_2==pKE->eFipsStandard, "?" );          // Hard-coded for V1 keys in CNG

        // Get Q, seed and gencounter
        testInteropReverseMemCopy( (PBYTE)&(pKE->dwGenCounter), &(pDsaKeyBlobV1->Count[0]), sizeof(UINT32) );
        memcpy( pKE->rbSeed, &(pDsaKeyBlobV1->Seed[0]), TEST_DL_DSA_V1_GROUPSIZE );
        memcpy( pKE->rbPrimeQ, &(pDsaKeyBlobV1->q[0]), TEST_DL_DSA_V1_GROUPSIZE  );

        // Fill each individual buffer
        cbTmp = sizeof(BCRYPT_DSA_KEY_BLOB);

        memcpy( pKE->rbPrimeP,  &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;
        memcpy( pKE->rbGenG,    &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;

        memcpy( pKE->rbPublicKeyA,  &rbKeyBlob[cbTmp], pKE->cbPrimeP ); cbTmp += pKE->cbPrimeP;
        memcpy( pKE->rbPrivateKeyA, &rbKeyBlob[cbTmp], pKE->cbPrimeQ ); cbTmp += pKE->cbPrimeQ;
    }

    // Export the DH key B (we only care about the public and private key)
    CHECK(pKE->pKeysDhB[IMPCNG_INDEX]!=NULL, "?");
    ntStatus = BCryptExportKey(
                (BCRYPT_KEY_HANDLE) pKE->pKeysDhB[IMPCNG_INDEX],
                NULL,       // Export key
                BCRYPT_DH_PRIVATE_BLOB,
                (PUCHAR) rbDhKeyBlob,
                sizeof( rbDhKeyBlob ),
                (ULONG*) &cbDhKeyBlob,
                0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptExportKey failed with 0x%x", ntStatus );

    pDhKeyBlob = (BCRYPT_DH_KEY_BLOB *) &rbDhKeyBlob[0];
    CHECK( pDhKeyBlob->cbKey==pKE->cbPrimeP, "?" );

    cbTmp = sizeof(BCRYPT_DH_KEY_BLOB) + 2*pDhKeyBlob->cbKey;       // Move over the P and G

    pKE->cbPrivateKeyB = pDhKeyBlob->cbKey;                         // Bigger key
    memcpy( pKE->rbPublicKeyB, &rbDhKeyBlob[cbTmp], pDhKeyBlob->cbKey ); cbTmp += pDhKeyBlob->cbKey;
    memcpy( pKE->rbPrivateKeyB,&rbDhKeyBlob[cbTmp], pDhKeyBlob->cbKey ); cbTmp += pDhKeyBlob->cbKey;
}

template<> VOID algImpTestInteropImportKeyEntryBuffers< ImpCng >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCRYPT_DSA_KEY_BLOB * pDsaKeyBlobV1 = NULL;
    BCRYPT_DSA_KEY_BLOB_V2 * pDsaKeyBlobV2 = NULL;

    BYTE rbKeyBlob[ TEST_DL_MAX_SIZEOF_DSA_BLOB ] = { 0 };
    UINT32 cbKeyBlob = 0;
    SIZE_T cbTmp = 0;

    BCRYPT_DH_KEY_BLOB * pDhKeyBlob = NULL;

    BYTE rbDhKeyBlob[ TEST_DL_MAX_SIZEOF_DH_BLOB ] = { 0 };
    SIZE_T cbDhKeyBlob = 0;

    CHECK(pKE->pGroups[IMPCNG_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDsa[IMPCNG_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhA[IMPCNG_INDEX]==NULL, "?");
    CHECK(pKE->pKeysDhB[IMPCNG_INDEX]==NULL, "?");

    ntStatus = BCryptOpenAlgorithmProvider(
                    &hAlg,
                    BCRYPT_DSA_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptOpenAlgorithmProvider with 0x%x", ntStatus );

    // Fix DSA key blob
    if (pKE->nBitsOfP>1024)
    {
        pDsaKeyBlobV2 = (BCRYPT_DSA_KEY_BLOB_V2 *) &rbKeyBlob[0];
        pDsaKeyBlobV2->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC_V2;
        pDsaKeyBlobV2->cbKey = pKE->cbPrimeP;
        pDsaKeyBlobV2->hashAlgorithm = DSA_HASH_ALGORITHM_SHA256;        // Hard-coded for CNG
        pDsaKeyBlobV2->standardVersion = DSA_FIPS186_3;
        pDsaKeyBlobV2->cbSeedLength = pKE->cbPrimeQ;
        pDsaKeyBlobV2->cbGroupSize = pKE->cbPrimeQ;

        CHECK( testDlCng_HashAlgEnumToScHash(pDsaKeyBlobV2->hashAlgorithm)==pKE->pHashAlgorithm, "?" );
        CHECK( testDlCng_FipsVersionEnumToScFipsVersion(pDsaKeyBlobV2->standardVersion)==pKE->eFipsStandard, "?" );

        cbTmp = sizeof(BCRYPT_DSA_KEY_BLOB_V2);

        // Set the gencounter
        testInteropReverseMemCopy(&(pDsaKeyBlobV2->Count[0]), (PBYTE)&(pKE->dwGenCounter), sizeof(UINT32));

        memcpy( &rbKeyBlob[cbTmp], pKE->rbSeed,   pKE->cbPrimeQ  ); cbTmp += pKE->cbPrimeQ;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbPrimeQ, pKE->cbPrimeQ  ); cbTmp += pKE->cbPrimeQ;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbPrimeP, pKE->cbPrimeP  ); cbTmp += pKE->cbPrimeP;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbGenG,   pKE->cbPrimeP  ); cbTmp += pKE->cbPrimeP;

        memcpy( &rbKeyBlob[cbTmp], pKE->rbPublicKeyA,   pKE->cbPrimeP  );   cbTmp += pKE->cbPrimeP;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbPrivateKeyA,  pKE->cbPrimeQ  );   cbTmp += pKE->cbPrimeQ;
    }
    else
    {
        pDsaKeyBlobV1 = (BCRYPT_DSA_KEY_BLOB *) &rbKeyBlob[0];
        pDsaKeyBlobV1->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC;
        pDsaKeyBlobV1->cbKey = pKE->cbPrimeP;

        CHECK( TEST_DL_DSA_V1_GROUPSIZE==pKE->cbPrimeQ, "?" );                  // Hard-coded for V1 keys in CNG
        CHECK( NULL==pKE->pHashAlgorithm, "?" );                                // Hard-coded for V1 keys in CNG
        CHECK( SYMCRYPT_DLGROUP_FIPS_186_2==pKE->eFipsStandard, "?" );          // Hard-coded for V1 keys in CNG

        // Set Q, seed and gencounter
        testInteropReverseMemCopy( &(pDsaKeyBlobV1->Count[0]), (PBYTE)&(pKE->dwGenCounter), sizeof(UINT32) );
        memcpy( &(pDsaKeyBlobV1->Seed[0]), pKE->rbSeed, TEST_DL_DSA_V1_GROUPSIZE );
        memcpy( &(pDsaKeyBlobV1->q[0]), pKE->rbPrimeQ, TEST_DL_DSA_V1_GROUPSIZE  );

        cbTmp = sizeof(BCRYPT_DSA_KEY_BLOB);

        memcpy( &rbKeyBlob[cbTmp], pKE->rbPrimeP, pKE->cbPrimeP  ); cbTmp += pKE->cbPrimeP;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbGenG,   pKE->cbPrimeP  ); cbTmp += pKE->cbPrimeP;

        memcpy( &rbKeyBlob[cbTmp], pKE->rbPublicKeyA,   pKE->cbPrimeP  );   cbTmp += pKE->cbPrimeP;
        memcpy( &rbKeyBlob[cbTmp], pKE->rbPrivateKeyA,  pKE->cbPrimeQ  );   cbTmp += pKE->cbPrimeQ;
    }

    cbKeyBlob = (ULONG)cbTmp;

    // Import the key
    ntStatus = BCryptImportKeyPair(
                    hAlg,
                    NULL,       // Import key
                    BCRYPT_DSA_PRIVATE_BLOB,
                    &hKey,
                    rbKeyBlob,
                    cbKeyBlob,
                    0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptImportKeyPair failed with 0x%x", ntStatus );

    pKE->pKeysDsa[IMPCNG_INDEX] = (PBYTE) hKey;

    ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    // DH key A
    ntStatus = BCryptOpenAlgorithmProvider(
                    &hAlg,
                    BCRYPT_DH_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER,
                    0 );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptOpenAlgorithmProvider with 0x%x", ntStatus );

    // Fix DH blob for key A
    testDlCng_DsaToDhBlob( pKE->nBitsOfP, rbKeyBlob, rbDhKeyBlob, &cbDhKeyBlob );

    ntStatus = BCryptImportKeyPair(
                    hAlg,
                    NULL,       // Import key
                    BCRYPT_DH_PRIVATE_BLOB,
                    &hKey,
                    rbDhKeyBlob,
                    (ULONG) cbDhKeyBlob,
                    BCRYPT_NO_KEY_VALIDATION );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptImportKeyPair failed with 0x%x", ntStatus );

    pKE->pKeysDhA[IMPCNG_INDEX] = (PBYTE) hKey;

    // Fix DH blob for key B
    pDhKeyBlob = (BCRYPT_DH_KEY_BLOB *) &rbDhKeyBlob[0];

    cbTmp = sizeof(BCRYPT_DH_KEY_BLOB) + 2*pDhKeyBlob->cbKey;       // Move over the P and G

    // Copy the public key
    CHECK( pDhKeyBlob->cbKey==pKE->cbPrimeP, "?" );
    memcpy( &rbDhKeyBlob[cbTmp], pKE->rbPublicKeyB,   pKE->cbPrimeP  );   cbTmp += pKE->cbPrimeP;

    // For the private key pad with zeros if needed
    SymCryptWipe(&rbDhKeyBlob[cbTmp],  pDhKeyBlob->cbKey);

    // Set the key in the correct location
    CHECK( pKE->cbPrimeP >= pKE->cbPrivateKeyB, "?");
    cbTmp += (pKE->cbPrimeP - pKE->cbPrivateKeyB);
    memcpy( &rbDhKeyBlob[cbTmp], pKE->rbPrivateKeyB,  pKE->cbPrivateKeyB  );   cbTmp += pKE->cbPrivateKeyB;

    ntStatus = BCryptImportKeyPair(
                    hAlg,
                    NULL,       // Import key
                    BCRYPT_DH_PRIVATE_BLOB,
                    &hKey,
                    rbDhKeyBlob,
                    (ULONG) cbDhKeyBlob,
                    BCRYPT_NO_KEY_VALIDATION );
    CHECK3( ntStatus == STATUS_SUCCESS, "BCryptImportKeyPair failed with 0x%x", ntStatus );

    pKE->pKeysDhB[IMPCNG_INDEX] = (PBYTE) hKey;

    ntStatus = BCryptCloseAlgorithmProvider( hAlg, 0 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<> VOID algImpTestInteropCleanKeyEntry< ImpCng >(PBYTE pKeyEntry)
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    CHECK(pKE->pKeysDsa[IMPCNG_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhA[IMPCNG_INDEX]!=NULL, "?");
    CHECK(pKE->pKeysDhB[IMPCNG_INDEX]!=NULL, "?");

    ntStatus = BCryptDestroyKey( (BCRYPT_KEY_HANDLE) pKE->pKeysDsa[IMPCNG_INDEX] );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptDestroyKey( (BCRYPT_KEY_HANDLE) pKE->pKeysDhA[IMPCNG_INDEX] );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    ntStatus = BCryptDestroyKey( (BCRYPT_KEY_HANDLE) pKE->pKeysDhB[IMPCNG_INDEX] );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

//
// CNG - DsaSign
//

/*
template<> VOID algImpTestInteropRandFunction< ImpCng, AlgDsaSign >(
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

template<> VOID algImpTestInteropQueryFunction< ImpCng, AlgDsaSign >(
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

    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbSignature = 0;

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptSignHash(
                (BCRYPT_KEY_HANDLE) (pDlKeyEntry->pKeysDsa[IMPCNG_INDEX]),
                NULL,
                pbBufferA,
                (ULONG) cbBufferA,
                pbBufferB,
                (ULONG) cbBufferB,
                &cbSignature,
                0 );

    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbSignature == cbBufferB, "?" );
}

template<> VOID algImpTestInteropReplyFunction< ImpCng, AlgDsaSign >(
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

    NTSTATUS ntStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( pbBufferC );
    UNREFERENCED_PARAMETER( cbBufferC );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    ntStatus = BCryptVerifySignature(
                (BCRYPT_KEY_HANDLE) (pDlKeyEntry->pKeysDsa[IMPCNG_INDEX]),
                NULL,
                pbBufferA,
                (ULONG) cbBufferA,
                pbBufferB,
                (ULONG) cbBufferB,
                0 );
    CHECK( ntStatus == STATUS_SUCCESS, "Signing verification for DSA failed." );
}

template<>FunctionalInteropImp<ImpCng, AlgDsaSign>::FunctionalInteropImp()
{
    m_RandFunction      = &algImpTestInteropRandFunction <ImpSc, AlgDsaSign>;         // Notice the ImpSc implementation
    m_QueryFunction     = &algImpTestInteropQueryFunction <ImpCng, AlgDsaSign>;
    m_ReplyFunction     = &algImpTestInteropReplyFunction <ImpCng, AlgDsaSign>;
}

template<>
FunctionalInteropImp<ImpCng, AlgDsaSign>::~FunctionalInteropImp()
{
}

//
// Cng - Dh
//

/*
template<> VOID algImpTestInteropRandFunction< ImpCng, AlgDh >(
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

template<> VOID algImpTestInteropQueryFunction< ImpCng, AlgDh >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    BCRYPT_SECRET_HANDLE hSecret = NULL;
    ULONG cbResult = 0;

    NTSTATUS ntStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( pbBufferB );
    UNREFERENCED_PARAMETER( cbBufferB );
    UNREFERENCED_PARAMETER( cbBufferA );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    // Private key A and Public key B (it will be opposire on the reply)

    ntStatus = BCryptSecretAgreement(
                    (BCRYPT_KEY_HANDLE) pKE->pKeysDhA[IMPCNG_INDEX],
                    (BCRYPT_KEY_HANDLE) pKE->pKeysDhB[IMPCNG_INDEX],
                    &hSecret,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptSecretAgreement failed." );

    ntStatus = BCryptDeriveKey(
                    hSecret,
                    BCRYPT_KDF_RAW_SECRET,  // This exists from BLUE and above
                    NULL,
                    pbBufferC,
                    (ULONG) cbBufferC,      // Use buffer C as scratch
                    &cbResult,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptDeriveKey failed." );
    CHECK( cbResult == cbBufferC, "BCryptDeriveKey output wrong size");

    // BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET reverses the output (why?)
    testInteropReverseMemCopy( pbBufferA, pbBufferC, cbBufferC );

    ntStatus = BCryptDestroySecret( hSecret );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptDestroySecret failed." );
}

template<> VOID algImpTestInteropReplyFunction< ImpCng, AlgDh >(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm )
{
    PTEST_DL_KEYENTRY pKE = (PTEST_DL_KEYENTRY) pKeyEntry;

    BCRYPT_SECRET_HANDLE hSecret = NULL;
    ULONG cbResult = 0;

    NTSTATUS ntStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( cbBufferB );
    UNREFERENCED_PARAMETER( pHashAlgorithm );

    // Private key B and Public key A

    ntStatus = BCryptSecretAgreement(
                    (BCRYPT_KEY_HANDLE) pKE->pKeysDhB[IMPCNG_INDEX],
                    (BCRYPT_KEY_HANDLE) pKE->pKeysDhA[IMPCNG_INDEX],
                    &hSecret,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptSecretAgreement failed." );

    ntStatus = BCryptDeriveKey(
                    hSecret,
                    BCRYPT_KDF_RAW_SECRET,  // This exists from BLUE and above
                    NULL,
                    pbBufferC,
                    (ULONG) cbBufferC,      // Use buffer C as scratch
                    &cbResult,
                    0 );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptDeriveKey failed." );
    CHECK( cbResult == cbBufferC, "BCryptDeriveKey output wrong size");

    // BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET reverses the output (why?)
    testInteropReverseMemCopy( pbBufferB, pbBufferC, cbBufferC );

    ntStatus = BCryptDestroySecret( hSecret );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptDestroySecret failed." );

    CHECK( SymCryptEqual( pbBufferA, pbBufferB, cbBufferA ), "SymCryptDhSecretAgreement produced different DH secret");
}

template<>FunctionalInteropImp<ImpCng, AlgDh>::FunctionalInteropImp()
{
    m_RandFunction      = &algImpTestInteropRandFunction <ImpSc, AlgDh>;         // Notice the ImpSc implementation
    m_QueryFunction     = &algImpTestInteropQueryFunction <ImpCng, AlgDh>;
    m_ReplyFunction     = &algImpTestInteropReplyFunction <ImpCng, AlgDh>;
}

template<>
FunctionalInteropImp<ImpCng, AlgDh>::~FunctionalInteropImp()
{
}
