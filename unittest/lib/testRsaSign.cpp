//
// TestRsaSign.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for hash functions.
//

#include "precomp.h"

#define MAX_RSA_TESTKEYS    (50)
RSAKEY_TESTBLOB g_RsaTestKeyBlobs[ MAX_RSA_TESTKEYS ] = {0};
UINT32 g_nRsaTestKeyBlobs = 0;

// RSA test keys for all RSA tests

VOID
rsaTestKeysAddOneFunky( UINT32 nBitsOfModulus )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PBYTE pbScratch = NULL;
    UINT32 cbScratch = 0;
    PBYTE pbScratchInternal = NULL;
    UINT32 cbScratchInternal = 0;

    CHECK( nBitsOfModulus > 1500, "Invalid key size" );
    UINT32 nBitsOfPrime1 = 512 + g_rng.uint32() % (nBitsOfModulus - 1024);
    UINT32 nBitsOfPrime2 = nBitsOfModulus - nBitsOfPrime1;

    UINT32 ndModulus = 0;
    UINT32 ndPrime1 = 0;
    UINT32 ndPrime2 = 0;

    UINT32 cbModulus = 0;
    UINT32 cbPrime1 = 0;
    UINT32 cbPrime2 = 0;

    // Set the public exponent to either 3 or 65537
    UINT64 pubExp = (g_rng.byte() & 1) ? 3 : (1 << 16) + 1;

    PSYMCRYPT_INT piModulus = NULL;
    PSYMCRYPT_INT piPrime1 = NULL;
    PSYMCRYPT_INT piPrime2 = NULL;

    PSYMCRYPT_INT piLow = NULL;
    PSYMCRYPT_INT piHigh = NULL;

    CHECK( g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS, "?" );
    PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ g_nRsaTestKeyBlobs++ ];
    SymCryptWipe( (PBYTE) pBlob, sizeof( *pBlob ) );

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

    pBlob->nBitsModulus = nBitsOfModulus;
    pBlob->u64PubExp = pubExp;

    pBlob->cbModulus = (nBitsOfModulus+7)/8;
    scError = SymCryptIntGetValue( piModulus, &pBlob->abModulus[0], pBlob->cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    pBlob->cbPrime1 = (nBitsOfPrime1+7)/8;
    scError = SymCryptIntGetValue( piPrime1, &pBlob->abPrime1[0], pBlob->cbPrime1, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    pBlob->cbPrime2 = (nBitsOfPrime2+7)/8;
    scError = SymCryptIntGetValue( piPrime2, &pBlob->abPrime2[0], pBlob->cbPrime2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK(scError==SYMCRYPT_NO_ERROR, "?");

    SymCryptWipe( pbScratch, cbScratch );
    SymCryptCallbackFree( pbScratch );

    iprint( "/%d", nBitsOfPrime1 );
}


VOID
rsaTestKeysAddOne( UINT32 bitSize )
{
    //iprint( "RSA key gen %d\n", bitSize );
    CHECK( g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS, "?" );

    SYMCRYPT_ERROR scError;
    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = bitSize;
    params.nPrimes = 2;
    params.nPubExp = 1;

    PSYMCRYPT_RSAKEY pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( pKey != NULL, "?" );

    UINT64 u64PubExp;

    // Pick a random-ish public exponent
    BYTE tmp[9];
    GENRANDOM( tmp, sizeof( tmp ) );
    u64PubExp = SYMCRYPT_LOAD_LSBFIRST64( tmp );
    UINT32 b = tmp[8];
    if( (b & 0xc0) != 0)
    {
        u64PubExp >>= b & 63;
        u64PubExp |= 1;
        if( u64PubExp == 1 )
        {
            u64PubExp = 3;
        }
    } else {
        u64PubExp = 65537;
    }

    UINT32 generateFlags = SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
    if( bitSize < SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS )
    {
        generateFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }

    scError = SymCryptRsakeyGenerate( pKey, &u64PubExp, 1, generateFlags );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ g_nRsaTestKeyBlobs++ ];
    SymCryptWipe( (PBYTE) pBlob, sizeof( *pBlob ) );

    pBlob->nBitsModulus = SymCryptRsakeyModulusBits( pKey );
    pBlob->cbModulus = SymCryptRsakeySizeofModulus( pKey );
    pBlob->cbPrime1 = SymCryptRsakeySizeofPrime( pKey, 0 );
    pBlob->cbPrime2 = SymCryptRsakeySizeofPrime( pKey, 1 );

    PBYTE ppPrime[2] = {&pBlob->abPrime1[0], &pBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pBlob->cbPrime1, pBlob->cbPrime2 };

    scError = SymCryptRsakeyGetValue( pKey, &pBlob->abModulus[0], pBlob->cbModulus, &pBlob->u64PubExp, 1, ppPrime, cbPrime, 2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    SymCryptRsakeyFree( pKey );
}

VOID rsaTestKeysGenerate()
{
    // Fill up our array of key blobs with generated keys
    const UINT32 desiredFixedKeySizes[] = {
        (8192 << 16) + 1, // 1 key of 8192 bits
        (4096 << 16) + 2, // 2 keys of 4096 bits
        (3072 << 16) + 3,
        (2048 << 16) + 5,
        (1536 << 16) + 2,
        (1024 << 16) + 5,
        (768  << 16) + 2,
        (512  << 16) + 2,
        0,
        };
    UINT32 bitSize;

    char * sep = " [test key gen: ";
    UINT32 previousSize = 0;

    if( g_nRsaTestKeyBlobs >= MAX_RSA_TESTKEYS )
    {
        goto cleanup;
    }

    for( int i = 0; desiredFixedKeySizes[i] != 0; i++ )
    {
        bitSize = desiredFixedKeySizes[i] >> 16;
        int n = desiredFixedKeySizes[i] & 0xff;
        while( n-- && g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS )
        {
            if( bitSize == previousSize )
            {
                iprint( "." );
            } else {
                iprint( "%s%d", sep, bitSize );
                sep = ",";
                previousSize = bitSize;
            }

            rsaTestKeysAddOne( bitSize );
        }
    }

    // And we fill the rest with randomly-sized keys
    // For performance we favor the smaller key sizes.
    // The last 10% of the keys are reserved for funky keys
    while( g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS - MAX_RSA_TESTKEYS / 10 )
    {
        UINT32 r = g_rng.uint32();
        // We use prime moduli as they are almost independent
        if( (r % 53) == 0 )
        {
            bitSize = (UINT32) g_rng.sizet( 4096, 8192 );
        } else if ( (r % 11) == 0 ) {
            bitSize = (UINT32) g_rng.sizet( 2048, 4096 );
        } else if( (r % 3) == 0 ) {
            bitSize = (UINT32) g_rng.sizet( 1024, 2048 );
        } else {
            bitSize = (UINT32) g_rng.sizet( 496, 2048 );
            // Arguably we should generate even smaller RSA keys to catch regressions for small keys
            // but the tests assume we can do PKCS1 signing with SHA256 for all generated keys, and
            // this 496 is the minimum
        }

        if( bitSize == previousSize )
        {
            iprint( "." );
        } else {
            iprint( "%s%d", sep, bitSize );
            sep = ",";
            previousSize = bitSize;
        }
        rsaTestKeysAddOne( bitSize );
    }

    while( g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS )
    {
        bitSize = (UINT32) g_rng.sizet( 3 * 512, 6 * 512 );
        iprint( ",F%d", bitSize );
        rsaTestKeysAddOneFunky( bitSize );
    }

    iprint( "]" );

cleanup:
    return;
}

PSYMCRYPT_RSAKEY
rsaKeyFromTestBlob( PCRSAKEY_TESTBLOB pBlob )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_RSA_PARAMS params;

    params.version = 1;
    params.nBitsOfModulus = pBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    PSYMCRYPT_RSAKEY pKey = ScDispatchSymCryptRsakeyAllocate( &params, 0 );
    CHECK( pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pBlob->abPrime1[0], &pBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pBlob->cbPrime1, pBlob->cbPrime2 };

    scError = ScDispatchSymCryptRsakeySetValue(
        &pBlob->abModulus[0], pBlob->cbModulus,
        &pBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return pKey;
}

PSYMCRYPT_RSAKEY
rsaTestKeyRandom()
{
    return rsaKeyFromTestBlob( &g_RsaTestKeyBlobs[ g_rng.uint32() % ARRAY_SIZE( g_RsaTestKeyBlobs ) ] );
}

PSYMCRYPT_RSAKEY
rsaTestKeyForSize( SIZE_T nBits )
{
    for( UINT32 i=0; i<g_nRsaTestKeyBlobs; i++ )
    {
        if( g_RsaTestKeyBlobs[i].nBitsModulus == nBits )
        {
            return rsaKeyFromTestBlob( &g_RsaTestKeyBlobs[i] );
        }
    }
    return NULL;
}

class RsaSignMultiImp: public RsaSignImplementation
{
public:
    RsaSignMultiImp( String algName );
    ~RsaSignMultiImp();

private:
    RsaSignMultiImp( const RsaSignMultiImp & );
    VOID operator=( const RsaSignMultiImp & );

public:

    typedef std::vector<RsaSignImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;                    // Implementations we use

    ImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob );

    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other,
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig );        // cbSig == cbModulus of key

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other );

    SIZE_T  m_cbSig;
};

RsaSignMultiImp::RsaSignMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<RsaSignImplementation>( algName, &m_imps );
}


RsaSignMultiImp::~RsaSignMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

NTSTATUS
RsaSignMultiImp::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    // m_imps is the set of implementations we support, but an implementation can opt out of any one key.
    // m_comps is the set of algorithm implementations that we are working with.

    m_comps.clear();

    if( pcKeyBlob != NULL )
    {
        m_cbSig = pcKeyBlob->cbModulus;
        CHECK( m_cbSig <= RSAKEY_MAXKEYSIZE, "Modulus too big" );
    }

    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pcKeyBlob ) == STATUS_SUCCESS )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
RsaSignMultiImp::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    ResultMerge res;
    NTSTATUS ntStatus;
    BYTE b[4];

    // Process result as MSBfirst array to get errors to print correctly.
    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        ntStatus = (*i)->verify( pbHash, cbHash, pbSig, cbSig, pcstrHashAlgName, u32Other );
        SYMCRYPT_STORE_MSBFIRST32( b, ntStatus );
        res.addResult( *i, b, 4 );
    }

    res.getResult( b, 4 );
    ntStatus = SYMCRYPT_LOAD_MSBFIRST32( b );
    return ntStatus;
}

NTSTATUS
RsaSignMultiImp::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    // RSA signatures are not necessarily deterministic (PSS) so we do the following:
    // - Have every implementation sign
    // - Have every implementation verify each signature
    // - return a random signature
    BYTE    sig[ RSAKEY_MAXKEYSIZE ];
    int nSigs = 0;
    NTSTATUS ntStatus;

    GENRANDOM( sig, sizeof( sig ) );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        sig[0]++;
        ntStatus = (*i)->sign( pbHash, cbHash, pcstrHashAlgName, u32Other, &sig[0], m_cbSig );
        CHECK( ntStatus == STATUS_SUCCESS, "Failure during RSA signature" );
        for( ImpPtrVector::iterator j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            ntStatus = (*j)->verify( pbHash, cbHash, &sig[0], m_cbSig, pcstrHashAlgName, u32Other );
            CHECK4( ntStatus == STATUS_SUCCESS, "RSA sig verification failure %s, %s",
                    (*i)->m_implementationName.c_str(),
                    (*j)->m_implementationName.c_str() );
        }

        // Copy a random sig to the output
        nSigs += 1;
        if( (g_rng.byte() % nSigs) == 0 )
        {
            CHECK5( cbSig == m_cbSig, "Signature mismatch, %d, %d, %s", cbSig, m_cbSig, (*i)->m_implementationName.c_str() );
            memcpy( pbSig, &sig[0], m_cbSig );
        }
    }

    return STATUS_SUCCESS;
}


VOID
createKatFileSinglePkcs1( FILE * f, PCRSAKEY_TESTBLOB pBlob, PCSTR hashName, UINT32 cbHash, PCSYMCRYPT_OID pOids, UINT32 nOids )
{
    BYTE hash[64];
    BYTE sig[1024];
    SIZE_T cbSig;
    SIZE_T cbTmp;
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_RSAKEY pKey = NULL;

    if( cbHash + 30 > pBlob->cbModulus )
    {
        // Hash is too large for this key, the padding will fail.
        // (The value 30 consists of up to 13 bytes OID, 6 bytes ASN.1 overhead, and 11 bytes padding.)
        goto cleanup;
    }

    CHECK( cbHash <= sizeof( hash ), "?" );
    GENRANDOM( hash, cbHash );

    fprintf( f, "N = " );
    fprintHex( f, pBlob->abModulus, pBlob->cbModulus );

    cbTmp = SymCryptUint64Bytesize( pBlob->u64PubExp );
    SymCryptStoreMsbFirstUint64( pBlob->u64PubExp, sig, cbTmp );
    fprintf( f, "e = "  );
    fprintHex( f, sig, cbTmp );

    fprintf( f, "P1 = " );
    fprintHex( f, pBlob->abPrime1, pBlob->cbPrime1 );

    fprintf( f, "P2 = " );
    fprintHex( f, pBlob->abPrime2, pBlob->cbPrime2 );

    fprintf( f, "HashAlg = \"%s\"\n", hashName );

    fprintf( f, "Hash = " );
    fprintHex( f, hash, cbHash );

    pKey = rsaKeyFromTestBlob( pBlob );

    scError = SymCryptRsaPkcs1Sign( pKey, hash, cbHash, pOids, nOids, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, sig, pBlob->cbModulus, &cbSig );
    CHECK4( scError == SYMCRYPT_NO_ERROR, "PKCS1 signature failed %d %d", cbHash, pBlob->cbModulus );

    fprintf( f, "Sig = " );
    fprintHex( f, sig, cbSig );

    fprintf( f, "\n" );

cleanup:
    if( pKey != NULL )
    {
        SymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
}

VOID
createKatFileSinglePss( FILE * f, PCRSAKEY_TESTBLOB pBlob, PCSTR hashName, PCSYMCRYPT_HASH pcHash, UINT32 cbHash, UINT32 cbSalt )
{
    BYTE hash[64];
    BYTE salt[64];
    BYTE sig[1024];
    SIZE_T cbSig;
    SIZE_T cbTmp;
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_RSAKEY pKey = NULL;

    if( cbHash + cbSalt + 3 > pBlob->cbModulus )
    {
        // Hash/salt is too large for this key, the padding will fail.
        goto cleanup;
    }

    CHECK( cbHash <= sizeof( hash ), "?" );
    GENRANDOM( hash, cbHash );
    GENRANDOM( salt, cbSalt );

    fprintf( f, "N = " );
    fprintHex( f, pBlob->abModulus, pBlob->cbModulus );

    cbTmp = SymCryptUint64Bytesize( pBlob->u64PubExp );
    SymCryptStoreMsbFirstUint64( pBlob->u64PubExp, sig, cbTmp );
    fprintf( f, "e = "  );
    fprintHex( f, sig, cbTmp );

    fprintf( f, "P1 = " );
    fprintHex( f, pBlob->abPrime1, pBlob->cbPrime1 );

    fprintf( f, "P2 = " );
    fprintHex( f, pBlob->abPrime2, pBlob->cbPrime2 );

    fprintf( f, "HashAlg = \"%s\"\n", hashName );

    fprintf( f, "Hash = " );
    fprintHex( f, hash, cbHash );

    fprintf( f, "cbSalt = %d\n", cbSalt );

    pKey = rsaKeyFromTestBlob( pBlob );
    scError = SymCryptRsaPssSign( pKey, hash, cbHash, pcHash, cbSalt, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, sig, pBlob->cbModulus, &cbSig );
    CHECK4( scError == SYMCRYPT_NO_ERROR, "PSS signature failed %d %d", cbHash, pBlob->cbModulus );

    fprintf( f, "Sig = " );
    fprintHex( f, sig, cbSig );

    fprintf( f, "\n" );

cleanup:
    if( pKey != NULL )
    {
        SymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
}

VOID
createKatFileRsaSign()
// This function is not normally used, but available for use whenever we want to re-generate
// new test vectors.
{
    // The NIST downloadable test vectors contain (N,e,d) and not (N,e,p,q).
    // Converting them is more work then generating our own. We test against known
    // good implementations, so we can rely on our newly generated vectors.
    FILE * f = fopen( "generated_kat_rsasign.dat", "wt" );
    CHECK( f != NULL, "Could not create output file" );

    fprintf( f, "#\n"
                "# DO NOT EDIT: Generated test vectors for RSA signatures\n"
                "#\n"
                "\n"
                );
    fprintf( f, "[RsaSignPkcs1]\n\n" );

    rsaTestKeysGenerate();

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];

        switch( g_rng.byte() % 8 )
        {
        case 0: createKatFileSinglePkcs1( f, pBlob, "MD5"   ,  16, SymCryptMd5OidList,    SYMCRYPT_MD5_OID_COUNT    ); break;
        case 1: createKatFileSinglePkcs1( f, pBlob, "SHA1"  ,  20, SymCryptSha1OidList,   SYMCRYPT_SHA1_OID_COUNT   ); break;
        case 2: createKatFileSinglePkcs1( f, pBlob, "SHA256",  32, SymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT ); break;
        case 3: createKatFileSinglePkcs1( f, pBlob, "SHA384",  48, SymCryptSha384OidList, SYMCRYPT_SHA384_OID_COUNT ); break;
        case 4: createKatFileSinglePkcs1( f, pBlob, "SHA512",  64, SymCryptSha512OidList, SYMCRYPT_SHA512_OID_COUNT ); break;
        case 5: createKatFileSinglePkcs1( f, pBlob, "SHA3-256",  32, SymCryptSha3_256OidList, SYMCRYPT_SHA3_256_OID_COUNT ); break;
        case 6: createKatFileSinglePkcs1( f, pBlob, "SHA3-384",  48, SymCryptSha3_384OidList, SYMCRYPT_SHA3_384_OID_COUNT ); break;
        case 7: createKatFileSinglePkcs1( f, pBlob, "SHA3-512",  64, SymCryptSha3_512OidList, SYMCRYPT_SHA3_512_OID_COUNT ); break;
        }
    }

    fprintf( f, "\n\nrnd = 1\n" );      // Trigger random-key test

    fprintf( f, "\n\n[RsaSignPss]\n\n" );

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];

        switch( g_rng.byte() % 8 )
        {
        case 0: createKatFileSinglePss( f, pBlob, "MD5"   , SymCryptMd5Algorithm,       16, 16 ); break;
        case 1: createKatFileSinglePss( f, pBlob, "SHA1"  , SymCryptSha1Algorithm,      20, 20 ); break;
        case 2: createKatFileSinglePss( f, pBlob, "SHA256", SymCryptSha256Algorithm,    32, 32 ); break;
        case 3: createKatFileSinglePss( f, pBlob, "SHA384", SymCryptSha384Algorithm,    48, 48 ); break;
        case 4: createKatFileSinglePss( f, pBlob, "SHA512", SymCryptSha512Algorithm,    64, 64 ); break;
        case 5: createKatFileSinglePss( f, pBlob, "SHA3_256", SymCryptSha3_256Algorithm,    32, 32 ); break;
        case 6: createKatFileSinglePss( f, pBlob, "SHA3_384", SymCryptSha3_384Algorithm,    48, 48 ); break;
        case 7: createKatFileSinglePss( f, pBlob, "SHA3_512", SymCryptSha3_512Algorithm,    64, 64 ); break;
        }
    }

    fprintf( f, "\n\nrnd = 1\n" );      // Trigger random-key test

    fclose( f );

    // Generating test vectors is not normal program flow, so we abort here to avoid getting into
    // non-standard states.
    CHECK( FALSE, "Written test vector file" );
}


VOID
testRsaSignSingle(
                            RsaSignImplementation * pRsaSign,
    _In_                    PCRSAKEY_TESTBLOB       pcRsaKeyBlob,
    _In_                    PCSTR                   pcstrHashAlgName,
                            UINT32                  u32Other,
    _In_reads_( cbHash )    PCBYTE                  pbHash,
                            SIZE_T                  cbHash,
    _In_reads_( cbSig )     PCBYTE                  pbSig,
                            SIZE_T                  cbSig,
                            INT64                   line )
{
    NTSTATUS    ntStatus;
    BYTE        sig[RSAKEY_MAXKEYSIZE];
    BYTE        hash[RSAKEY_MAXKEYSIZE];

    // iprint( "Single\n" );
    //CHECK( g_nOutstandingCheckedAllocs == 0, "Memory leak" );

    CHECK( cbSig == pcRsaKeyBlob->cbModulus, "?" );

    ntStatus = pRsaSign->setKey( pcRsaKeyBlob );
    CHECK( ntStatus == STATUS_SUCCESS, "Error setting key" );


    ntStatus = pRsaSign->verify( pbHash, cbHash, pbSig, cbSig, pcstrHashAlgName, u32Other );
    CHECK3( ntStatus == STATUS_SUCCESS, "Signature verification failure in line %lld", line)

    // Sign; the multi-imp will do cross-verification of all implementations.
    ntStatus = pRsaSign->sign( pbHash, cbHash, pcstrHashAlgName, u32Other, &sig[0], cbSig );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );

    // modify the signature and the hash, and verify errors
    CHECK( cbHash <= cbSig, "?" );
    memcpy( hash, pbHash, cbHash );
    UINT32 t = g_rng.uint32();
    hash[ (t/8) % cbHash ] ^= 1 << (t%8);
    ntStatus = pRsaSign->verify( hash, cbHash, pbSig, cbSig, pcstrHashAlgName, u32Other );
    CHECK3( ntStatus != STATUS_SUCCESS, "Signature verification success with modified hash value", line)
    hash[ (t/8) % cbHash ] ^= 1 << (t%8);

    t = g_rng.uint32();
    sig[ (t/8) % cbSig ] ^= 1 << (t%8);
    ntStatus = pRsaSign->verify( pbHash, cbHash, sig, cbSig, pcstrHashAlgName, u32Other );
    CHECK3( ntStatus != STATUS_SUCCESS, "Signature verification success with modified sig value", line)
    sig[ (t/8) % cbSig ] ^= 1 << (t%8);
    CHECK( pRsaSign->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
    //CHECK( g_nOutstandingCheckedAllocs == 0, "Memory leak" );
}

VOID
testRsaSignTestkeys(
    RsaSignImplementation * pRsaSign,
    INT64                   line )
{
    NTSTATUS    ntStatus;
    BYTE        sig[RSAKEY_MAXKEYSIZE];
    BYTE        hash[RSAKEY_MAXKEYSIZE];

    UNREFERENCED_PARAMETER( line );

    rsaTestKeysGenerate();

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];
        ntStatus = pRsaSign->setKey( pBlob );
        CHECK( ntStatus == STATUS_SUCCESS, "Error setting key" );

        GENRANDOM( hash, sizeof( hash ) );
        UINT32 cbHash = 32;
        UINT32 cbSalt = (UINT32) g_rng.sizet( 0, pBlob->cbModulus - 48 );

        // We always use the SHA256 alg for MGF as we've tested the others already
        // iprint( "%d, ", i );
        ntStatus = pRsaSign->sign( hash, cbHash, "SHA256", cbSalt, &sig[0], pBlob->cbModulus );
        CHECK( NT_SUCCESS( ntStatus ), "Error in RSA signing validation" );

        ntStatus = pRsaSign->verify( hash, cbHash, &sig[0], pBlob->cbModulus, "SHA256", cbSalt );
        CHECK( NT_SUCCESS( ntStatus ), "Error in RSA verification validation" );
    }
    CHECK( pRsaSign->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testRsaSignKats()
{
    // fix this.
    KatData *katRsaSign = getCustomResource( "kat_rsaSign.dat", "KAT_RSA_SIGN" );
    KAT_ITEM katItem;
    SYMCRYPT_ERROR scError;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<RsaSignMultiImp> pRsaSignMultiImp;

    while( 1 )
    {
        katRsaSign->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pRsaSignMultiImp.reset( new RsaSignMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pRsaSignMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pRsaSignMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "n" ) )
            {
                BString N = katParseData( katItem, "n" );
                BString e = katParseData( katItem, "e" );
                BString P1 = katParseData( katItem, "p1" );
                BString P2 = katParseData( katItem, "p2" );
                BString hashAlg = katParseData( katItem, "hashalg" );
                BString hash = katParseData( katItem, "hash" );
                BString sig = katParseData( katItem, "sig" );

                // Parse the optional cbSalt entry for PSS
                UINT32 u32Other = 0;
                if( findDataItem( katItem, "cbsalt" ) != NULL )
                {
                    u32Other = (UINT32) katParseInteger( katItem, "cbsalt" );
                }

                RSAKEY_TESTBLOB blob;
                blob.nBitsModulus = (UINT32)N.size() * 8;
                scError = SymCryptLoadMsbFirstUint64( e.data(), e.size(), &blob.u64PubExp );
                CHECK( scError == SYMCRYPT_NO_ERROR, "Error reading public exponent" );
                blob.cbModulus = (UINT32) N.size();
                blob.cbPrime1 = (UINT32) P1.size();
                blob.cbPrime2 = (UINT32) P2.size();

                CHECK( blob.cbModulus <= RSAKEY_MAXKEYSIZE && blob.cbPrime1 <= RSAKEY_MAXKEYSIZE && blob.cbPrime2 <= RSAKEY_MAXKEYSIZE,
                        "Test vector too large" );
                memcpy( blob.abModulus, N.data(), blob.cbModulus );
                memcpy( blob.abPrime1, P1.data(), blob.cbPrime1 );
                memcpy( blob.abPrime2, P2.data(), blob.cbPrime2 );

                char acStringName[100];
                memset( acStringName, 0, sizeof( acStringName ) );
                CHECK( hashAlg.size() < sizeof(acStringName) - 1, "?" );
                memcpy( acStringName, hashAlg.data(), hashAlg.size() );

                testRsaSignSingle(  pRsaSignMultiImp.get(),
                                    &blob,
                                    acStringName,
                                    u32Other,
                                    hash.data(), hash.size(),
                                    sig.data(), sig.size(),
                                    katItem.line );

                //FATAL2( "Unknown data record ending at line %lld", katRsaSign->m_line );
            } else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                testRsaSignTestkeys( pRsaSignMultiImp.get(), katItem.line );
            } else {
                CHECK( FALSE, "Invalid KAT record" );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katRsaSign;
}

VOID
testRsaSignPkcs1()
{
    // All normal cases are tested by the test vectors.
    // We just verify that the OID handling is correct
    //
    // The SymCrypt PKCS1 signature verification code does not parse the result of
    // the RSA public key operation. Rather, it encodes the hash with each
    // of the OIDs in turn and compares the encodings for equality.
    // This removes any parsing errors, so we don't need tests that try to find
    // the corner-cases of the parser.
    //
    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsaPkcs1Sign) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha256OidList) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeySizeofModulus) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsaPkcs1Verify) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeyAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeySetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeyFree) )
    {
        iprint( "    RsaSignPkcs1+ skipped\n");
        return;
    }

    iprint("    RsaSignPkcs1+");

    BYTE sig[ RSAKEY_MAXKEYSIZE ];
    PSYMCRYPT_RSAKEY pKey;
    BYTE hash[32];
    SIZE_T cbSig;
    SYMCRYPT_ERROR scError;

    for( int i = 0; i < 20; i++ )
    {
        pKey = rsaTestKeyRandom();

        GENRANDOM( hash, sizeof( hash ) );
        scError = ScDispatchSymCryptRsaPkcs1Sign(
                    pKey,
                    hash, sizeof( hash ),
                    ScDispatchSymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    sig, ScDispatchSymCryptRsakeySizeofModulus( pKey ),
                    &cbSig );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = ScDispatchSymCryptRsaPkcs1Verify(
                    pKey,
                    hash, sizeof( hash ),
                    sig, cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    ScDispatchSymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT,
                    0 );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "ScError = %08x", scError );

        // Now check for an error if we don't include the first OID that the signing used

        scError = ScDispatchSymCryptRsaPkcs1Verify(
                    pKey,
                    hash, sizeof( hash ),
                    sig, cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    ScDispatchSymCryptSha256OidList + 1, SYMCRYPT_SHA256_OID_COUNT - 1,
                    0 );
        CHECK( scError != SYMCRYPT_NO_ERROR, "?" );

        // Sign with the second OID
        scError = ScDispatchSymCryptRsaPkcs1Sign(
                    pKey,
                    hash, sizeof( hash ),
                    ScDispatchSymCryptSha256OidList + 1, SYMCRYPT_SHA256_OID_COUNT - 1,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    sig, ScDispatchSymCryptRsakeySizeofModulus( pKey ),
                    &cbSig );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = ScDispatchSymCryptRsaPkcs1Verify(
                    pKey,
                    hash, sizeof( hash ),
                    sig, cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    ScDispatchSymCryptSha256OidList+ 1, SYMCRYPT_SHA256_OID_COUNT - 1,
                    0 );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "ScError = %08x", scError );

        // Now check for success if we verify with both

        scError = ScDispatchSymCryptRsaPkcs1Verify(
                    pKey,
                    hash, sizeof( hash ),
                    sig, cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    ScDispatchSymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT,
                    0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        ScDispatchSymCryptRsakeyFree( pKey );
        pKey = NULL;
    }

    iprint( "\n" );
}

VOID
testRsaSignPss()
{
    iprint( "    RsaSignPss+" );

    BYTE sig[ RSAKEY_MAXKEYSIZE ];
    PSYMCRYPT_RSAKEY pKey = NULL;
    BYTE hash[64];
    UINT32 cbModulus;
    NTSTATUS ntStatus;


    std::unique_ptr<RsaSignMultiImp> pRsaSignMultiImp;
    pRsaSignMultiImp.reset( new RsaSignMultiImp( "RsaSignPss" ) );
    CHECK( pRsaSignMultiImp->m_imps.size() > 0, "No PSS impls?" );

    GENRANDOM( hash, sizeof( hash ) );

    for( int k = 0; k<20; k++ )
    {
        pKey = rsaTestKeyRandom();
        cbModulus = SymCryptRsakeySizeofModulus( pKey );
        CHECK( cbModulus <= sizeof( sig ), "?" );

        // Generate some random hash size/salt size values
        UINT32 cbHash;
        UINT32 cbSalt;
        cbHash = g_rng.uint32() % sizeof( hash );
        cbHash = SYMCRYPT_MIN( cbHash, cbModulus - 3);
        cbSalt = g_rng.uint32() % (cbModulus - 2 - cbHash );

        // The multi-imp sign automatically does a cross-verification of all
        // implementations
        ntStatus = pRsaSignMultiImp->sign(  hash, cbHash,
                                            "SHA256",
                                            cbSalt,
                                            sig, cbModulus );

        CHECK( NT_SUCCESS( ntStatus ), "Signature failure" );

        SymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
    iprint( "\n" );
}

VOID
testRsaSignAlgorithms()
{
    // Uncomment this function to generate a new KAT file
    // createKatFileRsaSign();

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );

    testRsaSignKats();
    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );

    if( isAlgorithmPresent( "RsaSignPkcs1", FALSE ) )
    {
        testRsaSignPkcs1();

        if( g_dynamicSymCryptModuleHandle != NULL )
        {
            print("    testRsaSignPkcs1 dynamic\n");
            g_useDynamicFunctionsInTestCall = TRUE;
            testRsaSignPkcs1();
            g_useDynamicFunctionsInTestCall = FALSE;
        }
    }

    if( isAlgorithmPresent( "RsaSignPss", FALSE ) )
    {
        testRsaSignPss();
    }

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );
}

