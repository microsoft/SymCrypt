//
// TestRsaEnc.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for hash functions.
//

#include "precomp.h"

class RsaEncMultiImp: public RsaEncImplementation
{
public:
    RsaEncMultiImp( String algName );
    ~RsaEncMultiImp();

private:
    RsaEncMultiImp( const RsaEncMultiImp & );
    VOID operator=( const RsaEncMultiImp & );

public:

    typedef std::vector<RsaEncImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;                    // Implementations we use

    ImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob );

    virtual NTSTATUS encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext );        // == cbModulus of key

    virtual NTSTATUS decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg );

    SIZE_T  m_cbCiphertext;

};

RsaEncMultiImp::RsaEncMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<RsaEncImplementation>( algName, &m_imps );
}


RsaEncMultiImp::~RsaEncMultiImp()
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
RsaEncMultiImp::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    // m_imps is the set of implementations we support, but an implementation can opt out of any one key.
    // m_comps is the set of algorithm implementations that we are working with.

    m_comps.clear();

    if( pcKeyBlob != NULL )
    {
        m_cbCiphertext = pcKeyBlob->cbModulus;
        CHECK( m_cbCiphertext <= RSAKEY_MAXKEYSIZE, "Modulus too big" );
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
 RsaEncMultiImp::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    BYTE msg[RSAKEY_MAXKEYSIZE];
    ResultMerge resMsg;
    ResultMerge resStatus;
    NTSTATUS ntStatus;
    SIZE_T cbResMsg = cbMsg + 1;
    BYTE b[4];

    CHECK( cbCiphertext == m_cbCiphertext, "Wrong ciphertext size" );

    GENRANDOM( msg, sizeof( msg ) );

    // Process result as MSBfirst array to get errors to print correctly.
    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        msg[0]++;
        ntStatus = (*i)->decrypt(   pbCiphertext, cbCiphertext,
                                    pcstrHashAlgName,
                                    pbLabel, cbLabel,
                                    msg, sizeof( msg ),
                                    &cbResMsg );
        SYMCRYPT_STORE_MSBFIRST32( b, ntStatus );
        resStatus.addResult( *i, b, 4 );
        resMsg.addResult( *i, msg, cbResMsg );
    }

    CHECK( cbResMsg <= cbMsg, "Buffer too small" );
    resMsg.getResult( pbMsg, cbResMsg );
    *pcbMsg = cbResMsg;

    resStatus.getResult( b, 4, FALSE );
    ntStatus = SYMCRYPT_LOAD_MSBFIRST32( b );
    return ntStatus;
}

NTSTATUS
RsaEncMultiImp::encrypt(
    _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                    SIZE_T  cbMsg,
                                    PCSTR   pcstrHashAlgName,
                                    PCBYTE  pbLabel,
                                    SIZE_T  cbLabel,
    _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                    SIZE_T  cbCiphertext )
{
    BYTE ciphertext[RSAKEY_MAXKEYSIZE];
    BYTE msg[ RSAKEY_MAXKEYSIZE ];
    SIZE_T cbMsgRes;
    int nEncs = 0;
    NTSTATUS ntStatus;
    NTSTATUS ntStatusRes = -1;

    CHECK( cbCiphertext == m_cbCiphertext, "Wrong ciphertext length" );

    GENRANDOM( msg, sizeof( msg ) );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); i++ )
    {
        ntStatus = (*i)->encrypt( pbMsg, cbMsg, pcstrHashAlgName, pbLabel, cbLabel, ciphertext, m_cbCiphertext );
        if( ntStatusRes == -1 )
        {
            ntStatusRes = ntStatus;
        } else {
            CHECK4( ntStatus == ntStatusRes, "Inconsistent encryption error %08x %08x", ntStatus, ntStatusRes );
        }

        if( NT_SUCCESS( ntStatus ) )
        {
            for( ImpPtrVector::iterator j = m_comps.begin(); j != m_comps.end(); j++ )
            {
                msg[0]++;
                ntStatus = (*j)->decrypt( ciphertext, cbCiphertext, pcstrHashAlgName, pbLabel, cbLabel, msg, sizeof( msg ), &cbMsgRes );
                CHECK( ntStatus == STATUS_SUCCESS, "Failure during RSA decryption" );
                CHECK( cbMsgRes == cbMsg, "Wrong message length" );
                CHECK( memcmp( pbMsg, msg, cbMsg ) == 0, "Wrong message data" );
            }
        }

        // Copy a random encryption to the output
        nEncs += 1;
        if( (g_rng.byte() % nEncs ) == 0 )
        {
            memcpy( pbCiphertext, ciphertext, cbCiphertext );
        }
    }

    return ntStatusRes;
}


VOID
createKatFileSingleRawEnc( FILE * f, PCRSAKEY_TESTBLOB pBlob )
{
    BYTE buf[RSAKEY_MAXKEYSIZE];

    SYMCRYPT_ERROR scError;

    UINT32 cbMod = pBlob->cbModulus;
    UINT32 nDigits = SymCryptDigitsFromBits( pBlob->nBitsModulus );

    SIZE_T cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS( nDigits );
    cbScratch = SYMCRYPT_MAX( cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );
    PBYTE pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );
    CHECK( pbScratch != NULL, "?" );

    PSYMCRYPT_MODULUS pMod = SymCryptModulusAllocate( nDigits );
    CHECK( pMod != NULL, "?" );

    PSYMCRYPT_INT pModInt = SymCryptIntFromModulus( pMod );
    CHECK( pModInt != NULL, "?" );

    scError = SymCryptIntSetValue( pBlob->abModulus, cbMod, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pModInt );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    SymCryptIntToModulus( pModInt, pMod, 20, SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch, cbScratch );

    // We have a modulus; now we need two modElement
    PSYMCRYPT_MODELEMENT pMsg = SymCryptModElementAllocate( pMod );
    PSYMCRYPT_MODELEMENT pTmp = SymCryptModElementAllocate( pMod );
    CHECK( pMsg != NULL && pTmp != NULL, "Out of memory" );

    SymCryptModSetRandom( pMod, pMsg, SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE | SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, pbScratch, cbScratch );


    fprintf( f, "N = " );
    fprintHex( f, pBlob->abModulus, cbMod );


    UINT64 exp = pBlob->u64PubExp;
    SIZE_T cbTmp = SymCryptUint64Bytesize( exp );
    SymCryptStoreMsbFirstUint64( exp, buf, cbTmp );
    fprintf( f, "e = "  );
    fprintHex( f, buf, cbTmp );

    fprintf( f, "P1 = " );
    fprintHex( f, pBlob->abPrime1, pBlob->cbPrime1 );

    fprintf( f, "P2 = " );
    fprintHex( f, pBlob->abPrime2, pBlob->cbPrime2 );

    scError = SymCryptModElementGetValue( pMod, pMsg, buf, cbMod, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to export random mod element" );
    fprintf( f, "Msg = " );
    fprintHex( f, buf, cbMod );

    // Now compute Msg^exp
    SymCryptModElementSetValueUint32( 1, pMod, pTmp, pbScratch, cbScratch );

    // Invariant: ciphertext = Tmp * Msg^exp
    while( exp != 0 )
    {
        if( (exp & 1) != 0 )
        {
            SymCryptModMul( pMod, pTmp, pMsg, pTmp, pbScratch, cbScratch );
            exp -= 1;
        }
        SymCryptModSquare( pMod, pMsg, pMsg, pbScratch, cbScratch );
        exp /= 2;
    }

    scError = SymCryptModElementGetValue( pMod, pTmp, buf, cbMod, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to export random mod element" );
    fprintf( f, "Ciphertext = " );
    fprintHex( f, buf, cbMod );

    fprintf( f, "\n" );

    if( pTmp != NULL )
    {
        SymCryptModElementFree( pMod, pTmp );
        pTmp = NULL;
    }

    if( pMsg != NULL )
    {
        SymCryptModElementFree( pMod, pMsg );
        pMsg = NULL;
    }

    if( pMod != NULL )
    {
        SymCryptModulusFree( pMod );
        pMod = NULL;
    }

    if( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
        pbScratch = NULL;
    }
}

VOID
createKatFileSinglePkcs1Enc( FILE * f, PCRSAKEY_TESTBLOB pBlob )
{
    BYTE msg[RSAKEY_MAXKEYSIZE];
    BYTE ciphertext[RSAKEY_MAXKEYSIZE];
    SIZE_T cbCiphertext;
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_RSAKEY pKey = NULL;
    SIZE_T cbMsg;


    cbCiphertext = pBlob->cbModulus;
    CHECK( cbCiphertext >= 64, "?" );
    CHECK( cbCiphertext <= sizeof( ciphertext ), "?" );

    // Pick random message size; must be <= cbCiphertext - 11
    cbMsg = g_rng.uint32() % (cbCiphertext - 10);

    GENRANDOM( msg, (ULONG) cbMsg );

    fprintf( f, "N = " );
    fprintHex( f, pBlob->abModulus, pBlob->cbModulus );

    // Use ciphertext buffer as temp space
    SIZE_T cbTmp = SymCryptUint64Bytesize( pBlob->u64PubExp );
    SymCryptStoreMsbFirstUint64( pBlob->u64PubExp, ciphertext, cbTmp );
    fprintf( f, "e = "  );
    fprintHex( f, ciphertext, cbTmp );

    fprintf( f, "P1 = " );
    fprintHex( f, pBlob->abPrime1, pBlob->cbPrime1 );

    fprintf( f, "P2 = " );
    fprintHex( f, pBlob->abPrime2, pBlob->cbPrime2 );

    fprintf( f, "Msg = " );
    fprintHex( f, msg, cbMsg );

    pKey = rsaKeyFromTestBlob( pBlob );

    scError = SymCryptRsaPkcs1Encrypt( pKey, msg, cbMsg, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, ciphertext, cbCiphertext, &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "PKCS1 encryption failed" );
    CHECK( cbTmp == cbCiphertext, "?" );

    fprintf( f, "Ciphertext = " );
    fprintHex( f, ciphertext, cbCiphertext );

    fprintf( f, "\n" );

    if( pKey != NULL )
    {
        SymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
}

VOID
createKatFileSingleOaep( FILE * f, PCRSAKEY_TESTBLOB pBlob, PCSTR hashName, PCSYMCRYPT_HASH pcHash, SIZE_T cbHash )
{
    BYTE msg[RSAKEY_MAXKEYSIZE];
    BYTE label[RSAKEY_MAXKEYSIZE];
    BYTE ciphertext[RSAKEY_MAXKEYSIZE];

    SIZE_T cbMsg;
    SIZE_T cbLabel;
    SIZE_T cbCiphertext;
    SIZE_T cbTmp;
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_RSAKEY pKey = NULL;

    cbCiphertext = pBlob->cbModulus;
    CHECK( cbCiphertext <= sizeof( ciphertext ), "?" );

    if( cbHash * 2 + 2 > cbCiphertext )
    {
        // Doesn't fit, skip this test case
        goto cleanup;
    }

    cbMsg = g_rng.sizet( 0, cbCiphertext - 2 - 2 * cbHash );
    GENRANDOM( msg, (ULONG) cbMsg );

    cbLabel = g_rng.sizet( 0, sizeof( label ) );
    GENRANDOM( label, (ULONG) cbLabel );

    fprintf( f, "N = " );
    fprintHex( f, pBlob->abModulus, pBlob->cbModulus );

    cbTmp = SymCryptUint64Bytesize( pBlob->u64PubExp );
    SymCryptStoreMsbFirstUint64( pBlob->u64PubExp, ciphertext, cbTmp );
    fprintf( f, "e = "  );
    fprintHex( f, ciphertext, cbTmp );

    fprintf( f, "P1 = " );
    fprintHex( f, pBlob->abPrime1, pBlob->cbPrime1 );

    fprintf( f, "P2 = " );
    fprintHex( f, pBlob->abPrime2, pBlob->cbPrime2 );

    fprintf( f, "HashAlg = \"%s\"\n", hashName );

    fprintf( f, "Msg = " );
    fprintHex( f, msg, cbMsg );

    fprintf( f, "Label = "  );
    fprintHex( f, label, cbLabel );

    pKey = rsaKeyFromTestBlob( pBlob );

    scError = SymCryptRsaOaepEncrypt( pKey, msg, cbMsg, pcHash, label, cbLabel, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, ciphertext, cbCiphertext, &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR, "OAEP encryption failed" );
    CHECK( cbTmp == cbCiphertext, "?" );

    fprintf( f, "Ciphertext = " );
    fprintHex( f, ciphertext, cbCiphertext );

    fprintf( f, "\n" );

cleanup:
    if( pKey != NULL )
    {
        SymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
}

VOID
createKatFileRsaEnc()
// This function is not normally used, but available for use whenever we want to re-generate
// new test vectors.
{
    // The NIST downloadable test vectors contain (N,e,d) and not (N,e,p,q).
    // Converting them is more work then generating our own. We test against known
    // good implementations, so we can rely on our newly generated vectors.
    FILE * f = fopen( "generated_kat_RsaEnc.dat", "wt" );
    CHECK( f != NULL, "Could not create output file" );


    fprintf( f, "#\n"
                "# DO NOT EDIT: Generated test vectors for RSA encryption\n"
                "#\n"
                );

    fprintf( f, "\n\n[RsaEncRaw]\n\n" );

    rsaTestKeysGenerate();

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];
        createKatFileSingleRawEnc( f, pBlob );
    }

    fprintf( f, "\n\nrnd = 1\n" );      // Trigger random-key test; 1 = RAW

    fprintf( f, "\n\n[RsaEncPkcs1]\n\n" );

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];
        createKatFileSinglePkcs1Enc( f, pBlob );
    }

    fprintf( f, "\n\nrnd = 2\n" );      // Trigger random-key test, 2 = PKCS1

    fprintf( f, "\n\n[RsaEncOaep]\n\n" );

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];

        switch( g_rng.byte() % 5 )
        {
        case 0: createKatFileSingleOaep( f, pBlob, "MD5"   , SymCryptMd5Algorithm,       16 ); break;
        case 1: createKatFileSingleOaep( f, pBlob, "SHA1"  , SymCryptSha1Algorithm,      20 ); break;
        case 2: createKatFileSingleOaep( f, pBlob, "SHA256", SymCryptSha256Algorithm,    32 ); break;
        case 3: createKatFileSingleOaep( f, pBlob, "SHA384", SymCryptSha384Algorithm,    48 ); break;
        case 4: createKatFileSingleOaep( f, pBlob, "SHA512", SymCryptSha512Algorithm,    64 ); break;
        }
    }

    fprintf( f, "\n\nrnd = 3\n" );      // Trigger random-key test, 3 = OAEP

    // Generating test vectors is not normal program flow, so we abort here to avoid getting into
    // non-standard states.
    CHECK( FALSE, "Written test vector file" );
}


VOID
testRsaEncSingle(
                                RsaEncImplementation  * pRsaEnc,
    _In_                        PCRSAKEY_TESTBLOB       pcRsaKeyBlob,
    _In_reads_( cbMsg )         PCBYTE                  pbMsg,
                                SIZE_T                  cbMsg,
    _In_                        PCSTR                   pcstrHashAlgName,
    _In_reads_( cbLabel )       PCBYTE                  pbLabel,
                                SIZE_T                  cbLabel,
    _In_reads_( cbCiphertext )  PCBYTE                  pbCiphertext,
                                SIZE_T                  cbCiphertext,
                                INT64                   line )
{
    NTSTATUS    ntStatus;
    BYTE buf[RSAKEY_MAXKEYSIZE];
    SIZE_T cbRes;
    SIZE_T cbKey;

    //iprint( "Single... " );

    cbKey = pcRsaKeyBlob->cbModulus;
    CHECK( cbCiphertext == cbKey, "?" );

    ntStatus = pRsaEnc->setKey( pcRsaKeyBlob );
    CHECK( ntStatus == STATUS_SUCCESS, "Error setting key" );

    ntStatus = pRsaEnc->decrypt( pbCiphertext, cbCiphertext, pcstrHashAlgName, pbLabel, cbLabel, buf, cbKey, &cbRes );
    CHECK3( ntStatus == STATUS_SUCCESS, "Decryption failure in line %lld", line);
    CHECK3( cbRes == cbMsg, "Wrong message length in line %lld", line );
    CHECK3( memcmp( buf, pbMsg, cbMsg ) == 0, "Wrong message in line %lld", line );

    // Check whether we get an error when the ciphertext is modified.
    // For RsaRaw we never get an error.
    // For OAEP we should always get an error.
    // PKCS1 will mostly give an error but sometimes succeed (prob about 2^-16)
    // We don't do this test for PKCS1 as PKCS1 decryption errors are tested elsewhere.
    // We detect RsaRaw because cbMsg == cbKey, and OAEP because pcstrHashAlgName != NULL

    if( cbMsg == cbKey || pcstrHashAlgName != NULL )            // Only for RsaRaw and OAEP
    {
        // Modify the ciphertext, not in the first byte to avoid values > modulus
        memcpy( buf, pbCiphertext, cbKey );
        UINT32 t = g_rng.uint32();
        buf[ 1 + ((t/8) % (cbKey - 1)) ] ^= 1 << (t%8);
        ntStatus = pRsaEnc->decrypt( buf, cbKey, pcstrHashAlgName, pbLabel, cbLabel, buf, cbKey, &cbRes );
        if( cbMsg == cbKey )
        {
            // We are handling RsaRaw
            CHECK( ntStatus == STATUS_SUCCESS, "Error decrypting modified RsaRaw ciphertext" );
        } else {
            // OAEP
            CHECK( !NT_SUCCESS( ntStatus ), "Modified ciphertext did not generate an RsaOaep decryption error" );
        }
    }

    // Encrypt; the multi-imp will do cross-verification of all implementations.
    ntStatus = pRsaEnc->encrypt( pbMsg, cbMsg, pcstrHashAlgName, pbLabel, cbLabel, buf, cbKey );
    CHECK3( ntStatus == STATUS_SUCCESS, "error encrypting message in line %lld", line );

    CHECK( pRsaEnc->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testRsaEncTestkeys(
    RsaEncImplementation * pRsaEnc,
    UINT32                  rnd,
    INT64                   line )
{
    NTSTATUS    ntStatus;
    BYTE        msg[RSAKEY_MAXKEYSIZE];
    BYTE        ciph[RSAKEY_MAXKEYSIZE];

    UNREFERENCED_PARAMETER( line );

    rsaTestKeysGenerate();

    for( int i=0; i<MAX_RSA_TESTKEYS; i++ )
    {
        PRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ i ];
        ntStatus = pRsaEnc->setKey( pBlob );
        CHECK( ntStatus == STATUS_SUCCESS, "Error setting key" );

        PCSTR strHash = "SHA256";

        GENRANDOM( msg, sizeof( msg ) );

        UINT32 cbMsg = 1 << 30; // Catch errors when this is not further set
        UINT32 cbLabel = (UINT32) g_rng.sizet( 0, 64 );

        // Special case for RAW encryption
        if( rnd == 1 )
        {
            cbMsg = pBlob->cbModulus;
            msg[0] = 0;                 // Make sure it is < modulus
        }

        // special case for OAEP encryption
        if( rnd == 2 )
        {
            // Overhead <= 30 bytes, 11 bytes for padding plus rest for OID & encoding
            cbMsg = (UINT32) g_rng.sizet( 0, pBlob->cbModulus - 30 );
        }

        // Special case for OAEP encryption
        if( rnd == 3 )
        {
            // Overhead = 2 + 2 * hashSize
            if( pBlob->cbModulus < 70 )
            {
                strHash = "SHA1";
                cbMsg = (UINT32) g_rng.sizet( 0, pBlob->cbModulus - 42 );
            } else {
                cbMsg = (UINT32) g_rng.sizet( 0, pBlob->cbModulus - 66 );
            }
        }

        // Calling the 'encrypt' function performs encrypt-and-decrypt, which is what we want to do.
        // iprint( "(%d, %d, %d)", pBlob->cbModulus, cbMsg, cbLabel );
        ntStatus = pRsaEnc->encrypt( msg, cbMsg, strHash, (msg + 1), cbLabel, ciph, pBlob->cbModulus  );
        CHECK( NT_SUCCESS( ntStatus ), "Error in RSA encryption validation" );
    }
    CHECK( pRsaEnc->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testRsaEncKats()
{
    // fix this.
    KatData *katRsaEnc = getCustomResource( "kat_RsaEnc.dat", "KAT_RSA_ENC" );
    KAT_ITEM katItem;
    SYMCRYPT_ERROR scError;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<RsaEncMultiImp> pRsaEncMultiImp;

    while( 1 )
    {
        katRsaEnc->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pRsaEncMultiImp.reset( new RsaEncMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pRsaEncMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pRsaEncMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "n" ) )
            {
                BString N = katParseData( katItem, "n" );
                BString e = katParseData( katItem, "e" );
                BString P1 = katParseData( katItem, "p1" );
                BString P2 = katParseData( katItem, "p2" );
                BString Ciphertext = katParseData( katItem, "ciphertext" );
                BString Msg = katParseData( katItem, "msg" );

                BString hashAlg;
                BString Label;

                if( katIsFieldPresent( katItem, "hashalg") )
                {
                    hashAlg = katParseData( katItem, "hashalg" );
                    Label = katParseData( katItem, "label" );
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

                testRsaEncSingle(  pRsaEncMultiImp.get(),
                                    &blob,
                                    Msg.data(), Msg.size(),
                                    hashAlg.size() ? acStringName : NULL,
                                    Label.data(), Label.size(),
                                    Ciphertext.data(), Ciphertext.size(),
                                    katItem.line );
            } else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                testRsaEncTestkeys( pRsaEncMultiImp.get(), (UINT32) katParseInteger( katItem, "rnd" ), katItem.line );
            } else {
                CHECK( FALSE, "Invalid KAT record" );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katRsaEnc;
}

VOID
testRsaEncRaw()
// Corner-case testing for raw encryption
// - test values 0, 1, 2, 3, N-3, N-2, N-1
{
    NTSTATUS ntStatus;

    iprint( "    RsaEncRaw+" );

    std::unique_ptr<RsaEncMultiImp> pRsaEncMultiImp;
    pRsaEncMultiImp.reset( new RsaEncMultiImp( "RsaEncRaw" ) );
    CHECK( pRsaEncMultiImp->m_imps.size() > 0, "No RsaEncRaw impls?" );

    // Choose a random test key
    rsaTestKeysGenerate();
    PCRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ g_rng.uint32() % ARRAY_SIZE( g_RsaTestKeyBlobs ) ];

    pRsaEncMultiImp->setKey( pBlob );

    SIZE_T cbKey = pBlob->cbModulus;

    BYTE abMsg[RSAKEY_MAXKEYSIZE];
    BYTE abCph[RSAKEY_MAXKEYSIZE];
    BYTE abRes[RSAKEY_MAXKEYSIZE];
    SIZE_T cbRes;

    for( int i=-3; i<=3; i++ )
    {
        if( i < 0 )
        {
            memcpy( abMsg, pBlob->abModulus, cbKey );
            // Manual subtraction
            SIZE_T j = cbKey;
            int c = i;
            do {
                j--;
                abMsg[j] = (BYTE)(abMsg[j] + c);
                c = -1;
            } while( abMsg[j] > pBlob->abModulus[j] );
        } else {
            SymCryptWipe( abMsg, cbKey );
            abMsg[cbKey-1] = (BYTE) i;
        }

        ntStatus = pRsaEncMultiImp->encrypt( abMsg, cbKey, NULL, NULL, 0, abCph, cbKey );
        CHECK3( NT_SUCCESS( ntStatus ), "Error encrypting RSA raw corner case %d", i );

        ntStatus = pRsaEncMultiImp->decrypt( abCph, cbKey, NULL, NULL, 0, abRes, cbKey, &cbRes );
        CHECK3( NT_SUCCESS( ntStatus ) && cbRes == cbKey, "Error decrypting RSA raw corner case %d", i );
        CHECK3( memcmp( abMsg, abRes, cbKey ) == 0, "Wrong message decrypt %d", i );

        if( i == 0 || i == 1)
        {
            for( SIZE_T j=0; j<cbKey - 1; j++ )
            {
                CHECK( abCph[j] == 0, "Wrong ciphertext?" );
            }
            CHECK( abCph[cbKey-1] == i, "Wrong ciphertext?" );
        }
    }

    CHECK( pRsaEncMultiImp->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
    iprint( "\n" );
}

VOID
testRsaEncPkcs1Errors()
{
    // We check various PKCS1 padding errors
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_RSAKEY pKey = NULL;

    BYTE paddedData[RSAKEY_MAXKEYSIZE];
    BYTE ciphertext[RSAKEY_MAXKEYSIZE];
    BYTE res[RSAKEY_MAXKEYSIZE];
    SIZE_T cbRes;
    BYTE b;
    UINT32 i;

    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsaRawEncrypt) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsaPkcs1Decrypt) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeyAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeySetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRsakeyFree) )
    {
        print("    skipped\n");
        return;
    }

    // Choose a random test key
    rsaTestKeysGenerate();
    PCRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ g_rng.uint32() % ARRAY_SIZE( g_RsaTestKeyBlobs ) ];

    UINT32 cbitModulus = pBlob->nBitsModulus;
    UINT32 cbModulus = pBlob->cbModulus;

    pKey = rsaKeyFromTestBlob( pBlob );
    CHECK( pKey != NULL, "No 2048-bit test key found" );

    for( i=0; i<sizeof( paddedData ); i++ )
    {
        do {
            paddedData[i] = g_rng.byte();
        } while( paddedData[i] == 0 );
    }

    paddedData[0] = 0;
    paddedData[1] = 2;
    paddedData[cbModulus - 1] = 0;

    scError = ScDispatchSymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_NO_ERROR && cbRes == 0, "?" );

    // Test first byte not zero
    if( cbitModulus % 8 != 1 )
    {
        // Setting the first byte to 1 might now work if the modulus starts with 0x01, 0x00, ...
        paddedData[0]++;
        scError = ScDispatchSymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
        paddedData[0]--;
    }

    // pick random nonzero b
    do{ b = g_rng.byte(); } while( b==0 );

    // Test second byte not 2
    paddedData[1] ^= b;
    scError = ScDispatchSymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
    paddedData[1] ^= b;

    // Test no zero byte
    paddedData[cbModulus - 1] ^= b;
    scError = ScDispatchSymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "?" );
    paddedData[cbModulus - 1] ^= b;

    // Set each subsequent byte to 0 and check result
    for( UINT32 i = 2; i < cbModulus; i++ )
    {
        b = paddedData[ i ];
        paddedData[i] = 0;
        scError = ScDispatchSymCryptRsaRawEncrypt( pKey, paddedData, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, ciphertext, cbModulus );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbModulus, &cbRes );
        if( i <= 9 )
        {
            CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "No error when pkcs1 padding is too short" );
        } else {
            CHECK5( scError == SYMCRYPT_NO_ERROR && cbRes == cbModulus - i - 1, "Wrong length %d %d %d", cbModulus, i, cbRes );

            // Now check for the buffer-too-small error
            scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbRes, &cbRes );
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
            if( cbRes > 0 )
            {
                scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, res, cbRes-1, &cbRes );
                CHECK( scError == SYMCRYPT_BUFFER_TOO_SMALL, "No buffer-too-small error message" );
            }

            cbRes = 1<<30;  // Big value to check that cbRes is actually being written to.
            scError = ScDispatchSymCryptRsaPkcs1Decrypt( pKey, ciphertext, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, nullptr, g_rng.byte(), &cbRes );
            CHECK( scError == SYMCRYPT_NO_ERROR && cbRes == cbModulus - i - 1, "Error when querying PKCS1 decryption length" );
        }

        paddedData[i] = b;
    }

//cleanup:
    if( pKey != NULL )
    {
        ScDispatchSymCryptRsakeyFree( pKey );
        pKey = NULL;
    }
}

VOID
testRsaEncOaep()
// Test many different message & label sizes
{
    NTSTATUS ntStatus;

    iprint( "    RsaEncOaep+" );

    std::unique_ptr<RsaEncMultiImp> pRsaEncMultiImp;
    pRsaEncMultiImp.reset( new RsaEncMultiImp( "RsaEncOaep" ) );
    CHECK( pRsaEncMultiImp->m_imps.size() > 0, "No RsaEncOaep impls?" );

    // Choose a random test key
    rsaTestKeysGenerate();
    PCRSAKEY_TESTBLOB pBlob = &g_RsaTestKeyBlobs[ g_rng.uint32() % ARRAY_SIZE( g_RsaTestKeyBlobs ) ];

    pRsaEncMultiImp->setKey( pBlob );

    SIZE_T cbKey = pBlob->cbModulus;

    BYTE abMsg[RSAKEY_MAXKEYSIZE];
    BYTE abCph[RSAKEY_MAXKEYSIZE];
    BYTE abRes[RSAKEY_MAXKEYSIZE];
    BYTE abLabel[RSAKEY_MAXKEYSIZE];
    SIZE_T cbRes;

    GENRANDOM( abMsg, sizeof( abMsg ) );
    GENRANDOM( abLabel, sizeof( abLabel ) );

    for( int i=0; i<30; i++ )
    {
        UINT32 cbMsg = g_rng.uint32() % cbKey;
        UINT32 cbLabel = g_rng.uint32() % cbKey;

        ntStatus = pRsaEncMultiImp->encrypt( abMsg, cbMsg, "SHA256", abLabel, cbLabel, abCph, cbKey );
        CHECK5( NT_SUCCESS( ntStatus ) == (cbMsg + 66) <= cbKey, "OAEP encryption error %d, %d, %d", cbKey, cbMsg, cbLabel );
        if( NT_SUCCESS( ntStatus ) )
        {
            ntStatus = pRsaEncMultiImp->decrypt( abCph, cbKey, "SHA256", abLabel, cbLabel, abRes, cbKey, &cbRes );
            CHECK( NT_SUCCESS( ntStatus ) && cbRes == cbMsg, "?" );
        }

        ntStatus = pRsaEncMultiImp->encrypt( abMsg, cbMsg, "SHA384", abLabel, cbLabel, abCph, cbKey );
        CHECK5( NT_SUCCESS( ntStatus ) == (cbMsg + 2 + 2*48) <= cbKey, "OAEP encryption error %d, %d, %d", cbKey, cbMsg, cbLabel );
        if( NT_SUCCESS( ntStatus ) )
        {
            ntStatus = pRsaEncMultiImp->decrypt( abCph, cbKey, "SHA384", abLabel, cbLabel, abRes, cbKey, &cbRes );
            CHECK( NT_SUCCESS( ntStatus ) && cbRes == cbMsg, "?" );
        }
    }

    CHECK( pRsaEncMultiImp->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
    iprint( "\n" );

}


VOID
testRsaEncAlgorithms()
{
    String sep;

    // Uncomment this function to generate a new KAT file
    // createKatFileRsaEnc();

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );

    testRsaEncKats();
    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );

    if( isAlgorithmPresent( "RsaEncRaw", FALSE ) )
    {
        testRsaEncRaw();
    }

    if( isAlgorithmPresent( "RsaEncPkcs1", FALSE ) )
    {
        testRsaEncPkcs1Errors();

        if (g_dynamicSymCryptModuleHandle != NULL)
        {
            print("    testRsaEncPkcs1Errors dynamic\n");
            g_useDynamicFunctionsInTestCall = TRUE;
            testRsaEncPkcs1Errors();
            g_useDynamicFunctionsInTestCall = FALSE;
        }
    }

    if( isAlgorithmPresent( "RsaEncOaep", FALSE ) )
    {
        testRsaEncOaep();
    }

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );
}

