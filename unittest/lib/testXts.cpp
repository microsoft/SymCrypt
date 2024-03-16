//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

class XtsMultiImp: public XtsImplementation
{
public:
    XtsMultiImp( String algName );
    ~XtsMultiImp();

private:
    XtsMultiImp( const XtsMultiImp & );
    VOID operator=( const XtsMultiImp & );

public:
    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey, UINT32 flags );

    virtual NTSTATUS encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    virtual NTSTATUS decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    virtual NTSTATUS encryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData );

    virtual NTSTATUS decryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData );


    typedef std::vector<XtsImplementation *> XtsImpPtrVector;

    XtsImpPtrVector m_imps;                    // Implementations we use

    XtsImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    bool m_operateInPlace;
};

XtsMultiImp::XtsMultiImp( String algName )
{
    getAllImplementations<XtsImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( XtsImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";

    m_operateInPlace = false;
}

XtsMultiImp::~XtsMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( XtsImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

NTSTATUS XtsMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey, UINT32 flags )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( XtsImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey, flags ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
XtsMultiImp::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    NTSTATUS    status = STATUS_SUCCESS;
    NTSTATUS    res;
    BYTE        bufData[(1 << 14) + 1];
    ResultMerge resData;
    PCBYTE      pbInternalSrc;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );

    res = STATUS_UNSUCCESSFUL;
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1);
        if( m_operateInPlace )
        {
            memcpy(bufData, pbSrc, cbData);
            pbInternalSrc = bufData;
        } else {
            pbInternalSrc = pbSrc;
        }
        status = (*i)->encrypt( cbDataUnit, tweak, pbInternalSrc, bufData, cbData );
        CHECK( bufData[cbData] == 'd', "?" );
        if( NT_SUCCESS( status ) )
        {
            resData.addResult( (*i), bufData, cbData );
            res = STATUS_SUCCESS;   // At least one implementation liked it.
        }
    }
    resData.getResult( pbDst, cbData );

    return res;
}

NTSTATUS
XtsMultiImp::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    NTSTATUS    status = STATUS_SUCCESS;
    NTSTATUS    res;
    BYTE        bufData[(1 << 14) + 1];
    ResultMerge resData;
    PCBYTE      pbInternalSrc;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );

    res = STATUS_UNSUCCESSFUL;
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1);
        if( m_operateInPlace )
        {
            memcpy(bufData, pbSrc, cbData);
            pbInternalSrc = bufData;
        } else {
            pbInternalSrc = pbSrc;
        }
        status = (*i)->decrypt( cbDataUnit, tweak, pbInternalSrc, bufData, cbData );
        CHECK( bufData[cbData] == 'd', "?" );
        if( NT_SUCCESS( status ) )
        {
            resData.addResult( (*i), bufData, cbData );
            res = STATUS_SUCCESS;   // At least one implementation liked it.
        }
    }
    resData.getResult( pbDst, cbData );

    return res;
}

NTSTATUS
XtsMultiImp::encryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData )
{
    NTSTATUS    status = STATUS_SUCCESS;
    NTSTATUS    res;
    BYTE        bufData[(1 << 14) + 1];
    ResultMerge resData;
    PCBYTE      pbInternalSrc;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );

    res = STATUS_UNSUCCESSFUL;
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1);
        if( m_operateInPlace )
        {
            memcpy(bufData, pbSrc, cbData);
            pbInternalSrc = bufData;
        } else {
            pbInternalSrc = pbSrc;
        }
        status = (*i)->encryptWith128bTweak( cbDataUnit, pbTweak, pbInternalSrc, bufData, cbData );
        CHECK( bufData[cbData] == 'd', "?" );
        if( status != STATUS_NOT_SUPPORTED )
        {
            resData.addResult( (*i), bufData, cbData );
            res = STATUS_SUCCESS;   // At least one implementation liked it.
        }
    }
    resData.getResult( pbDst, cbData );

    return res;
}

NTSTATUS
XtsMultiImp::decryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData )
{
    NTSTATUS    status = STATUS_SUCCESS;
    NTSTATUS    res;
    BYTE        bufData[(1 << 14) + 1];
    ResultMerge resData;
    PCBYTE      pbInternalSrc;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );

    res = STATUS_UNSUCCESSFUL;
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1);
        if( m_operateInPlace )
        {
            memcpy(bufData, pbSrc, cbData);
            pbInternalSrc = bufData;
        } else {
            pbInternalSrc = pbSrc;
        }
        status = (*i)->decryptWith128bTweak( cbDataUnit, pbTweak, pbInternalSrc, bufData, cbData );
        CHECK( bufData[cbData] == 'd', "?" );
        if( status != STATUS_NOT_SUPPORTED )
        {
            resData.addResult( (*i), bufData, cbData );
            res = STATUS_SUCCESS;   // At least one implementation liked it.
        }
    }
    resData.getResult( pbDst, cbData );

    return res;
}

VOID
katXtsSingle(
                                XtsMultiImp               * pImp,
    _In_reads_( cbKey )         PCBYTE                      pbKey,
                                SIZE_T                      cbKey,
                                ULONGLONG                   cbDataUnit,
                                ULONGLONG                   tweak,
    _In_reads_( cbPlaintext )   PCBYTE                      pbPlaintext,
                                SIZE_T                      cbPlaintext,
    _In_reads_( cbCiphertext )  PCBYTE                      pbCiphertext,
                                SIZE_T                      cbCiphertext,
                                ULONGLONG                   line)
{
    BYTE bufData[512];

    CHECK3( cbPlaintext <= sizeof( bufData ), "Buffer too small, need %lld bytes", cbPlaintext );
    CHECK3( cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line );
    CHECK3( cbDataUnit <= (1 << 16), "cbDataUnit too large in line %lld", line )

    CHECK( pImp->setKey( pbKey, cbKey, SYMCRYPT_FLAG_KEY_NO_FIPS ) == 0, "Error in setting key" );

    //
    // Do single encryption
    //
    memset( bufData, 0, sizeof( bufData ) );
    pImp->encrypt( (SIZE_T) cbDataUnit, tweak, pbPlaintext, bufData, cbPlaintext );
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext mismatch in line %lld", line );

    //
    // We don't do piece-wise encryption/decryption here; we do that in the random test.
    //

    //
    // Do single decryption
    //

    memset( bufData, 0, sizeof( bufData ) );
    pImp->decrypt( (SIZE_T) cbDataUnit, tweak, pbCiphertext, bufData, cbCiphertext );
    CHECK3( memcmp( bufData, pbPlaintext, cbCiphertext ) == 0, "Plaintext mismatch in line %lld", line );

}


VOID
testXtsRandom( XtsMultiImp * pImp, int rrep, SIZE_T keyLen, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line )
{
    BYTE buf1[ 1 << 14  ];
    BYTE buf2[ sizeof( buf1 ) ];
    BYTE buf3[ sizeof( buf1 ) ];

    Rng rng;

    //
    // Seed our RNG with the algorithm name and key size
    //
    SIZE_T algNameSize = pImp->m_algorithmName.size();
    CHECK( algNameSize < sizeof( buf1 ) - sizeof( ULONGLONG ), "Algorithm name too long" );
    memcpy( buf1, pImp->m_algorithmName.data(), algNameSize );
    SYMCRYPT_STORE_LSBFIRST64(&buf1[algNameSize], keyLen);
    rng.reset( buf1, algNameSize + sizeof( ULONGLONG ) );

    const SIZE_T bufSize = sizeof( buf1 );
    CHECK( bufSize > keyLen, "?" );

    memset( buf1, 0, sizeof( buf1 ) );

    SIZE_T keyIdx = 0;

    for( int i=0; i<rrep; i++ )
    {
        keyIdx = rng.sizet( bufSize - keyLen );

        CHECK3( pImp->setKey( &buf1[keyIdx], keyLen, SYMCRYPT_FLAG_KEY_NO_FIPS ) == 0, "Key setting failure, line %lld", line );

        SIZE_T cbDataUnit = SYMCRYPT_AES_BLOCK_SIZE + rng.sizet( 8192 );     // Random size, 16 - 8207 bytes
        CHECK( cbDataUnit < bufSize, "Data unit size too large" );
        SIZE_T maxDataUnits = bufSize / cbDataUnit;
        SIZE_T nDataUnits = rng.sizet( maxDataUnits + 1 );
        SIZE_T cbData = nDataUnits * cbDataUnit;

        CHECK( cbData <= bufSize, "?" );

        PBYTE pbData = &buf1[rng.sizet( bufSize - cbData + 1 )];

        //
        // Pick a tweak not too far from a power of two, as that tests various
        // overflows in the increment operation.
        // Overflow from -1 to 0 is tested from the tweak=1 starting point.
        //
        // 3/4s of the time test the 64-b tweak API, 1/4 of the time test the 128-b tweak API
        if( rng.byte() & 3 )
        {
            ULONGLONG tweak = 1ULL << rng.sizet( 64 );
            tweak += (ULONGLONG)rng.sizet( 1 + 4 * nDataUnits ) - 2 * nDataUnits;   // cast to ensure we do the offset computation in 64 bits, not in 32 bits.

            CHECK3( NT_SUCCESS( pImp->encrypt( cbDataUnit, tweak, pbData, buf2, cbData ) ), "Encrypt failure, line %lld", line );
            CHECK3( NT_SUCCESS( pImp->decrypt( cbDataUnit, tweak, buf2, buf3, cbData ) ),   "Decrypt failure, line %lld", line );
            CHECK3( memcmp( buf3, pbData, cbData ) == 0, "Encrypt/Decrypt mismatch, line %lld", line );

            pImp->m_operateInPlace = true;
            CHECK3( NT_SUCCESS( pImp->encrypt( cbDataUnit, tweak, buf3, buf3, cbData ) ), "In-place encrypt failure, line %lld", line );
            CHECK3( memcmp( buf3, buf2, cbData ) == 0, "In-place/Out-of-place Encrypt mismatch, line %lld", line );

            CHECK3( NT_SUCCESS( pImp->decrypt( cbDataUnit, tweak, buf3, buf3, cbData ) ), "In-place decrypt failure, line %lld", line );
            CHECK3( memcmp( buf3, pbData, cbData ) == 0, "In-place Encrypt/Decrypt mismatch, line %lld", line );
            pImp->m_operateInPlace = false;

            if( nDataUnits > 1 )
            {
                for( int j=0; j<5; j++ )
                {
                    //
                    // Pick a subset of the big request and check the encrypt/decrypt
                    //
                    SIZE_T nSubUnits = rng.sizet( nDataUnits );
                    SIZE_T cbSubUnits = nSubUnits * cbDataUnit;
                    SIZE_T unitOffset = rng.sizet( nDataUnits - nSubUnits + 1 );
                    SIZE_T cbOffset = unitOffset * cbDataUnit;
                    CHECK( unitOffset + nSubUnits <= nDataUnits, "?" );

                    CHECK3( NT_SUCCESS( pImp->encrypt( cbDataUnit, tweak + unitOffset, pbData + cbOffset, buf3, cbSubUnits ) ), "Encrypt failure, line %lld", line );
                    CHECK3( memcmp( buf3, &buf2[cbOffset], cbSubUnits ) == 0, "Partial Encrypt mismatch, line %lld", line );

                    CHECK3( NT_SUCCESS( pImp->decrypt( cbDataUnit, tweak + unitOffset, buf2 + cbOffset, buf3, cbSubUnits ) ), "Decrypt failure, line %lld", line );
                    CHECK3( memcmp( buf3, &pbData[cbOffset], cbSubUnits ) == 0, "Partial Decrypt mismatch, line %lld", line );
                }
            }
        } else {
            UINT64 tweakPower = rng.sizet(128);
            UINT64 tweakLow = 1ULL << (tweakPower & 63);
            UINT64 tweakHigh = 0;

            if( tweakPower & 64 )
            {
                tweakHigh = tweakLow;
                tweakLow = 0;
            }

            tweakLow += (UINT64)rng.sizet( 1 + 4 * nDataUnits ) - 2 * nDataUnits;   // cast to ensure we do the offset computation in 64 bits, not in 32 bits.
            if( (INT64)tweakLow < 0 )
            {
                tweakHigh--;
            }

            BYTE tweak[SYMCRYPT_AES_BLOCK_SIZE];
            SYMCRYPT_STORE_LSBFIRST64( &tweak[0], tweakLow );
            SYMCRYPT_STORE_LSBFIRST64( &tweak[8], tweakHigh );

            CHECK3( NT_SUCCESS( pImp->encryptWith128bTweak( cbDataUnit, &tweak[0], pbData, buf2, cbData ) ), "EncryptWith128bTweak failure, line %lld", line );
            CHECK3( NT_SUCCESS( pImp->decryptWith128bTweak( cbDataUnit, &tweak[0], buf2, buf3, cbData ) ),   "DecryptWith128bTweak failure, line %lld", line );
            CHECK3( memcmp( buf3, pbData, cbData ) == 0, "EncryptWith128bTweak/DecryptWith128bTweak mismatch, line %lld", line );

            pImp->m_operateInPlace = true;
            CHECK3( NT_SUCCESS( pImp->encryptWith128bTweak( cbDataUnit, tweak, buf3, buf3, cbData ) ), "In-place encrypt failure, line %lld", line );
            CHECK3( memcmp( buf3, buf2, cbData ) == 0, "In-place/Out-of-place EncryptWith128bTweak mismatch, line %lld", line );

            CHECK3( NT_SUCCESS( pImp->decryptWith128bTweak( cbDataUnit, tweak, buf3, buf3, cbData ) ), "In-place decrypt failure, line %lld", line );
            CHECK3( memcmp( buf3, pbData, cbData ) == 0, "In-place EncryptWith128bTweak/DecryptWith128bTweak mismatch, line %lld", line );
            pImp->m_operateInPlace = false;

            if( nDataUnits > 1 )
            {
                for( int k=0; k<5; k++ )
                {
                    //
                    // Pick a subset of the big request and check the encrypt/decrypt
                    //
                    SIZE_T nSubUnits = rng.sizet( nDataUnits );
                    SIZE_T cbSubUnits = nSubUnits * cbDataUnit;
                    SIZE_T unitOffset = rng.sizet( nDataUnits - nSubUnits + 1 );
                    SIZE_T cbOffset = unitOffset * cbDataUnit;
                    CHECK( unitOffset + nSubUnits <= nDataUnits, "?" );

                    SYMCRYPT_STORE_LSBFIRST64( &tweak[0], tweakLow + unitOffset);
                    SYMCRYPT_STORE_LSBFIRST64( &tweak[8], tweakHigh + (((tweakLow + unitOffset) < tweakLow) ? 1 : 0) );

                    CHECK3( NT_SUCCESS( pImp->encryptWith128bTweak( cbDataUnit, &tweak[0], pbData + cbOffset, buf3, cbSubUnits ) ), "EncryptWith128bTweak failure, line %lld", line );
                    CHECK3( memcmp( buf3, &buf2[cbOffset], cbSubUnits ) == 0, "Partial EncryptWith128bTweak mismatch, line %lld", line );

                    CHECK3( NT_SUCCESS( pImp->decryptWith128bTweak( cbDataUnit, &tweak[0], buf2 + cbOffset, buf3, cbSubUnits ) ), "DecryptWith128bTweak failure, line %lld", line );
                    CHECK3( memcmp( buf3, &pbData[cbOffset], cbSubUnits ) == 0, "Partial DecryptWith128bTweak mismatch, line %lld", line );
                }
            }
        }

        memcpy( pbData, buf2, cbData );
    }

    SymCryptSha256( buf1, bufSize, buf2 );
    if( memcmp( buf2, pbResult, cbResult ) != 0 )
    {
        print( "\nWrong xts result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( buf2, cbResult );
        iprint( "\n" );
        pImp->m_nErrorKatFailure++;
    }
}



VOID
testXtsKats()
{
    std::unique_ptr<KatData> katXts( getCustomResource( "kat_xts.dat", "KAT_XTS" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<XtsMultiImp> pXtsMultiImp;

    while( 1 )
    {
        katXts->getKatItem( & katItem );
        ULONGLONG line = katItem.line;

        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pXtsMultiImp.reset( new XtsMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pXtsMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "ciphertext" ) )
            {

                BString katKey = katParseData( katItem, "key" );
                BString katPlaintext = katParseData( katItem, "plaintext" );
                BString katCiphertext = katParseData( katItem, "ciphertext" );
                ULONGLONG tweak = katParseInteger( katItem, "tweak" );

                katXtsSingle(   pXtsMultiImp.get(),
                                katKey.data(), katKey.size(),
                                katPlaintext.size(),
                                tweak,
                                katPlaintext.data(), katPlaintext.size(),
                                katCiphertext.data(), katCiphertext.size(),
                                line );
            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() <= 4, "Wrong # items in RND record ending at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                SIZE_T keyLen = (SIZE_T) katParseInteger( katItem, "keylen" );
                BString katRnd = katParseData( katItem, "rnd" );
                testXtsRandom( pXtsMultiImp.get(), rrep, keyLen, katRnd.data(), katRnd.size(), line );
            } else
            {
                FATAL2( "Unknown data record ending at line %lld", line );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

VOID
testXtsAlgorithms()
{
    testXtsKats();
}



