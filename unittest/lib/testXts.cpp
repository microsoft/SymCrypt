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
    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey );

    virtual VOID encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    virtual VOID decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    typedef std::vector<XtsImplementation *> XtsImpPtrVector;

    XtsImpPtrVector m_imps;                    // Implementations we use

    XtsImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

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

NTSTATUS XtsMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( XtsImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

VOID
XtsMultiImp::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    BYTE        bufData[1 << 14];
    ResultMerge resData;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        SymCryptWipe( bufData, sizeof( cbData ) );
        (*i)->encrypt( cbDataUnit, tweak, pbSrc, bufData, cbData );
        resData.addResult( (*i), bufData, cbData );
    }
    resData.getResult( pbDst, cbData );
}

VOID
XtsMultiImp::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    BYTE        bufData[1 << 14];
    ResultMerge resData;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );
    for( XtsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        SymCryptWipe( bufData, sizeof( cbData ) );
        (*i)->decrypt( cbDataUnit, tweak, pbSrc, bufData, cbData );
        resData.addResult( (*i), bufData, cbData );
    }
    resData.getResult( pbDst, cbData );
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

    CHECK( pImp->setKey( pbKey, cbKey ) == 0, "Error in setting key" );
    CHECK3( (cbDataUnit & (cbDataUnit - 1) ) == 0, "Data unit size is not a power of 2 in line %lld", line );

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
    *(ULONGLONG SYMCRYPT_UNALIGNED *)&buf1[algNameSize] = keyLen;
    rng.reset( buf1, algNameSize + sizeof( ULONGLONG ) );

    const SIZE_T bufSize = sizeof( buf1 );
    CHECK( bufSize > keyLen, "?" );

    memset( buf1, 0, sizeof( buf1 ) );

    SIZE_T keyIdx = 0;

    for( int i=0; i<rrep; i++ )
    {
        keyIdx = rng.sizet( bufSize - keyLen );

        // iprint( "Eff key size = %d\n", g_rc2EffectiveKeyLength );
        CHECK3( NT_SUCCESS( pImp->setKey( &buf1[keyIdx], keyLen ) ), "Key setting failure, line %lld", line );

        SIZE_T cbDataUnit = SYMCRYPT_AES_BLOCK_SIZE + (rng.sizet( 8192 ) & ~(SYMCRYPT_AES_BLOCK_SIZE - 1));     // Random size, 16 - 8192 bytes in multiples of 16
        CHECK( cbDataUnit < bufSize, "Data unit size too large" );
        SIZE_T maxDataUnits = bufSize / cbDataUnit;
        SIZE_T nDataUnits = rng.sizet( maxDataUnits + 1 );
        SIZE_T cbData = nDataUnits * cbDataUnit;

        CHECK( cbData <= bufSize, "?" );

        //
        // Pick a tweak not too far from a power of two, as that tests various
        // overflows in the increment operation.
        // Overflow from -1 to 0 is tested from the tweak=1 starting point.
        //
        ULONGLONG tweak = 1ULL << rng.sizet( 64 );
        tweak += (ULONGLONG)rng.sizet( 1 + 4 * nDataUnits ) - 2 * nDataUnits;   // cast to ensure we do the offset computation in 64 bits, not in 32 bits.

        PBYTE pbData = &buf1[rng.sizet( bufSize - cbData + 1 ) ];

        pImp->encrypt( cbDataUnit, tweak, pbData, buf2, cbData );
        pImp->decrypt( cbDataUnit, tweak, buf2, buf3, cbData );
        CHECK3( memcmp( buf3, pbData, cbData ) == 0, "Encrypt/Decrypt mismatch, line %lld", line );

        if( nDataUnits > 1 )
        {
            for( int i=0; i<5; i++ )
            {
                //
                // Pick a subset of the big request and check the encrypt/decrypt
                //
                SIZE_T nSubUnits = rng.sizet( nDataUnits );
                SIZE_T cbSubUnits = nSubUnits * cbDataUnit;
                SIZE_T unitOffset = rng.sizet( nDataUnits - nSubUnits + 1 );
                SIZE_T cbOffset = unitOffset * cbDataUnit;
                CHECK( unitOffset + nSubUnits <= nDataUnits, "?" );

                pImp->encrypt( cbDataUnit, tweak + unitOffset, pbData + cbOffset, buf3, cbSubUnits );
                CHECK3( memcmp( buf3, &buf2[cbOffset], cbSubUnits ) == 0, "Partial encrypt mismatch, line %lld", line );

                pImp->decrypt( cbDataUnit, tweak + unitOffset, buf2 + cbOffset, buf3, cbSubUnits );
                CHECK3( memcmp( buf3, &pbData[cbOffset], cbSubUnits ) == 0, "Partial decrypt mismatch, line %lld", line );
            }
        }

        memcpy( pbData, buf2, cbData );
    }

    SymCryptSha256( buf1, bufSize, buf2 );
    if( memcmp( buf2, pbResult, cbResult ) != 0 )
    {
        print( "Wrong xts result in line %lld. \n"
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



