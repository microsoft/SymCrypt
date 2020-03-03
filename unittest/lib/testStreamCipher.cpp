//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

class StreamCipherMultiImp: public StreamCipherImplementation
{
public:
    StreamCipherMultiImp( String algName );
    ~StreamCipherMultiImp();

private:
    StreamCipherMultiImp( const StreamCipherMultiImp & );
    VOID operator=( const StreamCipherMultiImp & );

public:
    virtual std::set<SIZE_T> getNonceSizes();

    virtual std::set<SIZE_T> getKeySizes();

    virtual NTSTATUS setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey );

    virtual NTSTATUS setNonce( _In_reads_( cbKey ) PCBYTE pbNonce, SIZE_T cbNonce );

    virtual BOOL isRandomAccess();

    virtual VOID setOffset( UINT64 offset );

    virtual VOID encrypt(
        _In_reads_( cbData )    PCBYTE  pbSrc,
        _Out_writes_( cbData )  PBYTE   pbDst,
                                SIZE_T  cbData );

    typedef std::vector<StreamCipherImplementation *> StreamCipherImpPtrVector;

    StreamCipherImpPtrVector m_imps;                    // Implementations we use

    StreamCipherImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations
};

StreamCipherMultiImp::StreamCipherMultiImp( String algName )
{
    getAllImplementations<StreamCipherImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( StreamCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

StreamCipherMultiImp::~StreamCipherMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( StreamCipherImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

std::set<SIZE_T> StreamCipherMultiImp::getNonceSizes()
{
    std::set<SIZE_T> res;
    for( StreamCipherImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getNonceSizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

std::set<SIZE_T> StreamCipherMultiImp::getKeySizes()
{
    std::set<SIZE_T> res;
    for( StreamCipherImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getKeySizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

NTSTATUS StreamCipherMultiImp::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    for( StreamCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); i++ )
    {
        CHECK( NT_SUCCESS((*i)->setNonce( pbNonce, cbNonce ) ), "SetNonce failure" );
    }
    return STATUS_SUCCESS;
}

NTSTATUS StreamCipherMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( StreamCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

BOOL StreamCipherMultiImp::isRandomAccess()
{
    ResultMerge res;
    BOOL b;

    for( StreamCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        b = (*i)->isRandomAccess() != 0;
        res.addResult( (*i), (PCBYTE) &b, sizeof( b ) );
    }

    res.getResult( (PBYTE)&b, sizeof( b ), FALSE );

    return b;
}

VOID StreamCipherMultiImp::setOffset( UINT64 offset )
{
    for( StreamCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->setOffset( offset );
    }
}

VOID
StreamCipherMultiImp::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    BYTE bufData[1024];
    ResultMerge resData;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );

    for( StreamCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        SymCryptWipe( bufData, cbData );
        (*i)->encrypt( pbSrc, bufData, cbData );
        resData.addResult( (*i), bufData, cbData );
    }

    resData.getResult( pbDst, cbData );
}


VOID
katStreamCipherSingle(
                                StreamCipherImplementation * pImp,
    _In_reads_( cbKey )         PCBYTE                      pbKey,
                                SIZE_T                      cbKey,
    _In_reads_( cbNonce )       PCBYTE                      pbNonce,
                                SIZE_T                      cbNonce,
                                UINT64                      offset,
    _In_reads_( cbPlaintext )   PCBYTE                      pbPlaintext,
                                SIZE_T                      cbPlaintext,
    _In_reads_( cbCiphertext )  PCBYTE                      pbCiphertext,
                                SIZE_T                      cbCiphertext,
                                ULONGLONG                   line)
{
    BYTE bufData[512];

    CHECK3( cbPlaintext < sizeof( bufData ), "Buffer too small, need %lld bytes", cbPlaintext );
    CHECK3( cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line );

    CHECK( pImp->setKey( pbKey, cbKey ) == 0, "Error in setting key" );
    CHECK( pImp->setNonce( pbNonce, cbNonce ) == 0, "Error setting nonce" );
    if( offset != 0 )
    {
        pImp->setOffset( offset );
    }

    //
    // Do single encryption
    //
    memset( bufData, 0, sizeof( bufData ) );

    pImp->encrypt( pbPlaintext, bufData, cbPlaintext );
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext mismatch in line %lld", line );

    //
    // Do encryption piecewise
    //
    CHECK( pImp->setKey( pbKey, cbKey ) == 0, "Error in setting key 2" );
    CHECK( pImp->setNonce( pbNonce, cbNonce ) == 0, "Error setting nonce 2" );
    if( offset != 0 )
    {
        pImp->setOffset( offset );
    }

    memset( bufData, 0, sizeof( bufData ) );
    SIZE_T pos = 0;
    while( pos < cbPlaintext )
    {
        SIZE_T nBytes = g_rng.sizetNonUniform( (cbPlaintext - pos) + 1, 4, 1 );
        pImp->encrypt( pbPlaintext + pos, bufData + pos, nBytes );
        pos += nBytes;
    }
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext 2 mismatch in line %lld", line );

    //
    // Do random-access checks
    //
    if( pImp->isRandomAccess() )
    {
        for( int i=0; i<10; i++ )
        {
            SIZE_T cbBytes = g_rng.sizet( cbPlaintext + 1 );    // 0 .. cbPlaintext
            SIZE_T pos = g_rng.sizet( cbPlaintext - cbBytes + 1 );  // 0 .. cbPlaintext - cbBytes
            pImp->setOffset( offset + pos );
            pImp->encrypt( pbPlaintext + pos, bufData, cbBytes );
            CHECK3( memcmp( bufData, pbCiphertext + pos, cbBytes ) == 0, "Partial ciphertext mismatch in line %lld", line );
        }
    }
}

int SYMCRYPT_CDECL compareSizet( const VOID * p1, const VOID * p2 )
{
    SIZE_T v1 = *(SIZE_T *)p1;
    SIZE_T v2 = *(SIZE_T *)p2;

    if( v1 < v2 ) return -1;
    if( v1 == v2 ) return 0;
    return 1;
}

VOID
testStreamCipherRandom( StreamCipherMultiImp * pImp, int rrep, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line )
{
    BYTE buf[ 1024 ];
    BYTE resBuf[16];
    SIZE_T keySize[256];
    SIZE_T nonceSize[256];
    SIZE_T i;
    Rng rng;

    //
    // Seed our RNG with the algorithm name
    //
    SIZE_T algNameSize = pImp->m_algorithmName.size();
    CHECK( algNameSize < sizeof( buf ) - sizeof( ULONGLONG ), "Algorithm name too long" );
    memcpy( buf, pImp->m_algorithmName.data(), algNameSize );
    rng.reset( buf, algNameSize );

    const SIZE_T bufSize = sizeof( buf );

    memset( buf, 0, bufSize );

    std::set<SIZE_T> keySizeSet = pImp->getKeySizes();
    std::set<SIZE_T> nonceSizeSet = pImp->getNonceSizes();

    SIZE_T  nKeySizes = keySizeSet.size();
    SIZE_T  nNonceSizes = nonceSizeSet.size();

    CHECK( nKeySizes <= ARRAY_SIZE( keySize ), "Too many key sizes" );
    CHECK( nNonceSizes <= ARRAY_SIZE( nonceSize ), "Too many nonce sizes" );

    i = 0;
    for( std::set<SIZE_T>::iterator it = keySizeSet.begin(); it != keySizeSet.end(); it++ )
    {
        keySize[i++] = *it;
    }
    CHECK( i == nKeySizes, "?" );

    i = 0;
    for( std::set<SIZE_T>::iterator it = nonceSizeSet.begin(); it != nonceSizeSet.end(); it++ )
    {
        nonceSize[i++] = *it;
    }
    CHECK( i == nNonceSizes, "?" );

    // sort the arrays so that our results are deterministic
    qsort( keySize, nKeySizes, sizeof( SIZE_T ), &compareSizet );
    qsort( nonceSize, nNonceSizes, sizeof( SIZE_T ), &compareSizet );

    SIZE_T keyIdx = 0;
    SIZE_T nPieces;
    SIZE_T pos;
    SIZE_T len;
    SIZE_T bytes = 0;
    SIZE_T keyLen;
    SIZE_T nonceLen;
    SIZE_T nonceIdx;

    for( int i=0; i<rrep; i++ )
    {
        keyLen = keySize[ rng.sizet( nKeySizes ) ];
        keyIdx = rng.sizet( bufSize - keyLen );

        CHECK3( NT_SUCCESS( pImp->setKey( &buf[keyIdx], keyLen ) ), "Key setting failure, line %lld", line );

        if( nNonceSizes > 0 )
        {
            nonceLen = nonceSize[ rng.sizet( nNonceSizes ) ];
            nonceIdx = rng.sizet( bufSize - nonceLen );
            CHECK3( NT_SUCCESS( pImp->setNonce( &buf[nonceIdx], nonceLen ) ), "Nonce setting failure, line %lld", line )
        }

        //
        // The next byte is the # appends that we will do; 0 appends means we call the
        // hash function directly without init/append/result.
        //
        nPieces = rng.byte();
        nPieces = 1 + nPieces % 5;

        for( SIZE_T j=0; j<nPieces; j++ )
        {
            rng.randomSubRange( bufSize, &pos, &len );
            if( pImp->isRandomAccess() )
            {
                pImp->setOffset( rng.sizet( 1 << 12 ) );
            }
            pImp->encrypt( &buf[pos], &buf[pos], len );
            bytes += len;
        }
    }

    memset( resBuf, 0, sizeof( resBuf ) );
    for( SIZE_T i=0; i<bufSize; i++ )
    {
        resBuf[ i % sizeof( resBuf ) ]  ^= buf[i];
    }

    CHECK3( cbResult == sizeof( resBuf ), "Result size is wrong in line %lld", line );
    if( memcmp( resBuf, pbResult, sizeof( resBuf ) ) != 0 )
    {
        print( "\nWrong stream cipher result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( resBuf, cbResult );
        iprint( "\n" );

        pImp->m_nErrorKatFailure++;
    }
}



VOID
testStreamCipherKats()
{
    std::unique_ptr<KatData> katStreamCipher( getCustomResource( "kat_streamcipher.dat", "KAT_STREAM_CIPHER" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;
    UINT64 offset;

    std::unique_ptr<StreamCipherMultiImp> pStreamCipherMultiImp;


    while( 1 )
    {
        katStreamCipher->getKatItem( & katItem );
        ULONGLONG line = katItem.line;


        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pStreamCipherMultiImp.reset( new StreamCipherMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pStreamCipherMultiImp->m_imps.size() == 0);
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
                BString katNonce;
                PCBYTE pbNonce = NULL;
                SIZE_T cbNonce = 0;

                if( katIsFieldPresent( katItem, "nonce" ) )
                {
                    katNonce = katParseData( katItem, "nonce" );
                    pbNonce = katNonce.data();
                    cbNonce = katNonce.size();
                }

                offset = 0;
                if( katIsFieldPresent( katItem, "offset" ) )
                {
                    offset = katParseInteger( katItem, "offset" );
                }

                katStreamCipherSingle(  pStreamCipherMultiImp.get(),
                                        katKey.data(), katKey.size(),
                                        pbNonce, cbNonce,
                                        offset,
                                        katPlaintext.data(), katPlaintext.size(),
                                        katCiphertext.data(), katCiphertext.size(),
                                        line );

            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() == 2, "Wrong # items in RND record ending at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                BString katRnd = katParseData( katItem, "rnd" );
                testStreamCipherRandom( pStreamCipherMultiImp.get(), rrep, katRnd.data(), katRnd.size(), line );
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
testStreamCipherAlgorithms()
{
    testStreamCipherKats();
}




