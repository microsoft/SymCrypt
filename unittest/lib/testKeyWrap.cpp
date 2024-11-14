//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

class KeyWrapMultiImp: public KeyWrapImplementation
{
public:
    KeyWrapMultiImp( String algName );
    ~KeyWrapMultiImp();

private:
    KeyWrapMultiImp( const KeyWrapMultiImp & );
    VOID operator=( const KeyWrapMultiImp & );

public:
    virtual SIZE_T getMinPlaintextSize();
    virtual SIZE_T getMaxPlaintextSize();
    virtual SIZE_T getPlaintextSizeIncrement();
    virtual std::set<SIZE_T> getKeySizes();

    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey );
    virtual NTSTATUS encrypt( PCBYTE pbSrc, SIZE_T cbSrc, PBYTE pbDst, SIZE_T cbDst, SIZE_T* pcbResult );
    virtual NTSTATUS decrypt( PCBYTE pbSrc, SIZE_T cbSrc, PBYTE pbDst, SIZE_T cbDst, SIZE_T* pcbResult );

    typedef std::vector<KeyWrapImplementation *> KeyWrapMultiImptrVector;

    KeyWrapMultiImptrVector m_imps;     // Implementations we use

    KeyWrapMultiImptrVector m_comps;    // Subset of m_imps; set of ongoing computations

};

KeyWrapMultiImp::KeyWrapMultiImp( String algName )
{
    getAllImplementations<KeyWrapImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

KeyWrapMultiImp::~KeyWrapMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( KeyWrapMultiImptrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


SIZE_T KeyWrapMultiImp::getMinPlaintextSize()
{
    SIZE_T res = (SIZE_T) -1;
    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->getMinPlaintextSize();
        CHECK( res == (SIZE_T) -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T KeyWrapMultiImp::getMaxPlaintextSize()
{
    SIZE_T res = (SIZE_T) -1;
    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->getMaxPlaintextSize();
        CHECK( res == (SIZE_T) -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T KeyWrapMultiImp::getPlaintextSizeIncrement()
{
    SIZE_T res = (SIZE_T) -1;
    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->getPlaintextSizeIncrement();
        CHECK( res == (SIZE_T) -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

std::set<SIZE_T> KeyWrapMultiImp::getKeySizes()
{
    std::set<SIZE_T> res;
    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getKeySizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

NTSTATUS KeyWrapMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( KeyWrapMultiImptrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
KeyWrapMultiImp::encrypt( PCBYTE pbSrc, SIZE_T cbSrc, PBYTE pbDst, SIZE_T cbDst, SIZE_T* pcbResult )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS res = STATUS_UNSUCCESSFUL;
    BYTE bufData[1024];
    ResultMerge resData;
    SIZE_T cbResult = 0;

    CHECK( cbDst < sizeof( bufData ), "Buffer too small" );

    for( KeyWrapMultiImptrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbDst + 1 );
        status = (*i)->encrypt( pbSrc, cbSrc, bufData, cbDst, &cbResult );
        CHECK( bufData[cbDst] == 'd', "?" );
        if( NT_SUCCESS( status ) )
        {
            resData.addResult( (*i), bufData, cbResult );
            res = STATUS_SUCCESS;   // At least one implementation liked it.
        }
    }

    resData.getResult( pbDst, cbResult );
    *pcbResult = cbResult;

    return res;
}

NTSTATUS
KeyWrapMultiImp::decrypt( PCBYTE pbSrc, SIZE_T cbSrc, PBYTE pbDst, SIZE_T cbDst, SIZE_T* pcbResult )
{
    NTSTATUS status = STATUS_SUCCESS;
    BYTE bufData[1024];
    BYTE statusBuf[4];
    ResultMerge resStatus;
    ResultMerge resData;
    SIZE_T cbResult = 0;

    CHECK( cbDst < sizeof( bufData ), "Buffer too small" );

    for( KeyWrapMultiImptrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbDst + 1 );
        status = (*i)->decrypt( pbSrc, cbSrc, bufData, cbDst, &cbResult );
        CHECK( bufData[cbDst] == 'd', "?" );
        if( status == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        SYMCRYPT_STORE_LSBFIRST32( statusBuf, status );
        resStatus.addResult( (*i), statusBuf, sizeof(statusBuf) );
        resData.addResult( (*i), bufData, cbResult );
    }

    resStatus.getResult( statusBuf, sizeof( statusBuf ) );
    status = SYMCRYPT_LOAD_LSBFIRST32( statusBuf );

    if( NT_SUCCESS( status ) )
    {
        CHECK( cbResult <= cbDst, "Buffer too small" );
        resData.getResult( pbDst, cbResult, FALSE );
        *pcbResult = cbResult;
    }

    return status;
}


VOID
katKeyWrapSingle(
                                KeyWrapImplementation * pImp,
    _In_reads_( cbKey )         PCBYTE                  pbKey,
                                SIZE_T                  cbKey,
    _In_reads_( cbPlaintext )   PCBYTE                  pbPlaintext,
                                SIZE_T                  cbPlaintext,
    _In_reads_( cbCiphertext )  PCBYTE                  pbCiphertext,
                                SIZE_T                  cbCiphertext,
                                ULONGLONG               line)
{
    BYTE bufData[1024];
    NTSTATUS status;
    SIZE_T cbDstComputed = 0;
    SIZE_T bitIndex = 0;

    CHECK3( cbPlaintext <= sizeof( bufData ), "Buffer too small, need %lld bytes", cbPlaintext );
    CHECK3( cbCiphertext <= sizeof( bufData ), "Buffer too small, need %lld bytes", cbCiphertext );

    CHECK( NT_SUCCESS( pImp->setKey( pbKey, cbKey ) ), "Error in setting key" );

    //
    // Do single encryption
    //
    memset( bufData, 0, sizeof( bufData ) );

    status = pImp->encrypt( pbPlaintext, cbPlaintext, bufData, cbCiphertext, &cbDstComputed );
    CHECK( NT_SUCCESS( status ), "Encryption error" );
    CHECK3( memcmp( bufData, pbCiphertext, cbCiphertext ) == 0, "Ciphertext mismatch in line %lld", line );

    //
    // Do single decryption
    //
    status = pImp->decrypt( pbCiphertext, cbCiphertext, bufData, cbPlaintext, &cbDstComputed );
    CHECK( NT_SUCCESS( status ), "Decryption error" );
    CHECK3( memcmp( bufData, pbPlaintext, cbPlaintext ) == 0, "Plaintext mismatch in line %lld", line );

    //
    // Check decryption of corrupted ciphertext fails
    //
    memcpy( bufData, pbCiphertext, cbCiphertext );
    bitIndex = g_rng.sizet( cbCiphertext * 8 );
    bufData[bitIndex/8] ^= 1<<(bitIndex&7);
    status = pImp->decrypt( bufData, cbCiphertext, bufData, cbPlaintext, &cbDstComputed );
    CHECK( !NT_SUCCESS( status ), "No decryption error for corrupted ciphertext" );
}

VOID
testKeyWrapRandom( KeyWrapMultiImp * pImp, int rrep, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line )
{
    const SIZE_T bufSize = 1 << 10;
    const SIZE_T cbMaxPaddingAmount = 16;
    BYTE buf[ bufSize ];
    BYTE tmp1[ bufSize ];
    BYTE tmp2[ bufSize ];
    Rng rng;
    NTSTATUS status;

    //
    // Seed our RNG with the algorithm name
    //
    rng.reset( (PCBYTE) pImp->m_algorithmName.data(), pImp->m_algorithmName.size() );

    SIZE_T keyIdx = 0;

    SIZE_T cbPlaintextMin = pImp->getMinPlaintextSize();
    SIZE_T cbPlaintextMax = pImp->getMaxPlaintextSize();
    SIZE_T cbPlaintextIncrement = pImp->getPlaintextSizeIncrement();
    std::set<SIZE_T>keySizesSet = pImp->getKeySizes();
    
    std::vector<SIZE_T>keySizes( keySizesSet.begin(), keySizesSet.end() );

    std::sort( keySizes.begin(), keySizes.end() );

    memset( buf, 0, sizeof( buf ) );

    for( int i=0; i<rrep; i++ )
    {
        SIZE_T cbKey = keySizes[ rng.sizet( keySizes.size() )];

        CHECK( cbKey <= bufSize, "??" );

        keyIdx = rng.sizet( bufSize - cbKey );

        CHECK3( NT_SUCCESS( pImp->setKey( &buf[keyIdx], cbKey ) ), "Key setting failure, line %lld", line );
        
        SIZE_T cbData = rng.sizet( cbPlaintextMin, SYMCRYPT_MIN(cbPlaintextMax, bufSize-cbMaxPaddingAmount) );
        cbData = cbPlaintextIncrement * (cbData / cbPlaintextIncrement);
        SIZE_T srcIdx = rng.sizet( bufSize - cbData );
        SIZE_T dstIdx = rng.sizet( bufSize-cbMaxPaddingAmount - cbData );
        SIZE_T cbEncrypted;

        status = pImp->encrypt(
            &buf[srcIdx], cbData,
            tmp1, cbData+cbMaxPaddingAmount,
            &cbEncrypted );
        CHECK3( NT_SUCCESS( status ), "Encryption failure, line %lld", line );

        //
        // We first inject an error in the ciphertext to test that it is caught.
        //

        SIZE_T errorBitIdx = rng.sizet( cbEncrypted*8 );
        tmp1[errorBitIdx >> 3] ^= (BYTE)(1 << (errorBitIdx & 7));
        SIZE_T cbDecrypted;

        status = pImp->decrypt( tmp1, cbEncrypted,
                                tmp2, cbData,
                                &cbDecrypted );
        CHECK3( !NT_SUCCESS( status ), "No decryption error, line %lld", line );

        //
        // Then restore ciphertext decrypt, and ensure it matches plaintext
        //
        tmp1[errorBitIdx >> 3] ^= (BYTE)(1 << (errorBitIdx & 7));

        status = pImp->decrypt( tmp1, cbEncrypted,
                                tmp2, cbData,
                                &cbDecrypted );
        CHECK3( NT_SUCCESS( status ), "Decryption error, line %lld", line );
        CHECK3( cbDecrypted == cbData, "Decryption size mismatch, line %lld", line );
        CHECK3( memcmp( tmp2, &buf[srcIdx], cbData ) == 0, "Decryption mismatch, line %lld", line );

        memcpy( &buf[dstIdx], tmp1, cbData );
    }

    // verify the result matches the statically known random combination
    memset( tmp1, 0, cbResult );
    for( SIZE_T i=0; i<bufSize; i++ )
    {
        tmp1[ i % cbResult ] ^= buf[i];
    }

    if( memcmp( tmp1, pbResult, cbResult ) != 0 )
    {

        print( "Wrong keyWrap result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( tmp1, cbResult );
        iprint( "\n" );

        pImp->m_nErrorKatFailure++;
    }
}

VOID
testKeyWrapKats()
{
    std::unique_ptr<KatData> katKeyWrap( getCustomResource( "kat_keywrap.dat", "KAT_KEY_WRAP" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<KeyWrapMultiImp>     pKeyWrapMultiImp;

    while( 1 )
    {
        katKeyWrap->getKatItem( & katItem );
        ULONGLONG line = katItem.line;


        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pKeyWrapMultiImp.reset( new KeyWrapMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData     = (pKeyWrapMultiImp->m_imps.size() == 0);

            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        // Key Wrap data set handling
        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "ciphertext" ) )
            {
                BString katKey = katParseData( katItem, "key" );
                BString katPlaintext = katParseData( katItem, "plaintext" );
                BString katCiphertext = katParseData( katItem, "ciphertext" );

                katKeyWrapSingle( pKeyWrapMultiImp.get(),
                                    katKey.data(), katKey.size(),
                                    katPlaintext.data(), katPlaintext.size(),
                                    katCiphertext.data(), katCiphertext.size(),
                                    line );
            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() == 2, "Wrong # items in RND record ending at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                BString katRnd = katParseData( katItem, "rnd" );
                testKeyWrapRandom( pKeyWrapMultiImp.get(), rrep, katRnd.data(), katRnd.size(), line );
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
testKeyWrapAlgorithms()
{
    testKeyWrapKats();
}



