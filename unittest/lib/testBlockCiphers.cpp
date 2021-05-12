//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

class BlockCipherMultiImp: public BlockCipherImplementation
{
public:
    BlockCipherMultiImp( String algName );
    ~BlockCipherMultiImp();

private:
    BlockCipherMultiImp( const BlockCipherMultiImp & );
    VOID operator=( const BlockCipherMultiImp & );

public:
    virtual SIZE_T  msgBlockLen();
    virtual SIZE_T  chainBlockLen();
    virtual SIZE_T  coreBlockLen();
    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey );
    virtual VOID encrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData );
    virtual VOID decrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData );

    typedef std::vector<BlockCipherImplementation *> BlockCipherImpPtrVector;

    BlockCipherImpPtrVector m_imps;                    // Implementations we use

    BlockCipherImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations


};

BlockCipherMultiImp::BlockCipherMultiImp( String algName )
{
    getAllImplementations<BlockCipherImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( BlockCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

BlockCipherMultiImp::~BlockCipherMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( BlockCipherImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


SIZE_T BlockCipherMultiImp::msgBlockLen()
{
    SIZE_T res = (SIZE_T) -1;
    for( BlockCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->msgBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T BlockCipherMultiImp::chainBlockLen()
{
    SIZE_T res = (SIZE_T) -1;
    for( BlockCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->chainBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T BlockCipherMultiImp::coreBlockLen()
{
    SIZE_T res = (SIZE_T) -1;
    for( BlockCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->coreBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}


NTSTATUS BlockCipherMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( BlockCipherImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

VOID
BlockCipherMultiImp::encrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    BYTE bufData[512];
    BYTE bufChain[32];
    ResultMerge resData;
    ResultMerge resChain;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );
    CHECK( cbChain <= sizeof( bufChain ), "Buf too small" );

    for( BlockCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memcpy( bufChain, pbChain, cbChain );
        SymCryptWipe( bufData, cbData );
        (*i)->encrypt( bufChain, cbChain, pbSrc, bufData, cbData );
        resData.addResult( (*i), bufData, cbData );
        resChain.addResult( (*i), bufChain, cbChain );
    }

    resChain.getResult( pbChain, cbChain, FALSE );
    resData.getResult( pbDst, cbData );
}

VOID
BlockCipherMultiImp::decrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    BYTE bufData[512];
    BYTE bufChain[32];
    ResultMerge resData;
    ResultMerge resChain;

    CHECK( cbData <= sizeof( bufData ), "Buffer too small" );
    CHECK( cbChain <= sizeof( bufChain ), "Buf too small" );

   for( BlockCipherImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        memcpy( bufChain, pbChain, cbChain );
        SymCryptWipe( bufData, cbData );
        (*i)->decrypt( bufChain, cbChain, pbSrc, bufData, cbData );
        resData.addResult( (*i), bufData, cbData );
        resChain.addResult( (*i), bufChain, cbChain );
    }

    resChain.getResult( pbChain, cbChain, FALSE );
    resData.getResult( pbDst, cbData );
}


VOID
katBlockCipherSingle(
                                BlockCipherImplementation * pImp,
    _In_reads_( cbKey )         PCBYTE                      pbKey,
                                SIZE_T                      cbKey,
    _In_reads_opt_( cbChain )   PBYTE                       pbChain,
                                SIZE_T                      cbChain,
    _In_reads_( cbPlaintext )   PCBYTE                      pbPlaintext,
                                SIZE_T                      cbPlaintext,
    _In_reads_( cbCiphertext )  PCBYTE                      pbCiphertext,
                                SIZE_T                      cbCiphertext,
                                ULONGLONG                   line)
{
    BYTE bufData[512];
    BYTE bufChain[32];
    SIZE_T msgBlockLen = pImp->msgBlockLen();

    CHECK3( cbPlaintext < sizeof( bufData ), "Buffer too small, need %lld bytes", cbPlaintext );
    CHECK( cbChain <= sizeof( bufChain ), "?" );
    CHECK3( cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line );

    CHECK( pImp->setKey( pbKey, cbKey ) == 0, "Error in setting key" );

    //
    // Do single encryption
    //
    memset( bufData, 0, sizeof( bufData ) );
    if (cbChain > 0)
    {
        memcpy( bufChain, pbChain, cbChain );
    }

    pImp->encrypt( bufChain, cbChain, pbPlaintext, bufData, cbPlaintext );
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext mismatch in line %lld", line );

    //
    // Do encryption piecewise
    //
    memset( bufData, 0, sizeof( bufData ) );
    if (cbChain > 0)
    {
        memcpy( bufChain, pbChain, cbChain );
    }
    SIZE_T offset = 0;
    while( offset < cbPlaintext )
    {
        SIZE_T nBytes = g_rng.sizetNonUniform( (cbPlaintext - offset)/msgBlockLen + 1, 4, 1 ) * msgBlockLen;
        pImp->encrypt( bufChain, cbChain, pbPlaintext + offset, bufData + offset, nBytes );
        offset += nBytes;
    }
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext 2 mismatch in line %lld", line );

    //
    // Do single decryption
    //
    if (cbChain > 0)
    {
        memcpy( bufChain, pbChain, cbChain );
    }
    pImp->decrypt( bufChain, cbChain, pbCiphertext, bufData, cbCiphertext );
    CHECK3( memcmp( bufData, pbPlaintext, cbCiphertext ) == 0, "Plaintext mismatch in line %lld", line );

    //
    // Do piecewise decryption
    //
    memset( bufData, 0, sizeof( bufData ) );
    if (cbChain > 0)
    {
        memcpy( bufChain, pbChain, cbChain );
    }
    offset = 0;
    while( offset < cbPlaintext )
    {
        SIZE_T nBytes = g_rng.sizetNonUniform( (cbPlaintext - offset)/msgBlockLen + 1, 4, 1 ) * msgBlockLen;
        pImp->decrypt( bufChain, cbChain, pbCiphertext + offset, bufData + offset, nBytes );
        offset += nBytes;
    }
    CHECK3( memcmp( bufData, pbPlaintext, cbPlaintext ) == 0, "Plaintext 2 mismatch in line %lld", line );

}


VOID
testBlockCipherRandom( BlockCipherMultiImp * pImp, int rrep, SIZE_T keyLen, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line )
{
    BYTE buf[ 1024 ];
    BYTE chainBuf[64];
    Rng rng;

    //
    // Seed our RNG with the algorithm name and key size
    //
    SIZE_T algNameSize = pImp->m_algorithmName.size();
    CHECK( algNameSize < sizeof( buf ) - sizeof( ULONGLONG ), "Algorithm name too long" );
    memcpy( buf, pImp->m_algorithmName.data(), algNameSize );
    *(ULONGLONG SYMCRYPT_UNALIGNED *)&buf[algNameSize] = keyLen;
    rng.reset( buf, algNameSize + sizeof( ULONGLONG ) );

    const SIZE_T chainBlockLen = pImp->chainBlockLen();
    const SIZE_T msgBlockLen = pImp->msgBlockLen();
    const SIZE_T coreBlockLen = pImp->coreBlockLen();
    const SIZE_T bufSize = coreBlockLen * 32;
    CHECK( bufSize <= sizeof( buf ), "Input block len too large" );
    CHECK( bufSize > keyLen, "?" );
    CHECK( bufSize > chainBlockLen, "?" );
    CHECK( bufSize > msgBlockLen, "?" );

    memset( buf, 0, sizeof( buf ) );

    SIZE_T keyIdx = 0;
    SIZE_T chainIdx = 0;
    SIZE_T nPieces;
    SIZE_T pos;
    SIZE_T len;
    BOOL fEncrypt;
    SIZE_T cntFnc = 0;
    SIZE_T cntEnc = 0;
    SIZE_T cntPc[5] = {0};
    SIZE_T bytes = 0;

    for( int i=0; i<rrep; i++ )
    {
        keyIdx = rng.sizet( bufSize - keyLen );

        // iprint( "Eff key size = %d\n", g_rc2EffectiveKeyLength );
        CHECK3( NT_SUCCESS( pImp->setKey( &buf[keyIdx], keyLen ) ), "Key setting failure, line %lld", line );

        chainIdx = rng.sizet( bufSize - chainBlockLen );

        //
        // The next byte is the # appends that we will do; 0 appends means we call the
        // hash function directly without init/append/result.
        //
        nPieces = rng.byte();
        fEncrypt = ((nPieces & 1) != 0);
        nPieces = 1 + nPieces % 5;

        if( fEncrypt ) cntEnc++;
        cntPc[nPieces-1]++;

        memcpy( chainBuf, &buf[chainIdx], chainBlockLen );
        for( SIZE_T j=0; j<nPieces; j++ )
        {
            rng.randomSubRange( bufSize, &pos, &len );
            len = msgBlockLen * (len / msgBlockLen );
            g_rc2EffectiveKeyLength = 9 + (pos % (1024 - 9));
            if( fEncrypt )
            {
                pImp->encrypt( chainBuf, chainBlockLen, &buf[pos], &buf[pos], len );
                cntFnc++;
                cntEnc++;
            }
            else
            {
                pImp->decrypt( chainBuf, chainBlockLen, &buf[pos], &buf[pos], len );
                cntFnc++;
            }
            bytes += len;
        }
        memcpy( &buf[chainIdx], chainBuf, chainBlockLen );

    }

    memset( chainBuf, 0, coreBlockLen );
    for( SIZE_T i=0; i<bufSize; i++ )
    {
        chainBuf[ i % coreBlockLen ]  ^= buf[i];
    }

//    iprint( "%lld, %lld, [%lld,%lld,%lld,%lld,%lld] %lld\n", cntFnc, cntEnc,
//        cntPc[0], cntPc[1], cntPc[2], cntPc[3], cntPc[4], bytes );

    CHECK3( cbResult == coreBlockLen, "Result size is wrong in line %lld", line );
    if( memcmp( chainBuf, pbResult, coreBlockLen ) != 0 )
    {

        print( "Wrong blockcipher result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( chainBuf, cbResult );
        iprint( "\n" );

        pImp->m_nErrorKatFailure++;
    }
    g_rc2EffectiveKeyLength = 0;
}



VOID
testBlockCipherKats()
{
    std::unique_ptr<KatData> katBlockCipher( getCustomResource( "kat_blockcipher.dat", "KAT_BLOCK_CIPHER" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<BlockCipherMultiImp> pBlockCipherMultiImp;

    while( 1 )
    {
        katBlockCipher->getKatItem( & katItem );
        ULONGLONG line = katItem.line;


        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pBlockCipherMultiImp.reset( new BlockCipherMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pBlockCipherMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "effectivekeylength" ) )
            {
                g_rc2EffectiveKeyLength = (ULONG)katParseInteger( katItem, "effectivekeylength" );
            }

            if( katIsFieldPresent( katItem, "shift" ) )
            {
                g_modeCfbShiftParam = (SIZE_T) katParseInteger( katItem, "shift" );
            }

            if( katIsFieldPresent( katItem, "ciphertext" ) )
            {
                BYTE chainBuf[32];

                BString katKey = katParseData( katItem, "key" );
                BString katPlaintext = katParseData( katItem, "plaintext" );
                BString katCiphertext = katParseData( katItem, "ciphertext" );

                if( katIsFieldPresent( katItem, "iv" ) )
                {
                    BString katChain = katParseData( katItem, "iv" );
                    CHECK( katChain.size() <= sizeof( chainBuf ), "IV too long" );
                    memcpy( chainBuf, katChain.data(), katChain.size() );

                    katBlockCipherSingle( pBlockCipherMultiImp.get(),
                                            katKey.data(), katKey.size(),
                                            chainBuf, katChain.size(),
                                            katPlaintext.data(), katPlaintext.size(),
                                            katCiphertext.data(), katCiphertext.size(),
                                            line );
                } else
                {
                    katBlockCipherSingle( pBlockCipherMultiImp.get(),
                                            katKey.data(), katKey.size(),
                                            NULL, 0,
                                            katPlaintext.data(), katPlaintext.size(),
                                            katCiphertext.data(), katCiphertext.size(),
                                            line );
                }

            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() <= 4, "Wrong # items in RND record ending at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                SIZE_T keyLen = (SIZE_T) katParseInteger( katItem, "keylen" );
                BString katRnd = katParseData( katItem, "rnd" );
                testBlockCipherRandom( pBlockCipherMultiImp.get(), rrep, keyLen, katRnd.data(), katRnd.size(), line );
            } else
            {
                FATAL2( "Unknown data record ending at line %lld", line );
            }

            g_rc2EffectiveKeyLength = 0;
            g_modeCfbShiftParam = 1;
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

VOID
testBlockCipherAlgorithms()
{
    testBlockCipherKats();
}



