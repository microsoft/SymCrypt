//
// TestMac.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#define MAX_MAC_SIZE    (256)
#define MAX_INPUT_BLOCK_SIZE    (512)

class MacMultiImp: public MacImplementation
{
public:
    MacMultiImp( String algName );
    ~MacMultiImp();

private:
    MacMultiImp( const MacMultiImp & );
    VOID operator=( const MacMultiImp & );

public:

    typedef std::vector<MacImplementation *> MacImpPtrVector;

    MacImpPtrVector m_imps;                    // Implementations we use

    MacImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    virtual SIZE_T resultLen();
    virtual SIZE_T inputBlockLen();

    virtual NTSTATUS init( PCBYTE pbKey, SIZE_T cbKey );
    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void result( PBYTE pbResult, SIZE_T cbResult );
    virtual NTSTATUS mac( PCBYTE pbKey, SIZE_T cbKey, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult );

};

MacMultiImp::MacMultiImp( String algName )
{
    getAllImplementations<MacImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( MacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

MacMultiImp::~MacMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( MacImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


SIZE_T MacMultiImp::resultLen()
{
    SIZE_T res = (SIZE_T) -1;
    for( MacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->resultLen();
        CHECK( res == -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T MacMultiImp::inputBlockLen()
{
    SIZE_T res = (SIZE_T) -1;
    for( MacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->inputBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent input block len" );
        res = v;
    }

    return res;
}


NTSTATUS MacMultiImp::mac( PCBYTE pbKey, SIZE_T cbKey, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[500];
    ResultMerge res;
    NTSTATUS status;
    int nSuccess = 0;

    CHECK( cbResult <= sizeof( buf ), "??" );

    for( MacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SymCryptWipe( buf, cbResult );
        status = (*i)->mac( pbKey, cbKey, pbData, cbData, buf, cbResult );
        if( status == 0 )
        {
            res.addResult( (*i), buf, cbResult );
            nSuccess++;
        }
    }

    if( nSuccess == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }
    res.getResult( pbResult, cbResult );

    return STATUS_SUCCESS;

}


NTSTATUS MacMultiImp::init( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( MacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->init( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

VOID MacMultiImp::append( PCBYTE pbData, SIZE_T cbData )
{
   for( MacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        (*i)->append( pbData, cbData );
   }

}

VOID MacMultiImp::result( PBYTE pbResult, SIZE_T cbResult )
{
   BYTE buf[500];
   ResultMerge res;

   CHECK( cbResult <= sizeof( buf ), "?" );

   for( MacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, cbResult );
        (*i)->result( buf, cbResult );
        res.addResult( (*i), buf, cbResult );
   }

   res.getResult( pbResult, cbResult );
}

NTSTATUS
MacImplementation::mac(
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey,
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData,
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    NTSTATUS status;
    status = init( pbKey, cbKey );
    if( status != 0 )
    {
        return status;
    }

    append( pbData, cbData );
    result( pbResult, cbResult );

    return STATUS_SUCCESS;
}


VOID
testMacSingle(
                            MacImplementation     * pMac,
    _In_reads_( cbKey )    PCBYTE                  pbKey,
                            SIZE_T                  cbKey,
    _In_reads_( cbData )   PCBYTE                  pbData,
                            SIZE_T                  cbData,
    _In_reads_( cbResult ) PCBYTE                  pbResult,
                            SIZE_T                  cbResult,
                            ULONGLONG               line)
{
    BYTE res[1000];
    SIZE_T resultLen = pMac->resultLen();
    NTSTATUS status;

    CHECK( resultLen <= sizeof( res ), "Hash result too long" );
    if( resultLen != cbResult )
    {
        FATAL6( "Mac result len mismatch. Alg = %s, Imp = %s, line = %lld, result len = %d, expected %d",
                pMac->m_algorithmName.c_str(), pMac->m_implementationName.c_str(), line, cbResult, resultLen );
    }

    if( cbKey == 0 )
    {
        pbKey = NULL;
    }

    memset( res, 0, resultLen );
    status = pMac->mac( pbKey, cbKey, pbData, cbData, res, resultLen );

    if( status == 0 )
    {
        if( memcmp( res, pbResult, resultLen ) != 0 )
        {
            print( "Wrong MAC result in line %lld. \n"
                "Expected ", line );
            printHex( pbResult, cbResult );
            print( "\nGot      " );
            printHex( res, cbResult );
            print( "\n" );
            pMac->m_nErrorKatFailure++;
        }
    }

    memset( res, 0, resultLen );
    status = pMac->init( pbKey, cbKey );

    if( status != 0 )
    {
        return;
    }

    PCBYTE pbDataLeft = pbData;
    SIZE_T bytesLeft = cbData;

    while( bytesLeft > 0 )
    {
        SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
        pMac->append( pbDataLeft, todo );
        pbDataLeft += todo;
        bytesLeft -= todo;
    }
    pMac->result( res, resultLen );

    if( memcmp( res, pbResult, resultLen ) != 0 )
    {
        print( "Wrong incremental MAC result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pMac->m_nErrorKatFailure++;
    }

}


#define RND_BUF_SIZE    (1<<12)

VOID
testMacRandom( MacMultiImp * pMac, int rrep, SIZE_T keyLen, PCBYTE pbResult, SIZE_T cbResult, LONGLONG line )
{
    BYTE buf[ RND_BUF_SIZE ];
    BYTE res[64];
    NTSTATUS status;
    Rng rng;

    //
    // Seed our RNG with the algorithm name
    //
    rng.reset( (PCBYTE) pMac->m_algorithmName.data(), pMac->m_algorithmName.size() );

    const SIZE_T bufSize = SYMCRYPT_MAX( 64, pMac->inputBlockLen() * 4);
    CHECK( bufSize <= sizeof( buf ), "Input block len too large" );

    // We used to set the buffer to 0 at the start, but Poly1305 has a fixed-point at 0
    // If the key is all-zero, the output is also zero
    // So we now set the buffer to a nonzero value.
    memset( buf, 'N', sizeof( buf ) );
    SIZE_T destIdx = 0;
    SIZE_T keyIdx = 0;
    SIZE_T cbKey = 0;
    SIZE_T nAppends;
    SIZE_T pos;
    SIZE_T len;
    SIZE_T cbMac = pMac->resultLen();
    CHECK( cbMac <= sizeof( res ), "Hash result too long" );

    for( int i=0; i<rrep; i++ )
    {
        //
        // We first find where the key is
        //
        keyIdx = rng.sizet( bufSize );

        if( keyLen == -1 )
        {
            cbKey = rng.sizetNonUniform( bufSize - keyIdx, 64, 2 );
        }
        else
        {
            cbKey = keyLen;
        }

        //
        // The next bytes tells us where the result of this iteration will go in the buffer.
        //
        destIdx = rng.sizet( bufSize );

        //
        // The next byte is the # appends that we will do; 0 appends means we call the
        // hash function directly without init/append/result.
        //
        nAppends = rng.byte() % 5;
        if( nAppends == 0 )
        {
            rng.randomSubRange( bufSize, &pos, &len );
            status = pMac->mac( &buf[keyIdx], cbKey, &buf[pos], len, res, cbMac );
            CHECK( status == 0, "All MAC implementations failed in random MAC test" );
        } else {
            status = pMac->init( &buf[keyIdx], cbKey );
            CHECK( status == 0, "All MAC implementations failed in random MAC test" );
            for( SIZE_T j=0; j<nAppends; j++ )
            {
                rng.randomSubRange( bufSize, &pos, &len );
                pMac->append( &buf[pos], len );
            }
            pMac->result( res, cbMac );
        }

        if( destIdx + cbMac <= bufSize )
        {
            memcpy( &buf[destIdx], res, cbMac );
        } else {
            len = bufSize - destIdx;
            memcpy( &buf[destIdx], res, len );
            memcpy( &buf[0], &res[len], cbMac - len );
        }

    }

    CHECK( pMac->mac( &buf[0], keyLen == -1 ? 0 : keyLen, &buf[0], bufSize, res, cbMac ) == 0, "MAC failure" );
    if( cbResult != 0 )
    {
        CHECK5( cbResult == cbMac, "Wrong result length in line %lld, expected %d, got %d", line, cbMac, cbResult );
        if( memcmp( res, pbResult, cbMac ) != 0 )
        {

        print( "Wrong hash result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pMac->m_nErrorKatFailure++;

        }

    }

}

VOID
testMacConsistency( MacMultiImp * pMac, SIZE_T cbKey, LONGLONG megaBytes, LONGLONG line )
{
    //
    // Poly1305 uses modular arithmetic, and there is a risk of 2^-32 probability error in
    // things like carry handling. The fixed set of test vectors is unlikely to find this.
    // (Even the 'random' test is a fixed set of values with a known answer.)
    // The consistency check just runs random data through all implementations to check that they
    // are consistent with each other. Our reference implementation is based on general modular
    // arithmetic which is tested elsewhere, so this gives us confidence that our Poly1305
    // implementation is correct in this respect
    //

    PBYTE pbBuf;
    SIZE_T cbBuf = 1 << 20;
    LONGLONG i;

    CHECK( megaBytes > 0, "?" );
    CHECK3( megaBytes <= 1000, "Consistency check will take too long in line %lld", line );

    pbBuf = (PBYTE) malloc( cbBuf );
    CHECK( pbBuf != NULL, "Out of memory" );

    for( i=0; i<megaBytes; i++ )
    {
        GENRANDOM( pbBuf, (ULONG) cbBuf );

        pMac->mac( pbBuf, cbKey, pbBuf + cbKey, cbBuf - cbKey, pbBuf, pMac->resultLen() );

        // Redo with an all-one key which tends to trigger more overflows
        memset( pbBuf, 0xff, cbKey );
        pMac->mac( pbBuf, cbKey, pbBuf + cbKey, cbBuf - cbKey, pbBuf, pMac->resultLen() );
    }

    free( pbBuf );
}


VOID
testMacKats()
{
    std::unique_ptr<KatData> katMac( getCustomResource( "kat_mac.dat", "KAT_MAC" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<MacMultiImp> pMacMultiImp;

    while( 1 )
    {
        katMac->getKatItem( & katItem );
        ULONGLONG line = katItem.line;

        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pMacMultiImp.reset( new MacMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pMacMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "mac" ) )
            {
                SIZE_T nFields = 3;
                int katKlen = -1;

                if( katIsFieldPresent( katItem, "klen" ) )
                {
                    katKlen = (int) katParseInteger( katItem, "klen" );
                    nFields++;
                }
                if( katIsFieldPresent( katItem, "tlen" ) )
                {
                    CHECK3( pMacMultiImp->resultLen() == (SIZE_T) katParseInteger( katItem, "tlen" ),
                            "Wrong Tlen field in record at line %lld", line );
                    nFields++;
                }
                if( katIsFieldPresent( katItem, "count" ) )
                {
                    // We ignore this field
                    nFields++;
                }

                CHECK3( katItem.dataItems.size() == nFields, "Too many items in MD record at line %lld", line );
                BString katMsg = katParseData( katItem, "msg" );
                BString katMac = katParseData( katItem, "mac" );
                BString katKey = katParseData( katItem, "key" );
                if( katKlen >= 0 )
                {
                    CHECK3( (SIZE_T) katKlen == katKey.size(), "Klen & Key fields disagree at line %lld", line );
                }
                testMacSingle( pMacMultiImp.get(), katKey.data(), katKey.size(), katMsg.data(), katMsg.size(), katMac.data(), katMac.size(), line );
                continue;
            }
            if( katIsFieldPresent( katItem, "rnd" ) )
            {
                SIZE_T keyLen = (SIZE_T) -1;
                CHECK3( katItem.dataItems.size() <= 3, "Too many items in RND record at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                if( katIsFieldPresent( katItem, "keylen" ) )
                {
                    keyLen = (SIZE_T) katParseInteger( katItem, "keylen" );
                }
                else
                {
                    CHECK3( katItem.dataItems.size() == 2, "Unknown item in RNG record at line %lld", line );
                }
                BString katRnd = katParseData( katItem, "rnd" );
                testMacRandom( pMacMultiImp.get(), rrep, keyLen, katRnd.data(), katRnd.size(), line );
                continue;
            }
            if( katIsFieldPresent( katItem, "consistencymb" ) )
            {
                SIZE_T keyLen = (SIZE_T) -1;
                CHECK3( katItem.dataItems.size() <= 2, "Too many items in Consistency record at line %lld", line );
                LONGLONG megabytes = katParseInteger( katItem, "consistencymb" );
                if( katIsFieldPresent( katItem, "keylen" ) )
                {
                    keyLen = (SIZE_T) katParseInteger( katItem, "keylen" );
                }
                else
                {
                    CHECK3( katItem.dataItems.size() == 2, "Unknown item in consistency record at line %lld", line );
                }
                testMacConsistency( pMacMultiImp.get(), keyLen, megabytes, line );
                continue;
            }

            FATAL2( "Unknown data record at line %lld", line );
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}


VOID
testMacAlgorithms()
{
    BYTE    buf[8];
    BYTE    bufDynamic[8];

    testMacKats();

    //
    // Quick test that the Marvin default key works in SymCrypt
    //
    // Key = b79308cdced93cd5
    // Msg = "Marvin"
    // Mac = 7c0ae124d1185a37
    //
    ScDispatchSymCryptMarvin32( ScDispatchSymCryptMarvin32DefaultSeed, (PCBYTE) "Marvin", 6, buf );

    if( memcmp( buf, "\x7c\x0a\xe1\x24\xd1\x18\x5a\x37", sizeof( buf ) ) != 0 )
    {
        FATAL( "Wrong result for default seeded Marvin API" );
    }

    if( (g_dynamicSymCryptModuleHandle != NULL) &&
        (SCTEST_LOOKUP_DYNSYM(SymCryptMarvin32, TRUE) != NULL) )
    {
        g_useDynamicFunctionsInTestCall = TRUE;
        ScDispatchSymCryptMarvin32( ScDispatchSymCryptMarvin32DefaultSeed, (PCBYTE)"Marvin", 6, bufDynamic );
        g_useDynamicFunctionsInTestCall = FALSE;

        if( memcmp( bufDynamic, buf, sizeof( buf ) ) != 0 )
        {
            FATAL( "Wrong result for default seeded Marvin API" );
        }
    }
}

