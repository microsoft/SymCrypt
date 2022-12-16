//
// TestHash.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for hash functions.
//

#include "precomp.h"


#define MAX_HASH_SIZE    (256)
#define MAX_INPUT_BLOCK_SIZE    (512)

class HashMultiImp: public HashImplementation
{
public:
    HashMultiImp( String algName );
    ~HashMultiImp();

private:
    HashMultiImp( const HashMultiImp & );
    VOID operator=( const HashMultiImp & );

public:

    typedef std::vector<HashImplementation *> HashImpPtrVector;

    HashImpPtrVector m_imps;                    // Implementations we use

    HashImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    VOID addImplementation( HashImplementation * pHashImp );
    VOID setImpName();

    virtual SIZE_T resultLen();
    virtual SIZE_T inputBlockLen();

    virtual void init();
    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void result( PBYTE pbResult, SIZE_T cbResult );
    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes );
    virtual VOID hash( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult );
    virtual NTSTATUS exportSymCryptFormat(
            _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult,
            _In_                                                    SIZE_T  cbResultBufferSize,
            _Out_                                                   SIZE_T *pcbResult );
};

VOID
HashMultiImp::setImpName()
{
    String sumAlgName;
    char * sepStr = "<";

    for( HashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

HashMultiImp::HashMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<HashImplementation>( algName, &m_imps );
}

VOID
HashMultiImp::addImplementation( HashImplementation * pHashImp )
{
    m_imps.push_back( pHashImp );
    setImpName();
}


HashMultiImp::~HashMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( HashImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

SIZE_T HashMultiImp::resultLen()
{
    SIZE_T res = MAX_SIZE_T;
    for( HashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->resultLen();
        CHECK( res == -1 || res == v, "Inconsistent result len" );
        res = v;
    }

    return res;
}

SIZE_T HashMultiImp::inputBlockLen()
{
    SIZE_T res = MAX_SIZE_T;
    for( HashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->inputBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent input block len" );
        res = v;
    }

    return res;
}


VOID HashMultiImp::hash( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[500];
    ResultMerge res;

    CHECK( cbResult <= sizeof( buf ), "??" );

    for( HashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SymCryptWipe( buf, cbResult );
        (*i)->hash( pbData, cbData, buf, cbResult );
        res.addResult( (*i), buf, cbResult );
    }

    res.getResult( pbResult, cbResult );

}


VOID HashMultiImp::init()
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.assign( m_imps.begin(), m_imps.end() );

    for( HashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->init();
    }

}

VOID HashMultiImp::append( PCBYTE pbData, SIZE_T cbData )
{
   for( HashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        (*i)->append( pbData, cbData );
   }

}

VOID HashMultiImp::result( PBYTE pbResult, SIZE_T cbResult )
{
   BYTE buf[500];
   ResultMerge res;

   CHECK( cbResult <= sizeof( buf ), "?" );

   for( HashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, cbResult );
        (*i)->result( buf, cbResult );
        res.addResult( (*i), buf, cbResult );
   }

   res.getResult( pbResult, cbResult );
}

NTSTATUS
HashMultiImp::initWithLongMessage( ULONGLONG nBytes )
{
   //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( HashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->initWithLongMessage( nBytes ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
HashMultiImp::exportSymCryptFormat(
    _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult,
    _In_                                                    SIZE_T  cbResultBufferSize,
    _Out_                                                   SIZE_T *pcbResult )
{
    BYTE buf[1024];
    ResultMerge res;
    SIZE_T sizeTmp;
    SIZE_T size = MAX_SIZE_T;

    CHECK( cbResultBufferSize <= sizeof( buf ), "?" );

   for( HashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, sizeof( buf ) );
        if( NT_SUCCESS( (*i)->exportSymCryptFormat( buf, sizeof( buf ), &sizeTmp ) ) )
        {
            res.addResult( (*i), buf, sizeTmp );
            size = sizeTmp;         // if we get different sizes, ResultMerge will catch it.
        }
   }

   CHECK( size != -1, "No implementation supports SymCrypt hash state export format" );
   CHECK( size <= cbResultBufferSize, "Export blob too large" );

   *pcbResult = size;
   res.getResult( pbResult, size );

   return STATUS_SUCCESS;
}


class ParallelHashMultiImp: ParallelHashImplementation {
public:
    ParallelHashMultiImp( String algName );
    virtual ~ParallelHashMultiImp();

private:
    ParallelHashMultiImp( const ParallelHashMultiImp & );
    VOID operator=( const ParallelHashMultiImp & );

public:

    typedef std::vector<ParallelHashImplementation *> ParallelHashImpPtrVector;

    ParallelHashImpPtrVector m_imps;       // Implementations we use
    ParallelHashImpPtrVector m_comps;      // subset of m_imps; set of implementations in ongoing computation.

    virtual PCSYMCRYPT_HASH SymCryptHash();

    virtual SIZE_T resultLen();

    virtual SIZE_T inputBlockLen();

    virtual VOID init( SIZE_T nHashes );

    virtual VOID process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations );

    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes );

private:
};

ParallelHashMultiImp::ParallelHashMultiImp( String algName )
{
    getAllImplementations<ParallelHashImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumAlgName;
    char * sepStr = "<";

    for( ParallelHashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

ParallelHashMultiImp::~ParallelHashMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( ParallelHashImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

SIZE_T
ParallelHashMultiImp::resultLen()
{
    SIZE_T res;
    SIZE_T tmp;

    res = 0;
    for( ParallelHashImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        tmp = (*i)->resultLen();
        CHECK( (res == 0 || tmp == res) && tmp != 0, "Result length mismatch" );
        res = tmp;
    }

    return res;
}

SIZE_T
ParallelHashMultiImp::inputBlockLen()
{
    SIZE_T res;
    SIZE_T tmp;

    res = 0;
    for( ParallelHashImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        tmp = (*i)->inputBlockLen();
        CHECK( (res == 0 || tmp == res) && tmp != 0, "Result length mismatch" );
        res = tmp;
    }

    return res;
}

PCSYMCRYPT_HASH
ParallelHashMultiImp::SymCryptHash()
{
    PCSYMCRYPT_HASH res;

    for( ParallelHashImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        res = (*i)->SymCryptHash();
        if( res != NULL )
        {
            return res;
        }
    }

    CHECK( FALSE, "No parallel hash implementation provided SymCrypt hash object" );
    return NULL;
}


VOID
ParallelHashMultiImp::init( SIZE_T nHashes )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.assign( m_imps.begin(), m_imps.end() );

    for( ParallelHashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->init( nHashes );
    }

}

VOID
ParallelHashMultiImp::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    ResultMerge                 results[MAX_PARALLEL_HASH_OPERATIONS];
    BYTE                        buf[MAX_PARALLEL_HASH_OPERATIONS][MAX_HASH_SIZE];
    BCRYPT_MULTI_HASH_OPERATION op[MAX_PARALLEL_HASH_OPERATIONS];
    SIZE_T                      cbResult;

    cbResult = resultLen();

    CHECK( nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "?" );
    _Analysis_assume_( nOperations <= MAX_PARALLEL_HASH_OPERATIONS );

    if (nOperations == 0)
    {
        return;
    }

    for( ParallelHashImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        //
        // Set up the command sequence to put the result in the buf[] array
        //
        memcpy( op, pOperations, nOperations * sizeof( *pOperations ) );
        for( SIZE_T j=0; j<nOperations; j++ )
        {
            if( op[j].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH )
            {
                op[j].pbBuffer = &buf[j][0];
            }
        }

        (*i)->process( &op[0], nOperations );

        //
        // Put the results in the results merge array
        //
        for( SIZE_T j=0; j<nOperations; j++ )
        {
            if( pOperations[j].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH )
            {
                results[j].addResult( (*i), buf[j], cbResult );
            }
        }
    }

    for( SIZE_T i=0; i<nOperations; i++ )
    {
        if( pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH )
        {
            results[i].getResult( pOperations[i].pbBuffer, pOperations[i].cbBuffer );
        }
    }
}

NTSTATUS
ParallelHashMultiImp::initWithLongMessage( ULONGLONG nBytes )
{
   //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( ParallelHashImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->initWithLongMessage( nBytes ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;

}


_Use_decl_annotations_
VOID
HashImplementation::hash( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    init();
    append( pbData, cbData );
    result( pbResult, cbResult );
}


VOID
testHashSingle(                         HashImplementation *    pHash,
               _In_reads_( cbData )     PCBYTE                  pbData,
                                        SIZE_T                  cbData,
               _In_reads_( cbResult )   PCBYTE                  pbResult,
                                        SIZE_T                  cbResult,
                                        LONGLONG                line)
{
    BYTE res[1000];
    SIZE_T resultLen = pHash->resultLen();

    CHECK( resultLen <= sizeof( res ), "Hash result too long" );
    if( resultLen != cbResult )
    {
        FATAL6( "Hash result len mismatch. Alg = %s, Imp = %s, line = %lld, result len = %d, expected %d",
                pHash->m_algorithmName.c_str(), pHash->m_implementationName.c_str(), line, cbResult, resultLen );
    }
    _Analysis_assume_( resultLen == cbResult );

    memset( res, 0, resultLen );
    pHash->hash( pbData, cbData, res, resultLen );

    if( memcmp( res, pbResult, resultLen ) != 0 )
    {
        print( "Wrong hash result. \n"
            "Expected " );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );
        pHash->m_nErrorKatFailure++;
    }


    memset( res, 0, resultLen );
    pHash->init();

    PCBYTE pbDataLeft = pbData;
    SIZE_T bytesLeft = cbData;

    while( bytesLeft > 0 )
    {
        SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
        pHash->append( pbDataLeft, todo );
        pbDataLeft += todo;
        bytesLeft -= todo;
    }
    pHash->result( res, resultLen );

    if( memcmp( res, pbResult, resultLen ) != 0 )
    {
        print( "Wrong hash result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pHash->m_nErrorKatFailure++;
    }

}

#define RND_BUF_SIZE    (1<<12)

VOID
testHashRandom( HashMultiImp * pHash, int rrep, PCBYTE pbResult, SIZE_T cbResult, LONGLONG line )
{
    BYTE buf[ RND_BUF_SIZE ];
    BYTE res[64];
    Rng rng;

    //
    // Seed our RNG with the algorithm name
    //
    rng.reset( (PCBYTE) pHash->m_algorithmName.data(), pHash->m_algorithmName.size() );

    const SIZE_T bufSize = pHash->inputBlockLen() * 4;
    CHECK( bufSize <= sizeof( buf ), "Input block len too large" );

    memset( buf, 0, sizeof( buf ) );
    SIZE_T destIdx = 0;
    SIZE_T nAppends;
    SIZE_T pos;
    SIZE_T len;
    SIZE_T cbHash = pHash->resultLen();
    CHECK( cbHash <= sizeof( res ), "Hash result too long" );

    for( int i=0; i<rrep; i++ )
    {
        //
        // The first byte tells us where the result of this iteration will go in the buffer.
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
            pHash->hash( &buf[pos], len, res, cbHash );
        } else {
            pHash->init();
            for( SIZE_T j=0; j<nAppends; j++ )
            {
                rng.randomSubRange( bufSize, &pos, &len );
                pHash->append( &buf[pos], len );
            }
            pHash->result( res, cbHash );
        }

        if( destIdx + cbHash <= bufSize )
        {
            memcpy( &buf[destIdx], res, cbHash );
        } else {
            len = bufSize - destIdx;
            memcpy( &buf[destIdx], res, len );
            memcpy( &buf[0], &res[len], cbHash - len );
        }

    }

    pHash->hash( &buf[0], bufSize, res, cbHash );
    if( cbResult != 0 )
    {
        CHECK5( cbResult == cbHash, "Wrong result length in line %lld, expected %d, got %d", line, cbHash, cbResult );
        if( memcmp( res, pbResult, cbHash ) != 0 )
        {

        print( "Wrong hash result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pHash->m_nErrorKatFailure++;

        }

    }

}

VOID
testLongMessage( HashMultiImp * pHash, int maxLen, PCBYTE pbResult, SIZE_T cbResult, LONGLONG line )
{
    BString results;
    BYTE tmp[MAX_HASH_SIZE];
    BYTE res[MAX_HASH_SIZE];
    BYTE data[2*MAX_INPUT_BLOCK_SIZE];

    SIZE_T blockSize = pHash->inputBlockLen();
    SIZE_T resultLen = pHash->resultLen();

    CHECK( resultLen <= MAX_HASH_SIZE, "Result size too large" );
    CHECK3( resultLen == cbResult, "Incorrect result length in line %lld", line );
    CHECK( blockSize <= MAX_INPUT_BLOCK_SIZE, "Input block len too large" );

    memset( data, 'a', sizeof( data ) );


    //
    // maxLen is the maximum 2-log of the length
    //
    CHECK4( 10 <= maxLen && maxLen <= 63, "Len=%d is not valid in line %lld", maxLen, line );

    for( int len = 10; len <= maxLen; len++ )
    {
        ULONGLONG boundary = (ULONGLONG)1 << len;
        ULONGLONG startLen = boundary - blockSize;
        SIZE_T nBytes = 2*blockSize;

        pHash->initWithLongMessage( startLen );
        pHash->append( data, nBytes );
        pHash->result( res, cbResult );

        pHash->initWithLongMessage( startLen );
        for( SIZE_T i=0; i<nBytes; i++ )
        {
            pHash->append( data, 1 );
        }
        pHash->result( tmp, cbResult );
        CHECK3( memcmp( tmp, res, cbResult ) == 0, "Inconsistent results in line %lld", line );

        pHash->initWithLongMessage( startLen );
        while( nBytes > 0 )
        {
            pHash->append( data, SYMCRYPT_MIN( 5, nBytes ) );
            nBytes -= SYMCRYPT_MIN( 5, nBytes );
        }
        pHash->result( tmp, cbResult );
        CHECK3( memcmp( tmp, res, cbResult ) == 0, "Inconsistent results in line %lld", line );

        results.append( res, cbResult );
    }
    pHash->hash( (PCBYTE) results.data(), results.size(), res, cbResult );

    if( memcmp( res, pbResult, cbResult ) != 0 )
    {
        print( "Wrong %s result for long message test in line %lld. \n"
            "Expected ", pHash->m_algorithmName.c_str(), line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        for( HashMultiImp::HashImpPtrVector::iterator i = pHash->m_comps.begin(); i != pHash->m_comps.end(); ++i )
        {
            (*i)->m_nErrorKatFailure++;
        }
    }
}

VOID
testLongMessageConsistency( HashMultiImp * pHash, int nInputBlocks,  LONGLONG line )
{
    //
    // Some implementations process long hash operations in smaller blocks, for example
    // to release the guarded region needed when using the XMM registers in the SaveXmm environment.
    // This could introduce errors that the other tests wouldn't catch.
    //
    // This test performs an internal consistency check on the hash function;
    // hashing a large buffer all-at-once and hashing it incrementally in small blocks.
    // This will detect any errors in the logic to process that divides long messages
    // into shorter ones.
    // This test is not intended to look for errors in the logic to handle multiple
    // append calls.
    //
    BYTE res1[MAX_INPUT_BLOCK_SIZE];
    BYTE res2[MAX_INPUT_BLOCK_SIZE];
    SIZE_T resultLen = pHash->resultLen();
    SIZE_T blockLen = pHash->inputBlockLen();
    BYTE * pBuf;
    SIZE_T cbBuf;
    BYTE * pbData;
    SIZE_T cbData;

    CHECK3( nInputBlocks > 64, "Length not large enough in line %lld", line );

    cbBuf = nInputBlocks * blockLen - blockLen / 3;     // use uneven length to check padding on longer messages.
    pBuf = new BYTE[cbBuf];
    CHECK( pBuf != NULL, "Out of memory" );

    CHECK( (ULONG) cbBuf == cbBuf, "Buffer too large" );

    CHECK( NT_SUCCESS( GENRANDOM(pBuf, (ULONG) cbBuf) ), "?" );

    pHash->hash( pBuf, cbBuf, res1, resultLen );

    pHash->init();
    pbData = pBuf;
    cbData = cbBuf;

    while( cbData > 0 )
    {
        SIZE_T todo = SYMCRYPT_MIN( cbData, blockLen );
        pHash->append( pbData, todo );
        pbData += todo;
        cbData -= todo;
    }

    pHash->result( res2, resultLen );
    CHECK3( memcmp( res1, res2, resultLen ) == 0, "Long message consistency failure in line %lld", line );

    delete[] pBuf;
}

VOID
testExport( HashMultiImp * pHash, PCBYTE pbExport, SIZE_T cbExport, LONGLONG line )
{
    //
    // We export the state after hashing 1657 bytes of the message consisting of
    // bytes 0, 1, 2, ..., 255, 0, 1, ...
    // 1657 is the golden ratio times 1024.
    //
    BYTE msg1[1657];
    BYTE msg2[1234];
    BYTE exportBlob[1024];
    SIZE_T exportLen;

    UNREFERENCED_PARAMETER( line );

    for( int i=0; i<sizeof( msg1 ); i++ )
    {
        msg1[i] = (BYTE) (i & 0xff);
    }

    CHECK( NT_SUCCESS( GENRANDOM(msg2, sizeof( msg2 )) ), "?" );

    pHash->init();
    pHash->append( msg1, sizeof( msg1 ) );

    pHash->exportSymCryptFormat( &exportBlob[0], sizeof( exportBlob ), &exportLen );

    if( exportLen != cbExport || memcmp( pbExport, exportBlob, cbExport ) != 0 )
    {
        print( "Wrong export result. \n"
            "Expected " );
        printHex( pbExport, cbExport );
        print( "\nGot      " );
        printHex( exportBlob, exportLen );
        print( "\n" );
        pHash->m_nErrorKatFailure++;
    }

    //
    // The SymCrypt implementation re-imports its own blob after the export,
    // so now we do a random continuation of the hash and check consistency.
    //
    pHash->append( msg2, sizeof( msg2 ) );
    pHash->result( msg2, pHash->resultLen() );
}


VOID
testHashKats()
{
    // fix this.
    KatData *katHash = getCustomResource( "kat_hash.dat", "KAT_HASH" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<HashMultiImp> pHashMultiImp;

    while( 1 )
    {
        katHash->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pHashMultiImp.reset( new HashMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pHashMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pHashMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "md" ) )
            {
                LONGLONG katLen = -1;
                if( katIsFieldPresent( katItem, "len" ) )
                {
                    katLen = katParseInteger( katItem, "len" );
                }
                CHECK3( katItem.dataItems.size() == (SIZE_T)(katLen == -1 ? 2 : 3), "Too many items in MD record ending at line %lld", katHash->m_line );
                BString katMsg = katParseData( katItem, "msg" );
                BString katMD = katParseData( katItem, "md" );
                testHashSingle( pHashMultiImp.get(), (PCBYTE) katMsg.data(), katMsg.size(), (PCBYTE) katMD.data(), katMD.size(), katHash->m_line );
                continue;
            }
            if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() == 2, "Too many items in RND record ending at line %lld", katHash->m_line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                BString katRnd = katParseData( katItem, "rnd" );
                testHashRandom( pHashMultiImp.get(), rrep, katRnd.data(), katRnd.size(), (katHash->m_line) );
                continue;
            }

            if( katIsFieldPresent( katItem, "long" ) )
            {
                CHECK3( katItem.dataItems.size() == 2, "Too many items in LONG record ending at line %lld", katHash->m_line );
                int katLen = (int) katParseInteger( katItem, "len" );
                BString katLong = katParseData( katItem, "long" );
                testLongMessage( pHashMultiImp.get(), katLen, katLong.data(), katLong.size(), katHash->m_line );
                continue;
            }

            if( katIsFieldPresent( katItem, "medium" ) )
            {
                CHECK3( katItem.dataItems.size() == 1, "Too many items in MEDIUM record ending at line %lld", katHash->m_line );
                int katLen = (int) katParseInteger( katItem, "medium" );
                // katLen = # input blocks to use in test
                testLongMessageConsistency( pHashMultiImp.get(), katLen, katHash->m_line );
                continue;
            }

            if( katIsFieldPresent( katItem, "export" ) )
            {
                CHECK3( katItem.dataItems.size() == 1, "Too many items in EXPORT record ending at line %lld", katHash->m_line );
                BString exportBlob = katParseData( katItem, "export" );
                testExport( pHashMultiImp.get(), exportBlob.data(), exportBlob.size(), katHash->m_line );
                continue;
            }

            FATAL2( "Unknown data record ending at line %lld", katHash->m_line );
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katHash;
}

#define MAX_PAR_HASHES  MAX_PARALLEL_HASH_STATES
#define MAX_PAR_OPS     MAX_PARALLEL_HASH_OPERATIONS

C_ASSERT( MAX_PAR_OPS >= 2*MAX_PAR_HASHES );


BOOL
testParallelHash( String &sep, String algName )
// Return TRUE if a test was run
{
    static const SIZE_T BUF_SIZE = 1 << 20;

    BCRYPT_MULTI_HASH_OPERATION         op[MAX_PAR_OPS];
    BYTE                                result[MAX_PAR_OPS][MAX_HASH_SIZE];
    BYTE                                expected[MAX_PAR_OPS][MAX_HASH_SIZE];
    SYMCRYPT_HASH_STATE                 scHash[MAX_PAR_HASHES];
    ULONG                               cbResult;
    ULONG                               cbInputBlock;
    PCSYMCRYPT_HASH                     pHash;
    std::unique_ptr<ParallelHashMultiImp> pParHash;
    PBYTE                               pBuf;
    ULONG                               i;
    ULONG                               j;
    SIZE_T                              opIdx;
    SIZE_T                              nResults;
    SIZE_T                              testCnt;

    pParHash.reset( new ParallelHashMultiImp( algName ) );

    if( pParHash->m_imps.size() == 0 )
    {
        return FALSE;
    } else {
        iprint( "%s%s", sep.c_str(), algName.c_str() );
        sep = ", ";
    }

    pBuf = new BYTE[BUF_SIZE];

    CHECK( NT_SUCCESS( GENRANDOM(pBuf, BUF_SIZE) ), "?" );

    cbResult = (ULONG) pParHash->resultLen();
    CHECK( cbResult == pParHash->resultLen(), "?" );
    cbInputBlock = (ULONG) pParHash->inputBlockLen();
    CHECK( cbInputBlock == pParHash->inputBlockLen(), "!" );
    pHash = pParHash->SymCryptHash();

    CHECK( cbResult <= MAX_HASH_SIZE, "?" );
    _Analysis_assume_( cbResult <= MAX_HASH_SIZE );

    //
    // Wipe buffers to 0 so that we are sure we don't just compare empty implementations against each other.
    // We have a single test against a real implementation below, and wiping ensures we don't have some
    // old values that happen to be the right ones laying about.
    //
    SymCryptWipe( result, sizeof( result ) );
    SymCryptWipe( expected, sizeof( expected ) );

    //
    // First some test cases to help debugging. These start easy and slowly get more complicated.
    // All of these were derived by simplifying errors in the big test case.
    //
    // Simple first test case: 1 hash, hash the empty message.
    //
    pParHash->init( 1 );
    op[0].iHash = 0;
    op[0].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
    op[0].pbBuffer = NULL;
    op[0].cbBuffer = 0;
    op[1].iHash = 0;
    op[1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
    op[1].pbBuffer = &result[0][0];
    op[1].cbBuffer = (ULONG) cbResult;
    pParHash->process( op, 2 );
    SymCryptHash( pHash, NULL, 0, &expected[0][0], cbResult );

    CHECK( memcmp( result[0], expected[0], cbResult ) == 0, "Test case 1 failure");

    //
    // Test: 8-parallel, short message, all identical.
    //
    pParHash->init( 8 );
    for( i=0; i<8; i++ )
    {
        op[2*i].iHash = i;
        op[2*i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[2*i].pbBuffer = (PBYTE)"abc";
        op[2*i].cbBuffer = 3;
        op[2*i+1].iHash = i;
        op[2*i+1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[2*i+1].pbBuffer = &result[i][0];
        op[2*i+1].cbBuffer = cbResult;
    }
    pParHash->process( op, 16 );

    SymCryptHash( pHash, (PCBYTE) "abc", 3, &expected[0][0], cbResult );

    for( i=0; i<8; i++ )
    {
        CHECK3( memcmp( result[i], expected[0], cbResult) == 0, "Test case 2 failure %d", i);
    }

    //
    // Test: 8-parallel, long message, all identical.
    //
    pParHash->init( 8 );
    for( i=0; i<8; i++ )
    {
        op[2*i].iHash = i;
        op[2*i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[2*i].pbBuffer = pBuf;
        op[2*i].cbBuffer = cbInputBlock;
        op[2*i+1].iHash = i;
        op[2*i+1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[2*i+1].pbBuffer = &result[i][0];
        op[2*i+1].cbBuffer = cbResult;
    }
    pParHash->process( op, 16 );

    SymCryptHash( pHash, pBuf, cbInputBlock, &expected[0][0], cbResult );

    for( i=0; i<8; i++ )
    {
        CHECK3( memcmp( result[i], expected[0], cbResult) == 0, "Test case 3 failure %d", i);
    }

    //
    // Test: 2-parallel, different sizes.
    //
    pParHash->init( 2 );
    for( j=0; j<4; j++ )
    {
        for( i=0; i<2; i++ )
        {
            op[2*i].iHash = i;
            op[2*i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
            op[2*i].pbBuffer = pBuf;
            op[2*i].cbBuffer = 30 + 512 * ((j >> i) & 1);
            op[2*i+1].iHash = i;
            op[2*i+1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            op[2*i+1].pbBuffer = &result[i][0];
            op[2*i+1].cbBuffer = cbResult;
            SymCryptHash( pHash, pBuf, op[2*i].cbBuffer, &expected[i][0], cbResult );
        }
        pParHash->process( op, 4 );
        for( i=0; i<2; i++ )
        {
            CHECK4( memcmp( result[i], expected[i], cbResult) == 0, "Test case 4 failure %d, %d", j, i);
        }
    }

    //
    // Test: multiple finalized hashes on the same state
    //
    pParHash->init( 4 );
    nResults = 0;
    opIdx = 0;
    for( i=0; i<4; i++ )
    {
        op[opIdx].iHash = i;
        op[opIdx].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[opIdx].pbBuffer = pBuf;
        op[opIdx].cbBuffer = 384 - 7;
        opIdx++;
    }

    // Finish hash 0 four times
    for( i=0; i<4; i++ )
    {
        op[opIdx].iHash = 0;        // <-- Always finish hash state 0
        op[opIdx].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[opIdx].pbBuffer = &result[nResults][0];
        op[opIdx].cbBuffer = cbResult;
        opIdx++;
        SymCryptHash( pHash, pBuf, i==0 ? 384 - 7 : 0, &expected[nResults][0], cbResult );
        nResults++;
    }

    // Finish the other ones 4 times
    for( i=0; i<4; i++ )
    {
        for( j=1; j<4; j++ )
        {
            op[opIdx].iHash = j;        // <-- Always finish hash state 0
            op[opIdx].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            op[opIdx].pbBuffer = &result[nResults][0];
            op[opIdx].cbBuffer = cbResult;
            opIdx++;
            SymCryptHash( pHash, pBuf, i==0 ? 384 - 7 : 0, &expected[nResults][0], cbResult );
            nResults++;
        }
    }
    pParHash->process( op, opIdx );
    for( i=0; i<nResults; i++ )
    {
        CHECK4( memcmp( result[i], expected[i], cbResult) == 0, "Test case 5 failure %d, %d", j, i);
    }

    //
    // Test: Single call, all same size. This is the most common use case at the moment.
    //

    for( testCnt=0; testCnt < 400; testCnt++ )
    {
        SIZE_T nHashes = g_rng.sizet( MAX_PAR_HASHES + 1 );
        pParHash->init( nHashes );
        SIZE_T size = g_rng.sizetNonUniform( 1<<16, 256, 1 );
        for( i=0; i<nHashes; i++ )
        {
            op[2*i].iHash = i;
            op[2*i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
            op[2*i].pbBuffer = pBuf + g_rng.sizet( BUF_SIZE / 2 );
            op[2*i].cbBuffer = (ULONG) size;
            CHECK( size <= BUF_SIZE / 2, "Buffer too small" );

            op[2*i+1].iHash = i;
            op[2*i+1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            op[2*i+1].pbBuffer = &result[i][0];
            op[2*i+1].cbBuffer = cbResult;
            SymCryptHash( pHash, op[2*i].pbBuffer, op[2*i].cbBuffer, &expected[i][0], cbResult );
        }

        pParHash->process( op, 2*nHashes );

        for( i=0; i<nHashes; i++ )
        {
            CHECK5( memcmp( &result[i][0], &expected[i][0], cbResult ) == 0, "Hash result mismatch A, %d, %d, %d", testCnt, nHashes, i );
        }

    }

    // Test: random mutations
    // We keep an array of states, perform randomly chosen updates,
    // and keep track of what we expect the result to be.
    //

    //iprint( "\nReset RNG ***  ");
    //SIZE_T sd = g_rng.sizet( 65536 );
    //SIZE_T sd = 48431;
    //SymCryptWipe( buf, BUF_SIZE );
    //g_rng.reset( (PCBYTE)&sd, sizeof( sd ) );
    //iprint( "\n****seed %d\n", sd);

    pParHash->init( MAX_PAR_HASHES );

    for( i=0; i<MAX_PAR_HASHES; i++ )
    {
        SymCryptHashInit( pHash, &scHash[i] );
    }

    for( int testCnt = 0; testCnt < 3000; testCnt++ )
    {
        //iprint( "\nTest case %d\n", testCnt );
        SIZE_T nHashes = g_rng.sizet( MAX_PAR_HASHES + 1 );
        //iprint( "Hashes %d--%d\n", startHash, startHash + nHashes - 1 );
        nResults = 0;

        if( nHashes == 0 )
        {
            //
            // We cannot define any valid operation because there is no valid hash index.
            // Just test the core function with no-ops and try again.
            //
            pParHash->process( NULL, 0 );
            continue;
        }

        SIZE_T nOps = g_rng.sizet( MAX_PAR_OPS + 1 );
        //iprint( "Operations: %d\n", nOps );

        for( i=0; i < nOps; i++ )
        {
            ULONG iHash = (ULONG) g_rng.sizet( nHashes );
            op[i].iHash = iHash;

            BOOLEAN fAppend = (g_rng.byte() & 5) != 0;

            if( fAppend )
            {
                op[i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
                op[i].pbBuffer = pBuf + g_rng.sizet( BUF_SIZE / 2 );
                op[i].cbBuffer = (ULONG) g_rng.sizetNonUniform( 1 << 16, 256, 1 );
                CHECK( op[i].pbBuffer + op[i].cbBuffer < &pBuf[BUF_SIZE], "?" );

                SymCryptHashAppend( pHash,  &scHash[ iHash ], op[i].pbBuffer, op[i].cbBuffer );
                //iprint( "  Append[%d] %d\n", iHash + startHash, parOp[i].cbBuffer );
            } else {
                op[i].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
                op[i].pbBuffer = &result[nResults][0];
                op[i].cbBuffer = cbResult;

                SymCryptHashResult( pHash, &scHash[ iHash ], expected[nResults], cbResult );
                //iprint( "     Result[%d]\n", iHash + startHash );
                nResults++;
            }
        }

        pParHash->process( op, nOps );

        BOOL error = FALSE;
        for( i=0; i<nResults; i++ )
        {
            if( memcmp( &result[i][0], &expected[i][0], cbResult ) != 0 )
            {
                iprint( "\nErr %d %d", testCnt, i );
                error = TRUE;
            }
        }
        CHECK( !error, "Hash result mismatch B" );

        /*
        // For debugging: test that the two copies of the state match.

        for( i=0; i< MAX_PAR_HASHES; i++ )
        {
            SYMCRYPT_SHA256_STATE s1, s2;
            SymCryptSha256StateCopy( &parState[i], &s1 );
            SymCryptSha256StateCopy( &hashes[i], &s2 );
            SymCryptSha256Result( &s1, &expected[0][0] );
            SymCryptSha256Result( &s2, &expected[1][0] );
            CHECK3( memcmp( &expected[0][0], &expected[1][0], 32 ) == 0, "Hash state mismatch %d", i  );
        }
        */
    }

    delete[] pBuf;
    return TRUE;
}


VOID
testHashAlgorithms()
{
    String sep;
    BOOL doneAnything = FALSE;

    testHashKats();

    sep = "    ";
    doneAnything |= testParallelHash( sep, "ParSha256" );
    doneAnything |= testParallelHash( sep, "ParSha384" );
    doneAnything |= testParallelHash( sep, "ParSha512" );
    if( doneAnything )
    {
        iprint( "\n" );
    }
}

#if 0

//
// hashSetIntermediateState
//
// Set the intermediate state of a hash computation to a known value.
// By default this value sets all bytes of the natural representation of the
// intermediate state to the ASCII value 'b'.
//
// This is an ugly hack that messes with internal data structures of the library,
// but that is the only way to test this.
//
VOID
hashSetIntermediateState( ALG_IMP_ID alg, _Inout_ HASH_STATE * state, ULONGLONG msgLen )
{
    CHECK( msgLen % hashBlockSize( alg ) == 0, "Odd length in set intermediate state" );

    //
    // Not all implementations support this, so we default to no implementations
    //
    state->alg = alg & ALG_MASK;

    if( alg & IMP_SYMCRYPT )
    {
        memset( &state->symcrypt, 'b', sizeof( state->symcrypt ) );

        switch( alg & ALG_MASK )
        {
	    case ALG_MD2:
            state->symcrypt.md2.bytesInBuffer = 0;
            break;

	    case ALG_MD4:
            state->symcrypt.md4.dataLength = msgLen;
            break;

	    case ALG_MD5:
            state->symcrypt.md5.dataLength = msgLen;
            break;

        case ALG_SHA1:
            state->symcrypt.sha1.dataLength = msgLen;
            break;

        case ALG_SHA256:
            state->symcrypt.sha256.dataLength = msgLen;
            break;

        case ALG_SHA384:
            state->symcrypt.sha384.sha512.dataLengthH = 0;
            state->symcrypt.sha384.sha512.dataLengthL = msgLen;
            break;

        case ALG_SHA512:
            state->symcrypt.sha512.dataLengthH = 0;
            state->symcrypt.sha512.dataLengthL = msgLen;
            break;

        default:
            FATAL( "Unknown alg" );
        }

        state->alg |= IMP_SYMCRYPT;
    }

    if( alg & IMP_RSA32 )
    {
        memset( &state->rsa32, 'b', sizeof( state->rsa32 ) );

        switch( alg & ALG_MASK )
        {
        case ALG_MD2:
            state->rsa32.md2.count = 0;
            break;

        case ALG_MD4:
            state->rsa32.md4.count[0] = (ULONG) (msgLen * 8);
            state->rsa32.md4.count[1] = (ULONG) (msgLen >> 29);
            break;

        case ALG_MD5:
            state->rsa32.md5.i[0] = (ULONG) (msgLen * 8);
            state->rsa32.md5.i[1] = (ULONG) (msgLen >> 29);
            break;

        case ALG_SHA1:
            state->rsa32.sha1.count[1] = (ULONG) msgLen;
            state->rsa32.sha1.count[0] = (ULONG) (msgLen >> 32);
            break;

        case ALG_SHA256:
            state->rsa32.sha256.count[1] = (ULONG) msgLen;
            state->rsa32.sha256.count[0] = (ULONG) (msgLen >> 32);
            break;

        case ALG_SHA384:
            state->rsa32.sha384.count[1] = msgLen;
            state->rsa32.sha384.count[0] = 0;
            break;

        case ALG_SHA512:
            state->rsa32.sha512.count[1] = msgLen;
            state->rsa32.sha512.count[0] = 0;
            break;

        default:
            CHECK( FALSE, "Unknown hash alg" );
        }

        state->alg |= IMP_RSA32;
    }

    //
    // CAPI & CNG do not support setting the intermediate state
    //
}

//
// Perform a simple input/output test
//
VOID
hashSimpleTest( ALG_IMP_ID alg,
               _In_reads_( cbData )    PCBYTE pbData,
                                        SIZE_T cbData,
               _In_reads_( cbResult )  PCBYTE pbResult,
                                        SIZE_T cbResult )
{
    BYTE res[1000];
    HASH_STATE state;
    SIZE_T i;

    CHECK( cbResult == hashResultSize( alg ), "Wrong result size" );
    CHECK( cbResult <= sizeof( res ), "Hash result too large" );

    //
    // First we test it in one big call
    //
    CHECK( alg == hash( alg, pbData, cbData, res, cbResult ), "Implementation failure" );
    checkResult( "hashSimpleTest", alg, res, cbResult, pbResult, "Self test failure" );

    //
    // Then using a byte-by-byte append
    //
    hashInit( alg, &state );
    for( i=0; i<cbData; i++ ) {
        hashAppend( alg, &state, &pbData[i], 1 );
    }
    CHECK( alg == hashResult( alg, &state, res, cbResult ), "Implementation failure" );
    checkResult( "hashSimpleTest2", alg, res, cbResult, pbResult, "Self test failure" );
}

//
// Test inputs consisting of many 'a' characters
//
VOID
hashManyAsTest(                         ALG_IMP_ID alg,
                                        SIZE_T cNumberOfAs,
               _In_reads_( cbResult )   PCBYTE pbResult,
                                        SIZE_T cbResult )
{
    BYTE buf[1024];
    BYTE rndState[ 1024 ];
    SIZE_T rndIndex;
    PBYTE bigBuf;
    HASH_STATE state;
    SIZE_T size;
    SIZE_T stepSize;


    CHECK( cbResult == hashResultSize( alg ), "Wrong result size" );
    CHECK( cbResult < 1000, "Result size too large" );

    memset( rndState, 0, cbResult );
    rndIndex = cbResult;

    //
    // First we run the test using a bunch of small appends
    //
    memset( buf, 'a', sizeof( buf ) );
    hashInit( alg, &state );

    size = cNumberOfAs;
    while( size > sizeof( buf ) )
    {
        if( rndIndex >= cbResult ) {
            hash( alg, rndState, cbResult, rndState, cbResult );
            rndIndex = 0;
        }
        stepSize = sizeof( buf ) -  rndState[rndIndex++];
        hashAppend( alg, &state, buf, stepSize );
        size -= stepSize;
    }

    hashAppend( alg, &state, buf, size );

    CHECK( alg == hashResult( alg, &state, buf, cbResult ), "Missing implementation" );

    checkResult( "hashManyAsTest", alg, buf, cbResult, pbResult, "Many 'a'-s test failure" );

    //
    // Now we run the same test in one big hash call
    //
    bigBuf = malloc( cNumberOfAs );
    CHECK( bigBuf != NULL, "Out of memory" );
    memset( bigBuf, 'a', cNumberOfAs );

    CHECK( alg == hash( alg, bigBuf, cNumberOfAs, buf, cbResult ), "Missing implementation" );

    checkResult( "hashManyAsTest2", alg, buf, cbResult, pbResult, "Many 'a'-s test failure" );

    free( bigBuf );
}

//
// A self-driven pseudo-random test for a hash function
// This test is geared towards finding errors in the internal buffering
// and actual hash algorithm.
//
// This uses a single 1kB buffer and runs a load of hash operations on it.
//
VOID
hashRandomTest(                         ALG_IMP_ID  alg,
                                        SIZE_T      bufSize,
                                        ULONG       iterations,
                _In_reads_( cbResult ) PCBYTE      pbResult,
                                        SIZE_T      cbResult )
{
    BYTE buf[1024];
    HASH_STATE state;
    ALG_IMP_ID resAlg;
    SIZE_T idx, outputIdx, pos, len, nAppends;
    BYTE res[128];

    CHECK( cbResult == hashResultSize( alg ), "Wrong result size" );
    CHECK( cbResult < bufSize/2, "Result size too large" );
    CHECK( cbResult <= sizeof( res ), "Result too large" );
    CHECK( bufSize <= sizeof( buf ), "Buffer size too large" );

    CHECK( iterations > 0, "Hash randomtest too few iterations" );

    memset( buf, 0, bufSize );
    idx = 0;

    while( iterations-- > 0 )
    {
        //
        // The first byte tells us where the result of this iteration will go in the buffer.
        //
        outputIdx = (idx + buf[idx]) % bufSize;
        idx = (idx + 1) % bufSize;

        //
        // The next byte is the # appends that we will do; 0 appends means we call the
        // hash function directly without init/append/result.
        //
        nAppends = buf[idx] % 5;
        idx = (idx + 1) % bufSize;
        if( nAppends == 0 )
        {
            randomTestGetSubstringPosition( buf, bufSize, &idx, &pos, &len );
            resAlg = hash( alg, &buf[pos], len, res, cbResult );
        } else {
            hashInit( alg, &state );
            while( nAppends-- > 0 )
            {
                randomTestGetSubstringPosition( buf, bufSize, &idx, &pos, &len );
                hashAppend( alg, &state, &buf[pos], len );
            }
            resAlg = hashResult( alg, &state, res, cbResult );
        }

        CHECK( resAlg == alg, "Algorithm type mismatch" );

        if( outputIdx + cbResult <= bufSize )
        {
            memcpy( &buf[outputIdx], res, cbResult );
        } else {
            len = bufSize - outputIdx;
            memcpy( &buf[outputIdx], res, len );
            memcpy( &buf[0], &res[len], cbResult - len );
        }
        idx = outputIdx;
    }

    CHECK( alg == hash( alg, buf, bufSize, buf, cbResult ), "Alg mismatch" );
    checkResult( "hashRandomTest", alg, buf, cbResult, pbResult, "hash random test failure" );
}


//
// hashLongMessageTest
//
// X_n is defined as an n-byte string (where n is a multiple of the input block size)
// that results in the chaining state being all 'b' bytes after
// X_n has been processed.
//
// The test takes n as input and hashes X_n followed by 1000 bytes 'a'.
//
VOID
hashLongMessageTest( ALG_IMP_ID  alg,
                 ULONGLONG n,
                _In_reads_( cbResult ) PCBYTE  pbResult,
                                        SIZE_T  cbResult )
{
    HASH_STATE state;
    ALG_IMP_ID algRes, algExpected;
    BYTE buf[1000];
    BYTE res[1000];
    int i;

    CHECK( cbResult == hashResultSize( alg ), "Long message length is not multiple of input block size" );

    //
    // Only Symcrypt and RSA32 implementations can run this test.
    // Compute the set of result algorithms we expect.
    //
    algExpected = alg & (IMP_SYMCRYPT | IMP_RSA32 | ALG_MASK);

    memset( buf, 'a', sizeof( buf ) );

    hashSetIntermediateState( alg, &state, n );
    hashAppend( alg, &state, buf, sizeof( buf ) );
    algRes = hashResult( alg, &state, res, cbResult );
    CHECK( algRes == algExpected, "Alg mismatch" );

    checkResult( "hashLongMessageTest", alg, res, cbResult, pbResult, NULL );//"Long message failure 1" );

    //
    // Do it again byte-by-byte
    //
    hashSetIntermediateState( alg, &state, n );
    for( i=0; i<1000; i++ ) {
        hashAppend( alg, &state, buf, 1 );
    }
    algRes = hashResult( alg, &state, res, cbResult );
    CHECK( algRes == algExpected, "Alg mismatch" );

    checkResult( "hashLongMessageTest2", alg, res, cbResult, pbResult, NULL );//"Long message failure 2" );

    //
    // Do it again, 5 bytes at a time
    //
    hashSetIntermediateState( alg, &state, n );
    for( i=0; i<200; i++ ) {
        hashAppend( alg, &state, buf, 5 );
    }
    algRes = hashResult( alg, &state, res, cbResult );
    CHECK( algRes == algExpected, "Alg mismatch" );

    checkResult( "hashLongMessageTest3", alg, res, cbResult, pbResult, NULL );//"Long message failure 3" );
}

#endif
