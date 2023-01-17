//
// TestXof.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for XOFs.
//

#include "precomp.h"


#define MAX_XOF_RESULT_SIZE     1024
#define MAX_INPUT_BLOCK_SIZE    168

class XofMultiImp : public XofImplementation
{
public:
    XofMultiImp( String algName );
    ~XofMultiImp();

private:
    XofMultiImp( const XofMultiImp& );
    VOID operator=( const XofMultiImp& );

public:

    typedef std::vector<XofImplementation *> XofImpPtrVector;

    XofImpPtrVector m_imps;                    // Implementations we use

    XofImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    VOID addImplementation( XofImplementation * pXofImp );
    VOID setImpName();

    virtual SIZE_T inputBlockLen();

    virtual void init();
    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual void result( PBYTE pbResult, SIZE_T cbResult );
    virtual VOID xof( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult );
};

VOID
XofMultiImp::setImpName()
{
    String sumAlgName;
    char * sepStr = "<";

    for( XofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

XofMultiImp::XofMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<XofImplementation>( algName, &m_imps );
}

VOID
XofMultiImp::addImplementation( XofImplementation * pXofImp )
{
    m_imps.push_back( pXofImp );
    setImpName();
}


XofMultiImp::~XofMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( XofImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

SIZE_T XofMultiImp::inputBlockLen()
{
    SIZE_T res = MAX_SIZE_T;
    for( XofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->inputBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent input block len" );
        res = v;
    }

    return res;
}

VOID XofMultiImp::xof( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[MAX_XOF_RESULT_SIZE];
    ResultMerge res;

    CHECK( cbResult <= sizeof( buf ), "??" );

    for( XofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SymCryptWipe( buf, cbResult );
        (*i)->xof( pbData, cbData, buf, cbResult );
        res.addResult( (*i), buf, cbResult );
    }

    res.getResult( pbResult, cbResult );
}

VOID XofMultiImp::init()
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.assign( m_imps.begin(), m_imps.end() );

    for( XofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->init();
    }
}

VOID XofMultiImp::append( PCBYTE pbData, SIZE_T cbData )
{
   for( XofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        (*i)->append( pbData, cbData );
   }
}

VOID XofMultiImp::extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe)
{
    BYTE buf[MAX_XOF_RESULT_SIZE];
    ResultMerge res;

    CHECK(cbResult <= sizeof(buf), "?");

    for (XofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i)
    {
        (*i)->extract(buf, cbResult, bWipe);
        res.addResult((*i), buf, cbResult);
    }

    res.getResult(pbResult, cbResult);
}

VOID XofMultiImp::result( PBYTE pbResult, SIZE_T cbResult )
{
   BYTE buf[MAX_XOF_RESULT_SIZE];
   ResultMerge res;

   CHECK( cbResult <= sizeof( buf ), "?" );

   for( XofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, cbResult );
        (*i)->extract( buf, cbResult, TRUE );
        res.addResult( (*i), buf, cbResult );
   }

   res.getResult( pbResult, cbResult );
}

_Use_decl_annotations_
VOID
XofImplementation::xof( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    init();
    append( pbData, cbData );
    result( pbResult, cbResult );
}


VOID
testXofSingle(                          XofImplementation*      pXof,
               _In_reads_( cbData )     PCBYTE                  pbData,
                                        SIZE_T                  cbData,
               _In_reads_( cbResult )   PCBYTE                  pbResult,
                                        SIZE_T                  cbResult,
                                        LONGLONG                line)
{
    
    BYTE res[MAX_XOF_RESULT_SIZE];

    CHECK3(cbResult <= sizeof(res), "Xof result too large at line %lld", line);

    memset( res, 0, sizeof(res));
    pXof->xof( pbData, cbData, res, cbResult);

    if( memcmp( res, pbResult, cbResult) != 0 )
    {
        print( "Wrong hash result. \n"
            "Expected " );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );
        pXof->m_nErrorKatFailure++;
    }


    memset( res, 0, sizeof(res) );
    pXof->init();

    PCBYTE pbDataLeft = pbData;
    SIZE_T bytesLeft = cbData;

    while( bytesLeft > 0 )
    {
        SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
        pXof->append( pbDataLeft, todo );
        pbDataLeft += todo;
        bytesLeft -= todo;
    }

    PBYTE pbExtract = res;
    bytesLeft = cbResult;
    while (bytesLeft > 0)
    {
        SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
        pXof->extract(pbExtract, todo, FALSE);
        pbExtract += todo;
        bytesLeft -= todo;
    }

    if( memcmp( res, pbResult, cbResult ) != 0 )
    {
        print( "Wrong hash result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pXof->m_nErrorKatFailure++;
    }
}


VOID testXofMonteCarlo(                         XofImplementation*  pXof,
                        _In_reads_( cbSeed )    PCBYTE              pbSeed,
                                                SIZE_T              cbSeed,
                                                LONGLONG            uMinOutputBytes,
                                                LONGLONG            uMaxOutputBytes,
                                                LONGLONG            uIteration,
                        _In_reads_( cbResult )  PCBYTE              pbResult,
                                                SIZE_T              cbResult,
                                                LONGLONG            line)
{
    BYTE md[MAX_XOF_RESULT_SIZE];
    const LONGLONG range = (uMaxOutputBytes - uMinOutputBytes + 1);
    LONGLONG outputLength = uMaxOutputBytes;

    CHECK3(cbResult <= MAX_XOF_RESULT_SIZE, "Xof result too large at line %lld", line);

    //
    // In the MonteCarlo test, the input is always 128-bits.
    // md[] gets its initial value from the seed. If the seed is greater than 
    // 16 bytes then truncate it, and pad with zero if it's less than 16-bytes.
    //
    if (cbSeed >= 16)
    {
        memcpy(md, pbSeed, 16);
    }
    else
    {
        memcpy(md, pbSeed, cbSeed);
        memset(md + cbSeed, 0, 16 - cbSeed);
    }

    for (LONGLONG j = 0; j <= uIteration; j++)
    {
        for (UINT32 i = 0; i < 1000; i++)
        {
            pXof->xof(md, 16, md, outputLength);

            if (outputLength < 16)
            {
                // Zero pad to 128-bits
                memset(&md[outputLength], 0, 16 - outputLength);
            }

            outputLength = uMinOutputBytes + (SYMCRYPT_LOAD_MSBFIRST16(&md[outputLength - 2]) % range);
        }
    }

    if (memcmp(md, pbResult, cbResult) != 0)
    {
        print("Wrong MonteCarlo result in line %lld. \n"
            "Expected ", line);
        printHex(pbResult, cbResult);
        print("\nGot      ");
        printHex(md, cbResult);
        print("\n");

        pXof->m_nErrorKatFailure++;
    }
}

VOID
testXofRandom(XofMultiImp* pXof, int rrep, PCBYTE pbResult, SIZE_T cbResult, LONGLONG line)
{
    const UINT64 RND_BUF_SIZE = 1 << 12;
    BYTE buf[RND_BUF_SIZE];
    BYTE res[64];
    Rng rng;

    //
    // Seed our RNG with the algorithm name
    //
    rng.reset((PCBYTE)pXof->m_algorithmName.data(), pXof->m_algorithmName.size());

    const SIZE_T bufSize = pXof->inputBlockLen() * 4;
    CHECK(bufSize <= sizeof(buf), "Input block len too large");

    memset(buf, 0, sizeof(buf));
    SIZE_T destIdx = 0;
    SIZE_T nAppends;
    SIZE_T pos;
    SIZE_T len;
    SIZE_T cbHash = cbResult;
    CHECK(cbHash <= sizeof(res), "Hash result too long");

    for (int i = 0; i < rrep; i++)
    {
        //
        // The first byte tells us where the result of this iteration will go in the buffer.
        //
        destIdx = rng.sizet(bufSize);

        //
        // The next byte is the # appends that we will do; 0 appends means we call the
        // hash function directly without init/append/result.
        //
        nAppends = rng.byte() % 5;
        if (nAppends == 0)
        {
            rng.randomSubRange(bufSize, &pos, &len);
            pXof->xof(&buf[pos], len, res, cbHash);
        }
        else {
            pXof->init();
            for (SIZE_T j = 0; j < nAppends; j++)
            {
                rng.randomSubRange(bufSize, &pos, &len);
                pXof->append(&buf[pos], len);
            }
            pXof->result(res, cbHash);
        }

        if (destIdx + cbHash <= bufSize)
        {
            memcpy(&buf[destIdx], res, cbHash);
        }
        else {
            len = bufSize - destIdx;
            memcpy(&buf[destIdx], res, len);
            memcpy(&buf[0], &res[len], cbHash - len);
        }

    }

    pXof->xof(&buf[0], bufSize, res, cbHash);
    if (cbResult != 0)
    {
        CHECK5(cbResult == cbHash, "Wrong result length in line %lld, expected %d, got %d", line, cbHash, cbResult);
        if (memcmp(res, pbResult, cbHash) != 0)
        {

            print("Wrong XOF result in line %lld. \n"
                "Expected ", line);
            printHex(pbResult, cbResult);
            print("\nGot      ");
            printHex(res, cbResult);
            print("\n");

            pXof->m_nErrorKatFailure++;
        }

    }

}

VOID
testXofKats()
{
    KatData *katXof = getCustomResource( "kat_xof.dat", "KAT_XOF" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<XofMultiImp> pXofMultiImp;

    while( 1 )
    {
        katXof->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pXofMultiImp.reset( new XofMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pXofMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pXofMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "minimumoutputlengthbits") )
            {
                //
                // Monte Carlo test
                //
                LONGLONG minOutputBytes = katParseInteger(katItem, "minimumoutputlengthbits") / 8;
                LONGLONG maxOutputBytes = katParseInteger(katItem, "maximumoutputlengthbits") / 8;
                LONGLONG iteration = katParseInteger(katItem, "count");
                LONGLONG outputSize = katParseInteger(katItem, "outputlen") / 8;

                BString katSeed = katParseData(katItem, "msg");
                BString katOutput = katParseData(katItem, "output");
                CHECK3(outputSize == (LONGLONG)katOutput.size(), "Outputlen does not match the length of the output at line %lld", katXof->m_line);

                testXofMonteCarlo(pXofMultiImp.get(),
                                (PCBYTE)katSeed.data(), katSeed.size(), 
                                minOutputBytes, maxOutputBytes, 
                                iteration, 
                                (PCBYTE)katOutput.data(), katOutput.size(), 
                                katXof->m_line);
                continue;
            }

            if (katIsFieldPresent(katItem, "rnd"))
            {
                //
                // Random hashing test
                //
                CHECK3(katItem.dataItems.size() == 2, "Too many items in RND record ending at line %lld", katXof->m_line);
                int rrep = (int)katParseInteger(katItem, "rrep");
                BString katRnd = katParseData(katItem, "rnd");
                testXofRandom(pXofMultiImp.get(), rrep, katRnd.data(), katRnd.size(), (katXof->m_line));
                continue;
            }

            if( katIsFieldPresent( katItem, "output" ) )
            {
                BString katMsg = katParseData( katItem, "msg" );
                BString katMD = katParseData( katItem, "output" );

                LONGLONG katLen = -1;
                if (katIsFieldPresent(katItem, "outputlen"))
                {
                    katLen = katParseInteger(katItem, "outputlen") / 8;
                    CHECK3(katLen == (LONGLONG)katMD.size(), "Outputlen does not match the length of the output at line %lld", katXof->m_line);
                }

                testXofSingle( pXofMultiImp.get(), (PCBYTE) katMsg.data(), katMsg.size(), (PCBYTE) katMD.data(), katMD.size(), katXof->m_line );
                continue;
            }


            FATAL2( "Unknown data record ending at line %lld", katXof->m_line );
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katXof;
}


VOID
testXofAlgorithms()
{
    testXofKats();
}
