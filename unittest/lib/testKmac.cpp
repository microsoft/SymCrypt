//
// TestKmac.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for KMAC.
//

#include "precomp.h"


#define MAX_KMAC_RESULT_SIZE    1024
#define MAX_INPUT_BLOCK_SIZE    168

class KmacMultiImp : public KmacImplementation
{
public:
    KmacMultiImp( String algName );
    ~KmacMultiImp();

private:
    KmacMultiImp( const KmacMultiImp& );
    VOID operator=( const KmacMultiImp& );

public:

    typedef std::vector<KmacImplementation *> KmacImpPtrVector;

    KmacImpPtrVector m_imps;                    // Implementations we use

    KmacImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    VOID addImplementation(KmacImplementation * pKmacImp );
    VOID setImpName();

    virtual SIZE_T inputBlockLen();

    virtual void init(  PCBYTE pbCustomizationStr,
                        SIZE_T cbCustomizationStr,
                        PCBYTE pbKey,
                        SIZE_T cbKey);

    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual void result( PBYTE pbResult, SIZE_T cbResult );
    virtual void mac(PCBYTE pbCustomizationStr,
                    SIZE_T  cbCustomizationStr,
                    PCBYTE  pbKey,
                    SIZE_T  cbKey,
                    PCBYTE  pbData,
                    SIZE_T  cbData,
                    PBYTE   pbResult,
                    SIZE_T  cbResult);

    virtual void xof(PCBYTE pbCustomizationStr,
                    SIZE_T  cbCustomizationStr,
                    PCBYTE  pbKey,
                    SIZE_T  cbKey,
                    PCBYTE  pbData,
                    SIZE_T  cbData,
                    PBYTE   pbResult,
                    SIZE_T  cbResult);
};

VOID
KmacMultiImp::setImpName()
{
    String sumAlgName;
    char * sepStr = "<";

    for(KmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

KmacMultiImp::KmacMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<KmacImplementation>( algName, &m_imps );
}

VOID
KmacMultiImp::addImplementation(KmacImplementation * pKmacImp )
{
    m_imps.push_back( pKmacImp );
    setImpName();
}

KmacMultiImp::~KmacMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for(KmacImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

SIZE_T KmacMultiImp::inputBlockLen()
{
    SIZE_T res = MAX_SIZE_T;
    for(KmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->inputBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent input block len" );
        res = v;
    }

    return res;
}

VOID KmacMultiImp::xof( PCBYTE  pbCustomizationStr, 
                        SIZE_T  cbCustomizationStr,
                        PCBYTE  pbKey, 
                        SIZE_T  cbKey,
                        PCBYTE  pbData, 
                        SIZE_T  cbData, 
                        PBYTE   pbResult,
                        SIZE_T  cbResult )
{
    BYTE    buf[MAX_KMAC_RESULT_SIZE];
    ResultMerge res;

    CHECK( cbResult <= sizeof( buf ), "??" );

    for(KmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SymCryptWipe( buf, cbResult );
        (*i)->xof(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, buf, cbResult );
        res.addResult( (*i), buf, cbResult );
    }

    res.getResult( pbResult, cbResult );
}

VOID KmacMultiImp::mac( PCBYTE  pbCustomizationStr, 
                        SIZE_T  cbCustomizationStr,
                        PCBYTE  pbKey, 
                        SIZE_T  cbKey,
                        PCBYTE  pbData, 
                        SIZE_T  cbData, 
                        PBYTE   pbResult,
                        SIZE_T  cbResult )
{
    BYTE    buf[MAX_KMAC_RESULT_SIZE];
    ResultMerge res;

    CHECK(cbResult <= sizeof(buf), "??");

    for (KmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i)
    {
        SymCryptWipe(buf, cbResult);
        (*i)->mac(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, buf, cbResult);
        res.addResult((*i), buf, cbResult);
    }

    res.getResult(pbResult, cbResult);
}

VOID KmacMultiImp::init(PCBYTE pbCustomizationStr, 
                        SIZE_T cbCustomizationStr, 
                        PCBYTE pbKey, 
                        SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.assign( m_imps.begin(), m_imps.end() );

    for( KmacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->init(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey);
    }
}

VOID KmacMultiImp::append( PCBYTE pbData, SIZE_T cbData )
{
   for( KmacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        (*i)->append( pbData, cbData );
   }
}

VOID KmacMultiImp::extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe)
{
    BYTE buf[MAX_KMAC_RESULT_SIZE];
    ResultMerge res;

    CHECK(cbResult <= sizeof(buf), "?");

    for (KmacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i)
    {
        (*i)->extract(buf, cbResult, bWipe);
        res.addResult((*i), buf, cbResult);
    }

    res.getResult(pbResult, cbResult);
}

VOID KmacMultiImp::result( PBYTE pbResult, SIZE_T cbResult )
{
   BYTE buf[MAX_KMAC_RESULT_SIZE];
   ResultMerge res;

   CHECK( cbResult <= sizeof( buf ), "?" );

   for(KmacImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, cbResult );
        (*i)->result( buf, cbResult );
        res.addResult( (*i), buf, cbResult );
   }

   res.getResult( pbResult, cbResult );
}

_Use_decl_annotations_
VOID
KmacImplementation::mac(PCBYTE  pbCustomizationStr, 
                        SIZE_T  cbCustomizationStr,
                        PCBYTE  pbKey,
                        SIZE_T  cbKey,
                        PCBYTE  pbData,
                        SIZE_T  cbData, 
                        PBYTE   pbResult,
                        SIZE_T  cbResult )
{
    init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey );
    append( pbData, cbData );
    result( pbResult, cbResult );
}

_Use_decl_annotations_
VOID
KmacImplementation::xof(PCBYTE  pbCustomizationStr, 
                        SIZE_T  cbCustomizationStr,
                        PCBYTE  pbKey,
                        SIZE_T  cbKey,
                        PCBYTE  pbData,
                        SIZE_T  cbData, 
                        PBYTE   pbResult,
                        SIZE_T  cbResult )
{
    init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey );
    append( pbData, cbData );
    extract( pbResult, cbResult, TRUE);
}


VOID
testKmacSingle(                                 KmacImplementation*  pKmac,
               _In_reads_( cbCustomizationStr ) PCBYTE  pbCustomizationStr,
                                                SIZE_T  cbCustomizationStr,
               _In_reads_( cbKey )              PCBYTE  pbKey,
                                                SIZE_T  cbKey,
               _In_reads_( cbData )             PCBYTE  pbData,
                                                SIZE_T  cbData,
               _In_reads_( cbResult )           PCBYTE  pbResult,
                                                SIZE_T  cbResult,
                                                BOOL    bXofMode,
                                                LONGLONG line)
{
    
    BYTE res[MAX_KMAC_RESULT_SIZE];

    CHECK3(cbResult <= sizeof(res), "KMAC result too large at line %lld", line);

    memset( res, 0, sizeof(res));
    
    if(bXofMode)
        pKmac->xof( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, res, cbResult );
    else
        pKmac->mac( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, res, cbResult );


    if( memcmp( res, pbResult, cbResult) != 0 )
    {
        print( "Wrong mac result. \n"
            "Expected " );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );
        pKmac->m_nErrorKatFailure++;
    }


    memset( res, 0, sizeof(res) );
    pKmac->init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey );

    PCBYTE pbDataLeft = pbData;
    SIZE_T bytesLeft = cbData;

    while( bytesLeft > 0 )
    {
        SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
        pKmac->append( pbDataLeft, todo );
        pbDataLeft += todo;
        bytesLeft -= todo;
    }

    if (bXofMode)
    {
        // Only XOF mode allows incremental extraction
        PBYTE pbExtract = res;
        bytesLeft = cbResult;
        while (bytesLeft > 0)
        {
            SIZE_T todo = g_rng.sizetNonUniform(bytesLeft + 1, 32, 2);
            pKmac->extract(pbExtract, todo, FALSE);
            pbExtract += todo;
            bytesLeft -= todo;
        }
    }
    else
    {
        pKmac->result(res, cbResult);
    }

    if( memcmp( res, pbResult, cbResult ) != 0 )
    {
        print( "Wrong mac result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( res, cbResult );
        print( "\n" );

        pKmac->m_nErrorKatFailure++;
    }
}

VOID
testKmacRange(              KmacImplementation*     pKmac,
                            SIZE_T                  cbMessage,
                            SIZE_T                  cbKey,
                            SIZE_T                  cbCustomStr,
                            SIZE_T                  cbOutput,
    _In_reads_(cbResult)    PCBYTE                  pbResult,
                            SIZE_T                  cbResult,
                            LONGLONG                line)
{
    SYMCRYPT_SHA3_256_STATE sha3state;
    BYTE result[SYMCRYPT_SHA3_256_RESULT_SIZE];

    const SIZE_T MAX_INPUT_SIZE = 3 * 200;
    unsigned char input[MAX_INPUT_SIZE];
    unsigned char key[MAX_INPUT_SIZE];
    unsigned char customStr[MAX_INPUT_SIZE];
    unsigned char output[128];

    CHECK3(cbOutput <= sizeof(output), "Output size too large at line %lld", line);

    CHECK3(cbResult == sizeof(result), "Incorrect range result size at line %lld", line);

    // Initialize inputs
    for (unsigned int i = 0; i < sizeof(input); i++)
    {
        input[i] = (i & 0xff) | 0x80;
    }

    for (unsigned int i = 0; i < sizeof(key); i++)
    {
        key[i] = ('K' + i) & 0xff;
    }

    for (unsigned int i = 0; i < sizeof(customStr); i++)
    {
        customStr[i] = ('S' + i) & 0xff;
    }

    SymCryptSha3_256Init(&sha3state);

    for (SIZE_T mlen = 0; mlen <= cbMessage; mlen++)
    {
        for (SIZE_T klen = 0; klen <= cbKey; klen++)
        {
            for (SIZE_T slen = 0; slen <= cbCustomStr; slen++)
            {
                pKmac->mac(customStr, slen, key, klen, input, mlen, output, cbOutput);
                SymCryptSha3_256Append(&sha3state, output, cbOutput);
            }
        }
    }

    SymCryptSha3_256Result(&sha3state, result);

    if (memcmp(result, pbResult, cbResult) != 0)
    {
        print("Wrong kmac range test result. \n"
            "Expected ");
        printHex(pbResult, cbResult);
        print("\nGot      ");
        printHex(result, SYMCRYPT_SHA3_256_RESULT_SIZE);
        print("\n");
        pKmac->m_nErrorKatFailure++;
    }
}


VOID
testKmacKats()
{
    KatData *katKmac = getCustomResource( "kat_kmac.dat", "KAT_KMAC" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<KmacMultiImp> pKmacMultiImp;

    while( 1 )
    {
        katKmac->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pKmacMultiImp.reset( new KmacMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pKmacMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if (katIsFieldPresent(katItem, "range"))
            {
                LONGLONG katMaxInputSize = 0;
                LONGLONG katMaxKeySize = 0;
                LONGLONG katMaxCustomStrSize = 0;

                if (katIsFieldPresent(katItem, "maxinputsize"))
                {
                    katMaxInputSize = katParseInteger(katItem, "maxinputsize");
                }

                if (katIsFieldPresent(katItem, "maxkeysize"))
                {
                    katMaxKeySize = katParseInteger(katItem, "maxkeysize");
                }

                if (katIsFieldPresent(katItem, "maxcustomstrsize"))
                {
                    katMaxCustomStrSize = katParseInteger(katItem, "maxcustomstrsize");
                }

                CHECK3((katMaxInputSize || katMaxKeySize || katMaxCustomStrSize), "Invalid range test record ending at line %lld", katKmac->m_line);

                UINT64 katOutputSize = (UINT64)katParseInteger(katItem, "outputsize");
                BString katRange = katParseData(katItem, "range");

                testKmacRange(pKmacMultiImp.get(),
                    katMaxInputSize, katMaxKeySize, katMaxCustomStrSize, katOutputSize,
                    katRange.data(), katRange.size(), (katKmac->m_line));
                continue;
            }


            if( katIsFieldPresent( katItem, "output" ) )
            {
                CHECK3( (katItem.dataItems.size() == 5), "Invalid number of items in KAT record ending at line %lld", katKmac->m_line );
                BString katKey = katParseData(katItem, "key");
                BString katMsg = katParseData( katItem, "msg" );
                BString katS = katParseData(katItem, "customstr");
                LONGLONG katLen = katParseInteger(katItem, "outputlen");
                BString katOutput = katParseData(katItem, "output");

                if (katLen != 0)
                {
                    // L must match output length unless L=0 (KMACXOF)
                    CHECK3((katLen / 8) == (LONGLONG)katOutput.size(), "L does not match the length of the output at line %lld", katKmac->m_line);
                }

                testKmacSingle( pKmacMultiImp.get(), 
                                (PCBYTE) katS.data(), katS.size(), 
                                (PCBYTE) katKey.data(), katKey.size(), 
                                (PCBYTE) katMsg.data(), katMsg.size(), 
                                (PCBYTE) katOutput.data(), katOutput.size(),
                                katLen == 0, // bXofMode
                                katKmac->m_line );
                continue;
            }


            FATAL2( "Unknown data record ending at line %lld", katKmac->m_line );
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katKmac;
}


VOID
testKmacAlgorithms()
{
    testKmacKats();
}
