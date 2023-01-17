//
// TestCustomizableXof.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Test code for customizable XOFs.
//

#include "precomp.h"


#define MAX_XOF_RESULT_SIZE     1024
#define MAX_INPUT_BLOCK_SIZE    168

class CustomizableXofMultiImp : public CustomizableXofImplementation
{
public:
    CustomizableXofMultiImp( String algName );
    ~CustomizableXofMultiImp();

private:
    CustomizableXofMultiImp( const CustomizableXofMultiImp& );
    VOID operator=( const CustomizableXofMultiImp& );

public:

    typedef std::vector<CustomizableXofImplementation *> CustomizableXofImpPtrVector;

    CustomizableXofImpPtrVector m_imps;                    // Implementations we use

    CustomizableXofImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    VOID addImplementation(CustomizableXofImplementation * pXofImp );
    VOID setImpName();

    virtual SIZE_T inputBlockLen();

    virtual void init(PCBYTE pbNstr, SIZE_T cbNstr, PCBYTE pbSstr, SIZE_T cbSstr);
    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual void result( PBYTE pbResult, SIZE_T cbResult );
    virtual VOID xof(PCBYTE pbNstr, SIZE_T cbNstr,
                    PCBYTE pbSstr, SIZE_T cbSstr,
                    PCBYTE pbData, SIZE_T cbData, 
                    PBYTE pbResult, SIZE_T cbResult );
};

VOID
CustomizableXofMultiImp::setImpName()
{
    String sumAlgName;
    char * sepStr = "<";

    for(CustomizableXofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

CustomizableXofMultiImp::CustomizableXofMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<CustomizableXofImplementation>( algName, &m_imps );
}

VOID
CustomizableXofMultiImp::addImplementation(CustomizableXofImplementation * pXofImp )
{
    m_imps.push_back( pXofImp );
    setImpName();
}


CustomizableXofMultiImp::~CustomizableXofMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for(CustomizableXofImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

SIZE_T CustomizableXofMultiImp::inputBlockLen()
{
    SIZE_T res = MAX_SIZE_T;
    for(CustomizableXofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SIZE_T v = (*i)->inputBlockLen();
        CHECK( res == -1 || res == v, "Inconsistent input block len" );
        res = v;
    }

    return res;
}

VOID CustomizableXofMultiImp::xof(  PCBYTE pbNstr, SIZE_T cbNstr,
                                    PCBYTE pbSstr, SIZE_T cbSstr,
                                    PCBYTE pbData, SIZE_T cbData, 
                                    PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[MAX_XOF_RESULT_SIZE];
    ResultMerge res;

    CHECK( cbResult <= sizeof( buf ), "??" );

    for(CustomizableXofImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        SymCryptWipe( buf, cbResult );
        (*i)->xof( pbNstr, cbNstr, pbSstr, cbSstr, pbData, cbData, buf, cbResult );
        res.addResult( (*i), buf, cbResult );
    }

    res.getResult( pbResult, cbResult );
}

VOID CustomizableXofMultiImp::init(PCBYTE pbNstr, SIZE_T cbNstr, PCBYTE pbSstr, SIZE_T cbSstr )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.assign( m_imps.begin(), m_imps.end() );

    for( CustomizableXofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->init(pbNstr, cbNstr, pbSstr, cbSstr);
    }
}

VOID CustomizableXofMultiImp::append( PCBYTE pbData, SIZE_T cbData )
{
   for( CustomizableXofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        (*i)->append( pbData, cbData );
   }
}

VOID CustomizableXofMultiImp::extract(PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe)
{
    BYTE buf[MAX_XOF_RESULT_SIZE];
    ResultMerge res;

    CHECK(cbResult <= sizeof(buf), "?");

    for (CustomizableXofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i)
    {
        (*i)->extract(buf, cbResult, bWipe);
        res.addResult((*i), buf, cbResult);
    }

    res.getResult(pbResult, cbResult);
}


VOID CustomizableXofMultiImp::result( PBYTE pbResult, SIZE_T cbResult )
{
   BYTE buf[MAX_XOF_RESULT_SIZE];
   ResultMerge res;

   CHECK( cbResult <= sizeof( buf ), "?" );

   for(CustomizableXofImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
       SymCryptWipe( buf, cbResult );
        (*i)->extract( buf, cbResult, TRUE );
        res.addResult( (*i), buf, cbResult );
   }

   res.getResult( pbResult, cbResult );
}

_Use_decl_annotations_
VOID
CustomizableXofImplementation::xof( PCBYTE pbNstr, SIZE_T cbNstr,
                                    PCBYTE pbSstr, SIZE_T cbSstr,
                                    PCBYTE pbData, SIZE_T cbData, 
                                    PBYTE pbResult, SIZE_T cbResult )
{
    init( pbNstr, cbNstr, pbSstr, cbSstr );
    append( pbData, cbData );
    result( pbResult, cbResult );
}


VOID
testCustomizableXofSingle(CustomizableXofImplementation*        pXof,
               _In_reads_( cbNstr )     PCBYTE                  pbNstr,
                                        SIZE_T                  cbNstr,
               _In_reads_( cbSstr )     PCBYTE                  pbSstr,
                                        SIZE_T                  cbSstr,
               _In_reads_( cbData )     PCBYTE                  pbData,
                                        SIZE_T                  cbData,
               _In_reads_( cbResult )   PCBYTE                  pbResult,
                                        SIZE_T                  cbResult,
                                        LONGLONG                line)
{
    
    BYTE res[MAX_XOF_RESULT_SIZE];

    CHECK3(cbResult <= sizeof(res), "Xof result too large at line %lld", line);

    memset( res, 0, sizeof(res));
    pXof->xof( pbNstr, cbNstr, pbSstr, cbSstr, pbData, cbData, res, cbResult );

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
    pXof->init( pbNstr, cbNstr, pbSstr, cbSstr );

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


VOID
testCustomizableXofRange(CustomizableXofImplementation*                 pXof,
                                                SIZE_T                  cbMessage,
                                                SIZE_T                  cbNameStr,
                                                SIZE_T                  cbCustomStr,
                                                SIZE_T                  cbOutput,
                        _In_reads_(cbResult)    PCBYTE                  pbResult,
                                                SIZE_T                  cbResult,
                                                LONGLONG                line)
{
    SYMCRYPT_SHA3_256_STATE sha3state;
    BYTE result[SYMCRYPT_SHA3_256_RESULT_SIZE];

    const SIZE_T SHAKE_BLOCK_SIZE = pXof->inputBlockLen();
    const SIZE_T MAX_INPUT_SIZE = 3 * 200;
    unsigned char input[MAX_INPUT_SIZE];
    unsigned char nameStr[MAX_INPUT_SIZE];
    unsigned char customStr[MAX_INPUT_SIZE];
    unsigned char output[128];

    CHECK3(cbOutput <= sizeof(output), "Output size too large at line %lld", line);

    CHECK3(cbResult == sizeof(result), "Incorrect range result size at line %lld", line);

    // Initialize inputs
    for (unsigned int i = 0; i < sizeof(input); i++)
    {
        input[i] = (i & 0xff) | 0x80;
    }

    for (unsigned int i = 0; i < sizeof(nameStr); i++)
    {
        nameStr[i] = ('N' + i) & 0xff;
    }

    for (unsigned int i = 0; i < sizeof(customStr); i++)
    {
        customStr[i] = ('S' + i) & 0xff;
    }

    SymCryptSha3_256Init(&sha3state);

    for (SIZE_T mlen = 0; mlen <= cbMessage; mlen++)
    {
        for (SIZE_T nlen = 0; nlen <= cbNameStr; nlen++)
        {
            for (SIZE_T slen = 0; slen <= cbCustomStr; slen++)
            {
                pXof->xof(nameStr, nlen, customStr, slen, input, mlen, output, cbOutput);
                SymCryptSha3_256Append(&sha3state, output, cbOutput);
            }
        }
    }

    SymCryptSha3_256Result(&sha3state, result);

    if (memcmp(result, pbResult, cbResult) != 0)
    {
        print("Wrong customizable xof range test result. \n"
            "Expected ");
        printHex(pbResult, cbResult);
        print("\nGot      ");
        printHex(result, SYMCRYPT_SHA3_256_RESULT_SIZE);
        print("\n");
        pXof->m_nErrorKatFailure++;
    }
}

VOID
testCustomizableXofStateTransition(CustomizableXofImplementation* pXof, LONGLONG line)
{
    const SIZE_T OUTPUT_SIZE = 64;

    BYTE FunctionName[] = "Function Name";
    BYTE CustomizationString[] = "Customization";
    BYTE Input[] = "abc";
    BYTE xofOutput[OUTPUT_SIZE] = {};
    BYTE cxofOutput[OUTPUT_SIZE] = {};

    if (!pXof)
        return;

    // Append call in squeeze mode should start appending
    // in absorb mode to an empty state and should produce
    // an output as if the customizable XOF was initialized
    // with empty input strings.

    // Generate the output for empty input strings
    pXof->init(nullptr, 0, nullptr, 0);
    pXof->append(Input, sizeof(Input));
    pXof->extract(xofOutput, sizeof(xofOutput), TRUE);

    // Put the state into squeeze mode and then append Input to get
    // the output with empty input strings.
    pXof->init(FunctionName, sizeof(FunctionName), CustomizationString, sizeof(CustomizationString));
    pXof->append(Input, sizeof(Input));
    pXof->extract(cxofOutput, sizeof(cxofOutput), FALSE);
    pXof->append(Input, sizeof(Input));
    pXof->extract(cxofOutput, sizeof(cxofOutput), TRUE);

    CHECK3(memcmp(xofOutput, cxofOutput, OUTPUT_SIZE) == 0, "State transition error at line %lld", line);
}

VOID
testCustomizableXofKats()
{
    KatData *katXof = getCustomResource( "kat_cxof.dat", "KAT_CXOF" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<CustomizableXofMultiImp> pXofMultiImp;

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
            pXofMultiImp.reset( new CustomizableXofMultiImp( g_currentCategory ) );

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
            testCustomizableXofStateTransition(pXofMultiImp.get(), katXof->m_line);
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if (katIsFieldPresent(katItem, "range"))
            {
                LONGLONG katMaxInputSize = 0;
                LONGLONG katMaxNameStrSize = 0;
                LONGLONG katMaxCustomStrSize = 0;

                if (katIsFieldPresent(katItem, "maxinputsize"))
                {
                    katMaxInputSize = katParseInteger(katItem, "maxinputsize");
                }

                if (katIsFieldPresent(katItem, "maxnamestrsize"))
                {
                    katMaxNameStrSize = katParseInteger(katItem, "maxnamestrsize");
                }

                if (katIsFieldPresent(katItem, "maxcustomstrsize"))
                {
                    katMaxCustomStrSize = katParseInteger(katItem, "maxcustomstrsize");
                }

                CHECK3((katMaxInputSize || katMaxNameStrSize || katMaxCustomStrSize), "Invalid range test record ending at line %lld", katXof->m_line);

                UINT64 katOutputSize = (UINT64)katParseInteger(katItem, "outputsize");
                BString katRange = katParseData(katItem, "range");

                testCustomizableXofRange(pXofMultiImp.get(), 
                                        katMaxInputSize, katMaxNameStrSize, katMaxCustomStrSize, katOutputSize, 
                                        katRange.data(), katRange.size(), (katXof->m_line));
                continue;
            }

            if( katIsFieldPresent( katItem, "output" ) )
            {
                CHECK3( (katItem.dataItems.size() == 5), "Invalid number of items in KAT record ending at line %lld", katXof->m_line );
                BString katMsg = katParseData( katItem, "msg" );
                BString katMD = katParseData( katItem, "output" );
                BString katN = katParseData(katItem, "n");
                BString katS = katParseData(katItem, "s");

                LONGLONG katLen = -1;
                if (katIsFieldPresent(katItem, "outputlen"))
                {
                    katLen = katParseInteger(katItem, "outputlen") / 8;
                    CHECK3(katLen == (LONGLONG)katMD.size(), "Outputlen does not match the length of the output at line %lld", katXof->m_line);
                }

                testCustomizableXofSingle( pXofMultiImp.get(), 
                                            (PCBYTE) katN.data(), katN.size(), 
                                            (PCBYTE) katS.data(), katS.size(), 
                                            (PCBYTE) katMsg.data(), katMsg.size(), 
                                            (PCBYTE) katMD.data(), katMD.size(), 
                                            katXof->m_line );
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
testCustomizableXofAlgorithms()
{
    testCustomizableXofKats();
}
