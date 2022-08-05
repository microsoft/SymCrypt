//
// Test of SP 800-90 AES_CTR_DRGB
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

//
// The test vector is from the detailed DRBG Test Vectors file
// Starting on page 478 of 638.
//

static const BYTE g_abInstantiateEntropyInputPlusNonce[] =
{
    // Entropy input

    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,

    // Nonce
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,

};

#if 0
static const BYTE g_abReseedEntropy[] =
{

   0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
   0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,
   0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
   0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,
   0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
   0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
};
#endif

static const BYTE g_abOutput1[ 32 ] =
{
    0xE6,0x86,0xDD,0x55,0xF7,0x58,0xFD,0x91,
    0xBA,0x7C,0xB7,0x26,0xFE,0x0B,0x57,0x3A,
    0x18,0x0A,0xB6,0x74,0x39,0xFF,0xBD,0xFE,
    0x5E,0xC2,0x8F,0xB3,0x7A,0x16,0xA5,0x3B,
};

//
// We call the generate function a second time with a known answer to test the
// correctness of the backtracking resistance function at the end of each generate.
//

static const BYTE g_abOutput2[ 32 ] =
{
    0x8D, 0xA6, 0xCC, 0x59, 0xE7, 0x03, 0xCE, 0xD0,
    0x7D, 0x58, 0xD9, 0x6E, 0x5B, 0x6D, 0x78, 0x36,
    0xC3, 0x25, 0x99, 0x73, 0x5B, 0x73, 0x4F, 0x88,
    0xC1, 0xA7, 0x3B, 0x53, 0xC7, 0xA6, 0xD8, 0x2E,
};



VOID
testAesCtrDrbgDetailedVectors()
{
    SYMCRYPT_RNG_AES_STATE rng;
    BYTE buf[32];

    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRngAesInstantiate)    ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRngAesGenerate) )
    {
        print("    skipped\n");
        return;
    }

    ScDispatchSymCryptRngAesInstantiate( &rng, g_abInstantiateEntropyInputPlusNonce, sizeof( g_abInstantiateEntropyInputPlusNonce ) );

    ScDispatchSymCryptRngAesGenerate( &rng, buf, sizeof( buf ) );

    CHECK( memcmp( buf, g_abOutput1, sizeof( buf ) ) == 0, "Wrong output of AES_CTR_DRBG" );

    ScDispatchSymCryptRngAesGenerate( &rng, buf, sizeof( buf ) );

    CHECK( memcmp( buf, g_abOutput2, sizeof( buf ) ) == 0, "Wrong output of AES_CTR_DRBG 2" );

}


//////////////////////////////////////////////////
//

class RngSp800_90MultiImp: public RngSp800_90Implementation
{
public:
    RngSp800_90MultiImp( String algName );
    ~RngSp800_90MultiImp();

private:
    RngSp800_90MultiImp( const RngSp800_90MultiImp & );
    VOID operator=( const RngSp800_90MultiImp & );

public:

    typedef std::vector<RngSp800_90Implementation *> RngImpPtrVector;

    RngImpPtrVector m_imps;                    // Implementations we use

    RngImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    virtual NTSTATUS instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy );
    virtual NTSTATUS reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy );
    virtual VOID generate( _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData );
};

RngSp800_90MultiImp::RngSp800_90MultiImp( String algName )
{
    getAllImplementations<RngSp800_90Implementation>( algName, &m_imps );

    m_algorithmName = algName;

    String sumAlgName;
    char * sepStr = "<";

    for( RngImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

RngSp800_90MultiImp::~RngSp800_90MultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( RngImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

NTSTATUS
RngSp800_90MultiImp::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    NTSTATUS status;

    m_comps.clear();

    for( RngImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        status = (*i)->instantiate( pbEntropy, cbEntropy );
        if( NT_SUCCESS( status ) )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
RngSp800_90MultiImp::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    NTSTATUS status;

    for( RngImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        status = (*i)->reseed( pbEntropy, cbEntropy );
        if( !NT_SUCCESS( status ) )
        {
            CHECK( NT_SUCCESS( status ), "Failed to reseed" );
        }
    }

    return STATUS_SUCCESS;
}

VOID
RngSp800_90MultiImp::generate( _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{
   BYTE buf[500];
   ResultMerge res;

   CHECK( cbData <= sizeof( buf ), "?" );

   for( RngImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
   {
        SymCryptWipe( buf, cbData );
        (*i)->generate( buf, cbData );
        res.addResult( (*i), buf, cbData );
   }

   res.getResult( pbData, cbData );
}



VOID
testAesCtrDrbgSingle(
    RngSp800_90Implementation * pRng,
    PCBYTE pbEntropy, SIZE_T cbEntropy,
    PCBYTE pbReseed, SIZE_T cbReseed,
    PCBYTE pbRes, SIZE_T cbRes,
    LONGLONG generateAfterInstantiate,
    ULONGLONG line )
{
    BYTE buf[64];

    CHECK3( cbRes <= sizeof( buf ), "RNG result size too large in record on line %lld", line );
    CHECK3( generateAfterInstantiate == -1 || generateAfterInstantiate <= sizeof( buf ),
            "RNG result size too large in record -2- on line %lld", line );

    pRng->instantiate( pbEntropy, cbEntropy );

    if( generateAfterInstantiate > 0 )
    {
        pRng->generate( buf, (SIZE_T) generateAfterInstantiate );
    }

    pRng->reseed( pbReseed, cbReseed );

    pRng->generate( buf, cbRes );

    if( memcmp( buf, pbRes, cbRes ) != 0 )
    {
        print( "Wrong RNG result in line %lld. \n"
            "Expected ", line );
        printHex( pbRes, cbRes );
        print( "\nGot      " );
        printHex( buf, cbRes );
        print( "\n" );

        pRng->m_nErrorKatFailure++;
    }


}

VOID
testRngs()
{
    std::unique_ptr<KatData> katRng( getCustomResource( "kat_rng.dat", "KAT_RNG" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    BOOL doneAnything = FALSE;
    LONGLONG generateAfterInstantiate = -1;

    String sep = "    ";
    std::unique_ptr<RngSp800_90MultiImp> pRngMultiImp;

    while( 1 )
    {
        katRng->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pRngMultiImp.reset( new RngSp800_90MultiImp( g_currentCategory ) );
            generateAfterInstantiate = -1;

            skipData = (pRngMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "entropyinput" ) )
            {
                BString katEntropy = katParseData( katItem, "entropyinput" ) + katParseData( katItem, "nonce" );
                BString katReseed = katParseData( katItem, "entropyinputreseed" );
                BString katRes = katParseData( katItem, "returnedbits" );

                testAesCtrDrbgSingle(
                            pRngMultiImp.get(),
                            katEntropy.data(), katEntropy.size(),
                            katReseed.data(), katReseed.size(),
                            katRes.data(), katRes.size(),
                            generateAfterInstantiate,
                            katRng->m_line );

                continue;
            }

            if( katIsFieldPresent( katItem, "generateafterinstantiate" ) )
            {
                generateAfterInstantiate = katParseInteger( katItem, "generateafterinstantiate" );
                continue;
            }

            FATAL2( "Unknown data record ending at line %lld", katRng->m_line );
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}




VOID
testAesCtrDrbg()
{
    print("    testAesCtrDrbgDetailedVectors static\n");
    testAesCtrDrbgDetailedVectors();

    if (g_dynamicSymCryptModuleHandle != NULL)
    {
        print("    testAesCtrDrbgDetailedVectors dynamic\n");
        g_useDynamicFunctionsInTestCall = TRUE;
        testAesCtrDrbgDetailedVectors();
        g_useDynamicFunctionsInTestCall = FALSE;
    }

    testRngs();
}





