//
// Main.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include "precomp.h"

#define EQU =
#include "C_asm_shared.inc"

VOID
rdrandTest();

extern "C" {

//
// Place to put declaration of function to be called by the developertest
//

}

VOID
developertest()
{
    //
    // This function is called before the main testing begins.
    // It is primarilly used during development of new code to run the test code
    // without having to wait for all the other things to run.
    // 
    // Note: there is also a DeveloperTest algorithm that can be used for developer performance
    // tests.
    //
}


//
// Special extern declarations to allow us to disable AES-NI on the RSA32 library
//
extern "C" {
extern BYTE AesUseXmm;
extern BOOL AesDetectXmmDone;
}

char * AlgMd2::name = "Md2";

char * AlgMd4::name = "Md4";

char * AlgMd5::name = "Md5";

char * AlgSha1::name = "Sha1";

char * AlgSha256::name = "Sha256";

char * AlgSha384::name = "Sha384";

char * AlgSha512::name = "Sha512";

char * AlgHmacMd5::name = "HmacMd5";

char * AlgHmacSha1::name = "HmacSha1";

char * AlgHmacSha256::name = "HmacSha256";

char * AlgHmacSha384::name = "HmacSha384";

char * AlgHmacSha512::name = "HmacSha512";

char * AlgAesCmac::name = "AesCmac";

char * AlgMarvin32::name = "Marvin32";

char * AlgAes::name = "Aes";

char * AlgDes::name = "Des";

char * Alg3Des::name = "Des3";

char * Alg2Des::name = "Des2";

char * AlgDesx::name = "Desx";

char * AlgRc2::name = "Rc2";

char * AlgRc4::name = "Rc4";

char * AlgChaCha20::name = "ChaCha20";

char * AlgPoly1305::name = "Poly1305";

char * AlgAesCtrDrbg::name = "AesCtrDrbg";

char * AlgAesCtrF142::name = "AesCtrF142";

char * AlgParallelSha256::name = "ParSha256";
WCHAR * AlgParallelSha256::pwstrBasename = L"SHA256";

char * AlgParallelSha384::name = "ParSha384";
WCHAR * AlgParallelSha384::pwstrBasename = L"SHA384";

char * AlgParallelSha512::name = "ParSha512";
WCHAR * AlgParallelSha512::pwstrBasename = L"SHA512";

char * AlgPbkdf2::name = "Pbkdf2";

char * AlgSp800_108::name = "Sp800_108";

char * AlgTlsPrf1_1::name = "TlsPrf1_1";

char * AlgTlsPrf1_2::name = "TlsPrf1_2";

char * AlgHkdf::name = "Hkdf";

char * AlgXtsAes::name = "XtsAes";

char * AlgTlsCbcHmacSha1::name   = "TlsCbcHmacSha1";

char * AlgTlsCbcHmacSha256::name = "TlsCbcHmacSha256";

char * AlgTlsCbcHmacSha384::name = "TlsCbcHmacSha384";

char * AlgIntAdd::name = "IntAdd";

char * AlgIntSub::name = "IntSub";

char * AlgIntMul::name = "IntMul";

char * AlgIntSquare::name = "IntSquare";

char * AlgIntDivMod::name = "IntDivMod";

char * AlgModAdd::name = "ModAdd";

char * AlgModSub::name = "ModSub";

char * AlgModMul::name = "ModMul";

char * AlgModSquare::name = "ModSquare";

char * AlgModInv::name = "ModInv";

char * AlgModExp::name = "ModExp";

char * AlgScsTable::name = "ScsTable";

char * AlgIEEE802_11SaeCustom::name = "IEEE802_11SaeCustom";

char * AlgTrialDivision::name = "TrialDivision";

char * AlgTrialDivisionContext::name = "TrialDivisionContext";

char * AlgWipe::name = "Wipe";

char * AlgRsaEncRaw::name = "RsaEncRaw";

char * AlgRsaDecRaw::name = "RsaDecRaw";

char * AlgRsaEncPkcs1::name = "RsaEncPkcs1";

char * AlgRsaDecPkcs1::name = "RsaDecPkcs1";

char * AlgRsaEncOaep::name = "RsaEncOaep";

char * AlgRsaDecOaep::name = "RsaDecOaep";

char * AlgRsaSignPkcs1::name = "RsaSignPkcs1";

char * AlgRsaVerifyPkcs1::name = "RsaVerifyPkcs1";

char * AlgRsaSignPss::name = "RsaSignPss";

char * AlgRsaVerifyPss::name = "RsaVerifyPss";

char * AlgDsaSign::name = "DsaSign";

char * AlgDsaVerify::name = "DsaVerify";

char * AlgDh::name = "Dh";

char * AlgEcurveAllocate::name = "EcurveAllocate";

char * AlgEcpointSetZero::name = "EcpointSetZero";

char * AlgEcpointSetDistinguished::name = "EcpointSetDistinguished";

char * AlgEcpointSetRandom::name = "EcpointSetRandom";

char * AlgEcpointIsEqual::name = "EcpointIsEqual";

char * AlgEcpointIsZero::name = "EcpointIsZero";

char * AlgEcpointOnCurve::name = "EcpointOnCurve";

char * AlgEcpointAdd::name = "EcpointAdd";

char * AlgEcpointAddDiffNz::name = "EcpointAddDiffNz";

char * AlgEcpointDouble::name = "EcpointDouble";

char * AlgEcpointScalarMul::name = "EcpointScalarMul";

char * AlgEcdsaSign::name = "EcdsaSign";

char * AlgEcdsaVerify::name = "EcdsaVerify";

char * AlgEcdh::name = "Ecdh";

char * AlgDeveloperTest::name = "DeveloperTest";

char * ModeEcb::name = "Ecb";
ULONG ModeEcb::flags = 0;

char * ModeCbc::name = "Cbc";
ULONG ModeCbc::flags = MODE_FLAG_CHAIN;

char * ModeCfb::name = "Cfb";
ULONG ModeCfb::flags = MODE_FLAG_CHAIN | MODE_FLAG_CFB;

char * ModeCcm::name = "Ccm";

char * ModeGcm::name = "Gcm";

BOOL AlgRc4::isRandomAccess = FALSE;
BOOL AlgChaCha20::isRandomAccess = TRUE;

ULONG   g_rc2EffectiveKeyLength = 0;
SIZE_T  g_modeCfbShiftParam = 1;

Rng g_rng;

BOOL g_modifiedCpuFeatures = FALSE;
BOOL g_runKernelmodeTest = FALSE;
BOOL g_failRegisterSave = FALSE;
BOOL g_runRsaAverageKeyPerf = FALSE;

DWORD g_osVersion;
ULONG g_rngSeed = 0;

ULONGLONG g_nTotalErrors = 0;

SYMCRYPT_CPU_FEATURES g_disabledOnCommandLine = 0;

//
// For most performance data we compute a line (a*n + b) for the time it takes to process an n-byte
// message. We also compute the 90 percentile of the deviation of the cloud points from this line.
// The flag below can be set to show this 90 percentile range in the output.
//
BOOL g_showPerfRangeInfo = FALSE;   

//
// For the ECC algorithms we show detailed information if this flag is set.
//
BOOL g_verbose = FALSE;

//
// Profiling options to run an algorithm in a tight loop
//
BOOL g_profile = FALSE;
UINT32 g_profile_iterations = 0;
UINT32 g_profile_key = 0;

//
// Flag that specifies that we run performance tests
//
BOOL g_perfTestsRunning = FALSE;

//
// Flag that specifies tests are running against BCrypt SGX enclave proxy.
//
BOOL g_sgx = FALSE;

AlgorithmImplementation::AlgorithmImplementation()
{
    m_nErrorDisagreeWithMajority = 0;
    m_nErrorNoMajority = 0;
    m_nErrorKatFailure = 0;
    m_nResults = 0;

    m_perfDataFunction = NULL;
    m_perfDecryptFunction = NULL;
    m_perfKeyFunction = NULL;
    m_perfCleanFunction = NULL;
}

#if 0

#define INIT_CODE( Buf1, Buf2, dataSize )
#define PERF_CODE( Buf1, Buf2, dataSize ) SymCryptWipe( Buf1, dataSize );
CREATE_PERF_FUNCTION( Wipe, 100, 100000 )
#undef INIT_CODE
#undef PERF_CODE

#define INIT_CODE( Buf1, Buf2, dataSize )
#define PERF_CODE( Buf1, Buf2, dataSize ) SymCryptWipe( Buf1+dataSize, 64-dataSize );
CREATE_PERF_FUNCTION( WipeAlign, 100, 100000 )
#undef INIT_CODE
#undef PERF_CODE

VOID 
perftestWipe()
{
    int dataSizes[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 32, 34, 48, 57, 64, 80, 83, 104, 112, 128, 1024, 4096};
    int i;
    double perf;
    
    print( "SymCryptWipe performance\n" );
    for( i=0; i<sizeof( dataSizes ) / sizeof( dataSizes[0] ); i++ )
    {
        perf = computePerf( PERF_FUNCTION( Wipe ), dataSizes[i], 1 );
        print( "%4d bytes  %8.2f cycles    %5.2f cycles/byte\n",
            dataSizes[i], perf, perf/dataSizes[i] );
    }

    print( "\n" );

    for( i=0; i<=64; i++ )
    {
        perf = computePerf( PERF_FUNCTION( WipeAlign ), i, 1 );
        print( "Alignment %2d %8.2f cycles\n", i, perf );
    }
    printOutput( 50 );
}

#endif


//
// Test filters.
// If a filter is empty, all algorithm implementations pass the test.
// If a filter is nonempty, an algorithm implementation passes the test if one
// of the elements in the vector is a prefix of the
// corresponding algorithm or implementation name. 
//
// Thus, we can test all RSA32 or SymCrypt algorithms together,
// And all AES algorithms (including AES-CBC).
// We don't do exact-match as that makes it easy to forget to test
// some implementations (like the RSA32-old one for AES).
//
typedef std::vector<String> StringVector;

StringSet g_algorithmsToTest;     
StringSet g_implementationsToTest;

BOOL setContainsPrefix( const StringSet & set, const std::string & str )
{
    if( set.size() == 0 )
    {
        return TRUE;
    }
    
    BOOL found = FALSE;
    for( StringSet::const_iterator i = set.begin(); i != set.end(); ++i )
    {
        found = TRUE;
        for( SIZE_T j=0; j< str.size(); j++ )
        {
            if( charToLower( (*i)[j] ) != charToLower( str[j] ) )
            {
                found = FALSE;
                break;
            }
        }

        if( found && i->size() == str.size() )
        {
            return TRUE;
        }
    }
    
    return FALSE;    
}

BOOL
updateNameSet( _In_ PSTR * names, _Inout_ StringSet * set, CHAR op, _In_ PSTR name )
{
    BOOL nameMatch = FALSE;
    SIZE_T nameLen = strlen( name );
    
    if( nameLen == 0 )
    {
        return FALSE;
    }
    
    for( SIZE_T i=0; names[i] != NULL; i++ )
    {
        if( STRNICMP( name, names[i], nameLen ) == 0 )
        {
            nameMatch = TRUE;
            if( op == '+' )
            {
                set->insert( names[i] );
            }
            else
            {
                if( set->size() == 0 )
                {
                    for( SIZE_T j=0; names[j] != NULL; j++ )
                    {
                        set->insert( names[j] );
                    }
                }
                set->erase( names[i] );
            }
        }
    }

    return nameMatch;
    
}

BOOL
isAlgorithmPresent( String algName, BOOL isPrefix )
{
    for( AlgorithmImplementationVector::const_iterator i= g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        if( isPrefix )
        {
            if( (*i)->m_algorithmName.find( algName ) == 0 )
            {
                return TRUE;
            }
        } else {
            if( (*i)->m_algorithmName == algName )
            {
                return TRUE;            }
        }
    }
    return FALSE;
}

char * g_algorithmNames[] = {
    AlgMd2::name,
    AlgMd4::name,
    AlgMd5::name,
    AlgSha1::name,
    AlgSha256::name,
    AlgSha384::name,
    AlgSha512::name,
    AlgHmacMd5::name,
    AlgHmacSha1::name,
    AlgHmacSha256::name,
    AlgHmacSha384::name,
    AlgHmacSha512::name,
    AlgAesCmac::name,
    AlgMarvin32::name,
    AlgAes::name,
    AlgDes::name,
    Alg2Des::name,
    Alg3Des::name,
    AlgDesx::name,
    AlgRc2::name,
    AlgRc4::name,
    AlgChaCha20::name,
    AlgPoly1305::name,
    AlgAesCtrDrbg::name,
    AlgAesCtrF142::name,
    AlgParallelSha256::name,
    AlgParallelSha384::name,
    AlgParallelSha512::name,
    AlgPbkdf2::name,
    AlgSp800_108::name,
    AlgTlsPrf1_1::name,
    AlgTlsPrf1_2::name,
    AlgHkdf::name,
    AlgXtsAes::name,
    AlgTlsCbcHmacSha1::name,
    AlgTlsCbcHmacSha256::name,
    AlgTlsCbcHmacSha384::name,
    AlgIntAdd::name,
    AlgIntSub::name,
    AlgIntMul::name,
    AlgIntSquare::name,
    AlgIntDivMod::name,
    AlgModAdd::name,
    AlgModSub::name,
    AlgModMul::name,
    AlgModSquare::name,
    AlgModInv::name,
    AlgModExp::name,
    AlgScsTable::name,
    AlgIEEE802_11SaeCustom::name,
    AlgTrialDivision::name,
    AlgTrialDivisionContext::name,
    AlgWipe::name,
    AlgRsaEncRaw::name,
    AlgRsaDecRaw::name,
    AlgRsaEncPkcs1::name,
    AlgRsaDecPkcs1::name,
    AlgRsaEncOaep::name,
    AlgRsaDecOaep::name,
    AlgRsaSignPkcs1::name,
    AlgRsaVerifyPkcs1::name,
    AlgRsaSignPss::name,
    AlgRsaVerifyPss::name,
    AlgDsaSign::name,
    AlgDsaVerify::name,
    AlgDh::name,
    AlgEcurveAllocate::name,
    AlgEcpointSetZero::name,
    AlgEcpointSetDistinguished::name,
    AlgEcpointSetRandom::name,
    AlgEcpointIsEqual::name,
    AlgEcpointIsZero::name,
    AlgEcpointOnCurve::name,
    AlgEcpointAdd::name,
    AlgEcpointAddDiffNz::name,
    AlgEcpointDouble::name,
    AlgEcpointScalarMul::name,
    AlgEcdsaSign::name,
    AlgEcdsaVerify::name,
    AlgEcdh::name,

    AlgDeveloperTest::name,
    NULL,
};

VOID
usage()
{
    char * sep;
    int i;
    SIZE_T col;

    iprint( "\n"
            "\n"
            "USAGE: symcryptunittest <option>...\n"
            "Each option is a '+' or '-' followed by a string\n"
            "Options:\n"
            "  +<cpufeature>     ensure that cpu feature is present in CPU\n"
            "  -<cpufeature>     disable CPU feature for SymCrypt.\n"
            "                    \"-aesni\" also disables AES-NI usage for RSA32\n"
            " +<impl. prefix>    run only those implementations that match the prefix\n"
            " -<impl. prefix>    do not run the implementations that match the prefix\n"
            " +<alg. prefix>     run only those algorithms that match the prefix\n"
            " -<alg. prefix>     do not run algorithms that match the prefix\n"
            "  showrange         show 90-percentile range on the deviation of individual \n"
            "                    performance measurement from the linear performance data\n"
            "  osversion=xxxx    Use Capi/Cng calling conventions for OS version xxxx\n"
            "                    XP = <tbd>, Vista = 0600, Win7 = 0601, Win8 = 0602, Blue=0603\n"
            "  rngseed=xxxxxxxx  Set seed for test RNG algorithm, default = 0 = random\n"
            "  kernel            Run the kernel-mode tests \n"
            "  verbose           Print detailed information for some algorithms\n"
            "  profile:xxx [key=yyy]    Run one or more algorithms in a tight loop, xxx times for\n"
            "                           each key/datasize combination. The algorithms to run are specified\n"
            "                           by the +/- options. The optional key parameter can specify\n"
            "                           that only the key size with the hex code yyy will be run.\n"
            "                           Note: If you don't know the desired key, run profiling without\n"
            "                               the key parameter and all possible codes will get printed.\n"
            "  rsakgp            Run perf measurement of RSA key generation.\n"
            "  sgx               Run CNG and symcrypt test implementations against BCrypt in SGX enclave.\n" 
            "                    This option is only valid for win8_1 version and newer of the tests.\n"
            "\n"
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
            " CPU feature:       aesni, pclmulqdq, sse2, sse3, ssse3, avx2,\n"
            "                    rdrand, rdseed, savexmmnofail, shani, adx, bmi2\n"
#elif SYMCRYPT_CPU_ARM64
            " CPU feature:       neon, i_sha1, i_sha256, i_aes, i_pmull\n"
#elif SYMCRYPT_CPU_ARM 
            " CPU feature:       neon\n"
#endif
            );

    sep = " Implementations:   "; 
    for( i=0; g_implementationNames[i] != NULL; i++ )
    {
        iprint( "%s%s", sep, g_implementationNames[i] );
        sep = ", ";
    }
    iprint( "\n" );

    sep = " Algorithm names:   ";
    col = 0;
    for( i=0; g_algorithmNames[i] != NULL; i++ )
    {
        if( col + strlen( sep ) + strlen( g_algorithmNames[i] ) > 77 )
        {
            iprint( "%s\n                    ", sep );
            col = 20;
            sep = "";
        }
        iprint( "%s%s", sep, g_algorithmNames[i] );
        col += strlen( sep ) + strlen( g_algorithmNames[i] );
        sep = ", ";
    }

    iprint( "\n" );
}

//
// Table of CPUID feature data
//

typedef struct _CPU_FEATURE_DATA
{
    PSTR                    name;
    SYMCRYPT_CPU_FEATURES   mask;
} CPU_FEATURE_DATA;

const CPU_FEATURE_DATA g_cpuFeatureData[] =
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    { "sse2", SYMCRYPT_CPU_FEATURE_SSE2 },
    { "ssse3", SYMCRYPT_CPU_FEATURE_SSSE3 },
    { "aesni", SYMCRYPT_CPU_FEATURE_AESNI },
    { "pclmulqdq", SYMCRYPT_CPU_FEATURE_PCLMULQDQ },
    { "rdrand", SYMCRYPT_CPU_FEATURE_RDRAND },
    { "rdseed", SYMCRYPT_CPU_FEATURE_RDSEED },
    { "avx2", SYMCRYPT_CPU_FEATURE_AVX2 },
    { "savexmmnofail", SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL },
    { "shani", SYMCRYPT_CPU_FEATURE_SHANI },
    { "adx", SYMCRYPT_CPU_FEATURE_ADX },
    { "bmi2", SYMCRYPT_CPU_FEATURE_BMI2 },
#elif SYMCRYPT_CPU_ARM64
    { "neon", SYMCRYPT_CPU_FEATURE_NEON },
    { "i_aes", SYMCRYPT_CPU_FEATURE_NEON_AES },
    { "i_pmull", SYMCRYPT_CPU_FEATURE_NEON_PMULL },
    { "i_sha1", SYMCRYPT_CPU_FEATURE_NEON_SHA1 },
    { "i_sha256", SYMCRYPT_CPU_FEATURE_NEON_SHA256 },
#elif SYMCRYPT_CPU_ARM
    { "neon", SYMCRYPT_CPU_FEATURE_NEON },
#else
    { "aesni", 0 },         // allow disabling of RSA32 AES-NI support even when SymCrypt is compiled for generic CPU
#endif
};

VOID printSymCryptCpuInfo( PCSTR text, SYMCRYPT_CPU_FEATURES notPresent )
{
    CHAR sep = ' ';
    print( "%s: ", text );
    for( int i=0; i < sizeof( g_cpuFeatureData ) / sizeof( g_cpuFeatureData[0] ); i++ )
    {
        if( !(notPresent & g_cpuFeatureData[i].mask) )
        {
            print( "%c%s", sep, g_cpuFeatureData[i].name );
            sep = ',';  
        }
    }
    print( "\n" );
}


VOID
processSingleOption( _In_ PSTR option )
{
    BOOL optionHandled = FALSE;
    if( option[0] == '+' || option[0] == '-' )
    {
        if( STRICMP( &option[0], "-aesni" ) == 0 )
        {
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
            //
            // Disable AES-NI for RSA32 and SymCrypt
            //
            AesUseXmm = 0;
            AesDetectXmmDone = TRUE;    
#endif                
        }

        for( int i=0; i < sizeof(g_cpuFeatureData)/sizeof(g_cpuFeatureData[0]); i++ )
        {
            if( STRICMP( &option[1], g_cpuFeatureData[i].name ) == 0 )
            {
                if( option[0] == '-' )
                {
                    g_SymCryptCpuFeaturesNotPresent |= g_cpuFeatureData[i].mask;
                    g_disabledOnCommandLine |=  g_cpuFeatureData[i].mask;
                    g_modifiedCpuFeatures = TRUE;
                } else {
                    if( !SYMCRYPT_CPU_FEATURES_PRESENT( g_cpuFeatureData[i].mask ) )
                    {
                        FATAL2( "CPU feature not available: %s", option );
                    }
                }
                optionHandled = TRUE;
                break;
            }
        }
    } else {
        if( STRICMP( &option[0], "showrange" ) == 0 )
        {
            g_showPerfRangeInfo = TRUE;
            optionHandled = TRUE;
        }

        if( STRICMP( &option[0], "verbose" ) == 0 )
        {
            g_verbose = TRUE;
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "profile:", 8 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 8 );
            g_profile = TRUE;
            g_profile_iterations = (UINT32) strtol( &option[8], &endptr, 0 );
            if (g_profile_iterations == 0)
            {
                FATAL( "Number of profile iterations must be greater than zero." );
            }
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "key=", 4 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 4 );
            if (!g_profile)
            {
                FATAL2( "Key parameter present without profile parameter \"%s\"", &option[0] );
            }
            g_profile_key = (UINT32) strtol( &option[4], &endptr, 16 );
            optionHandled = TRUE;
        }

        if( STRICMP( &option[0], "kernel" ) == 0 )
        {
            g_runKernelmodeTest = TRUE;
            optionHandled = TRUE;
        }

        if( STRICMP( &option[0], "rsakgp" ) == 0 )
        {
            g_runRsaAverageKeyPerf = TRUE;
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "osversion=", 10 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 10 );  
            // SAL_readableTo(elementCount(10))
            g_osVersion = (UINT32) strtol( &option[10], &endptr, 16 );
            if( endptr != &option[14] || g_osVersion < 0x0500 || g_osVersion > 0x0800 )
            {
                FATAL2( "Invalid OS version \"%s\"", &option[10] );
            }
            optionHandled = TRUE;
            g_modifiedCpuFeatures = TRUE; 
        }
        if( STRNICMP( &option[0], "rngseed=", 8 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 8 );  
            g_rngSeed = (UINT32) strtol( &option[8], &endptr, 16 );
            optionHandled = TRUE;
        }
        if (STRICMP(&option[0], "sgx") == 0)
        {
            g_sgx = TRUE;
            optionHandled = TRUE;
        }
    }
    if( !optionHandled )
    {
        print( "Unknown option \"%s\"", option );
        usage();
        exit( -1 );
    }
}

VOID
processOptions( int argc, _In_reads_( argc ) char * argv[] )
{
    char sepchar = ' ';
    iprint( "\nOptions:" );

    for( int i=1; i<argc; i++ )
    {
        iprint( "%c %s", sepchar, argv[i] );
        sepchar = ',';

        BOOL optionHandled = FALSE;
        if( argv[i][0] == '+' || argv[i][0] == '-' )
        {
            CHAR c = argv[i][0];
            String str( argv[i] + 1 );
            
            if( updateNameSet( g_algorithmNames, 
                                &g_algorithmsToTest, c, argv[i] + 1 ) )
            {
                optionHandled = TRUE;
            }

            // if an option matches both algorithm names & implementation names, the alg name wins.
            if( !optionHandled && 
                updateNameSet( g_implementationNames,
                                &g_implementationsToTest, c, argv[i] + 1 ) )
            {
                optionHandled = TRUE;
            }
        }
        if( !optionHandled )
        {
            processSingleOption( argv[i] );
        }
    }

    iprint( "\n" );
}



AlgorithmImplementationVector g_algorithmImplementation;

_Analysis_noreturn_
VOID
fatal( _In_ PSTR file, ULONG line, _In_ PSTR format, ... )
{
    va_list vl;

    printOutput( 0 );
    
    fprintf( stdout, "*\n\n***** FATAL ERROR %s(%d): ", file, line );

    va_start( vl, format );

    vfprintf( stdout, format, vl );

    exit( -1 );
}

#if !SYMCRYPT_APPLE_CC
KatData *
getCustomResource( _In_ PSTR resourceName, _In_ PSTR resourceType )
{
    HRSRC   resourceHandle;
    HGLOBAL resourceDataHandle;

    PCCHAR  pbData;
    SIZE_T  cbData;

    resourceHandle = FindResourceA( NULL, resourceName, resourceType );
    CHECK( resourceHandle != NULL, "Failed to find resource" );
    
    resourceDataHandle = LoadResource( NULL, resourceHandle );
    CHECK( resourceDataHandle != NULL, "Failed to laod resource" );
    
    cbData = SizeofResource( NULL, resourceHandle );
    CHECK( cbData != 0, "?" );

    pbData = (PCCHAR) LockResource( resourceDataHandle );
    CHECK( pbData != NULL, "?" );

    return new KatData( resourceName, pbData, cbData );
}

void getPlatformInformation()
{   
    OSVERSIONINFO versionInfo;

    versionInfo.dwOSVersionInfoSize = sizeof( versionInfo );

    CHECK( GetVersionEx( &versionInfo ), "Failed to get OS version info" );

    g_osVersion = (versionInfo.dwMajorVersion << 8) + (versionInfo.dwMinorVersion & 0xff);
}
#endif

void printPlatformInformation( _In_z_ char * text )
{

    iprint( "\n%s "
#if SYMCRYPT_CPU_X86
        "x86"
#elif SYMCRYPT_CPU_AMD64 
        "amd64"
#elif SYMCRYPT_CPU_ARM64
        "arm64"
#elif SYMCRYPT_CPU_ARM 
        "arm"
#else
        "generic"
#endif

#if defined(DBG)
        "Chk"
#else
        "Fre"
#endif    

#if SYMCRYPT_APPLE_CC
        ", iOS\n", text);
#else
        ", Windows %04x\n", text, g_osVersion );
#endif

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    int CPUInfo[4];
    char nameBuf[20];

    __cpuid( CPUInfo, 0 );
    memcpy( &nameBuf[0], (BYTE *)&CPUInfo[1], 4 );
    memcpy( &nameBuf[4], (BYTE *)&CPUInfo[3], 4 );
    memcpy( &nameBuf[8], (BYTE *)&CPUInfo[2], 4 );
    nameBuf[12] = 0;
    
    __cpuid( CPUInfo, 1 );
    DWORD cpuidfammod = CPUInfo[0];
    DWORD family;

    family = (cpuidfammod >> 8) & 0xf;

    if( family == 0xf )
    {
        family += (cpuidfammod >> 20) & 0xff;
    }

    DWORD model;
    model = ((cpuidfammod >> 12) & 0xf0) + ((cpuidfammod >> 4) & 0xf);

    iprint( "CPU \"%s\", Fam = 0x%02x, Model = 0x%02x \n", nameBuf, family, model );

#endif
}

VOID
printCpuidInfo()
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64

#define WORD_EAX    0
#define WORD_EBX    1
#define WORD_ECX    2
#define WORD_EDX    3

    int CPUInfo[4];

    print( "CPUID raw information\n" );
    print( "leaf        eax       ebx       ecx       edx\n");
    for( int i=0; i<=7; i++)
    {
        __cpuidex( CPUInfo, i, 0 );
        print( "%1d         %08x, %08x, %08x, %08x\n", i, CPUInfo[WORD_EAX], CPUInfo[WORD_EBX], CPUInfo[WORD_ECX], CPUInfo[WORD_EDX] );
    }
    iprint( "\n" );

#endif
}


#if 0   // superseded by the testKdf infrastructure
const LPWSTR cngMacAlgorithmName[] = {
    BCRYPT_AES_CMAC_ALGORITHM,
    BCRYPT_MD5_ALGORITHM,
    BCRYPT_SHA1_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALGORITHM,
};

const PCSYMCRYPT_MAC  symcryptMAC[] = {
    SymCryptAesCmacAlgorithm,
    SymCryptHmacMd5Algorithm,
    SymCryptHmacSha1Algorithm,
    SymCryptHmacSha256Algorithm,
    SymCryptHmacSha384Algorithm,
    SymCryptHmacSha512Algorithm
};

VOID
SYMCRYPT_CALL
testonepbkdf2case(
                            PCSYMCRYPT_MAC  macAlgorithm,
                            BCRYPT_ALG_HANDLE   hAlg,
    _In_reads_(cbSecret)    PCBYTE          pbSecret,
                            SIZE_T          cbSecret,
    _In_reads_opt_(cbSalt)  PCBYTE          pbSalt,
                            SIZE_T          cbSalt,
                            ULONGLONG       iterationCnt,
    _In_range_(1, SYMCRYPT_HMAC_SHA512_RESULT_SIZE * 4)
                            SIZE_T          secreteSize
    )
{
    NTSTATUS status;
    BYTE    cngResult[SYMCRYPT_HMAC_SHA512_RESULT_SIZE * 4];
    BYTE    symcryptResult[SYMCRYPT_HMAC_SHA512_RESULT_SIZE * 4];

    status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pbSecret, (DWORD)cbSecret, (PUCHAR)pbSalt, (DWORD)cbSalt, iterationCnt, cngResult, (DWORD)secreteSize, 0);
    if (!NT_SUCCESS(status))
    {
        printf("Cannot perform CNG PBKDF2 0x%x\n", status);
        return;
    }

    SymCryptPbkdf2(macAlgorithm, pbSecret, cbSecret, pbSalt, cbSalt, iterationCnt, symcryptResult, secreteSize);

    if (memcmp(cngResult, symcryptResult, secreteSize) != 0)
    {
        printf("Pbkdf2Result does not match \n");
    }

}

VOID
SYMCRYPT_CALL
testpbkdf2()
{
    DWORD   index, passwordSize;
    NTSTATUS status;
    BYTE    password[32] = {0};
    const BYTE    salt[] =
    {
        's', 'a', 'l', 't', '#',
    };

    //comparing result with BCryptDeriveKeyPBKDF2
    for (index = 0; index < 6; index ++)
    {
        BCRYPT_ALG_HANDLE   hHmacAlg;
        DWORD   dwFlag = BCRYPT_ALG_HANDLE_HMAC_FLAG;
        ULONGLONG           iteration;
        SIZE_T              resultsize;
        if (wcscmp(cngMacAlgorithmName[index], BCRYPT_AES_CMAC_ALGORITHM) == 0)
        {
            dwFlag = 0;
        }

       status = BCryptOpenAlgorithmProvider(&hHmacAlg, cngMacAlgorithmName[index], MS_PRIMITIVE_PROVIDER, dwFlag);
       if (!NT_SUCCESS(status))
       {
            printf("Cannot open CNG hmac provider 0x%x\n", status);
            break;
        }

       status = BCryptGenRandom(
           NULL,
           password,
           sizeof(password),
           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
       if (!NT_SUCCESS(status))
       {
           printf("Cannot generate random password 0x%x\n", status);
           break;
       }
       status = BCryptGenRandom(
           NULL,
           (PUCHAR)&iteration,
           sizeof(iteration),
           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
       if (!NT_SUCCESS(status))
       {
           printf("Cannot generate random iteration count 0x%x\n", status);
           break;
       }

       status = BCryptGenRandom(
           NULL,
           (PUCHAR)&resultsize,
           sizeof(resultsize),
           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
       if (!NT_SUCCESS(status))
       {
           printf("Cannot generate random password 0x%x\n", status);
           break;
       }

       iteration = 1 + iteration % 500;
       resultsize = max( 1, resultsize % (SYMCRYPT_HMAC_SHA512_RESULT_SIZE * 4));

       for (passwordSize = 0; passwordSize <= 32; passwordSize += 1)
       {
           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), NULL, 0, 1, symcryptMAC[index]->resultSize);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), NULL, 0, 1, symcryptMAC[index]->resultSize + 1);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), NULL, 0, 1, symcryptMAC[index]->resultSize - 1);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), salt, sizeof(salt), 1, symcryptMAC[index]->resultSize);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), salt, sizeof(salt), 1, symcryptMAC[index]->resultSize + 1);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), salt, sizeof(salt), 1, symcryptMAC[index]->resultSize - 1);

           testonepbkdf2case(symcryptMAC[index], hHmacAlg, password, sizeof(password), salt, sizeof(salt), iteration, resultsize);
       }
        
       BCryptCloseAlgorithmProvider(hHmacAlg, 0);
       hHmacAlg = 0;
    }
}
#endif

VOID
initTestInfrastructure( int argc, _In_reads_( argc ) char * argv[] )
{
    iprint( "SymCrypt unit test program, " 
             "Built " __DATE__ " " __TIME__ "\n"
             "Copyright (c) Microsoft Corp, all rights reserved \n");

#define SYMCRYPT_CHECK_ASM_OFFSET( a, b ) CHECK4( (a) == (b), "Assembler offset incorrect: %s should be %d", #a, (b) );
    SYMCRYPT_CHECK_ASM_OFFSETS;
#undef SYMCRYPT_CHECK_ASM_OFFSET

    SymCryptInit();

#if !SYMCRYPT_APPLE_CC
    getPlatformInformation();
#endif

    printPlatformInformation( "System information" );
    printSymCryptCpuInfo( "Hardware CPU features", g_SymCryptCpuFeaturesNotPresent );

    // printCpuidInfo();

    processOptions( argc, argv );

    if( g_modifiedCpuFeatures )
    {
        printPlatformInformation( "Modified System information for this test" );
        printSymCryptCpuInfo( "Modified CPU features for this test", g_SymCryptCpuFeaturesNotPresent );
    }

    if( g_rngSeed == 0 )
    {
        CHECK( NT_SUCCESS( GENRANDOM(&g_rngSeed, sizeof( g_rngSeed )) ), "Failed to get random seed" );
    }
    g_rng.reset( (PCBYTE)&g_rngSeed, sizeof( g_rngSeed ) );
    iprint( "\nTest Rng seed = %08x\n", g_rngSeed );

    if( g_algorithmsToTest.size() > 0 )
    {
        print( "\nAlgorithms to test:\n" );
        for( StringSet::const_iterator i = g_algorithmsToTest.begin(); i != g_algorithmsToTest.end(); i++ )
        {
            print( "    %s\n", i->c_str() );
        }
    }
    
    if( g_implementationsToTest.size() > 0 )
    {
        print( "\nImplementations to test:\n" );
        for( StringSet::const_iterator i = g_implementationsToTest.begin(); i != g_implementationsToTest.end(); i++ )
        {
            print( "    %s\n", i->c_str() );
        }
    } else {
        //
        // Disable the RSA32 implementation by default
        //
        updateNameSet( g_implementationNames, &g_implementationsToTest, '-', "rsa32" );
    }
    
    AllocWithChecksInit();

    printOutput( 0 );
}

#if !SYMCRYPT_APPLE_CC
VOID
callKernelmodeTests()
{
    // Code copied from BCryptPrimitives.dll

    NTSTATUS status;
    UNICODE_STRING DriverName;
    OBJECT_ATTRIBUTES ObjA;
    IO_STATUS_BLOCK IOSB;
    HANDLE hDevice = 0;
    BOOL res;
    DWORD tmp;
    ULONG nCpus;
    ULONG i;

    KM_TEST_INPUT testInput;
    KM_TEST_RESULT testResult;

    print( "Running kernel-mode test...\n" );

    //
    // have to use the Nt flavor of the file open call because it's a base
    // device not aliased to \DosDevices
    //

    RtlInitUnicodeString( &DriverName, DEVICE_NAME );
    InitializeObjectAttributes(
                &ObjA,
                &DriverName,
                OBJ_CASE_INSENSITIVE,
                0,
                0
                );

    //
    // needs to be non-alertable, else, the DeviceIoControl may return
    // STATUS_USER_APC.
    //

    status = NtOpenFile(
                &hDevice,
                SYNCHRONIZE | FILE_READ_DATA,
                &ObjA,
                &IOSB,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_SYNCHRONOUS_IO_NONALERT
                );


    if( !NT_SUCCESS(status) )
    {
        print( "   Failed to open device %08x", status );
        g_nTotalErrors++;
        goto cleanup;
    }

    testInput.disable = g_disabledOnCommandLine;

    iprint( "Launching Kernel-mode test..." );
    res = DeviceIoControl ( hDevice,
                            IOCTL_RUN_TEST,
                            &testInput, sizeof( testInput ),
                            &testResult, sizeof( testResult ),
                            &tmp,
                            NULL );
    iprint( " done.\n" );

    if( res == 0 )
    {
        print( "  IOCTL failed, %d, %08x, %d", res, GetLastError(), tmp );
        g_nTotalErrors++;
        goto cleanup;
    }

    printSymCryptCpuInfo( "SymCrypt CPU features used:", testResult.featuresUsed );
    print( "\n" );
    print( "SymCrypt error code: %08x\n", testResult.firstSymCryptError );
    print( "Main thread error  : %08x\n", testResult.mainThreadError );
    print( "# test cases run   : %lld\n", testResult.nTestCases );

    nCpus = 64;
    while( nCpus > 0 && testResult.nDpcsOnCpu[nCpus-1] == 0 )
    {
        nCpus--;
    }
    iprint( "# DPCs on each cpu: " );
    for( i=0; i<nCpus; i++ )
    {
        print( "%d:%lld  ", i, testResult.nDpcsOnCpu[i] );
    }
    iprint( "\n" );

    if( testResult.firstSymCryptError != 0 || testResult.mainThreadError != 0 )
    {
        iprint( "ERROR in results\n" );
        g_nTotalErrors++;
        goto cleanup;
    }

cleanup:
    if( hDevice != 0 )
    {
        CloseHandle( hDevice );
        hDevice = 0;
    }

    print( "\n" );
}

#define PATH_BUFFER_LEN 300

VOID
runKernelmodeTests()
{
    SC_HANDLE scManager = 0;
    SC_HANDLE scService = 0;
    BOOL serviceStarted = FALSE;
    BOOL success;
    SERVICE_STATUS serviceStatus;
    PCHAR pEnd;
    int index;
    DWORD dw;


    iprint( "Setting up test service\n" );
    CHAR quotedPathName[PATH_BUFFER_LEN];

    index = 0;

    //quotedPathName[index++] = '"';
    dw = GetCurrentDirectory( PATH_BUFFER_LEN - index, &quotedPathName[index] );
    if( dw == 0 )
    {
        print( "Failed to get current direcotry, error = %08x", GetLastError() );
        g_nTotalErrors++;
        goto cleanup;
    }
    index += dw;
    if( index + 100 > PATH_BUFFER_LEN )
    {
        print( "Path name too long\n" );
        g_nTotalErrors++;
        goto cleanup;
    }

    quotedPathName[index++] = '\\';

    if( StringCchCopyEx( &quotedPathName[index], PATH_BUFFER_LEN - index, testDriverName, &pEnd, NULL, 0 ) != S_OK )
    {
        print( "Concat failed\n" );
        g_nTotalErrors++;
        goto cleanup;
    }

    //*pEnd++ = '"';
    *pEnd++ = '\0';


    scManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if( scManager == NULL )
    {
        print( "Failed to open service control manager, error = %08x.   (Not running as Admin?)\n", GetLastError() );
        g_nTotalErrors++;
        goto cleanup;
    }

    scService = CreateService(
                    scManager,
                    "SymCryptDriver",
                    NULL, //"SymCrypt test driver",
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_IGNORE,
                    quotedPathName,
                    NULL,           // loadOrderGroup
                    NULL,           // TagId
                    NULL,           // dependencies
                    NULL,           // driver object name
                    NULL );          // password

    if( scService == 0 )
    {
        print( "Failed to create service, error = %08x\n", GetLastError() );
        g_nTotalErrors++;
        goto cleanup;
    }

    serviceStarted = StartService( scService, 0, NULL );
    if( !serviceStarted )
    {
        print( "Failed to start service, error = %08x\n", GetLastError() );
        g_nTotalErrors++;
        iprint( "Press any key to continue..." );
        getc( stdin );
        print( "\n" );
        goto cleanup;
    }

    Sleep( 2000 );
    callKernelmodeTests();

cleanup:

    if( serviceStarted )
    {
        success = ControlService( scService, SERVICE_CONTROL_STOP, &serviceStatus );
        if( !success )
        {
            print( "Failed to stop service, error = %08x\n", GetLastError() );
        }
    }

    if( scService != 0 )
    {
        
        if( !DeleteService( scService ) )
        {
            print( "Failed to delete service, error = %08x\n", GetLastError() );
        }

        if( !CloseServiceHandle( scService ) )
        {
            print( "Failed to close service handle, error = %08x\n", GetLastError() );
        }

        scService = 0;
    }

    if( scManager != NULL )
    {
        if( !CloseServiceHandle( scManager ) )
        {
            print( "Failed to close service manager handle, error = %08x\n", GetLastError() );
        }
        scManager = 0;
    }
}
#endif //!SYMCRYPT_APPLE_CC

VOID
runFunctionalTests()
{
    
#if !SYMCRYPT_APPLE_CC
    if( g_runKernelmodeTest )
    {
        runKernelmodeTests();
        return;
    }
#endif

    print( "\nFunctional tests:\n" );
    
    developertest();

    rdrandTest();

    testWipe();

    testUtil();

    testHashAlgorithms();

    testBlockCipherAlgorithms();

    testMacAlgorithms();

    testStreamCipherAlgorithms();

    testKdfAlgorithms();

    testAuthEncAlgorithms();
    
    testAesCtrDrbg();

    testXtsAlgorithms();

    testTlsCbcHmacAlgorithms();

    testArithmetic();

    testScsTable();

    testRsa();

    testDl();

    testEcc();

    testIEEE802_11SaeCustom();

    iprint( "Functional testing done.\n" );

    PrintTable ptResults;
    PrintTable ptErrors;

    g_nTotalErrors = 0;

    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        String row = (*i)->m_algorithmName + (*i)->m_modeName;
        ptResults.addItemNonZero( row, (*i)->m_implementationName, (*i)->m_nResults );

        ULONGLONG nErrors = (*i)->m_nErrorDisagreeWithMajority + (*i)->m_nErrorNoMajority + (*i)->m_nErrorKatFailure;
        
        ptErrors. addItemNonZero( row, (*i)->m_implementationName, nErrors );

        g_nTotalErrors += nErrors;

    }
    ptResults.print( "Number of verified results" );
    print( "\n" );
    ptErrors.print( "NUMBER OF ERRORS" );

    print( "\n" );

    printOutput( 0 );

}

#if !SYMCRYPT_APPLE_CC
VOID
runPerfTests()
{
    if( g_runKernelmodeTest )
    {
        return;
    }

    g_perfTestsRunning = TRUE;
    
    measurePerf();

    print( "Unit of performance measurement: %s\n    frequency = %4.0f MHz (vs. tickCtr) / %4.0f MHz (vs. perfCtr)\n", 
            g_perfUnits, g_tscFreqTickCtr / 1e6, g_tscFreqPerfCtr / 1e6 );

    PrintTable ptPerf;
    PrintTable ptWipe;
    
    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        for( std::vector<AlgorithmImplementation::ALG_PERF_INFO>::const_iterator j = (*i)->m_perfInfo.begin();
                j != (*i)->m_perfInfo.end();
                ++j )
        {
            String name = (*i)->m_algorithmName + (*i)->m_modeName;
            if( j->keySize > 0 )
            {
                char buf[100];
                SNPRINTF_S( buf, sizeof( buf ), _TRUNCATE, "-%4d", (ULONG) (j->keySize & 0xffff) * 8 );

                name = name + buf;
            }
            name = name + " " + j->strPostfix;

            ptPerf.addItem( name, (*i)->m_implementationName, 
                        j->cPerByte, j->cFixed, j->cRange );
        }
    }

    if( TRUE || isAlgorithmPresent( "Wipe", FALSE ) )   // Check doesn't work, should fix...
    {
        for( int offset = 0; offset < PERF_WIPE_N_OFFSETS; offset ++ )
        {
            for( int len = 0; len <= PERF_WIPE_MAX_SIZE; len ++ )
            {
                CHAR row[20];
                CHAR col[20];
                CHAR item[20];

                SNPRINTF_S( row, sizeof( row ), _TRUNCATE, "%2d", len );
                SNPRINTF_S( col, sizeof( col ), _TRUNCATE, "%2d", offset );
                SNPRINTF_S( item, sizeof( item ), _TRUNCATE, "%3.0f", g_wipePerf[len][offset] );

                            
                ptWipe.addItem( String( row ), String( col ), String( item ) );
            }
        }
    
        ptWipe.print( "Wipe performance for each len & alignment" );
    }

    ptPerf.print( "Performance for n-byte message/key" );
    printOutput( 0 );

    if( g_runRsaAverageKeyPerf )
    {
        runRsaAverageKeyGenPerf();
    }

    g_perfTestsRunning = FALSE;

}
#endif //SYMCRYPT_APPLE_CC
    

VOID
exitTestInfrastructure()
{
    while( g_algorithmImplementation.begin() != g_algorithmImplementation.end() )
    {
        delete g_algorithmImplementation.back();
        g_algorithmImplementation.pop_back();
    }

    CHECK( g_nTotalErrors == 0, "Errors detected in algorithms, see tables above for details." );

    print( "\n...SymCrypt unit test done\n" );
    printOutput( 0 );
}

VOID
rdrandTest()
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    BOOL present = SymCryptRdrandStatus() == SYMCRYPT_NO_ERROR;
    BYTE buf[SYMCRYPT_SHA512_RESULT_SIZE];

    if( present )
    {
        BYTE * p = new BYTE[ 3 * SYMCRYPT_RDRAND_RESEED_SIZE ];
        CHECK( p != NULL, "Out of memory in rdrandTest()" );
        SymCryptRdrandGet( p, 3 * SYMCRYPT_RDRAND_RESEED_SIZE, buf );

        //
        // print part of the result, so that the compiler can't optimize it all away
        //
        print( "RDRAND present %c\n", '0' + buf[3] % 45 );
        delete [] p;
    }

    present = SymCryptRdseedStatus() == SYMCRYPT_NO_ERROR;
    if( present )
    {
        SymCryptRdseedGet( buf, sizeof( buf ) );

        //
        // print part of the result, so that the compiler can't optimize it all away
        //
        print( "RDSEED present %c\n", '0' + buf[3] % 45 );
    }
#endif
}

//
// Below some of the code used to test the XMM registers.
// This is Unittest code, so outside the extern "C" block.
//


#if SYMCRYPT_CPU_X86
/////////////////////////////////////////////////////////////
//
// Code to set up the XMM registers for testing in SAVE_XMM mode

__m128i g_xmmStartState[8];
__m128i g_xmmTestState[8];

//
// The save/restore functions work on an aligned subset of the structure.
// We don't care which part is used, we copy the start structure, store the 
// XMM registers in it, and check that it is the same.
//

VOID
verifyXmmRegisters()
{
    BOOL difference = FALSE;
    if( TestSaveXmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_SSE2 ) && !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL ) )
    {
        memset( g_xmmTestState, 0, sizeof( g_xmmTestState ) );
        SymCryptEnvUmSaveXmmRegistersAsm( g_xmmTestState );

        difference = memcmp( g_xmmTestState, g_xmmStartState, sizeof( g_xmmStartState ) ) != 0;

        if( difference )
        {
            //
            // Starting late 2018 our compiler & CRT are now using XMM registers for transient things.
            // In particular, the compiler calls memset() on a large local struct to wipe the memory.
            // (Part of the security mitigations against leaking data from uninitialized stack variables.)
            // The CRT in turn uses XMM0 to wipe more efficiently.
            // This is indistinguishable from a SymCrypt bug where we use XMM registers in X86 code without
            // proper save/restore logic.
            // In short: we cannot test this anymore in user mode. We'd have to compile for Win7 kernel mode
            // to even run this test.
            // For now we will relax this test to not be triggered by the compiler/CRT. This means that we
            // no longer test this property, but we can at least detect some violations, which is better
            // than none.
            //
            if( (g_xmmTestState[0].m128i_u64[0] | g_xmmTestState[0].m128i_u64[1]) == 0 &&
                memcmp( &g_xmmTestState[1], &g_xmmStartState[1], 7 * sizeof( g_xmmStartState[0] ) ) == 0 )
            {
                difference = FALSE;
            }
        }

        if( difference )
        {
            print( "\n" );
            print( "Registers different: " );
            for( int i=0; i<8; i++ )
            {
                if( memcmp( &g_xmmTestState[i], &g_xmmStartState[i], 16 ) != 0 )
                {
                    print( "xmm%d ", i );
                }

            }
            print( "\nStartState:\n" );
            printHexArray( (PCBYTE) g_xmmStartState, 8, 16 );
            print( "TestState:\n");
            printHexArray( (PCBYTE) g_xmmTestState, 8, 16 );

            ULONGLONG checksum;
            SymCryptMarvin32( SymCryptMarvin32DefaultSeed, (PCBYTE) g_xmmStartState, 8*16, (PBYTE) &checksum );
            print( "%04x\n", (ULONG) checksum & 0xffff );
            SymCryptMarvin32( SymCryptMarvin32DefaultSeed, (PCBYTE) g_xmmTestState, 8*16, (PBYTE) &checksum );
            print( "%04x\n", (ULONG) checksum & 0xffff );

            FATAL( "Xmm registers modified without proper save/restore" );
        }
    }
}


VOID
initXmmRegisters()
{
/*
#pragma prefast(push)
#pragma prefast(disable:6031)
    BCryptGenRandom( NULL, (PBYTE) g_xmmStartState, sizeof( g_xmmStartState ), BCRYPT_USE_SYSTEM_PREFERRED_RNG );
#pragma prefast(pop)
    memcpy( g_xmmTestState, g_xmmStartState, sizeof( g_xmmStartState ) );

    SymCryptEnvUmRestoreXmmRegistersAsm( g_xmmStartState );
*/
    if( TestSaveXmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_SSE2 ) && !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL ) )
    {
        SymCryptEnvUmSaveXmmRegistersAsm( g_xmmStartState );
        verifyXmmRegisters();
    }
}

#else

VOID verifyXmmRegisters() 
{
}

VOID initXmmRegisters() 
{
}
#endif

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
/////////////////////////////////////////////////////////////
//
// Code to set up the XMM registers for testing in SAVE_XMM mode

#if SYMCRYPT_CPU_AMD64
__m256i g_ymmStartState[16];
__m256i g_ymmTestState[16];
#else
__m256i g_ymmStartState[8];
__m256i g_ymmTestState[8];
#endif


VOID
verifyYmmRegisters()
{
    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        verifyXmmRegisters();
        return;
    }

    //
    // We know that AVX2 is present from here on
    //
    if( TestSaveYmmEnabled )
    {
        SymCryptEnvUmSaveYmmRegistersAsm( g_ymmTestState );

        //
        // On AMD64 it is perfectly fine for the XMM register values to have been modified. 
        // On x86 it is not.
        // We don't use memcmp() 'cause it might use XMM registers on x86
        //
        for( int i=0; i<sizeof( g_ymmStartState ); i++ )
        {
            if( ((volatile BYTE * )&g_ymmStartState[0])[i] != ((volatile BYTE * )&g_ymmTestState[0])[i] &&
                (SYMCRYPT_CPU_X86 || (i & 16) == 1 )
                )
            {
                FATAL2( "Ymm registers modified without proper save/restore %d", i );
            }
        }
    }
}


VOID
initYmmRegisters()
{
    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        initXmmRegisters();
        return;
    }
    if( TestSaveYmmEnabled )
    {
        //
        // Do the memset outside the save area 'cause it might use XMM registers on x86
        //
        memset( g_ymmTestState, 17, sizeof( g_ymmTestState ) );
        SymCryptEnvUmSaveYmmRegistersAsm( g_ymmStartState );
        verifyYmmRegisters();
    }
}

#else

VOID verifyYmmRegisters() 
{
}

VOID initYmmRegisters() 
{
}
#endif

VOID
printHexArray( PCBYTE pData, SIZE_T nElements, SIZE_T elementSize )
{
    for( ULONG i=0; i<nElements; i++ )
    {
        print( "%2d: ", i );
        for( ULONG j=0; j<elementSize; j++ )
        {
            print( "%02x", *pData++ );
            if( j % 4 == 3 )
            {
                print( " " );
            }
        }
        print( "\n" );
    }
}

#if SYMCRYPT_CPU_X86
// XMM registers are never a problem on amd64, and we don't have the save-xmm asm code
VOID
printXmmRegisters( char * text )
{
    __m128i regs[8];

    SymCryptEnvUmSaveXmmRegistersAsm( &regs[0] );
    print( "\nXmm registers %s\n", text );
    printHexArray( (PCBYTE) &regs[0], 8, 16 );
}

#endif