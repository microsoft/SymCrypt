//
// Main.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

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
    // It is primarily used during development of new code to run the test code
    // without having to wait for all the other things to run.
    //
    // Note: there is also a DeveloperTest algorithm that can be used for developer performance
    // tests.
    //
}

//
// Special extern declarations to allow us to disable AES-NI on the RSA32 library
//
#if INCLUDE_IMPL_RSA32
extern "C" {
extern BYTE AesUseXmm;
extern BOOL AesDetectXmmDone;
}
#endif

ULONG ModeEcb::flags = 0;
ULONG ModeCbc::flags = MODE_FLAG_CHAIN;
ULONG ModeCfb::flags = MODE_FLAG_CHAIN | MODE_FLAG_CFB;


BOOL AlgRc4::isRandomAccess = FALSE;
BOOL AlgChaCha20::isRandomAccess = TRUE;

ULONG   g_rc2EffectiveKeyLength = 0;
SIZE_T  g_modeCfbShiftParam = 1;

Rng g_rng;

BOOL g_modifiedCpuFeatures = FALSE;
BOOL g_failRegisterSave = FALSE;
BOOL g_runRsaAverageKeyPerf = FALSE;

DWORD g_osVersion;
ULONG g_rngSeed = 0;

ULONGLONG g_nTotalErrors = 0;

SYMCRYPT_CPU_FEATURES g_disabledOnCommandLine = 0;

PVOID g_dynamicSymCryptModuleHandle = nullptr;

BOOL g_useDynamicFunctionsInTestCall = FALSE;

//
// For most performance data we compute a line (a*n + b) for the time it takes to process an n-byte
// message. We also compute the 90 percentile of the deviation of the cloud points from this line.
// The flag below can be set to show this 90 percentile range in the output.
//
BOOL g_showPerfRangeInfo = FALSE;

//
// We show detailed information if this flag is set.
//
BOOL g_verbose = FALSE;

//
// Option to skip running performance tests
// Helpful when running in an emulated environment where we just want to test the functionality
//
BOOL g_noPerfTests = FALSE;

//
// Profiling options to run an algorithm in a tight loop
//
BOOL g_profile = FALSE;
UINT32 g_profile_iterations = 0;
UINT32 g_profile_key = 0;

//
// Profiling options to run an algorithm for a range of specific sizes
//
BOOL g_measure_specific_sizes = FALSE;
UINT32 g_measure_sizes_start = 0;
UINT32 g_measure_sizes_end = 0;
UINT32 g_measure_sizes_increment = 1;
UINT32 g_measure_sizes_repetitions = 1;
String g_measure_sizes_stringPrefix = "";

String g_dynamicModulePath = "";

//
// Flag that specifies that we run performance tests
//
BOOL g_perfTestsRunning = FALSE;

//
// Flag to print the FIPS status indicator
//
BOOL g_printStatusIndicator = FALSE;

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
        if( str.size() >= i->size())
        {
            found = TRUE;
            for( SIZE_T j=0; j< i->size(); j++ )
            {
                if( charToLower( (*i)[j] ) != charToLower( str[j] ) )
                {
                    found = FALSE;
                    break;
                }
            }

            if( found )
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOL
updateNameSet( _In_z_ PCSTR * names, _Inout_ StringSet * set, CHAR op, _In_ PSTR name )
{
    BOOL nameMatch = FALSE;
    SIZE_T nameLen = strlen( name );

    if( nameLen == 0 )
    {
        return FALSE;
    }

    for( SIZE_T i=0; names[i] != NULL; i++ )
    {
        if( op == '+' )
        {
            SIZE_T prefixLen = strlen( names[i] );
            prefixLen = prefixLen < nameLen ? prefixLen : nameLen;
            // if parameter is a prefix of the set element
            // or set element is a prefix of the parameter
            if( STRNICMP( name, names[i], prefixLen ) == 0 )
            {
                nameMatch = TRUE;
                set->insert( name );
                break;
            }
        }
        else
        {
            // if parameter is a prefix of the set element
            if( STRNICMP( name, names[i], nameLen ) == 0 )
            {
                if( set->size() == 0 )
                {
                    for( SIZE_T j=0; names[j] != NULL; j++ )
                    {
                        set->insert( names[j] );
                    }
                }
                set->erase( names[i] );
                nameMatch = TRUE;
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
                return TRUE;
            }
        }
    }
    return FALSE;
}

const char * g_algorithmNames[] = {
    AlgMd2::name,
    AlgMd4::name,
    AlgMd5::name,
    AlgSha1::name,
    AlgSha224::name,
    AlgSha256::name,
    AlgSha384::name,
    AlgSha512::name,
    AlgSha512_224::name,
    AlgSha512_256::name,
    AlgSha3_224::name,
    AlgSha3_256::name,
    AlgSha3_384::name,
    AlgSha3_512::name,
    AlgShake128::name,
    AlgShake256::name,
    AlgCShake128::name,
    AlgCShake256::name,
    AlgKmac128::name,
    AlgKmac256::name,
    AlgHmacMd5::name,
    AlgHmacSha1::name,
    AlgHmacSha224::name,
    AlgHmacSha256::name,
    AlgHmacSha384::name,
    AlgHmacSha512::name,
    AlgHmacSha512_224::name,
    AlgHmacSha512_256::name,
    AlgHmacSha3_224::name,
    AlgHmacSha3_256::name,
    AlgHmacSha3_384::name,
    AlgHmacSha3_512::name,
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
    AlgChaCha20Poly1305::name,
    AlgAesCtrDrbg::name,
    AlgAesCtrF142::name,
    AlgDynamicRandom::name,
    AlgParallelSha256::name,
    AlgParallelSha384::name,
    AlgParallelSha512::name,
    AlgPbkdf2::name,
    AlgSp800_108::name,
    AlgTlsPrf1_1::name,
    AlgTlsPrf1_2::name,
    AlgSshKdf::name,
    AlgSrtpKdf::name,
    AlgHkdf::name,
    AlgSskdfMac::name,
    AlgSskdfHash::name,
    AlgXtsAes::name,
    AlgAesKw::name,
    AlgAesKwp::name,
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
    //AlgRsaDecRaw::name,
    AlgRsaEncPkcs1::name,
    //AlgRsaDecPkcs1::name,
    AlgRsaEncOaep::name,
    //AlgRsaDecOaep::name,
    AlgRsaSignPkcs1::name,
    //AlgRsaVerifyPkcs1::name,
    AlgRsaSignPss::name,
    AlgRsakeySetValue::name,
    AlgRsakeySetValueFromPrivateExponent::name,
    //AlgRsaVerifyPss::name,
    //AlgDsaSign::name,
    //AlgDsaVerify::name,
    AlgDh::name,
    AlgDsa::name,
    AlgEcurveAllocate::name,
    AlgEckeySetRandom::name,
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
    AlgEckeySetValue::name,
    AlgXmss::name,
    AlgLms::name,
    AlgMlKem::name,
    AlgMlKemkeySetValue::name,
    AlgMlDsa::name,
    AlgMlDsakeySetValue::name,

    AlgDeveloperTest::name,
    NULL,
};


const char * g_modeNames[] = {
    ModeEcb::name,
    ModeCbc::name,
    ModeCfb::name,
    ModeCcm::name,
    ModeGcm::name,
    ModeNone::name,
    NULL,
};

VOID
usage()
{
    const char * sep;
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
            "  sizes:<startSize>,<endSize>,<sizeIncrement>,<numberOfRepetitions>\n"
            "                    Run algorithms for dataSizes specified at the command line, rather\n"
            "                    than using the sizes built into the unit tests and performing\n"
            "                    a linear regression. All parameters are unsigned decimal integers.\n"
            "                    Only a prefix of the parameters needs to be specified - i.e. sizes:1024\n"
            "                    tests specified algorithms/implementations at only a dataSize of 1024\n"
            "  sizeprefix:<prefix>      Only applies when sizes: parameter is also specified. Prefixes\n"
            "                           output of test command with a specific string. This can enable\n"
            "                           easier concatenation of many test runs on differing platforms into\n"
            "                           a single .csv for postprocessing.\n"
            "  verbose           Print detailed information for some algorithms\n"
            "  noperftests       Skip running the performance tests - only run functional tests\n"
            "  profile:xxx [key=yyy]    Run one or more algorithms in a tight loop, xxx times for\n"
            "                           each key/datasize combination. The algorithms to run are specified\n"
            "                           by the +/- options. The optional key parameter can specify\n"
            "                           that only the key size with the hex code yyy will be run.\n"
            "                           Note: If you don't know the desired key, run profiling without\n"
            "                               the key parameter and all possible codes will get printed.\n"
            "  rsakgp            Run perf measurement of RSA key generation.\n"
            "  sgx               Run CNG and symcrypt test implementations against BCrypt in SGX enclave.\n"
            "                    This option is only valid for win8_1 version and newer of the tests.\n"
            "  testSaveYmm       This option enables the unit tests to test the save/restore logic for\n"
            "                    Ymm registers. Normally the C runtime may overwrite Ymm registers and\n"
            "                    these tests will fail, so the test is disabled by default.\n"
            "  dynamic:<path_to_module>\n"
            "                    This option instructs the unit tests to load <path_to_module> as another\n"
            "                    external implementation of the SymCrypt APIs, which will be added as an\n"
            "                    implementation called SymCryptDynamic. By default, all calls to SymCrypt\n"
            "                    are passed to both the statically and dynamically linked SymCrypt versions\n"
            " statusindicator    Print FIPS status indicator string\n"
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

    sep = " Mode names:        ";
    for( i=0; g_modeNames[i] != NULL; i++ )
    {
        iprint( "%s%s", sep, g_modeNames[i] );
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
    { "vaes", SYMCRYPT_CPU_FEATURE_VAES },
    { "avx512", SYMCRYPT_CPU_FEATURE_AVX512 },
    { "cmpxchg16b", SYMCRYPT_CPU_FEATURE_CMPXCHG16B },
#elif SYMCRYPT_CPU_ARM64
    { "neon", SYMCRYPT_CPU_FEATURE_NEON },
    { "i_aes", SYMCRYPT_CPU_FEATURE_NEON_AES },
    { "i_pmull", SYMCRYPT_CPU_FEATURE_NEON_PMULL },
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
    for( SIZE_T i=0; i < sizeof( g_cpuFeatureData ) / sizeof( g_cpuFeatureData[0] ); i++ )
    {
        if( !(notPresent & g_cpuFeatureData[i].mask) )
        {
            print( "%c%s", sep, g_cpuFeatureData[i].name );
            sep = ',';
        }
    }
    print( "\n" );
}

VOID printTestVectorSaveOptions()
{
    CHAR sep = ' ';
    print("\nTest Vector Save/Restore options:");
    if (TestSaveXmmEnabled)
    {
        print("%cTestSaveXmmEnabled", sep);
        sep = ',';
    }
    if (TestSaveYmmEnabled)
    {
        print("%cTestSaveYmmEnabled", sep);
        sep = ',';
    }
    if (sep == ' ')
    {
        print(" None");
    }
    print("\n");
}

VOID
printSymCryptFipsGetSelftestsPerformed()
{
    UINT32 fipsSelfTestsPerformed = SymCryptFipsGetSelftestsPerformed();
    print("static  SymCryptFipsGetSelftestsPerformed() %x\n", fipsSelfTestsPerformed);

    if( g_dynamicSymCryptModuleHandle != NULL )
    {
        decltype(&SymCryptFipsGetSelftestsPerformed) dynamicSymCryptFipsGetSelftestsPerformed = SCTEST_LOOKUP_DYNSYM(SymCryptFipsGetSelftestsPerformed, TRUE);
        if (dynamicSymCryptFipsGetSelftestsPerformed != NULL)
        {
            print("dynamic SymCryptFipsGetSelftestsPerformed() %x\n", dynamicSymCryptFipsGetSelftestsPerformed());
        }
    }
}

VOID
processSingleOption( _In_ PSTR option )
{
    BOOL optionHandled = FALSE;
    if( option[0] == '+' || option[0] == '-' )
    {
        if( STRICMP( &option[0], "-aesni" ) == 0 )
        {
#if INCLUDE_IMPL_RSA32 & (SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64)
            //
            // Disable AES-NI for RSA32 and SymCrypt
            //
            AesUseXmm = 0;
            AesDetectXmmDone = TRUE;
#endif
        }

        for( SIZE_T i=0; i < sizeof(g_cpuFeatureData)/sizeof(g_cpuFeatureData[0]); i++ )
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

        if( STRICMP( &option[0], "noperftests" ) == 0 )
        {
            g_noPerfTests = TRUE;
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "profile:", 8 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 8 );
            g_profile = TRUE;
            g_profile_iterations = (UINT32) strtoul( &option[8], &endptr, 0 );
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
            g_profile_key = (UINT32) strtoul( &option[4], &endptr, 16 );
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "sizes:", 6 ) == 0 )
        {
            char * endptr;
            __analysis_assume( strlen(option) >= 6 );
            g_measure_specific_sizes = TRUE;
            g_measure_sizes_start = (UINT32) strtoul( &option[6], &endptr, 0 );
            g_measure_sizes_end = (UINT32) strtoul( endptr+1, &endptr, 0 );
            g_measure_sizes_increment = (UINT32) strtoul( endptr+1, &endptr, 0 );
            g_measure_sizes_repetitions = (UINT32) strtoul( endptr+1, &endptr, 0 );

            if (g_measure_sizes_end == 0)
            {
                g_measure_sizes_end = g_measure_sizes_start;
            }
            if (g_measure_sizes_increment == 0)
            {
                g_measure_sizes_increment = (g_measure_sizes_start >= g_measure_sizes_end) ? 1 : g_measure_sizes_end - g_measure_sizes_start;
            }
            if (g_measure_sizes_repetitions == 0)
            {
                g_measure_sizes_repetitions = 1;
            }
            optionHandled = TRUE;
        }

        if( STRNICMP( &option[0], "sizeprefix:", 11 ) == 0 )
        {
            __analysis_assume( strlen(option) >= 11 );

            g_measure_sizes_stringPrefix = String( &option[11] );
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
            g_osVersion = (UINT32) strtoul( &option[10], &endptr, 16 );
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
            g_rngSeed = (UINT32) strtoul( &option[8], &endptr, 16 );
            optionHandled = TRUE;
        }
        if (STRICMP(&option[0], "sgx") == 0)
        {
            g_sgx = TRUE;
            optionHandled = TRUE;
        }
        if (STRICMP(&option[0], "testSaveYmm") == 0)
        {
            TestSaveYmmEnabled = TRUE;
            optionHandled = TRUE;
        }
        if (STRNICMP(&option[0], "dynamic:", 8) == 0)
        {
            __analysis_assume(strlen(option) >= 8);

            g_dynamicModulePath = String(&option[8]);
            optionHandled = TRUE;
        }
        if (STRICMP(&option[0], "statusindicator") == 0)
        {
            g_printStatusIndicator = TRUE;
            optionHandled = TRUE;
        }

    }
    if( !optionHandled )
    {
        print( "\nUnknown option \"%s\"", option );
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

VOID printCpuidInfo();

_Analysis_noreturn_
VOID
fatal( _In_ PCSTR file, ULONG line, _In_ PCSTR format, ... )
{
    va_list vl;

    printCpuidInfo();
    printOutput( 0 );

    fprintf( stdout, "*\n\n***** FATAL ERROR %s(%lu): ", file, line );

    va_start( vl, format );

    vfprintf( stdout, format, vl );
    fprintf( stdout, "\n" );

    TRAP_DEBUGGER();
    exit( -1 );
}

#if SYMCRYPT_MS_VC
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
    CHECK( resourceDataHandle != NULL, "Failed to load resource" );

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

    #pragma warning(push)
    #pragma warning(disable:4996) // GetVersionEx is deprecated
    CHECK( GetVersionEx( &versionInfo ), "Failed to get OS version info" );
    #pragma warning(pop)

    g_osVersion = (versionInfo.dwMajorVersion << 8) + (versionInfo.dwMinorVersion & 0xff);
}
#elif SYMCRYPT_GNUC
#include "resource.h"
KatData *
getCustomResource( _In_ PSTR resourceName, _In_ PSTR /* resourceType */)
{
    PCCHAR pbData = nullptr;
    SIZE_T cbData = GetResourceBytes((const char *)resourceName, &pbData);
    CHECK( cbData != 0, "Resource not found" );

    return new KatData( resourceName, pbData, cbData - 1 );
}

#endif

void printPlatformInformation( _In_z_ char * text )
{

#if SYMCRYPT_CPU_X86
    PCSTR const arch = "x86";
#elif SYMCRYPT_CPU_AMD64
    PCSTR const arch = "amd64";
#elif SYMCRYPT_CPU_ARM64
    PCSTR const arch = "arm64";
#elif SYMCRYPT_CPU_ARM
    PCSTR const arch = "arm";
#else
    PCSTR const arch = "generic";
#endif

#if SYMCRYPT_DEBUG
    PCSTR const flavor = "Debug";
#else
    PCSTR const flavor = "Release";
#endif

    std::ostringstream osName;
#if SYMCRYPT_PLATFORM_WINDOWS
    osName << "Windows ";
    osName << std::hex << g_osVersion;
#elif (SYMCRYPT_PLATFORM_APPLE || SYMCRYPT_PLATFORM_UNIX)
    utsname nameStruct;
    if( uname(&nameStruct) >= 0 )
    {
        osName << nameStruct.sysname << " " << nameStruct.release;
    }
    else
    {
        osName << "Unknown platform (uname failed!)";
    }
#else
    osName << "Unknown platform";
#endif

    iprint( "\n%s %s %s %s\n", text, arch, flavor, osName.str().c_str() );

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    int CPUInfo[4];
    char nameBuf[20];

    __cpuidex( CPUInfo, 0, 0 );
    memcpy( &nameBuf[0], (BYTE *)&CPUInfo[1], 4 );
    memcpy( &nameBuf[4], (BYTE *)&CPUInfo[3], 4 );
    memcpy( &nameBuf[8], (BYTE *)&CPUInfo[2], 4 );
    nameBuf[12] = 0;

    __cpuidex( CPUInfo, 1, 0 );
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
#define CPUID_1_ECX_OSXSAVE_BIT 27

    int CPUInfo[4];

    print( "\nCPUID raw information\n" );
    print( "leaf        eax       ebx       ecx       edx\n");
    for( int i=0; i<=7; i++)
    {
        __cpuidex( CPUInfo, i, 0 );
        print( "%1d         %08x, %08x, %08x, %08x\n", i, CPUInfo[WORD_EAX], CPUInfo[WORD_EBX], CPUInfo[WORD_ECX], CPUInfo[WORD_EDX] );
    }

    __cpuidex(CPUInfo, 1, 0);
    if( (CPUInfo[WORD_ECX] & (1 << CPUID_1_ECX_OSXSAVE_BIT)) != 0 )
    {
        INT64 xGetBvResult = _xgetbv( _XCR_XFEATURE_ENABLED_MASK );
        print( "\nxGetBv(0)\n%016llx", xGetBvResult );
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
       resultsize = SYMCRYPT_MAX( 1, resultsize % (SYMCRYPT_HMAC_SHA512_RESULT_SIZE * 4));

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

//
// Reach into the internals of SymCrypt to retrieve the build string
extern "C" {
extern const CHAR * const SymCryptBuildString;
};

VOID
initTestInfrastructure( int argc, _In_reads_( argc ) char * argv[] )
{
    ULONGLONG moduleLoadStart, moduleLoadEnd;
    iprint( "SymCrypt unit test program, "
             "Library version %s\n"
             "Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n", SymCryptBuildString );

#define SYMCRYPT_CHECK_ASM_OFFSET( a, b ) CHECK4( (a) == (b), "Assembler offset incorrect: %s should be %d", #a, (b) );
    SYMCRYPT_CHECK_ASM_OFFSETS;
#undef SYMCRYPT_CHECK_ASM_OFFSET

    SymCryptInit();

#if SYMCRYPT_MS_VC
    getPlatformInformation();
#endif

    printPlatformInformation( "System information:" );
    printSymCryptCpuInfo( "Hardware CPU features", g_SymCryptCpuFeaturesNotPresent );

    processOptions( argc, argv );

    if( g_modifiedCpuFeatures )
    {
        printPlatformInformation( "Modified System information for this test" );
        printSymCryptCpuInfo( "Modified CPU features for this test", g_SymCryptCpuFeaturesNotPresent );
    }

    printTestVectorSaveOptions();

    if( !g_dynamicModulePath.empty() )
    {
        moduleLoadStart = GET_PERF_CLOCK();
        g_dynamicSymCryptModuleHandle = loadDynamicModuleFromPath(g_dynamicModulePath.c_str());
        moduleLoadEnd = GET_PERF_CLOCK();
        CHECK(g_dynamicSymCryptModuleHandle != NULL, "Failed to load dynamic module. Is the path correct?");

        iprint("\nLoaded %s to %llx\nTook ~%d cycles.\n", g_dynamicModulePath.c_str(), (UINT64)g_dynamicSymCryptModuleHandle, moduleLoadEnd-moduleLoadStart);

        SCTEST_GET_DYNSYM(SymCryptModuleInit, TRUE)(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR);

        // If dynamic module supports disabling CPU features, then disable them
        // Note this currently assumes the target under test has the same architecture as the unit tests
        decltype(&SctestDisableCpuFeatures) dynamicSctestDisableCpuFeatures = SCTEST_LOOKUP_DYNSYM(SctestDisableCpuFeatures, TRUE);
        if( dynamicSctestDisableCpuFeatures != NULL )
        {
            printSymCryptCpuInfo( "Dynamic Hardware CPU features", dynamicSctestDisableCpuFeatures(g_disabledOnCommandLine) );
        }
    }

    printSymCryptFipsGetSelftestsPerformed();

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
        // Disable the RSA32b implementation by default
        //
        updateNameSet( g_implementationNames, &g_implementationsToTest, '-', "rsa32b" );
    }

    AllocWithChecksInit();

    printOutput( 0 );
}

VOID
runFunctionalTests()
{
    print( "\n\nFunctional tests:\n" );

    developertest();

    // Optionally rerun tests which directly call SymCrypt APIs specifying g_useDynamicFunctionsInTestCall
    // to dispatch the calls to the dynamic SymCrypt module.
    for( BOOL useDynamicFunctions : {FALSE, TRUE} )
    {
        // Unfortunately range based for loop needs a new variable declaration
        g_useDynamicFunctionsInTestCall = useDynamicFunctions;
        if( g_useDynamicFunctionsInTestCall && !g_dynamicSymCryptModuleHandle )
        {
            break;
        }

        iprint("SymCrypt %s function tests\n", g_useDynamicFunctionsInTestCall ? "dynamic" : "static");

        rdrandTest();

        testWipe();

        testUtil();

        testScsTable();

        testScsTools();

        testPaddingPkcs7();

#if SYMCRYPT_MS_VC
        testIEEE802_11SaeCustom();
#endif
    }

    iprint("Multi-implementation tests\n");

    g_useDynamicFunctionsInTestCall = FALSE;
    // From here we will have the dynamic SymCrypt module act as an alternative implementation
    // which will enable comparative functional and performance tests
    // The tests may modify g_useDynamicFunctionsInTestCall themselves to perform specific subtests
    // with dispatch functions

    testDataAccessors();

    testHashAlgorithms();

    testBlockCipherAlgorithms();

    testKeyWrapAlgorithms();

    testMacAlgorithms();

    testXofAlgorithms();

    testCustomizableXofAlgorithms();

    testKmacAlgorithms();

    testStreamCipherAlgorithms();

    testKdfAlgorithms();

    testAuthEncAlgorithms();

    testAesCtrDrbg();

    testXtsAlgorithms();

    testTlsCbcHmacAlgorithms();

    testArithmetic();

    testRsaSignAlgorithms();

    testRsaEncAlgorithms();

    testDhAlgorithms();

    testDsaAlgorithms();

    testEcc();

    testHbs();

    testKem();

    testPqDsa();

    printSymCryptFipsGetSelftestsPerformed();

    testStatusIndicator(g_printStatusIndicator);

    testServiceIndicator();

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

VOID
runPerfTests()
{
    if( g_noPerfTests )
    {
        return;
    }

    g_perfTestsRunning = TRUE;

    for( UINT32 measurementRepetitions = 0; measurementRepetitions < g_measure_sizes_repetitions; measurementRepetitions++ )
    {
        measurePerf();
    }

    print( "Unit of performance measurement: %s\n    frequency = %4.0f MHz (using std::chrono)\n",
        g_perfUnits, g_tscFreq / 1e6);

    if( g_measure_specific_sizes )
        print("AlgorithmName,KeySize,Operation,KeyParam,ImplementationName,DataSize,%s\n", g_perfUnits);


    PrintTable ptPerf;
    PrintTable ptWipe;

    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        for( std::vector<AlgorithmImplementation::ALG_PERF_INFO>::const_iterator j = (*i)->m_perfInfo.begin();
                j != (*i)->m_perfInfo.end();
                ++j )
        {
            if( !g_measure_specific_sizes )
            {
                String name = (*i)->m_algorithmName + (*i)->m_modeName;
                if( j->keySize > 0 )
                {
                    ULONG keySize = (ULONG) (j->keySize & 0xffff);

                    // Hack: For ML-DSA, don't multiply the key size by 8 since it refers to a
                    // parameter set. In the future we should refactor the performance measurement
                    // architecture to be able to handle these types of algorithms more gracefully.
                    if( (*i)->m_algorithmName.substr(0, 5) != "MlDsa" )
                    {
                        keySize *= 8;
                    }

                    char buf[100];
                    SNPRINTF_S( buf, sizeof( buf ), _TRUNCATE, "-%4lu", keySize );

                    name = name + buf;
                }
                name = name;
                if (j->operationName != NULL && strlen(j->operationName) > 0)
                {
                    name += String(" ") + j->operationName;
                }

                if (j->strPostfix != NULL && strlen(j->strPostfix) > 0)
                {
                    name += String(" ") + j->strPostfix;
                }

                ptPerf.addItem( name, (*i)->m_implementationName,
                            j->cPerByte, j->cFixed, j->cRange );
            }
            else
            {
                print( "%s%s,%lu,%s,%s,%s,%lu,%lu\n",
                    g_measure_sizes_stringPrefix.c_str(),
                    ((*i)->m_algorithmName + (*i)->m_modeName).c_str(),
                    (ULONG) (j->keySize & 0xffff) * 8,
                    j->operationName,
                    j->strPostfix,
                    ((*i)->m_implementationName).c_str(),
                    (ULONG) j->dataSize,
                    (ULONG) floor(j->cFixed) );
            }
        }
    }

    if( !g_measure_specific_sizes || isAlgorithmPresent( "Wipe", FALSE ) )   // Check doesn't work, should fix...
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

    if( !g_measure_specific_sizes )
    {
        ptPerf.print( "Performance for n-byte message/key" );
        printOutput( 0 );

        if( g_runRsaAverageKeyPerf )
        {
            PrintTable ptRsaKeygen;
            addRsaKeyGenPerfSymCrypt<ImpScStatic>(ptRsaKeygen);
            if( g_dynamicSymCryptModuleHandle != NULL )
            {
                addRsaKeyGenPerfSymCrypt<ImpScDynamic>( ptRsaKeygen );
            }
#if INCLUDE_IMPL_MSBIGNUM
            addRsaKeyGenPerfMsBignum( ptRsaKeygen );
#endif
            ptRsaKeygen.print( "RSA key generation performance" );
            printOutput( 0 );
        }
    }

    g_perfTestsRunning = FALSE;

}


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
    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRdrandStatus)    ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRdrandGet)       ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRdseedStatus)    ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptRdseedGet) )
    {
        print("    rdrandTest skipped\n");
        return;
    }

    BOOL present = ScDispatchSymCryptRdrandStatus() == SYMCRYPT_NO_ERROR;
    BYTE buf[SYMCRYPT_SHA512_RESULT_SIZE];

    if( present )
    {
        BYTE * p = new BYTE[ 3 * SYMCRYPT_RDRAND_RESEED_SIZE ];
        CHECK( p != NULL, "Out of memory in rdrandTest()" );
        ScDispatchSymCryptRdrandGet( p, 3 * SYMCRYPT_RDRAND_RESEED_SIZE, buf );

        //
        // print part of the result, so that the compiler can't optimize it all away
        //
        print( "RDRAND present %c\n", '0' + buf[3] % 45 );
        delete [] p;
    }

    present = ScDispatchSymCryptRdseedStatus() == SYMCRYPT_NO_ERROR;
    if( present )
    {
        ScDispatchSymCryptRdseedGet( buf, sizeof( buf ) );

        //
        // print part of the result, so that the compiler can't optimize it all away
        //
        print( "RDSEED present %c\n", '0' + buf[3] % 45 );
    }
#endif
}

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

VOID
fprintHex( FILE * f, PCBYTE pbData, SIZE_T cbData )
{
    for( SIZE_T i=0; i<cbData; i++ )
    {
        fprintf( f, "%02x", pbData[i] );
    }
    fprintf( f, "\n" );
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

VOID
ReverseMemCopy(
    PBYTE pbDst,
    PCBYTE pbSrc,
    SIZE_T cbSrc
)
{
    PBYTE p;

    p = pbDst + cbSrc - 1;
    while(p >= pbDst)
    {
        *p-- = *pbSrc++;
    }
}
