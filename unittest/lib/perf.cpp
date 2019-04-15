//
// Performance measurement infrastructure
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


#include "precomp.h"


ULONGLONG g_minMeasurementClockTime = 0;
ULONGLONG g_largeMeasurementClockTime = (ULONGLONG)-1;
double g_perfScaleFactor;

double g_tscFreqTickCtr;
double g_tscFreqPerfCtr;

BOOLEAN g_enableCpuIdBeforeRdtsc = TRUE;

//
// The performance infrastructure has some flexibility to use different clocks.
// At the moment they can all use the time stamp counter.
// 

#if SYMCRYPT_CPU_ARM

#define GET_PERF_CLOCK() __rdpmccntr64()
#define SET_PERF_SCALEFACTOR() {g_perfScaleFactor = 1.0; g_minMeasurementClockTime = (ULONG) (10000 / g_perfScaleFactor); g_largeMeasurementClockTime = (ULONGLONG) (100000000 / g_perfScaleFactor);}
#define PERF_UNIT   "cycles"

#elif SYMCRYPT_CPU_ARM64

#define GET_PERF_CLOCK() _ReadStatusReg(ARM64_PMCCNTR_EL0)
#define SET_PERF_SCALEFACTOR() {g_perfScaleFactor = 1.0; g_minMeasurementClockTime = (ULONG) (10000 / g_perfScaleFactor); g_largeMeasurementClockTime = (ULONGLONG) (100000000 / g_perfScaleFactor);}
#define PERF_UNIT   "cycles"

#else



FORCEINLINE
ULONGLONG
GET_PERF_CLOCK()
{
    int tmp[4]; 

    if( g_enableCpuIdBeforeRdtsc )
    {
        __cpuid( tmp, 0);
    }
    return __rdtsc();
}

#define SET_PERF_SCALEFACTOR() {g_perfScaleFactor = 1.0; g_minMeasurementClockTime = 10000; g_largeMeasurementClockTime = (ULONGLONG) ((1<<28) / g_perfScaleFactor);}
#define PERF_UNIT   "cycles"

#endif


/*
//
// Some commented-out definitions that will be useful if we ever port this to a platform
// that doesn't have a time stamp counter
//

#if defined( _ARM_ )

#define GET_PERF_CLOCK() getPerfClock()
#define SET_PERF_SCALEFACTOR()  setPerfScaleFactor()

FORCEINLINE
ULONGLONG getPerfClock()
{
    LARGE_INTEGER t;
    QueryPerformanceCounter( &t );
    return (ULONGLONG) t.QuadPart;
}

#define PERF_UNIT   "ns"

VOID
setPerfScaleFactor()    // FOR ARM
{
    LARGE_INTEGER freq;
    QueryPerformanceFrequency( &freq );

    CHECK( freq.QuadPart != 0, "QueryPerformanceFrequency returned zero" );
    print( "Performance counter frequency = %lld\n", freq.QuadPart );

    g_perfScaleFactor = (double) 1e9 / (double) freq.QuadPart;  // print ns/b rather than clocks/b
    g_minMeasurementClockTime = 100;
}


VOID
setPerfScaleFactor()    // FOR IA64, even older
{
    SYSTEM_INFO systemInfo;
    ULONG nProcessors;
    NTSTATUS status;
    PPROCESSOR_POWER_INFORMATION    pProcPowerInfo = NULL;
    LARGE_INTEGER perfFreq;
    ULONG maxCurrent;
    
    //
    // Gather CPU information
    //
    GetSystemInfo( &systemInfo );
    nProcessors = systemInfo.dwNumberOfProcessors;

    pProcPowerInfo = new PROCESSOR_POWER_INFORMATION[ nProcessors ];
    CHECK( pProcPowerInfo != NULL, "Out of memory" );

    status = CallNtPowerInformation( ProcessorInformation, NULL, 0, pProcPowerInfo, nProcessors * sizeof( *pProcPowerInfo ) );
    CHECK3( NT_SUCCESS( status ), "Failed to get power info %08x", status );

    maxCurrent = 0;
    for( ULONG i=0; i<nProcessors; i++ )
    {
        //iprint( "Proc %2d, curr =%6d, max = %6d\n", i, pProcPowerInfo[i].CurrentMhz, pProcPowerInfo[i].MaxMhz );
        //maxCurrent = max( maxCurrent, pProcPowerInfo[i].CurrentMhz );
        maxCurrent = max( maxCurrent, pProcPowerInfo[i].MaxMhz );
    }

    QueryPerformanceFrequency(&perfFreq); 
    print( "Performance frequency %I64u\n", perfFreq.QuadPart );

    g_perfScaleFactor = (1e6 * maxCurrent)/perfFreq.QuadPart;

    g_minMeasurementClockTime = min( 1000, (ULONG) (10000/g_perfScaleFactor) );
    
    delete[] pProcPowerInfo;
}
*/

PSTR g_perfUnits = PERF_UNIT;

PVOID g_stackAllocLinkedList;     // We put alloca's in a linked list so the compiler won't optimize it away.

__declspec( align( 256 )) BYTE g_perfBuffer[8 * PERF_BUFFER_SIZE];

#define MAX_RUNS_PER_MEASUREMENT    (1<<15)
#define MEASUREMENTS_PER_RESULT     30
#define RESULTS_PER_DATAPOINT       10
#define MAX_SIZES                   25

double g_perfMeasurementOverhead = 0.0;

typedef VOID (SYMCRYPT_CALL * WIPE_FN)( PBYTE pbData, SIZE_T cbData );

//
// Some flags to specify other parameters that various performance functions need
//
#define PERF_PER_MODULUS_TYPE   1       // Different types of moduli: general, odd, prime, Pseudo-Mersenne, NIST P_*
#define PERF_PER_ECURVE_TYPE    2       // Different elliptic curves
#define PERF_PER_RSA_FACTORS    4       // Different # of factors

typedef struct _ALG_MEASURE_PARAMS
{
    LPCSTR      algName;
    ULONG       flags;
    SIZE_T      keySizes[MAX_SIZES];
    SIZE_T      dataSizes[MAX_SIZES];
} ALG_MEASURE_PARAMS;


//
// This table contains a mapping from "AlgName + ModeName" to a set of key sizes and datasizes.
// This works well for symmetric algorithms. Some algs don't use keysize, and some use an empty ModeName, but that addresses the necessary flexibility.
//
// For asymmetrics we have a slightly different problem:
// INT algorithms might have different performance for different divisor value types, and sizes
// MODELEMENT algorithms might have different performacne for different modulus types & sizes
// EC algorithms have different performance for different curves. (We are not generating curves on-the-fly, and only used pre-defined ones.)
// RSA algorithms have different performacne for key size, # primes, and pubexp value.
// 

#define PERF_NO_KEYPERF                     1
#define PERF_DATASIZE_SAME_AS_KEYSIZE       (1<<30)     // This unique datasize signifies that the datasize is equal to the corresponding keysize

const ALG_MEASURE_PARAMS g_algMeasureParams[] = 
{
    "Null"                  , 0, {}, {64, 128, 256, 512, 1024, (1<<13) },
    "Md2"                   , 0, {}, {64, 128, 256, 512, 1024, (1<<13) },
    "Md4"                   , 0, {}, {64, 128, 256, 512, 1024, (1<<14) },
    "Md5"                   , 0, {}, {64, 128, 256, 512, 1024, (1<<14) },
    "Sha1"                  , 0, {}, {64, 128, 256, 512, 1024, (1<<14) },
    "Sha256"                , 0, {}, {64, 128, 256, 512, 1024, (1<<13) },
    "Sha384"                , 0, {}, {128, 256, 512, 1024, (1<<13) },
    "Sha512"                , 0, {}, {128, 256, 512, 1024, (1<<13) },
    "HmacMd5"               , 0, {16}, {64, 128, 256, 512, 1024, (1<<13) },
    "HmacSha1"              , 0, {20}, {64, 128, 256, 512, 1024, (1<<13) },
    "HmacSha256"            , 0, {32}, {64, 128, 256, 512, 1024, (1<<13) },
    "HmacSha384"            , 0, {64}, {128, 256, 512, 1024, (1<<13) },
    "HmacSha512"            , 0, {64}, {128, 256, 512, 1024, (1<<13) },
    "AesCmac"               , 0, {16,24,32}, {128, 4096, 65536 },
    "Marvin32"              , 0, {8}, {0, 1, 2, 3, 39, 40, 1 << 16 },
    "AesEcb"                , 0, {16,24,32}, {112, 512, 1024, 2048, 4096,},
    "AesCbc"                , 0, {16,24,32}, {128, 256, 512, 1024, 2048, 4096,}, // start at 128 bytes as that is the breaking point on SaveXmm save/restore
    "AesCfb"                , 0, {16,24,32}, {16, 32, 48, 64, 128, 256, 512, 1024,},
    "DesEcb"                , 0, {8}, {8,16,24,32,64,128,256,1024},
    "DesCbc"                , 0, {8}, {8,16,24,32,64,128,256,1024},
    "DesCfb"                , 0, {8}, {8,16,24,32,64,128,256,1024},
    "Des2Ecb"               , 0, {16}, {8,16,24,32,64,128,256,1024},
    "Des2Cbc"               , 0, {16}, {8,16,24,32,64,128,256,1024},
    "Des2Cfb"               , 0, {16}, {8,16,24,32,64,128,256,1024},
    "Des3Ecb"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "Des3Cbc"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "Des3Cfb"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "DesxEcb"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "DesxCbc"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "DesxCfb"               , 0, {24}, {8,16,24,32,64,128,256,1024},
    "Rc2Ecb"                , 0, {8,16}, {8,16,24,32,64,128,256,1024},
    "Rc2Cbc"                , 0, {8,16}, {8,16,24,32,64,128,256,1024},
    "Rc2Cfb"                , 0, {8,16}, {8,16,24,32,64,128,256,1024},
    "AesCcm"                , 0, {16,24,32}, {128,1024, 4096},
    "AesGcm"                , 0, {16,24,32}, {128,1024, 4096},
    "Rc4"                   , 0, {8}, {16, 32, 128, 512, 4096},
    "ChaCha20"              , 0, {32}, {64, 128, 256, 512, 4096},
    "Poly1305"              , 0, {32}, {64, 128, 256, 512, 4096},
    "AesCtrDrbg"            , 0, {48}, {128,512,4096},
    "AesCtrF142"            , 0, {48}, {128,512,4096},
    "ParSha256"             , 0, {}, {1024,1 << 14},
    "ParSha384"             , 0, {}, {1024,1 << 14},
    "ParSha512"             , 0, {}, {1024,1 << 14},
    "Pbkdf2HmacMd5"         , 0, {32}, {16, 128, 512},
    "Pbkdf2HmacSha1"        , 0, {32}, {20, 100, 500},
    "Pbkdf2HmacSha256"      , 0, {32}, {32, 128, 512},
    "Pbkdf2HmacSha512"      , 0, {32}, {64, 128, 512},
    "Pbkdf2AesCmac"         , 0, {16}, {16, 128, 512},
    "Sp800_108HmacMd5"      , 0, {32}, {16, 128, 512},
    "Sp800_108HmacSha1"     , 0, {32}, {20, 100, 500},
    "Sp800_108HmacSha256"   , 0, {32}, {32, 128, 512},
    "Sp800_108HmacSha512"   , 0, {32}, {64, 128, 512},
    "Sp800_108AesCmac"      , 0, {16}, {16, 128, 512},
    "TlsPrf1_1HmacMd5"      , 0, {32}, { 32, 64, 128, 512, 1024 },
    "TlsPrf1_2HmacSha256"   , 0, {32}, { 32, 64, 128, 512, 1024 },
    "TlsPrf1_2HmacSha384"   , 0, {32}, { 32, 64, 128, 512, 1024 },
    "TlsPrf1_2HmacSha512"   , 0, {32}, { 32, 64, 128, 512, 1024 },
    "HkdfHmacSha256"        , 0, {32}, { 32, 64, 128, 512, 1024 },
    "HkdfHmacSha1"          , 0, {32}, { 32, 64, 128, 512, 1024 },
    "XtsAes"                , 0, {32,48,64}, {512, 1024, 2048, 4096, 8192, 16384, 32768},
    "TlsCbcHmacSha1"        , 0, {64}, {256, 8192},
    "TlsCbcHmacSha256"      , 0, {64}, {256, 8192},
    "TlsCbcHmacSha384"      , 0, {64}, {256, 8192},
    "IntAdd"                , 1, {32,64,128,256, 512, 1024},{},
    "IntSub"                , 1, {32,64,128,256, 512, 1024},{},
    "IntMul"                , 1, {32,64,128,256, 512, 1024},{},
    "IntSquare"             , 1, {32,64,128,256, 512, 1024},{},
    "IntDivMod"             , 1, {32,64,128,256, 512, 1024},{},
    "ModAdd"                , 1, {PERF_KEY_SECRET | 24, PERF_KEY_PUB_ODD | 24,                       PERF_KEY_PUB_NIST | 24,
                                  PERF_KEY_SECRET | 32, PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_NIST | 32,
                                  PERF_KEY_SECRET | 48, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_NIST | 48,
                                  PERF_KEY_SECRET | 64, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 66,
                                  PERF_KEY_PUB_ODD | 128, PERF_KEY_PUB_ODD | 256, }, {},
    "ModSub"                , 1, {PERF_KEY_SECRET | 24, PERF_KEY_PUB_ODD | 24,                       PERF_KEY_PUB_NIST | 24,
                                  PERF_KEY_SECRET | 32, PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_NIST | 32,
                                  PERF_KEY_SECRET | 48, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_NIST | 48,
                                  PERF_KEY_SECRET | 64, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 66,
                                  PERF_KEY_PUB_ODD | 128, PERF_KEY_PUB_ODD | 256, }, {},
    "ModMul"                , 1, {PERF_KEY_SECRET | 24, PERF_KEY_PUB_ODD | 24,                       PERF_KEY_PUB_NIST | 24,
                                  PERF_KEY_SECRET | 32, PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_NIST | 32,
                                  PERF_KEY_SECRET | 48, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_NIST | 48,
                                  PERF_KEY_SECRET | 64, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 66,
                                  PERF_KEY_SECRET |128, PERF_KEY_PUB_ODD |128,
                                  PERF_KEY_SECRET |256, PERF_KEY_PUB_ODD |256, PERF_KEY_PUB_ODD | 384 }, {},
    "ModSquare"             , 1, {PERF_KEY_SECRET | 24, PERF_KEY_PUB_ODD | 24,                       PERF_KEY_PUB_NIST | 24,
                                  PERF_KEY_SECRET | 32, PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_NIST | 32,
                                  PERF_KEY_SECRET | 48, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_NIST | 48,
                                  PERF_KEY_SECRET | 64, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 66,
                                  PERF_KEY_SECRET |128, PERF_KEY_PUB_ODD |128,
                                  PERF_KEY_SECRET |256, PERF_KEY_PUB_ODD |256, PERF_KEY_PUB_ODD | 384 }, {},
    "ModInv"                , 1, {PERF_KEY_PUBLIC | PERF_KEY_PRIME | 24, 
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 32,   
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 48,   
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 64,}, {},
    "ModExp"                , 1, {PERF_KEY_PUBLIC | PERF_KEY_PRIME | 24,
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 32,   
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 48,   
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 64,
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 128,
                                  PERF_KEY_PUBLIC | PERF_KEY_PRIME | 256,
                                  }, {},
    "ScsTable"              , 1, {32, 64, 128, 256}, {},
    "TrialDivisionContext"  , 1, {32, 64, 128, 256, 512, 1024}, {},
    "TrialDivision"         , 1, {32, 64, 128, 256, 512, 1024}, {PERF_DATASIZE_SAME_AS_KEYSIZE},

    "RsaEncRaw"             , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaDecRaw"             , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaEncPkcs1"           , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaDecPkcs1"           , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaEncOaep"            , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaDecOaep"            , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},

    "RsaSignPkcs1"          , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaVerifyPkcs1"        , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaSignPss"            , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},
    "RsaVerifyPss"          , 1, {128, 256, 384, 512}, {PERF_DATASIZE_SAME_AS_KEYSIZE},

    "DsaSign"               , 1, {64, 128, 256}, {},
    "DsaVerify"             , 1, {64, 128, 256}, {},
    "Dh"                    , 1, {64, 128, 256}, {PERF_DATASIZE_SAME_AS_KEYSIZE},

    "EcurveAllocate"        , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512, PERF_KEY_C255_19,}, {},
    "EcpointSetZero"        , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointSetDistinguished", 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointSetRandom"      , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512, PERF_KEY_C255_19,}, {},
    "EcpointIsEqual"        , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointIsZero"         , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointOnCurve"        , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointAdd"            , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointAddDiffNz"      , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointDouble"         , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcpointScalarMul"      , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512, PERF_KEY_C255_19,}, {},
    "EcdsaSign"             , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "EcdsaVerify"           , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512,}, {},
    "Ecdh"                  , 1, {PERF_KEY_NIST192, PERF_KEY_NIST224, PERF_KEY_NIST256, PERF_KEY_NIST384, PERF_KEY_NIST521, PERF_KEY_NUMS256, PERF_KEY_NUMS384, PERF_KEY_NUMS512, PERF_KEY_C255_19,}, {},

    "IEEE802_11SaeCustom"   , 0, {}, {},

// Enable the line below if you are running perf on the developer test
//    "DeveloperTest"         , 1, {1},{},

};



int __cdecl compareUlonglong( const VOID * p1, const VOID * p2 )
{
    ULONGLONG v1 = *(ULONGLONG *)p1;
    ULONGLONG v2 = *(ULONGLONG *)p2;

    if( v1 < v2 ) return -1;
    if( v1 == v2 ) return 0;
    return 1;
}

int __cdecl compareDouble( const VOID * p1, const VOID * p2 )
{
    double v1 = *(double *)p1;
    double v2 = *(double *)p2;

    if( v1 < v2 ) return -1;
    if( v1 == v2 ) return 0;
    return 1;
}

double correctAverage( double average, double * pData, SIZE_T cdData )
//
// Compute the error of the average as accurately as possible.
//
{
    double deviation[ MAX_SIZES ];
    CHECK( cdData <= MAX_SIZES, "?" );
    CHECK( cdData > 0, "?" );

    //
    // Compute the deviations
    //
    for( SIZE_T i=0; i<cdData; i++ )
    {
        deviation[i] = pData[i] - average;
    }

    //
    // We want to add the deviations in the numerically stablest order.
    // That means in order of increasing aboslute value.
    // We do this by sorting, finding the zero-point, and then adding the elements
    // upwards and downwards from there.
    //
    qsort( deviation, cdData, sizeof( deviation[0] ), &compareDouble );

    double sum = 0.0;
    SIZE_T pos = 0;
    
    while( pos < cdData && deviation[pos] < 0.0 )
    {
        pos++;
    }
    SIZE_T neg = pos;

    while( pos < cdData && neg > 0 )
    {
        if( fabs(deviation[pos]) > fabs(deviation[neg - 1]) )
        {
            sum += deviation[ neg - 1 ];
            --neg;
        } else
        {
            sum += deviation[ pos ];
            ++pos;
        }
    }

    while( pos < cdData )
    {
        sum += deviation[ pos ];
        ++pos;
    }

    while( neg > 0 )
    {
        sum += deviation[ neg - 1 ];
        --neg;
    }

    double result = average + (sum / cdData);
    return result;
    
}



double measureDataPerfGivenStack(   
                                SIZE_T keySize, 
                                SIZE_T dataSize, 
                                PerfKeyFn keyFn, 
                                PerfDataFn prepFn, 
                                PerfDataFn dataFn, 
                                PerfCleanFn cleanFn, 
                                int * pNRuns )
{
    PBYTE buf1 = g_perfBuffer + 0*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f); // cache-aligned buffers
    PBYTE buf2 = g_perfBuffer + 2*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f);
    PBYTE buf3 = g_perfBuffer + 4*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f);
    //PBYTE buf4 = g_perfBuffer + 6*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f);

    ULONGLONG   durations[ MEASUREMENTS_PER_RESULT ];

    if( keyFn != NULL )
    {
        (*keyFn)( buf1, buf2, buf3, keySize );
    }

    int runs = *pNRuns;
    int i=0;
    
    if( prepFn != NULL )
    {
        (*prepFn) (buf1, buf2, buf3, dataSize );
    }

    ULONGLONG loopStart = GET_PERF_CLOCK();
    while( i < MEASUREMENTS_PER_RESULT && ( (GET_PERF_CLOCK() - loopStart) < g_largeMeasurementClockTime ) )
    {
        ULONGLONG start = GET_PERF_CLOCK();
        for( int j=0; j<runs; j++ )
        {
            (*dataFn)( buf1, buf2, buf3, dataSize );
        }
        ULONGLONG duration = GET_PERF_CLOCK() - start;
        if( duration < g_minMeasurementClockTime )
        {
            //
            // The measuremennt was too short, restart & double the # runs we do.
            //
            i = 0; 
            loopStart = GET_PERF_CLOCK();
            runs <<= 1;
            CHECK( runs <= MAX_RUNS_PER_MEASUREMENT, "Measurement too fast" );
            continue;
        }
        durations[i] = duration;
        ++i;
    }

    /*
    // Helpful when debugging
    print( " mdpgs");
    char c = '[';
    for( int j=0; j<i; j++ )
    {
        print( "%c%I64d", c, durations[j] );
        c = ',';
    }
    print( "]\n" );
    */

    qsort( durations, i, sizeof( durations[0] ), compareUlonglong );

    //
    // We return the one-third percentile point to compensate for expected slow-downs.
    //
    double res = (double) durations[i/3];
    res /= runs;
    res *= g_perfScaleFactor;
    res -= g_perfMeasurementOverhead;

    *pNRuns = runs;

    if( cleanFn != NULL )
    {
        (*cleanFn)( buf1, buf2, buf3 );
    }

    return res;
}

double measureKeyPerfGivenStack(    SIZE_T keySize, 
                                    PerfKeyFn keyFn, 
                                    PerfCleanFn cleanFn, 
                                    int * pNRuns )
{
    PBYTE buf1 = g_perfBuffer + 0*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0xf);
    PBYTE buf2 = g_perfBuffer + 2*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0xf);
    PBYTE buf3 = g_perfBuffer + 4*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0xf);
    //PBYTE buf4 = g_perfBuffer + 6*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0xf);

    ULONGLONG   durations[ MEASUREMENTS_PER_RESULT ];


    int runs = *pNRuns;
    int i=0;
    while( i < MEASUREMENTS_PER_RESULT )
    {
        ULONGLONG duration;
        ULONGLONG start = GET_PERF_CLOCK();
        for( int j=0; j<runs; j++ )
        {

            (*keyFn)( buf1, buf2, buf3, keySize );
            (*cleanFn)( buf1, buf2, buf3 );
        }
        duration = GET_PERF_CLOCK() - start;
        if( duration < g_minMeasurementClockTime )
        {
            //
            // The measuremennt was too short, restart & double the # runs we do.
            //
            i = 0; 
            runs <<= 1;
            CHECK( runs <= MAX_RUNS_PER_MEASUREMENT, "Measurement too fast" );
            continue;
        }
        durations[i] = duration;
        ++i;
    }
    qsort( durations, MEASUREMENTS_PER_RESULT, sizeof( durations[0] ), compareUlonglong );

    //
    // We return the one-third percentile point to compensate for expected slow-downs.
    //
    double res = (double) durations[MEASUREMENTS_PER_RESULT/3];
    res /= runs;
    res *= g_perfScaleFactor;
    res -= 2 * g_perfMeasurementOverhead;

    *pNRuns = runs;

    return res;
}


double measureWipePerfGivenStack(   
                                SIZE_T dataSize, 
                                SIZE_T dataOffset, 
                                WIPE_FN wipeFn, 
                                int * pNRuns )
{
    PBYTE buf = g_perfBuffer + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x7f) + dataOffset;

    ULONGLONG   durations[ MEASUREMENTS_PER_RESULT ];

    int runs = *pNRuns;
    int i=0;
    
    while( i < MEASUREMENTS_PER_RESULT )
    {
        ULONGLONG start = GET_PERF_CLOCK();
        for( int j=0; j<runs; j++ )
        {

            (*wipeFn)( buf, dataSize );
        }
        ULONGLONG duration = GET_PERF_CLOCK() - start;
        if( duration < g_minMeasurementClockTime )
        {
            //
            // The measuremennt was too short, restart & double the # runs we do.
            //
            i = 0; 
            runs <<= 1;
            CHECK( runs <= MAX_RUNS_PER_MEASUREMENT, "Measurement too fast" );
            continue;
        }
        durations[i] = duration;
        ++i;
    }
    qsort( durations, MEASUREMENTS_PER_RESULT, sizeof( durations[0] ), compareUlonglong );

    //
    // We return the one-third percentile point to compensate for expected slow-downs.
    //
    double res = (double) durations[MEASUREMENTS_PER_RESULT/3];
    res /= runs;
    res *= g_perfScaleFactor;
    res -= g_perfMeasurementOverhead;

    *pNRuns = runs;

    return res;
}




double measurePerfMoveStack(    SIZE_T keySize, 
                                SIZE_T dataSize, 
                                PerfKeyFn keyFn, 
                                PerfDataFn prepFn, 
                                PerfDataFn dataFn, 
                                PerfCleanFn cleanFn, 
                                BOOL    measureKey,
                                int * pNRuns )
{
    SIZE_T stackMove = 16 + g_rng.sizet( (1 << 17) );
#pragma prefast(push)
#pragma prefast(disable:6255)
    VOID * p = _alloca( stackMove );
#pragma prefast(pop)

    *(VOID **)p = g_stackAllocLinkedList;
    g_stackAllocLinkedList = p;

    if( measureKey )
    {
        return measureKeyPerfGivenStack( keySize, keyFn, cleanFn, pNRuns );
    }
    else
    {
        return measureDataPerfGivenStack( keySize, dataSize, keyFn, prepFn, dataFn, cleanFn, pNRuns );
    }
}


double measureWipePerfMoveStack( 
                                SIZE_T dataSize, 
                                SIZE_T dataOffset, 
                                WIPE_FN wipeFn, 
                                int * pNRuns )
{
    SIZE_T stackMove = 16 + g_rng.sizet( (1 << 17) );
#pragma prefast(push)
#pragma prefast(disable:6255)
    VOID * p = _alloca( stackMove );
#pragma prefast(pop)

    *(VOID **)p = g_stackAllocLinkedList;
    g_stackAllocLinkedList = p;

    return measureWipePerfGivenStack( dataSize, dataOffset, wipeFn, pNRuns );
   
}


double measurePerfOneSize( SIZE_T keySize, SIZE_T dataSize, PerfKeyFn keyFn, PerfDataFn prepFn, PerfDataFn dataFn, PerfCleanFn cleanFn, BOOL measureKey )
{
    int nRuns = 1;
    double results[ RESULTS_PER_DATAPOINT ];
    int i = 0;

    ULONGLONG starttime = GET_PERF_CLOCK();

    // Limit total time to MIN_RESULTS or 1 billion clock cycles.
    while( i < RESULTS_PER_DATAPOINT && (GET_PERF_CLOCK() - starttime) < g_largeMeasurementClockTime  )
    {
        results[i] = measurePerfMoveStack( keySize, dataSize, keyFn, prepFn, dataFn, cleanFn, measureKey, &nRuns );
        i++;
    }

    /*
    // Helpful when debugging
    print( " mpos");
    char c = '[';
    for( int j=0; j<i; j++ )
    {
        print( "%c%f", c, results[j] );
        c = ',';
    }
    print( "]\n" );
    */

    qsort( results, i, sizeof( results[0] ), compareDouble );

    //
    // Return the one-third point to compensate for expected slowdowns.
    //
    return results[ i / 3];
}

double measureWipePerfOneSize( SIZE_T dataSize, SIZE_T dataOffset, WIPE_FN wipeFn )
{
    int nRuns = 1;
    double results[ RESULTS_PER_DATAPOINT ];
    
    for( int i=0; i<RESULTS_PER_DATAPOINT; i++ )
    {
        results[i] = measureWipePerfMoveStack( dataSize, dataOffset, wipeFn, &nRuns );
    }

    qsort( results, RESULTS_PER_DATAPOINT, sizeof( results[0] ), compareDouble );

    //
    // Return the one-third point to compensate for expected slowdowns.
    //
    return results[ RESULTS_PER_DATAPOINT / 3];
}


VOID createSizeSet( const SIZE_T pSizeList[], std::set<SIZE_T> * res )
{
    res->clear();
    
    for( int i= MAX_SIZES-1; i>=0; i-- )
    {
        if( pSizeList[i] == 0 && res->size() == 0 )
        {
            continue;
        }
        res->insert( pSizeList[i] );
    }

    if( res->size() == 0 )
    {
        res->insert( 0 );
    }

    //for( std::set<SIZE_T>::const_iterator i= sizes.begin(); i != sizes.end(); ++i )
    //{
    //    print( "%I64u, ", (ULONGLONG)*i );
    //}
    //iprint( "\n" );
    
}


VOID measurePerfData( 
                        PerfKeyFn keyFn, 
                        PerfDataFn prepFn,
                        PerfDataFn dataFn,
                        PerfCleanFn cleanFn, 
                        std::set<SIZE_T> * pDataSizes, 
                        SIZE_T keySize,
                        AlgorithmImplementation::ALG_PERF_INFO * pRes )
{
    SIZE_T x[ MAX_SIZES ];
    double y[ MAX_SIZES ];
    double perByte;
    double fixed;

    SIZE_T sumXi = 0;
    SIZE_T n = 0;

    for( std::set<SIZE_T>::const_iterator i = pDataSizes->begin(); i != pDataSizes->end(); ++i )
    {
        SIZE_T dataSize = *i;
        
        SYMCRYPT_ASSERT( n < MAX_SIZES );

        if ( dataSize == PERF_DATASIZE_SAME_AS_KEYSIZE)
        {
            dataSize = keySize;
            x[n] = 0;           // Set this to 0 so later it will know there is only one datasize
            sumXi += 0;
        }
        else
        {
            x[n] = dataSize;
            sumXi += dataSize;
        }
        
        y[n] = measurePerfOneSize( keySize, dataSize, keyFn, prepFn, dataFn, cleanFn, FALSE );
        
        //iprint( "Size = %5I64u, clocks = %f\n", (ULONGLONG) size, y[n] );
        ++n;
    }

    SYMCRYPT_ASSERT( n > 0 );

    if( n > 1 )
    {
        double avX = (double) sumXi / n;

        //
        // Compute the average of the y values accurately.
        // Inacuracies in this lead to numerical instabilities that are quite visible
        // in cases where the algorithm time does not depend on x.
        //
        double avY = correctAverage( 0.0, y, n );
        //print( "avY1 = %f\n", avY );
        avY = correctAverage( avY, y, n );
        //print( "avY2 = %f\n", avY );
        avY = correctAverage( avY, y, n );
        //print( "avY3 = %f\n", avY );

        double sumDxDy = 0.0;
        double sumDx2 = 0.0;
        for( SIZE_T i=0; i<n; i++ )
        {
            sumDxDy += (x[i] - avX) * (y[i] - avY );
            sumDx2 += (x[i] - avX) * (x[i] - avX );
        }
        

        //
        // We fit a line to the data points using Linear Regression
        //

        // iprint( "%f %f %f %f\n", avX, avY, sumDxDy, sumDx2 );

        perByte = sumDxDy / sumDx2;
        fixed = avY - perByte * avX;

        if( fixed < 0 )
        {
            // Our estimated fixed cost per request is < 0, which is nonsensical and due to measurement errors.
            // This makes reporting ugly, especially with graphs. 
            // As we know that the fixed cost must be >=0, we set it to 0 and re-optimize the perByte cost.
            // Our line becomes: Y = c*X for a per-byte cost c.
            
            // Minimise_c Sum_i (Yi - c*Xi)^2
            // Minimise_c Sum_i (Yi^2 - 2*c*Xi*Yi + c^2*Xi^2)
            // Minimise_c (Sum_i Xi^2)*c^2 - 2*(Sum_i Xi*Yi)*c + (Sum_i Yi^2)
            // differentiate w.r.t. c
            //  2*(Sum_i Xi^2)*c - 2*(Sum_i Xi*Yi) = 0
            // and thus c = (Sum_i Xi*Yi) / (Sum_i Xi^2) 

            ULONGLONG sumXiXi = 0;      // Our Xi < 2^24 or so, so a 64-bit accumulator is enough
            double sumXiYi = 0.0;
            for( SIZE_T i=0; i<n; i++ )
            {
                sumXiXi += (ULONGLONG) x[i] * x[i];
                sumXiYi += (double) x[i] * y[i];
            }
            fixed = 0;
            perByte = sumXiYi / sumXiXi;
        }

        // Note: We should consider switching to the Theil�Sen estimator because it is much less sensitive to outliers

    } else 
    {
        // Only one data size. If datasize == 0, we have just a fixed overhead, otherwise we have only a perByte cost
        if( x[0] == 0 )
        {
            perByte = 0;
            fixed = y[0];
        } else {
            perByte = y[0]/x[0];
            fixed = 0;
        }
    }
    

    double lineDeviation[ MAX_SIZES ];
    for( SIZE_T i=0; i< n; i++ )
    {
        lineDeviation[i] = abs( y[i] - (fixed + perByte * x[i] ) );
    }
    qsort( lineDeviation, n, sizeof( lineDeviation[0] ), &compareDouble );
    double deviation90Percentile = lineDeviation[ (n * 9) / 10 ];

    pRes->cFixed = fixed;
    pRes->cPerByte = perByte;
    pRes->cRange = deviation90Percentile;
}

const struct {
    UINT32  exKeyParam;
    char *  str;
} g_exKeyParamMapping[] = {
    { 0,                                    "   " },
    { PERF_KEY_SECRET,                      "s  " },
    { PERF_KEY_PUB_ODD,                     "po " },
    { PERF_KEY_PUBLIC,                      "p  " },
    { PERF_KEY_PUB_PM,                      "pm " },
    { PERF_KEY_PUB_NIST,                    "pn " },
    { PERF_KEY_SECRET | PERF_KEY_PRIME,     "s P" },
    { PERF_KEY_PUBLIC | PERF_KEY_PRIME,     "p P" },
    { PERF_KEY_PUB_ODD | PERF_KEY_PRIME,    "poP" },
    { PERF_KEY_PUB_PM | PERF_KEY_PRIME,     "pmP" },
    { PERF_KEY_PUB_NIST | PERF_KEY_PRIME,   "pnP" },
    { PERF_KEY_NIST_CURVE,                  "nst" },
    { PERF_KEY_NUMS_CURVE,                  "nms" },
    { PERF_KEY_C255_CURVE,                  "c25" },
};


VOID measurePerfOneAlg( AlgorithmImplementation * pAlgImp )
{
    PerfDataFn dataFn = pAlgImp->m_perfDataFunction;
    PerfDataFn decryptFn = pAlgImp->m_perfDecryptFunction;
    PerfKeyFn  keyFn = pAlgImp->m_perfKeyFunction;
    PerfCleanFn cleanFn = pAlgImp->m_perfCleanFunction;

    CHECK4( keyFn == NULL || cleanFn != NULL, "No clean function in %s/%s", pAlgImp->m_implementationName.c_str(), pAlgImp->m_algorithmName.c_str() );        

    const ALG_MEASURE_PARAMS * pParams = NULL;

    String algMode = pAlgImp->m_algorithmName + pAlgImp->m_modeName;
    
    //print( "%s\n", algMode.c_str() );
    
    for( int i=0; i<ARRAY_SIZE( g_algMeasureParams ); i++ )
    {
        if( g_algMeasureParams[i].algName == algMode )
        {
            pParams = &g_algMeasureParams[i];
        }
    }

    if( pParams == NULL )
    {
        return;
    }

    std::set<SIZE_T> keySizes;
    std::set<SIZE_T> dataSizes;

    createSizeSet( pParams->keySizes, &keySizes );
    createSizeSet( pParams->dataSizes, &dataSizes );

    SIZE_T nKeySizes = keySizes.size();
    CHECK3( nKeySizes <= MAX_SIZES, "Too many sizes for algorithm %s", pParams->algName );

    for( std::set<SIZE_T>::const_iterator k = keySizes.begin(); k != keySizes.end(); ++k )
    {
        UINT32 keyBytes = *k & 0x00ffffff;
        UINT32 keyFlags = *k & 0xff000000;

        AlgorithmImplementation::ALG_PERF_INFO perfInfo;
        if( nKeySizes > 1 )
        {
            perfInfo.keySize = keyBytes;
        } else {
            perfInfo.keySize = 0;
        }

        //
        // First we measure the speed of the key expansion, if any
        //
        if( keyFn != NULL && (pParams->flags & PERF_NO_KEYPERF) == 0 )
        {
            perfInfo.cPerByte = 0;
            perfInfo.cFixed = measurePerfOneSize( *k, 0, keyFn, NULL, NULL, cleanFn, TRUE );
            perfInfo.strPostfix = "key";
            
            pAlgImp->m_perfInfo.push_back( perfInfo );
        }

        if( dataFn != NULL )
        {
            if( decryptFn != NULL )
            {
                perfInfo.strPostfix = "enc";
            } else {
                perfInfo.strPostfix = NULL;

                for( int i=0; i < ARRAY_SIZE( g_exKeyParamMapping ); i++ )
                {
                    if( keyFlags == g_exKeyParamMapping[i].exKeyParam )
                    {
                        perfInfo.strPostfix = g_exKeyParamMapping[i].str;
                        break;
                    }
                }
                CHECK3( perfInfo.strPostfix != NULL, "Extended key param not found %08x", *k );
            }

            measurePerfData( keyFn, dataFn, dataFn, cleanFn, &dataSizes, *k, &perfInfo );
            pAlgImp->m_perfInfo.push_back( perfInfo );
        }

        if( decryptFn != NULL )
        {
            perfInfo.strPostfix = "dec";

            measurePerfData( keyFn, dataFn, decryptFn, cleanFn, &dataSizes, *k, &perfInfo );
            pAlgImp->m_perfInfo.push_back( perfInfo );
        }
       
    }
}

VOID
SYMCRYPT_NOINLINE
measurePerfOfAlgorithms()
{
    ULONGLONG startClock;
    ULONGLONG clockCycles;
    LARGE_INTEGER startCnt;
    LARGE_INTEGER stopCnt;
    LARGE_INTEGER cntFreq;
    ULONGLONG startTick;
    ULONGLONG ms;
    double cntTime;

    //
    // Experimentally we know that the very first algorithms to be measured returns too large measurements.
    // We test the first algorithm and throw away the results to circumvent this.
    // 
    /* This is too slow when the first algorithm is really expensive...
    AlgorithmImplementation * pAlgImp = * g_algorithmImplementation.begin();
    if( pAlgImp != NULL )
    {
        for( int i=0; i<4; i++ )
        {
            measurePerfOneAlg( pAlgImp );
            pAlgImp->m_perfInfo.clear();
        }
    }
    */

    QueryPerformanceCounter( &startCnt );
    startTick = GetTickCount64();
    startClock = GET_PERF_CLOCK();

    for( std::vector<AlgorithmImplementation *>::iterator i = g_algorithmImplementation.begin(); 
            i != g_algorithmImplementation.end();
            i++ )
    {
        
        //iprint( "Performance testing %s/%s\n", (*i)->m_implementationName.c_str(), (*i)->m_algorithmName.c_str() );
        //Sleep( 10 );
        measurePerfOneAlg( *i );
    }

    clockCycles = GET_PERF_CLOCK() - startClock;
    ms = GetTickCount64() - startTick;
    QueryPerformanceCounter( &stopCnt );

    QueryPerformanceFrequency( &cntFreq );

    cntTime = ((double) stopCnt.QuadPart - startCnt.QuadPart) / cntFreq.QuadPart;
    g_tscFreqTickCtr = (double) clockCycles / ((double) ms / 1000);
    g_tscFreqPerfCtr = (double) clockCycles / cntTime;
}


double g_wipePerf[PERF_WIPE_MAX_SIZE+1][PERF_WIPE_N_OFFSETS];

//
// We use a wrapper as the perf system compensates for that overhead
//
VOID
SYMCRYPT_CALL
wipeWrapper( PBYTE pbData, SIZE_T cbData )
{
    SymCryptWipe( pbData, cbData );
    //memset( pbData, 0, cbData );
}

// We need two functions to measure, because the compiler is smart enough to 
// not use indirect calls if there is only ever one target.
// and that messes up the perf numbers.
VOID
SYMCRYPT_CALL
memsetWrapper( PBYTE pbData, SIZE_T cbData )
{
    memset( pbData, 0, cbData );
}

VOID
measurePerfOfWipe()
{
    UINT32 t;

    // Use the measurement fucntion with memset to avoid fixed target optimizations
    SYMCRYPT_FORCE_WRITE32( &t, (UINT32) measureWipePerfOneSize( 16, 0, &memsetWrapper ) );

    for( SIZE_T offset = 0; offset < PERF_WIPE_N_OFFSETS; offset ++ )
    {
        for( SIZE_T len = 0; len <= PERF_WIPE_MAX_SIZE; len ++ )
        {
            g_wipePerf[len][offset] = measureWipePerfOneSize( len, offset, &wipeWrapper );
        }
    }
}


VOID
measurePerf()
{
    iprint( "\nStarting performance measurements..." );
    
    int oldPriority = GetThreadPriority( GetCurrentThread() );
    
    CHECK( SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL ), "Failed to set priority" );
    //print( "Thread priority set to %d\n", GetThreadPriority( GetCurrentThread() ) );
    
    DWORD_PTR affinitymask = (DWORD_PTR)1 << GetCurrentProcessorNumber();
    affinitymask = SetThreadAffinityMask( GetCurrentThread(), affinitymask );
    CHECK( affinitymask != 0, "Failed to set affinity mask" );

    
    initPerfSystem();


    measurePerfOfAlgorithms();

    if( TRUE || isAlgorithmPresent( "Wipe", FALSE ) )
    {
        measurePerfOfWipe();
    }


    CHECK( SetThreadAffinityMask( GetCurrentThread(), affinitymask ) != 0, "Failed to restore affinity mask" );
    CHECK( GetThreadPriority( GetCurrentThread() ) == THREAD_PRIORITY_TIME_CRITICAL, "Thread priority decay" );
    CHECK( SetThreadPriority( GetCurrentThread(), oldPriority ), "Failed to set priority" );

    iprint( "...done\n" );
}

SYMCRYPT_NOINLINE
VOID
nullPerfFunction( PBYTE, PBYTE, PBYTE, SIZE_T )
{
}

VOID
initPerfSystem()
{
    //
    // Sleep to let the system handle any background things (scrolling the window...) that might interfere with us
    //
    Sleep( 100 );
    
    //
    // On Win7 the early measurements are unreliable. Presumably it takes a while to wake up the CPU
    // and get it running at the highest clock frequency. 
    // We have a do-nothing loop that cannot be optimized away 
    // to ensure we get this before we start the actual measurements.
    //
    // To ensure that the compiler cannot optimize our busy-work away we actually print some result
    // which cannot be faked without doing the work.
    //

    SIZE_T r = g_rng.sizet( MAX_SIZE_T );
    SIZE_T x = r;
    SIZE_T y = 0;
    for( int i=0; i<(1<<27); i++ )
    {
        x += y;
        y ^= x;
        x += y>>5;
        y ^= x+1;
    }
    print( ".%c.\n", ' ' + (r + x)%(127-' '));    // DO NOT REMOVE, ensures that do-busy work isn't optimized away

    SET_PERF_SCALEFACTOR();
    //print( "Perf scale factor = %f\n", (float) g_perfScaleFactor );

    for( int i=0; i<50; i++ )
    {
        g_perfMeasurementOverhead = 0.0;
        g_perfMeasurementOverhead = measurePerfOneSize( 0, 0, NULL, NULL, nullPerfFunction, NULL, FALSE );
    }

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    if( g_perfMeasurementOverhead > 1000 )
    {
        print( "Detected Hypervisor due to very high overhead; disabling CPUID before RDTSC\n" );
        g_enableCpuIdBeforeRdtsc = FALSE;
        for( int i=0; i<50; i++ )
        {
            g_perfMeasurementOverhead = 0.0;
            g_perfMeasurementOverhead = measurePerfOneSize( 0, 0, NULL, NULL, nullPerfFunction, NULL, FALSE );
        }
    }
#endif

    print( "Performance measurement overhead = %.1f %s", g_perfMeasurementOverhead, PERF_UNIT );
}

VOID
runProfiling()
{
    std::set<SIZE_T> keySizes;
    std::set<SIZE_T> dataSizes;

    g_perfTestsRunning = TRUE;

    print("\nProfiling start (%d iteration(s))\n", g_profile_iterations);

    for( std::vector<AlgorithmImplementation *>::iterator ppAlgImp = g_algorithmImplementation.begin();
            ppAlgImp != g_algorithmImplementation.end();
            ppAlgImp++ )
    {
        AlgorithmImplementation * pAlgImp = *ppAlgImp;

        PerfDataFn dataFn = pAlgImp->m_perfDataFunction;
        PerfDataFn decryptFn = pAlgImp->m_perfDecryptFunction;
        PerfKeyFn  keyFn = pAlgImp->m_perfKeyFunction;
        PerfCleanFn cleanFn = pAlgImp->m_perfCleanFunction;

        CHECK4( keyFn == NULL || cleanFn != NULL, "No clean function in %s/%s",
                    pAlgImp->m_implementationName.c_str(),
                    pAlgImp->m_algorithmName.c_str() );

        const ALG_MEASURE_PARAMS * pParams = NULL;

        String algMode = pAlgImp->m_algorithmName + pAlgImp->m_modeName;
        String fullName = pAlgImp->m_implementationName + algMode;

        for( int i=0; i<ARRAY_SIZE( g_algMeasureParams ); i++ )
        {
            if( g_algMeasureParams[i].algName == algMode )
            {
                pParams = &g_algMeasureParams[i];
            }
        }

        if (pParams == NULL)
        {
            print( "No parameters for %s. Skipping profiling...\n", algMode.c_str() );
            continue;
        }

        print(" %s\n", fullName.c_str() );

        createSizeSet( pParams->keySizes, &keySizes );
        createSizeSet( pParams->dataSizes, &dataSizes );

        SIZE_T nKeySizes = keySizes.size();
        CHECK3( nKeySizes <= MAX_SIZES, "Too many sizes for algorithm %s", pParams->algName );

        for( std::set<SIZE_T>::const_iterator k = keySizes.begin(); k != keySizes.end(); ++k )
        {
            SIZE_T keySize = *k;

            if ((g_profile_key == 0) || (g_profile_key == (keySize & 0xffffff)))
            {
                print("  Key: 0x%X\n", keySize );

                PBYTE buf1 = g_perfBuffer + 0*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f); // cache-aligned buffers
                PBYTE buf2 = g_perfBuffer + 2*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f);
                PBYTE buf3 = g_perfBuffer + 4*PERF_BUFFER_SIZE + (g_rng.sizet( PERF_BUFFER_SIZE ) & ~0x3f);

                if( keyFn != NULL )
                {
                    (*keyFn)( buf1, buf2, buf3, keySize );
                    // printf("keyFn called\n");
                }

                for( std::set<SIZE_T>::const_iterator i = (&dataSizes)->begin(); i != (&dataSizes)->end(); ++i )
                {
                    SIZE_T dataSize = *i;

                    if (dataSize == PERF_DATASIZE_SAME_AS_KEYSIZE)
                    {
                        dataSize = keySize;
                    }

                    if( dataFn != NULL )
                    {
                        print("   DataFn Ds: %d\n", dataSize );

                        for ( UINT32 j = 0; j<g_profile_iterations; j++ )
                        {
                            (*dataFn)( buf1, buf2, buf3, dataSize );
                            // printf("dataFn called\n");
                        }
                    }

                    Sleep( 100 );

                    if( decryptFn != NULL )
                    {
                        print("   DecrFn Ds: %d\n", dataSize );

                        for ( UINT32 j = 0; j<g_profile_iterations; j++ )
                        {
                            (*decryptFn)( buf1, buf2, buf3, dataSize );
                            // printf("dataFn called\n");
                        }
                    }

                    Sleep( 100 );
                }

                if( cleanFn != NULL )
                {
                    (*cleanFn)( buf1, buf2, buf3 );
                    // printf("cleanFn called\n");
                }
            }
        }
    }

    iprint("Profiling end\n");

    g_perfTestsRunning = FALSE;
}

#include "bigpriv.h"
#include "ms_rsa.h"

VOID
runRsaAverageKeyGenPerf()
{
    UINT32 bitSizes[] = {512, 3*256, 1024, 3*512, 2048, 3*1024, 4096, 3*2048, 8192, };
    bigctx_t bignumCtx = { 0 };
    SYMCRYPT_RSA_PARAMS scRsaParams = {0};
    RSA_PRIVATE_KEY bnPrivateKey;
    big_prime_search_stat_t bnStats = { 0 };

    iprint( "\n" 
        " Trial division limits: \n" );
    for( UINT32 i=0; i<ARRAY_SIZE( bitSizes ); i++ )
    {
        PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = SymCryptCreateTrialDivisionContext( SymCryptDigitsFromBits( bitSizes[i] / 2 ) );
        CHECK( pContext != NULL, "Out of memory" );
        iprint( "%5d -> %7d\n", bitSizes[i], SymCryptTestTrialdivisionMaxSmallPrime( pContext ) );
        SymCryptFreeTrialDivisionContext( pContext );
    }

    iprint( "\n"
            "RSA key generation performance\n"
            "KeySize    Bignum   SymCrypt  |  BnAvg   ScAvg\n"
            "==============================+===============\n"
        );

    for( UINT32 i=0; i<ARRAY_SIZE( bitSizes ); i++ )
    {
        UINT32 bitSize = bitSizes[i];
        UINT64 lastPrintTime = 0;

        UINT64 scTicks;
        UINT64 bnTicks;
        double scCost;
        double bnCost;
        double scTotal = 0.0;
        double bnTotal = 0.0;

        scRsaParams.version = 1;
        scRsaParams.nBitsOfModulus = bitSize;
        scRsaParams.nPrimes = 2;
        scRsaParams.nPubExp = 1;

        for( UINT32 j=0; j<10; j++ )
        {
            UINT64 start = GET_PERF_CLOCK();

            PSYMCRYPT_RSAKEY pScKey = SymCryptRsakeyAllocate( &scRsaParams, 0 );
            SymCryptRsakeyGenerate( pScKey, NULL, 0, 0 );
            SymCryptRsakeyFree( pScKey );

            UINT64 stop = GET_PERF_CLOCK();
            scTicks = stop - start;
            start = stop;

            rsa_construction( bitSize, &bnPrivateKey, NULL, 0, &bnStats, &bignumCtx );
            rsa_destruction( &bnPrivateKey, &bignumCtx );

            stop = GET_PERF_CLOCK();
            bnTicks = stop - start;

            scCost = scTicks * g_perfScaleFactor - g_perfMeasurementOverhead;
            bnCost = bnTicks * g_perfScaleFactor - g_perfMeasurementOverhead;
            scTotal += scCost;
            bnTotal += bnCost;

            print( "  %5d    %s    %s   | %s    %s\n", bitSize, 
                    formatNumber( bnCost ).c_str(),
                    formatNumber( scCost ).c_str(),
                    formatNumber( bnTotal / (j+1) ).c_str(),
                    formatNumber( scTotal / (j+1) ).c_str()
                );
            if( stop - lastPrintTime > (1<<30) )
            {
                printOutput(1);
                lastPrintTime = stop;
            }
        }
        print( "                              |\n");
    }
    iprint( "\n" );
}
