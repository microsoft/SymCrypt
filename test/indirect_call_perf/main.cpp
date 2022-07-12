//
// Test program to investigate performance of indirect function calls.
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// We've had some conflicting information about the perf effects of using indirect function calls.
// This program measures the actual performance in varying situations to help us diagnose the issue.
//


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <intrin.h>

#if SYMCRYPT_CPU_ARM

#define GET_PERF_CLOCK() __rdpmccntr64()

#elif SYMCRYPT_CPU_ARM64

#define GET_PERF_CLOCK() _ReadStatusReg(ARM64_PMCCNTR_EL0)

#else

FORCEINLINE
ULONGLONG
GET_PERF_CLOCK()
{
    int tmp[4]; __cpuid( tmp, 0);

    return __rdtsc();
}

#endif

int g_x, g_y;

typedef void (* NULLFUNCTYPE)();

__declspec(noinline)
void nullFunc1() 
{
    g_x += g_y;
    g_y ^= g_x;
};

__declspec(noinline)
void nullFunc2() 
{
    g_x ^= g_y;
    g_y += g_x;
};

__declspec(noinline)
void nullFunc3() 
{
    g_x -= g_y;
    g_y ^= g_x;
};

__declspec(noinline)
void nullFunc4() 
{
    g_x ^= g_y;
    g_y -= g_x;
};

NULLFUNCTYPE    f[256];

void (*g_funcPtr)() = NULL;
SIZE_T g_ptrDiff = 1 << 30;

#define CALL_TO_MEASURE nullFunc1();
//#define CALL_TO_MEASURE f[j & 0xff]()

//#define PER_LOOP_OP g_funcPtr = (VOID (*)())(((SIZE_T)g_funcPtr) ^ g_ptrDiff)
#define PER_LOOP_OP


#define N_RESULTS   10
#define N_LOOP      100000000

void printPerfNumbers()
{
    double res[N_RESULTS];

    for( int i=0; i<N_RESULTS; i++ )
    {
        ULONGLONG start = GET_PERF_CLOCK();
        for( int j=0; j<N_LOOP; j++ )
        {
            CALL_TO_MEASURE;
            PER_LOOP_OP;
        }
        ULONGLONG stop = GET_PERF_CLOCK();
        res[i] = (double)(stop - start) / N_LOOP;
    }
    for( int i=0; i<N_RESULTS; i++ )
    {
        printf( "%5.2f\n", res[i] );
    }
}


int SYMCRYPT_CDECL
main( int argc, _In_reads_( argc ) LPSTR * argv[] )
{
    UNREFERENCED_PARAMETER( argv );

    printf( "Indirect call performance test program\n"
        "Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n"
        "\n" );

    if( argc != 32178 )
    {
        g_funcPtr = &nullFunc1;
        g_ptrDiff = 0;
        g_ptrDiff = (SIZE_T) &nullFunc1 ^ (SIZE_T) &nullFunc2;

        int s = 3;
        for( int i=0; i<256; i++ )
        {
            switch( i % 4 )
            {
            case 0:
                f[i] = &nullFunc1;
                break;
            case 1:
                f[i] = &nullFunc2;
                break;
            case 2:
                f[i] = &nullFunc3;
                break;
            case 3:
                f[i] = &nullFunc4;
                break;
            }
            s++;
        }
    }

    //
    // Print a few things so that we can verify that we set everything up correctly.
    //
    printf( "%d\n", (ULONG) g_ptrDiff );
    for( int i=0; i<256; i++ )
    {
        printf( "%c", (char)('0' + ((SIZE_T)f[i])%29 ));
    }
    printf( "\n" );


    if( !SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL ) )
    {
        printf( "Set thread priority failed\n" );
    }

    printPerfNumbers();

    return 0;
}







