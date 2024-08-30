//
// testSelftest.cpp
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#include "selftestFuncList.cpp"

VOID testSelftestOne( const SELFTEST_INFO * pSelfTestInfo, PrintTable* perfTable )
{
    ULONGLONG nInject = 0;
    const int nTries = 10000;
    ULONGLONG nInjectCalls;

    // Set a random starting point for error injection
    memset( TestErrorInjectionSeed, 0, sizeof( TestErrorInjectionSeed ) );
    *(SIZE_T *)TestErrorInjectionSeed = g_rng.sizet( MAX_SIZE_T ) | 1;
    TestSelftestsEnabled = TRUE;

    //
    // Find out how many times this selftest function calls the error injection so that we can set
    // the probability correctly.
    //
    nInjectCalls = TestErrorInjectionCalls;
    TestErrorInjectionProb = 1;
    pSelfTestInfo->f();
    nInjectCalls = TestErrorInjectionCalls - nInjectCalls;

    CHECK( nInjectCalls < 1000, "Too many inject calls" );

    //
    // If there are N calls to error injection, we set the probability of an injection to 1/(N+1).
    //

    TestErrorInjectionProb = (ULONG)nInjectCalls + 1;

    ULONGLONG clockSum = 0;

    for( int i=0; i<nTries; i++ )
    {
        ULONGLONG errorInjectionCount = TestErrorInjectionCount;
        ULONGLONG fatalCount = TestFatalCount;

        ULONGLONG startClock = GET_PERF_CLOCK();

        pSelfTestInfo->f();

        ULONGLONG endClock = GET_PERF_CLOCK();

        if( errorInjectionCount != TestErrorInjectionCount )
        {
            nInject++;

            CHECK3( fatalCount != TestFatalCount, 
                    "Self test failure in %s, error injected but no fatal call\n", pSelfTestInfo->name );
        }
        else
        {
            // For perf measurement, only count results where no error injection occurred
            clockSum += endClock - startClock;

            CHECK3( fatalCount == TestFatalCount,
                    "Self test %s failed even when no error was injected", pSelfTestInfo->name );
        }
    }

    // Get the average number of clock cycles each selftest takes per iteration, so that we can
    // catch performance regressions or unacceptably slow tests when we add new ones. Note that for
    // measuring algorithm performance (i.e. not selftests), the unit tests use linear regression
    // to determine the average number of cycles per byte, and fixed overhead, across many runs.
    // We do not yet perform linear regression on the selftest performance results, so they will be
    // less accurate and may show unexpected values for platforms where we don't affinitize the
    // unit test thread to a single core (e.g. Linux), or on architectures where clock cycle count
    // varies based on CPU frequency (e.g. AMD64).
    ULONGLONG clockCycleAverage = clockSum / (nTries - nInject);
    perfTable->addItem( pSelfTestInfo->name, "Cycles", clockCycleAverage );

    TestSelftestsEnabled = FALSE;

    if( nInject < nTries/5 )
    {
        FATAL3( "Self test of %s produced only %d error injections\n", pSelfTestInfo->name, nInject );
    }

    if( nInject > nTries - nTries/10 )
    {
        FATAL3( "Self test of %s produced too many error injections: %d", pSelfTestInfo->name, nInject );
    }

}

VOID
testSelftest()
{
    PrintTable selftestPerfTable;

    for( int i=0; g_selfTests[i].f != NULL; i++ )
    {
        testSelftestOne( &g_selfTests[i], &selftestPerfTable );
    }
    for( int i=0; g_selfTests_allocating[i].f != NULL; i++ )
    {
        testSelftestOne( &g_selfTests_allocating[i], &selftestPerfTable );
    }

    selftestPerfTable.print( "Self test performance" );
}

