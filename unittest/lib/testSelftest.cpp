//
// testSelftest.cpp
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#include "selftestFuncList.cpp"

VOID testSelftestOne( const SELFTEST_INFO * pSelfTestInfo )
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
    // If there are N calls to error injection, we set the probability of an injection to
    // 1/(N+1). This 
    //

    TestErrorInjectionProb = (ULONG)nInjectCalls + 1;

    for( int i=0; i<nTries; i++ )
    {
        ULONGLONG errorInjectionCount = TestErrorInjectionCount;
        ULONGLONG fatalCount = TestFatalCount;

        pSelfTestInfo->f();

        if( errorInjectionCount != TestErrorInjectionCount )
        {
            nInject++;

            CHECK3( fatalCount != TestFatalCount, 
                    "Self test failure in %s, error injected but no fatal call\n", pSelfTestInfo->name );
        }
        else
        {
            CHECK3( fatalCount == TestFatalCount,
                    "Self test %s failed even when no error was injected", pSelfTestInfo->name );
        }
    }

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
    iprint( "\nTesting self tests:\n" );
    String sep = "    ";

    for( int i=0; g_selfTests[i].f != NULL; i++ )
    {
        iprint( "%s%s", sep.c_str(), g_selfTests[i].name );
        sep = ", ";
        testSelftestOne( &g_selfTests[i] );
    }
    iprint( "\n" );
}
