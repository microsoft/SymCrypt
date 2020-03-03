//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


PSTR testDriverName = TESTDRIVER_NAME;

const char * g_implementationNames[] = 
{
    ImpSc::name,
#if INCLUDE_IMPL_RSA32    
    ImpRsa32::name,
    ImpRsa32b::name,
#endif
#if INCLUDE_IMPL_CAPI    
    ImpCapi::name,
#endif
#if INCLUDE_IMPL_CNG    
    ImpCng::name,
#endif
#if INCLUDE_IMPL_REF
    ImpRef::name,
#endif
#if INCLUDE_IMPL_MSBIGNUM
    ImpMsBignum::name,
#endif    
    NULL,
};

VOID 
addAllAlgs()
{
    addSymCryptAlgs();

    if( !g_sgx )
    {
        // SGX mode cares about testing BCrypt functions in enclaves, so ignores CAPI and RSA32 tests
        // which are identical to normal mode. SymCrypt provides implementations for all algs, 
        // so they must run because the test fails if there are algorithms where no implementations were tested.
#if INCLUDE_IMPL_RSA32
        addRsa32Algs();
#endif
#if INCLUDE_IMPL_CAPI
        addCapiAlgs();
#endif            
    }

#if INCLUDE_IMPL_CNG
    addCngAlgs();
#endif
#if INCLUDE_IMPL_REF
    addRefAlgs();
#endif
#if INCLUDE_IMPL_MSBIGNUM
    addMsBignumAlgs();
#endif        
}


DWORD WINAPI umThreadFunc( LPVOID param )
{
    runTestThread( param );
    return 0;
}

VOID
scheduleAsyncTest( SelfTestFn f )
{
    //
    // No async testing in user mode, just run the test in-line.
    //
    f();
}


VOID
testMultiThread()
{
    HANDLE threads[64];
    int i;
    g_fExitMultithreadTest = FALSE;
    g_nMultithreadTestsRun = 0;

    iprint( "\nMulti-thread test..." );

    for( i=0; i<ARRAY_SIZE( threads ); i++ )
    {
        threads[i] = CreateThread( NULL, 0, &umThreadFunc, (LPVOID) g_rng.sizet( (SIZE_T)-1 ), 0, NULL );
        CHECK3( threads[i] != NULL, "Failed to start thread i", i)
    }

    Sleep( 1000 * 5 );

    g_fExitMultithreadTest = TRUE;

    for( i=0; i<ARRAY_SIZE( threads ); i++ )
    {
        // Timeout increased from 5 seconds to 15. In Entropy Validation test, we run several SymCryptUnitTests in parallel, and
        // the timeout wasn't enough in that case.
        CHECK( WaitForSingleObject( threads[i], 15000 ) == 0, "Thread did not exit in time" );
        CloseHandle( threads[i] );
    }
    iprint( " done. %lld tests run.\n", g_nMultithreadTestsRun );
}
