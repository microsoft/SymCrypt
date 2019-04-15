//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


PSTR testDriverName = TESTDRIVER_NAME;

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

    Sleep( 1000 * 10 );

    g_fExitMultithreadTest = TRUE;

    for( i=0; i<ARRAY_SIZE( threads ); i++ )
    {
        CHECK( WaitForSingleObject( threads[i], 5000 ) == 0, "Thread did not exit in time" );
        CloseHandle( threads[i] );
    }
    iprint( " done. %lld tests run.\n", g_nMultithreadTestsRun );
}