//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

PSTR testDriverName = TESTDRIVER_NAME;

PVOID loadDynamicModuleFromPath(PCSTR dynamicModulePath)
{
    return (PVOID) LoadLibraryExA(dynamicModulePath, NULL, 0);
}

PVOID getDynamicSymbolPointerFromString(PVOID hModule, PCSTR pSymbolName, SCTEST_DYNSYM_TYPE symbolType)
{
    static decltype(&getDynamicSymbolPointerFromString) pSctestGetSymbolAddress = nullptr;
    static bool lookupAttempted = false;

    if (!lookupAttempted)
    {
        pSctestGetSymbolAddress = (decltype(&getDynamicSymbolPointerFromString))GetProcAddress((HMODULE)hModule, "SctestGetSymbolAddress");
        lookupAttempted = true;
    }

    if (pSctestGetSymbolAddress == nullptr)
    {
        // Ignore symbolType if looking up symbols directly in dynamic module
        return GetProcAddress((HMODULE)hModule, pSymbolName);
    }
    else
    {
        return pSctestGetSymbolAddress((HMODULE)hModule, pSymbolName, symbolType);
    }
}

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64

/////////////////////////////////////////////////////////////
//
// Code to set up the Vector registers for testing when TestSaveXmmEnabled or TestSaveYmmEnabled

#if SYMCRYPT_CPU_AMD64
__m128i g_xmmStartState[16];
__m128i g_xmmTestState[16];
__m256i g_ymmStartState[16];
__m256i g_ymmTestState[16];
#else
__m256i g_ymmStartState[8];
__m256i g_ymmTestState[8];
#endif

VOID
verifyVectorRegisters()
{
    if (TestSaveYmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_AVX2))
    {
        SymCryptEnvUmSaveYmmRegistersAsm( g_ymmTestState );

        //
        // We want to test that the top half of the Ymm registers have been preserved.
        // For MSFT x64 ABI Xmm6-Xmm15 are non-volatile so should be preserved. We also check this
        // is done, which gives us confidence none of our assembly breaks the ABI. This check also
        // applies to x86.
        //
        for( int i=0; i<sizeof( g_ymmStartState ); i++ )
        {
            if( ((volatile BYTE * )&g_ymmStartState[0])[i] != ((volatile BYTE * )&g_ymmTestState[0])[i] &&
                (((i & 16) == 16 ) || (i > 6*sizeof( g_ymmStartState[0] )))
                )
            {
                FATAL3( "Ymm registers modified without proper save/restore Ymm%d[%d]", i>>5, i&31);
            }
        }
    }
#if SYMCRYPT_CPU_AMD64
    //
    // For x86 all vector registers Xmm0-Xmm7 are volatile by default - so we cannot test that
    // they are not modified. E.g. In the unit tests we call BCrypt to generate random numbers
    // and BCrypt can trash the full Xmm state, as this is how our AES intrinsics are compiled
    // (using all registers and no save/restore in prologue/epilogue).
    // The CRT is also free to trash the state semi-arbitrarily (observationally the CRT tends to
    // only trash Xmm0 - Xmm5, same as AMD64, but it is free to use all Xmm registers)
    //
    else if (TestSaveXmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_SSE2) && !SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL))
    {
        memset( g_xmmTestState, 0, sizeof( g_xmmTestState ) );
        SymCryptEnvUmSaveXmmRegistersAsm(g_xmmTestState);

        //
        // For MSFT x64 ABI Xmm6-Xmm15 are non-volatile so should be preserved. We just check this
        // is done, which gives us confidence none of our assembly breaks the ABI.
        //
        for( int i = 6 * sizeof(g_xmmStartState[0]); i < sizeof(g_xmmStartState); i++ )
        {
            if( ((volatile BYTE * )&g_xmmStartState[0])[i] != ((volatile BYTE * )&g_xmmTestState[0])[i] )
            {
                FATAL3( "Xmm registers modified without proper save/restore Xmm%d[%d]", i>>4, i&15);
            }
        }
    }
#endif
}

VOID
initVectorRegisters()
{
    if (TestSaveYmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_AVX2))
    {
        //
        // Do the memsets outside the save area as it might use vector registers
        // Set the initial Ymm registers to a non-trivial value. It is likely (for performance
        // reasons) that the upper halves are already zero-ed and will be re-zeroed by any function
        // we call.
        //
        memset( g_ymmTestState, 17, sizeof( g_ymmTestState ) );
        memset( g_ymmStartState, (__rdtsc() & 255) ^ 0x42, sizeof( g_ymmStartState ) );
        SymCryptEnvUmRestoreYmmRegistersAsm( g_ymmStartState );
        verifyVectorRegisters();
    }
#if SYMCRYPT_CPU_AMD64
    else if (TestSaveXmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_SSE2) && !SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL))
    {
        //
        // Do the memsets outside the save area as it might use Xmm registers
        // Set the initial Xmm registers to a non-trivial value.
        //
        memset( g_xmmTestState, 17, sizeof( g_xmmTestState ) );
        memset( g_xmmStartState, (__rdtsc() & 255) ^ 0x42, sizeof( g_xmmStartState ) );
        SymCryptEnvUmRestoreXmmRegistersAsm( g_xmmStartState );
        verifyVectorRegisters();
    }
#endif
}

VOID
cleanVectorRegisters()
{
}

#else

VOID verifyVectorRegisters()
{
}

VOID initVectorRegisters()
{
}

VOID
cleanVectorRegisters()
{
}

#endif

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
        // Timeout increased from 15 seconds to 2 minutes. In Entropy Validation test, we run several SymCryptUnitTests in parallel, and
        // the timeout wasn't enough in that case.
        CHECK( WaitForSingleObject( threads[i], 120000 ) == 0, "Thread did not exit in time" );
        CloseHandle( threads[i] );
    }
    iprint( " done. %lld tests run.\n", g_nMultithreadTestsRun );
}

#include "main_exe_common.cpp"