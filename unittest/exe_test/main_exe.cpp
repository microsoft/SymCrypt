//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_DEFS( Unittest );

#include "main_exe_common.cpp"

int __cdecl
main( int argc, _In_reads_( argc ) char * argv[] )
{

    initTestInfrastructure( argc, argv );

    // As of January 2020, we can't test XMM/YMM register saving and restoring because basic CRT
    // functions like memcpy and memcmp use the XMM registers. This causes the test to fail on
    // x86, but there's no point in testing this on AMD64 either because it effectively ignores
    // the modified XMM values, meaning it's not actually testing anything.
    TestSaveXmmEnabled = FALSE;
    TestSaveYmmEnabled = FALSE;

    addAllAlgs();

    if (!g_profile && !g_measure_specific_sizes)
    {
        runFunctionalTests();
    }

    if (g_profile)
    {
        runProfiling();
    }
    else
    {
        runPerfTests();

        if (!g_measure_specific_sizes)
        {
            testMultiThread();

            testSelftest();
        }
    }

    exitTestInfrastructure();

    return 0;
}

