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

    TestSaveXmmEnabled = TRUE;
    TestSaveYmmEnabled = TRUE;

    addAllAlgs();

    if (!g_profile)
    {
        runFunctionalTests();
    }

    TestSaveXmmEnabled = FALSE;
    TestSaveYmmEnabled = FALSE;

    if (g_profile)
    {
        runProfiling();
    }
    else
    {
        runPerfTests();

        testMultiThread();

        testSelftest();
    }

    exitTestInfrastructure();

    return 0;
}

