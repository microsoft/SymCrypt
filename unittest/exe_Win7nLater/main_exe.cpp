//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN7_N_LATER;

#include "main_exe_common.cpp"

int __cdecl
main( int argc, _In_reads_( argc ) char * argv[] )
{

    initTestInfrastructure( argc, argv );

    addAllAlgs();

    if (g_profile)
    {
        runProfiling();
    }
    else
    {
        runFunctionalTests();

        testMultiThread();

        runPerfTests();
    }

    exitTestInfrastructure();

    return 0;
}

