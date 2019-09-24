//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include "rsa32_implementations.h"
#include "capi_implementations.h"
#include "cng_implementations.h"
#include "sc_implementations.h"
#include "ref_implementations.h"

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LEGACY;

const char * g_implementationNames[] =
{
    ImpSc::name,
    ImpRsa32::name,
    ImpRsa32b::name,
    ImpCapi::name,
    ImpCng::name,
    ImpRef::name,
    NULL,
};

#include "main_exe_common.cpp"

int __cdecl
main( int argc, _In_reads_( argc ) char * argv[] )
{

    initTestInfrastructure( argc, argv );

    addCapiAlgs();
    addRsa32Algs();
    addCngAlgs();
    addSymCryptAlgs();
    addRefAlgs();

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

