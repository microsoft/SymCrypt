//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

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

int SYMCRYPT_CDECL
main( int argc, _In_reads_( argc ) char * argv[] )
{
    initTestInfrastructure( argc, argv );

    addAllAlgs();

    if (!g_profile && !g_measure_specific_sizes)
    {
        runFunctionalTests();
    }

    // In performance testing we don't care about ImpSc which has overhead from vector save/restore
    // testing shim
    // Instead we want to test ImpScStatic which just directly calls into statically linked SymCrypt
    // functions
    // We call updateSymCryptStaticAlgs to switch out the static SymCrypt implementations
    updateSymCryptStaticAlgs();

    // Disable Vector save testing for non-functional tests
    // This avoids unnecessary costs in the statically linked SymCrypt functions which use the unit
    // test environment so may save/restore in user mode unnecessarily for test purposes
    TestSaveXmmEnabled = FALSE;
    TestSaveYmmEnabled = FALSE;

    // Clean vector registers of any random values
    // (having dirty Ymm state hurts SSE performance)
    cleanVectorRegisters();

    if (g_profile)
    {
        runProfiling();
    }
    else
    {
        runPerfTests();

        if (!g_measure_specific_sizes)
        {
#if SYMCRYPT_TEST_SELFTEST
            testSelftest();
#endif

            testMultiThread();
        }
    }

    exitTestInfrastructure();

    return 0;
}
