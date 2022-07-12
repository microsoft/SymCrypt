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

    // Set up vector registers to be in a state that should not be modified by unit tests
    // This may do nothing if TestSaveXXXEnabled is FALSE, but it can also:
    //  On Windows AMD64 set Xmm6-Xmm15 to random values
    //    these values are non-volatile in Window x64 ABI, so should be preserved. If they are not
    //    preserved it indicates a problem with our assembly not adhering to the Windows ABI
    //  On Linux AMD64 set Ymm0-Ymm15 to random values
    //    these values are naturally volatile on Linux, but symcryptunittest callers may specify the
    //    following environment variable:
    //      GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX_Usable,-AVX_Fast_Unaligned_Load,-AVX2_Usable
    //    to avoid use of AVX in glibc. This means we can test the Ymm save/restore logic that is
    //    used in Windows kernel using Linux user mode.
    initVectorRegisters();

    addAllAlgs();

    if (!g_profile && !g_measure_specific_sizes)
    {
        runFunctionalTests();
    }

    // Check that all uses of vector registers in the functional unit tests correctly saved/restored
    verifyVectorRegisters();


    if (g_profile)
    {
        runProfiling();
    }
    else
    {
        runPerfTests();

        if (!g_measure_specific_sizes)
        {
            testSelftest();

            // Disable Vector save tests for multithreaded tests
            TestSaveXmmEnabled = FALSE;
            TestSaveYmmEnabled = FALSE;
            testMultiThread();
        }
    }

    exitTestInfrastructure();

    return 0;
}
