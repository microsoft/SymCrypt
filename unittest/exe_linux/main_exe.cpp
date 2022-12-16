//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_DEFS(Unittest);

#include <dlfcn.h>
#include <sys/random.h>

PVOID loadDynamicModuleFromPath(PCSTR dynamicModulePath)
{
    //
    // Considered using dlmopen, which loads the module in its own fresh namespace which would help
    // to ensure there is no symbol confusion of any kind. Unfortunately, I found that using dlmopen
    // is not supported by gdb so you cannot set breakpoints on functions in the dlmopen-ed library.
    // As RTLD_DEEPBIND seems to do the trick in preventing symbol confusion, sticking with dlopen
    // for now.
    //
    // dlmopen(LM_ID_NEWLM, dynamicModulePath, RTLD_NOW | RTLD_DEEPBIND);

    //
    // RTLD_NOW means that all unresolved symbols in the library are resolved eagerly before dlopen
    // returns
    // RTLD_DEEPBIND means that the symbols within the loaded library are used in preference to
    // those in the global scope (which ensures that the library will call its own copies of
    // internal SymCrypt functions)
    //
    PVOID hModule = dlopen(dynamicModulePath, RTLD_NOW | RTLD_DEEPBIND);
    if (!hModule) {
        iprint("\nFailed to load dynamic module with: %s\n", dlerror());
    }
    return hModule;
}

PVOID getDynamicSymbolPointerFromString(PVOID hModule, PCSTR pSymbolName, SCTEST_DYNSYM_TYPE symbolType)
{
    UNREFERENCED_PARAMETER(symbolType);
    return dlsym(hModule, pSymbolName);
}

// Define oe_sgx_get_additional_host_entropy so we can test the oe module with our symcryptunittest
// executable
extern "C"
{
    int oe_sgx_get_additional_host_entropy(uint8_t* data, size_t size)
    {
        SIZE_T result = getrandom( data, size, 0 );
        if (result != size )
        {
            SymCryptFatal( 'oehe' );
        }
        return 1; // 1 indicates success
    }
}

#if SYMCRYPT_CPU_AMD64
/////////////////////////////////////////////////////////////
//
// Code to set up the YMM registers for testing in SAVE_YMM mode

__m256i g_ymmStartState[16];
__m256i g_ymmTestState[16];

VOID
verifyVectorRegisters()
{

    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        return;
    }

    //
    // We know that AVX2 is present from here on
    //
    if( TestSaveYmmEnabled )
    {
        SymCryptEnvUmSaveYmmRegistersAsm( g_ymmTestState );

        //
        // It is perfectly fine for the XMM register values to have been modified.
        // We just test that the top half of the Ymm registers have been preserved.
        //
        for( int i=0; i<sizeof( g_ymmStartState ); i++ )
        {
            if( ((volatile BYTE * )&g_ymmStartState[0])[i] != ((volatile BYTE * )&g_ymmTestState[0])[i] &&
                ((i & 16) == 16 )
                )
            {
                FATAL3( "Ymm registers modified without proper save/restore Ymm%d[%d]", i>>5, i&31);
            }
        }
    }
}

VOID
initVectorRegisters()
{
    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        return;
    }
    if( TestSaveYmmEnabled )
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
}

VOID
cleanVectorRegisters()
{
    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        return;
    }

    _mm256_zeroupper();
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

VOID testMultiThread()
{
}

#define SYMCRYPT_TEST_SELFTEST (1)

#include "main_exe_common.cpp"
