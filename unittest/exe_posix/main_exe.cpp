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

#ifndef RTLD_DEEPBIND
    #define DLOPEN_FLAGS (RTLD_NOW)
#else
    #define DLOPEN_FLAGS (RTLD_NOW | RTLD_DEEPBIND)
#endif

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
    // See macro defined above for flags:
    // RTLD_NOW means that all unresolved symbols in the library are resolved eagerly before dlopen
    // returns
    // RTLD_DEEPBIND means that the symbols within the loaded library are used in preference to
    // those in the global scope (which ensures that the library will call its own copies of
    // internal SymCrypt functions). Note that this is not supported on macOS.
    //

    PVOID hModule = dlopen(dynamicModulePath, DLOPEN_FLAGS);

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
#if !SYMCRYPT_PLATFORM_APPLE
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
#endif

#if SYMCRYPT_CPU_AMD64
/////////////////////////////////////////////////////////////
//
// Code to set up the YMM/ZMM registers for testing in SAVE_YMM/SAVE_ZMM mode

__m256i g_ymmStartState[16];
__m256i g_ymmTestState[16];
// Extra space in ZMM buffers for k0-k7 mask registers (8 * 8 bytes = one extra __m512i)
__m512i g_zmmStartState[33];
__m512i g_zmmTestState[33];

VOID
verifyVectorRegisters()
{

    if( TestSaveZmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX512 ) )
    {
        SymCryptEnvUmSaveZmmRegistersAsm( g_zmmTestState );

        //
        // Check that all bytes of ZMM16-31 are preserved. These registers only exist in
        // AVX-512, so only AVX-512 code should touch them.
        // We don't check ZMM0-15 here because the lower 32 bytes (YMM portion) are
        // protected by the YMM save/restore mechanism (tested via TestSaveYmmEnabled),
        // and the upper 32 bytes may be legitimately zeroed by AVX operations (e.g.
        // vzeroupper).
        //
        for( SIZE_T i=16*64; i<32*64; i++ )
        {
            if( ((volatile BYTE * )&g_zmmStartState[0])[i] != ((volatile BYTE * )&g_zmmTestState[0])[i] )
            {
                FATAL3( "Zmm registers modified without proper save/restore Zmm%d[%d]", (int)(i/64), (int)(i%64));
            }
        }

        //
        // Check that mask registers k0-k7 are preserved.
        // Mask registers are stored after the 32 ZMM registers in the save buffer.
        //
        for( SIZE_T i=0; i<8*8; i++ )
        {
            if( ((volatile BYTE * )&g_zmmStartState[0])[32*64 + i] != ((volatile BYTE * )&g_zmmTestState[0])[32*64 + i] )
            {
                FATAL3( "Mask register modified without proper save/restore k%d[%d]", (int)(i/8), (int)(i%8));
            }
        }
    }
    else if( TestSaveYmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        SymCryptEnvUmSaveYmmRegistersAsm( g_ymmTestState );

        //
        // It is perfectly fine for the XMM register values to have been modified.
        // We just test that the top half of the Ymm registers have been preserved.
        //
        for( SIZE_T i=0; i<sizeof( g_ymmStartState ); i++ )
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
    if( TestSaveZmmEnabled && SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX512 ) )
    {
        //
        // Do the memsets outside the save area as it might use vector registers
        // Set the initial Zmm and mask registers to a non-trivial value.
        //
        memset( g_zmmTestState, 17, sizeof( g_zmmTestState ) );
        memset( g_zmmStartState, (__rdtsc() & 255) ^ 0x42, sizeof( g_zmmStartState ) );
        SymCryptEnvUmRestoreZmmRegistersAsm( g_zmmStartState );
        verifyVectorRegisters();
    }
    else if( TestSaveYmmEnabled )
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
