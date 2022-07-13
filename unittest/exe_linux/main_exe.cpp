//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_DEFS( Unittest );

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

#else

VOID verifyVectorRegisters()
{
}

VOID initVectorRegisters()
{
}

#endif

VOID testMultiThread()
{
}

#define SYMCRYPT_TEST_SELFTEST (1)

#include "main_exe_common.cpp"
