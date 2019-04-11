//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

BOOLEAN g_fExitMultithreadTest = FALSE;

ULONGLONG g_nMultithreadTestsRun = 0;

VOID
runTestThread( VOID * seed )
{
    BYTE rnd[SYMCRYPT_SHA512_RESULT_SIZE];
    ULONGLONG n = 0;

    memcpy( rnd, &seed, sizeof( seed ) );

    int nTests = 0;

    while( g_selfTests[nTests].f != NULL )
    {
        nTests++;
    }

    CHECK( nTests <= 64, "Too many tests for my RNG system" );

    while( !g_fExitMultithreadTest )
    {
        SymCryptSha512( rnd, sizeof(rnd), rnd );
        for( int i=0; i<SYMCRYPT_SHA512_RESULT_SIZE; i++ )
        {
            g_selfTests[ rnd[i] % nTests ].f();
            n++;
        }
    }

    InterlockedAdd64( (LONGLONG volatile *) &g_nMultithreadTestsRun, n );
}