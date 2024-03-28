//
// env_opteeTa.c
// Platform-specific code for OPTEE TA.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

// OPTEE TA specific data
#define TEE_ERROR_BAD_STATE               0xFFFF0007

typedef uint32_t TEE_Result;

void TEE_Panic(TEE_Result panicCode);


SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvOpteeTa(void)
{
    return 0;
}

VOID
SYMCRYPT_CALL
SymCryptInitEnvOpteeTa( UINT32 version )
{
    if( g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED )
    {
        return;
    }
    
    // Optee module relies on the unconditional availability of certain CPU features (ASIMD, AES, PMULL, SHA256)
    g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~(SYMCRYPT_CPU_FEATURE_NEON|SYMCRYPT_CPU_FEATURE_NEON_AES|SYMCRYPT_CPU_FEATURE_NEON_PMULL|SYMCRYPT_CPU_FEATURE_NEON_SHA256);

    SymCryptInitEnvCommon( version );
}

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatalEnvOpteeTa( ULONG fatalCode )
{
    UINT32 fatalCodeVar;

    SymCryptFatalIntercept( fatalCode );

    //
    // Put the fatal code in a location where it shows up in the dump
    //
    SYMCRYPT_FORCE_WRITE32( &fatalCodeVar, fatalCode );

    //
    // Our first preference is to fastfail,
    // the second to create an AV, which can trigger a core dump so that we get to
    // see what is going wrong.
    //
    __fastfail( FAST_FAIL_CRYPTO_LIBRARY );

    TEE_Panic(TEE_ERROR_BAD_STATE);
    
    //
    // Next we write to the NULL pointer, this causes an AV
    //
    SYMCRYPT_FORCE_WRITE32( (volatile UINT32 *)NULL, fatalCode );

    SymCryptFatalHang( fatalCode );
}

VOID
SYMCRYPT_CALL
SymCryptTestInjectErrorEnvOpteeTa( PBYTE pbBuf, SIZE_T cbBuf )
{
    //
    // This feature is only used during testing. In production it is always
    // an empty function that the compiler can optimize away.
    //
    UNREFERENCED_PARAMETER( pbBuf );
    UNREFERENCED_PARAMETER( cbBuf );
}

