//
// module.c
// Main file for SymCrypt DLL/shared object library
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_LINUX_USERMODE

// Module main function executed by the runtime upon load
VOID __attribute__((constructor)) SymCryptModuleMain()
{
    SymCryptInit();

    // We must test HMAC-SHA256 first since it's used by our integrity verification
    SymCryptHmacSha256Selftest(); 

    SymCryptModuleVerifyIntegrity();

    SymCrypt3DesSelftest(); 
 
    SymCryptAesSelftest( SYMCRYPT_AES_SELFTEST_ALL ); 
    SymCryptAesCmacSelftest(); 
    SymCryptCcmSelftest(); 
    SymCryptGcmSelftest(); 
    SymCryptXtsAesSelftest(); 
    
    SymCryptRngAesInstantiateSelftest(); 
    SymCryptRngAesReseedSelftest(); 
    SymCryptRngAesGenerateSelftest(); 
    
    SymCryptHmacSha1Selftest(); 
    SymCryptHmacSha384Selftest();
    SymCryptHmacSha512Selftest(); 
    
    SymCryptParallelSha256Selftest(); 
    SymCryptParallelSha512Selftest(); 
    
    SymCryptTlsPrf1_1SelfTest(); 
    SymCryptTlsPrf1_2SelfTest(); 
    
    SymCryptHkdfSelfTest(); 
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    PVOID ptr = NULL;
    if(posix_memalign( &ptr, SYMCRYPT_ASYM_ALIGN_VALUE, nBytes ) != 0)
    {
        return NULL;
    }

    return ptr;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree( VOID * pMem )
{
    free( pMem );
}

VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor, UINT32 patch )
{
    if( api > SYMCRYPT_CODE_VERSION_API )
    {
        SymCryptFatal( 'vers' );
    }
}