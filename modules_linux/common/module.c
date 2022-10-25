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

    if( SYMCRYPT_DO_FIPS_SELFTESTS )
    {
        // We must test HMAC-SHA256 first since it's used by our integrity verification
        SymCryptHmacSha256Selftest();

        SymCryptModuleVerifyIntegrity();

        SymCryptRngAesInstantiateSelftest();
        SymCryptRngAesReseedSelftest();
        SymCryptRngAesGenerateSelftest();
    }

    // RNG must be initialized before the following selftests, but this should happen
    // regardless of whether or SYMCRYPT_DO_FIPS_SELFTESTS is set
    SymCryptRngInit();

    if( SYMCRYPT_DO_FIPS_SELFTESTS )
    {
        SymCrypt3DesSelftest();

        SymCryptAesSelftest( SYMCRYPT_AES_SELFTEST_ALL );
        SymCryptAesCmacSelftest();
        SymCryptCcmSelftest();
        SymCryptGcmSelftest();
        SymCryptXtsAesSelftest();

        SymCryptHmacSha1Selftest();
        SymCryptHmacSha384Selftest();
        SymCryptHmacSha512Selftest();

        SymCryptParallelSha256Selftest();
        SymCryptParallelSha512Selftest();

        SymCryptTlsPrf1_1SelfTest();
        SymCryptTlsPrf1_2SelfTest();

        SymCryptHkdfSelfTest();

        SymCryptSp800_108_HmacSha1SelfTest();
        SymCryptSp800_108_HmacSha256SelfTest();
        SymCryptSp800_108_HmacSha384SelfTest();
        SymCryptSp800_108_HmacSha512SelfTest();

        SymCryptPbkdf2_HmacSha1SelfTest();

        SymCryptSrtpKdfSelfTest();

        SymCryptSshKdfSha256SelfTest();
        SymCryptSshKdfSha512SelfTest();

        SymCryptSha3_256Selftest();

        g_SymCryptFipsSelftestsPerformed |= SYMCRYPT_SELFTEST_ALGORITHM_STARTUP;
    }
}

VOID __attribute__((destructor)) SymCryptModuleDestructor()
{
    SymCryptRngUninit();
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

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom( PBYTE pbBuffer, SIZE_T cbBuffer )
{
    SymCryptRandom( pbBuffer, cbBuffer );
    return SYMCRYPT_NO_ERROR;
}


PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    PVOID ptr = malloc(sizeof(pthread_mutex_t));

    if( ptr )
    {
        if( pthread_mutex_init( (pthread_mutex_t *)ptr, NULL ) != 0 )
        {
            free(ptr);
            ptr = NULL;
        }
    }

    return ptr;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_destroy( (pthread_mutex_t *)pMutex );

    free(pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_lock( (pthread_mutex_t *)pMutex );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_unlock( (pthread_mutex_t *)pMutex );
}


VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    if( api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }
}