//
// module.c
// Main file for SymCrypt Windows user-mode module, symcrypt.dll
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

// Ensure that windows.h doesn't re-define the status_* symbols
#define WIN32_NO_STATUS
#include <windows.h>
#include <windef.h>
#include <bcrypt.h>
#include <symcrypt.h>
#include <symcrypt_low_level.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;

#define SYMCRYPT_FIPS_STATUS_INDICATOR
#include "../modules/statusindicator_common.h"
#include "../lib/status_indicator.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

VOID
PerformStartupAlgorithmSelftests()
{
    SymCrypt3DesSelftest();

    SymCryptAesSelftest( SYMCRYPT_AES_SELFTEST_ALL );
    SymCryptAesCmacSelftest();
    SymCryptCcmSelftest();
    SymCryptGcmSelftest();
    SymCryptXtsAesSelftest();

    SymCryptHmacSha1Selftest();
    SymCryptHmacSha256Selftest();
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

    SymCryptSskdfSelfTest();

    SymCryptHmacSha3_256Selftest();

    g_SymCryptFipsSelftestsPerformed |= SYMCRYPT_SELFTEST_ALGORITHM_STARTUP;
}

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE instance,
    _In_ DWORD reason,
    _In_ PVOID reserved)
{
    UNREFERENCED_PARAMETER( reserved );

    HMODULE hDummy = NULL;

    if( reason == DLL_PROCESS_ATTACH )
    {
        DisableThreadLibraryCalls(instance);

        // Take a reference to our own module so that we can't be unloaded. We don't want to be unloaded
        // and reloaded, because this would cause the FIPS selftests to run repeatedly, which is expensive.
        // Being unloaded can also cause problems in VTL1. Failure here is not fatal, though.
        GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCWSTR) &DllMain,
            &hDummy );

        SymCryptInit();

        // TODO: We should only run these selftests once per boot, when the first process loads the DLL
        if( SYMCRYPT_DO_FIPS_SELFTESTS )
        {
            PerformStartupAlgorithmSelftests();
        }
    }

    return TRUE;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    return _aligned_malloc( nBytes, SYMCRYPT_ASYM_ALIGN_VALUE );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    _aligned_free( ptr );
}

VOID
SYMCRYPT_CALL
SymCryptProvideEntropy(
    _In_reads_(cbEntropy)   PCBYTE  pbEntropy,
                            SIZE_T  cbEntropy )
{
    UNREFERENCED_PARAMETER(pbEntropy);
    UNREFERENCED_PARAMETER(cbEntropy);
}

VOID
SYMCRYPT_CALL
SymCryptRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG) cbBuffer, 0 );
    if (!NT_SUCCESS(status))
    {
        SymCryptFatal(status);
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = BCryptGenRandom( BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG) cbBuffer, 0 );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    LPCRITICAL_SECTION lpCriticalSection = malloc( sizeof(CRITICAL_SECTION) );
    InitializeCriticalSection(lpCriticalSection);
    return (PVOID)lpCriticalSection;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    LPCRITICAL_SECTION lpCriticalSection = (LPCRITICAL_SECTION)pMutex;
    DeleteCriticalSection(lpCriticalSection);
    free(lpCriticalSection);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    EnterCriticalSection( (LPCRITICAL_SECTION) pMutex );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    LeaveCriticalSection( (LPCRITICAL_SECTION) pMutex );
}

VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    if (api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }
}