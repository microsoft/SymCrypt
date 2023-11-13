//
// main.cpp
// Main file for symcrypt.sys
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <symcrypt.h>
#include <symcrypt_low_level.h>
#include <bcrypt.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST;

#define GENRANDOM(pbBuf, cbBuf)     BCryptGenRandom( NULL, (PBYTE) (pbBuf), (UINT32) (cbBuf), BCRYPT_USE_SYSTEM_PREFERRED_RNG )


#define SYMCRYPT_FIPS_STATUS_INDICATOR
#include "../modules/statusindicator_common.h"
#include "../lib/status_indicator.h"

NTSTATUS
DriverEntry(
    _In_  struct _DRIVER_OBJECT* DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    SymCryptInit();

    UNREFERENCED_PARAMETER( DriverObject );
    UNREFERENCED_PARAMETER( RegistryPath );

    return STATUS_SUCCESS;
}

VOID SYMCRYPT_CALL SymCryptModuleInit(UINT32 api, UINT32 minor)
{
    if (api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR))
    {
        SymCryptFatal('vers');
    }
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc(SIZE_T nBytes)
{
    PBYTE p, res = NULL;
    ULONG offset;

    p = (PBYTE) ExAllocatePoolZero(NonPagedPoolNx, nBytes + SYMCRYPT_ASYM_ALIGN_VALUE + 4, 'cmyS');
    if (!p)
    {
        goto cleanup;
    }

    res = (PBYTE) (((ULONG_PTR)p + 4 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~(SYMCRYPT_ASYM_ALIGN_VALUE - 1));
    offset = (ULONG)(res - p);
    *(ULONG *) &res[-4] = offset;

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    PBYTE p;
    ULONG offset;

    p = (PBYTE) ptr;
    offset = *(ULONG *) &p[-4];

    ExFreePoolWithTag(p - offset, 'cmyS');
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
    // Need to remove dependency on BCrypt
    GENRANDOM( pbBuffer, cbBuffer );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = STATUS_SUCCESS;

    // Need to remove dependency on BCrypt
    status = GENRANDOM( pbBuffer, cbBuffer );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    PFAST_MUTEX pFastMutex = (PFAST_MUTEX) ExAllocatePoolZero( NonPagedPoolNx, sizeof(FAST_MUTEX), 'uMCS' );
    ExInitializeFastMutex(pFastMutex);
    return (PVOID)pFastMutex;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    ExFreePoolWithTag( (PBYTE)pMutex, 'uMCS' );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    ExAcquireFastMutex((PFAST_MUTEX)pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    ExReleaseFastMutex((PFAST_MUTEX)pMutex);
}
