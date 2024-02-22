//
// main.c
// Main file for symcryptk.dll
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <symcrypt.h>
#include <symcrypt_low_level.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST;

#define SYMCRYPT_FIPS_STATUS_INDICATOR
#define FIPS_SERVICE_DESC_ENTROPY_SOURCE
#define FIPS_SERVICE_DESC_SELF_TESTS
#define FIPS_SERVICE_DESC_SHOW_STATUS
#define FIPS_SERVICE_DESC_SHOW_VERSION
#include "../lib/status_indicator.h"

// Our DriverEntry function is not used, as this module acts as an export driver which is linked
// directly to the kernel. In other words, it's not initialized by WDF, and we don't create any
// device objects or use other WDF functions. However, we need to define the function to be able
// to link with some of the KMDF libs.
NTSTATUS
DriverEntry(
    _In_  struct _DRIVER_OBJECT* DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
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

    SymCryptInit();
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
    UNREFERENCED_PARAMETER( pbBuffer );
    UNREFERENCED_PARAMETER( cbBuffer );

    // No one should be using this yet
    SymCryptFatal( 'rnd1' );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    UNREFERENCED_PARAMETER( pbBuffer );
    UNREFERENCED_PARAMETER( cbBuffer );

    // No one should be using this yet
    SymCryptFatal( 'rnd2' );
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
