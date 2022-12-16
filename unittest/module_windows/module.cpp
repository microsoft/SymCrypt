//
// module.cpp
// Main file for SymCrypt DLL/shared object library
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;

BYTE g_bAllocFill = 0;

UINT64 g_magic;

SYMCRYPT_CPU_FEATURES g_originalSymCryptCpuFeaturesNotPresent;

VOID
SYMCRYPT_CALL
AllocWithChecksInit()
{
    GENRANDOM( (PBYTE) &g_bAllocFill, sizeof( g_bAllocFill ) );
    GENRANDOM( (PBYTE) &g_magic, sizeof( g_magic ) );
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    PBYTE p;
    PBYTE res;
    ULONG offset;
    SIZE_T nAllocated;

    CHECK( g_bAllocFill != 0, "AllocFill not initialized" );

    nAllocated = nBytes + SYMCRYPT_ASYM_ALIGN_VALUE + 16 + 8;   // alignment + 16 byte prefix + 8 byte postfix
    CHECK( (ULONG) nAllocated == nAllocated, "?" );

    p = new BYTE[ nAllocated ];

    // We randomize the fill value a bit to ensure that unused space isn't fully predictable.
    // (We had a bug where ModElementIsEqual tested equality of uninitialized space, and it worked...)
    memset( p, g_bAllocFill, nAllocated );

    // Result is first aligned value at least 16 bytes into the buffer
    res = (PBYTE) (((ULONG_PTR)p + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~(SYMCRYPT_ASYM_ALIGN_VALUE-1) );

    offset = (ULONG)(res - p);
    CHECK( offset >= 16 && offset < 256, "?" );

    *(UINT64 *) &res[-8] = g_magic ^ (SIZE_T) res ^ 'strt';
    *(UINT64 *) &res[nBytes ] = g_magic ^ (SIZE_T) res ^ 'end.';
    *(UINT32 *) &res[-12] = (UINT32) nBytes;
    *(UINT32 *) &res[-16] = offset;

    return res;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    PBYTE p;
    SIZE_T nBytes;

    p = (PBYTE)ptr;
    nBytes = *(UINT32*)&p[-12];

    CHECK(*(ULONGLONG*)&p[-8] == (g_magic ^ (SIZE_T)p ^ 'strt'), "Left magic corrupted");
    CHECK(*(ULONGLONG*)&p[nBytes] == (g_magic ^ (SIZE_T)p ^ 'end.'), "Right magic corrupted");
    delete[](p - *(UINT32*)&p[-16]);
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
    CHECK( cbBuffer < 0xffffffff, "Random buffer too large" );

    GENRANDOM( pbBuffer, (UINT32) cbBuffer );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = STATUS_SUCCESS;

    CHECK( cbBuffer < 0xffffffff, "Random buffer too large" );

    status = GENRANDOM( pbBuffer, (UINT32) cbBuffer );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    return ALLOCATE_FAST_INPROC_MUTEX();
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    FREE_FAST_INPROC_MUTEX(pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    ACQUIRE_FAST_INPROC_MUTEX(pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    RELEASE_FAST_INPROC_MUTEX(pMutex);
}

_Analysis_noreturn_
VOID
fatal( _In_ PCSTR file, ULONG line, _In_ PCSTR format, ... )
{
    va_list vl;

    fprintf( stdout, "*\n\n***** FATAL ERROR %s(%lu): ", file, line );

    va_start( vl, format );

    vfprintf( stdout, format, vl );
    fprintf( stdout, "\n" );

    exit( -1 );
}

VOID SYMCRYPT_CALL SymCryptModuleInit( UINT32 api, UINT32 minor )
{
    SymCryptInit();

    AllocWithChecksInit();

    if (api != SYMCRYPT_CODE_VERSION_API ||
        (api == SYMCRYPT_CODE_VERSION_API && minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        SymCryptFatal( 'vers' );
    }

    // Save the original CPU features flags.
    g_originalSymCryptCpuFeaturesNotPresent = g_SymCryptCpuFeaturesNotPresent;
}

SYMCRYPT_CPU_FEATURES SctestDisableCpuFeatures(SYMCRYPT_CPU_FEATURES disable)
{
    // Ugly hack, directly manipulate the CPU features flags.
    g_SymCryptCpuFeaturesNotPresent = g_originalSymCryptCpuFeaturesNotPresent | disable;
    return g_SymCryptCpuFeaturesNotPresent;
}