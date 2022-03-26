//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// callback.cpp: Callback functions for SymCrypt and MsBignum
//

#include "precomp.h"

//
// Format of checked allocation:
// 8 bytes, SIZE_T of original allocation
// 8 bytes magic
// <inner buffer>
// 8 bytes magic
//

volatile INT64 g_nOutstandingCheckedAllocs = 0;
volatile INT64 g_nAllocs = 0;

volatile INT64 g_nOutstandingCheckedAllocsMsBignum = 0;
volatile INT64 g_nAllocsMsBignum = 0;

BYTE g_bAllocFill= 0;

UINT64 g_magic;

VOID
SYMCRYPT_CALL
AllocWithChecksInit()
{
    while( (g_bAllocFill = g_rng.byte()) == 0 );

    GENRANDOM( (PBYTE) &g_magic, sizeof( g_magic ) );
}

PVOID
SYMCRYPT_CALL
AllocWithChecks( SIZE_T nBytes, volatile INT64 * pOutstandingAllocs, volatile INT64 * pAllocs )
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
    memset( p, (BYTE)(g_bAllocFill ^ (g_rng.byte() & 1)), nAllocated );

    // Result is first aligned value at least 16 bytes into the buffer
    res = (PBYTE) (((ULONG_PTR)p + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~(SYMCRYPT_ASYM_ALIGN_VALUE-1) );

    offset = (ULONG)(res - p);
    CHECK( offset >= 16 && offset < 256, "?" );

    *(UINT64 *) &res[-8] = g_magic ^ (SIZE_T) res ^ 'strt';
    *(UINT64 *) &res[nBytes ] = g_magic ^ (SIZE_T) res ^ 'end.';
    *(UINT32 *) &res[-12] = (UINT32) nBytes;
    *(UINT32 *) &res[-16] = offset;

    InterlockedIncrement64( pOutstandingAllocs );
    InterlockedIncrement64( pAllocs );
    return res;
}

PVOID
SYMCRYPT_CALL
AllocWithChecksSc( SIZE_T nBytes )
{
    return AllocWithChecks( nBytes, &g_nOutstandingCheckedAllocs, &g_nAllocs );
}

PVOID
SYMCRYPT_CALL
AllocWithChecksMsBignum( SIZE_T nBytes )
{
    return AllocWithChecks( nBytes, &g_nOutstandingCheckedAllocsMsBignum, &g_nAllocsMsBignum );
}

VOID
FreeWithChecks( PVOID ptr, volatile INT64 * pOutstandingAllocs )
{
    PBYTE p;
    SIZE_T nBytes;

    p = (PBYTE) ptr;
    nBytes = *(UINT32 *) &p[-12];

    if (!g_perfTestsRunning)
    {
        for( SIZE_T i=0; i<nBytes; i++ )
        {
            CHECK( p[i] == 0 || p[i] == g_bAllocFill, "Free called with nonzero remenant data" );
        }
    }

    CHECK( *(ULONGLONG *)&p[-8] == (g_magic ^ (SIZE_T) p ^ 'strt'), "Left magic corrupted" );
    CHECK( *(ULONGLONG *)&p[nBytes] == (g_magic ^ (SIZE_T) p ^ 'end.'), "Right magic corrupted" );
    CHECK( InterlockedDecrement64( pOutstandingAllocs ) != -1, "?" );
    delete[] ( p - *(UINT32 *)&p[-16] );
}

VOID
FreeWithChecksSc( PVOID ptr )
{
    FreeWithChecks( ptr, &g_nOutstandingCheckedAllocs );
}

VOID
FreeWithChecksMsBignum( PVOID ptr )
{
    FreeWithChecks( ptr, &g_nOutstandingCheckedAllocsMsBignum );
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    return AllocWithChecksSc( nBytes );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree( PVOID ptr )
{
    FreeWithChecksSc( ptr );
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

#if INCLUDE_IMPL_MSBIGNUM


//
// Callback functions for MsBignum
//
__success(return != NULL)
__out_bcount_part_opt(cb, 0)
void* WINAPI mp_alloc_temp (
  __in               DWORDREGC cb,
  __in_opt           LPCSTR    pszSource_info,
  __inout_ecount(1)  bigctx_t  *pCtx)
{
    PBYTE p;

    UNREFERENCED_PARAMETER(pszSource_info);

    CHECK( SYMCRYPT_ASYM_ALIGN_VALUE >= sizeof(DWORDREG), "Too small ASYM_ALIGN_VALUE for bignum alloc" );

    p = (PBYTE) AllocWithChecksMsBignum( cb + SYMCRYPT_ASYM_ALIGN_VALUE );

    if (NULL == p)
    {
        SetMpErrno_clue(MP_ERRNO_NO_MEMORY, "mp_alloc_temp", pCtx);
    }

    *((DWORDREG *) p) = cb + SYMCRYPT_ASYM_ALIGN_VALUE;

    return (p + SYMCRYPT_ASYM_ALIGN_VALUE);
}

void WINAPI mp_free_temp(
  __in               void     *pVoid,
  __in_opt           LPCSTR    pszSource_info,
  __inout_ecount(1)  bigctx_t  *pCtx)
{
    PBYTE p = (PBYTE) pVoid;

    UNREFERENCED_PARAMETER(pszSource_info);

    UNREFERENCED_PARAMETER(pCtx);

    p -= SYMCRYPT_ASYM_ALIGN_VALUE;

    SymCryptWipe( p, *((DWORDREG *)p) );

    FreeWithChecksMsBignum(p);
}

void WINAPI SetMpErrno(__in mp_errno_tc code, PBIGCTX_ARG)
{
    if (NULL != pbigctx)
    {
        pbigctx->latest_errno = code;
    }
}

void WINAPI SetMpErrno_clue1(__in mp_errno_tc code, __in_opt const char *hint, PBIGCTX_ARG)
{
    UNREFERENCED_PARAMETER(hint);

    SetMpErrno(code, PBIGCTX_PASS);
}

#if defined(__cplusplus)
extern "C" {
#endif

BOOL_SUCCESS WINAPI random_bytes(
  __out_ecount(nbyte)  BYTE   *barray,
  __in       const     size_t  nbyte,
  PBIGCTX_ARG)
{
    NTSTATUS status;
    BOOL     fRet = FALSE;

    CHECK( nbyte < 0xffffffff, "Random buffer too large" );

    status = GENRANDOM( barray, (UINT32) nbyte );

    if( pbigctx == NULL )
    {
        fRet = FALSE;
        goto cleanup;
    }

    if (!NT_SUCCESS(status))
    {
        if (STATUS_NO_MEMORY == status)
        {
            pbigctx->latest_errno = MP_ERRNO_NO_MEMORY;
        }
        else
        {
            pbigctx->latest_errno = MP_ERRNO_INTERNAL_ERROR;
        }
        goto cleanup;
    }

    fRet = TRUE;

cleanup:
    return fRet;
}

#if defined(__cplusplus)
}
#endif

#endif // INCLUDE_IMPL_MSBIGNUM
