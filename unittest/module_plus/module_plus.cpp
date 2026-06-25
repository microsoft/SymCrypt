//
// module_plus.cpp - main source for symcrypt_plus_testmodule.{dll,so}.
// See README.md in this directory for the design rationale.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <pthread.h>
#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

#include "symcrypt.h"

// ========================================================================
// SymCryptFatal
//
// Required by SYMCRYPT_ASSERT and SYMCRYPT_CHECK_MAGIC in debug/checked
// builds.  Not exported from the base testmodule (it's an internal
// env-specific function), so we provide our own minimal implementation.
// ========================================================================

extern "C"
_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatal( UINT32 fatalCode )
{
    fprintf( stderr,
        "\n*** SymCryptFatal (plus module): code 0x%08X ***\n",
        fatalCode );
    fflush( stderr );
    _Exit( -1 );
}


static BYTE   g_bAllocFill = 0;
static UINT64 g_magic      = 0;

#define CHECK_PLUS( cond, msg ) \
    do { \
        if( !(cond) ) { \
            fprintf( stderr, "CHECK failed (%s:%d): %s\n", __FILE__, __LINE__, msg ); \
            SymCryptFatal( 0xdeadbeef ); \
        } \
    } while(0)


static void
AllocWithChecksInit()
{
    while( g_bAllocFill == 0 )
    {
        SymCryptRandom( &g_bAllocFill, sizeof(g_bAllocFill) );
    }
    SymCryptRandom( (PBYTE) &g_magic, sizeof(g_magic) );
}

extern "C"
PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    PBYTE p;
    PBYTE res;
    UINT32 offset;
    SIZE_T nAllocated;
    SIZE_T nAdditionalBytes;

    CHECK_PLUS( g_bAllocFill != 0, "AllocFill not initialized" );

    nAdditionalBytes = SYMCRYPT_ASYM_ALIGN_VALUE + 16 + 8;
    CHECK_PLUS( nBytes <= UINT32_MAX - nAdditionalBytes, "Alloc size overflow" );

    nAllocated = nBytes + nAdditionalBytes;
    p = new BYTE[ nAllocated ];

    memset( p, g_bAllocFill, nAllocated );

    res = (PBYTE)(((uintptr_t)p + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) &
                  ~(uintptr_t)(SYMCRYPT_ASYM_ALIGN_VALUE - 1));

    offset = (UINT32)(res - p);
    CHECK_PLUS( offset >= 16 && offset < 256, "Alignment offset out of range" );

    *(UINT64 *)&res[-8]       = g_magic ^ (SIZE_T)res ^ 'strt';
    *(UINT64 *)&res[nBytes]   = g_magic ^ (SIZE_T)res ^ 'end.';
    *(UINT32 *)&res[-12]      = (UINT32)nBytes;
    *(UINT32 *)&res[-16]      = offset;

    return res;
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptCallbackFree( PVOID ptr )
{
    PBYTE p = (PBYTE)ptr;
    SIZE_T nBytes = *(UINT32 *)&p[-12];

    CHECK_PLUS( *(UINT64 *)&p[-8]      == (g_magic ^ (SIZE_T)p ^ 'strt'),
                "Left magic corrupted (plus module)" );
    CHECK_PLUS( *(UINT64 *)&p[nBytes]  == (g_magic ^ (SIZE_T)p ^ 'end.'),
                "Right magic corrupted (plus module)" );

    delete[]( p - *(UINT32 *)&p[-16] );
}

extern "C"
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    SymCryptRandom( pbBuffer, cbBuffer );
    return SYMCRYPT_NO_ERROR;
}

// ========================================================================
// Mutex callbacks - required by symcrypt.h function declarations.
// ========================================================================

#if defined(_WIN32)

extern "C" PVOID SYMCRYPT_CALL SymCryptCallbackAllocateMutexFastInproc()
{
    PCRITICAL_SECTION pCs = new CRITICAL_SECTION;
    InitializeCriticalSection( pCs );
    return pCs;
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    DeleteCriticalSection( (PCRITICAL_SECTION)pMutex );
    delete (PCRITICAL_SECTION)pMutex;
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    EnterCriticalSection( (PCRITICAL_SECTION)pMutex );
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    LeaveCriticalSection( (PCRITICAL_SECTION)pMutex );
}

#else  // POSIX

extern "C" PVOID SYMCRYPT_CALL SymCryptCallbackAllocateMutexFastInproc()
{
    pthread_mutex_t *pMutex = new pthread_mutex_t;
    pthread_mutex_init( pMutex, NULL );
    return pMutex;
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_destroy( (pthread_mutex_t *) pMutex );
    delete (pthread_mutex_t *) pMutex;
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_lock( (pthread_mutex_t *) pMutex );
}

extern "C" VOID SYMCRYPT_CALL SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    pthread_mutex_unlock( (pthread_mutex_t *) pMutex );
}

#endif

// ========================================================================
// SymCryptModuleInit
//
// Called by the test exe after dlopening this module. Sequence:
//   1. Locate the base SymCrypt module (already loaded as an import / DT_NEEDED dep)
//      and call its SymCryptModuleInit explicitly (we can't call it by name
//      because this module re-exports SymCryptModuleInit, so a direct call
//      would recurse).
//   2. Initialize our own alloc-check state.
// ========================================================================

typedef VOID (SYMCRYPT_CALL *PFN_SYMCRYPT_MODULE_INIT)( UINT32 api, UINT32 minor );

#if !defined(_WIN32)
#  define _PLUS_STRINGIFY(x) #x
#  define PLUS_STRINGIFY(x)  _PLUS_STRINGIFY(x)
#  define PLUS_LIBSYMCRYPT_SONAME \
        "libsymcrypt.so." PLUS_STRINGIFY(SYMCRYPT_CODE_VERSION_API)
#endif

extern "C"
VOID
SYMCRYPT_CALL
SymCryptModuleInit( UINT32 api, UINT32 minor )
{
#if defined(_WIN32)
    HMODULE hBase = GetModuleHandleA( "symcrypttestmodule" );
    CHECK_PLUS( hBase != NULL,
        "Could not find symcrypttestmodule.dll "
        "(must be loaded as import dependency)" );

    PFN_SYMCRYPT_MODULE_INIT pfnBaseInit =
        (PFN_SYMCRYPT_MODULE_INIT)GetProcAddress( hBase, "SymCryptModuleInit" );
    CHECK_PLUS( pfnBaseInit != NULL,
        "Could not find SymCryptModuleInit in symcrypttestmodule" );

    pfnBaseInit( api, minor );
#else
    // libsymcrypt.so.<API> is already loaded as our DT_NEEDED dependency.
    // RTLD_NOLOAD returns a handle to the existing image without re-loading;
    // it does still bump the refcount, so we balance with dlclose.
    void *hBase = dlopen( PLUS_LIBSYMCRYPT_SONAME, RTLD_NOW | RTLD_NOLOAD );
    CHECK_PLUS( hBase != NULL,
        "Could not locate " PLUS_LIBSYMCRYPT_SONAME
        " (must be loaded as DT_NEEDED dependency)" );

    PFN_SYMCRYPT_MODULE_INIT pfnBaseInit =
        (PFN_SYMCRYPT_MODULE_INIT) dlsym( hBase, "SymCryptModuleInit" );
    CHECK_PLUS( pfnBaseInit != NULL,
        "Could not find SymCryptModuleInit in " PLUS_LIBSYMCRYPT_SONAME );

    pfnBaseInit( api, minor );

    dlclose( hBase );
#endif

    AllocWithChecksInit();
}
