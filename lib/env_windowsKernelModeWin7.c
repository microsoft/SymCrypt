//
// env_windowsKernelModeWin7.c
// Platform-specific code for windows kernel mode, Windows 7 and later
//
// This requires saving the XMM registers on X86, but does not require
// a guarded region.
//
// Note: we no longer support the use of a guarded region. That is only needed
// on XP and Vista, and we simply don't use XMM 
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


//
// Define _NTSYSTEM_ to supress some __declspec(dllimport) definitions, which under some circumstance lead
// to an additional indirect function call, which adds some attack surface to kernel mode.
//
#define _NTSYSTEM_

#include <nt.h>
#include <ntrtl.h>
#include <ntosp.h>
#include <windef.h>


#include "symcrypt.h"
#include "sc_lib.h"

SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvWindowsKernelmodeWin7nLater()
{
    return 0;
}


VOID
SYMCRYPT_CALL
SymCryptInitEnvWindowsKernelmodeWin7nLater( UINT32 version )
{
    RTL_OSVERSIONINFOW  verInfo;
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64 
    ULONGLONG   FeatureMask;
#endif

    if( g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED )
    {
        return;
    }

    //
    // Check that we are on Win7 or later and not something earlier
    //
    verInfo.dwOSVersionInfoSize = sizeof( verInfo );
    if( !NT_SUCCESS( RtlGetVersion( &verInfo ) ) )
    {
        SymCryptFatal( 'nsrv' );
    }

    if( verInfo.dwMajorVersion < 6 || (verInfo.dwMajorVersion == 6 && verInfo.dwMinorVersion < 1 ) )
    {
        SymCryptFatal( 'nsrv' );
    }

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64 
    //
    // First we detect what the CPU has
    // 
    SymCryptDetectCpuFeaturesByCpuid( SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM );

    //
    // We also need to be sure that the OS supports the extended registers.
    //
    FeatureMask = RtlGetEnabledExtendedFeatures( (ULONGLONG) -1 );

    if( !(FeatureMask & XSTATE_MASK_AVX ) )
    {
        g_SymCryptCpuFeaturesNotPresent |= SYMCRYPT_CPU_FEATURE_AVX2;
    }

#elif SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64

    SymCryptDetectCpuFeaturesFromRegisters();

#endif    

    SymCryptInitEnvCommon( version );
}

_Analysis_noreturn_
VOID 
SYMCRYPT_CALL 
SymCryptFatalEnvWindowsKernelmodeWin7nLater( UINT32 fatalCode )
{
    SymCryptFatalIntercept( fatalCode );

#pragma prefast( disable:28159 )    // PreFast complains about use of BugCheckEx.    
    KeBugCheckEx( CRYPTO_LIBRARY_INTERNAL_ERROR, fatalCode, 0, 0, 0 );

    SymCryptFatalHang( fatalCode );
}


VOID 
SYMCRYPT_CALL 
SymCryptTestInjectErrorEnvWindowsKernelmodeWin7nLater( PBYTE pbBuf, SIZE_T cbBuf ) 
{
    //
    // This feature is only used during testing. In production it is always
    // an empty function that the compiler can optimize away.
    //
    UNREFERENCED_PARAMETER( pbBuf );
    UNREFERENCED_PARAMETER( cbBuf );
}

#if SYMCRYPT_CPU_X86 

C_ASSERT( sizeof( XSTATE_SAVE ) <= SYMCRYPT_XSTATE_SAVE_SIZE );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveXmmEnvWindowsKernelmodeWin7nLater( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    SYMCRYPT_ERROR result = SYMCRYPT_NO_ERROR;

    if( !NT_SUCCESS( KeSaveExtendedProcessorState( XSTATE_MASK_LEGACY_SSE, (PXSTATE_SAVE)&pSaveData->data[0] ) ) )
    {
        result = SYMCRYPT_EXTERNAL_FAILURE;
        goto cleanup;
    }

    SYMCRYPT_SET_MAGIC( pSaveData );
cleanup:
    return result;
}

VOID
SYMCRYPT_CALL
SymCryptRestoreXmmEnvWindowsKernelmodeWin7nLater( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    SYMCRYPT_CHECK_MAGIC( pSaveData );

    KeRestoreExtendedProcessorState( (PXSTATE_SAVE)&pSaveData->data[0]  );

    SYMCRYPT_WIPE_MAGIC( pSaveData );
}

#elif SYMCRYPT_CPU_AMD64

SYMCRYPT_ERROR 
SYMCRYPT_CALL 
SymCryptSaveXmmEnvWindowsKernelmodeWin7nLater( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) 
{
    //
    // In amd64 kernel mode there is no need to save XMM registers.
    // The compiler should inline this function and optimize it away.
    //

    UNREFERENCED_PARAMETER( pSaveArea );

    return SYMCRYPT_NO_ERROR;
}

VOID 
SYMCRYPT_CALL 
SymCryptRestoreXmmEnvWindowsKernelmodeWin7nLater( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea )
{
    //
    // In amd64 kernel mode there is no need to save XMM registers.
    // The compiler should inline this function and optimize it away.
    //

    UNREFERENCED_PARAMETER( pSaveArea );
}
#endif

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveYmmEnvWindowsKernelmodeWin7nLater( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    SYMCRYPT_ERROR result = SYMCRYPT_NO_ERROR;

    C_ASSERT( sizeof( pSaveData->data ) >= sizeof( XSTATE_SAVE ) );
    C_ASSERT( sizeof( pSaveData->data ) == sizeof( XSTATE_SAVE ) ); 

    //
    // A rare error check. If we are called without AVX2 enabled something is badly
    // wrong, and it could create a corrupted CPU state which is impossible to debug.
    //
    if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ) )
    {
        SymCryptFatal( ' mmy' );
    }

    //
    // Our init routine disabled AVX2 if the XSTATE_MASK_AVX isn't supported, so we don't have to check
    // for that anymore.
    //
    if( !NT_SUCCESS( KeSaveExtendedProcessorState( XSTATE_MASK_AVX, (PXSTATE_SAVE)&pSaveData->data[0] ) ) )
    {
        result = SYMCRYPT_EXTERNAL_FAILURE;
        goto cleanup;
    }

    SYMCRYPT_SET_MAGIC( pSaveData );

cleanup:
    return result;
}

VOID
SYMCRYPT_CALL
SymCryptRestoreYmmEnvWindowsKernelmodeWin7nLater( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{

    SYMCRYPT_CHECK_MAGIC( pSaveData );

    KeRestoreExtendedProcessorState( (PXSTATE_SAVE)&pSaveData->data[0] );

    SYMCRYPT_WIPE_MAGIC( pSaveData );
}

#endif

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

VOID
SYMCRYPT_CALL
SymCryptCpuidExFuncEnvWindowsKernelmodeWin7nLater( int cpuInfo[4], int function_id, int subfunction_id )
{
    __cpuidex( cpuInfo, function_id, subfunction_id );
}

#endif
