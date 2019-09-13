//
// SymCrypt_inline.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Inline implementations for functions defined in symcrypt.h
//

///////////////////////////////////////////////////////////////
// Some functions and macros that we need for inlining code
///////////////////////////////////////////////////////////////

//
// SymCryptFatal
//
// Call the Fatal routine passed to the library upon initialization
//
_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatal( UINT32 fatalCode );


//
// We use an ASSERT macro to catch problems in CHKed builds
// HARD_ASSERT checks also in FRE builds.
//

#define SYMCRYPT_HARD_ASSERT( _x ) \
    {\
        if( !(_x) ){ SymCryptFatal( 'asrt' ); }\
    }\
    _Analysis_assume_( _x )

#if defined( DBG )
#define SYMCRYPT_ASSERT( _x ) SYMCRYPT_HARD_ASSERT( _x )
#else
#define SYMCRYPT_ASSERT( _x ) \
    _Analysis_assume_( _x )
#endif


//////////////////////////////////////////////////////////
//
// Environment macros
//

#ifdef __cplusplus
#define SYMCRYPT_EXTERN_C extern "C" {
#define SYMCRYPT_EXTERN_C_END }
#else
#define SYMCRYPT_EXTERN_C
#define SYMCRYPT_EXTERN_C_END
#endif

//
// Callers of SymCrypt should NOT depend on the function names in these macros.
// The definition of these macros can change in future releases of the library.
//

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
typedef struct _SYMCRYPT_EXTENDED_SAVE_DATA      SYMCRYPT_EXTENDED_SAVE_DATA, *PSYMCRYPT_EXTENDED_SAVE_DATA;

#define SYMCRYPT_ENVIRONMENT_DEFS_SAVEYMM( envName ) \
    SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveYmmEnv##envName( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ); \
    SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveYmm( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) \
        { return SymCryptSaveYmmEnv##envName( pSaveArea ); } \
    \
    VOID SYMCRYPT_CALL SymCryptRestoreYmmEnv##envName( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ); \
    VOID SYMCRYPT_CALL SymCryptRestoreYmm( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) \
        { SymCryptRestoreYmmEnv##envName( pSaveArea ); } \

#define SYMCRYPT_ENVIRONMENT_DEFS_SAVEXMM( envName ) \
    SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveXmmEnv##envName( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ); \
    SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveXmm( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) \
        { return SymCryptSaveXmmEnv##envName( pSaveArea ); } \
    \
    VOID SYMCRYPT_CALL SymCryptRestoreXmmEnv##envName( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ); \
    VOID SYMCRYPT_CALL SymCryptRestoreXmm( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) \
        { SymCryptRestoreXmmEnv##envName( pSaveArea ); } \


#else

#define SYMCRYPT_ENVIRONMENT_DEFS_SAVEYMM( envName )
#define SYMCRYPT_ENVIRONMENT_DEFS_SAVEXMM( envName )

#endif

// Environment forwarding functions.
// CPUIDEX is only forwarded on CPUs that have it.
#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86 
#define SYMCRYPT_ENVIRONMENT_FORWARD_CPUIDEX( envName ) \
    VOID SYMCRYPT_CALL SymCryptCpuidExFuncEnv##envName( int cpuInfo[4], int function_id, int subfunction_id ); \
    VOID SYMCRYPT_CALL SymCryptCpuidExFunc( int cpuInfo[4], int function_id, int subfunction_id ) \
        { SymCryptCpuidExFuncEnv##envName( cpuInfo, function_id, subfunction_id ); }
#else
#define SYMCRYPT_ENVIRONMENT_FORWARD_CPUIDEX( envName )
#endif

#define SYMCRYPT_ENVIRONMENT_DEFS( envName ) \
SYMCRYPT_EXTERN_C \
    VOID SYMCRYPT_CALL SymCryptInitEnv##envName( UINT32 version ); \
    VOID SYMCRYPT_CALL SymCryptInit() \
        { SymCryptInitEnv##envName( SYMCRYPT_API_VERSION ); } \
    \
    _Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatalEnv##envName( UINT32 fatalCode ); \
    _Analysis_noreturn_ VOID SYMCRYPT_CALL SymCryptFatal( UINT32 fatalCode ) \
        { SymCryptFatalEnv##envName( fatalCode ); } \
    SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnv##envName(); \
    SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresent() \
        { return SymCryptCpuFeaturesNeverPresentEnv##envName(); } \
    \
    SYMCRYPT_ENVIRONMENT_DEFS_SAVEXMM( envName ) \
    SYMCRYPT_ENVIRONMENT_DEFS_SAVEYMM( envName ) \
    \
    VOID SYMCRYPT_CALL SymCryptTestInjectErrorEnv##envName( PBYTE pbBuf, SIZE_T cbBuf ); \
    VOID SYMCRYPT_CALL SymCryptInjectError( PBYTE pbBuf, SIZE_T cbBuf ) \
        { SymCryptTestInjectErrorEnv##envName( pbBuf, cbBuf ); } \
    SYMCRYPT_ENVIRONMENT_FORWARD_CPUIDEX( envName ) \
SYMCRYPT_EXTERN_C_END

//
// To avoid hard-do-diagnose mistakes, we skip defining environment macros in those cases where we
// know they cannot or should not be used.
//

#define SYMCRYPT_ENVIRONMENT_GENERIC                            SYMCRYPT_ENVIRONMENT_DEFS( Generic )

#if defined(EFI) | defined(PCAT) | defined(DIRECT)
    #define SYMCRYPT_ENVIRONMENT_WINDOWS_BOOTLIBRARY                SYMCRYPT_ENVIRONMENT_DEFS( WindowsBootlibrary )
#endif

//
// There are no defined symbols that we can use to detect that we are in debugger code
// But this is unlikely to be misued.
//
#define SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELDEBUGGER             SYMCRYPT_ENVIRONMENT_DEFS( WindowsKernelDebugger )



#define SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LEGACY          SYMCRYPT_ENVIRONMENT_GENERIC

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_WIN7_N_LATER    SYMCRYPT_ENVIRONMENT_DEFS( WindowsKernelmodeWin7nLater )
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
#define SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_WIN8_1_N_LATER  SYMCRYPT_ENVIRONMENT_DEFS( WindowsKernelmodeWin8_1nLater )
#endif

#define SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST          SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_WIN8_1_N_LATER



#define SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LEGACY            SYMCRYPT_ENVIRONMENT_GENERIC

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN7_N_LATER      SYMCRYPT_ENVIRONMENT_DEFS( WindowsUsermodeWin7nLater )
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
#define SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN8_1_N_LATER    SYMCRYPT_ENVIRONMENT_DEFS( WindowsUsermodeWin8_1nLater )
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
#define SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN10_SGX         SYMCRYPT_ENVIRONMENT_DEFS( Win10Sgx )
#endif

#define SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST            SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_WIN8_1_N_LATER




//////////////////////////////////////////////////////////
//
// SymCryptWipe & SymCryptWipeKnownSize
//


#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64

//
// If the known size is large we call the generic wipe function anyway.
// For small known sizes we perform the wipe inline.
// We put the limit at 8 native writes, which varies by platform.
//
//
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_ARM
#define SYMCRYPT_WIPE_FUNCTION_LIMIT (32)            // If this is increased beyond 64 the code below must be updated.
#elif SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_ARM64
#define SYMCRYPT_WIPE_FUNCTION_LIMIT (64)            // If this is increased beyond 64 the code below must be updated.
#else
#error ??
#endif

//
// The buffer analysis code doesn't understand our optimized in-line wiping code
// well enough to conclude it is safe.
//
#pragma prefast(push)
#pragma prefast( disable: 26001 )


FORCEINLINE
VOID
SYMCRYPT_CALL
#pragma prefast( suppress: 6101, "Logic why this properly initializes the pbData buffer is too complicated for prefast" )
SymCryptWipeKnownSize( _Out_writes_bytes_( cbData ) PVOID pbData, SIZE_T cbData )
{
    volatile BYTE * pb = (volatile BYTE *) pbData;

    if( cbData > SYMCRYPT_WIPE_FUNCTION_LIMIT )
    {
        SymCryptWipe( pbData, cbData );
    } else
    {
        //
        // We assume that pb is aligned, so we wipe from the end to the front to keep alignment.
        //
        if( cbData & 1 )
        {
            cbData--;
            SYMCRYPT_FORCE_WRITE8( (volatile BYTE *) &pb[cbData], 0 );
        }
        if( cbData & 2 )
        {
            cbData -= 2;
            SYMCRYPT_FORCE_WRITE16( (volatile UINT16 *) &pb[cbData], 0 );
        }
        if( cbData & 4 )
        {
            cbData -= 4;
            SYMCRYPT_FORCE_WRITE32( (volatile UINT32 *) &pb[cbData], 0 );
        }
        if( cbData & 8 )
        {
            cbData -= 8;
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData], 0 );
        }
        if( cbData & 16 )
        {
            cbData -= 16;
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData     ], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData +  8], 0 );
        }
        if( cbData & 32 )
        {
            cbData -= 32;
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData     ], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData +  8], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 16], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 24], 0 );
        }
#if SYMCRYPT_WIPE_FUNCTION_LIMIT >= 64
        if( cbData & 64 )
        {
            cbData -= 64;
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData     ], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData +  8], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 16], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 24], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 32], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 40], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 48], 0 );
            SYMCRYPT_FORCE_WRITE64( (volatile UINT64 *) &pb[cbData + 56], 0 );
        }
#endif
    }
}

#pragma prefast(pop)

#else // Platform switch for SymCryptWipeKnownSize

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptWipeKnownSize( _Out_writes_bytes_( cbData ) PVOID pbData, SIZE_T cbData )
{
    SymCryptWipe( pbData, cbData );
}

#endif  // Platform switch for SymCryptWipeKnownSize
