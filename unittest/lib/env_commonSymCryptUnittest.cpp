//
// env_commonSymCryptUnitTest
// Common parts of non-standard environment to support the unit test
//

//
// Some test hooks to allow the unit test to have its own environment.
//
extern "C" {
#include "sc_lib-testhooks.h"
}

//
// We hack and create a NEW environment for our unit test.
//

BOOLEAN     TestSelftestsEnabled = FALSE;

ULONGLONG   TestFatalCount = 0;
ULONGLONG   TestErrorInjectionCount = 0;
ULONGLONG   TestErrorInjectionCalls = 0;
ULONG       TestErrorInjectionProb = 0;

BYTE TestErrorInjectionSeed[ SYMCRYPT_SHA1_RESULT_SIZE ] = {0};

extern "C" {
;


///////////////////////////////////////////////////////
// Start of the actual fake environment code

SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresentEnvUnittest()
{
    return 0;
}

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatalEnvUnittest( ULONG fatalCode )
{
    if( TestSelftestsEnabled )
    {
        TestFatalCount++;
        return;
    }

    FATAL5( "*\n\nSymCrypt fatal error '%c%c%c%c' ", (fatalCode >> 24) & 0xff, (fatalCode >> 16) & 0xff, (fatalCode >> 8) & 0xff, fatalCode & 0xff );
}

VOID SYMCRYPT_CALL SymCryptTestInjectErrorEnvUnittest( PBYTE pbBuf, SIZE_T cbBuf )
{
    if( TestSelftestsEnabled )
    {
        ++TestErrorInjectionCalls;
        if( TestErrorInjectionSeed[10]% TestErrorInjectionProb == 1 )
        {
            SIZE_T bitNo = (*(ULONGLONG *)TestErrorInjectionSeed) % (8*cbBuf);
            pbBuf[ bitNo/8 ] ^= ( 1 << (bitNo % 8) );

            ++TestErrorInjectionCount;
        }
        SymCryptSha1( TestErrorInjectionSeed, sizeof( TestErrorInjectionSeed ), TestErrorInjectionSeed );
    }
}



PVOID malloc_align32( SIZE_T size )
{
    PVOID pBase = malloc( size + 8 + 31 );
    if( pBase == NULL )
    {
        return pBase;
    }
    PBYTE pAligned = (PBYTE)((((ULONG_PTR) pBase) + 8 + 31) & ~31);
    *(PVOID *) (pAligned - 8) = pBase;
    return pAligned;
}

VOID free_align32( PVOID p )
{
    CHECK( ((ULONG_PTR)p & 31) == 0, "?" );
    free( *(PVOID *) ((PBYTE)p - 8) );
}

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

char g_saveInProgressTypes[16] = { 0 };
int g_savesInProgress = 0;
PVOID g_savePtrs[sizeof(g_saveInProgressTypes)] = { 0 };
extern "C" {
ULONG g_nSaves = 0;
}

#endif

#if SYMCRYPT_CPU_X86
//
// We have XMM save/restore logic even in Windows user mode so that we can test the library in user mode
// This makes it much easier to do thorough testing.
// We can disable these tests through a flag to get reasonable performance measurements on the same code.
//

#pragma warning(push)
#pragma warning(disable:4359)
typedef SYMCRYPT_ALIGN_STRUCT _SYMCRYPT_ENV_XMM_SAVE_DATA_REGS {
    //
    // The alignment on x86 is only 4, so we can't align the __m128i fields properly.
    // We add some padding and let the assembler code adjust the alignmetn of the actual data.
    // This is all transperant to the C code
    //
    __m128i xmm[8];         // 8 for the XMM registers.
    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_ENV_XMM_SAVE_DATA_REGS, *PSYMCRYPT_ENV_XMM_SAVE_DATA_REGS;

#pragma warning(pop)

typedef struct _SYMCRYPT_ENV_XMM_SAVE_DATA {
    PSYMCRYPT_ENV_XMM_SAVE_DATA_REGS    pRegs;
    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_ENV_XMM_SAVE_DATA, *PSYMCRYPT_ENV_XMM_SAVE_DATA;

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveXmmEnvUnittest( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    PSYMCRYPT_ENV_XMM_SAVE_DATA         p = (PSYMCRYPT_ENV_XMM_SAVE_DATA) pSaveData;
    PSYMCRYPT_ENV_XMM_SAVE_DATA_REGS    pRegs;
    __m128i regs[8];

    if( TestSaveXmmEnabled  )
    {
        //
        // To test the fallback from the failure of the savexmm function we introduce occasional errors
        //
        if( !SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL ) && __rdtsc() % 101 == 0 )
        {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }

        //
        // Malloc & Free can modify the XMM registers, so we save them first in a temp
        // so that we call them inside the save/restore area.
        //
        SymCryptEnvUmSaveXmmRegistersAsm( &regs[0] );

        pRegs = (PSYMCRYPT_ENV_XMM_SAVE_DATA_REGS) malloc_align32( sizeof( *pRegs ) );
        if( pRegs == NULL )
        {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }

        memcpy( &pRegs->xmm[0], &regs[0], sizeof( regs ) );
        SYMCRYPT_SET_MAGIC( pRegs );
        p->pRegs = pRegs;
        SYMCRYPT_SET_MAGIC( p );

        CHECK(g_savesInProgress < sizeof(g_saveInProgressTypes), "Too many nested saves!");
        g_saveInProgressTypes[g_savesInProgress] = 'X';
        g_savePtrs[g_savesInProgress] = pSaveData;
        g_savesInProgress++;
    }

    return SYMCRYPT_NO_ERROR;
}


VOID
SYMCRYPT_CALL
SymCryptRestoreXmmEnvUnittest( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    PSYMCRYPT_ENV_XMM_SAVE_DATA         p = (PSYMCRYPT_ENV_XMM_SAVE_DATA) pSaveData;
    PSYMCRYPT_ENV_XMM_SAVE_DATA_REGS    pRegs;

    __m128i regs[8];

    if( TestSaveXmmEnabled )
    {

        SYMCRYPT_CHECK_MAGIC( p );
        pRegs = p->pRegs;
        SYMCRYPT_CHECK_MAGIC( pRegs );

        CHECK(g_savesInProgress > 0, "No saves in progress!");
        g_savesInProgress--;
        CHECK(g_saveInProgressTypes[g_savesInProgress] == 'X', "XMM not saved");
        CHECK(g_savePtrs[g_savesInProgress] == pSaveData, "?" );

        memcpy( &regs[0], &pRegs->xmm[0], sizeof( regs ) );
        SYMCRYPT_WIPE_MAGIC( pRegs );
        free_align32( pRegs );
        p->pRegs = NULL;
        SYMCRYPT_WIPE_MAGIC( p );

        SymCryptEnvUmRestoreXmmRegistersAsm( &regs[0] );
    }
}

#elif SYMCRYPT_CPU_AMD64

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveXmmEnvUnittest( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );

    return SYMCRYPT_NO_ERROR;
}


VOID
SYMCRYPT_CALL
SymCryptRestoreXmmEnvUnittest( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    UNREFERENCED_PARAMETER( pSaveData );
}


#endif

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

//
// We have YMM save/restore logic even in Windows user mode so that we can test the library in user mode
// This makes it much easier to do thorough testing.
// We can disable these tests through a flag to get reasonable performance measurements on the same code.
//

typedef SYMCRYPT_ALIGN_AT(32) struct _SYMCRYPT_ENV_YMM_SAVE_DATA_REGS {
    __m256i ymm[16];         // 16 for the XMM registers
    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_ENV_YMM_SAVE_DATA_REGS, *PSYMCRYPT_ENV_YMM_SAVE_DATA_REGS;

typedef struct _SYMCRYPT_ENV_YMM_SAVE_DATA {
    PSYMCRYPT_ENV_YMM_SAVE_DATA_REGS    pRegs;
    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_ENV_YMM_SAVE_DATA, *PSYMCRYPT_ENV_YMM_SAVE_DATA;

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveYmmEnvUnittest( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    PSYMCRYPT_ENV_YMM_SAVE_DATA         p = (PSYMCRYPT_ENV_YMM_SAVE_DATA) pSaveData;
    PSYMCRYPT_ENV_YMM_SAVE_DATA_REGS    pRegs;
    __m256i regs[16];

    CHECK( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ), "?" );

    if( TestSaveYmmEnabled )
    {

        //
        // To test the fallback from the failure of the saveYmm function we introduce occasional errors
        //
        if( __rdtsc() % 101 == 0 )
        {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }

        //
        // Alloc can modify the regs, so save them first so that the modification happens
        // inside the save block
        //
        SymCryptEnvUmSaveYmmRegistersAsm( regs );

        pRegs = (PSYMCRYPT_ENV_YMM_SAVE_DATA_REGS) malloc_align32( sizeof( *pRegs ) );
        if( pRegs == NULL )
        {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }

        memcpy( pRegs->ymm, regs, sizeof( regs ) );
        SYMCRYPT_SET_MAGIC( pRegs );
        SYMCRYPT_CHECK_MAGIC( pRegs );

        p->pRegs = pRegs;
        SYMCRYPT_SET_MAGIC( p );

        CHECK(g_savesInProgress < sizeof(g_saveInProgressTypes), "Too many nested saves!");
        g_saveInProgressTypes[g_savesInProgress] = 'Y';
        g_savePtrs[g_savesInProgress] = pSaveData;
        g_savesInProgress++;
    }

    return SYMCRYPT_NO_ERROR;
}


VOID
SYMCRYPT_CALL
SymCryptRestoreYmmEnvUnittest( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData )
{
    PSYMCRYPT_ENV_YMM_SAVE_DATA         p = (PSYMCRYPT_ENV_YMM_SAVE_DATA) pSaveData;
    PSYMCRYPT_ENV_YMM_SAVE_DATA_REGS    pRegs;
    __m256i regs[16];

    CHECK( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 ), "?" );

    if( TestSaveYmmEnabled )
    {
        SYMCRYPT_CHECK_MAGIC( p );
        pRegs = p->pRegs;
        SYMCRYPT_CHECK_MAGIC( pRegs );

        CHECK(g_savesInProgress > 0, "No saves in progress!");
        g_savesInProgress--;
        CHECK(g_saveInProgressTypes[g_savesInProgress] == 'Y', "YMM not saved");
        CHECK(g_savePtrs[g_savesInProgress] == pSaveData, "?" );

        memcpy( regs, pRegs->ymm, sizeof( regs ) );
        SYMCRYPT_WIPE_MAGIC( pRegs );
        free_align32( pRegs );
        p->pRegs = NULL;
        SYMCRYPT_WIPE_MAGIC( p );

        SymCryptEnvUmRestoreYmmRegistersAsm( regs );
    }
}

#endif


VOID
SYMCRYPT_CALL
SymCryptEnvUnittestDetectCpuFeatures( ULONG flags )
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    SymCryptDetectCpuFeaturesByCpuid( flags );
#elif SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64
    UNREFERENCED_PARAMETER( flags );
    g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~SYMCRYPT_CPU_FEATURE_NEON;
#else
    UNREFERENCED_PARAMETER( flags );
    g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) (-1);
#endif
}

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86

VOID
SYMCRYPT_CALL
SymCryptCpuidExFuncEnvUnittest( int cpuInfo[4], int function_id, int subfunction_id )
{
    __cpuidex( cpuInfo, function_id, subfunction_id );
}

#endif
}   // extern "C"



