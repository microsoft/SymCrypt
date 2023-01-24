//
// env_windowsSymCryptUnitTest
// Non-standard environment to support the unit test
//

#include "precomp.h"
#include "env_commonSymCryptUnittest.cpp"

#if SYMCRYPT_CPU_AMD64
BOOLEAN     TestSaveXmmEnabled = TRUE;  // For AMD64 we always test Xmm6-Xmm15 are preserved
#else
BOOLEAN     TestSaveXmmEnabled = FALSE;
#endif
BOOLEAN     TestSaveYmmEnabled = FALSE;

extern "C" {

VOID
SYMCRYPT_CALL
SymCryptInitEnvUnittest( UINT32 version )
{
    if( g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED )
    {
        return;
    }

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    SymCryptDetectCpuFeaturesByCpuid( SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM );

    //
    // Check that when SymCrypt thinks AVX2 available (using _xgetbv and __cpuidex)
    // Windows also reports AVX state available with GetEnabledXStateFeatures
    // Note: AVX state may be available without SymCrypt's AVX2 feature (i.e. IvyBridge supports AVX but not AVX2)
    //
    if (((GetEnabledXStateFeatures() & XSTATE_MASK_AVX) == 0) &&
        ((g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX2) == 0) )
    {
        FATAL3("GetEnabledXStateFeatures (%016lx) and g_SymCryptCpuFeaturesNotPresent (%08x) set by _xgetbv disagree on whether AVX2 should be enabled!",
            GetEnabledXStateFeatures(), g_SymCryptCpuFeaturesNotPresent);
    }
    //
    // Check that when SymCrypt thinks AVX512 available (using _xgetbv and __cpuidex)
    // Windows also reports AVX512 state available with GetEnabledXStateFeatures
    // Note: AVX512 state may be available without SymCrypt's AVX512 feature (i.e. Knights Landing does not support AVX512VL)
    //
    if (((GetEnabledXStateFeatures() & XSTATE_MASK_AVX512) == 0) &&
        ((g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX512) == 0) )
    {
        FATAL3("GetEnabledXStateFeatures (%016lx) and g_SymCryptCpuFeaturesNotPresent (%08x) set by _xgetbv disagree on whether AVX512 should be enabled!",
            GetEnabledXStateFeatures(), g_SymCryptCpuFeaturesNotPresent);
    }

    //
    // By default we don't fail XMM so that we get proper performance for GCM.
    // We allow the nofail to be disabled by command-line option.
    //
    g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;

#elif SYMCRYPT_CPU_ARM

    g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~SYMCRYPT_CPU_FEATURE_NEON;

#elif SYMCRYPT_CPU_ARM64

    SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();

#endif

    SymCryptInitEnvCommon( version );
}

}   // extern "C"
