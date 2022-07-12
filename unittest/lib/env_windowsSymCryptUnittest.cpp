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
    // Check OS reports the same AVX2 availability through GetEnabledXStateFeatures and _xgetbv
    //
    if (((GetEnabledXStateFeatures() & XSTATE_MASK_AVX) != 0) ^
        ((g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX2) == 0) )
    {
        FATAL3("GetEnabledXStateFeatures (%d) and g_SymCryptCpuFeaturesNotPresent (%d) set by _xgetbv disagree on whether AVX2 should be enabled!",
            GetEnabledXStateFeatures() & XSTATE_MASK_AVX, g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX2);
    }
    //
    // Check OS reports the same AVX512 availability through GetEnabledXStateFeatures and _xgetbv
    //
    if (((GetEnabledXStateFeatures() & XSTATE_MASK_AVX512) != 0) ^
        ((g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX512) == 0) )
    {
        FATAL3("GetEnabledXStateFeatures (%d) and g_SymCryptCpuFeaturesNotPresent (%d) set by _xgetbv disagree on whether AVX512 should be enabled!",
            GetEnabledXStateFeatures() & XSTATE_MASK_AVX512, g_SymCryptCpuFeaturesNotPresent & SYMCRYPT_CPU_FEATURE_AVX512);
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
