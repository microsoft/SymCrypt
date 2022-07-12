//
// env_linuxSymCryptUnitTest
// Non-standard environment to support the unit test
//

#include "precomp.h"
#include "env_commonSymCryptUnittest.cpp"

BOOLEAN     TestSaveXmmEnabled = FALSE;
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
