//
// cpuid_um.c   code for CPU feature detection based on CPUID
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This file contains the CPUID code that is only compiled for user-mode.
// The IsProcessorFeaturePresent API is only in UM, so linking any code out of
// a source file that contains a call to it doesn't work for KM code.
// By splitting it into a separate file, the code is ignored by KM callers because
// they never reference anything in this file.
//



#include "precomp.h"

#if SYMCRYPT_CPU_ARM64 && SYMCRYPT_MS_VC
#undef UNREFERENCED_PARAMETER
#include <processthreadsapi.h>

// From winnt.h
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30   

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent()
{
    if( IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) )
    {
        g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~(
        SYMCRYPT_CPU_FEATURE_NEON           |
        SYMCRYPT_CPU_FEATURE_NEON_AES       |
        SYMCRYPT_CPU_FEATURE_NEON_PMULL     |
        SYMCRYPT_CPU_FEATURE_NEON_SHA256    |
        SYMCRYPT_CPU_FEATURE_NEON_SHA1
        );
    } else {
        g_SymCryptCpuFeaturesNotPresent = (SYMCRYPT_CPU_FEATURES) ~SYMCRYPT_CPU_FEATURE_NEON;
    }
}
#endif
