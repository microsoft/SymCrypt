//
// sc_lib-testhooks.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// The declarations from sc_lib.h that our unit test code also needs without all the other things in the sc_lib.h file.
//

//
// Global flags
//

#define SYMCRYPT_FLAG_LIB_INITIALIZED   0x00000001

extern UINT32 g_SymCryptFlags;

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64

#define SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM  1      // enable checking of OSXSAVE bit & XGETBV logic

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesByCpuid( UINT32 flags );

#elif SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromRegisters();

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();
#endif

#if SYMCRYPT_CPU_ARM64

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromRegistersNoTry();

#endif

//==============================================================================================
//  Common environment functions
//==============================================================================================

VOID
SYMCRYPT_CALL
SymCryptInitEnvCommon( UINT32 version );

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatalHang( UINT32 fatalcode );

