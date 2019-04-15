//
// SymCrypt library pre-compiled header file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#ifdef __cplusplus
#error C++
#endif
#include <stdlib.h>

#if defined(_MSC_VER)

    #include <windows.h>

    #define ATOMIC_OR32(_dest, _val)     InterlockedOr( (volatile LONG *)(_dest), (LONG)(_val) )

#elif defined(__APPLE_CC__)

    #include "precomp_iOS.h"

    #define ATOMIC_OR32(_dest, _val)     OSAtomicOr32Barrier( (uint32_t)(_val), (volatile uint32_t *)(_dest) )

#else

    #error Unknown compiler

#endif

#include "symcrypt.h"
#include "sc_lib.h"

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
#include <wmmintrin.h>
#include <immintrin.h>
#elif SYMCRYPT_CPU_ARM
#include <arm_neon.h>
#elif SYMCRYPT_CPU_ARM64
#include <arm64_neon.h>
#endif
