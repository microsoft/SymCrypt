//
// SymCrypt library pre-compiled header file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#ifdef __cplusplus
#error C++
#endif

#include <stdlib.h>
#include <string.h>

#include "symcrypt.h"
#include "sc_lib.h"

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
#include <wmmintrin.h>
#include <immintrin.h>

    #if SYMCRYPT_GNUC
        #include <xsaveintrin.h>
        #define _XCR_XFEATURE_ENABLED_MASK 0
    #endif
#endif