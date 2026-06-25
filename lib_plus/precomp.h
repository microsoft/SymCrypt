//
// precomp.h
//
// Pre-compiled header for symcrypt_plus library.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#ifdef __cplusplus
#error C++
#endif

#include <stdlib.h>
#include <string.h>

#include "symcrypt.h"
#include "symcrypt_atomics.h"
#include "symcrypt_ec_encoding.h"
#include "symcrypt_hpke.h"

//
// Portability definitions that sc_lib.h used to provide.
// On MSVC, TRUE/FALSE normally come from Windows SDK headers (windef.h),
// but symcrypt.h doesn't pull in those headers.
//

#if !defined(TRUE)
#define TRUE  (1)
#endif

#if !defined(FALSE)
#define FALSE (0)
#endif

#if !defined(UNREFERENCED_PARAMETER)
#define UNREFERENCED_PARAMETER(x)   ((void)x)
#endif
