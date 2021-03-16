//
// SymCrypt library pre-compiled header file for the Xcode compiler
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include <libkern/OSAtomic.h>   // atomic operations

// Ignore the incompatible pointer types void * to PSYMCRYPT_XXX
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#define FIELD_OFFSET(type,field)    ((UINT32)(uintptr_t)&(((type *)0)->field))
#define UNREFERENCED_PARAMETER(x)   (x)

#define FAST_FAIL_CRYPTO_LIBRARY    22
#define __fastfail(x)               (*((volatile int *)(0)) = (int) (x))
