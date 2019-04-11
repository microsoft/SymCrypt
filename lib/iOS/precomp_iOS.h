//
// SymCrypt library pre-compiled header file for the Xcode compiler
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//


#include <string.h>             // memcpy, memcmp
#include <libkern/OSAtomic.h>   // atomic operations

// Ingnore the incompatible pointer types void * to PSYMCRYPT_XXX
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#define FIELD_OFFSET(type,field)    ((UINT32)(uintptr_t)&(((type *)0)->field))
#define UNREFERENCED_PARAMETER(x)   (x)

#define FAST_FAIL_CRYPTO_LIBRARY    22
#define __fastfail(x)               (*((volatile int *)(0)) = (int) (x)) 

#if !defined min
#define min(a,b) \
({ __typeof__ (a) __a = (a); \
__typeof__ (b) __b = (b); \
__a < __b ? __a : __b; })
#endif

#if !defined max
#define max(a,b) \
({ __typeof__ (a) __a = (a); \
__typeof__ (b) __b = (b); \
__a > __b ? __a : __b; })
#endif
