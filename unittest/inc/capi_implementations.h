//
// capi_implementations.h Header file for CAPI implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#pragma once

#include <wincrypt.h>
extern HCRYPTPROV g_capiProvider;

//
// Stub classes used as selector in templates. This class is never instantiated.
//
class ImpCapi{
public:
    static char * name;
};

//
// Storage for the hash implementation
//
template< class Algorithm >
class HashImpState<ImpCapi, Algorithm> {
public:
    HCRYPTHASH  hHash;
};

template< class Algorithm >
class MacImpState<ImpCapi, Algorithm> {
public:
    HCRYPTKEY   hKey;
    HCRYPTHASH  hHash;
};

#define CAPI_CALG_ARRAY_SIZE    256
#define CAPI_MAX_KEY_SIZE       256

template< class Algorithm, class Mode>
class BlockCipherImpState<ImpCapi, Algorithm, Mode> {
public:
    static ULONG        calg[CAPI_CALG_ARRAY_SIZE];         // One calg for each key size
    HCRYPTKEY           hKey;

};

template<class Algorithm>
class StreamCipherImpState<ImpCapi, Algorithm> {
public:
    HCRYPTKEY   hKey;
};

