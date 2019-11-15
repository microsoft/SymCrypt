//
// cng_implementations.h Header file for CNG implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

VOID
SetCngKeySizeFlag();

VOID
AddBCryptBuffer( BCryptBufferDesc * pBufferDesc, ULONG BufferType, PCVOID pData, SIZE_T cbData );


//
// Stub classes used as selector in templates. This class is never instantiated.
//
class ImpCng{
public:
    static char * name;
};


template< class Algorithm >
class HashImpState<ImpCng, Algorithm> {
public:
    static BCRYPT_ALG_HANDLE   hAlg;       // Handle to algorithm provider

    //
    // Data for the ongoing hash computation
    //
    BYTE    hashObjectBuffer[1024];
    BCRYPT_HASH_HANDLE  hHash;
};

template< class Algorithm >
class ParallelHashImpState<ImpCng, Algorithm> {
public:
    static BCRYPT_ALG_HANDLE hAlg;      // handle to alg provider

    BYTE                hashObjectBuffer[(5 + MAX_PARALLEL_HASH_STATES) * 1024];
    BCRYPT_HASH_HANDLE  hHash;
};

template< class Algorithm >
class MacImpState<ImpCng, Algorithm> {
public:
    static BCRYPT_ALG_HANDLE    hAlg;

    //
    // Data for the ongoing mac computation
    //
    BYTE                        hashObjectBuffer[1024];
    BCRYPT_HASH_HANDLE          hHash;
};

template< class Algorithm, class Mode >
class BlockCipherImpState<ImpCng, Algorithm, Mode> {
public:
    static  BCRYPT_ALG_HANDLE   hAlg;
    DWORD                       keyObjSize;

    PULONG              pMagic;                     // Pointer to magic value that should not be overwritten by the key object.
    BCRYPT_KEY_HANDLE   hKey;

    //
    // Data for the key
    //
    BYTE                keyObjectBuffer[768];   
};


template< class Algorithm, class Mode >
class AuthEncImpState<ImpCng, Algorithm, Mode> {
public:
    static BCRYPT_ALG_HANDLE    hAlg;
    BCRYPT_ALG_HANDLE           hAlgNoMode;

    SIZE_T                      totalCbData;        // Used for CCM but not GCM

    DWORD               keyObjSizeSmall;
    DWORD               keyObjSizeBig;

    BCRYPT_KEY_HANDLE   hKey;

    BOOL                inComputation;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BYTE                abMacContext[16];           // Mac context buffer used for chaining calls.

    PULONG              pMagic;                     // Pointer to magic value that should not be overwritten by the key object.
    //
    // Data for the key
    //
    BYTE                keyObjectBuffer[1 << 12];   // AES/GCM key can be 2.5 kB or so.
};


template< class Algorithm >
class StreamCipherImpState<ImpCng, Algorithm> {
public:
    static BCRYPT_ALG_HANDLE    hAlg;

    BYTE                keyObjectBuffer[768];
    BCRYPT_KEY_HANDLE   hKey;
};

template< class Algorithm >
class RngSp800_90ImpState<ImpCng, Algorithm> {
public:
};


template< class Algorithm, class BaseAlg >
class KdfImpState<ImpCng, Algorithm, BaseAlg > {
public:
    static BCRYPT_ALG_HANDLE hAlg;   // handle to the KDF algorithm
    BCRYPT_ALG_HANDLE hBaseAlg; // handle to the PRF algorithm
};

template<>
class XtsImpState<ImpCng, AlgXtsAes> {
public:
    BCRYPT_KEY_HANDLE   hKey;
    PULONG              pMagic;                     // Pointer to magic value that should not be overwritten by the key object.
    DWORD               keyObjSize;
    BYTE                keyObjectBuffer[2048];   
    //
    // No need for alg handle. XTS is only available when we have Pseudo-handles.
    //
};

template<>
class RsaSignImpState<ImpCng, AlgRsaSignPkcs1> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class RsaSignImpState<ImpCng, AlgRsaSignPss> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class RsaEncImpState<ImpCng, AlgRsaEncRaw> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class RsaEncImpState<ImpCng, AlgRsaEncPkcs1> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class RsaEncImpState<ImpCng, AlgRsaEncOaep> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class DhImpState<ImpCng, AlgDh> {
public:
    BCRYPT_KEY_HANDLE   hKey;
};

template<>
class DsaImpState<ImpCng, AlgDsa> {
public:
    BCRYPT_KEY_HANDLE   hKey;
    UINT32              cbP;
    UINT32              cbQ;
};
