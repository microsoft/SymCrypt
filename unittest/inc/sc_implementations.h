//
// SymCrypt implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// The Marvin API names use 'seed' instead of 'key'.
// Map them so that our infrastructure works
//
typedef SYMCRYPT_MARVIN32_EXPANDED_SEED SYMCRYPT_MARVIN32_EXPANDED_KEY, *PSYMCRYPT_MARVIN32_EXPANDED_KEY;
#define SymCryptMarvin32ExpandKey SymCryptMarvin32ExpandSeed
#define SymCryptMarvin32KeyCopy SymCryptMarvin32SeedCopy


class ImpSc{
public:
    static char * name;
};

//
// Specialized Hash classes
//

template<>
class HashImpState<ImpSc, AlgMd2> {
public:
    SYMCRYPT_MD2_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpSc, AlgMd4> {
public:
    SYMCRYPT_MD4_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpSc, AlgMd5> {
public:
    SYMCRYPT_MD5_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpSc, AlgSha1> {
public:
    SYMCRYPT_SHA1_STATE sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpSc, AlgSha256> {
public:
    SYMCRYPT_SHA256_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpSc, AlgSha384> {
public:
    SYMCRYPT_SHA384_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpSc, AlgSha512> {
public:
    SYMCRYPT_SHA512_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class ParallelHashImpState<ImpSc, AlgParallelSha256> {
public:
                                                SYMCRYPT_SHA256_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};

template<>
class ParallelHashImpState<ImpSc, AlgParallelSha384> {
public:
                                                SYMCRYPT_SHA384_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};

template<>
class ParallelHashImpState<ImpSc, AlgParallelSha512> {
public:
                                                SYMCRYPT_SHA512_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};


template<>
class MacImpState<ImpSc, AlgHmacMd5> {
public:
    SYMCRYPT_HMAC_MD5_EXPANDED_KEY  key;
    SYMCRYPT_HMAC_MD5_STATE         state;
};

template<>
class MacImpState<ImpSc, AlgHmacSha1> {
public:
    SYMCRYPT_HMAC_SHA1_EXPANDED_KEY key;
    SYMCRYPT_HMAC_SHA1_STATE        state;
};

template<>
class MacImpState<ImpSc, AlgHmacSha256> {
public:
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA256_STATE          state;
};

template<>
class MacImpState<ImpSc, AlgHmacSha384> {
public:
    SYMCRYPT_HMAC_SHA384_EXPANDED_KEY    key;
    SYMCRYPT_HMAC_SHA384_STATE          state;
};

template<>
class MacImpState<ImpSc, AlgHmacSha512> {
public:
    SYMCRYPT_HMAC_SHA512_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA512_STATE          state;
};

template<>
class MacImpState<ImpSc, AlgAesCmac> {
public:
    SYMCRYPT_AES_CMAC_EXPANDED_KEY      key;
    SYMCRYPT_AES_CMAC_STATE             state;
};

template<>
class MacImpState<ImpSc, AlgMarvin32> {
public:
    SYMCRYPT_MARVIN32_EXPANDED_KEY      key;
    SYMCRYPT_MARVIN32_STATE             state;
};

template<>
class MacImpState<ImpSc, AlgPoly1305> {
public:
    SYMCRYPT_POLY1305_STATE state;
};

template<class Mode>
class BlockCipherImpState< ImpSc, AlgAes, Mode> {
public:
    SYMCRYPT_AES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpSc, AlgDes, Mode> {
public:
    SYMCRYPT_DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpSc, Alg2Des, Mode> {
public:
    SYMCRYPT_3DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpSc, Alg3Des, Mode> {
public:
    SYMCRYPT_3DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpSc, AlgDesx, Mode> {
public:
    SYMCRYPT_DESX_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpSc, AlgRc2, Mode> {
public:
    SYMCRYPT_RC2_EXPANDED_KEY   key;
};

template<>
class AuthEncImpState<ImpSc, AlgAes, ModeCcm> {
public:
    BOOLEAN                     inComputation;
    SYMCRYPT_AES_EXPANDED_KEY   key;
    SYMCRYPT_CCM_STATE          ccmState;
    SIZE_T                      totalCbData;
};

template<>
class AuthEncImpState<ImpSc, AlgAes, ModeGcm> {
public:
    SYMCRYPT_GCM_EXPANDED_KEY   key;
    SYMCRYPT_GCM_STATE          gcmState;
    BOOLEAN                     inComputation;
    SIZE_T                      totalCbData;        // not used, but allows common code.
};

template<>
class StreamCipherImpState<ImpSc, AlgRc4> {
public:
    SYMCRYPT_RC4_STATE  state;
};

template<>
class StreamCipherImpState<ImpSc, AlgChaCha20> {
public:
    BYTE    key[32];
    BYTE    nonce[12];
    UINT64  offset;
    SYMCRYPT_CHACHA20_STATE state;
};
    
template<>
class RngSp800_90ImpState<ImpSc, AlgAesCtrDrbg> {
public:
    SYMCRYPT_RNG_AES_STATE state;
};

template<>
class RngSp800_90ImpState<ImpSc, AlgAesCtrF142> {
public:
    SYMCRYPT_RNG_AES_FIPS140_2_STATE state;
};


template<class BaseAlg>
class KdfImpState<ImpSc, AlgPbkdf2, BaseAlg> {
public:
    SYMCRYPT_PBKDF2_EXPANDED_KEY    key;
};

template<class BaseAlg>
class KdfImpState<ImpSc, AlgSp800_108, BaseAlg> {
public:
    SYMCRYPT_SP800_108_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpSc, AlgTlsPrf1_1, BaseAlg> {
public:
    SYMCRYPT_TLSPRF1_1_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpSc, AlgTlsPrf1_2, BaseAlg> {
public:
    SYMCRYPT_TLSPRF1_2_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpSc, AlgHkdf, BaseAlg> {
public:
    SYMCRYPT_HKDF_EXPANDED_KEY     key;
};

template<>
class XtsImpState<ImpSc, AlgXtsAes> {
public:
    SYMCRYPT_XTS_AES_EXPANDED_KEY   key;
};
