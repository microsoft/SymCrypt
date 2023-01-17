//
// SymCrypt implementation classes pattern
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Specialized Hash classes
//

template<>
class HashImpState<ImpXxx, AlgMd2> {
public:
    SYMCRYPT_MD2_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpXxx, AlgMd4> {
public:
    SYMCRYPT_MD4_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpXxx, AlgMd5> {
public:
    SYMCRYPT_MD5_STATE  sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha1> {
public:
    SYMCRYPT_SHA1_STATE sc;
    SYMCRYPT_HASH_STATE scHash;
    BOOLEAN             isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha256> {
public:
    SYMCRYPT_SHA256_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha384> {
public:
    SYMCRYPT_SHA384_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha512> {
public:
    SYMCRYPT_SHA512_STATE   sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha3_256> {
public:
    SYMCRYPT_SHA3_256_STATE sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha3_384> {
public:
    SYMCRYPT_SHA3_384_STATE sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class HashImpState<ImpXxx, AlgSha3_512> {
public:
    SYMCRYPT_SHA3_512_STATE sc;
    SYMCRYPT_HASH_STATE     scHash;
    BOOLEAN                 isReset;
};

template<>
class XofImpState<ImpXxx, AlgShake128> {
public:
    SYMCRYPT_SHAKE128_STATE sc;
    BOOLEAN                 isReset;
};

template<>
class XofImpState<ImpXxx, AlgShake256> {
public:
    SYMCRYPT_SHAKE256_STATE sc;
    BOOLEAN                 isReset;
};

template<>
class CustomizableXofImpState<ImpXxx, AlgCShake128> {
public:
    SYMCRYPT_CSHAKE128_STATE    sc;
};

template<>
class CustomizableXofImpState<ImpXxx, AlgCShake256> {
public:
    SYMCRYPT_CSHAKE256_STATE    sc;
};

template<>
class KmacImpState<ImpXxx, AlgKmac128> {
public:
    SYMCRYPT_KMAC128_EXPANDED_KEY   key;
    SYMCRYPT_KMAC128_STATE          state;
};

template<>
class KmacImpState<ImpXxx, AlgKmac256> {
public:
    SYMCRYPT_KMAC256_EXPANDED_KEY   key;
    SYMCRYPT_KMAC256_STATE          state;
};

template<>
class ParallelHashImpState<ImpXxx, AlgParallelSha256> {
public:
                                                SYMCRYPT_SHA256_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};

template<>
class ParallelHashImpState<ImpXxx, AlgParallelSha384> {
public:
                                                SYMCRYPT_SHA384_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};

template<>
class ParallelHashImpState<ImpXxx, AlgParallelSha512> {
public:
                                                SYMCRYPT_SHA512_STATE       sc[MAX_PARALLEL_HASH_STATES];
    _Field_range_(0, MAX_PARALLEL_HASH_STATES)  SIZE_T                      nHashes;
};


template<>
class MacImpState<ImpXxx, AlgHmacMd5> {
public:
    SYMCRYPT_HMAC_MD5_EXPANDED_KEY  key;
    SYMCRYPT_HMAC_MD5_STATE         state;
};

template<>
class MacImpState<ImpXxx, AlgHmacSha1> {
public:
    SYMCRYPT_HMAC_SHA1_EXPANDED_KEY key;
    SYMCRYPT_HMAC_SHA1_STATE        state;
};

template<>
class MacImpState<ImpXxx, AlgHmacSha256> {
public:
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA256_STATE          state;
};

template<>
class MacImpState<ImpXxx, AlgHmacSha384> {
public:
    SYMCRYPT_HMAC_SHA384_EXPANDED_KEY    key;
    SYMCRYPT_HMAC_SHA384_STATE          state;
};

template<>
class MacImpState<ImpXxx, AlgHmacSha512> {
public:
    SYMCRYPT_HMAC_SHA512_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA512_STATE          state;
};

template<>
class MacImpState<ImpXxx, AlgAesCmac> {
public:
    SYMCRYPT_AES_CMAC_EXPANDED_KEY      key;
    SYMCRYPT_AES_CMAC_STATE             state;
};

template<>
class MacImpState<ImpXxx, AlgMarvin32> {
public:
    SYMCRYPT_MARVIN32_EXPANDED_KEY      key;
    SYMCRYPT_MARVIN32_STATE             state;
};

template<>
class MacImpState<ImpXxx, AlgPoly1305> {
public:
    SYMCRYPT_POLY1305_STATE state;
};

template<class Mode>
class BlockCipherImpState< ImpXxx, AlgAes, Mode> {
public:
    SYMCRYPT_AES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpXxx, AlgDes, Mode> {
public:
    SYMCRYPT_DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpXxx, Alg2Des, Mode> {
public:
    SYMCRYPT_3DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpXxx, Alg3Des, Mode> {
public:
    SYMCRYPT_3DES_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpXxx, AlgDesx, Mode> {
public:
    SYMCRYPT_DESX_EXPANDED_KEY   key;
};

template<class Mode>
class BlockCipherImpState<ImpXxx, AlgRc2, Mode> {
public:
    SYMCRYPT_RC2_EXPANDED_KEY   key;
};

template<>
class AuthEncImpState<ImpXxx, AlgAes, ModeCcm> {
public:
    BOOLEAN                     inComputation;
    SYMCRYPT_AES_EXPANDED_KEY   key;
    SYMCRYPT_CCM_STATE          ccmState;
    SIZE_T                      totalCbData;
};

template<>
class AuthEncImpState<ImpXxx, AlgAes, ModeGcm> {
public:
    SYMCRYPT_GCM_EXPANDED_KEY   key;
    SYMCRYPT_GCM_STATE          gcmState;
    BOOLEAN                     inComputation;
    SIZE_T                      totalCbData;        // not used, but allows common code.
};

template<>
class AuthEncImpState<ImpXxx, AlgChaCha20Poly1305, ModeNone> {
public:
    BYTE    key[32];
};

template<>
class StreamCipherImpState<ImpXxx, AlgRc4> {
public:
    SYMCRYPT_RC4_STATE  state;
};

template<>
class StreamCipherImpState<ImpXxx, AlgChaCha20> {
public:
    BYTE    key[32];
    BYTE    nonce[12];
    UINT64  offset;
    SYMCRYPT_CHACHA20_STATE state;
};

template<>
class RngSp800_90ImpState<ImpXxx, AlgAesCtrDrbg> {
public:
    SYMCRYPT_RNG_AES_STATE state;
};

template<>
class RngSp800_90ImpState<ImpXxx, AlgAesCtrF142> {
public:
    SYMCRYPT_RNG_AES_FIPS140_2_STATE state;
};

template<>
class RngSp800_90ImpState<ImpXxx, AlgDynamicRandom> {
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgPbkdf2, BaseAlg> {
public:
    SYMCRYPT_PBKDF2_EXPANDED_KEY    key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgSp800_108, BaseAlg> {
public:
    SYMCRYPT_SP800_108_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgTlsPrf1_1, BaseAlg> {
public:
    SYMCRYPT_TLSPRF1_1_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgTlsPrf1_2, BaseAlg> {
public:
    SYMCRYPT_TLSPRF1_2_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgHkdf, BaseAlg> {
public:
    SYMCRYPT_HKDF_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgSshKdf, BaseAlg> {
public:
    SYMCRYPT_SSHKDF_EXPANDED_KEY     key;
};

template<class BaseAlg>
class KdfImpState<ImpXxx, AlgSrtpKdf, BaseAlg> {
public:
    SYMCRYPT_SRTPKDF_EXPANDED_KEY     key;
};

template<>
class XtsImpState<ImpXxx, AlgXtsAes> {
public:
    SYMCRYPT_XTS_AES_EXPANDED_KEY   key;
};

template<>
class RsaSignImpState<ImpXxx, AlgRsaSignPkcs1> {
public:
    PSYMCRYPT_RSAKEY    pKey;
};

template<>
class RsaSignImpState<ImpXxx, AlgRsaSignPss> {
public:
    PSYMCRYPT_RSAKEY    pKey;
};

template<>
class RsaEncImpState<ImpXxx, AlgRsaEncRaw> {
public:
    PSYMCRYPT_RSAKEY    pKey;
};

template<>
class RsaEncImpState<ImpXxx, AlgRsaEncPkcs1> {
public:
    PSYMCRYPT_RSAKEY    pKey;
};

template<>
class RsaEncImpState<ImpXxx, AlgRsaEncOaep> {
public:
    PSYMCRYPT_RSAKEY    pKey;
};

template<>
class DhImpState<ImpXxx, AlgDh> {
public:
    PSYMCRYPT_DLGROUP   pGroup;
    PSYMCRYPT_DLKEY     pKey;
};

template<>
class DsaImpState<ImpXxx, AlgDsa> {
public:
    PSYMCRYPT_DLGROUP   pGroup;
    PSYMCRYPT_DLKEY     pKey;
};
