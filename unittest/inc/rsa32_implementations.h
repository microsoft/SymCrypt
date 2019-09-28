//
// RSA32 implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Header files for RSA32.lib
//
#include <aes.h>
#include <aesfast.h>
#include <sha.h>
#include <sha2.h>
#include <md5.h>
#include <md4.h>
#include <md2.h>
#include <hmac.h>
#include <modes.h>
#include <des.h>
#include <tripldes.h>
#include <rc2.h>
#include <hmac.h>
#include <aes_ccm.h>
extern "C" {
    #include <aes_gcm.h>
}
#include <rc4.h>


//
// Create a naming convention for result length and input block length.
// Values not defined by the RSA32.lib headers are taken from the symcrypt headers
//
#define RSA32_MD2_RESULT_SIZE            SYMCRYPT_MD2_RESULT_SIZE
#define RSA32_MD2_INPUT_BLOCK_SIZE       SYMCRYPT_MD2_INPUT_BLOCK_SIZE

#define RSA32_MD4_RESULT_SIZE            SYMCRYPT_MD4_RESULT_SIZE
#define RSA32_MD4_INPUT_BLOCK_SIZE       SYMCRYPT_MD4_INPUT_BLOCK_SIZE

#define RSA32_OLDMD4_RESULT_SIZE         SYMCRYPT_MD4_RESULT_SIZE
#define RSA32_OLDMD4_INPUT_BLOCK_SIZE    SYMCRYPT_MD4_INPUT_BLOCK_SIZE

#define RSA32_MD5_RESULT_SIZE            MD5DIGESTLEN
#define RSA32_MD5_INPUT_BLOCK_SIZE       SYMCRYPT_MD5_INPUT_BLOCK_SIZE

#define RSA32_SHA1_RESULT_SIZE           A_SHA_DIGEST_LEN
#define RSA32_SHA1_INPUT_BLOCK_SIZE      SYMCRYPT_SHA1_INPUT_BLOCK_SIZE

#define RSA32_SHA256_RESULT_SIZE         SHA256_DIGEST_LEN
#define RSA32_SHA256_INPUT_BLOCK_SIZE    SYMCRYPT_SHA256_INPUT_BLOCK_SIZE

#define RSA32_SHA384_RESULT_SIZE         SHA384_DIGEST_LEN
#define RSA32_SHA384_INPUT_BLOCK_SIZE    SYMCRYPT_SHA384_INPUT_BLOCK_SIZE

#define RSA32_SHA512_RESULT_SIZE         SHA512_DIGEST_LEN
#define RSA32_SHA512_INPUT_BLOCK_SIZE    SYMCRYPT_SHA512_INPUT_BLOCK_SIZE

#define RSA32_HMAC_MD5_INPUT_BLOCK_SIZE  RSA32_MD5_INPUT_BLOCK_SIZE
#define RSA32_HMAC_SHA1_INPUT_BLOCK_SIZE RSA32_SHA1_INPUT_BLOCK_SIZE

#define RSA32_HMAC_MD5_RESULT_SIZE       RSA32_MD5_RESULT_SIZE
#define RSA32_HMAC_SHA1_RESULT_SIZE      RSA32_SHA1_RESULT_SIZE



#define RSA32B_MD4_RESULT_SIZE           MD4DIGESTLEN
#define RSA32B_MD4_INPUT_BLOCK_SIZE      SYMCRYPT_MD4_INPUT_BLOCK_SIZE

#define RSA32_AES_BLOCK_SIZE             AES_BLOCK_SIZE
#define RSA32_DES_BLOCK_SIZE             DES_BLOCKLEN
#define RSA32_3DES_BLOCK_SIZE            DES_BLOCKLEN
#define RSA32_RC2_BLOCK_SIZE             RC2_BLOCKLEN



//
// Stub classes used as selector in templates. This class is never instantiated.
// Some algorithms have 2 implementations in RSA32.lib. We treat this as two
// different implementation names, 'rsa32' and 'rsa32b'.
//
class ImpRsa32{
public:
    static char * name;
};

class ImpRsa32b{
public:
    static char * name;
};


template<>
class HashImpState<ImpRsa32, AlgMd2> {
public:
    MD2_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32, AlgMd4> {
public:
    MD4_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32b, AlgMd4> {
public:
    MDstruct    md4;
    BYTE        buf[RSA32B_MD4_INPUT_BLOCK_SIZE];
    SIZE_T      bytesInBuf;
};

template<>
class HashImpState<ImpRsa32, AlgMd5> {
public:
    MD5_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32, AlgSha1> {
public:
    A_SHA_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32, AlgSha256> {
public:
    SHA256_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32, AlgSha384> {
public:
    SHA384_CTX     ctx;
};

template<>
class HashImpState<ImpRsa32, AlgSha512> {
public:
    SHA512_CTX     ctx;
};


template<>
class MacImpState<ImpRsa32, AlgHmacMd5> {
public:
    HMACMD5_CTX     keyCtx;
    HMACMD5_CTX     macCtx;  
};

template<>
class MacImpState<ImpRsa32, AlgHmacSha1> {
public:
    HMACSHA_CTX     keyCtx;
    HMACSHA_CTX     macCtx;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32, AlgAes, Mode> {
public:
    AES_KEY     key;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32b, AlgAes, Mode> {
public:
    AESTable     key;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32, AlgDes, Mode> {
public:
    DESTable    key;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32, Alg2Des, Mode> {
public:
    DES3TABLE   key;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32, Alg3Des, Mode> {
public:
    DES3TABLE   key;
};

template<class Mode>
class BlockCipherImpState<ImpRsa32, AlgDesx, Mode> {
public:
    DESXTable   key;
};

typedef struct _RC2_KEY
{
    WORD    key[RC2_TABLESIZE];
} RSA32_RC2_KEY;

template<class Mode>
class BlockCipherImpState<ImpRsa32, AlgRc2, Mode> {
public:
    RSA32_RC2_KEY  key;
};


template<class Mode>
class AuthEncImpState<ImpRsa32, AlgAes, Mode> {
public:
    AES_KEY     key;
};

template<>
class StreamCipherImpState<ImpRsa32, AlgRc4> {
public:
    RC4_KEYSTRUCT   state;
};
