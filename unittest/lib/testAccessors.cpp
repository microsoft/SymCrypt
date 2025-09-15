//
// Test for data accessor functions
//
// Note: we don't use shim/dispatch macros for any of these tests because the implementations are
// trivial, and it's not worth the extra complexity of dynamically loading the symbol addresses
// from the test module when running dynamic module tests.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

VOID
testGetBlockCipher()
{
    PCSYMCRYPT_BLOCKCIPHER pBlockCipher;

    //
    // Test SymCryptGetBlockCipher function
    //
    
    // Test valid block cipher IDs
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_AES);
    CHECK(pBlockCipher == SymCryptAesBlockCipher, "Wrong pointer for AES block cipher");
    
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_DES);
    CHECK(pBlockCipher == SymCryptDesBlockCipher, "Wrong pointer for DES block cipher");
    
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_3DES);
    CHECK(pBlockCipher == SymCrypt3DesBlockCipher, "Wrong pointer for 3DES block cipher");
    
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_DESX);
    CHECK(pBlockCipher == SymCryptDesxBlockCipher, "Wrong pointer for DESX block cipher");
    
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_RC2);
    CHECK(pBlockCipher == SymCryptRc2BlockCipher, "Wrong pointer for RC2 block cipher");
    
    // Test invalid block cipher IDs
    pBlockCipher = SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_NULL);
    CHECK(pBlockCipher == NULL, "Expected NULL for invalid block cipher ID");
    
    pBlockCipher = SymCryptGetBlockCipher((SYMCRYPT_BLOCKCIPHER_ID)999);
    CHECK(pBlockCipher == NULL, "Expected NULL for out-of-range block cipher ID");
}

VOID
testGetEcurveParams()
{
    PCSYMCRYPT_ECURVE_PARAMS pEcurveParams;

    //
    // Test SymCryptGetEcurveParams function
    //
    
    // Test valid curve IDs
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NIST_P192);
    CHECK(pEcurveParams == SymCryptEcurveParamsNistP192, "Wrong pointer for NIST P192 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NIST_P224);
    CHECK(pEcurveParams == SymCryptEcurveParamsNistP224, "Wrong pointer for NIST P224 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NIST_P256);
    CHECK(pEcurveParams == SymCryptEcurveParamsNistP256, "Wrong pointer for NIST P256 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NIST_P384);
    CHECK(pEcurveParams == SymCryptEcurveParamsNistP384, "Wrong pointer for NIST P384 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NIST_P521);
    CHECK(pEcurveParams == SymCryptEcurveParamsNistP521, "Wrong pointer for NIST P521 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NUMS_P256T1);
    CHECK(pEcurveParams == SymCryptEcurveParamsNumsP256t1, "Wrong pointer for NUMS P256T1 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NUMS_P384T1);
    CHECK(pEcurveParams == SymCryptEcurveParamsNumsP384t1, "Wrong pointer for NUMS P384T1 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NUMS_P512T1);
    CHECK(pEcurveParams == SymCryptEcurveParamsNumsP512t1, "Wrong pointer for NUMS P512T1 curve");
    
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_CURVE25519);
    CHECK(pEcurveParams == SymCryptEcurveParamsCurve25519, "Wrong pointer for Curve25519");
    
    // Test invalid curve IDs
    pEcurveParams = SymCryptGetEcurveParams(SYMCRYPT_ECURVE_ID_NULL);
    CHECK(pEcurveParams == NULL, "Expected NULL for invalid curve ID");
    
    pEcurveParams = SymCryptGetEcurveParams((SYMCRYPT_ECURVE_ID)999);
    CHECK(pEcurveParams == NULL, "Expected NULL for out-of-range curve ID");
}

VOID
testGetHashAlgorithm()
{
    PCSYMCRYPT_HASH pHashAlgorithm;

    //
    // Test SymCryptGetHashAlgorithm function
    //
    
    // Test valid hash IDs
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_MD2);
    CHECK(pHashAlgorithm == SymCryptMd2Algorithm, "Wrong pointer for MD2 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_MD4);
    CHECK(pHashAlgorithm == SymCryptMd4Algorithm, "Wrong pointer for MD4 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_MD5);
    CHECK(pHashAlgorithm == SymCryptMd5Algorithm, "Wrong pointer for MD5 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA1);
    CHECK(pHashAlgorithm == SymCryptSha1Algorithm, "Wrong pointer for SHA1 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA224);
    CHECK(pHashAlgorithm == SymCryptSha224Algorithm, "Wrong pointer for SHA224 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA256);
    CHECK(pHashAlgorithm == SymCryptSha256Algorithm, "Wrong pointer for SHA256 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA384);
    CHECK(pHashAlgorithm == SymCryptSha384Algorithm, "Wrong pointer for SHA384 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA512);
    CHECK(pHashAlgorithm == SymCryptSha512Algorithm, "Wrong pointer for SHA512 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA512_224);
    CHECK(pHashAlgorithm == SymCryptSha512_224Algorithm, "Wrong pointer for SHA512_224 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA512_256);
    CHECK(pHashAlgorithm == SymCryptSha512_256Algorithm, "Wrong pointer for SHA512_256 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA3_224);
    CHECK(pHashAlgorithm == SymCryptSha3_224Algorithm, "Wrong pointer for SHA3_224 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA3_256);
    CHECK(pHashAlgorithm == SymCryptSha3_256Algorithm, "Wrong pointer for SHA3_256 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA3_384);
    CHECK(pHashAlgorithm == SymCryptSha3_384Algorithm, "Wrong pointer for SHA3_384 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHA3_512);
    CHECK(pHashAlgorithm == SymCryptSha3_512Algorithm, "Wrong pointer for SHA3_512 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHAKE128);
    CHECK(pHashAlgorithm == SymCryptShake128HashAlgorithm, "Wrong pointer for SHAKE128 algorithm");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_SHAKE256);
    CHECK(pHashAlgorithm == SymCryptShake256HashAlgorithm, "Wrong pointer for SHAKE256 algorithm");
    
    // Test invalid hash IDs
    pHashAlgorithm = SymCryptGetHashAlgorithm(SYMCRYPT_HASH_ID_NULL);
    CHECK(pHashAlgorithm == NULL, "Expected NULL for invalid hash ID");
    
    pHashAlgorithm = SymCryptGetHashAlgorithm((SYMCRYPT_HASH_ID)999);
    CHECK(pHashAlgorithm == NULL, "Expected NULL for out-of-range hash ID");
}

VOID
testGetMacAlgorithm()
{
    PCSYMCRYPT_MAC pMacAlgorithm;

    //
    // Test SymCryptGetMacAlgorithm function
    //
    
    // Test valid MAC IDs
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_MD5);
    CHECK(pMacAlgorithm == SymCryptHmacMd5Algorithm, "Wrong pointer for HMAC MD5 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA1);
    CHECK(pMacAlgorithm == SymCryptHmacSha1Algorithm, "Wrong pointer for HMAC SHA1 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA224);
    CHECK(pMacAlgorithm == SymCryptHmacSha224Algorithm, "Wrong pointer for HMAC SHA224 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA256);
    CHECK(pMacAlgorithm == SymCryptHmacSha256Algorithm, "Wrong pointer for HMAC SHA256 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA384);
    CHECK(pMacAlgorithm == SymCryptHmacSha384Algorithm, "Wrong pointer for HMAC SHA384 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA512);
    CHECK(pMacAlgorithm == SymCryptHmacSha512Algorithm, "Wrong pointer for HMAC SHA512 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA512_224);
    CHECK(pMacAlgorithm == SymCryptHmacSha512_224Algorithm, "Wrong pointer for HMAC SHA512_224 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA512_256);
    CHECK(pMacAlgorithm == SymCryptHmacSha512_256Algorithm, "Wrong pointer for HMAC SHA512_256 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA3_224);
    CHECK(pMacAlgorithm == SymCryptHmacSha3_224Algorithm, "Wrong pointer for HMAC SHA3_224 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA3_256);
    CHECK(pMacAlgorithm == SymCryptHmacSha3_256Algorithm, "Wrong pointer for HMAC SHA3_256 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA3_384);
    CHECK(pMacAlgorithm == SymCryptHmacSha3_384Algorithm, "Wrong pointer for HMAC SHA3_384 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA3_512);
    CHECK(pMacAlgorithm == SymCryptHmacSha3_512Algorithm, "Wrong pointer for HMAC SHA3_512 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_AES_CMAC);
    CHECK(pMacAlgorithm == SymCryptAesCmacAlgorithm, "Wrong pointer for AES CMAC algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_KMAC_128);
    CHECK(pMacAlgorithm == SymCryptKmac128Algorithm, "Wrong pointer for KMAC 128 algorithm");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_KMAC_256);
    CHECK(pMacAlgorithm == SymCryptKmac256Algorithm, "Wrong pointer for KMAC 256 algorithm");
    
    // Test invalid MAC IDs
    pMacAlgorithm = SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_NULL);
    CHECK(pMacAlgorithm == NULL, "Expected NULL for invalid MAC ID");
    
    pMacAlgorithm = SymCryptGetMacAlgorithm((SYMCRYPT_MAC_ID)999);
    CHECK(pMacAlgorithm == NULL, "Expected NULL for out-of-range MAC ID");
}

VOID
testGetMarvin32DefaultSeed()
{
    PCSYMCRYPT_MARVIN32_EXPANDED_SEED pMarvin32Seed;

    //
    // Test SymCryptGetMarvin32DefaultSeed function
    //
    pMarvin32Seed = SymCryptGetMarvin32DefaultSeed();
    CHECK(pMarvin32Seed == SymCryptMarvin32DefaultSeed, "Wrong pointer for Marvin32 default seed");
}

VOID
testGetOidList()
{
    PCSYMCRYPT_OID pOidList;
    SIZE_T oidCount;

    //
    // Test SymCryptGetOidList function
    //
    
    // Test valid OID list IDs
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_MD5, &oidCount);
    CHECK(pOidList == SymCryptMd5OidList, "Wrong pointer for MD5 OID list");
    CHECK(oidCount == SYMCRYPT_MD5_OID_COUNT, "Wrong count for MD5 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA1, &oidCount);
    CHECK(pOidList == SymCryptSha1OidList, "Wrong pointer for SHA1 OID list");
    CHECK(oidCount == SYMCRYPT_SHA1_OID_COUNT, "Wrong count for SHA1 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA224, &oidCount);
    CHECK(pOidList == SymCryptSha224OidList, "Wrong pointer for SHA224 OID list");
    CHECK(oidCount == SYMCRYPT_SHA224_OID_COUNT, "Wrong count for SHA224 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA256, &oidCount);
    CHECK(pOidList == SymCryptSha256OidList, "Wrong pointer for SHA256 OID list");
    CHECK(oidCount == SYMCRYPT_SHA256_OID_COUNT, "Wrong count for SHA256 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA384, &oidCount);
    CHECK(pOidList == SymCryptSha384OidList, "Wrong pointer for SHA384 OID list");
    CHECK(oidCount == SYMCRYPT_SHA384_OID_COUNT, "Wrong count for SHA384 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA512, &oidCount);
    CHECK(pOidList == SymCryptSha512OidList, "Wrong pointer for SHA512 OID list");
    CHECK(oidCount == SYMCRYPT_SHA512_OID_COUNT, "Wrong count for SHA512 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA512_224, &oidCount);
    CHECK(pOidList == SymCryptSha512_224OidList, "Wrong pointer for SHA512_224 OID list");
    CHECK(oidCount == SYMCRYPT_SHA512_224_OID_COUNT, "Wrong count for SHA512_224 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA512_256, &oidCount);
    CHECK(pOidList == SymCryptSha512_256OidList, "Wrong pointer for SHA512_256 OID list");
    CHECK(oidCount == SYMCRYPT_SHA512_256_OID_COUNT, "Wrong count for SHA512_256 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA3_224, &oidCount);
    CHECK(pOidList == SymCryptSha3_224OidList, "Wrong pointer for SHA3_224 OID list");
    CHECK(oidCount == SYMCRYPT_SHA3_224_OID_COUNT, "Wrong count for SHA3_224 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA3_256, &oidCount);
    CHECK(pOidList == SymCryptSha3_256OidList, "Wrong pointer for SHA3_256 OID list");
    CHECK(oidCount == SYMCRYPT_SHA3_256_OID_COUNT, "Wrong count for SHA3_256 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA3_384, &oidCount);
    CHECK(pOidList == SymCryptSha3_384OidList, "Wrong pointer for SHA3_384 OID list");
    CHECK(oidCount == SYMCRYPT_SHA3_384_OID_COUNT, "Wrong count for SHA3_384 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA3_512, &oidCount);
    CHECK(pOidList == SymCryptSha3_512OidList, "Wrong pointer for SHA3_512 OID list");
    CHECK(oidCount == SYMCRYPT_SHA3_512_OID_COUNT, "Wrong count for SHA3_512 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHAKE128, &oidCount);
    CHECK(pOidList == SymCryptShake128OidList, "Wrong pointer for SHAKE128 OID list");
    CHECK(oidCount == SYMCRYPT_SHAKE128_OID_COUNT, "Wrong count for SHAKE128 OID list");
    
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHAKE256, &oidCount);
    CHECK(pOidList == SymCryptShake256OidList, "Wrong pointer for SHAKE256 OID list");
    CHECK(oidCount == SYMCRYPT_SHAKE256_OID_COUNT, "Wrong count for SHAKE256 OID list");

    // Test OID list function with NULL count parameter
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_SHA256, NULL);
    CHECK(pOidList == SymCryptSha256OidList, "Wrong pointer for SHA256 OID list with NULL count");
    
    // Test invalid OID list IDs
    pOidList = SymCryptGetOidList(SYMCRYPT_OID_LIST_ID_NULL, &oidCount);
    CHECK(pOidList == NULL, "Expected NULL for invalid OID list ID");
    
    pOidList = SymCryptGetOidList((SYMCRYPT_OID_LIST_ID)999, &oidCount);
    CHECK(pOidList == NULL, "Expected NULL for out-of-range OID list ID");
}

VOID
testDataAccessors()
{
    print("    Data accessors");

    testGetBlockCipher();
    testGetEcurveParams();
    testGetHashAlgorithm();
    testGetMacAlgorithm();
    testGetMarvin32DefaultSeed();
    testGetOidList();

    print("\n");
}
