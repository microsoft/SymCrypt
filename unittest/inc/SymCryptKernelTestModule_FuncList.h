//
// SymCryptKernelTestModule_FuncList.h
// Lists functions and symbols that the SymCryptKernelTestModule supports, used by both the user mode
// and kernel mode components of the test module to set up directing calls from user mode
// unit tests to test driver.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// FUNCTION and SYMBOL macros are defined in the source files that include this header as
// what we need to do with the listed SymCrypt symbol names is different in the user mode
// dll and the kernel mode test driver

// List all symbols that unit tests need to know the address of
SYMBOL(SymCryptMarvin32DefaultSeed)
SYMBOL(SymCryptAesCmacAlgorithm)
SYMBOL(SymCryptHmacMd5Algorithm)
SYMBOL(SymCryptHmacSha1Algorithm)
SYMBOL(SymCryptHmacSha256Algorithm)
SYMBOL(SymCryptHmacSha384Algorithm)
SYMBOL(SymCryptHmacSha512Algorithm)
SYMBOL(SymCryptHmacSha3_256Algorithm)
SYMBOL(SymCryptHmacSha3_384Algorithm)
SYMBOL(SymCryptHmacSha3_512Algorithm)
SYMBOL(SymCryptMd2Algorithm)
SYMBOL(SymCryptMd4Algorithm)
SYMBOL(SymCryptMd5Algorithm)
SYMBOL(SymCryptSha1Algorithm)
SYMBOL(SymCryptSha256Algorithm)
SYMBOL(SymCryptSha384Algorithm)
SYMBOL(SymCryptSha512Algorithm)
SYMBOL(SymCryptSha3_256Algorithm)
SYMBOL(SymCryptSha3_384Algorithm)
SYMBOL(SymCryptSha3_512Algorithm)
SYMBOL(SymCryptShake128HashAlgorithm)
SYMBOL(SymCryptShake256HashAlgorithm)
SYMBOL(SymCryptKmac128Algorithm)
SYMBOL(SymCryptKmac256Algorithm)
SYMBOL(SymCryptMd5OidList)
SYMBOL(SymCryptSha1OidList)
SYMBOL(SymCryptSha256OidList)
SYMBOL(SymCryptSha384OidList)
SYMBOL(SymCryptSha512OidList)
SYMBOL(SymCryptSha3_256OidList)
SYMBOL(SymCryptSha3_384OidList)
SYMBOL(SymCryptSha3_512OidList)
SYMBOL(SymCryptAesBlockCipher)
SYMBOL(SymCrypt3DesBlockCipher)
SYMBOL(SymCryptDesBlockCipher)
SYMBOL(SymCryptDesxBlockCipher)
SYMBOL(SymCryptRc2BlockCipher)
SYMBOL(SymCryptEcurveParamsCurve25519)
SYMBOL(SymCryptEcurveParamsNistP192)
SYMBOL(SymCryptEcurveParamsNistP224)
SYMBOL(SymCryptEcurveParamsNistP256)
SYMBOL(SymCryptEcurveParamsNistP384)
SYMBOL(SymCryptEcurveParamsNistP521)
SYMBOL(SymCryptEcurveParamsNumsP256t1)
SYMBOL(SymCryptEcurveParamsNumsP384t1)
SYMBOL(SymCryptEcurveParamsNumsP512t1)

// List all functions that unit tests need to call into
FUNCTION(SymCrypt3DesCbcDecrypt)
FUNCTION(SymCrypt3DesCbcEncrypt)
FUNCTION(SymCrypt3DesDecrypt)
FUNCTION(SymCrypt3DesEncrypt)
FUNCTION(SymCrypt3DesExpandKey)
FUNCTION(SymCrypt3DesSelftest)
FUNCTION(SymCryptAesCbcDecrypt)
FUNCTION(SymCryptAesCbcEncrypt)
FUNCTION(SymCryptAesCbcMac)
FUNCTION(SymCryptAesCmac)
FUNCTION(SymCryptAesCmacAppend)
FUNCTION(SymCryptAesCmacExpandKey)
FUNCTION(SymCryptAesCmacInit)
FUNCTION(SymCryptAesCmacKeyCopy)
FUNCTION(SymCryptAesCmacResult)
FUNCTION(SymCryptAesCmacSelftest)
FUNCTION(SymCryptAesCmacStateCopy)
FUNCTION(SymCryptAesCtrMsb64)
FUNCTION(SymCryptAesDecrypt)
FUNCTION(SymCryptAesEcbDecrypt)
FUNCTION(SymCryptAesEcbEncrypt)
FUNCTION(SymCryptAesEncrypt)
FUNCTION(SymCryptAesExpandKey)
FUNCTION(SymCryptAesExpandKeyEncryptOnly)
FUNCTION(SymCryptAesKeyCopy)
FUNCTION(SymCryptAesKwDecrypt)
FUNCTION(SymCryptAesKwEncrypt)
FUNCTION(SymCryptAesKwpDecrypt)
FUNCTION(SymCryptAesKwpEncrypt)
FUNCTION(SymCryptAesSelftest)
FUNCTION(SymCryptCbcDecrypt)
FUNCTION(SymCryptCbcEncrypt)
FUNCTION(SymCryptCbcMac)
FUNCTION(SymCryptCcmDecrypt)
FUNCTION(SymCryptCcmDecryptFinal)
FUNCTION(SymCryptCcmDecryptPart)
FUNCTION(SymCryptCcmEncrypt)
FUNCTION(SymCryptCcmEncryptFinal)
FUNCTION(SymCryptCcmEncryptPart)
FUNCTION(SymCryptCcmInit)
FUNCTION(SymCryptCcmSelftest)
FUNCTION(SymCryptCcmValidateParameters)
FUNCTION(SymCryptCfbDecrypt)
FUNCTION(SymCryptCfbEncrypt)
FUNCTION(SymCryptChaCha20Crypt)
FUNCTION(SymCryptChaCha20Init)
FUNCTION(SymCryptChaCha20Poly1305Decrypt)
FUNCTION(SymCryptChaCha20Poly1305Encrypt)
FUNCTION(SymCryptChaCha20Poly1305Selftest)
FUNCTION(SymCryptChaCha20Selftest)
FUNCTION(SymCryptChaCha20SetOffset)
FUNCTION(SymCryptCtrMsb64)
FUNCTION(SymCryptDesDecrypt)
FUNCTION(SymCryptDesEncrypt)
FUNCTION(SymCryptDesExpandKey)
FUNCTION(SymCryptDesSelftest)
FUNCTION(SymCryptDesxDecrypt)
FUNCTION(SymCryptDesxEncrypt)
FUNCTION(SymCryptDesxExpandKey)
FUNCTION(SymCryptDesxSelftest)
FUNCTION(SymCryptDhSecretAgreement)
FUNCTION(SymCryptDhSecretAgreementSelftest)
FUNCTION(SymCryptDlgroupAllocate)
FUNCTION(SymCryptDlgroupCopy)
FUNCTION(SymCryptDlgroupCreate)
FUNCTION(SymCryptDlgroupFree)
FUNCTION(SymCryptDlgroupGenerate)
FUNCTION(SymCryptDlgroupGetSizes)
FUNCTION(SymCryptDlgroupGetValue)
FUNCTION(SymCryptDlgroupIsSame)
FUNCTION(SymCryptDlgroupSetValue)
FUNCTION(SymCryptDlgroupSetValueSafePrime)
FUNCTION(SymCryptDlgroupWipe)
FUNCTION(SymCryptDlkeyAllocate)
FUNCTION(SymCryptDlkeyCopy)
FUNCTION(SymCryptDlkeyCreate)
FUNCTION(SymCryptDlkeyFree)
FUNCTION(SymCryptDlkeyGenerate)
FUNCTION(SymCryptDlkeyGetGroup)
FUNCTION(SymCryptDlkeyGetValue)
FUNCTION(SymCryptDlkeyHasPrivateKey)
FUNCTION(SymCryptDlkeySetPrivateKeyLength)
FUNCTION(SymCryptDlkeySetValue)
FUNCTION(SymCryptDlkeySizeofPrivateKey)
FUNCTION(SymCryptDlkeySizeofPublicKey)
FUNCTION(SymCryptDlkeyWipe)
FUNCTION(SymCryptDsaSelftest)
FUNCTION(SymCryptDsaSign)
FUNCTION(SymCryptDsaVerify)
FUNCTION(SymCryptEcDhSecretAgreement)
FUNCTION(SymCryptEcDhSecretAgreementSelftest)
FUNCTION(SymCryptEcDsaSelftest)
FUNCTION(SymCryptEcDsaSign)
FUNCTION(SymCryptEcDsaVerify)
FUNCTION(SymCryptEcbDecrypt)
FUNCTION(SymCryptEcbEncrypt)
FUNCTION(SymCryptEckeyAllocate)
FUNCTION(SymCryptEckeyCopy)
FUNCTION(SymCryptEckeyCreate)
FUNCTION(SymCryptEckeyFree)
FUNCTION(SymCryptEckeyGetValue)
FUNCTION(SymCryptEckeyHasPrivateKey)
FUNCTION(SymCryptEckeySetRandom)
FUNCTION(SymCryptEckeySetValue)
FUNCTION(SymCryptEckeySizeofPrivateKey)
FUNCTION(SymCryptEckeySizeofPublicKey)
FUNCTION(SymCryptEckeyWipe)
FUNCTION(SymCryptEcurveAllocate)
FUNCTION(SymCryptEcurveBitsizeofFieldModulus)
FUNCTION(SymCryptEcurveBitsizeofGroupOrder)
FUNCTION(SymCryptEcurveFree)
FUNCTION(SymCryptEcurveHighBitRestrictionNumOfBits)
FUNCTION(SymCryptEcurveHighBitRestrictionPosition)
FUNCTION(SymCryptEcurveHighBitRestrictionValue)
FUNCTION(SymCryptEcurveIsSame)
FUNCTION(SymCryptEcurvePrivateKeyDefaultFormat)
FUNCTION(SymCryptEcurveSizeofFieldElement)
FUNCTION(SymCryptEcurveSizeofScalarMultiplier)
FUNCTION(SymCryptEqual)
FUNCTION(SymCryptGcmAuthPart)
FUNCTION(SymCryptGcmDecrypt)
FUNCTION(SymCryptGcmDecryptFinal)
FUNCTION(SymCryptGcmDecryptPart)
FUNCTION(SymCryptGcmEncrypt)
FUNCTION(SymCryptGcmEncryptFinal)
FUNCTION(SymCryptGcmEncryptPart)
FUNCTION(SymCryptGcmExpandKey)
FUNCTION(SymCryptGcmInit)
FUNCTION(SymCryptGcmKeyCopy)
FUNCTION(SymCryptGcmSelftest)
FUNCTION(SymCryptGcmStateCopy)
FUNCTION(SymCryptGcmValidateParameters)
FUNCTION(SymCryptHash)
FUNCTION(SymCryptHashAppend)
FUNCTION(SymCryptHashInit)
FUNCTION(SymCryptHashInputBlockSize)
FUNCTION(SymCryptHashResult)
FUNCTION(SymCryptHashResultSize)
FUNCTION(SymCryptHashStateSize)
FUNCTION(SymCryptHkdf)
FUNCTION(SymCryptHkdfDerive)
FUNCTION(SymCryptHkdfExpandKey)
FUNCTION(SymCryptHkdfExtractPrk)
FUNCTION(SymCryptHkdfPrkExpandKey)
FUNCTION(SymCryptHmacMd5)
FUNCTION(SymCryptHmacMd5Append)
FUNCTION(SymCryptHmacMd5ExpandKey)
FUNCTION(SymCryptHmacMd5Init)
FUNCTION(SymCryptHmacMd5KeyCopy)
FUNCTION(SymCryptHmacMd5Result)
FUNCTION(SymCryptHmacMd5Selftest)
FUNCTION(SymCryptHmacMd5StateCopy)
FUNCTION(SymCryptHmacSha1)
FUNCTION(SymCryptHmacSha1Append)
FUNCTION(SymCryptHmacSha1ExpandKey)
FUNCTION(SymCryptHmacSha1Init)
FUNCTION(SymCryptHmacSha1KeyCopy)
FUNCTION(SymCryptHmacSha1Result)
FUNCTION(SymCryptHmacSha1Selftest)
FUNCTION(SymCryptHmacSha1StateCopy)
FUNCTION(SymCryptHmacSha256)
FUNCTION(SymCryptHmacSha256Append)
FUNCTION(SymCryptHmacSha256ExpandKey)
FUNCTION(SymCryptHmacSha256Init)
FUNCTION(SymCryptHmacSha256KeyCopy)
FUNCTION(SymCryptHmacSha256Result)
FUNCTION(SymCryptHmacSha256Selftest)
FUNCTION(SymCryptHmacSha256StateCopy)
FUNCTION(SymCryptHmacSha384)
FUNCTION(SymCryptHmacSha384Append)
FUNCTION(SymCryptHmacSha384ExpandKey)
FUNCTION(SymCryptHmacSha384Init)
FUNCTION(SymCryptHmacSha384KeyCopy)
FUNCTION(SymCryptHmacSha384Result)
FUNCTION(SymCryptHmacSha384Selftest)
FUNCTION(SymCryptHmacSha384StateCopy)
FUNCTION(SymCryptHmacSha512)
FUNCTION(SymCryptHmacSha512Append)
FUNCTION(SymCryptHmacSha512ExpandKey)
FUNCTION(SymCryptHmacSha512Init)
FUNCTION(SymCryptHmacSha512KeyCopy)
FUNCTION(SymCryptHmacSha512Result)
FUNCTION(SymCryptHmacSha512Selftest)
FUNCTION(SymCryptHmacSha512StateCopy)
FUNCTION(SymCryptHmacSha3_256)
FUNCTION(SymCryptHmacSha3_256Append)
FUNCTION(SymCryptHmacSha3_256ExpandKey)
FUNCTION(SymCryptHmacSha3_256Init)
FUNCTION(SymCryptHmacSha3_256KeyCopy)
FUNCTION(SymCryptHmacSha3_256Result)
FUNCTION(SymCryptHmacSha3_256Selftest)
FUNCTION(SymCryptHmacSha3_256StateCopy)
FUNCTION(SymCryptHmacSha3_384)
FUNCTION(SymCryptHmacSha3_384Append)
FUNCTION(SymCryptHmacSha3_384ExpandKey)
FUNCTION(SymCryptHmacSha3_384Init)
FUNCTION(SymCryptHmacSha3_384KeyCopy)
FUNCTION(SymCryptHmacSha3_384Result)
FUNCTION(SymCryptHmacSha3_384Selftest)
FUNCTION(SymCryptHmacSha3_384StateCopy)
FUNCTION(SymCryptHmacSha3_512)
FUNCTION(SymCryptHmacSha3_512Append)
FUNCTION(SymCryptHmacSha3_512ExpandKey)
FUNCTION(SymCryptHmacSha3_512Init)
FUNCTION(SymCryptHmacSha3_512KeyCopy)
FUNCTION(SymCryptHmacSha3_512Result)
FUNCTION(SymCryptHmacSha3_512Selftest)
FUNCTION(SymCryptHmacSha3_512StateCopy)
FUNCTION(SymCryptShake128)
FUNCTION(SymCryptShake128Default)
FUNCTION(SymCryptShake128Init)
FUNCTION(SymCryptShake128Append)
FUNCTION(SymCryptShake128Result)
FUNCTION(SymCryptShake128Extract)
FUNCTION(SymCryptShake128StateCopy)
FUNCTION(SymCryptShake256)
FUNCTION(SymCryptShake256Default)
FUNCTION(SymCryptShake256Init)
FUNCTION(SymCryptShake256Append)
FUNCTION(SymCryptShake256Result)
FUNCTION(SymCryptShake256Extract)
FUNCTION(SymCryptShake256StateCopy)
FUNCTION(SymCryptCShake128)
FUNCTION(SymCryptCShake128Init)
FUNCTION(SymCryptCShake128Append)
FUNCTION(SymCryptCShake128Result)
FUNCTION(SymCryptCShake128Extract)
FUNCTION(SymCryptCShake128StateCopy)
FUNCTION(SymCryptCShake256)
FUNCTION(SymCryptCShake256Init)
FUNCTION(SymCryptCShake256Append)
FUNCTION(SymCryptCShake256Result)
FUNCTION(SymCryptCShake256Extract)
FUNCTION(SymCryptCShake256StateCopy)
FUNCTION(SymCryptKmac128ExpandKey)
FUNCTION(SymCryptKmac128ExpandKeyEx)
FUNCTION(SymCryptKmac128)
FUNCTION(SymCryptKmac128Ex)
FUNCTION(SymCryptKmac128Init)
FUNCTION(SymCryptKmac128Append)
FUNCTION(SymCryptKmac128Extract)
FUNCTION(SymCryptKmac128Result)
FUNCTION(SymCryptKmac128ResultEx)
FUNCTION(SymCryptKmac128KeyCopy)
FUNCTION(SymCryptKmac128StateCopy)
FUNCTION(SymCryptKmac256ExpandKey)
FUNCTION(SymCryptKmac256ExpandKeyEx)
FUNCTION(SymCryptKmac256)
FUNCTION(SymCryptKmac256Ex)
FUNCTION(SymCryptKmac256Init)
FUNCTION(SymCryptKmac256Append)
FUNCTION(SymCryptKmac256Extract)
FUNCTION(SymCryptKmac256Result)
FUNCTION(SymCryptKmac256ResultEx)
FUNCTION(SymCryptKmac256KeyCopy)
FUNCTION(SymCryptKmac256StateCopy)
FUNCTION(SymCryptLoadLsbFirstUint32)
FUNCTION(SymCryptLoadLsbFirstUint64)
FUNCTION(SymCryptLoadMsbFirstUint32)
FUNCTION(SymCryptLoadMsbFirstUint64)
FUNCTION(SymCryptMarvin32)
FUNCTION(SymCryptMarvin32Append)
FUNCTION(SymCryptMarvin32ExpandSeed)
FUNCTION(SymCryptMarvin32Init)
FUNCTION(SymCryptMarvin32Result)
FUNCTION(SymCryptMarvin32SeedCopy)
FUNCTION(SymCryptMarvin32Selftest)
FUNCTION(SymCryptMarvin32StateCopy)
FUNCTION(SymCryptMd2)
FUNCTION(SymCryptMd2Append)
FUNCTION(SymCryptMd2Init)
FUNCTION(SymCryptMd2Result)
FUNCTION(SymCryptMd2Selftest)
FUNCTION(SymCryptMd2StateCopy)
FUNCTION(SymCryptMd2StateExport)
FUNCTION(SymCryptMd2StateImport)
FUNCTION(SymCryptMd4)
FUNCTION(SymCryptMd4Append)
FUNCTION(SymCryptMd4Init)
FUNCTION(SymCryptMd4Result)
FUNCTION(SymCryptMd4Selftest)
FUNCTION(SymCryptMd4StateCopy)
FUNCTION(SymCryptMd4StateExport)
FUNCTION(SymCryptMd4StateImport)
FUNCTION(SymCryptMd5)
FUNCTION(SymCryptMd5Append)
FUNCTION(SymCryptMd5Init)
FUNCTION(SymCryptMd5Result)
FUNCTION(SymCryptMd5Selftest)
FUNCTION(SymCryptMd5StateCopy)
FUNCTION(SymCryptMd5StateExport)
FUNCTION(SymCryptMd5StateImport)
FUNCTION(SymCryptMlKemkeyAllocate)
FUNCTION(SymCryptMlKemkeyFree)
FUNCTION(SymCryptMlKemkeyGenerate)
FUNCTION(SymCryptMlKemkeySetValue)
FUNCTION(SymCryptMlKemkeyGetValue)
FUNCTION(SymCryptMlKemSizeofKeyFormatFromParams)
FUNCTION(SymCryptMlKemSizeofCiphertextFromParams)
FUNCTION(SymCryptMlKemEncapsulate)
FUNCTION(SymCryptMlKemEncapsulateEx)
FUNCTION(SymCryptMlKemDecapsulate)
FUNCTION(SymCryptMlKemSelftest)
FUNCTION(SymCryptParallelSha256Init)
FUNCTION(SymCryptParallelSha256Process)
FUNCTION(SymCryptParallelSha256Selftest)
FUNCTION(SymCryptParallelSha384Init)
FUNCTION(SymCryptParallelSha384Process)
FUNCTION(SymCryptParallelSha384Selftest)
FUNCTION(SymCryptParallelSha512Init)
FUNCTION(SymCryptParallelSha512Process)
FUNCTION(SymCryptParallelSha512Selftest)
FUNCTION(SymCryptPbkdf2)
FUNCTION(SymCryptPbkdf2Derive)
FUNCTION(SymCryptPbkdf2ExpandKey)
FUNCTION(SymCryptPoly1305)
FUNCTION(SymCryptPoly1305Append)
FUNCTION(SymCryptPoly1305Init)
FUNCTION(SymCryptPoly1305Result)
FUNCTION(SymCryptPoly1305Selftest)
FUNCTION(SymCryptProvideEntropy)
FUNCTION(SymCryptRandom)
FUNCTION(SymCryptRc2Decrypt)
FUNCTION(SymCryptRc2Encrypt)
FUNCTION(SymCryptRc2ExpandKey)
FUNCTION(SymCryptRc2ExpandKeyEx)
FUNCTION(SymCryptRc2Selftest)
FUNCTION(SymCryptRc4Crypt)
FUNCTION(SymCryptRc4Init)
FUNCTION(SymCryptRc4Selftest)
FUNCTION(SymCryptRngAesFips140_2Generate)
FUNCTION(SymCryptRngAesFips140_2Instantiate)
FUNCTION(SymCryptRngAesFips140_2Reseed)
FUNCTION(SymCryptRngAesFips140_2Uninstantiate)
FUNCTION(SymCryptRngAesGenerate)
FUNCTION(SymCryptRngAesGenerateSelftest)
FUNCTION(SymCryptRngAesInstantiate)
FUNCTION(SymCryptRngAesInstantiateSelftest)
FUNCTION(SymCryptRngAesReseed)
FUNCTION(SymCryptRngAesReseedSelftest)
FUNCTION(SymCryptRngAesUninstantiate)
FUNCTION(SymCryptRsaOaepDecrypt)
FUNCTION(SymCryptRsaOaepEncrypt)
FUNCTION(SymCryptRsaSelftest)
FUNCTION(SymCryptRsaPkcs1Decrypt)
FUNCTION(SymCryptRsaPkcs1Encrypt)
FUNCTION(SymCryptRsaPkcs1Sign)
FUNCTION(SymCryptRsaPkcs1Verify)
FUNCTION(SymCryptRsaPssSign)
FUNCTION(SymCryptRsaPssVerify)
FUNCTION(SymCryptRsaRawDecrypt)
FUNCTION(SymCryptRsaRawEncrypt)
FUNCTION(SymCryptRsakeyAllocate)
FUNCTION(SymCryptRsakeyFree)
FUNCTION(SymCryptRsakeyGenerate)
FUNCTION(SymCryptRsakeyGetCrtValue)
FUNCTION(SymCryptRsakeyGetNumberOfPrimes)
FUNCTION(SymCryptRsakeyGetNumberOfPublicExponents)
FUNCTION(SymCryptRsakeyGetValue)
FUNCTION(SymCryptRsakeyHasPrivateKey)
FUNCTION(SymCryptRsakeyModulusBits)
FUNCTION(SymCryptRsakeySetValue)
FUNCTION(SymCryptRsakeySetValueFromPrivateExponent)
FUNCTION(SymCryptRsakeySizeofModulus)
FUNCTION(SymCryptRsakeySizeofPrime)
FUNCTION(SymCryptRsakeySizeofPublicExponent)
FUNCTION(SymCryptRsakeyWipe)
FUNCTION(SymCryptSha1)
FUNCTION(SymCryptSha1Append)
FUNCTION(SymCryptSha1Init)
FUNCTION(SymCryptSha1Result)
FUNCTION(SymCryptSha1Selftest)
FUNCTION(SymCryptSha1StateCopy)
FUNCTION(SymCryptSha1StateExport)
FUNCTION(SymCryptSha1StateImport)
FUNCTION(SymCryptSha256)
FUNCTION(SymCryptSha256Append)
FUNCTION(SymCryptSha256Init)
FUNCTION(SymCryptSha256Result)
FUNCTION(SymCryptSha256Selftest)
FUNCTION(SymCryptSha256StateCopy)
FUNCTION(SymCryptSha256StateExport)
FUNCTION(SymCryptSha256StateImport)
FUNCTION(SymCryptSha384)
FUNCTION(SymCryptSha384Append)
FUNCTION(SymCryptSha384Init)
FUNCTION(SymCryptSha384Result)
FUNCTION(SymCryptSha384Selftest)
FUNCTION(SymCryptSha384StateCopy)
FUNCTION(SymCryptSha384StateExport)
FUNCTION(SymCryptSha384StateImport)
FUNCTION(SymCryptSha512)
FUNCTION(SymCryptSha512Append)
FUNCTION(SymCryptSha512Init)
FUNCTION(SymCryptSha512Result)
FUNCTION(SymCryptSha512Selftest)
FUNCTION(SymCryptSha512StateCopy)
FUNCTION(SymCryptSha512StateExport)
FUNCTION(SymCryptSha512StateImport)
FUNCTION(SymCryptSha3_256)
FUNCTION(SymCryptSha3_256Append)
FUNCTION(SymCryptSha3_256Init)
FUNCTION(SymCryptSha3_256Result)
FUNCTION(SymCryptSha3_256StateCopy)
FUNCTION(SymCryptSha3_256StateExport)
FUNCTION(SymCryptSha3_256StateImport)
FUNCTION(SymCryptSha3_384)
FUNCTION(SymCryptSha3_384Append)
FUNCTION(SymCryptSha3_384Init)
FUNCTION(SymCryptSha3_384Result)
FUNCTION(SymCryptSha3_384StateCopy)
FUNCTION(SymCryptSha3_384StateExport)
FUNCTION(SymCryptSha3_384StateImport)
FUNCTION(SymCryptSha3_512)
FUNCTION(SymCryptSha3_512Append)
FUNCTION(SymCryptSha3_512Init)
FUNCTION(SymCryptSha3_512Result)
FUNCTION(SymCryptSha3_512StateCopy)
FUNCTION(SymCryptSha3_512StateExport)
FUNCTION(SymCryptSha3_512StateImport)
FUNCTION(SymCryptSizeofDlgroupFromBitsizes)
FUNCTION(SymCryptSizeofDlkeyFromDlgroup)
FUNCTION(SymCryptSizeofEckeyFromCurve)
FUNCTION(SymCryptSizeofRsakeyFromParams)
FUNCTION(SymCryptSp800_108)
FUNCTION(SymCryptSp800_108Derive)
FUNCTION(SymCryptSp800_108ExpandKey)
FUNCTION(SymCryptStoreLsbFirstUint32)
FUNCTION(SymCryptStoreLsbFirstUint64)
FUNCTION(SymCryptStoreMsbFirstUint32)
FUNCTION(SymCryptStoreMsbFirstUint64)
FUNCTION(SymCryptTlsCbcHmacVerify)
FUNCTION(SymCryptTlsPrf1_1)
FUNCTION(SymCryptTlsPrf1_1Derive)
FUNCTION(SymCryptTlsPrf1_1ExpandKey)
FUNCTION(SymCryptTlsPrf1_2)
FUNCTION(SymCryptTlsPrf1_2Derive)
FUNCTION(SymCryptTlsPrf1_2ExpandKey)
FUNCTION(SymCryptSrtpKdf)
FUNCTION(SymCryptSrtpKdfExpandKey)
FUNCTION(SymCryptSrtpKdfDerive)
FUNCTION(SymCryptSshKdf)
FUNCTION(SymCryptSshKdfExpandKey)
FUNCTION(SymCryptSshKdfDerive)
FUNCTION(SymCryptSskdfMacExpandSalt)
FUNCTION(SymCryptSskdfMacDerive)
FUNCTION(SymCryptSskdfMac)
FUNCTION(SymCryptSskdfHash)
FUNCTION(SymCryptUint32Bitsize)
FUNCTION(SymCryptUint32Bytesize)
FUNCTION(SymCryptUint64Bitsize)
FUNCTION(SymCryptUint64Bytesize)
FUNCTION(SymCryptWipe)
FUNCTION(SymCryptXorBytes)
FUNCTION(SymCryptXtsAesDecrypt)
FUNCTION(SymCryptXtsAesDecryptWith128bTweak)
FUNCTION(SymCryptXtsAesEncrypt)
FUNCTION(SymCryptXtsAesEncryptWith128bTweak)
FUNCTION(SymCryptXtsAesExpandKey)
FUNCTION(SymCryptXtsAesExpandKeyEx)
FUNCTION(SymCryptXtsAesKeyCopy)
FUNCTION(SymCryptXtsAesSelftest)
FUNCTION(SymCryptSessionDestroy)
FUNCTION(SymCryptSessionGcmDecrypt)
FUNCTION(SymCryptSessionGcmEncrypt)
FUNCTION(SymCryptSessionReceiverInit)
FUNCTION(SymCryptSessionSenderInit)
FUNCTION(SymCryptDlkeyExtendKeyUsage)
FUNCTION(SymCryptEckeyExtendKeyUsage)
FUNCTION(SymCryptRsakeyExtendKeyUsage)
FUNCTION(SymCryptRsakeyCreate)
FUNCTION(SymCryptMapUint32)
FUNCTION(SymCryptPaddingPkcs7Add)
FUNCTION(SymCryptPaddingPkcs7Remove)
FUNCTION(SymCryptFipsGetSelftestsPerformed)
FUNCTION(SymCryptDeprecatedStatusIndicator)
FUNCTION(SymCryptXmsskeyAllocate)
FUNCTION(SymCryptXmsskeyFree)
FUNCTION(SymCryptXmsskeyGenerate)
FUNCTION(SymCryptXmsskeyGetValue)
FUNCTION(SymCryptXmsskeySetValue)
FUNCTION(SymCryptXmssSizeofKeyBlobFromParams)
FUNCTION(SymCryptXmssMtParamsFromAlgId)
FUNCTION(SymCryptXmssParamsFromAlgId)
FUNCTION(SymCryptXmssSetParams)
FUNCTION(SymCryptXmssSign)
FUNCTION(SymCryptXmssSizeofSignatureFromParams)
FUNCTION(SymCryptXmssVerify)
FUNCTION(SymCryptXmssSelftest)
FUNCTION(SymCryptLmskeyAllocate)
FUNCTION(SymCryptLmskeyFree)
FUNCTION(SymCryptLmskeyGenerate)
FUNCTION(SymCryptLmskeyGetValue)
FUNCTION(SymCryptLmskeySetValue)
FUNCTION(SymCryptLmsSizeofKeyBlobFromParams)
FUNCTION(SymCryptLmsParamsFromAlgId)
FUNCTION(SymCryptLmsSetParams)
FUNCTION(SymCryptLmsSign)
FUNCTION(SymCryptLmsSizeofSignatureFromParams)
FUNCTION(SymCryptLmsVerify)
FUNCTION(SymCryptLmsSelftest)
