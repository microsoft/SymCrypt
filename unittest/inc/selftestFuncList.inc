//
// Selftestfunclist.cpp
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

// 
// Array of self test functions.
// This is in a separate file so that the Kernel test program can include
// it directly, and we only have to keep a single list. 
//
// The Kernel mode code cannot link to the primary lib or compile the precomp.h
// header file because the /kernel flag is required for kernel-mode code, and 
// it is not compatible with C++ exceptions used in the STL.
//

VOID
SYMCRYPT_CALL
SymCryptAesSelftestVoid()
{
    SymCryptAesSelftest( SYMCRYPT_AES_SELFTEST_ALL );
}

const SELFTEST_INFO g_selfTests[] = 
{
    {&SymCryptMd2Selftest, "Md2"},
    {&SymCryptMd4Selftest, "Md4"},
    {&SymCryptMd5Selftest, "Md5"},
    {&SymCryptSha1Selftest, "Sha1"},
    {&SymCryptSha256Selftest, "Sha256"},
    {&SymCryptSha384Selftest, "Sha384"},
    {&SymCryptSha512Selftest, "Sha512"},
    {&SymCryptSha3_256Selftest, "Sha3_256"},
    {&SymCryptSha3_384Selftest, "Sha3_384"},
    {&SymCryptSha3_512Selftest, "Sha3_512"},
    {&SymCryptShake128Selftest, "Shake128"},
    {&SymCryptShake256Selftest, "Shake256"},
    {&SymCryptCShake128Selftest, "CShake128"},
    {&SymCryptCShake256Selftest, "CShake256"},
    {&SymCryptKmac128Selftest, "Kmac128"},
    {&SymCryptKmac256Selftest, "Kmac256"},
    {&SymCryptHmacMd5Selftest, "HmacMd5" },
    {&SymCryptHmacSha1Selftest, "HmacSha1" },
    {&SymCryptHmacSha256Selftest, "HmacSha256" },
    {&SymCryptHmacSha384Selftest, "HmacSha384" },
    {&SymCryptHmacSha512Selftest, "HmacSha512" },
    {&SymCryptAesCmacSelftest, "AesCmac" },
    {&SymCryptMarvin32Selftest, "Marvin32" },
    {&SymCryptAesSelftestVoid, "Aes" },
    {&SymCryptDesSelftest, "Des" },
    {&SymCrypt3DesSelftest, "3Des" },
    {&SymCryptDesxSelftest, "Desx" },
    {&SymCryptRc2Selftest, "Rc2" },
    {&SymCryptCcmSelftest, "Ccm" },
    {&SymCryptGcmSelftest, "Gcm" },
    {&SymCryptRc4Selftest, "Rc4" },
    {&SymCryptRngAesInstantiateSelftest, "AesCtrDrbgInstantiate" },
    {&SymCryptRngAesReseedSelftest, "AesCtrDrbgReseed" },
    {&SymCryptRngAesGenerateSelftest, "AesCtrDrbgGenerate"},
    {&SymCryptPbkdf2_HmacSha1SelfTest, "Pbkdf2_HmacSha1"},
    {&SymCryptPbkdf2_HmacSha256SelfTest, "Pbkdf2_HmacSha256"},
    {&SymCryptSp800_108_HmacSha1SelfTest, "SP800-108_HmacSha1" },
    {&SymCryptSp800_108_HmacSha256SelfTest, "SP800-108_HmacSha256" },
    {&SymCryptSp800_108_HmacSha384SelfTest, "SP800-108_HmacSha384" },
    {&SymCryptSp800_108_HmacSha512SelfTest, "SP800-108_HmacSha512" },
    {&SymCryptTlsPrf1_1SelfTest, "TLS PRF 1.1" },
    {&SymCryptTlsPrf1_2SelfTest, "TLS PRF 1.2" },
    {&SymCryptHkdfSelfTest, "HKDF" },
    {&SymCryptXtsAesSelftest, "Xts-Aes" },
    {&SymCryptParallelSha256Selftest, "ParallelSha256" },
    {&SymCryptParallelSha384Selftest, "ParallelSha384" },
    {&SymCryptParallelSha512Selftest, "ParallelSha512" },
    {&SymCryptSrtpKdfSelfTest, "SrtpKdf" },
    {&SymCryptSshKdfSha256SelfTest, "SshKdfSha256" },
    {&SymCryptSshKdfSha512SelfTest, "SshKdfSha512" },
    
    {NULL, NULL},
};

