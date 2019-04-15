//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testInterop.h"

IMPLEMENTATION_DATA g_Implementations[TEST_INTEROP_NUMOF_IMPS] = {
    { ImpSc::name,          IMPSC_INDEX         },
    { ImpMsBignum::name,    IMPMSBIGNUM_INDEX   },
    { ImpCng::name,         IMPCNG_INDEX        },
};

// Functions needed for MsBignum hashes (see pfnHash type)
BOOL
WINAPI
SHA1Hash(
    __in_bcount( cbData )   const unsigned char* pbData,
                            unsigned int   cbData,
    __out_bcount( SYMCRYPT_SHA1_RESULT_SIZE )
                            unsigned char*  pbResult )
{
    SymCryptSha1( (PCBYTE)pbData,cbData,(PBYTE)pbResult);
    return TRUE;

}

BOOL
WINAPI
SHA256Hash(
    __in_bcount( cbData )   const unsigned char* pbData,
                            unsigned int   cbData,
    __out_bcount( SYMCRYPT_SHA256_RESULT_SIZE )
                            unsigned char*  pbResult )
{
    SymCryptSha256( (PCBYTE)pbData,cbData,(PBYTE)pbResult);
    return TRUE;
}

HASHALG_DATA g_HashAlgs[] = {
    { SymCryptMd5Algorithm ,    "MD5",      BCRYPT_MD5_ALGORITHM,       NULL        },
    { SymCryptSha1Algorithm,    "SHA1",     BCRYPT_SHA1_ALGORITHM,      SHA1Hash   },
    { SymCryptSha256Algorithm,  "SHA256",   BCRYPT_SHA256_ALGORITHM,    SHA256Hash },
    { SymCryptSha384Algorithm,  "SHA384",   BCRYPT_SHA384_ALGORITHM,    NULL },
    { SymCryptSha512Algorithm,  "SHA512",   BCRYPT_SHA512_ALGORITHM,    NULL },
};

// Translation algorithm from the implementation to its index:
//      SymCrypt => 0
//      MsBignum => 1
//      Cng      => 2
UINT32 testInteropImplToInd( AlgorithmImplementation * pImpl )
{
    if (pImpl == NULL)
    {
        CHECK( FALSE, "NULL implementation\n");
        return (UINT32)(-1);
    }
    else
    {
        for(UINT32 i=0; i<TEST_INTEROP_NUMOF_IMPS; i++)
        {
            if (pImpl->m_implementationName == g_Implementations[i].name)
            {
                return i;
            }
        }

        CHECK( FALSE, "Unknown implementation\n");
        return (UINT32)(-1);
    }
}

// Hash algorithms translations
VOID testInteropScToHashContext( PCSYMCRYPT_HASH pHashAlgorithm, PBYTE rgbDigest, hash_function_context* pHashFunCxt)
{
    pHashFunCxt->dwVersion = HASH_FUNCTION_STRUCTURE_VERSION;
    pHashFunCxt->pvContext = NULL;
    pHashFunCxt->pdwDigest = (PDWORD)rgbDigest;

    if (pHashAlgorithm == NULL)
    {
        CHECK( FALSE, "NULL hash algorithm\n");
    }
    else
    {
        for(UINT32 i=0; i<TEST_INTEROP_NUMOF_HASHALGS; i++)
        {
            if (pHashAlgorithm == g_HashAlgs[i].pHashAlgorithm)
            {
                pHashFunCxt->pfHash = g_HashAlgs[i].msBignumHashFunc;
                pHashFunCxt->cbDigest = (DWORD)SymCryptHashResultSize(pHashAlgorithm);
                return;
            }
        }

        CHECK( FALSE, "NULL hash algorithm\n");
    }
}

LPCWSTR testInteropScToCngHash( PSYMCRYPT_HASH pHashAlgorithm )
{
    if (pHashAlgorithm == NULL)
    {
        CHECK( FALSE, "NULL hash algorithm\n");
        return L"";
    }
    else
    {
        for(UINT32 i=0; i<TEST_INTEROP_NUMOF_HASHALGS; i++)
        {
            if (pHashAlgorithm == g_HashAlgs[i].pHashAlgorithm)
            {
                return g_HashAlgs[i].cngName;
            }
        }

        CHECK( FALSE, "Unknown hash algorithm\n");
        return L"";
    }
}

PCSYMCRYPT_HASH testInteropRandomHash()
{
    BYTE rand = 0;

    do
    {
        rand = g_rng.byte() & 0x07;
    } while (rand > TEST_INTEROP_NUMOF_HASHALGS-1);

    return g_HashAlgs[rand].pHashAlgorithm;
}

LPCSTR testInteropHashAlgToString( PCSYMCRYPT_HASH pHashAlgorithm )
{
    if (pHashAlgorithm == NULL)
    {
        return "NULL";
    }
    else
    {
        for(UINT32 i=0; i<TEST_INTEROP_NUMOF_HASHALGS; i++)
        {
            if (pHashAlgorithm == g_HashAlgs[i].pHashAlgorithm)
            {
                return g_HashAlgs[i].shortName;
            }
        }

        return "Unknown";
    }
}

VOID
testInteropReverseMemCopy(
    PBYTE pbDst,
    PBYTE pbSrc,
    SIZE_T cbSrc
)
{
    PBYTE p;

    p = pbDst + cbSrc - 1;
    while(p >= pbDst)
    {
        *p-- = *pbSrc++;
    }
}