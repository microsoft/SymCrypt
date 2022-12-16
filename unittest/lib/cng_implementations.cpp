//
// CNG implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#if INCLUDE_IMPL_CNG

char * ImpCng::name = "Cng";

#define BCRYPT_CHAIN_MODE_XXX   CONCAT2( BCRYPT_CHAIN_MODE_, ALG_MODE )

#define BCRYPT_SP800_108_ALGORITHM  BCRYPT_SP800108_CTR_HMAC_ALGORITHM
#define BCRYPT_TLSPRF1_1_ALGORITHM  BCRYPT_TLS1_1_KDF_ALGORITHM
#define BCRYPT_TLSPRF1_2_ALGORITHM  BCRYPT_TLS1_2_KDF_ALGORITHM

#define CngHmacMd5HashAlgNameU      BCRYPT_MD5_ALGORITHM
#define CngHmacSha1HashAlgNameU     BCRYPT_SHA1_ALGORITHM
#define CngHmacSha256HashAlgNameU   BCRYPT_SHA256_ALGORITHM
#define CngHmacSha384HashAlgNameU   BCRYPT_SHA384_ALGORITHM
#define CngHmacSha512HashAlgNameU   BCRYPT_SHA512_ALGORITHM
#define CngAesCmacHashAlgNameU      BCRYPT_AES_CMAC_ALGORITHM

ULONG g_cngKeySizeFlag = 0;
BCryptDeriveKeyPBKDF2Fn         CngPbkdf2Fn = NULL;
BCryptKeyDerivationFn           CngKeyDerivationFn = NULL;
BCryptCreateMultiHashFn         CngCreateMultiHashFn = NULL;
BCryptProcessMultiOperationsFn  CngProcessMultiOperationsFn = NULL;

// CNG crypto primitive functions defaulted to BCrypt implementations.
BCryptCloseAlgorithmProviderFn  CngCloseAlgorithmProviderFn = BCryptCloseAlgorithmProvider;
BCryptCreateHashFn              CngCreateHashFn = BCryptCreateHash;
BCryptDecryptFn                 CngDecryptFn = BCryptDecrypt;
BCryptDeriveKeyFn               CngDeriveKeyFn = BCryptDeriveKey;
BCryptDeriveKeyCapiFn           CngDeriveKeyCapiFn = BCryptDeriveKeyCapi;
BCryptDeriveKeyPBKDF2Fn         CngDeriveKeyPBKDF2Fn = BCryptDeriveKeyPBKDF2;
BCryptDestroyHashFn             CngDestroyHashFn = BCryptDestroyHash;
BCryptDestroyKeyFn              CngDestroyKeyFn = BCryptDestroyKey;
BCryptDestroySecretFn           CngDestroySecretFn = BCryptDestroySecret;
BCryptDuplicateHashFn           CngDuplicateHashFn = BCryptDuplicateHash;
BCryptDuplicateKeyFn            CngDuplicateKeyFn = BCryptDuplicateKey;
BCryptEncryptFn                 CngEncryptFn = BCryptEncrypt;
BCryptExportKeyFn               CngExportKeyFn = BCryptExportKey;
BCryptFinalizeKeyPairFn         CngFinalizeKeyPairFn = BCryptFinalizeKeyPair;
BCryptFinishHashFn              CngFinishHashFn = BCryptFinishHash;
BCryptGenerateKeyPairFn         CngGenerateKeyPairFn = BCryptGenerateKeyPair;
BCryptGenerateSymmetricKeyFn    CngGenerateSymmetricKeyFn = BCryptGenerateSymmetricKey;
BCryptGenRandomFn               CngGenRandomFn = BCryptGenRandom;
BCryptGetPropertyFn             CngGetPropertyFn = BCryptGetProperty;
BCryptHashFn                    CngHashFn = BCryptHash;
BCryptHashDataFn                CngHashDataFn = BCryptHashData;
BCryptImportKeyFn               CngImportKeyFn = BCryptImportKey;
BCryptImportKeyPairFn           CngImportKeyPairFn = BCryptImportKeyPair;
BCryptOpenAlgorithmProviderFn   CngOpenAlgorithmProviderFn = BCryptOpenAlgorithmProvider;
BCryptSecretAgreementFn         CngSecretAgreementFn = BCryptSecretAgreement;
BCryptSetPropertyFn             CngSetPropertyFn = BCryptSetProperty;
BCryptSignHashFn                CngSignHashFn = BCryptSignHash;
BCryptVerifySignatureFn         CngVerifySignatureFn = BCryptVerifySignature;

inline FARPROC WINAPI CheckedGetProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName)
{
    FARPROC procAddress = GetProcAddress(hModule, lpProcName);
    CHECK4(procAddress != NULL, "Could not GetProcAddress %s, %08x", lpProcName, GetLastError());
    return procAddress;
}

#ifndef BCRYPT_EXTENDED_KEYSIZE
// Definition from BCrypt.h which is NTDDI-filtered
#define BCRYPT_EXTENDED_KEYSIZE         0x00000080
#endif


VOID
SetCngKeySizeFlag()
{
    if( g_osVersion <= 0x0602 )
    {
        g_cngKeySizeFlag = 0;
    } else {
        g_cngKeySizeFlag = BCRYPT_EXTENDED_KEYSIZE;
    }
}

template<class Algorithm>
NTSTATUS
CngRc2KeySupport( BCRYPT_ALG_HANDLE hAlg, SIZE_T cbKey );

template<>
NTSTATUS
CngRc2KeySupport<AlgRc2>( BCRYPT_ALG_HANDLE hAlg, SIZE_T cbKey )
{
    ULONG kl = g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8*(ULONG)cbKey;
    BOOL suc;
    NTSTATUS status;

    if( g_osVersion <= 0x0602 )
    {
        suc = kl >= 40 && kl <= 128;
        if( !suc )
        {
            //
            // We know this will not work on <= Win8.
            //
            return STATUS_NOT_SUPPORTED;
        }
    } else {
        suc = kl >=16 && kl <= 1024;
    }

    status = CngSetPropertyFn( hAlg, BCRYPT_EFFECTIVE_KEY_LENGTH, (PBYTE) &kl, 4, 0 );

    if( suc & !NT_SUCCESS( status ) )
    {
        CHECK5( FALSE, "Failed to set RC2 effective key size, %04x, %04x, %d", status, g_osVersion, kl );
    }


    return status;
}

template<class Algorithm>
NTSTATUS
CngRc2KeySupport( BCRYPT_ALG_HANDLE hAlg, SIZE_T cbKey )
{
    UNREFERENCED_PARAMETER( hAlg );
    UNREFERENCED_PARAMETER( cbKey );
    return STATUS_SUCCESS;
}


VOID
AddBCryptBuffer( BCryptBufferDesc * pBufferDesc, ULONG BufferType, PCVOID pData, SIZE_T cbData )
{
    ULONG i = pBufferDesc->cBuffers++;
    pBufferDesc->pBuffers[i].BufferType = BufferType;
    pBufferDesc->pBuffers[i].cbBuffer = (ULONG) cbData;
    pBufferDesc->pBuffers[i].pvBuffer = (PVOID) pData;
}

ULONG
bcoapReusableFlag()
{
    if( g_osVersion < 0x0602 )
    {
        return 0;
    }
    return BCRYPT_HASH_REUSABLE_FLAG;
}

// The following function checks if BCrypt supports
// AES CMAC with the HMAC flag set. This means that
// PBKDF2 and SP800-108 in CNG accept AES CMAC.
// Supported in Threshold and above (no version #
// set yet)
BOOL
cngAesCmac_HmacMode()
{
    NTSTATUS Status = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;

    Status = CngOpenAlgorithmProviderFn(
        &hAlg,
        BCRYPT_AES_CMAC_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);

    if (hAlg != NULL)
    {
        CngCloseAlgorithmProviderFn(hAlg, 0);
    }

    return (Status == STATUS_SUCCESS);
}

#define IMP_NAME    CNG
#define IMP_Name    Cng

#define ALG_NAME    MD2
#define ALG_Name    Md2
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    MD4
#define ALG_Name    Md4
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    MD5
#define ALG_Name    Md5
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA1
#define ALG_Name    Sha1
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA256
#define ALG_Name    Sha256
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA384
#define ALG_Name    Sha384
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA512
#define ALG_Name    Sha512
#include "cng_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define SYMCRYPT_PARALLELSHA256_RESULT_SIZE SYMCRYPT_SHA256_RESULT_SIZE
#define SYMCRYPT_PARALLELSHA384_RESULT_SIZE SYMCRYPT_SHA384_RESULT_SIZE
#define SYMCRYPT_PARALLELSHA512_RESULT_SIZE SYMCRYPT_SHA512_RESULT_SIZE

#define ALG_NAME    PARALLELSHA256
#define ALG_Name    ParallelSha256
#include "cng_imp_parallelhashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    PARALLELSHA384
#define ALG_Name    ParallelSha384
#include "cng_imp_parallelhashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    PARALLELSHA512
#define ALG_Name    ParallelSha512
#include "cng_imp_parallelhashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


#define MAC_PROVIDER_NAME( A ) CONCAT3( BCRYPT_, A, _ALGORITHM )

#define BCRYPT_HMAC_MD5_ALGORITHM   BCRYPT_MD5_ALGORITHM
#define BCRYPT_HMAC_SHA1_ALGORITHM   BCRYPT_SHA1_ALGORITHM
#define BCRYPT_HMAC_SHA256_ALGORITHM   BCRYPT_SHA256_ALGORITHM
#define BCRYPT_HMAC_SHA384_ALGORITHM   BCRYPT_SHA384_ALGORITHM
#define BCRYPT_HMAC_SHA512_ALGORITHM   BCRYPT_SHA512_ALGORITHM

#define BCOAP_FLAGS     BCRYPT_ALG_HANDLE_HMAC_FLAG

#define ALG_NAME    HMAC_MD5
#define ALG_Name    HmacMd5
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA1
#define ALG_Name    HmacSha1
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA256
#define ALG_Name    HmacSha256
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA384
#define ALG_Name    HmacSha384
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA512
#define ALG_Name    HmacSha512
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#undef BCOAP_FLAGS
#define BCOAP_FLAGS 0

#define ALG_NAME    AES_CMAC
#define ALG_Name    AesCmac
#include "cng_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#undef BCOAP_FLAGS

#define PROVIDER_NAME( A )  CONCAT3( BCRYPT_, A, _ALGORITHM )


#define ALG_NAME    AES
#define ALG_Name    Aes

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode



#define ALG_Mode    Ccm
#define ALG_MODE    CCM
#include "cng_imp_authenc.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Gcm
#define ALG_MODE    GCM
#include "cng_imp_authenc.cpp"
#undef ALG_MODE
#undef ALG_Mode


#undef ALG_Name
#undef ALG_NAME


#define ALG_NAME    DES
#define ALG_Name    Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    2DES
#define ALG_Name    2Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    3DES
#define ALG_Name    3Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    DESX
#define ALG_Name    Desx

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode



#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    RC2
#define ALG_Name    Rc2

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "cng_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME



#define ALG_NAME    PBKDF2
#define ALG_Name    Pbkdf2

#define ALG_Base    HmacMd5
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha1
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha256
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    AesCmac
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SP800_108
#define ALG_Name    Sp800_108

#define ALG_Base    HmacMd5
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha1
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha256
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    AesCmac
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_sp800_108pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    TLSPRF1_1
#define ALG_Name    TlsPrf1_1

#define ALG_Base    HmacMd5
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_tlsprf1_1pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    TLSPRF1_2
#define ALG_Name    TlsPrf1_2

#define ALG_Base    HmacSha256
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "cng_imp_kdfpattern.cpp"
#include "cng_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name


#undef IMP_NAME
#undef IMP_Name



template<>
std::set<SIZE_T>
AuthEncImp<ImpCng, AlgAes, ModeCcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    for( int i=7; i<=13; i++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpCng, AlgAes, ModeGcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}



//////////////////////////
// RC4

BCRYPT_ALG_HANDLE StreamCipherImpState<ImpCng, AlgRc4>::hAlg;

template<>
VOID
algImpKeyPerfFunction< ImpCng, AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_ALG_HANDLE hAlg = StreamCipherImpState<ImpCng, AlgRc4>::hAlg;
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngGenerateSymmetricKeyFn(
                            hAlg,
                            &hKey,
                            buf1 + 16, 768,
                            buf2, (ULONG) keySize,
                            g_cngKeySizeFlag ) ),
           "Error importing key" );


    *(BCRYPT_KEY_HANDLE *) buf1 = hKey;
}

template<>
VOID
algImpDataPerfFunction<ImpCng,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS status;
    ULONG res;
    status = CngEncryptFn( *(BCRYPT_KEY_HANDLE *)buf1, buf2, (ULONG) dataSize, NULL, NULL, 0, buf3, (ULONG) dataSize, &res, 0 );
    CHECK3( NT_SUCCESS( status ), "BcryptEncrypt error %08x", status );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyKeyFn( *(BCRYPT_KEY_HANDLE *) buf1 ) ), "?" );
}


StreamCipherImp<ImpCng, AlgRc4>::StreamCipherImp()
{
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, PROVIDER_NAME( RC4 ), NULL, 0 ) == STATUS_SUCCESS,
        "Could not open CNG/" STRING( ALG_Name ) );

    state.hKey = 0;
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpCng, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpCng, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpCng, AlgRc4>;
}

template<>
StreamCipherImp<ImpCng, AlgRc4>::~StreamCipherImp()
{
    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
    }
    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/" STRING( ALG_Name ) );
    state.hAlg = 0;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpCng, AlgRc4>::getNonceSizes()
{
    std::set<SIZE_T> res;

    // No nonce sizes supported for RC4

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpCng, AlgRc4>::getKeySizes()
{
    std::set<SIZE_T> res;
    SIZE_T maxKeySize;

    if( g_osVersion <= 0x0602 )
    {
        //
        // Win8 and before truncate keys > 64 bytes.
        //
        maxKeySize = 64;
    } else {
        maxKeySize = 256;
    }

    for( SIZE_T i=1; i<=maxKeySize; i++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpCng, AlgRc4>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    UNREFERENCED_PARAMETER( pbNonce );

    CHECK( cbNonce == 0, "RC4 does not take a nonce" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpCng, AlgRc4>::setOffset( UINT64 offset )
{
    UNREFERENCED_PARAMETER( offset );
    CHECK( FALSE, "RC4 is not random access" );
}

template<>
NTSTATUS
StreamCipherImp<ImpCng, AlgRc4>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    NTSTATUS status;

    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
    }

    if( g_osVersion <= 0x0602 && cbKey > 64 )
    {
        //
        // Win8 and before truncate longer keys, we have to fail the manually
        //
        return STATUS_UNSUCCESSFUL;
    }

    status = CngGenerateSymmetricKeyFn(
                            state.hAlg,
                            &state.hKey,
                            &state.keyObjectBuffer[0], sizeof( state.keyObjectBuffer ),
                            (PBYTE) pbKey, (ULONG) cbKey,
                            g_cngKeySizeFlag );

    return status;
}

template<>
VOID
StreamCipherImp<ImpCng, AlgRc4>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{

    ULONG res;
    CHECK( NT_SUCCESS( CngEncryptFn( state.hKey, (PBYTE) pbSrc, (ULONG) cbData, NULL, NULL, 0, pbDst, (ULONG) cbData, &res, 0 ) ),
        "Encryption error" );
    CHECK( res == cbData, "?" );
}




template<>
VOID
algImpDataPerfFunction<ImpCng,AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );

    CHECK( NT_SUCCESS(CngGenRandomFn( NULL, buf3, (ULONG) dataSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG )), "?" );
}

template<>
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::RngSp800_90Imp()
{
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpCng, AlgAesCtrDrbg>;
}

template<>
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::~RngSp800_90Imp()
{
}

template<>
NTSTATUS
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    UNREFERENCED_PARAMETER( pbEntropy );
    UNREFERENCED_PARAMETER( cbEntropy );

    //
    // Return an error so that we opt out of the known-answer test.
    //
    return STATUS_NOT_IMPLEMENTED;
}


template<>
NTSTATUS
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    UNREFERENCED_PARAMETER( pbEntropy );
    UNREFERENCED_PARAMETER( cbEntropy );

    //
    // Return an error so that we opt out of the known-answer test.
    //
    return STATUS_NOT_IMPLEMENTED;
}

template<>
VOID
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{
    CHECK( NT_SUCCESS(CngGenRandomFn( NULL, pbData, (ULONG) cbData, BCRYPT_USE_SYSTEM_PREFERRED_RNG )), "?" );
}


template<>
VOID
algImpKeyPerfFunction< ImpCng, AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    ULONG dataUnitSize = 512;

    CHECK( NT_SUCCESS( CngGenerateSymmetricKeyFn( BCRYPT_XTS_AES_ALG_HANDLE, (BCRYPT_KEY_HANDLE *) buf1, buf1 + 64, 2048, buf2, (ULONG)keySize, 0 ) ), "?" );
    CHECK( NT_SUCCESS( CngSetPropertyFn( *(BCRYPT_KEY_HANDLE *) buf1, BCRYPT_MESSAGE_BLOCK_LENGTH, (PBYTE)&dataUnitSize, sizeof( dataUnitSize ), 0 ) ), "?" );
}

template<>
VOID
algImpDataPerfFunction<ImpCng,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONGLONG tweak = 'twek';
    ULONG res;
    CHECK( NT_SUCCESS( CngEncryptFn( *(BCRYPT_KEY_HANDLE*) buf1, buf2, (ULONG)dataSize, NULL, (PBYTE)&tweak, 8, buf3, (ULONG) dataSize, &res, 0 ) ), "?" );
}

template<>
VOID
algImpDecryptPerfFunction<ImpCng,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONGLONG tweak = 'twek';
    ULONG res;
    CHECK( NT_SUCCESS( CngDecryptFn( *(BCRYPT_KEY_HANDLE*) buf1, buf2, (ULONG) dataSize, NULL, (PBYTE)&tweak, 8, buf3, (ULONG) dataSize, &res, 0 ) ), "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyKeyFn( *(BCRYPT_KEY_HANDLE *) buf1 ) ), "?" );
}


template<>
XtsImp<ImpCng, AlgXtsAes>::XtsImp()
{
    DWORD res;

    state.hKey = 0;

    CHECK( CngGetPropertyFn( BCRYPT_XTS_AES_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PBYTE)&state.keyObjSize, sizeof( DWORD ), &res, 0 ) == STATUS_SUCCESS && res == sizeof( DWORD ),
    "Could not get Authenc small object size" );

    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgXtsAes>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgXtsAes>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgXtsAes>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgXtsAes>;
}

template<>
XtsImp<ImpCng, AlgXtsAes>::~XtsImp()
{
    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey )), "?");
        state.hKey = 0;
    }
}

template<>
NTSTATUS
XtsImp<ImpCng, AlgXtsAes>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    NTSTATUS status = STATUS_SUCCESS;
    BYTE blob[1024];
    ULONG cbBlob;
    static int keyType = 0;
    PBYTE   pKeyObject;
    DWORD   cbKeyObject;

    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
        CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    }

    keyType = (keyType + 1) % 2;
    switch( keyType )
    {
    case 0:
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSize;
        break;
    case 1:
        pKeyObject = NULL;
        cbKeyObject = 0;
        break;
    default:
        CHECK( FALSE, "?" );
        goto Cleanup;
    }
    //iprint( "%c", '0' + keyType );

    CHECK( cbKeyObject <= sizeof( state.keyObjectBuffer ) - 4, "?" );
    state.pMagic = (ULONG *) &state.keyObjectBuffer[cbKeyObject];

    *state.pMagic = 'ntft';

    status = CngGenerateSymmetricKeyFn(
                            BCRYPT_XTS_AES_ALG_HANDLE,
                            &state.hKey,
                            pKeyObject, cbKeyObject,
                            (PBYTE) pbKey, (ULONG) cbKey,
                            g_cngKeySizeFlag );

    if( !NT_SUCCESS( status ) )
    {
        return status;
    }

    //
    // Test the opaque blob import/export
    // Can be removed once this is part of the CNG BVTs
    //

    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );

    CHECK( NT_SUCCESS( CngExportKeyFn( state.hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, sizeof( blob ), &cbBlob, 0 ) ), "Opaque blob export error" );
    CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    CHECK( NT_SUCCESS( CngImportKeyFn( BCRYPT_XTS_AES_ALG_HANDLE, NULL, BCRYPT_OPAQUE_KEY_BLOB, &state.hKey, pKeyObject, cbKeyObject, blob, cbBlob, 0 ) ), "Opaque blob import error" );

    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );

Cleanup:
    return status;



}

template<>
VOID
XtsImp<ImpCng, AlgXtsAes>::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    ULONG dataUnitSize = (ULONG) cbDataUnit;
    ULONG res;

    CHECK( NT_SUCCESS( CngSetPropertyFn( state.hKey, BCRYPT_MESSAGE_BLOCK_LENGTH, (PBYTE)&dataUnitSize, sizeof( dataUnitSize ), 0 ) ), "?" );
    CHECK( NT_SUCCESS( CngEncryptFn( state.hKey, (PBYTE)pbSrc, (ULONG) cbData, NULL, (PBYTE)&tweak, 8, pbDst, (ULONG) cbData, &res, 0 ) ), "?" );
    CHECK( res == cbData, "?" );
}

template<>
VOID
XtsImp<ImpCng, AlgXtsAes>::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    ULONG dataUnitSize = (ULONG) cbDataUnit;
    ULONG res;

    CHECK( NT_SUCCESS( CngSetPropertyFn( state.hKey, BCRYPT_MESSAGE_BLOCK_LENGTH, (PBYTE)&dataUnitSize, sizeof( dataUnitSize ), 0 ) ), "?" );
    CHECK( NT_SUCCESS( CngDecryptFn( state.hKey, (PBYTE)pbSrc, (ULONG) cbData, NULL, (PBYTE)&tweak, 8, pbDst, (ULONG) cbData, &res, 0 ) ), "?" );
    CHECK( res == cbData, "?" );
}

//
// TLS-CBC-HMAC-VERIFY
//

// TLS-CBC-HMAC-VERIFY-SHA1
template<>
VOID
algImpKeyPerfFunction< ImpCng, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    CHECK( NT_SUCCESS(CngCreateHashFn( BCRYPT_HMAC_SHA1_ALG_HANDLE, (BCRYPT_HASH_HANDLE *)buf1, buf1 + 16, PERF_BUFFER_SIZE - 16, buf3, (ULONG)keySize, 0 )), "" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng,AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyHashFn( *(BCRYPT_HASH_HANDLE *) buf1 ) ), "?" );
}

template<>
VOID
algImpDataPerfFunction<ImpCng,AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;
    UINT32 paddingSize;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (UINT32)dataSize, 0 )), "?" );
    CHECK( NT_SUCCESS( CngFinishHashFn( hHash, &buf3[dataSize], SYMCRYPT_HMAC_SHA1_RESULT_SIZE, 0 )), "?" );

    paddingSize = 15 - (dataSize & 15);
    memset( &buf3[dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpCng,AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (((UINT32)dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA1_RESULT_SIZE, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG )), "?" );
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha1>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpCng, AlgTlsCbcHmacSha1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpCng, AlgTlsCbcHmacSha1>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpCng, AlgTlsCbcHmacSha1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgTlsCbcHmacSha1>;
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha1>::~TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha1>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha1>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
                            SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
                            SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
                            SIZE_T  cbData )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash;
    BCRYPT_HASH_HANDLE hHash2;

    CHECK( cbKey > 0, "No key provided" );

    CHECK( NT_SUCCESS( CngCreateHashFn( BCRYPT_HMAC_SHA1_ALG_HANDLE, &hHash, NULL, 0, (PBYTE)pbKey, (UINT32) cbKey, 0)), "?" );
    if( (pbKey[0] & 1) == 1 )
    {
        CHECK( NT_SUCCESS( CngDuplicateHashFn( hHash, &hHash2, NULL, 0, 0 ) ), "?" );
        CHECK( NT_SUCCESS( CngDestroyHashFn( hHash )), "?" );
        hHash = hHash2;
        hHash2 = 0;
    }
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, (PBYTE)pbHeader, (UINT32) cbHeader, 0 ) ), "?" );
    Status = CngHashDataFn( hHash, (PBYTE)pbData, (UINT32) cbData, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG );
    CHECK( NT_SUCCESS( CngDestroyHashFn( hHash)), "?" );

    return Status;
}

// TLS-CBC-HMAC-VERIFY-SHA256
template<>
VOID
algImpKeyPerfFunction< ImpCng, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    CHECK( NT_SUCCESS(CngCreateHashFn( BCRYPT_HMAC_SHA256_ALG_HANDLE, (BCRYPT_HASH_HANDLE *)buf1, buf1 + 16, PERF_BUFFER_SIZE - 16, buf3, (ULONG)keySize, 0 )), "" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng,AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyHashFn( *(BCRYPT_HASH_HANDLE *) buf1 ) ), "?" );
}

template<>
VOID
algImpDataPerfFunction<ImpCng,AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;
    UINT32 paddingSize;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (UINT32)dataSize, 0 )), "?" );
    CHECK( NT_SUCCESS( CngFinishHashFn( hHash, &buf3[dataSize], SYMCRYPT_HMAC_SHA256_RESULT_SIZE, 0 )), "?" );

    paddingSize = 15 - (dataSize & 15);
    memset( &buf3[dataSize + SYMCRYPT_HMAC_SHA256_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpCng,AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (((UINT32)dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA256_RESULT_SIZE, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG )), "?" );
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha256>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpCng, AlgTlsCbcHmacSha256>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpCng, AlgTlsCbcHmacSha256>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpCng, AlgTlsCbcHmacSha256>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgTlsCbcHmacSha256>;
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha256>::~TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha256>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha256>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
                            SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
                            SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
                            SIZE_T  cbData )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash;
    BCRYPT_HASH_HANDLE hHash2;

    CHECK( cbKey > 0, "No key provided" );

    CHECK( NT_SUCCESS( CngCreateHashFn( BCRYPT_HMAC_SHA256_ALG_HANDLE, &hHash, NULL, 0, (PBYTE)pbKey, (UINT32) cbKey, 0)), "?" );
    if( (pbKey[0] & 1) == 1 )
    {
        CHECK( NT_SUCCESS( CngDuplicateHashFn( hHash, &hHash2, NULL, 0, 0 ) ), "?" );
        CHECK( NT_SUCCESS( CngDestroyHashFn( hHash )), "?" );
        hHash = hHash2;
        hHash2 = 0;
    }
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, (PBYTE)pbHeader, (UINT32) cbHeader, 0 ) ), "?" );
    Status = CngHashDataFn( hHash, (PBYTE)pbData, (UINT32) cbData, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG );
    CHECK( NT_SUCCESS( CngDestroyHashFn( hHash)), "?" );

    return Status;
}

// TLS-CBC-HMAC-VERIFY-SHA384
template<>
VOID
algImpKeyPerfFunction< ImpCng, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    CHECK( NT_SUCCESS(CngCreateHashFn( BCRYPT_HMAC_SHA384_ALG_HANDLE, (BCRYPT_HASH_HANDLE *)buf1, buf1 + 16, PERF_BUFFER_SIZE - 16, buf3, (ULONG)keySize, 0 )), "" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng,AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyHashFn( *(BCRYPT_HASH_HANDLE *) buf1 ) ), "?" );
}

template<>
VOID
algImpDataPerfFunction<ImpCng,AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;
    UINT32 paddingSize;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (UINT32)dataSize, 0 )), "?" );
    CHECK( NT_SUCCESS( CngFinishHashFn( hHash, &buf3[dataSize], SYMCRYPT_HMAC_SHA384_RESULT_SIZE, 0 )), "?" );

    paddingSize = 15 - (dataSize & 15);
    memset( &buf3[dataSize + SYMCRYPT_HMAC_SHA384_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpCng,AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE hHash = *(BCRYPT_HASH_HANDLE *) buf1;

    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf2, 13, 0 )), "?" );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, buf3, (((UINT32)dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA384_RESULT_SIZE, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG )), "?" );
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha384>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpCng, AlgTlsCbcHmacSha384>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpCng, AlgTlsCbcHmacSha384>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpCng, AlgTlsCbcHmacSha384>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgTlsCbcHmacSha384>;
}

template<>
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha384>::~TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha384>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha384>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
                            SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
                            SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
                            SIZE_T  cbData )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash;
    BCRYPT_HASH_HANDLE hHash2;

    CHECK( cbKey > 0, "No key provided" );

    CHECK( NT_SUCCESS( CngCreateHashFn( BCRYPT_HMAC_SHA384_ALG_HANDLE, &hHash, NULL, 0, (PBYTE)pbKey, (UINT32) cbKey, 0)), "?" );
    if( (pbKey[0] & 1) == 1 )
    {
        CHECK( NT_SUCCESS( CngDuplicateHashFn( hHash, &hHash2, NULL, 0, 0 ) ), "?" );
        CHECK( NT_SUCCESS( CngDestroyHashFn( hHash )), "?" );
        hHash = hHash2;
        hHash2 = 0;
    }
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, (PBYTE)pbHeader, (UINT32) cbHeader, 0 ) ), "?" );
    Status = CngHashDataFn( hHash, (PBYTE)pbData, (UINT32) cbData, BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG );
    CHECK( NT_SUCCESS( CngDestroyHashFn( hHash)), "?" );

    return Status;
}


// Table with the RSA keys' sizes and pointers to keys
struct {
    SIZE_T                      keySize;
    BCRYPT_KEY_HANDLE           pkRsakey;
} g_precomputedCngRsaKeys[] = {
    {  32, NULL },
    {  64, NULL },
    { 128, NULL },
    { 256, NULL },
    { 384, NULL },
    { 512, NULL },
    {1024, NULL },
};

void
SetupCngRsaKey( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bFound = FALSE;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    for( i=0; i < ARRAY_SIZE(g_precomputedCngRsaKeys); i++ )
    {
        if ( keySize == g_precomputedCngRsaKeys[i].keySize )
        {
            bFound = TRUE;

            if ( g_precomputedCngRsaKeys[i].pkRsakey == NULL )
            {
                ntStatus = CngOpenAlgorithmProviderFn(
                                &hAlg,
                                BCRYPT_RSA_ALGORITHM,
                                MS_PRIMITIVE_PROVIDER,
                                0 );
                CHECK( ntStatus == STATUS_SUCCESS, "?" );

                ntStatus = CngGenerateKeyPairFn(
                                hAlg,
                                &hKey,
                                ((ULONG)keySize) * 8,
                                0 );
                CHECK( ntStatus == STATUS_SUCCESS, "?" );

                ntStatus = CngFinalizeKeyPairFn(
                                hKey,
                                0 );
                CHECK( ntStatus == STATUS_SUCCESS, "?" );

                ntStatus = CngCloseAlgorithmProviderFn( hAlg, 0 );
                CHECK( ntStatus == STATUS_SUCCESS, "?" );

                g_precomputedCngRsaKeys[i].pkRsakey = hKey;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((BCRYPT_KEY_HANDLE *) buf1) = g_precomputedCngRsaKeys[i].pkRsakey;
}

void
cng_RsaKeyPerf( PBYTE buf1, PBYTE buf2, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SetupCngRsaKey( buf1, keySize );

    buf2[0] = 0;
    scError = SymCryptCallbackRandom( buf2 + 1, keySize - 1 );  // Don't fill it up so that it is smaller than the modulus
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}


typedef struct _CNG_HASH_INFO {
    PCSTR   name;
    LPCWSTR wideName;
} CNG_HASH_INFO;
typedef const CNG_HASH_INFO * PCCNG_HASH_INFO;

const CNG_HASH_INFO cngHashInfoTable[] = {
    {   "MD5",      L"MD5" },
    {   "SHA1",     L"SHA1" },
    {   "SHA256",   L"SHA256" },
    {   "SHA384",   L"SHA384" },
    {   "SHA512",   L"SHA512" },
    { NULL },
};

PCCNG_HASH_INFO getHashInfo( PCSTR pcstrName )
{
    for( int i=0; cngHashInfoTable[i].name != NULL; i++ )
    {
        if( STRICMP( pcstrName, cngHashInfoTable[i].name ) == 0 )
        {
            return &cngHashInfoTable[i];
        }
    }
    CHECK( FALSE, "?" );
    return NULL;
}


//================================================
// Rsa Pkcs1 Sign
template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbDst = 0;

    PBYTE pTmp = NULL;
    BCRYPT_PKCS1_PADDING_INFO * pPaddingInfo = NULL;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    // Create the padding info in the last bytes of buf2
    pTmp = buf2 + PERF_RSA_HASH_ALG_SIZE;
    pPaddingInfo = (BCRYPT_PKCS1_PADDING_INFO *) pTmp;

    pPaddingInfo->pszAlgId = PERF_RSA_HASH_ALG_CNG;

    ntStatus = CngSignHashFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    ntStatus = CngVerifySignatureFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    BCRYPT_PAD_PKCS1);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngSignHashFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            (ULONG) dataSize,
            &cbDst,
            BCRYPT_PAD_PKCS1);
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;

    ntStatus = CngVerifySignatureFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) dataSize,
                    BCRYPT_PAD_PKCS1);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}


template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpCng, AlgRsaSignPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPkcs1>;

    state.hKey = NULL;
}

template<>
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::~RsaSignImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_SIGN_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    NTSTATUS ntStatus;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;

    ntStatus = BCryptSignHash(
        state.hKey,
        &paddingInfo,
        (PBYTE) pbHash,
        (UINT32)cbHash,
        pbSig,
        (UINT32)cbSig,
        &cbResult,
        BCRYPT_PAD_PKCS1 );

    CHECK( NT_SUCCESS( ntStatus ) && cbResult == cbSig, "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    NTSTATUS ntStatus;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;

    ntStatus = BCryptVerifySignature(
        state.hKey,
        &paddingInfo,
        (PBYTE)pbHash,
        (UINT32)cbHash,
        (PBYTE)pbSig,
        (UINT32)cbSig,
        BCRYPT_PAD_PKCS1 );

    return ntStatus;
}


//================================================
// Rsa PSS Sign
template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbDst = 0;

    PBYTE pTmp = NULL;
    BCRYPT_PSS_PADDING_INFO * pPaddingInfo = NULL;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    // Create the padding info in the last bytes of buf2
    pTmp = buf2 + PERF_RSA_HASH_ALG_SIZE;
    pPaddingInfo = (BCRYPT_PSS_PADDING_INFO *) pTmp;

    pPaddingInfo->pszAlgId = PERF_RSA_HASH_ALG_CNG;
    pPaddingInfo->cbSalt = PERF_RSA_HASH_ALG_SIZE;

    ntStatus = CngSignHashFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    &cbDst,
                    BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    ntStatus = CngVerifySignatureFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngSignHashFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            (ULONG) dataSize,
            &cbDst,
            BCRYPT_PAD_PSS);
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;

    ntStatus = CngVerifySignatureFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) dataSize,
                    BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}


template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
RsaSignImp<ImpCng, AlgRsaSignPss>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaSignPss>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpCng, AlgRsaSignPss>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPss>;

    state.hKey = NULL;
}

template<>
RsaSignImp<ImpCng, AlgRsaSignPss>::~RsaSignImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPss>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_SIGN_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPss>::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    NTSTATUS ntStatus;
    BCRYPT_PSS_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;
    ULONG cbResult;

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;
    paddingInfo.cbSalt = u32Other;

    ntStatus = BCryptSignHash(
        state.hKey,
        &paddingInfo,
        (PBYTE) pbHash,
        (UINT32)cbHash,
        pbSig,
        (UINT32)cbSig,
        &cbResult,
        BCRYPT_PAD_PSS );

    CHECK( NT_SUCCESS( ntStatus ) && cbResult == cbSig, "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPss>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    NTSTATUS ntStatus;
    BCRYPT_PSS_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;
    paddingInfo.cbSalt = u32Other;

    ntStatus = BCryptVerifySignature(
        state.hKey,
        &paddingInfo,
        (PBYTE)pbHash,
        (UINT32)cbHash,
        (PBYTE)pbSig,
        (UINT32)cbSig,
        BCRYPT_PAD_PSS );

    // saml 2022/04:
    // In order to update error message returned from SymCryptRsaPssVerify and not break
    // multi-implementation test of SymCrypt vs. CNG, we must map STATUS_INVALID_SIGNATURE
    // to STATUS_INVALID_PARAMETER for now.
    // Once both CNG and SymCrypt are updated reliably we can reintroduce testing that the two
    // error responses cohere - but for now they won't.
    if( ntStatus == STATUS_INVALID_SIGNATURE )
    {
        ntStatus = STATUS_INVALID_PARAMETER;
    }

    return ntStatus;
}

// Rsa Encryption

template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE rbResult[1024] = { 0 };
    ULONG cbDst = 0;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)keySize,
                    NULL,
                    NULL,
                    0,
                    buf3,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_NONE );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    CHECK( sizeof(rbResult) >= keySize, "?" );

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)keySize,
                    NULL,
                    NULL,
                    0,
                    rbResult,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_NONE );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );
    CHECK( memcmp(buf2, rbResult, cbDst) == 0, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngEncryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf2,
            (ULONG)dataSize,
            NULL,
            NULL,
            0,
            buf3,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_NONE );
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;
    ULONG cbDst;

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)dataSize,
                    NULL,
                    NULL,
                    0,
                    buf2 + dataSize,
                    (ULONG)dataSize,
                    &cbDst,
                    BCRYPT_PAD_NONE );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<>
RsaEncImp<ImpCng, AlgRsaEncRaw>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncRaw>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgRsaEncRaw>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncRaw>;

    state.hKey = NULL;
}

template<>
RsaEncImp<ImpCng, AlgRsaEncRaw>::~RsaEncImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncRaw>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncRaw>::encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext )
{
    NTSTATUS ntStatus;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    CHECK( cbMsg == cbCiphertext, "?" );

    ntStatus = CngEncryptFn(
                    state.hKey,
                    (PBYTE)pbMsg, (ULONG)cbMsg,
                    NULL,
                    NULL, 0,
                    pbCiphertext, (ULONG)cbCiphertext,
                    &cbResult,
                    0 );

    if( ntStatus != STATUS_SUCCESS )
    {
        iprint( "ntStatus = %08x\n", ntStatus );
        iprint( "cbMsg = %d\n, cbResult = %d\n", cbMsg, cbResult );
    }
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbResult == cbMsg, "?" );

    return ntStatus;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncRaw>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    NTSTATUS ntStatus;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    ntStatus = CngDecryptFn(
                    state.hKey,
                    (PBYTE) pbCiphertext, (ULONG)cbCiphertext,
                    NULL,
                    NULL, 0,
                    pbMsg, (ULONG)cbMsg,
                    &cbResult,
                    0 );

    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbResult == cbCiphertext, "?" );

    *pcbMsg = cbResult;
    return ntStatus;
}

// RSA Pkcs1 encryption

template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE rbResult[1024] = { 0 };
    ULONG cbDst = 0;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)keySize - PERF_RSA_PKCS1_LESS_BYTES,     // This is the maximum size for PKCS1
                    NULL,
                    NULL,
                    0,
                    buf3,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    CHECK( sizeof(rbResult) >= keySize, "?" );

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)keySize,
                    NULL,
                    NULL,
                    0,
                    rbResult,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize - PERF_RSA_PKCS1_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, rbResult, cbDst) == 0, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngEncryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf2,
            (ULONG)dataSize - PERF_RSA_PKCS1_LESS_BYTES,        // This is the maximum size for PKCS1
            NULL,
            NULL,
            0,
            buf3,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_PKCS1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;
    ULONG cbDst;

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)dataSize,
                    NULL,
                    NULL,
                    0,
                    buf2 + dataSize,
                    (ULONG)dataSize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<>
RsaEncImp<ImpCng, AlgRsaEncPkcs1>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgRsaEncPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncPkcs1>;

    state.hKey = NULL;
}

template<>
RsaEncImp<ImpCng, AlgRsaEncPkcs1>::~RsaEncImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncPkcs1>::encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext )
{
    NTSTATUS ntStatus;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    CHECK( cbMsg < cbCiphertext, "?" );

    ntStatus = CngEncryptFn(
                    state.hKey,
                    (PBYTE)pbMsg, (ULONG)cbMsg,
                    NULL,
                    NULL, 0,
                    pbCiphertext, (ULONG)cbCiphertext,
                    &cbResult,
                    BCRYPT_PAD_PKCS1 );

    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbResult == cbCiphertext, "?" );

    return ntStatus;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncPkcs1>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    NTSTATUS ntStatus;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    ntStatus = CngDecryptFn(
                    state.hKey,
                    (PBYTE) pbCiphertext, (ULONG)cbCiphertext,
                    NULL,
                    NULL, 0,
                    pbMsg, (ULONG)cbMsg,
                    &cbResult,
                    BCRYPT_PAD_PKCS1 );

    // Normalize error code to allow equality testing across different implementations
    ntStatus = NT_SUCCESS( ntStatus ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    *pcbMsg = cbResult;
    return ntStatus;
}


// RSA Oaep encryption

template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbDst = 0;

    PBYTE pTmp = NULL;
    BCRYPT_OAEP_PADDING_INFO * pPaddingInfo = NULL;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    // Set the padding info at the end of buf2 (after the plaintext)
    pTmp = buf2 + keySize;
    pPaddingInfo = (BCRYPT_OAEP_PADDING_INFO *) pTmp;
    pPaddingInfo->pszAlgId = PERF_RSA_HASH_ALG_CNG;
    pPaddingInfo->pbLabel = buf2 + 2*keySize;                       // Use buf2 bytes as label
    pPaddingInfo->cbLabel = PERF_RSA_LABEL_LENGTH;

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)keySize - PERF_RSA_OAEP_LESS_BYTES,      // This is the maximum size for OAEP
                    (VOID *) (buf2 + keySize),
                    NULL,
                    0,
                    buf3,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)keySize,
                    (VOID *) (buf2 + keySize),
                    NULL,
                    0,
                    buf3 + keySize,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize - PERF_RSA_OAEP_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, buf3 + keySize, cbDst) == 0, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)dataSize - PERF_RSA_OAEP_LESS_BYTES,      // This is the maximum size for OAEP
                    (VOID *) (buf2 + dataSize),
                    NULL,
                    0,
                    buf3,
                    (ULONG)dataSize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == dataSize, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;
    ULONG cbDst;

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)dataSize,
                    (VOID *) (buf2 + dataSize),
                    NULL,
                    0,
                    buf3 + dataSize,
                    (ULONG)dataSize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == dataSize - PERF_RSA_OAEP_LESS_BYTES, "?" );
}

template<>
RsaEncImp<ImpCng, AlgRsaEncOaep>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncOaep>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgRsaEncOaep>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncOaep>;

    state.hKey = NULL;
}

template<>
RsaEncImp<ImpCng, AlgRsaEncOaep>::~RsaEncImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncOaep>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncOaep>::encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext )
{
    NTSTATUS ntStatus;
    ULONG cbResult;
    PCCNG_HASH_INFO pHashInfo;
    BCRYPT_OAEP_PADDING_INFO padding;

    pHashInfo = getHashInfo( pcstrHashAlgName);
    padding.pszAlgId = pHashInfo->wideName;
    padding.pbLabel = (PBYTE)pbLabel;
    padding.cbLabel = (ULONG)cbLabel;

    ntStatus = CngEncryptFn(
                    state.hKey,
                    (PBYTE)pbMsg, (ULONG)cbMsg,
                    &padding,
                    NULL, 0,
                    pbCiphertext, (ULONG)cbCiphertext,
                    &cbResult,
                    BCRYPT_PAD_OAEP );

    CHECK( cbResult == cbCiphertext, "Wrong ciphertext size" );

    return NT_SUCCESS( ntStatus ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
RsaEncImp<ImpCng, AlgRsaEncOaep>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    NTSTATUS ntStatus;
    ULONG cbResult;
    PCCNG_HASH_INFO pHashInfo;
    BCRYPT_OAEP_PADDING_INFO padding;

    pHashInfo = getHashInfo( pcstrHashAlgName);
    padding.pszAlgId = pHashInfo->wideName;
    padding.pbLabel = (PBYTE)pbLabel;
    padding.cbLabel = (ULONG)cbLabel;

    ntStatus = CngDecryptFn(
                    state.hKey,
                    (PBYTE) pbCiphertext, (ULONG)cbCiphertext,
                    &padding,
                    NULL, 0,
                    pbMsg, (ULONG)cbMsg,
                    &cbResult,
                    BCRYPT_PAD_OAEP );

    // Normalize error code to allow equality testing across different implementations
    ntStatus = NT_SUCCESS( ntStatus ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    *pcbMsg = cbResult;
    return ntStatus;
}



//================================================
// Diffie Hellman

template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    PCDLGROUP_TESTBLOB pGroupBlob;
    NTSTATUS ntStatus;
    BCRYPT_KEY_HANDLE hKey1, hKey2;
    BCRYPT_DH_PARAMETER_HEADER * pParams;

    UNREFERENCED_PARAMETER( buf3 );

    pGroupBlob = dlgroupForSize( 8*keySize, TRUE );
    CHECK( pGroupBlob != NULL, "Could not find DH group of right size" );
    CHECK( pGroupBlob->cbPrimeP == keySize, "?" );

    ntStatus = BCryptGenerateKeyPair(   BCRYPT_DH_ALG_HANDLE,
                                        &hKey1,
                                        8 * (ULONG) keySize,
                                        0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to generate DH key object" );

    ntStatus = BCryptGenerateKeyPair(   BCRYPT_DH_ALG_HANDLE,
                                        &hKey2,
                                        8 * (ULONG) keySize,
                                        0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to generate DH key object" );

    // Set up the BCRYPT_DH_PARAMETER_HEADER in buf2
    pParams = (BCRYPT_DH_PARAMETER_HEADER *) buf2;
    pParams->cbLength = sizeof( BCRYPT_DH_PARAMETER_HEADER) + 2 * (UINT32)keySize;
    pParams->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    pParams->cbKeyLength = (UINT32)keySize;
    memcpy( (PBYTE)(pParams + 1), &pGroupBlob->abPrimeP, keySize );
    memcpy( (PBYTE)(pParams + 1) + keySize, &pGroupBlob->abGenG, keySize );

    ntStatus = BCryptSetProperty(   hKey1,
                                    BCRYPT_DH_PARAMETERS,
                                    buf2, sizeof( *pParams ) + 2 * (ULONG)keySize,
                                    0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set DH group parameters" );

    ntStatus = BCryptSetProperty(   hKey2,
                                    BCRYPT_DH_PARAMETERS,
                                    buf2, sizeof( *pParams ) + 2 * (ULONG)keySize,
                                    0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set DH group parameters" );

    ntStatus = BCryptFinalizeKeyPair( hKey1, 0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set finalize DH key" );

    ntStatus = BCryptFinalizeKeyPair( hKey2, 0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set finalize DH key" );

    ((BCRYPT_KEY_HANDLE *)buf1)[0] = hKey1;
    ((BCRYPT_KEY_HANDLE *)buf1)[1] = hKey2;
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    NTSTATUS ntStatus;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    ntStatus = BCryptDestroyKey( ((BCRYPT_KEY_HANDLE *)buf1)[0] );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
    ntStatus = BCryptDestroyKey( ((BCRYPT_KEY_HANDLE *)buf1)[1] );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    PCDLGROUP_TESTBLOB pGroupBlob;
    NTSTATUS ntStatus;
    BCRYPT_KEY_HANDLE hKey;
    ULONG cbResult;
    BCRYPT_DH_PARAMETER_HEADER * pParams;

    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf3 );

    pGroupBlob = dlgroupForSize( 8* dataSize, TRUE );
    CHECK( pGroupBlob != NULL, "Could not find DH group of right size" );
    CHECK( pGroupBlob->cbPrimeP == dataSize, "?" );

    ntStatus = BCryptGenerateKeyPair(   BCRYPT_DH_ALG_HANDLE,
                                        &hKey,
                                        8 * (ULONG) dataSize,
                                        0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to generate DH key object" );

    // Set up the BCRYPT_DH_PARAMETER_HEADER in buf2
    pParams = (BCRYPT_DH_PARAMETER_HEADER *) buf2;
    pParams->cbLength = sizeof( BCRYPT_DH_PARAMETER_HEADER) + 2 * (UINT32)dataSize;
    pParams->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    pParams->cbKeyLength = (UINT32)dataSize;
    memcpy( (PBYTE)(pParams + 1), &pGroupBlob->abPrimeP, dataSize );
    memcpy( (PBYTE)(pParams + 1) + dataSize, &pGroupBlob->abGenG, dataSize );

    ntStatus = BCryptSetProperty(   hKey,
                                    BCRYPT_DH_PARAMETERS,
                                    buf2, sizeof( *pParams ) + 2 * (ULONG)dataSize,
                                    0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set DH group parameters" );

    ntStatus = BCryptFinalizeKeyPair( hKey, 0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set finalize DH key" );

    ntStatus = BCryptExportKey( hKey,
                                NULL,
                                BCRYPT_DH_PUBLIC_BLOB,
                                buf2,
                                10 * (ULONG)dataSize,
                                &cbResult,
                                0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed to set finalize DH key" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_SECRET_HANDLE hSecret;
    NTSTATUS ntStatus;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( buf3 );

    ntStatus = BCryptSecretAgreement(   ((BCRYPT_KEY_HANDLE *)buf1)[0],
                                        ((BCRYPT_KEY_HANDLE *)buf1)[1],
                                        &hSecret,
                                        0 );
    CHECK( NT_SUCCESS( ntStatus ), "?" );

    ntStatus = BCryptDeriveKey( hSecret,
                                BCRYPT_KDF_RAW_SECRET,  // This exists from BLUE and above
                                NULL,
                                buf2,
                                (ULONG)dataSize,
                                &cbResult,
                                0 );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
    CHECK( cbResult == dataSize, "Wrong result size" );

    ntStatus = BCryptDestroySecret( hSecret );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
}

template<>
DhImp<ImpCng, AlgDh>::DhImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgDh>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpCng, AlgDh>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgDh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgDh>;

    state.hKey = NULL;
}

template<>
DhImp<ImpCng, AlgDh>::~DhImp()
{
    if( state.hKey != NULL )
    {
        CHECK( NT_SUCCESS( BCryptDestroyKey( state.hKey ) ), "?" );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
DhImp<ImpCng, AlgDh>::setKey( PCDLKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE blobBuf[sizeof( BCRYPT_DH_KEY_BLOB) + 4 * DLKEY_MAXKEYSIZE];
    BCRYPT_DH_KEY_BLOB * pBlob = (BCRYPT_DH_KEY_BLOB *) blobBuf;
    PBYTE p;
    UINT32 cbP;
    UINT32 flags = 0;

    if( state.hKey != NULL )
    {
        CHECK( NT_SUCCESS( BCryptDestroyKey( state.hKey )), "?" );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        goto cleanup;
    }

    cbP = pcKeyBlob->pGroup->cbPrimeP;

    pBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
    pBlob->cbKey = cbP;
    p = (PBYTE) (pBlob + 1);

    memcpy( p, pcKeyBlob->pGroup->abPrimeP, cbP );
    p += cbP;
    memcpy( p, pcKeyBlob->pGroup->abGenG, cbP );
    p += cbP;
    memcpy( p, pcKeyBlob->abPubKey, cbP );
    p += cbP;
    SymCryptWipe( p, cbP );
    memcpy( p + cbP - pcKeyBlob->cbPrivKey, pcKeyBlob->abPrivKey, pcKeyBlob->cbPrivKey );
    p += cbP;

    if( pcKeyBlob->fPrivateModP )
    {
        // Having a private key mod P is incompatible with FIPS SP800-56ar3 checks
        // Ensure we have opted out of running these checks in BCrypt
        flags |= BCRYPT_NO_KEY_VALIDATION;
    }

    ntStatus = BCryptImportKeyPair( BCRYPT_DH_ALG_HANDLE,
                                    NULL,
                                    BCRYPT_DH_PRIVATE_BLOB,
                                    &state.hKey,
                                    blobBuf,
                                    (UINT32)(p - blobBuf),
                                    flags );
    CHECK( NT_SUCCESS( ntStatus ), "?" );

cleanup:
    return ntStatus;
}

template<>
NTSTATUS
DhImp<ImpCng,AlgDh>::sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,   // Must be on same group object
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE blobBuf[sizeof( BCRYPT_DH_KEY_BLOB) + 4 * DLKEY_MAXKEYSIZE];
    BCRYPT_DH_KEY_BLOB * pBlob = (BCRYPT_DH_KEY_BLOB *) blobBuf;
    PBYTE p;
    UINT32 cbP;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_SECRET_HANDLE hSecret;
    ULONG cbResult;

    cbP = pcPubkey->pGroup->cbPrimeP;

    pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    pBlob->cbKey = cbP;
    p = (PBYTE) (pBlob + 1);

    memcpy( p, pcPubkey->pGroup->abPrimeP, cbP );
    p += cbP;
    memcpy( p, pcPubkey->pGroup->abGenG, cbP );
    p += cbP;
    memcpy( p, pcPubkey->abPubKey, cbP );
    p += cbP;

    ntStatus = BCryptImportKeyPair( BCRYPT_DH_ALG_HANDLE,
                                    NULL,
                                    BCRYPT_DH_PUBLIC_BLOB,
                                    &hKey,
                                    blobBuf,
                                    (UINT32)(p - blobBuf),
                                    0 );
    CHECK( NT_SUCCESS( ntStatus ), "?" );

    ntStatus = BCryptSecretAgreement(   state.hKey,
                                        hKey,
                                        &hSecret,
                                        0 );
    CHECK4( NT_SUCCESS( ntStatus ), "Error during secret agreement %08x %08x", state.hKey, ntStatus );


    ntStatus = BCryptDeriveKey( hSecret,
                                BCRYPT_KDF_RAW_SECRET,  // This exists from BLUE and above
                                NULL,
                                blobBuf,
                                (ULONG) cbSecret,
                                &cbResult,
                                0 );
    CHECK( ntStatus == STATUS_SUCCESS, "BCryptDeriveKey failed." );
    CHECK( cbResult == cbSecret, "BCryptDeriveKey output wrong size");

    ReverseMemCopy( pbSecret, blobBuf, cbSecret );

    ntStatus = BCryptDestroySecret( hSecret );
    CHECK( NT_SUCCESS( ntStatus ), "?" );

    ntStatus = BCryptDestroyKey( hKey );
    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return STATUS_SUCCESS;
}


// DSA start

BCRYPT_KEY_HANDLE
DsaKeyBlobToHandle( PCDLKEY_TESTBLOB pcKeyBlob, BYTE * pbTmp )
{
    // Convert a test key blob to a CNG handle, or NULL
    PCDLGROUP_TESTBLOB pGroupBlob = pcKeyBlob->pGroup;
    UINT32 cbP = pGroupBlob->cbPrimeP;
    PBYTE pNext;
    BCRYPT_KEY_HANDLE hKey = NULL;
    SIZE_T blobSize = 0;
    BOOL predictSuccess;
    NTSTATUS ntStatus;

    // DSA key import is a bit weird due to the way the API grew over time.
    //  There are two blob formats, one for keys <= 1024 bits and one is for keys > 1024 bits.
    // There are also other restrictions
    // - bitsize of the key must be a multiple of 64 between 512 and 3072.
    // - group size must be 160 bits for keys <= 1024 bits, and 256 bits for keys > 1024 bits

    predictSuccess = (cbP % 8) == 0;
    predictSuccess &= cbP >= 512 / 8;       // Min key size for CNG
    predictSuccess &= cbP <= 3072 / 8;      // Max key size for CNG
    if( cbP <= 1024/8 )
    {
        // BCRYPT_DSA_KEY_BLOB for a group with size cbKey bytes is followed by
        // - Group Modulus P, cbKey bytes long
        // - Group Generator G, cbKey bytes long
        // - Public key H, cbKey bytes long
        // - private key X, optional, 20 bytes long
        if( pGroupBlob->cbPrimeQ != 20 )
        {
            // Wrong group size for CNG, we can't deal with this key
            goto cleanup;
        }
        BCRYPT_DSA_KEY_BLOB * pHeader = (BCRYPT_DSA_KEY_BLOB *) pbTmp;
        pNext = (PBYTE) (pHeader + 1);

        // Set the header fields.
        pHeader->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC;
        pHeader->cbKey = cbP;
        SymCryptWipe( &pHeader->Count, 4 );
        SymCryptWipe( &pHeader->Seed, 20 );     // We don't have a seed, use 0 and don't ask for a key validation
        memcpy( pHeader->q, pGroupBlob->abPrimeQ, 20 );     // Prime P is always 20 bytes

        memcpy( pNext, pGroupBlob->abPrimeP, cbP );
        pNext += cbP;
        memcpy( pNext, pGroupBlob->abGenG, cbP );
        pNext += cbP;
        memcpy( pNext, pcKeyBlob->abPubKey, cbP );
        pNext += cbP;
        memcpy( pNext, pcKeyBlob->abPrivKey, 20 );       // Private key is always 160 bits for this blob type
        pNext += 20;
        blobSize = pNext - pbTmp;
    } else {
        // BCRYPT_DSA_KEY_BLOB_V2 requires that
        //
        if( pGroupBlob->cbPrimeQ != 32 )
        {
            // Wrong size for CNG, can't deal with this key
            goto cleanup;
        }
        const UINT32 cbQ = 32;

        BCRYPT_DSA_KEY_BLOB_V2 * pHeader = (BCRYPT_DSA_KEY_BLOB_V2 *) pbTmp;
        pNext = (PBYTE) (pHeader + 1);

        pHeader->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC_V2;
        pHeader->cbKey = cbP;
        pHeader->hashAlgorithm = DSA_HASH_ALGORITHM_SHA256;
        pHeader->standardVersion = DSA_FIPS186_3;
        pHeader->cbSeedLength = cbQ;
        pHeader->cbGroupSize = cbQ;
        SymCryptWipe( pHeader->Count, 4 );

        SymCryptWipe( pNext, cbQ );  // Seed
        pNext += cbQ;

        memcpy( pNext, pGroupBlob->abPrimeQ, cbQ );
        pNext += cbQ;

        memcpy( pNext, pGroupBlob->abPrimeP, cbP );
        pNext += cbP;

        memcpy( pNext, pGroupBlob->abGenG, cbP );
        pNext += cbP;

        memcpy( pNext, pcKeyBlob->abPubKey, cbP );
        pNext += cbP;

        memcpy( pNext, pcKeyBlob->abPrivKey, cbQ );
        pNext += cbQ;

        blobSize = pNext - pbTmp;
    }

    ntStatus = BCryptImportKeyPair( BCRYPT_DSA_ALG_HANDLE,
                                    NULL,
                                    BCRYPT_DSA_PRIVATE_BLOB,
                                    &hKey,
                                    pbTmp, (UINT32) blobSize,
                                    BCRYPT_NO_KEY_VALIDATION );
    CHECK( NT_SUCCESS( ntStatus ) == predictSuccess, "Unexpected BCryptImportKeyPair(DSA) result" );

cleanup:
    return hKey;
}


template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus;
    BCRYPT_KEY_HANDLE hKey;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    // Future: it would be better to use a DL group and/or key that is already generated, but
    // this is simpler

    ntStatus = BCryptGenerateKeyPair( BCRYPT_DSA_ALG_HANDLE, &hKey, (UINT32)keySize * 8, 0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed BCryptGenerateKeyPair for DSA" );

    ntStatus = BCryptFinalizeKeyPair( hKey, 0 );
    CHECK( NT_SUCCESS( ntStatus ), "Failed BCryptFinalizeKeyPair for DSA" );

    *(BCRYPT_KEY_HANDLE *)buf1 = hKey;
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    NTSTATUS ntStatus;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    ntStatus = BCryptDestroyKey( ((BCRYPT_KEY_HANDLE *)buf1)[0] );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;

    UINT32 groupSize = dataSize <= 1024/8 ? 20 : 32;
    ULONG cbResult;

    ntStatus = BCryptSignHash(  *(BCRYPT_KEY_HANDLE *) buf1,
                                NULL,
                                buf2, groupSize,
                                buf3, 2*groupSize,
                                &cbResult,
                                0 );
    CHECK( NT_SUCCESS( ntStatus ) && cbResult == 2*groupSize, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpCng, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS ntStatus;

    UINT32 groupSize = dataSize <= 1024/8 ? 20 : 32;

    ntStatus = BCryptVerifySignature(   *(BCRYPT_KEY_HANDLE *) buf1,
                                        NULL,
                                        buf2, groupSize,
                                        buf3, 2*groupSize,
                                        0 );
    CHECK( NT_SUCCESS( ntStatus ), "?" );
}


template<>
DsaImp<ImpCng, AlgDsa>::DsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgDsa>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpCng, AlgDsa>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgDsa>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgDsa>;

    state.hKey = NULL;
}

template<>
DsaImp<ImpCng, AlgDsa>::~DsaImp()
{
    if( state.hKey != NULL )
    {
        CHECK( NT_SUCCESS( BCryptDestroyKey( state.hKey ) ), "?" );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
DsaImp<ImpCng, AlgDsa>::setKey( PCDLKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE buf[7 * DLKEY_MAXKEYSIZE ];    // Big enough for CNG header + fields of import blob

    if( state.hKey != NULL )
    {
        CHECK( NT_SUCCESS( BCryptDestroyKey( state.hKey )), "?" );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        goto cleanup;
    }

    state.hKey = DsaKeyBlobToHandle( pcKeyBlob, buf );
    state.cbP = pcKeyBlob->pGroup->cbPrimeP;
    state.cbQ = pcKeyBlob->pGroup->cbPrimeQ;

    ntStatus = state.hKey == NULL ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;

cleanup:
    return ntStatus;
}

template<>
NTSTATUS
DsaImp<ImpCng,AlgDsa>::sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbResult;

    if( cbHash != state.cbQ )
    {
        ntStatus = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    ntStatus = BCryptSignHash( state.hKey, NULL, (PBYTE)pbHash, (ULONG)cbHash, pbSig, (ULONG)cbSig, &cbResult, 0 );

    CHECK( cbResult == cbSig, "Signature length mismatch" );

    // Normalize the status code so that the MultiImp can directly compare two results
    ntStatus = NT_SUCCESS( ntStatus ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

cleanup:
    return ntStatus;
}

template<>
NTSTATUS
DsaImp<ImpCng,AlgDsa>::verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig )
{
    NTSTATUS ntStatus;

    if( cbHash != state.cbQ )
    {
        ntStatus = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    ntStatus = BCryptVerifySignature(   state.hKey,
                                        NULL,
                                        (PBYTE)pbHash, (ULONG)cbHash,
                                        (PBYTE)pbSig, (ULONG)cbSig,
                                        0 );
    ntStatus = NT_SUCCESS( ntStatus ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

cleanup:
    return ntStatus;
}
// DSA end

/*


template<>
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::~RsaSignImp()
{
    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    NTSTATUS ntStatus;
    BCRYPT_RSAKEY_BLOB * pBlob = NULL;
    PBYTE pTmp;

    if( state.hKey != NULL )
    {
        BCryptDestroyKey( state.hKey );
        state.hKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    // Allocate memory for our blob
    pBlob = (BCRYPT_RSAKEY_BLOB *) malloc( sizeof( *pBlob ) + 8 + 3 * RSAKEY_MAXKEYSIZE );
    CHECK( pBlob != NULL, "?" );

    pBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBlob->BitLength= pcKeyBlob->nBitsModulus;
    pBlob->cbPublicExp = 8;
    pBlob->cbModulus = pcKeyBlob->cbModulus;
    pBlob->cbPrime1 = pcKeyBlob->cbPrime1;
    pBlob->cbPrime2 = pcKeyBlob->cbPrime2;

    pTmp = (PBYTE) (pBlob + 1);
    SYMCRYPT_STORE_MSBFIRST64( pTmp, pcKeyBlob->u64PubExp );
    pTmp += 8;

    memcpy( pTmp, &pcKeyBlob->abModulus[0], pBlob->cbModulus );
    pTmp += pBlob->cbModulus;

    memcpy( pTmp, &pcKeyBlob->abPrime1[0], pBlob->cbPrime1 );
    pTmp += pBlob->cbPrime1;
    memcpy( pTmp, &pcKeyBlob->abPrime2[0], pBlob->cbPrime2 );
    pTmp += pBlob->cbPrime2;

    ntStatus = BCryptImportKeyPair(
        BCRYPT_RSA_SIGN_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &state.hKey,
        (PBYTE) pBlob,
        (UINT32)(pTmp - (PBYTE) pBlob),
        0 );

    CHECK( NT_SUCCESS( ntStatus ), "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    NTSTATUS ntStatus;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;
    ULONG cbResult;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;

    ntStatus = BCryptSignHash(
        state.hKey,
        &paddingInfo,
        (PBYTE) pbHash,
        (UINT32)cbHash,
        pbSig,
        (UINT32)cbSig,
        &cbResult,
        BCRYPT_PAD_PKCS1 );

    CHECK( NT_SUCCESS( ntStatus ) && cbResult == cbSig, "?" );

    return ntStatus;
}

template<>
NTSTATUS
RsaSignImp<ImpCng, AlgRsaSignPkcs1>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    NTSTATUS ntStatus;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    PCCNG_HASH_INFO pInfo;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    paddingInfo.pszAlgId = pInfo->wideName;

    ntStatus = BCryptVerifySignature(
        state.hKey,
        &paddingInfo,
        (PBYTE)pbHash,
        (UINT32)cbHash,
        (PBYTE)pbSig,
        (UINT32)cbSig,
        BCRYPT_PAD_PKCS1 );

    return ntStatus;
}

*/

//===
/*
template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaDecRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngDecryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf3,
            (ULONG)dataSize,
            NULL,
            NULL,
            0,
            buf2,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_NONE );
}

template<>
RsaImp<ImpCng, AlgRsaDecRaw>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaDecRaw>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncRaw>;
}

template<>
RsaImp<ImpCng, AlgRsaDecRaw>::~RsaImp()
{
}
*/

// Rsa Pkcs1 Encryption
/*
template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE rbResult[1024] = { 0 };
    ULONG cbDst = 0;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)keySize - PERF_RSA_PKCS1_LESS_BYTES,     // This is the maximum size for PKCS1
                    NULL,
                    NULL,
                    0,
                    buf3,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    CHECK( sizeof(rbResult) >= keySize, "?" );

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)keySize,
                    NULL,
                    NULL,
                    0,
                    rbResult,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_PKCS1 );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize - PERF_RSA_PKCS1_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, rbResult, cbDst) == 0, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngEncryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf2,
            (ULONG)dataSize - PERF_RSA_PKCS1_LESS_BYTES,        // This is the maximum size for PKCS1
            NULL,
            NULL,
            0,
            buf3,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_PKCS1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}
*/

/*
template<>
RsaImp<ImpCng, AlgRsaEncPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpCng, AlgRsaEncPkcs1>::~RsaImp()
{
}
*/

/*
// Rsa Pkcs1 Decryption
template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaDecPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngDecryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf3,
            (ULONG)dataSize,
            NULL,
            NULL,
            0,
            buf2,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_PKCS1 );
}

template<>
RsaImp<ImpCng, AlgRsaDecPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaDecPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpCng, AlgRsaDecPkcs1>::~RsaImp()
{
}
*/

// Rsa Oaep Encryption
/*
template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BYTE rbResult[1024] = { 0 };
    ULONG cbDst = 0;

    PBYTE pTmp = NULL;
    BCRYPT_OAEP_PADDING_INFO * pPaddingInfo = NULL;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    // Set the padding info at the end of buf2 (after the plaintext)
    pTmp = buf2 + keySize;
    pPaddingInfo = (BCRYPT_OAEP_PADDING_INFO *) pTmp;
    pPaddingInfo->pszAlgId = PERF_RSA_HASH_ALG_CNG;
    pPaddingInfo->pbLabel = buf2;                       // Use buf2 bytes as label
    pPaddingInfo->cbLabel = PERF_RSA_LABEL_LENGTH;

    ntStatus = CngEncryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf2,
                    (ULONG)keySize - PERF_RSA_OAEP_LESS_BYTES,      // This is the maximum size for OAEP
                    (VOID *) (buf2 + keySize),
                    NULL,
                    0,
                    buf3,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    CHECK( sizeof(rbResult) >= keySize, "?" );

    ntStatus = CngDecryptFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    buf3,
                    (ULONG)keySize,
                    (VOID *) (buf2 + keySize),
                    NULL,
                    0,
                    rbResult,
                    (ULONG)keySize,
                    &cbDst,
                    BCRYPT_PAD_OAEP );
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize - PERF_RSA_OAEP_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, rbResult, cbDst) == 0, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngEncryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf2,
            (ULONG)dataSize - PERF_RSA_OAEP_LESS_BYTES,     // This is the maximum size for OAEP
            (VOID *) (buf2 + dataSize),
            NULL,
            0,
            buf3,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_OAEP );
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}
*/

/*
template<>
RsaImp<ImpCng, AlgRsaEncOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpCng, AlgRsaEncOaep>::~RsaImp()
{
}
*/

/*
// Rsa Oaep Decryption
template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaDecOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngDecryptFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            buf3,
            (ULONG)dataSize,
            (VOID *) (buf2 + dataSize),
            NULL,
            0,
            buf2,
            (ULONG)dataSize,
            &cbDst,
            BCRYPT_PAD_OAEP );
}

template<>
RsaImp<ImpCng, AlgRsaDecOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaDecOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpCng, AlgRsaDecOaep>::~RsaImp()
{
}


template<>
RsaImp<ImpCng, AlgRsaSignPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpCng, AlgRsaSignPkcs1>::~RsaImp()
{
}

// Rsa Pkcs1 Verify
template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaVerifyPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    CngVerifySignatureFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            (BCRYPT_PKCS1_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            (ULONG) dataSize,
            BCRYPT_PAD_PKCS1);
}

template<>
RsaImp<ImpCng, AlgRsaVerifyPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaVerifyPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpCng, AlgRsaVerifyPkcs1>::~RsaImp()
{
}
*/

/*
// Rsa Pss Sign
template<>
VOID
algImpKeyPerfFunction<ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG cbDst = 0;

    PBYTE pTmp = NULL;
    BCRYPT_PSS_PADDING_INFO * pPaddingInfo = NULL;

    cng_RsaKeyPerf( buf1, buf2, keySize );

    // Create the padding info in the last bytes of buf2
    pTmp = buf2 + PERF_RSA_HASH_ALG_SIZE;
    pPaddingInfo = (BCRYPT_PSS_PADDING_INFO *) pTmp;

    pPaddingInfo->pszAlgId = PERF_RSA_HASH_ALG_CNG;
    pPaddingInfo->cbSalt = PERF_RSA_LABEL_LENGTH;

    ntStatus = CngSignHashFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    &cbDst,
                    BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
    CHECK( cbDst == keySize, "?" );

    ntStatus = CngVerifySignatureFn(
                    *((BCRYPT_KEY_HANDLE *) buf1),
                    (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    (ULONG) keySize,
                    BCRYPT_PAD_PSS);
    CHECK( ntStatus == STATUS_SUCCESS, "?" );
}

template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ULONG cbDst = 0;

    CngSignHashFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            (ULONG) dataSize,
            &cbDst,
            BCRYPT_PAD_PSS);
}

template<>
VOID
algImpCleanPerfFunction<ImpCng, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
RsaImp<ImpCng, AlgRsaSignPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaSignPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPss>;
}

template<>
RsaImp<ImpCng, AlgRsaSignPss>::~RsaImp()
{
}
*/
// Rsa Pss Verify

/*
template<>
VOID
algImpDataPerfFunction< ImpCng, AlgRsaVerifyPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    CngVerifySignatureFn(
            *((BCRYPT_KEY_HANDLE *) buf1),
            (BCRYPT_PSS_PADDING_INFO *) (buf2+PERF_RSA_HASH_ALG_SIZE),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            (ULONG) dataSize,
            BCRYPT_PAD_PSS);
}

template<>
RsaImp<ImpCng, AlgRsaVerifyPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaVerifyPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaSignPss>;
}

template<>
RsaImp<ImpCng, AlgRsaVerifyPss>::~RsaImp()
{
}
*/

VOID
addCngAlgs()
{
    SetCngKeySizeFlag();

    BOOL bCngAesCmac_HmacMode = cngAesCmac_HmacMode();
    BCRYPT_ALG_HANDLE hAlg;

    PCSTR targetLibrary = "BCrypt.dll";
    if (g_sgx)
    {
        targetLibrary = "BCryptSgxProxy.dll";
    }
    HMODULE hModule = LoadLibrary( targetLibrary );
    CHECK4( hModule != NULL, "Could not LoadLibrary %s, %08x", targetLibrary, GetLastError() );

    CngPbkdf2Fn = (BCryptDeriveKeyPBKDF2Fn) GetProcAddress( hModule, "BCryptDeriveKeyPBKDF2" );
    CngKeyDerivationFn = (BCryptKeyDerivationFn) GetProcAddress( hModule, "BCryptKeyDerivation" );
    CngCreateMultiHashFn = (BCryptCreateMultiHashFn) GetProcAddress( hModule, "BCryptCreateMultiHash" );
    CngProcessMultiOperationsFn = (BCryptProcessMultiOperationsFn) GetProcAddress( hModule, "BCryptProcessMultiOperations" );

    if (g_sgx)
    {
        // Shim BCrypt crypto primitive calls through proxy to execute in an SGX enclave.
        // This also keeps the proxy loaded for the lifetime of this process, as BCrypt would normally be via static import.
        CngCloseAlgorithmProviderFn = (BCryptCloseAlgorithmProviderFn) CheckedGetProcAddress(hModule, "BCryptCloseAlgorithmProvider" );
        CngCreateHashFn = (BCryptCreateHashFn) CheckedGetProcAddress( hModule, "BCryptCreateHash" );
        CngDecryptFn = (BCryptDecryptFn) CheckedGetProcAddress( hModule, "BCryptDecrypt" );
        CngDeriveKeyFn = (BCryptDeriveKeyFn) CheckedGetProcAddress( hModule, "BCryptDeriveKey" );
        CngDeriveKeyCapiFn = (BCryptDeriveKeyCapiFn) CheckedGetProcAddress( hModule, "BCryptDeriveKeyCapi" );
        CngDestroyHashFn = (BCryptDestroyHashFn) CheckedGetProcAddress( hModule, "BCryptDestroyHash" );
        CngDestroyKeyFn = (BCryptDestroyKeyFn) CheckedGetProcAddress( hModule, "BCryptDestroyKey" );
        CngDestroySecretFn = (BCryptDestroySecretFn) CheckedGetProcAddress( hModule, "BCryptDestroySecret" );
        CngDuplicateHashFn = (BCryptDuplicateHashFn) CheckedGetProcAddress( hModule, "BCryptDuplicateHash" );
        CngDuplicateKeyFn = (BCryptDuplicateKeyFn) CheckedGetProcAddress( hModule, "BCryptDuplicateKey" );
        CngEncryptFn = (BCryptEncryptFn) CheckedGetProcAddress( hModule, "BCryptEncrypt" );
        CngExportKeyFn = (BCryptExportKeyFn) CheckedGetProcAddress( hModule, "BCryptExportKey" );
        CngFinalizeKeyPairFn = (BCryptFinalizeKeyPairFn) CheckedGetProcAddress( hModule, "BCryptFinalizeKeyPair" );
        CngFinishHashFn = (BCryptFinishHashFn) CheckedGetProcAddress( hModule, "BCryptFinishHash" );
        CngGenerateKeyPairFn = (BCryptGenerateKeyPairFn) CheckedGetProcAddress( hModule, "BCryptGenerateKeyPair" );
        CngGenerateSymmetricKeyFn = (BCryptGenerateSymmetricKeyFn) CheckedGetProcAddress( hModule, "BCryptGenerateSymmetricKey" );
        CngGenRandomFn = (BCryptGenRandomFn) CheckedGetProcAddress( hModule, "BCryptGenRandom" );
        CngGetPropertyFn = (BCryptGetPropertyFn) CheckedGetProcAddress( hModule, "BCryptGetProperty" );
        CngHashFn = (BCryptHashFn)CheckedGetProcAddress(hModule, "BCryptHash");
        CngHashDataFn = (BCryptHashDataFn) CheckedGetProcAddress( hModule, "BCryptHashData" );
        CngImportKeyFn = (BCryptImportKeyFn) CheckedGetProcAddress( hModule, "BCryptImportKey" );
        CngImportKeyPairFn = (BCryptImportKeyPairFn) CheckedGetProcAddress( hModule, "BCryptImportKeyPair" );
        CngOpenAlgorithmProviderFn = (BCryptOpenAlgorithmProviderFn) CheckedGetProcAddress( hModule, "BCryptOpenAlgorithmProvider" );
        CngSecretAgreementFn = (BCryptSecretAgreementFn) CheckedGetProcAddress( hModule, "BCryptSecretAgreement" );
        CngSetPropertyFn = (BCryptSetPropertyFn) CheckedGetProcAddress( hModule, "BCryptSetProperty" );
        CngSignHashFn = (BCryptSignHashFn) CheckedGetProcAddress( hModule, "BCryptSignHash" );
        CngVerifySignatureFn = (BCryptVerifySignatureFn) CheckedGetProcAddress( hModule, "BCryptVerifySignature" );
    }
    else
    {
        CHECK3(FreeLibrary(hModule), "Failed to free %s handle", targetLibrary);
    }

    addImplementationToGlobalList<HashImp<ImpCng, AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpCng, AlgSha512>>();

    if( CngCreateMultiHashFn != NULL )
    {
        CHECK( CngProcessMultiOperationsFn != NULL, "Could not find BCrypProcessMultiOperations" );
        addImplementationToGlobalList<ParallelHashImp<ImpCng, AlgParallelSha256>>();
        addImplementationToGlobalList<ParallelHashImp<ImpCng, AlgParallelSha384>>();
        addImplementationToGlobalList<ParallelHashImp<ImpCng, AlgParallelSha512>>();
    }

    addImplementationToGlobalList<MacImp<ImpCng, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpCng, AlgHmacSha1>>();
    addImplementationToGlobalList<MacImp<ImpCng, AlgHmacSha256>>();
    addImplementationToGlobalList<MacImp<ImpCng, AlgHmacSha384>>();
    addImplementationToGlobalList<MacImp<ImpCng, AlgHmacSha512>>();

    if( g_osVersion >= OS_VERSION_WIN8 )    // Is this the right limit?
    {
        addImplementationToGlobalList<MacImp<ImpCng, AlgAesCmac>>();
    }

    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgAes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDes, ModeCbc>>();
    if( g_osVersion >= 0x0602 )
    {
        // Not supported on Win7
        addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDes, ModeCfb>>();
    }
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, Alg3Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDesx, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDesx, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgDesx, ModeCbc>>();

    if( g_osVersion >= OS_VERSION_WIN7 )
    {
        addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgRc2, ModeCfb>>();
        addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgRc2, ModeEcb>>();
        addImplementationToGlobalList<BlockCipherImp<ImpCng, AlgRc2, ModeCbc>>();
    }

    if( g_osVersion >= OS_VERSION_WIN7 )
    {
        //
        // These don't work on Vista, haven't investigated yet.
        //
        addImplementationToGlobalList<AuthEncImp<ImpCng, AlgAes, ModeCcm>>();
        addImplementationToGlobalList<AuthEncImp<ImpCng, AlgAes, ModeGcm>>();
    }

    addImplementationToGlobalList<StreamCipherImp<ImpCng, AlgRc4>>();

    addImplementationToGlobalList<RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>>();

    if( CngPbkdf2Fn != NULL && CngKeyDerivationFn != NULL )
    {
        addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgHmacMd5>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgHmacSha1>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgHmacSha256>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgHmacSha384>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgHmacSha512>>();
        if (bCngAesCmac_HmacMode)
        {
            addImplementationToGlobalList<KdfImp<ImpCng, AlgPbkdf2, AlgAesCmac>>();
        }
    }

    if( CngKeyDerivationFn != NULL )
    {
        addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgHmacMd5>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgHmacSha1>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgHmacSha256>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgHmacSha384>>();
        addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgHmacSha512>>();
        if (bCngAesCmac_HmacMode)
        {
            addImplementationToGlobalList<KdfImp<ImpCng, AlgSp800_108, AlgAesCmac>>();
        }

        if (g_osVersion >= OS_VERSION_WIN8)
        {
            addImplementationToGlobalList<KdfImp<ImpCng, AlgTlsPrf1_1, AlgHmacMd5>>();
            addImplementationToGlobalList<KdfImp<ImpCng, AlgTlsPrf1_2, AlgHmacSha256>>();
            addImplementationToGlobalList<KdfImp<ImpCng, AlgTlsPrf1_2, AlgHmacSha384>>();
            addImplementationToGlobalList<KdfImp<ImpCng, AlgTlsPrf1_2, AlgHmacSha512>>();
        }
    }

    //
    // See if XTS is supported.
    //
    if( NT_SUCCESS( CngOpenAlgorithmProviderFn( &hAlg, BCRYPT_XTS_AES_ALGORITHM, NULL, 0 )))
    {
        addImplementationToGlobalList<XtsImp<ImpCng, AlgXtsAes>>();
        CngCloseAlgorithmProviderFn( hAlg, 0 );
        hAlg = 0;
    }

    // See if TlsCbcHmacVerify option is supported
    if( NT_SUCCESS( CngOpenAlgorithmProviderFn( &hAlg, BCRYPT_HMAC_SHA256_ALGORITHM, NULL,
                                                BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG )))
    {
        CngCloseAlgorithmProviderFn( hAlg, 0 );
        hAlg = 0;

        addImplementationToGlobalList<TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha1>>();
        addImplementationToGlobalList<TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha256>>();
        addImplementationToGlobalList<TlsCbcHmacImp<ImpCng, AlgTlsCbcHmacSha384>>();
    }

    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncOaep>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecOaep>>();

    addImplementationToGlobalList<RsaSignImp<ImpCng, AlgRsaSignPkcs1>>();
    addImplementationToGlobalList<RsaSignImp<ImpCng, AlgRsaSignPss>>();

    addImplementationToGlobalList<RsaEncImp<ImpCng, AlgRsaEncRaw>>();
    addImplementationToGlobalList<RsaEncImp<ImpCng, AlgRsaEncPkcs1>>();
    addImplementationToGlobalList<RsaEncImp<ImpCng, AlgRsaEncOaep>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaSignPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaVerifyPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaSignPss>>();
    //addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaVerifyPss>>();

    addImplementationToGlobalList<DhImp<ImpCng, AlgDh>>();
    addImplementationToGlobalList<DsaImp<ImpCng, AlgDsa>>();
}

#endif //INCLUDE_IMPL_CNG
