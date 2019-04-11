//
// CNG implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "cng_implementations.h"

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


StreamCipherImp<ImpCng, AlgRc4>::StreamCipherImp<ImpCng, AlgRc4>()
{
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, PROVIDER_NAME( RC4 ), NULL, 0 ) == STATUS_SUCCESS, 
        "Could not open CNG/" STRING( ALG_Name ) );

    state.hKey = 0;
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpCng, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpCng, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpCng, AlgRc4>;
}

template<>
StreamCipherImp<ImpCng, AlgRc4>::~StreamCipherImp<ImpCng, AlgRc4>()
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
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>()
{
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpCng, AlgAesCtrDrbg>;
}

template<>
RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>::~RngSp800_90Imp<ImpCng, AlgAesCtrDrbg>()
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
XtsImp<ImpCng, AlgXtsAes>::XtsImp<ImpCng, AlgXtsAes>()
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
XtsImp<ImpCng, AlgXtsAes>::~XtsImp<ImpCng, AlgXtsAes>()
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
RsaImp<ImpCng, AlgRsaEncRaw>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpCng, AlgRsaEncRaw>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpCng, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpCng, AlgRsaEncRaw>;
}

template<>
RsaImp<ImpCng, AlgRsaEncRaw>::~RsaImp()
{
}

// Rsa Decryption (only the Data perf function is new)

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

// Rsa Pkcs1 Encryption
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

// Rsa Oaep Encryption
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
algImpCleanPerfFunction<ImpCng, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
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

// Rsa Pss Verify

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
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncRaw>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecRaw>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncPkcs1>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecPkcs1>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaEncOaep>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaDecOaep>>();

    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaSignPkcs1>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaVerifyPkcs1>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaSignPss>>();
    addImplementationToGlobalList<RsaImp<ImpCng, AlgRsaVerifyPss>>();
}


