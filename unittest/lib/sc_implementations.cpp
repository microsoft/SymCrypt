//
// SymCrypt implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#define SYMCRYPT_2DES_EXPANDED_KEY  SYMCRYPT_3DES_EXPANDED_KEY

#define SCRATCH_BUF_OFFSET  (1 << 15)
#define SCRATCH_BUF_SIZE    (1 << 15)

template<class Implementation, class Algorithm, class Mode>
VOID
SYMCRYPT_CALL
SYMCRYPT_EncryptTest(
    _In_                    PVOID   pExpandedKey,
    _In_                    PBYTE   pbChainingValue,
    _In_reads_( cbData )    PCBYTE  pbSrc,
    _Out_writes_( cbData )  PBYTE   pbDst,
                            SIZE_T  cbData );

template<class Implementation, class Algorithm, class Mode>
VOID
SYMCRYPT_CALL
SYMCRYPT_DecryptTest(
    _In_                    PVOID   pExpandedKey,
    _In_                    PBYTE   pbChainingValue,
    _In_reads_( cbData )    PCBYTE  pbSrc,
    _Out_writes_( cbData )  PBYTE   pbDst,
                            SIZE_T  cbData );

template<class Implementation>
VOID
setupPerfInt( PBYTE pb, SIZE_T cb, UINT32 nDigits );

template<class Implementation>
VOID
setupIntsForPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T inSize, UINT32 outFactor );


template<class Implementation>
VOID
setupModulus( PBYTE buf1, PBYTE buf3, SIZE_T keySize );

template<class Implementation>
void
setupModOperations( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );


template<class Implementation>
void
SetupSymCryptRsaKey( PBYTE buf1, SIZE_T keySize, UINT32 generateFlags );

template<class Implementation>
void
sc_RsaKeyPerf( PBYTE buf1, PBYTE buf2, SIZE_T keySize, UINT32 generateFlags );

template<class Implementation>
VOID
DlgroupSetup( PBYTE buf1, SIZE_T keySize, BOOLEAN forDiffieHellman );

template<class Implementation>
void
SetupDlGroup( PBYTE buf1, SIZE_T keySize );

template<class Implementation>
void
SetupSymCryptDsa( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

template<class Implementation>
PSYMCRYPT_DLKEY
dlkeyObjectFromTestBlob( PCSYMCRYPT_DLGROUP pGroup, PCDLKEY_TESTBLOB pBlob, UINT32 algFlags, BOOL setPrivate = TRUE );

template<class Implementation>
void
CleanupSymCryptCurves();

template<class Implementation>
void
SetupSymCryptCurves( PBYTE buf1, SIZE_T keySize );


template<class Implementation>
void
SetupSymCryptEcpoints( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

template<class Implementation>
void
SetupSymCryptEckey( PBYTE buf1, PBYTE buf2, PBYTE buf3, UINT32 setRandomFlags );

VOID
trialDivisionSetFakePrime( PSYMCRYPT_TRIALDIVISION_PRIME p )
{
    p->invMod2e64 = 0x5a5a5a5a5a5a5a5b; // Fake, doesn't matter as long as it is odd and not too small to be especially fast...
    p->compareLimit = 0;        // This makes the trial division never 'hit' unless the input is all-zeroes.
}

VOID
createFakeTrialDivisionContext( PBYTE pBuf, UINT32 primesPerGroup )
{
    PBYTE pAlloc= pBuf;
    UINT32 nGroups = 1000;
    UINT32 nPrimes = nGroups * primesPerGroup;

    PSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PSYMCRYPT_TRIALDIVISION_CONTEXT) pAlloc;
    pAlloc += sizeof( *pContext );

    pContext->pGroupList = (PSYMCRYPT_TRIALDIVISION_GROUP) pAlloc;
    pAlloc += (nGroups + 1) * sizeof( SYMCRYPT_TRIALDIVISION_GROUP );

    pContext->pPrimeList = (PSYMCRYPT_TRIALDIVISION_PRIME) pAlloc;
    pAlloc += (nPrimes + 1) * sizeof( SYMCRYPT_TRIALDIVISION_PRIME );

    pContext->pPrimes = (PUINT32) pAlloc;
    pAlloc += (nPrimes + 1) * sizeof( UINT32 );

    pContext->nBytesAlloc = pAlloc - pBuf;

    // The special primes hinder our measurements a bit, but only by something like 0.3%.
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[0] );
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[1] );
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[2] );

    UINT32 i;
    for( i=0; i<nPrimes; i++ )
    {
        trialDivisionSetFakePrime( &pContext->pPrimeList[i] );
    }

    for( i=0; i<nGroups; i++ )
    {
        pContext->pGroupList[i].nPrimes = primesPerGroup;
        memset( &pContext->pGroupList[i].factor[0], 0xa5, 9 * sizeof( UINT32 ) );
    }

    pContext->pGroupList[nGroups].nPrimes = 0;
}

typedef struct _HASH_INFO {
    PCSTR   name;
    PCSYMCRYPT_HASH pcHash;
    PCSYMCRYPT_OID  pcOids;
    UINT32          nOids;
} HASH_INFO;
typedef const HASH_INFO * PCHASH_INFO;

typedef struct _DLGROUP_INFO {
    PCDLGROUP_TESTBLOB pBlob;
    PSYMCRYPT_DLGROUP pGroup;
} DLGROUP_INFO;
typedef DLGROUP_INFO * PDLGROUP_INFO;

template<class Implementation>
PCHASH_INFO getHashInfo(PCSTR pcstrName);

#include "sc_imp_shims.h"

char * ImpSc::name = "SymCrypt";

#define IMP_NAME    SYMCRYPT
#define IMP_Name    Sc

#include "sc_imp_pattern.cpp"

#undef IMP_NAME
#undef IMP_Name

char * ImpScStatic::name = "SymCryptStatic";

#define IMP_NAME    SYMCRYPT
#define IMP_Name    ScStatic

#include "sc_imp_pattern.cpp"

#undef IMP_NAME
#undef IMP_Name

char * ImpScDynamic::name = "SymCryptDynamic";

#define IMP_NAME    SYMCRYPTDYNAMIC
#define IMP_Name    ScDynamic
#define IMP_UseSymCryptRandom (1)

#include "sc_imp_pattern.cpp"

#undef IMP_UseSymCryptRandom
#undef IMP_NAME
#undef IMP_Name

template<class ImpScVariant>
VOID
addSymCryptImplementationToGlobalList()
{
    //
    // We use a template function to decide which algorithm implementations to
    // run.
    // We could make each algorithm auto-register using static initializers,
    // but this is test code and we want to be able to test (and dynamically disable)
    // the initializer code. So we do it manually once.
    //

    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha512>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_256>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_384>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_512>>();

    addImplementationToGlobalList<XofImp<ImpScVariant, AlgShake128>>();
    addImplementationToGlobalList<XofImp<ImpScVariant, AlgShake256>>();
    addImplementationToGlobalList<CustomizableXofImp<ImpScVariant, AlgCShake128>>();
    addImplementationToGlobalList<CustomizableXofImp<ImpScVariant, AlgCShake256>>();
    addImplementationToGlobalList<KmacImp<ImpScVariant, AlgKmac128>>();
    addImplementationToGlobalList<KmacImp<ImpScVariant, AlgKmac256>>();

    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha1>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha256>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha384>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha512>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgAesCmac>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgMarvin32>>();

    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeCfb>>();

    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeCfb>>();

    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgAes, ModeCcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgAes, ModeGcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgChaCha20Poly1305, ModeNone>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_1, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha512>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgHkdf, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgHkdf, AlgHmacSha1>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha512>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSrtpKdf, AlgAes>>();

    addImplementationToGlobalList<MacImp<ImpScVariant, AlgPoly1305>>();

    addImplementationToGlobalList<StreamCipherImp<ImpScVariant, AlgRc4>>();
    addImplementationToGlobalList<StreamCipherImp<ImpScVariant, AlgChaCha20>>();

    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha256>>();
    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha384>>();
    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha512>>();

    addImplementationToGlobalList<XtsImp<ImpScVariant, AlgXtsAes>>();

    addImplementationToGlobalList<RngSp800_90Imp<ImpScVariant, AlgAesCtrDrbg>>();
    addImplementationToGlobalList<RngSp800_90Imp<ImpScVariant, AlgAesCtrF142>>();

    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha1>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha256>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha384>>();


    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaEncRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaDecRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaEncPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaDecPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaEncOaep>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaDecOaep>>();

    addImplementationToGlobalList<RsaSignImp<ImpScVariant, AlgRsaSignPkcs1>>();
    addImplementationToGlobalList<RsaSignImp<ImpScVariant, AlgRsaSignPss>>();

    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncRaw>>();
    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncPkcs1>>();
    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncOaep>>();

    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaSignPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaVerifyPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaSignPss>>();
    //addImplementationToGlobalList<RsaImp<ImpScVariant, AlgRsaVerifyPss>>();

    addImplementationToGlobalList<DhImp<ImpScVariant, AlgDh>>();
    addImplementationToGlobalList<DsaImp<ImpScVariant, AlgDsa>>();

    //addImplementationToGlobalList<DlImp<ImpScVariant, AlgDsaSign>>();
    //addImplementationToGlobalList<DlImp<ImpScVariant, AlgDsaVerify>>();
    //addImplementationToGlobalList<DlImp<ImpScVariant, AlgDh>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcurveAllocate>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdsaSign>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdsaVerify>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdh>>();

#if SYMCRYPT_MS_VC
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIEEE802_11SaeCustom>>();
#endif

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgDeveloperTest>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetZero>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetDistinguished>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetRandom>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointIsEqual>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointIsZero>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointOnCurve>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointAdd>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointAddDiffNz>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointDouble>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointScalarMul>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntAdd>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntSub>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntMul>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntSquare>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntDivMod>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModAdd>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModSub>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModMul>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModSquare>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModExp>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModInv>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgScsTable>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgTrialDivision>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgTrialDivisionContext>>();
}

VOID
addSymCryptAlgs()
{
    SymCryptInit();

    addSymCryptImplementationToGlobalList<ImpSc>();

    if (g_dynamicSymCryptModuleHandle)
    {
        addSymCryptImplementationToGlobalList<ImpScDynamic>();
        addImplementationToGlobalList<RngSp800_90Imp<ImpScDynamic, AlgDynamicRandom>>();
    }
}

VOID
updateSymCryptStaticAlgs()
{
    // This could surely be done more efficiently, but just do the simple thing here

    // Remove all implementations from ImpSc
    for (AlgorithmImplementationVector::iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); )
    {
        if ((*i)->m_implementationName == ImpSc::name)
        {
            delete *i;
            i = g_algorithmImplementation.erase(i);
        }
        else
        {
            i++;
        }
    }

    // Add implementations from ImpScStatic
    addSymCryptImplementationToGlobalList<ImpScStatic>();
}
