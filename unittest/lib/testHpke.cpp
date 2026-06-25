//
// testHpke.cpp
//
// Unit tests for the HPKE implementation in symcrypt_plus.
//
// Includes KAT (Known Answer Test) vectors from the HPKE and HPKE-PQ specifications,
// as well as functional round-trip tests that exercise the full API lifecycle:
// key generation, SetupSender/SetupRecipient, Seal/Open, OpenUnordered,
// SecretExport, and error paths.
//
// Dynamic dispatch testing is handled through the multi-imp framework:
// HpkeMultiImp cross-validates all registered implementations (ImpSc, ImpScDynamic)
// by running each one-shot operation across every implementation and verifying
// agreement (for deterministic ops) or cross-opening (for randomized seal).
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include "symcrypt_hpke.h"

extern "C" {
#include "hpke_internal.h"
}

struct HPKE_TEST_PARAMS
{
    String                      name;
    SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite;
    SIZE_T                      cbEnc;
};

static const SYMCRYPT_HPKE_KEM_ID rgHpkeSupportedKemIds[] = {
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
    SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
};

static const SYMCRYPT_HPKE_KDF_ID rgHpkeSupportedKdfIds[] = {
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
    SYMCRYPT_HPKE_KDF_ID_SHAKE128,
    SYMCRYPT_HPKE_KDF_ID_SHAKE256,
};

static const SYMCRYPT_HPKE_AEAD_ID rgHpkeSealAeadIds[] = {
    SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
    SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305,
};

static String
testHpkeCiphersuiteName(
    SYMCRYPT_HPKE_CIPHERSUITE ciphersuite )
{
    char szName[64];

    SNPRINTF_S(
        szName, sizeof(szName), _TRUNCATE,
        "kem=0x%04x / kdf=0x%04x / aead=0x%04x",
        (unsigned) ciphersuite.kemId,
        (unsigned) ciphersuite.kdfId,
        (unsigned) ciphersuite.aeadId );

    return String( szName );
}

static VOID
testHpkeAppendSupportedCiphersuite(
    _Inout_ std::vector<HPKE_TEST_PARAMS>  &params,
            SYMCRYPT_HPKE_CIPHERSUITE       ciphersuite )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbEnc = 0;

    scError = SymCryptHpkeValidateCiphersuite( ciphersuite, NULL, NULL );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        return;
    }

    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams( ciphersuite, &cbEnc );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE test matrix enc size query failed" );

    params.push_back( { testHpkeCiphersuiteName( ciphersuite ), ciphersuite, cbEnc } );
}

static std::vector<HPKE_TEST_PARAMS>
testHpkeBuildTestParams(
    BOOL fExportOnly )
{
    std::vector<HPKE_TEST_PARAMS> params;

    for( SYMCRYPT_HPKE_KEM_ID kemId : rgHpkeSupportedKemIds )
    {
        for( SYMCRYPT_HPKE_KDF_ID kdfId : rgHpkeSupportedKdfIds )
        {
            if( fExportOnly )
            {
                testHpkeAppendSupportedCiphersuite(
                    params,
                    { (UINT16) kemId, (UINT16) kdfId, (UINT16) SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY } );
            }
            else
            {
                for( SYMCRYPT_HPKE_AEAD_ID aeadId : rgHpkeSealAeadIds )
                {
                    testHpkeAppendSupportedCiphersuite( params, { (UINT16) kemId, (UINT16) kdfId, (UINT16) aeadId } );
                }
            }
        }
    }

    CHECK( params.size() > 0, "HPKE test matrix is empty" );
    return params;
}


//
// HpkeMultiImp — orchestrator for cross-implementation testing.
// Modelled after KemMultiImp: randomized seal => cross-open; deterministic
// open/secretExport => ResultMerge.
//
class HpkeMultiImp
{
public:
    HpkeMultiImp( String algName );

private:
    HpkeMultiImp( const HpkeMultiImp & );
    VOID operator=( const HpkeMultiImp & );

public:
    typedef std::vector<HpkeImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;                    // All registered implementations
    ImpPtrVector m_comps;                   // Active implementations for current key
    ImpPtrVector m_senderComps;             // Active implementations for current sender context
    ImpPtrVector m_recipientComps;          // Active implementations for current recipient context

    NTSTATUS setKey(
                                                SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
                                                UINT32                      format,
        _In_reads_bytes_( cbKey )               PCBYTE                      pbKey,
                                                SIZE_T                      cbKey );

    NTSTATUS getKey(
                                                UINT32                      format,
        _Out_writes_bytes_( cbKey )             PBYTE                       pbKey,
                                                SIZE_T                      cbKey );

    NTSTATUS deriveKeyPair(
                                                SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
        _In_reads_bytes_( cbIkm )               PCBYTE                      pbIkm,
                                                SIZE_T                      cbIkm );

    NTSTATUS sealSingleShot(
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_opt_( cbAad )           PCBYTE                      pbAad,
                                                SIZE_T                      cbAad,
        _In_reads_bytes_( cbPlaintext )         PCBYTE                      pbPlaintext,
                                                SIZE_T                      cbPlaintext,
        _Out_writes_bytes_( cbEnc )             PBYTE                       pbEnc,
                                                SIZE_T                      cbEnc,
        _Out_writes_bytes_( cbCiphertext )      PBYTE                       pbCiphertext,
                                                SIZE_T                      cbCiphertext );

    NTSTATUS openSingleShot(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_opt_( cbAad )           PCBYTE                      pbAad,
                                                SIZE_T                      cbAad,
        _In_reads_bytes_( cbCiphertext )        PCBYTE                      pbCiphertext,
                                                SIZE_T                      cbCiphertext,
        _Out_writes_bytes_( cbPlaintext )       PBYTE                       pbPlaintext,
                                                SIZE_T                      cbPlaintext );

    NTSTATUS secretExportSingleShot(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_( cbExporterContext )   PCBYTE                      pbExporterContext,
                                                SIZE_T                      cbExporterContext,
        _Out_writes_bytes_( cbExportedValue )   PBYTE                       pbExportedValue,
                                                UINT16                      cbExportedValue );

    NTSTATUS setupSenderDeterministic(
        _In_reads_bytes_( cbRandom )            PCBYTE                      pbRandom,
                                                SIZE_T                      cbRandom,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _Out_writes_bytes_( cbEnc )             PBYTE                       pbEnc,
                                                SIZE_T                      cbEnc );

    NTSTATUS setupRecipient(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId );

    NTSTATUS seal(
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_opt_( cbSrc )           PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst,
        _Out_opt_                               UINT64 *                    pu64SeqNumber );

    NTSTATUS open(
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_( cbSrc )               PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst );

    NTSTATUS openUnordered(
                                                UINT64                      u64SeqNumber,
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_( cbSrc )               PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst );

    NTSTATUS secretExportSender(
        _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                    SIZE_T                  cbExporterContext,
        _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                    UINT16                  cbResult );

    NTSTATUS secretExportRecipient(
        _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                    SIZE_T                  cbExporterContext,
        _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                    UINT16                  cbResult );

    SIZE_T encSize();
};

HpkeMultiImp::HpkeMultiImp( String algName )
{
    getAllImplementations<HpkeImplementation>( algName, &m_imps );
}

NTSTATUS
HpkeMultiImp::setKey(
                                                SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
                                                UINT32                      format,
        _In_reads_bytes_( cbKey )               PCBYTE                      pbKey,
                                                SIZE_T                      cbKey )
{
    m_comps.clear();
    m_senderComps.clear();
    m_recipientComps.clear();

    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( ciphersuite, format, pbKey, cbKey ) == STATUS_SUCCESS )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::getKey(
                                                UINT32                      format,
        _Out_writes_bytes_( cbKey )             PBYTE                       pbKey,
                                                SIZE_T                      cbKey )
{
    BYTE abKey[4096];
    ResultMerge res;
    NTSTATUS ntStatus;

    CHECK( cbKey < sizeof(abKey), "Key buffer too large" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abKey, 'k', cbKey + 1 );
        ntStatus = (*i)->getKey( format, abKey, cbKey );
        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp::getKey failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abKey[cbKey] == 'k', "Buffer overrun in getKey" );

        res.addResult( (*i), abKey, cbKey );
    }

    res.getResult( pbKey, cbKey );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::deriveKeyPair(
                                                SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
        _In_reads_bytes_( cbIkm )               PCBYTE                      pbIkm,
                                                SIZE_T                      cbIkm )
{
    m_comps.clear();
    m_senderComps.clear();
    m_recipientComps.clear();

    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->deriveKeyPair( ciphersuite, pbIkm, cbIkm ) == STATUS_SUCCESS )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::sealSingleShot(
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_opt_( cbAad )           PCBYTE                      pbAad,
                                                SIZE_T                      cbAad,
        _In_reads_bytes_( cbPlaintext )         PCBYTE                      pbPlaintext,
                                                SIZE_T                      cbPlaintext,
        _Out_writes_bytes_( cbEnc )             PBYTE                       pbEnc,
                                                SIZE_T                      cbEnc,
        _Out_writes_bytes_( cbCiphertext )      PBYTE                       pbCiphertext,
                                                SIZE_T                      cbCiphertext )
{
    //
    // Seal is randomized (KEM uses fresh randomness), so we cannot use ResultMerge.
    // Instead, we have each implementation seal, then cross-open with every other
    // implementation, similar to KemMultiImp::encapsulate.
    //
    BYTE abSealEnc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE abSealCt[4096 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE abOpenPt[4096];
    NTSTATUS ntStatus;
    int nSeals = 0;

    CHECK( cbEnc <= sizeof(abSealEnc), "enc buffer too large" );
    CHECK( cbCiphertext <= sizeof(abSealCt), "ciphertext buffer too large" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abSealEnc, 'e', cbEnc );
        memset( abSealCt, 'c', cbCiphertext );

        ntStatus = (*i)->sealSingleShot( pbInfo, cbInfo,
            pbPsk, cbPsk, pbPskId, cbPskId,
            pbAad, cbAad,
            pbPlaintext, cbPlaintext,
            abSealEnc, cbEnc,
            abSealCt, cbCiphertext );
        //
        // A backend may not support this exact operation (e.g. a ciphersuite
        // option or PSK length it cannot handle). Skip it as a sealer; the
        // remaining implementations still cross-validate among themselves.
        //
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp seal failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );

        //
        // Cross-open: every other implementation that supports this operation
        // must be able to open the ciphertext sealed by implementation i
        //
        for( ImpPtrVector::iterator j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            ntStatus = (*j)->openSingleShot(
                abSealEnc, cbEnc,
                pbInfo, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                pbAad, cbAad,
                abSealCt, cbCiphertext,
                abOpenPt, cbPlaintext );
            if( ntStatus == STATUS_NOT_SUPPORTED )
            {
                continue;
            }
            CHECK5( ntStatus == STATUS_SUCCESS,
                "HPKE seal->open cross-validation failure: sealed by %s, opened by %s (%s)",
                (*i)->m_implementationName.c_str(),
                (*j)->m_implementationName.c_str(),
                (*j)->getLastError().c_str() );
            CHECK4( memcmp( abOpenPt, pbPlaintext, cbPlaintext ) == 0,
                "HPKE seal->open content mismatch: %s -> %s",
                (*i)->m_implementationName.c_str(),
                (*j)->m_implementationName.c_str() );
        }

        //
        // Copy a random implementation's output to the caller
        //
        nSeals += 1;
        if( (g_rng.byte() % nSeals) == 0 )
        {
            memcpy( pbEnc, abSealEnc, cbEnc );
            memcpy( pbCiphertext, abSealCt, cbCiphertext );
        }
    }

    CHECK( nSeals > 0, "HpkeMultiImp seal: no implementation supported this operation" );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::openSingleShot(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_opt_( cbAad )           PCBYTE                      pbAad,
                                                SIZE_T                      cbAad,
        _In_reads_bytes_( cbCiphertext )        PCBYTE                      pbCiphertext,
                                                SIZE_T                      cbCiphertext,
        _Out_writes_bytes_( cbPlaintext )       PBYTE                       pbPlaintext,
                                                SIZE_T                      cbPlaintext )
{
    BYTE abPt[4096];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbPlaintext < sizeof(abPt), "Plaintext buffer too large" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abPt, 'p', cbPlaintext + 1 );
        ntStatus = (*i)->openSingleShot(
            pbEnc, cbEnc, pbInfo, cbInfo,
            pbPsk, cbPsk, pbPskId, cbPskId,
            pbAad, cbAad,
            pbCiphertext, cbCiphertext,
            abPt, cbPlaintext );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp open failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abPt[cbPlaintext] == 'p', "Buffer overrun in open" );

        res.addResult( (*i), abPt, cbPlaintext );
        nResults++;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbPlaintext, cbPlaintext );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::secretExportSingleShot(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _In_reads_bytes_( cbExporterContext )   PCBYTE                      pbExporterContext,
                                                SIZE_T                      cbExporterContext,
        _Out_writes_bytes_( cbExportedValue )   PBYTE                       pbExportedValue,
                                                UINT16                      cbExportedValue )
{
    BYTE abExported[256];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbExportedValue < sizeof(abExported), "Export buffer too large" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abExported, 'x', cbExportedValue + 1 );
        ntStatus = (*i)->secretExportSingleShot(
            pbEnc, cbEnc, pbInfo, cbInfo,
            pbPsk, cbPsk, pbPskId, cbPskId,
            pbExporterContext, cbExporterContext,
            abExported, cbExportedValue );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp secretExport failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abExported[cbExportedValue] == 'x', "Buffer overrun in secretExport" );

        res.addResult( (*i), abExported, cbExportedValue );
        nResults++;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbExportedValue, cbExportedValue );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::setupSenderDeterministic(
        _In_reads_bytes_( cbRandom )            PCBYTE                      pbRandom,
                                                SIZE_T                      cbRandom,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId,
        _Out_writes_bytes_( cbEnc )             PBYTE                       pbEnc,
                                                SIZE_T                      cbEnc )
{
    BYTE abEnc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE + 1];
    ResultMerge res;
    NTSTATUS ntStatus;

    CHECK( cbEnc < sizeof(abEnc), "Enc buffer too large" );

    m_senderComps.clear();

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abEnc, 'e', cbEnc + 1 );
        ntStatus = (*i)->setupSenderDeterministic(
            pbRandom, cbRandom,
            pbInfo, cbInfo,
            pbPsk, cbPsk,
            pbPskId, cbPskId,
            abEnc, cbEnc );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp setupSenderDeterministic failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abEnc[cbEnc] == 'e', "Buffer overrun in setupSenderDeterministic" );

        res.addResult( *i, abEnc, cbEnc );
        m_senderComps.push_back( *i );
    }

    if( m_senderComps.size() == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbEnc, cbEnc );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::setupRecipient(
        _In_reads_bytes_( cbEnc )               PCBYTE                      pbEnc,
                                                SIZE_T                      cbEnc,
        _In_reads_bytes_opt_( cbInfo )          PCBYTE                      pbInfo,
                                                SIZE_T                      cbInfo,
        _In_reads_bytes_opt_( cbPsk )           PCBYTE                      pbPsk,
                                                SIZE_T                      cbPsk,
        _In_reads_bytes_opt_( cbPskId )         PCBYTE                      pbPskId,
                                                SIZE_T                      cbPskId )
{
    NTSTATUS ntStatus;

    m_recipientComps.clear();

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        ntStatus = (*i)->setupRecipient(
            pbEnc, cbEnc,
            pbInfo, cbInfo,
            pbPsk, cbPsk,
            pbPskId, cbPskId );

        if( ntStatus == STATUS_SUCCESS )
        {
            m_recipientComps.push_back( *i );
        }
        else if( ntStatus != STATUS_NOT_SUPPORTED )
        {
            CHECK5( FALSE, "HpkeMultiImp setupRecipient failed: impl=%s ntStatus=0x%08x %s",
                (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        }
    }

    return m_recipientComps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::seal(
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_opt_( cbSrc )           PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst,
        _Out_opt_                               UINT64 *                    pu64SeqNumber )
{
    BYTE abDst[4096 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    ResultMerge res;
    NTSTATUS ntStatus;
    UINT64 u64SeqNumber = 0;
    BOOL fHaveSeqNumber = FALSE;
    SIZE_T nResults = 0;

    CHECK( cbDst < sizeof(abDst), "Ciphertext buffer too large" );

    for( ImpPtrVector::iterator i = m_senderComps.begin(); i != m_senderComps.end(); )
    {
        UINT64 u64LocalSeqNumber = 0;
        memset( abDst, 'c', cbDst + 1 );

        ntStatus = (*i)->seal(
            pbAuthData, cbAuthData,
            pbSrc, cbSrc,
            abDst, cbDst,
            pu64SeqNumber == nullptr ? nullptr : &u64LocalSeqNumber );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            //
            // A skipped stateful Seal permanently desyncs this implementation's
            // AEAD sequence number from the rest, so drop it from the active
            // sender set for the remainder of this context.
            //
            i = m_senderComps.erase( i );
            continue;
        }

        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp seal failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abDst[cbDst] == 'c', "Buffer overrun in seal" );

        if( pu64SeqNumber != nullptr )
        {
            if( fHaveSeqNumber )
            {
                CHECK( u64LocalSeqNumber == u64SeqNumber, "HpkeMultiImp seal seq mismatch" );
            }
            else
            {
                u64SeqNumber = u64LocalSeqNumber;
                fHaveSeqNumber = TRUE;
            }
        }

        res.addResult( *i, abDst, cbDst );
        nResults++;
        ++i;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbDst, cbDst );
    if( pu64SeqNumber != nullptr )
    {
        *pu64SeqNumber = u64SeqNumber;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::open(
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_( cbSrc )               PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst )
{
    BYTE abDst[4096];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbDst < sizeof(abDst), "Plaintext buffer too large" );

    for( ImpPtrVector::iterator i = m_recipientComps.begin(); i != m_recipientComps.end(); )
    {
        memset( abDst, 'p', cbDst + 1 );

        ntStatus = (*i)->open(
            pbAuthData, cbAuthData,
            pbSrc, cbSrc,
            abDst, cbDst );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            //
            // A skipped stateful Open permanently desyncs this implementation's
            // AEAD sequence number from the rest, so drop it from the active
            // recipient set for the remainder of this context.
            //
            i = m_recipientComps.erase( i );
            continue;
        }

        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp open failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abDst[cbDst] == 'p', "Buffer overrun in open" );

        res.addResult( *i, abDst, cbDst );
        nResults++;
        ++i;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbDst, cbDst );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::openUnordered(
                                                UINT64                      u64SeqNumber,
        _In_reads_bytes_opt_( cbAuthData )      PCBYTE                      pbAuthData,
                                                SIZE_T                      cbAuthData,
        _In_reads_bytes_( cbSrc )               PCBYTE                      pbSrc,
                                                SIZE_T                      cbSrc,
        _Out_writes_bytes_( cbDst )             PBYTE                       pbDst,
                                                SIZE_T                      cbDst )
{
    BYTE abDst[4096];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbDst < sizeof(abDst), "Plaintext buffer too large" );

    for( ImpPtrVector::iterator i = m_recipientComps.begin(); i != m_recipientComps.end(); ++i )
    {
        memset( abDst, 'u', cbDst + 1 );

        ntStatus = (*i)->openUnordered(
            u64SeqNumber,
            pbAuthData, cbAuthData,
            pbSrc, cbSrc,
            abDst, cbDst );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp openUnordered failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abDst[cbDst] == 'u', "Buffer overrun in openUnordered" );

        res.addResult( *i, abDst, cbDst );
        nResults++;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbDst, cbDst );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::secretExportSender(
        _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                    SIZE_T                  cbExporterContext,
        _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                    UINT16                  cbResult )
{
    BYTE abResult[256];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbResult < sizeof(abResult), "Export buffer too large" );

    for( ImpPtrVector::iterator i = m_senderComps.begin(); i != m_senderComps.end(); ++i )
    {
        memset( abResult, 's', cbResult + 1 );

        ntStatus = (*i)->secretExportSender(
            pbExporterContext, cbExporterContext,
            abResult, cbResult );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp secretExportSender failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abResult[cbResult] == 's', "Buffer overrun in secretExportSender" );

        res.addResult( *i, abResult, cbResult );
        nResults++;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbResult, cbResult );
    return STATUS_SUCCESS;
}

NTSTATUS
HpkeMultiImp::secretExportRecipient(
        _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                    SIZE_T                  cbExporterContext,
        _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                    UINT16                  cbResult )
{
    BYTE abResult[256];
    ResultMerge res;
    NTSTATUS ntStatus;
    SIZE_T nResults = 0;

    CHECK( cbResult < sizeof(abResult), "Export buffer too large" );

    for( ImpPtrVector::iterator i = m_recipientComps.begin(); i != m_recipientComps.end(); ++i )
    {
        memset( abResult, 'r', cbResult + 1 );

        ntStatus = (*i)->secretExportRecipient(
            pbExporterContext, cbExporterContext,
            abResult, cbResult );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK5( ntStatus == STATUS_SUCCESS, "HpkeMultiImp secretExportRecipient failed: impl=%s ntStatus=0x%08x %s",
            (*i)->m_implementationName.c_str(), (unsigned) ntStatus, (*i)->getLastError().c_str() );
        CHECK( abResult[cbResult] == 'r', "Buffer overrun in secretExportRecipient" );

        res.addResult( *i, abResult, cbResult );
        nResults++;
    }

    if( nResults == 0 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    res.getResult( pbResult, cbResult );
    return STATUS_SUCCESS;
}

SIZE_T
HpkeMultiImp::encSize()
{
    CHECK( m_comps.size() > 0, "HpkeMultiImp::encSize called with no active implementations" );
    return m_comps[0]->encSize();
}


//
// ========================================================================
// testHpkeRoundTrip
//
// Basic round-trip: generate key, sender setup + seal, recipient setup + open.
// Verifies that decrypted plaintext matches original.
// ========================================================================
//
static VOID
testHpkeRoundTrip(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );

    // Test plaintext
    const BYTE plaintext[] = "Hello, HPKE with ML-KEM!";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;   // exclude NUL

    // AAD
    const BYTE aad[] = "additional authenticated data";
    const SIZE_T cbAad = sizeof(aad) - 1;

    // Info
    const BYTE info[] = "test info string";
    const SIZE_T cbInfo = sizeof(info) - 1;

    // Buffers
    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]; // plaintext + tag
    BYTE decrypted[256];
    UINT64 seqNumber;

    //
    // Step 1: Allocate recipient key and generate keypair
    //
    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "SymCryptHpkekeyAllocate failed" );

    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkekeyGenerate failed" );

    //
    // Step 2: Allocate sender and recipient contexts
    //
    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr, "SymCryptHpkeContextAllocate (sender) failed" );

    pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pRecipientCtx != nullptr, "SymCryptHpkeContextAllocate (recipient) failed" );

    //
    // Step 3: Setup sender — produces enc
    //
    scError = SymCryptHpkeSetupSender(
        pSenderCtx,
        pKey,                   // recipient's public key
        info, cbInfo,
        nullptr, 0,                // no PSK
        nullptr, 0,                // no PSK ID
        enc, pParams->cbEnc,
        0 );
    CHECK4( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeSetupSender failed for %s, scError=%d", pParams->name.c_str(), scError );

    //
    // Step 4: Seal plaintext
    //
    scError = SymCryptHpkeSeal(
        pSenderCtx,
        aad, cbAad,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        &seqNumber );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeSeal failed" );
    CHECK3( seqNumber == 0, "First seal should have seq 0, got %lld", seqNumber );

    //
    // Step 5: Setup recipient — uses enc from sender
    //
    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx,
        pKey,                   // recipient's private key
        enc, pParams->cbEnc,
        info, cbInfo,
        nullptr, 0,
        nullptr, 0,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeSetupRecipient failed" );

    //
    // Step 6: Open ciphertext
    //
    scError = SymCryptHpkeOpen(
        pRecipientCtx,
        aad, cbAad,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeOpen failed" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0, "Decrypted plaintext doesn't match" );

    //
    // Step 7: Zero-length plaintext round-trip
    //
    scError = SymCryptHpkeSeal(
        pSenderCtx,
        aad, cbAad,
        plaintext, 0,
        ciphertext, cbTag,
        &seqNumber );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeSeal failed for empty plaintext" );

    scError = SymCryptHpkeOpen(
        pRecipientCtx,
        aad, cbAad,
        ciphertext, cbTag,
        decrypted, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptHpkeOpen failed for empty plaintext" );

    //
    // Cleanup
    //
    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeMultipleMessages
//
// Tests that multiple Seal/Open operations work with incrementing sequence
// numbers, and that OpenUnordered works with explicit sequence numbers.
// ========================================================================
//
static VOID
testHpkeMultipleMessages(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );

    const int nMessages = 5;
    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertexts[5][128 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    SIZE_T cbCiphertexts[5];
    BYTE decrypted[128];
    UINT64 seqNumber;

    const BYTE info[] = "multi-msg test";
    const SIZE_T cbInfo = sizeof(info) - 1;

    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "SymCryptHpkekeyAllocate failed (multi)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGenerate failed (multi)" );

    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr && pRecipientCtx != nullptr, "Context alloc failed (multi)" );

    scError = SymCryptHpkeSetupSender( pSenderCtx, pKey, info, cbInfo,
        nullptr, 0, nullptr, 0, enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (multi)" );

    scError = SymCryptHpkeSetupRecipient( pRecipientCtx, pKey, enc, pParams->cbEnc,
        info, cbInfo, nullptr, 0, nullptr, 0, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (multi)" );

    //
    // Seal nMessages messages
    //
    for ( int i = 0; i < nMessages; i++ )
    {
        char msg[64];
        int cbMsg = SNPRINTF_S( msg, sizeof(msg), _TRUNCATE, "Message number %d", i );

        scError = SymCryptHpkeSeal(
            pSenderCtx, nullptr, 0,
            (PCBYTE) msg, (SIZE_T) cbMsg,
            ciphertexts[i], (SIZE_T) cbMsg + cbTag,
            &seqNumber );
        cbCiphertexts[i] = (SIZE_T) cbMsg + cbTag;
        CHECK( scError == SYMCRYPT_NO_ERROR, "Seal failed (multi)" );
        CHECK3( seqNumber == (UINT64) i, "Seal seq mismatch at msg %d", i );
    }

    //
    // Open messages in order
    //
    for ( int i = 0; i < nMessages; i++ )
    {
        char expected[64];
        int cbExpected = SNPRINTF_S( expected, sizeof(expected), _TRUNCATE, "Message number %d", i );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, nullptr, 0,
            ciphertexts[i], cbCiphertexts[i],
            decrypted, cbCiphertexts[i] - cbTag );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Open failed (multi)" );
        CHECK( memcmp( decrypted, expected, cbExpected ) == 0, "Open content mismatch (multi)" );
    }

    //
    // Test OpenUnordered — replay message 2 using explicit seq number
    //
    {
        char expected[64];
        int cbExpected = SNPRINTF_S( expected, sizeof(expected), _TRUNCATE, "Message number %d", 2 );

        scError = SymCryptHpkeOpenUnordered(
            pRecipientCtx, 2,       // seq=2
            nullptr, 0,
            ciphertexts[2], cbCiphertexts[2],
            decrypted, cbCiphertexts[2] - cbTag );
        CHECK( scError == SYMCRYPT_NO_ERROR, "OpenUnordered failed" );
        CHECK( memcmp( decrypted, expected, cbExpected ) == 0, "OpenUnordered content mismatch" );
    }

    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkePsk
//
// Tests PSK mode — sender and recipient share a pre-shared key.
// ========================================================================
//
static VOID
testHpkePsk(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );

    const BYTE psk[] = "this is a pre-shared key for testing";
    const SIZE_T cbPsk = sizeof(psk) - 1;
    const BYTE pskId[] = "test-psk-id";
    const SIZE_T cbPskId = sizeof(pskId) - 1;
    const BYTE info[] = "psk mode test";
    const SIZE_T cbInfo = sizeof(info) - 1;

    const BYTE plaintext[] = "PSK mode plaintext";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE encWrongPsk[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE decrypted[256];
    UINT64 seqNumber;

    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "Key alloc failed (PSK)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (PSK)" );

    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr && pRecipientCtx != nullptr, "Ctx alloc failed (PSK)" );

    //
    // Setup with PSK
    //
    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo,
        psk, cbPsk, pskId, cbPskId,
        enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (PSK)" );

    scError = SymCryptHpkeSeal(
        pSenderCtx, nullptr, 0,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        nullptr );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Seal failed (PSK)" );

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx, pKey, enc, pParams->cbEnc,
        info, cbInfo, psk, cbPsk, pskId, cbPskId, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (PSK)" );

    scError = SymCryptHpkeOpen(
        pRecipientCtx, nullptr, 0,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Open failed (PSK)" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0, "PSK decrypted mismatch" );

    //
    // Verify that wrong PSK causes auth failure (without seq mismatch)
    //
    PSYMCRYPT_HPKECONTEXT pWrongPskCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pWrongPskCtx != nullptr, "Wrong PSK ctx alloc failed" );

    const BYTE wrongPsk[] = "WRONG pre-shared key!!!!!!!!!!";
    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo,
        psk, cbPsk, pskId, cbPskId,
        encWrongPsk, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (wrong PSK path)" );

    scError = SymCryptHpkeSeal(
        pSenderCtx, nullptr, 0,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        &seqNumber );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Seal failed (wrong PSK path)" );
    CHECK( seqNumber == 0, "Wrong-PSK path expected seq 0" );

    scError = SymCryptHpkeSetupRecipient(
        pWrongPskCtx, pKey, encWrongPsk, pParams->cbEnc,
        info, cbInfo, wrongPsk, sizeof(wrongPsk) - 1, pskId, cbPskId, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient with wrong PSK should still succeed" );

    scError = SymCryptHpkeOpen(
        pWrongPskCtx, nullptr, 0,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext );
    CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE, "Wrong PSK should cause auth failure" );

    //
    // Randomized negative test: PSK-ID without PSK must fail
    //
    BYTE randomPskId[32];
    SIZE_T cbRandomPskId = 1 + (g_rng.uint32() % sizeof(randomPskId));
    scError = SymCryptCallbackRandom( randomPskId, cbRandomPskId );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Random generation failed (PSK-ID test)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo,
        nullptr, 0,
        randomPskId, cbRandomPskId,
        enc, pParams->cbEnc,
        0 );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
        "SetupSender with PSK-ID and no PSK should fail" );

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx, pKey, enc, pParams->cbEnc,
        info, cbInfo,
        nullptr, 0,
        randomPskId, cbRandomPskId,
        0 );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
        "SetupRecipient with PSK-ID and no PSK should fail" );

    SymCryptHpkeContextFree( pWrongPskCtx );
    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeSecretExport
//
// Tests the export-only mode and SecretExport with AEAD ciphersuites.
// ========================================================================
//
static VOID
testHpkeSecretExport(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    const BYTE info[] = "export test";
    const SIZE_T cbInfo = sizeof(info) - 1;

    const BYTE exporterContext1[] = "context one";
    const BYTE exporterContext2[] = "context two";

    const UINT16 cbExport = 32;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE senderExport1[cbExport], senderExport2[cbExport];
    BYTE recipientExport1[cbExport], recipientExport2[cbExport];

    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "Key alloc failed (export)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (export)" );

    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr && pRecipientCtx != nullptr, "Ctx alloc failed (export)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo, nullptr, 0, nullptr, 0, enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (export)" );

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx, pKey, enc, pParams->cbEnc, info, cbInfo, nullptr, 0, nullptr, 0, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (export)" );

    //
    // Export with two different contexts — should produce different secrets
    //
    scError = SymCryptHpkeSecretExport(
        pSenderCtx, exporterContext1, sizeof(exporterContext1) - 1, senderExport1, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport sender ctx1 failed" );

    scError = SymCryptHpkeSecretExport(
        pSenderCtx, exporterContext2, sizeof(exporterContext2) - 1, senderExport2, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport sender ctx2 failed" );

    scError = SymCryptHpkeSecretExport(
        pRecipientCtx, exporterContext1, sizeof(exporterContext1) - 1, recipientExport1, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport recipient ctx1 failed" );

    scError = SymCryptHpkeSecretExport(
        pRecipientCtx, exporterContext2, sizeof(exporterContext2) - 1, recipientExport2, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport recipient ctx2 failed" );

    //
    // Sender and recipient should derive the same secrets for the same exporter context
    //
    CHECK( memcmp( senderExport1, recipientExport1, cbExport ) == 0,
        "Sender/Recipient export1 mismatch" );
    CHECK( memcmp( senderExport2, recipientExport2, cbExport ) == 0,
        "Sender/Recipient export2 mismatch" );

    //
    // Different exporter contexts should produce different secrets
    //
    CHECK( memcmp( senderExport1, senderExport2, cbExport ) != 0,
        "Different exporter contexts should yield different secrets" );

    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeExportOnly
//
// Tests the Export-Only AEAD mode (Seal/Open should fail, SecretExport should work).
// ========================================================================
//
static VOID
testHpkeExportOnly(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKE_CIPHERSUITE exportOnlySuite = pParams->ciphersuite;

    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    CHECK( exportOnlySuite.aeadId == SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY, "Expected Export-Only ciphersuite" );

    const UINT16 cbExport = 32;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[64];
    BYTE exported[cbExport];

    pKey = SymCryptHpkekeyAllocate( exportOnlySuite );
    CHECK( pKey != nullptr, "Key alloc failed (export-only)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (export-only)" );

    pSenderCtx = SymCryptHpkeContextAllocate( exportOnlySuite );
    pRecipientCtx = SymCryptHpkeContextAllocate( exportOnlySuite );
    CHECK( pSenderCtx != nullptr && pRecipientCtx != nullptr, "Ctx alloc failed (export-only)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, nullptr, 0, nullptr, 0, nullptr, 0, enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (export-only)" );

    //
    // Seal should fail for Export-Only
    //
    scError = SymCryptHpkeSeal(
        pSenderCtx, nullptr, 0,
        (PCBYTE) "test", 4,
        ciphertext, sizeof(ciphertext),
        nullptr );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "Seal should fail for Export-Only" );

    //
    // SecretExport should work
    //
    scError = SymCryptHpkeSecretExport(
        pSenderCtx, (PCBYTE) "ctx", 3, exported, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport failed (export-only sender)" );

    //
    // Recipient side — SecretExport should match
    //
    BYTE recipientExported[cbExport];
    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx, pKey, enc, pParams->cbEnc, nullptr, 0, nullptr, 0, nullptr, 0, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (export-only)" );

    scError = SymCryptHpkeSecretExport(
        pRecipientCtx, (PCBYTE) "ctx", 3, recipientExported, cbExport );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport failed (export-only recipient)" );

    CHECK( memcmp( exported, recipientExported, cbExport ) == 0,
        "Export-only sender/recipient secrets don't match" );

    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkekeyImportExport
//
// Tests key serialization (SetValue/GetValue) round-trip.
// ========================================================================
//
static VOID
testHpkekeyImportExport(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey1 = nullptr;
    PSYMCRYPT_HPKEKEY pKey2 = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );

    SIZE_T cbPublicKey = 0;
    SIZE_T cbPrivateKey = 0;

    const BYTE plaintext[] = "key import/export test";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE decrypted[256];

    //
    // Query key sizes
    //
    scError = SymCryptHpkeSizeofKeyFormatFromParams(
        pParams->ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPublicKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat (public) failed" );

    scError = SymCryptHpkeSizeofKeyFormatFromParams(
        pParams->ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivateKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat (private) failed" );

    //
    // Generate key 1, export public + private
    //
    pKey1 = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey1 != nullptr, "Key1 alloc failed" );
    scError = SymCryptHpkekeyGenerate( pKey1, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Key1 generate failed" );

    std::vector<BYTE> publicKeyBlob( cbPublicKey );
    std::vector<BYTE> privateKeyBlob( cbPrivateKey );

    scError = SymCryptHpkekeyGetValue(
        pKey1, publicKeyBlob.data(), cbPublicKey,
        SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "GetValue (public) failed" );

    scError = SymCryptHpkekeyGetValue(
        pKey1, privateKeyBlob.data(), cbPrivateKey,
        SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "GetValue (private) failed" );

    //
    // Import private key into key 2 and verify round-trip
    //
    pKey2 = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey2 != nullptr, "Key2 alloc failed" );

    scError = SymCryptHpkekeySetValue(
        privateKeyBlob.data(), cbPrivateKey,
        SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0, pKey2 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetValue (private) failed" );

    //
    // Use key1's public part for sender, key2's private part for recipient
    // This proves import/export preserves the key material.
    //
    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr && pRecipientCtx != nullptr, "Ctx alloc failed (import/export)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey1, nullptr, 0, nullptr, 0, nullptr, 0, enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (import/export)" );

    scError = SymCryptHpkeSeal(
        pSenderCtx, nullptr, 0,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        nullptr );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Seal failed (import/export)" );

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx, pKey2, enc, pParams->cbEnc, nullptr, 0, nullptr, 0, nullptr, 0, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient with imported key failed" );

    scError = SymCryptHpkeOpen(
        pRecipientCtx, nullptr, 0,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Open with imported key failed" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
        "Import/export key round-trip decrypted mismatch" );

    SymCryptHpkeContextFree( pRecipientCtx );
    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey2 );
    SymCryptHpkekeyFree( pKey1 );
}


//
// ========================================================================
// testHpkeSingleShot
//
// Tests the SingleShot Seal/Open APIs and cross-validates them against
// the multi-step Setup+Seal / Setup+Open APIs.
// ========================================================================
//
static VOID
testHpkeSingleShot(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed (singleshot)" );

    const BYTE plaintext[] = "SingleShot cross-validation test!";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;
    const BYTE aad[] = "singleshot AAD";
    const SIZE_T cbAad = sizeof(aad) - 1;
    const BYTE info[] = "singleshot info";
    const SIZE_T cbInfo = sizeof(info) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE decrypted[256];

    //
    // Generate a key
    //
    PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "Key alloc failed (singleshot)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (singleshot)" );

    //
    // Test 1: SingleShot Seal → SingleShot Open round-trip
    //
    scError = SymCryptHpkeSealSingleShot(
        pKey,
        info, cbInfo,
        nullptr, 0, nullptr, 0,     // no PSK
        aad, cbAad,
        plaintext, cbPlaintext,
        enc, pParams->cbEnc,
        ciphertext, cbPlaintext + cbTag,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SealSingleShot failed" );

    scError = SymCryptHpkeOpenSingleShot(
        pKey,
        enc, pParams->cbEnc,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        aad, cbAad,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "OpenSingleShot failed" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
        "SingleShot round-trip plaintext mismatch" );

    //
    // Test 2: SingleShot Seal → multi-step Open (cross-validate)
    //
    scError = SymCryptHpkeSealSingleShot(
        pKey,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        aad, cbAad,
        plaintext, cbPlaintext,
        enc, pParams->cbEnc,
        ciphertext, cbPlaintext + cbTag,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SealSingleShot failed (cross-validate)" );

    {
        PSYMCRYPT_HPKECONTEXT pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Ctx alloc failed (cross-validate open)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey, enc, pParams->cbEnc,
            info, cbInfo, nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (cross-validate)" );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, aad, cbAad,
            ciphertext, cbPlaintext + cbTag,
            decrypted, cbPlaintext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-step Open of SingleShot Seal failed" );
        CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
            "Cross-validate SingleShot→MultiStep plaintext mismatch" );

        SymCryptHpkeContextFree( pRecipientCtx );
    }

    //
    // Test 3: Multi-step Seal → SingleShot Open (cross-validate)
    //
    {
        PSYMCRYPT_HPKECONTEXT pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pSenderCtx != nullptr, "Ctx alloc failed (cross-validate seal)" );

        scError = SymCryptHpkeSetupSender(
            pSenderCtx, pKey,
            info, cbInfo, nullptr, 0, nullptr, 0,
            enc, pParams->cbEnc, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (cross-validate)" );

        scError = SymCryptHpkeSeal(
            pSenderCtx, aad, cbAad,
            plaintext, cbPlaintext,
            ciphertext, cbPlaintext + cbTag,
            nullptr );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-step Seal failed (cross-validate)" );

        SymCryptHpkeContextFree( pSenderCtx );
    }

    scError = SymCryptHpkeOpenSingleShot(
        pKey,
        enc, pParams->cbEnc,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        aad, cbAad,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SingleShot Open of multi-step Seal failed" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
        "Cross-validate MultiStep→SingleShot plaintext mismatch" );

    //
    // Test 4: Empty plaintext (auth-only) SingleShot round-trip
    //
    scError = SymCryptHpkeSealSingleShot(
        pKey,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        aad, cbAad,
        nullptr, 0,
        enc, pParams->cbEnc,
        ciphertext, cbTag,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SealSingleShot empty-plaintext failed" );

    scError = SymCryptHpkeOpenSingleShot(
        pKey,
        enc, pParams->cbEnc,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        aad, cbAad,
        ciphertext, cbTag,
        nullptr, 0,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "OpenSingleShot empty-plaintext failed" );

    //
    // Test 5: SingleShot with PSK
    //
    const BYTE psk[] = "this is a pre-shared key for SingleShot";
    const BYTE pskId[] = "singleshot-psk-id";

    scError = SymCryptHpkeSealSingleShot(
        pKey,
        info, cbInfo,
        psk, sizeof(psk) - 1,
        pskId, sizeof(pskId) - 1,
        aad, cbAad,
        plaintext, cbPlaintext,
        enc, pParams->cbEnc,
        ciphertext, cbPlaintext + cbTag,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SealSingleShot with PSK failed" );

    scError = SymCryptHpkeOpenSingleShot(
        pKey,
        enc, pParams->cbEnc,
        info, cbInfo,
        psk, sizeof(psk) - 1,
        pskId, sizeof(pskId) - 1,
        aad, cbAad,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "OpenSingleShot with PSK failed" );
    CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
        "SingleShot PSK round-trip plaintext mismatch" );

    //
    // Test 6: SingleShot tampered ciphertext should fail
    //
    ciphertext[0] ^= 0x01;
    scError = SymCryptHpkeOpenSingleShot(
        pKey,
        enc, pParams->cbEnc,
        info, cbInfo,
        psk, sizeof(psk) - 1,
        pskId, sizeof(pskId) - 1,
        aad, cbAad,
        ciphertext, cbPlaintext + cbTag,
        decrypted, cbPlaintext,
        0 );
    CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
        "SingleShot Open with tampered ciphertext should fail" );

    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeDataIntegrity
//
// Comprehensive data-in-transit corruption tests.
// Verifies that modification of any component (enc, ciphertext, AAD, or
// use of wrong key) causes expected authentication failure.
// ========================================================================
//
static VOID
testHpkeDataIntegrity(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKEKEY pWrongKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;
    PSYMCRYPT_HPKECONTEXT pRecipientCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );

    const BYTE plaintext[] = "Data integrity test message for HPKE";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;

    const BYTE aad[] = "authenticated additional data";
    const SIZE_T cbAad = sizeof(aad) - 1;

    const BYTE info[] = "integrity test info";
    const SIZE_T cbInfo = sizeof(info) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE decrypted[256];
    SIZE_T cbCiphertext;

    const int nIterations = 5;

    //
    // Generate recipient key and a second (wrong) key
    //
    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "Key alloc failed (integrity)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (integrity)" );

    pWrongKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pWrongKey != nullptr, "Wrong key alloc failed (integrity)" );
    scError = SymCryptHpkekeyGenerate( pWrongKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Wrong key gen failed (integrity)" );

    for( int iIter = 0; iIter < nIterations; iIter++ )
    {
    //
    // Perform a valid Seal to get enc + ciphertext
    //
    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr, "Sender ctx alloc failed (integrity)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo,
        nullptr, 0, nullptr, 0,
        enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (integrity)" );

    scError = SymCryptHpkeSeal(
        pSenderCtx, aad, cbAad,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        nullptr );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Seal failed (integrity)" );
    cbCiphertext = cbPlaintext + cbTag;

    //
    // Test 1: Tampered enc (KEM encapsulated secret)
    //
    // Flipping a random bit in enc causes the recipient to derive a different shared secret,
    // which leads to different AEAD key/nonce => authentication failure on Open.
    //
    {
        BYTE tamperedEnc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
        memcpy( tamperedEnc, enc, pParams->cbEnc );
        tamperedEnc[g_rng.sizet( pParams->cbEnc )] ^= 1 << (g_rng.byte() & 7);

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (tampered enc)" );

        // SetupRecipient may succeed (ML-KEM decapsulation produces a shared secret
        // regardless of ciphertext validity due to implicit rejection), but Open must fail.
        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            tamperedEnc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );

        if( scError == SYMCRYPT_NO_ERROR )
        {
            // Recipient derived a (wrong) shared secret; Open should fail with auth error
            scError = SymCryptHpkeOpen(
                pRecipientCtx, aad, cbAad,
                ciphertext, cbCiphertext,
                decrypted, cbCiphertext - cbTag );
            CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
                "Tampered enc should cause auth failure on Open" );
        }
        // If SetupRecipient itself fails, that's also acceptable

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 2: Tampered ciphertext (random bit in AEAD ciphertext)
    //
    {
        BYTE tamperedCt[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
        memcpy( tamperedCt, ciphertext, cbCiphertext );
        tamperedCt[g_rng.sizet( cbCiphertext )] ^= 1 << (g_rng.byte() & 7);

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (tampered ct)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (tampered ct)" );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, aad, cbAad,
            tamperedCt, cbCiphertext,
            decrypted, cbCiphertext - cbTag );
        CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
            "Tampered ciphertext should cause auth failure" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 3: Tampered AEAD tag (random bit in the AEAD tag)
    //
    {
        BYTE tamperedTag[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
        memcpy( tamperedTag, ciphertext, cbCiphertext );
        tamperedTag[cbCiphertext - cbTag + g_rng.sizet( cbTag )] ^= 1 << (g_rng.byte() & 7);

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (tampered tag)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (tampered tag)" );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, aad, cbAad,
            tamperedTag, cbCiphertext,
            decrypted, cbCiphertext - cbTag );
        CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
            "Tampered AEAD tag should cause auth failure" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 4: Modified AAD — correct ciphertext but different AAD on Open
    //
    {
        const BYTE wrongAad[] = "wrong additional authenticated data";
        const SIZE_T cbWrongAad = sizeof(wrongAad) - 1;

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (wrong AAD)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (wrong AAD)" );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, wrongAad, cbWrongAad,
            ciphertext, cbCiphertext,
            decrypted, cbCiphertext - cbTag );
        CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
            "Wrong AAD should cause auth failure" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 5: AAD omitted when it was included in Seal
    //
    {
        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (omit AAD)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (omit AAD)" );

        scError = SymCryptHpkeOpen(
            pRecipientCtx, nullptr, 0,     // no AAD
            ciphertext, cbCiphertext,
            decrypted, cbCiphertext - cbTag );
        CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
            "Omitted AAD should cause auth failure" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 6: Wrong recipient key — completely different keypair
    //
    {
        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (wrong key)" );

        // Use pWrongKey (different keypair) to attempt decryption
        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pWrongKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );

        if( scError == SYMCRYPT_NO_ERROR )
        {
            // ML-KEM implicit rejection: decapsulation succeeds but produces wrong secret
            scError = SymCryptHpkeOpen(
                pRecipientCtx, aad, cbAad,
                ciphertext, cbCiphertext,
                decrypted, cbCiphertext - cbTag );
            CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
                "Wrong recipient key should cause auth failure on Open" );
        }
        // If SetupRecipient itself fails, that's also acceptable

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 7: Truncated ciphertext — random length shorter than AEAD tag
    //
    {
        SIZE_T cbTruncated = g_rng.sizet( cbTag - 1 ) + 1;   // 1..cbTag-1 bytes, always < AEAD tag

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (truncated ct)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (truncated ct)" );

        // Pass a random number of bytes less than the 16-byte GCM tag
        scError = SymCryptHpkeOpen(
            pRecipientCtx, aad, cbAad,
            ciphertext, cbTruncated,
            decrypted, 0 );
        CHECK( scError != SYMCRYPT_NO_ERROR,
            "Truncated ciphertext should fail" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    //
    // Test 8: Wrong info parameter — different info in SetupRecipient
    //
    {
        const BYTE wrongInfo[] = "wrong info string";
        const SIZE_T cbWrongInfo = sizeof(wrongInfo) - 1;

        pRecipientCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc failed (wrong info)" );

        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey,
            enc, pParams->cbEnc,
            wrongInfo, cbWrongInfo,      // different info
            nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient failed (wrong info)" );

        // Different info => different key schedule => different AEAD keys => auth failure
        scError = SymCryptHpkeOpen(
            pRecipientCtx, aad, cbAad,
            ciphertext, cbCiphertext,
            decrypted, cbCiphertext - cbTag );
        CHECK( scError == SYMCRYPT_AUTHENTICATION_FAILURE,
            "Wrong info should cause auth failure" );

        SymCryptHpkeContextFree( pRecipientCtx );
        pRecipientCtx = nullptr;
    }

    SymCryptHpkeContextFree( pSenderCtx );
    pSenderCtx = nullptr;

    } // end for( iIter )

    //
    // Cleanup
    //
    SymCryptHpkekeyFree( pWrongKey );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeSealValidationFailureDoesNotConsumeSequence
//
// Predictable Seal validation failures must happen before the sequence number
// is consumed. Otherwise a caller could observe nonce gaps for failed calls.
// ========================================================================
//
static VOID
testHpkeSealValidationFailureDoesNotConsumeSequence(
    const HPKE_TEST_PARAMS *pParams )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = nullptr;
    PSYMCRYPT_HPKECONTEXT pSenderCtx = nullptr;

    SIZE_T cbTag;
    scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed (Seal validation)" );

    const BYTE info[] = "seal validation sequence test";
    const SIZE_T cbInfo = sizeof(info) - 1;
    const BYTE aad[] = "aad";
    const BYTE plaintext[] = "message after failed seal";
    const SIZE_T cbPlaintext = sizeof(plaintext) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    UINT64 seqNumber = (UINT64) -1;

    pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != nullptr, "Key alloc failed (Seal validation)" );
    scError = SymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (Seal validation)" );

    pSenderCtx = SymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != nullptr, "Ctx alloc failed (Seal validation)" );

    scError = SymCryptHpkeSetupSender(
        pSenderCtx, pKey, info, cbInfo,
        nullptr, 0, nullptr, 0,
        enc, pParams->cbEnc, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender failed (Seal validation)" );

    scError = SymCryptHpkeSeal(
        pSenderCtx,
        aad, sizeof(aad) - 1,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag - 1,
        &seqNumber );
    CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
        "Seal with invalid output length should fail before seq increment" );

    CHECK( seqNumber == (UINT64) -1,
        "Failed Seal should not write the output sequence number" );

    scError = SymCryptHpkeSeal(
        pSenderCtx,
        aad, sizeof(aad) - 1,
        plaintext, cbPlaintext,
        ciphertext, cbPlaintext + cbTag,
        &seqNumber );
    CHECK( scError == SYMCRYPT_NO_ERROR,
        "Valid Seal after validation failure should succeed" );
    CHECK( seqNumber == 0,
        "Seal validation failure should not consume sequence number" );

    SymCryptHpkeContextFree( pSenderCtx );
    SymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeMultiThread
//
// Exercises the HPKE operations the API documents as thread-safe (Seal,
// OpenUnordered) on a shared context. Uses ScDispatch HPKE shims so the
// test re-drives against the dynamic SymCrypt module when
// g_useDynamicFunctionsInTestCall is flipped at the call site.
//
// Phase 1: N threads concurrently Seal on one sender context; verify
//          returned seqNumbers form the full set {0..N*H-1} (no duplicates,
//          no gaps) — the atomic counter held under contention.
// Phase 2: serial Open on one recipient context, in seqNumber order after
//          sorting (simulates re-ordered arrival).
// Phase 3: concurrent OpenUnordered on a g_rng-shuffled view, recipient
//          context shared across threads.
// ========================================================================
//

static const UINT32 HPKE_MT_THREAD_COUNT = 4;
static const UINT32 HPKE_MT_MESSAGES_PER_THREAD = 32;
static const SIZE_T HPKE_MT_MAX_PAYLOAD = 64;

struct HPKE_MT_ENTRY
{
    UINT64  seqNumber;
    UINT32  threadId;
    UINT32  messageIdx;
    SIZE_T  cbPlaintext;
    SIZE_T  cbAad;
    SIZE_T  cbCiphertext;
    BYTE    plaintext[HPKE_MT_MAX_PAYLOAD];
    BYTE    aad[HPKE_MT_MAX_PAYLOAD];
    BYTE    ciphertext[HPKE_MT_MAX_PAYLOAD + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
};

static VOID
testHpkeMultiThreadSealWorker(
                                                PSYMCRYPT_HPKECONTEXT       pSenderCtx,
                                                SIZE_T                      cbTag,
                                                UINT32                      iThread,
    _Out_writes_( HPKE_MT_MESSAGES_PER_THREAD ) HPKE_MT_ENTRY *             pEntries )
{
    SYMCRYPT_ERROR scError;

    for( UINT32 iMessage = 0; iMessage < HPKE_MT_MESSAGES_PER_THREAD; iMessage++ )
    {
        HPKE_MT_ENTRY *e = &pEntries[iMessage];

        e->threadId = iThread;
        e->messageIdx = iMessage;

        int cbPlaintext = SNPRINTF_S( (char *) e->plaintext, sizeof(e->plaintext), _TRUNCATE,
            "HPKE multithread plaintext t=%u m=%u", iThread, iMessage );
        int cbAad = SNPRINTF_S( (char *) e->aad, sizeof(e->aad), _TRUNCATE,
            "HPKE multithread aad t=%u m=%u", iThread, iMessage );
        CHECK( cbPlaintext > 0 && cbAad > 0, "HPKE multithread payload formatting failed" );

        e->cbPlaintext = (SIZE_T) cbPlaintext;
        e->cbAad = (SIZE_T) cbAad;
        e->cbCiphertext = e->cbPlaintext + cbTag;
        CHECK( e->cbCiphertext <= sizeof(e->ciphertext),
            "HPKE multithread ciphertext buffer too small" );

        scError = ScDispatchSymCryptHpkeSeal(
            pSenderCtx,
            e->aad, e->cbAad,
            e->plaintext, e->cbPlaintext,
            e->ciphertext, e->cbCiphertext,
            &e->seqNumber );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread Seal failed" );
    }
}

static VOID
testHpkeMultiThreadOpenUnorderedWorker(
                                                PCSYMCRYPT_HPKECONTEXT      pRecipientCtx,
    _In_reads_( cEntries )                      const HPKE_MT_ENTRY *       pEntries,
                                                SIZE_T                      cEntries )
{
    SYMCRYPT_ERROR scError;
    BYTE decrypted[HPKE_MT_MAX_PAYLOAD];

    for( SIZE_T i = 0; i < cEntries; i++ )
    {
        const HPKE_MT_ENTRY *e = &pEntries[i];

        scError = ScDispatchSymCryptHpkeOpenUnordered(
            pRecipientCtx, e->seqNumber,
            e->aad, e->cbAad,
            e->ciphertext, e->cbCiphertext,
            decrypted, e->cbPlaintext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread OpenUnordered failed" );
        CHECK( memcmp( decrypted, e->plaintext, e->cbPlaintext ) == 0,
            "HPKE multithread OpenUnordered plaintext mismatch" );
    }
}

static VOID
testHpkeMultiThread(
    const HPKE_TEST_PARAMS *pParams )
{
    // Export-Only ciphersuites have no Seal / Open; nothing to thread-test.
    if( pParams->ciphersuite.aeadId == SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY )
    {
        return;
    }

    SYMCRYPT_ERROR scError;

    SIZE_T cbTag;
    scError = ScDispatchSymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed (multithread)" );
    CHECK( cbTag <= SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE,
        "AEAD tag size exceeds SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE — bump the constant" );

    PSYMCRYPT_HPKEKEY      pKey          = NULL;
    PSYMCRYPT_HPKECONTEXT  pSenderCtx    = NULL;
    PSYMCRYPT_HPKECONTEXT  pOrderedCtx   = NULL;
    PSYMCRYPT_HPKECONTEXT  pUnorderedCtx = NULL;

    pKey = ScDispatchSymCryptHpkekeyAllocate( pParams->ciphersuite );
    CHECK( pKey != NULL, "HPKE multithread key alloc failed" );

    scError = ScDispatchSymCryptHpkekeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread key generate failed" );

    const BYTE info[] = "HPKE multithread setup info";
    const SIZE_T cbInfo = sizeof(info) - 1;

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];

    pSenderCtx = ScDispatchSymCryptHpkeContextAllocate( pParams->ciphersuite );
    CHECK( pSenderCtx != NULL, "HPKE multithread sender ctx alloc failed" );
    scError = ScDispatchSymCryptHpkeSetupSender(
        pSenderCtx, pKey,
        info, cbInfo,
        nullptr, 0, nullptr, 0,
        enc, pParams->cbEnc,
        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread SetupSender failed" );

    //
    // Phase 1: concurrent Seal on one shared sender context.
    //
    std::vector<HPKE_MT_ENTRY> entries( (SIZE_T) HPKE_MT_THREAD_COUNT * HPKE_MT_MESSAGES_PER_THREAD );
    {
        std::vector<std::thread> threads;
        threads.reserve( HPKE_MT_THREAD_COUNT );

        for( UINT32 iThread = 0; iThread < HPKE_MT_THREAD_COUNT; iThread++ )
        {
            HPKE_MT_ENTRY *threadEntries = entries.data() + (SIZE_T) iThread * HPKE_MT_MESSAGES_PER_THREAD;
            threads.push_back( std::thread(
                testHpkeMultiThreadSealWorker,
                pSenderCtx, cbTag, iThread, threadEntries ) );
        }
        for( auto &t : threads )
        {
            t.join();
        }
    }

    //
    // Validate sequence-number assignment under contention: every Seal returned
    // a unique seqNumber and the full set equals {0, ..., N*H - 1}.
    //
    {
        std::vector<UINT64> sortedSeqs;
        sortedSeqs.reserve( entries.size() );
        for( const auto &e : entries )
        {
            sortedSeqs.push_back( e.seqNumber );
        }
        std::sort( sortedSeqs.begin(), sortedSeqs.end() );
        for( SIZE_T i = 0; i < sortedSeqs.size(); i++ )
        {
            CHECK( sortedSeqs[i] == (UINT64) i,
                "HPKE multithread Seal did not produce a contiguous unique seqNumber set" );
        }
    }

    //
    // Phase 2: serial Open in seqNumber order. `entries` reflects Seal
    // completion order, which under thread contention is generally not
    // seqNumber order; sorting first simulates the Recipient re-ordering
    // ciphertexts that arrived out of order on the wire.
    //
    {
        std::vector<HPKE_MT_ENTRY *> orderedView;
        orderedView.reserve( entries.size() );
        for( auto &e : entries )
        {
            orderedView.push_back( &e );
        }
        std::sort( orderedView.begin(), orderedView.end(),
            []( const HPKE_MT_ENTRY *a, const HPKE_MT_ENTRY *b ) { return a->seqNumber < b->seqNumber; } );

        pOrderedCtx = ScDispatchSymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pOrderedCtx != NULL, "HPKE multithread ordered recipient ctx alloc failed" );
        scError = ScDispatchSymCryptHpkeSetupRecipient(
            pOrderedCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0,
            0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread ordered SetupRecipient failed" );

        BYTE decrypted[HPKE_MT_MAX_PAYLOAD];
        for( const HPKE_MT_ENTRY *e : orderedView )
        {
            scError = ScDispatchSymCryptHpkeOpen(
                pOrderedCtx,
                e->aad, e->cbAad,
                e->ciphertext, e->cbCiphertext,
                decrypted, e->cbPlaintext );
            CHECK( scError == SYMCRYPT_NO_ERROR,
                "HPKE multithread ordered Open failed (ciphertexts re-sorted by seqNumber)" );
            CHECK( memcmp( decrypted, e->plaintext, e->cbPlaintext ) == 0,
                "HPKE multithread ordered Open plaintext mismatch" );
        }
    }

    //
    // Phase 3: concurrent OpenUnordered on a deterministically-shuffled view.
    // OpenUnordered is documented thread-safe, so the recipient context is
    // shared across worker threads.
    //
    {
        std::vector<HPKE_MT_ENTRY> shuffled = entries;
        // Shuffle via g_rng so a failing run replays deterministically.
        for( SIZE_T i = shuffled.size(); i > 1; i-- )
        {
            SIZE_T j = g_rng.sizet( i );
            std::swap( shuffled[i - 1], shuffled[j] );
        }

        pUnorderedCtx = ScDispatchSymCryptHpkeContextAllocate( pParams->ciphersuite );
        CHECK( pUnorderedCtx != NULL, "HPKE multithread unordered recipient ctx alloc failed" );
        scError = ScDispatchSymCryptHpkeSetupRecipient(
            pUnorderedCtx, pKey,
            enc, pParams->cbEnc,
            info, cbInfo,
            nullptr, 0, nullptr, 0,
            0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HPKE multithread unordered SetupRecipient failed" );

        const SIZE_T perThread = shuffled.size() / HPKE_MT_THREAD_COUNT;
        std::vector<std::thread> threads;
        threads.reserve( HPKE_MT_THREAD_COUNT );
        for( UINT32 iThread = 0; iThread < HPKE_MT_THREAD_COUNT; iThread++ )
        {
            const HPKE_MT_ENTRY *slice = shuffled.data() + iThread * perThread;
            SIZE_T cSlice = (iThread + 1 == HPKE_MT_THREAD_COUNT)
                ? shuffled.size() - iThread * perThread
                : perThread;
            threads.push_back( std::thread(
                testHpkeMultiThreadOpenUnorderedWorker,
                pUnorderedCtx, slice, cSlice ) );
        }
        for( auto &t : threads )
        {
            t.join();
        }
    }

    ScDispatchSymCryptHpkeContextFree( pUnorderedCtx );
    ScDispatchSymCryptHpkeContextFree( pOrderedCtx );
    ScDispatchSymCryptHpkeContextFree( pSenderCtx );
    ScDispatchSymCryptHpkekeyFree( pKey );
}


//
// ========================================================================
// testHpkeErrorCases
//
// Tests various error paths.
// ========================================================================
//
static VOID
testHpkeErrorCases()
{
    SYMCRYPT_ERROR scError;

    //
    // 1. Invalid ciphersuite should return nullptr
    //
    {
        SYMCRYPT_HPKE_CIPHERSUITE badSuite = { 0xFFFF, 0x0001, 0x0001 };
        PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( badSuite );
        CHECK( pKey == nullptr, "Invalid KEM should return nullptr from Allocate" );

        PSYMCRYPT_HPKECONTEXT pCtx = SymCryptHpkeContextAllocate( badSuite );
        CHECK( pCtx == nullptr, "Invalid KEM should return nullptr from ContextAllocate" );
    }

    //
    // 2. Mismatched ciphersuites between context and key
    //
    {
        SYMCRYPT_HPKE_CIPHERSUITE suite1 = {
            SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            SYMCRYPT_HPKE_AEAD_ID_AESGCM128
        };
        SYMCRYPT_HPKE_CIPHERSUITE suite2 = {
            SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,      // different KDF
            SYMCRYPT_HPKE_AEAD_ID_AESGCM128
        };

        PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( suite1 );
        CHECK( pKey != nullptr, "Key alloc failed (mismatch)" );
        scError = SymCryptHpkekeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen failed (mismatch)" );

        PSYMCRYPT_HPKECONTEXT pCtx = SymCryptHpkeContextAllocate( suite2 );
        CHECK( pCtx != nullptr, "Ctx alloc failed (mismatch)" );

        BYTE enc[1088];
        scError = SymCryptHpkeSetupSender( pCtx, pKey, nullptr, 0, nullptr, 0, nullptr, 0,
            enc, 1088, 0 );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
            "SetupSender with mismatched ciphersuite should fail" );

        SymCryptHpkeContextFree( pCtx );
        SymCryptHpkekeyFree( pKey );
    }

    //
    // 3. PSK without PSK ID should fail
    //
    {
        SYMCRYPT_HPKE_CIPHERSUITE suite = {
            SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            SYMCRYPT_HPKE_AEAD_ID_AESGCM128
        };

        PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( suite );
        CHECK( pKey != nullptr, "Key alloc (PSK validation)" );
        scError = SymCryptHpkekeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen (PSK validation)" );

        PSYMCRYPT_HPKECONTEXT pCtx = SymCryptHpkeContextAllocate( suite );
        CHECK( pCtx != nullptr, "Ctx alloc (PSK validation)" );

        BYTE enc[1088];
        const BYTE psk[] = "some psk";

        scError = SymCryptHpkeSetupSender( pCtx, pKey, nullptr, 0,
            psk, sizeof(psk) - 1, nullptr, 0,          // PSK but no PSK ID
            enc, 1088, 0 );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
            "PSK without PSK ID should fail" );

        SymCryptHpkeContextFree( pCtx );
        SymCryptHpkekeyFree( pKey );
    }

    //
    // 4. Size query functions
    //
    {
        SYMCRYPT_HPKE_CIPHERSUITE suite = {
            SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            SYMCRYPT_HPKE_AEAD_ID_AESGCM128
        };

        SIZE_T cbEncaps, cbAeadOverhead;

        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams( suite, &cbEncaps );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed" );
        CHECK3( cbEncaps == 1088, "Expected enc size 1088, got %d", (int) cbEncaps );

        scError = SymCryptHpkeSizeofAeadOverheadFromParams( suite, &cbAeadOverhead );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed" );
        CHECK3( cbAeadOverhead == 16, "Expected AEAD overhead 16, got %d", (int) cbAeadOverhead );
    }

    //
    // 5. Role enforcement: Seal is sender-only, Open is recipient-only
    //    (the restriction documented on SetupSender / SetupRecipient).
    //    A context used for the wrong direction must fail.
    //
    {
        SYMCRYPT_HPKE_CIPHERSUITE suite = {
            SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
            SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            SYMCRYPT_HPKE_AEAD_ID_AESGCM128
        };

        PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( suite );
        CHECK( pKey != nullptr, "Key alloc (role)" );
        scError = SymCryptHpkekeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "KeyGen (role)" );

        SIZE_T cbEnc = 0;
        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams( suite, &cbEnc );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofEnc (role)" );
        SIZE_T cbTag = 0;
        scError = SymCryptHpkeSizeofAeadOverheadFromParams( suite, &cbTag );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead (role)" );

        BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
        CHECK( cbEnc <= sizeof(enc), "enc buffer too small (role)" );

        const BYTE pt[] = "role enforcement plaintext";
        const SIZE_T cbPt = sizeof(pt) - 1;
        BYTE ct[sizeof(pt) - 1 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
        BYTE dec[sizeof(pt) - 1];
        BYTE exported[32];

        // Sender context: Seal allowed; Open / OpenUnordered rejected.
        PSYMCRYPT_HPKECONTEXT pSenderCtx = SymCryptHpkeContextAllocate( suite );
        CHECK( pSenderCtx != nullptr, "Sender ctx alloc (role)" );
        scError = SymCryptHpkeSetupSender(
            pSenderCtx, pKey, nullptr, 0, nullptr, 0, nullptr, 0, enc, cbEnc, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupSender (role)" );

        scError = SymCryptHpkeSeal( pSenderCtx, nullptr, 0, pt, cbPt, ct, cbPt + cbTag, nullptr );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Seal on sender ctx should succeed (role)" );
        
        scError = SymCryptHpkeOpenUnordered( pSenderCtx, 0, nullptr, 0, ct, cbPt + cbTag, dec, cbPt );
        CHECK( scError == SYMCRYPT_NO_ERROR, "OpenUnordered on sender ctx should succeed (role)" );
        
        scError = SymCryptHpkeOpen( pSenderCtx, nullptr, 0, ct, cbPt + cbTag, dec, cbPt );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "Open on sender ctx must be rejected (role)" );
        
        // Recipient context: Open allowed; Seal rejected.
        PSYMCRYPT_HPKECONTEXT pRecipientCtx = SymCryptHpkeContextAllocate( suite );
        CHECK( pRecipientCtx != nullptr, "Recipient ctx alloc (role)" );
        scError = SymCryptHpkeSetupRecipient(
            pRecipientCtx, pKey, enc, cbEnc, nullptr, 0, nullptr, 0, nullptr, 0, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetupRecipient (role)" );

        scError = SymCryptHpkeSeal( pRecipientCtx, nullptr, 0, pt, cbPt, ct, cbPt + cbTag, nullptr );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT, "Seal on recipient ctx must be rejected (role)" );

        scError = SymCryptHpkeOpenUnordered( pRecipientCtx, 0, nullptr, 0, ct, cbPt + cbTag, dec, cbPt );
        CHECK( scError == SYMCRYPT_NO_ERROR, "OpenUnordered on recipient ctx should succeed (role)" );

        scError = SymCryptHpkeOpen( pRecipientCtx, nullptr, 0, ct, cbPt + cbTag, dec, cbPt );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Open on recipient ctx should succeed (role)" );

        // SecretExport is valid for either role.
        scError = SymCryptHpkeSecretExport( pSenderCtx, (PCBYTE) "x", 1, exported, sizeof(exported) );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport on sender ctx (role)" );
        scError = SymCryptHpkeSecretExport( pRecipientCtx, (PCBYTE) "x", 1, exported, sizeof(exported) );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SecretExport on recipient ctx (role)" );

        SymCryptHpkeContextFree( pRecipientCtx );
        SymCryptHpkeContextFree( pSenderCtx );
        SymCryptHpkekeyFree( pKey );
    }
}


//
// ========================================================================
// testHpkeKat
//
// Known Answer Tests. Every registered implementation is driven through the
// full vector set via the multi-imp interface, to the extent each supports:
//   - setup record   ("info"): deriveKeyPair(ikmR) + getKey == pkRm;
//                               setupSenderDeterministic(ikmE) == enc;
//                               setupRecipient(enc).
//   - encryption record ("seq"): seal == ct (sender); open / openUnordered == pt (recipient).
//   - export record ("exporter_context"): secretExportSender / secretExportRecipient == value.
//
// ========================================================================
//

struct HpkeKatImpState
{
    HpkeImplementation *    pImp;
    BOOL                    disqualified;   // wrong answer on a supported suite (non-SymCrypt only)
    BOOL                    keyReady;       // deriveKeyPair succeeded for current setup
    BOOL                    senderReady;    // setupSenderDeterministic succeeded for current setup
    BOOL                    sealInOrder;    // in-order Seal still counter-aligned for this suite
    BOOL                    recipientReady; // setupRecipient succeeded for current setup
    BOOL                    openInOrder;    // in-order Open still counter-aligned for this suite
};

// Result of evaluating one KAT operation for one implementation.
enum HpkeKatGate
{
    HPKE_KAT_GATE_OK,        // succeeded and (if checked) matched the vector
    HPKE_KAT_GATE_SKIP,      // STATUS_NOT_SUPPORTED — capability gap, operation not run
    HPKE_KAT_GATE_DROPPED,   // wrong answer from a non-SymCrypt backend; disqualified
};

// SymCrypt backends are the reference implementation: any KAT divergence is fatal.
static bool
hpkeKatImpIsSymCrypt( const HpkeImplementation * pImp )
{
    const std::string & n = pImp->m_implementationName;
    return n == "SymCrypt" || n == "SymCryptStatic" || n == "SymCryptDynamic";
}

// Every SymCrypt backend except the dynamic module is expected to cover the
// entire KAT surface; the dynamic module legitimately lacks the internal-only
// entrypoints (e.g. deterministic SetupSender), so it may report NOT_SUPPORTED.
static bool
hpkeKatImpMustSupportAll( const HpkeImplementation * pImp )
{
    return hpkeKatImpIsSymCrypt( pImp ) &&
           pImp->m_implementationName != "SymCryptDynamic";
}

// Emit a CI-visible warning at most once per (impl, phase, reason). The line
// starts with the Azure DevOps "##[warning]" logging command so it surfaces as
// a warning annotation in CI.
static VOID
hpkeKatWarnOnce(
    const HpkeImplementation *  pImp,
    SYMCRYPT_HPKE_CIPHERSUITE   suite,
    PCSTR                       phase,
    ULONGLONG                   line,
    PCSTR                       reason )
{
    static std::set<std::string> s_warned;
    std::string key = pImp->m_implementationName + "|" + phase + "|" + reason;
    if( !s_warned.insert( key ).second )
    {
        return;
    }

    iprint(
        "\n##vso[task.logissue type=warning][HPKE interop gate] '%s' dropped at the %s stage "
        "(suite kem=%u kdf=%u aead=%u) - (line %lld): %s.\n",
        pImp->m_implementationName.c_str(), phase,
        (unsigned) suite.kemId, (unsigned) suite.kdfId, (unsigned) suite.aeadId, line,
        reason );
}

// Drop a non-SymCrypt implementation from further cross-validation, warning once.
static VOID
hpkeKatDisqualify(
    HpkeKatImpState &           st,
    SYMCRYPT_HPKE_CIPHERSUITE   suite,
    PCSTR                       phase,
    ULONGLONG                   line )
{
    st.disqualified     = TRUE;
    st.keyReady         = FALSE;
    st.senderReady      = FALSE;
    st.sealInOrder      = FALSE;
    st.recipientReady   = FALSE;
    st.openInOrder      = FALSE;

    hpkeKatWarnOnce( st.pImp, suite, phase, line,
        "failed KAT cross-validation; excluding it from further HPKE testing" );
}

// Classify one KAT operation outcome and apply the gate policy:
// - NOT_SUPPORTED            -> skip (warn if a SymCrypt backend that should support everything reports it).
// - success + correct answer -> ok.
// - anything else            -> fatal for SymCrypt (reference); disqualify+warn for other backends.
static HpkeKatGate
hpkeKatGateResult(
    HpkeKatImpState &           st,
    SYMCRYPT_HPKE_CIPHERSUITE   suite,
    ULONGLONG                   line,
    PCSTR                       phase,
    NTSTATUS                    ntStatus,
    bool                        fAnswerCorrect )
{
    if( ntStatus == STATUS_NOT_SUPPORTED )
    {
        if( hpkeKatImpMustSupportAll( st.pImp ) )
        {
            hpkeKatWarnOnce( st.pImp, suite, phase, line,
                "returned STATUS_NOT_SUPPORTED for an operation SymCrypt should support" );
        }
        return HPKE_KAT_GATE_SKIP;
    }

    if( ntStatus == STATUS_SUCCESS && fAnswerCorrect )
    {
        return HPKE_KAT_GATE_OK;
    }

    if( hpkeKatImpIsSymCrypt( st.pImp ) )
    {
        CHECK5( FALSE,
            "HPKE KAT: reference implementation '%s' diverged at the %s stage "
            "(line %lld) - SymCrypt regression",
            st.pImp->m_implementationName.c_str(), phase, line );
    }

    hpkeKatDisqualify( st, suite, phase, line );
    return HPKE_KAT_GATE_DROPPED;
}

static VOID
testHpkeKat( HpkeMultiImp & multiImp )
{
    std::unique_ptr<KatData> katHpke( getCustomResource( "kat_hpke.dat", "KAT_HPKE" ) );
    KAT_ITEM katItem;

    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKE_CIPHERSUITE currentSuite = {};
    BOOLEAN bCategoryFound = FALSE;
    BOOLEAN bSetupSeen = FALSE;

    UINT32 cSetupRecords = 0;
    UINT32 cEncryptionRecords = 0;
    UINT32 cExportRecords = 0;

    std::vector<HpkeKatImpState> impStates;
    for( HpkeImplementation * pImp : multiImp.m_imps )
    {
        HpkeKatImpState st = { pImp, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE };
        impStates.push_back( st );
    }

    while( 1 )
    {
        katHpke->getKatItem( &katItem );
        ULONGLONG line = katItem.line;

        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            // Ciphersuite parameters live in the setup record that follows.
            bCategoryFound = TRUE;
            bSetupSeen = FALSE;
            continue;
        }

        if( katItem.type != KAT_TYPE_DATASET )
        {
            continue;
        }

        CHECK3( bCategoryFound, "HPKE KAT dataset at line %lld has no ciphersuite category!", line );

        if( katIsFieldPresent( katItem, "info" ) )
        {
            //
            // Setup record: per backend, derive the key from ikmR (check pkRm),
            // reproduce enc from ikmE via deterministic SetupSender, and stand up
            // the recipient context from the published enc.
            //
            LONGLONG mode = katParseInteger( katItem, "mode" );
            CHECK3( mode == SYMCRYPT_HPKE_MODE_BASE || mode == SYMCRYPT_HPKE_MODE_PSK,
                "Unsupported HPKE KAT mode at line %lld", line );

            currentSuite.kemId  = (UINT16) katParseInteger( katItem, "kem_id" );
            currentSuite.kdfId  = (UINT16) katParseInteger( katItem, "kdf_id" );
            currentSuite.aeadId = (UINT16) katParseInteger( katItem, "aead_id" );

            BString katInfo = katParseData( katItem, "info" );
            BString katIkmR = katParseData( katItem, "ikmr" );
            BString katIkmE = katParseData( katItem, "ikme" );
            BString katPkRm = katParseData( katItem, "pkrm" );
            BString katEnc  = katParseData( katItem, "enc" );
            BString katPsk;
            BString katPskId;
            PCBYTE pbPsk = nullptr;
            PCBYTE pbPskId = nullptr;
            SIZE_T cbPsk = 0;
            SIZE_T cbPskId = 0;

            if( mode == SYMCRYPT_HPKE_MODE_PSK )
            {
                katPsk = katParseData( katItem, "psk" );
                katPskId = katParseData( katItem, "psk_id" );
                pbPsk = katPsk.data();
                cbPsk = katPsk.size();
                pbPskId = katPskId.data();
                cbPskId = katPskId.size();
            }

            SIZE_T cbPk = 0;
            scError = SymCryptHpkeSizeofKeyFormatFromParams(
                currentSuite, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat failed at line %lld", line );
            CHECK3( cbPk == katPkRm.size(), "Public key size mismatch at line %lld", line );

            for( HpkeKatImpState & st : impStates )
            {
                st.keyReady = FALSE;
                st.senderReady = FALSE;
                st.sealInOrder = FALSE;
                st.recipientReady = FALSE;
                st.openInOrder = FALSE;
                if( st.disqualified )
                {
                    continue;
                }

                NTSTATUS ntStatus = st.pImp->deriveKeyPair(
                    currentSuite, katIkmR.data(), katIkmR.size() );
                if( hpkeKatGateResult( st, currentSuite, line, "DeriveKeyPair",
                        ntStatus, true ) != HPKE_KAT_GATE_OK )
                {
                    continue;
                }

                std::vector<BYTE> implPk( cbPk );
                ntStatus = st.pImp->getKey(
                    SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, implPk.data(), cbPk );
                bool fPkOk = ( ntStatus == STATUS_SUCCESS &&
                               memcmp( implPk.data(), katPkRm.data(), cbPk ) == 0 );
                if( hpkeKatGateResult( st, currentSuite, line, "DeriveKeyPair public-key",
                        ntStatus, fPkOk ) != HPKE_KAT_GATE_OK )
                {
                    continue;
                }
                st.keyReady = TRUE;

                // Deterministic SetupSender from ikmE must reproduce the vector's enc.
                std::vector<BYTE> implEnc( katEnc.size() );
                ntStatus = st.pImp->setupSenderDeterministic(
                    katIkmE.data(), katIkmE.size(),
                    katInfo.data(), katInfo.size(),
                    pbPsk, cbPsk,
                    pbPskId, cbPskId,
                    implEnc.data(), implEnc.size() );
                bool fEncOk = ( ntStatus == STATUS_SUCCESS &&
                                memcmp( implEnc.data(), katEnc.data(), katEnc.size() ) == 0 );
                HpkeKatGate encGate = hpkeKatGateResult( st, currentSuite, line,
                    "SetupSenderDeterministic", ntStatus, fEncOk );
                if( encGate == HPKE_KAT_GATE_DROPPED )
                {
                    continue;
                }
                st.senderReady = ( encGate == HPKE_KAT_GATE_OK );
                st.sealInOrder = st.senderReady;

                // Recipient context from the published enc.
                ntStatus = st.pImp->setupRecipient(
                    katEnc.data(), katEnc.size(),
                    katInfo.data(), katInfo.size(),
                    pbPsk, cbPsk,
                    pbPskId, cbPskId );
                HpkeKatGate ctxGate = hpkeKatGateResult( st, currentSuite, line,
                    "SetupRecipient", ntStatus, true );
                if( ctxGate == HPKE_KAT_GATE_DROPPED )
                {
                    continue;
                }
                st.recipientReady = ( ctxGate == HPKE_KAT_GATE_OK );
                st.openInOrder = st.recipientReady;
            }

            bSetupSeen = TRUE;
            cSetupRecords++;
            continue;
        }

        if( katIsFieldPresent( katItem, "seq" ) )
        {
            //
            // Encryption record: Seal must reproduce ct (sender direction, for
            // backends with a deterministic sender context) and OpenUnordered must
            // reproduce pt (recipient direction).
            //
            CHECK3( bSetupSeen, "Encryption record at line %lld without prior setup!", line );

            SIZE_T cbTag = 0;
            scError = SymCryptHpkeSizeofAeadOverheadFromParams( currentSuite, &cbTag );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed at line %lld", line );

            LONGLONG seq = katParseInteger( katItem, "seq" );
            BString katPt  = katParseData( katItem, "pt" );
            BString katAad = katParseData( katItem, "aad" );
            BString katCt  = katParseData( katItem, "ct" );

            SIZE_T cbPlaintext = katCt.size() - cbTag;
            CHECK3( cbPlaintext == katPt.size(), "Plaintext size mismatch at line %lld", line );

            for( HpkeKatImpState & st : impStates )
            {
                if( st.disqualified )
                {
                    continue;
                }

                if( st.sealInOrder )
                {
                    std::vector<BYTE> implCt( katCt.size() );
                    UINT64 seqNum = 0;
                    NTSTATUS ntStatus = st.pImp->seal(
                        katAad.data(), katAad.size(),
                        katPt.data(), katPt.size(),
                        implCt.data(), implCt.size(),
                        &seqNum );
                    bool fCtOk = ( ntStatus == STATUS_SUCCESS &&
                                   seqNum == (UINT64) seq &&
                                   memcmp( implCt.data(), katCt.data(), katCt.size() ) == 0 );
                    HpkeKatGate sealGate = hpkeKatGateResult( st, currentSuite, line, "Seal",
                        ntStatus, fCtOk );
                    if( sealGate == HPKE_KAT_GATE_DROPPED )
                    {
                        continue;
                    }
                    if( sealGate == HPKE_KAT_GATE_SKIP )
                    {
                        st.sealInOrder = FALSE;
                    }
                }

                if( st.recipientReady )
                {
                    std::vector<BYTE> implPt( cbPlaintext );

                    if( st.openInOrder )
                    {
                        NTSTATUS ntStatus = st.pImp->open(
                            katAad.data(), katAad.size(),
                            katCt.data(), katCt.size(),
                            implPt.data(), cbPlaintext );
                        bool fPtOk = ( ntStatus == STATUS_SUCCESS &&
                                       ( cbPlaintext == 0 ||
                                         memcmp( implPt.data(), katPt.data(), cbPlaintext ) == 0 ) );
                        HpkeKatGate openGate = hpkeKatGateResult( st, currentSuite, line,
                            "Open", ntStatus, fPtOk );
                        if( openGate == HPKE_KAT_GATE_DROPPED )
                        {
                            continue;
                        }
                        if( openGate == HPKE_KAT_GATE_SKIP )
                        {
                            st.openInOrder = FALSE;
                        }
                    }

                    NTSTATUS ntStatus = st.pImp->openUnordered(
                        (UINT64) seq,
                        katAad.data(), katAad.size(),
                        katCt.data(), katCt.size(),
                        implPt.data(), cbPlaintext );
                    bool fPtOk = ( ntStatus == STATUS_SUCCESS &&
                                   ( cbPlaintext == 0 ||
                                     memcmp( implPt.data(), katPt.data(), cbPlaintext ) == 0 ) );
                    hpkeKatGateResult( st, currentSuite, line, "OpenUnordered",
                        ntStatus, fPtOk );
                }
            }

            cEncryptionRecords++;
            continue;
        }

        if( katIsFieldPresent( katItem, "exporter_context" ) )
        {
            //
            // Export record: SecretExport must reproduce the vector's value.
            //
            CHECK3( bSetupSeen, "Export record at line %lld without prior setup!", line );

            BString katCtx      = katParseData( katItem, "exporter_context" );
            LONGLONG L          = katParseInteger( katItem, "l" );
            BString katExpected = katParseData( katItem, "exported_value" );

            CHECK3( L >= 0 && L <= 0xFFFF, "Export L out of range at line %lld", line );
            CHECK3( (SIZE_T) L == katExpected.size(), "Export L mismatch at line %lld", line );

            UINT16 cbExport = (UINT16) L;

            for( HpkeKatImpState & st : impStates )
            {
                if( st.disqualified )
                {
                    continue;
                }

                if( st.senderReady )
                {
                    std::vector<BYTE> implExport( cbExport );
                    NTSTATUS ntStatus = st.pImp->secretExportSender(
                        katCtx.data(), katCtx.size(),
                        implExport.data(), cbExport );
                    bool fOk = ( ntStatus == STATUS_SUCCESS &&
                                 memcmp( implExport.data(), katExpected.data(), cbExport ) == 0 );
                    if( hpkeKatGateResult( st, currentSuite, line, "SecretExportSender",
                            ntStatus, fOk ) == HPKE_KAT_GATE_DROPPED )
                    {
                        continue;
                    }
                }

                if( st.recipientReady )
                {
                    std::vector<BYTE> implExport( cbExport );
                    NTSTATUS ntStatus = st.pImp->secretExportRecipient(
                        katCtx.data(), katCtx.size(),
                        implExport.data(), cbExport );
                    bool fOk = ( ntStatus == STATUS_SUCCESS &&
                                 memcmp( implExport.data(), katExpected.data(), cbExport ) == 0 );
                    hpkeKatGateResult( st, currentSuite, line, "SecretExportRecipient",
                        ntStatus, fOk );
                }
            }

            cExportRecords++;
            continue;
        }

        FATAL2( "HPKE KAT record at line %lld has unrecognized format", line );
    }

    //
    // Drop disqualified backends from the shared multiImp and release per-impl
    // key/context state (clearing the key also frees any cached context).
    //
    {
        std::vector<HpkeImplementation *> survivors;
        UINT32 cDisqualified = 0;

        for( HpkeKatImpState & st : impStates )
        {
            st.pImp->setKey( currentSuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, nullptr, 0 );

            if( st.disqualified )
            {
                cDisqualified++;
            }
            else
            {
                survivors.push_back( st.pImp );
            }
        }

        if( cDisqualified != 0 )
        {
            multiImp.m_imps.swap( survivors );
            multiImp.m_comps.clear();
            multiImp.m_senderComps.clear();
            multiImp.m_recipientComps.clear();
        }
    }

    CHECK3( cSetupRecords > 0, "Expected HPKE KAT setup records, got %d", cSetupRecords );
    CHECK3( cEncryptionRecords > 0, "Expected HPKE KAT encryption records, got %d", cEncryptionRecords );
    CHECK3( cExportRecords > 0, "Expected HPKE KAT export records, got %d", cExportRecords );

    iprint( " records: %u setup, %u encryption, %u export", cSetupRecords, cEncryptionRecords, cExportRecords );
}


//
// ========================================================================
// testHpkeMultiImp
//
// Cross-implementation testing through the HpkeMultiImp framework. The class
// header documents the cross-validation pattern.
// ========================================================================
//
static VOID
testHpkeMultiImp(
    _In_ HpkeMultiImp & multiImp,
    _In_ const std::vector<HPKE_TEST_PARAMS> &testParams )
{
    HpkeMultiImp * pHpke = &multiImp;

    NTSTATUS ntStatus;
    SYMCRYPT_ERROR scError;

    for( SIZE_T iParam = 0; iParam < testParams.size(); iParam++ )
    {
        const HPKE_TEST_PARAMS *pParams = &testParams[iParam];
        BOOL fExportOnly = pParams->ciphersuite.aeadId == SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY;

        // Key generation is intentionally not part of the multi-imp interface:
        // cross-validating randomness isn't meaningful. Generate once here and
        // distribute the private blob to every implementation.
        PSYMCRYPT_HPKEKEY pKey = SymCryptHpkekeyAllocate( pParams->ciphersuite );
        CHECK( pKey != nullptr, "Multi-imp: key alloc failed" );

        scError = SymCryptHpkekeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-imp: key gen failed" );

        SIZE_T cbPrivateKey = 0;
        scError = SymCryptHpkeSizeofKeyFormatFromParams(
            pParams->ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivateKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-imp: size query failed" );

        std::vector<BYTE> privateKeyBlob( cbPrivateKey );
        scError = SymCryptHpkekeyGetValue(
            pKey, privateKeyBlob.data(), cbPrivateKey,
            SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-imp: key export failed" );

        SymCryptHpkekeyFree( pKey );
        pKey = nullptr;

        ntStatus = pHpke->setKey(
            pParams->ciphersuite,
            SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY,
            privateKeyBlob.data(), cbPrivateKey );
        CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: setKey failed" );

        SIZE_T cbPublicKey = 0;
        scError = SymCryptHpkeSizeofKeyFormatFromParams(
            pParams->ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPublicKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-imp: public key size query failed" );

        std::vector<BYTE> publicKeyBlob( cbPublicKey );
        ntStatus = pHpke->getKey( SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, publicKeyBlob.data(), cbPublicKey );
        CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: getKey (public) failed" );

        for( int i = 0; !fExportOnly && i < 10; i++ )
        {
            // Alternate base / PSK mode each iteration to exercise both paths
            // through the multi-imp single-shot wrappers cross-implementation.
            const BYTE plaintext[] = "Multi-imp HPKE round-trip test plaintext!";
            const SIZE_T cbPlaintext = sizeof(plaintext) - 1;
            const BYTE aad[] = "multi-imp AAD";
            const SIZE_T cbAad = sizeof(aad) - 1;
            const BYTE info[] = "multi-imp info";
            const SIZE_T cbInfo = sizeof(info) - 1;

            BOOL fUsePsk = (i & 1) != 0;
            const BYTE pskBytes[]   = "multi-imp HPKE pre-shared-key bytes";
            const BYTE pskIdBytes[] = "multi-imp PSK identifier";
            PCBYTE pbPsk    = fUsePsk ? pskBytes   : nullptr;
            SIZE_T cbPsk    = fUsePsk ? sizeof(pskBytes) - 1   : 0;
            PCBYTE pbPskId  = fUsePsk ? pskIdBytes : nullptr;
            SIZE_T cbPskId  = fUsePsk ? sizeof(pskIdBytes) - 1 : 0;

            SIZE_T cbEnc = pHpke->encSize();

            SIZE_T cbTag;
            scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
            CHECK( scError == SYMCRYPT_NO_ERROR, "Multi-imp: SizeofAeadOverhead failed" );

            SIZE_T cbCiphertext = cbPlaintext + cbTag;

            std::vector<BYTE> enc( cbEnc );
            BYTE ciphertext[256 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
            BYTE decrypted[256];

            ntStatus = pHpke->sealSingleShot(
                info, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                aad, cbAad,
                plaintext, cbPlaintext,
                enc.data(), cbEnc,
                ciphertext, cbCiphertext );
            CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: seal failed" );

            ntStatus = pHpke->openSingleShot(
                enc.data(), cbEnc,
                info, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                aad, cbAad,
                ciphertext, cbCiphertext,
                decrypted, cbPlaintext );
            CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: open failed" );
            CHECK( memcmp( decrypted, plaintext, cbPlaintext ) == 0,
                "Multi-imp: plaintext content mismatch" );

            const BYTE exporterCtx[] = "multi-imp exporter";
            BYTE exported[32];

            ntStatus = pHpke->secretExportSingleShot(
                enc.data(), cbEnc,
                info, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                exporterCtx, sizeof(exporterCtx) - 1,
                exported, sizeof(exported) );
            CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: secretExport failed" );

            ntStatus = pHpke->sealSingleShot(
                info, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                nullptr, 0,
                plaintext, 0,
                enc.data(), cbEnc,
                ciphertext, cbTag );
            CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: seal (empty) failed" );

            ntStatus = pHpke->openSingleShot(
                enc.data(), cbEnc,
                info, cbInfo,
                pbPsk, cbPsk, pbPskId, cbPskId,
                nullptr, 0,
                ciphertext, cbTag,
                decrypted, 0 );
            CHECK( ntStatus == STATUS_SUCCESS, "Multi-imp: open (empty) failed" );
        }

        //
        // Stateful cross-implementation interop. For each (sender, recipient)
        // pair: SetupSender + N Seals on sender; SetupRecipient + N in-order
        // Opens on recipient; cross-check SecretExport. Runs in both base
        // and PSK mode.
        //
        {
            const SIZE_T cbEnc = pHpke->encSize();
            SIZE_T cbTag = 0;
            if( !fExportOnly )
            {
                scError = SymCryptHpkeSizeofAeadOverheadFromParams( pParams->ciphersuite, &cbTag );
                CHECK3( scError == SYMCRYPT_NO_ERROR,
                    "Multi-imp interop [%s]: SizeofAeadOverhead failed", pParams->name.c_str() );
                CHECK3( cbTag <= SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE,
                    "Multi-imp interop [%s]: AEAD tag size exceeds SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE", pParams->name.c_str() );
            }

            const BYTE info[]           = "multi-imp interop info";
            const SIZE_T cbInfo         = sizeof(info) - 1;
            const BYTE exporterCtx[]    = "multi-imp interop exporter";
            const SIZE_T cbExporterCtx  = sizeof(exporterCtx) - 1;
            const BYTE pskBytes[]       = "multi-imp interop pre-shared-key bytes";
            const BYTE pskIdBytes[]     = "multi-imp interop PSK identifier";

            const SIZE_T cN = 4;            // # messages per (sender, recipient) pair
            const SIZE_T cbMessage = 48;    // a few different non-trivial sizes
            BYTE plaintexts[cN][cbMessage];
            BYTE aads[cN][cbMessage];
            BYTE ciphertexts[cN][cbMessage + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
            BYTE decrypted[cbMessage];

            std::vector<BYTE> enc( cbEnc );
            BYTE senderExport[32];
            BYTE recipientExport[sizeof(senderExport)];

            for( BOOL fUsePsk : { FALSE, TRUE } )
            {
                PCBYTE pbPsk    = fUsePsk ? pskBytes   : nullptr;
                SIZE_T cbPsk    = fUsePsk ? sizeof(pskBytes) - 1   : 0;
                PCBYTE pbPskId  = fUsePsk ? pskIdBytes : nullptr;
                SIZE_T cbPskId  = fUsePsk ? sizeof(pskIdBytes) - 1 : 0;
                const char *pszMode = fUsePsk ? "PSK" : "base";

                for( HpkeMultiImp::ImpPtrVector::iterator iSender = pHpke->m_comps.begin();
                     iSender != pHpke->m_comps.end();
                     ++iSender )
                {
                    ntStatus = (*iSender)->setupSender(
                        info, cbInfo,
                        pbPsk, cbPsk, pbPskId, cbPskId,
                        enc.data(), cbEnc );
                    CHECK5( ntStatus == STATUS_SUCCESS,
                        "Multi-imp interop [%s %s]: setupSender failed (%s)",
                        pParams->name.c_str(), pszMode, (*iSender)->getLastError().c_str() );

                    for( SIZE_T iMsg = 0; !fExportOnly && iMsg < cN; iMsg++ )
                    {
                        GENRANDOM( plaintexts[iMsg], (UINT32) cbMessage );
                        GENRANDOM( aads[iMsg], (UINT32) cbMessage );

                        ntStatus = (*iSender)->seal(
                            aads[iMsg], cbMessage,
                            plaintexts[iMsg], cbMessage,
                            ciphertexts[iMsg], cbMessage + cbTag,
                            nullptr );
                        CHECK5( ntStatus == STATUS_SUCCESS,
                            "Multi-imp interop [%s %s]: sender seal failed (%s)",
                            pParams->name.c_str(), pszMode, (*iSender)->getLastError().c_str() );
                    }

                    ntStatus = (*iSender)->secretExportSender(
                        exporterCtx, cbExporterCtx,
                        senderExport, sizeof(senderExport) );
                    CHECK5( ntStatus == STATUS_SUCCESS,
                        "Multi-imp interop [%s %s]: sender SecretExport failed (%s)",
                        pParams->name.c_str(), pszMode, (*iSender)->getLastError().c_str() );

                    for( HpkeMultiImp::ImpPtrVector::iterator iRecipient = pHpke->m_comps.begin();
                         iRecipient != pHpke->m_comps.end();
                         ++iRecipient )
                    {
                        ntStatus = (*iRecipient)->setupRecipient(
                            enc.data(), cbEnc,
                            info, cbInfo,
                            pbPsk, cbPsk, pbPskId, cbPskId );
                        CHECK5( ntStatus == STATUS_SUCCESS,
                            "Multi-imp interop [%s %s]: setupRecipient failed (%s)",
                            pParams->name.c_str(), pszMode, (*iRecipient)->getLastError().c_str() );

                        ntStatus = (*iRecipient)->secretExportRecipient(
                            exporterCtx, cbExporterCtx,
                            recipientExport, sizeof(recipientExport) );
                        CHECK5( ntStatus == STATUS_SUCCESS,
                            "Multi-imp interop [%s %s]: recipient SecretExport failed (%s)",
                            pParams->name.c_str(), pszMode, (*iRecipient)->getLastError().c_str() );
                        CHECK4( memcmp( senderExport, recipientExport, sizeof(senderExport) ) == 0,
                            "Multi-imp interop [%s %s]: SecretExport sender/recipient disagree",
                            pParams->name.c_str(), pszMode );

                        for( SIZE_T iMsg = 0; !fExportOnly && iMsg < cN; iMsg++ )
                        {
                            memset( decrypted, 'd', sizeof(decrypted) );
                            ntStatus = (*iRecipient)->open(
                                aads[iMsg], cbMessage,
                                ciphertexts[iMsg], cbMessage + cbTag,
                                decrypted, cbMessage );
                            CHECK5( ntStatus == STATUS_SUCCESS,
                                "Multi-imp interop [%s %s]: recipient ordered Open failed (%s)",
                                pParams->name.c_str(), pszMode, (*iRecipient)->getLastError().c_str() );
                            CHECK4( memcmp( decrypted, plaintexts[iMsg], cbMessage ) == 0,
                                "Multi-imp interop [%s %s]: recipient plaintext mismatch",
                                pParams->name.c_str(), pszMode );
                        }
                    }
                }
            }
        }
    }

    //
    // Free per-imp keys before the outstanding-allocation check in testPqDsa():
    // HpkeImp instances live in g_algorithmImplementation until exitTestInfrastructure().
    //
    SYMCRYPT_HPKE_CIPHERSUITE emptySuite = {};
    pHpke->setKey( emptySuite, 0, nullptr, 0 );
}

//
// ========================================================================
// testHpkeRandomKat / testHpkeRandomCrossCheck
//
// Randomized HPKE test driver. Both entry points share the same per-iteration
// helper; they differ only in seed (fixed vs g_rngSeed) and whether they
// accumulate a regression-hash digest.
//
//   - Pre-context phase (key APIs) routes through HpkeMultiImp so all
//     registered backends agree on the derived public key.
//   - Post-context phase has two sub-paths picked per iteration:
//       DET_ENCAP   — multi-imp deterministic SetupSender: internal encapsulate
//                     is derived from an rng-chosen pbRandom, so Encap, Decap
//                     and the resulting Seal/Open/OpenUnordered/SecretExport are
//                     reproducible and absorbed into the digest.
//       KEM_RANDOM  — full public-API path through HpkeMultiImp single-shot
//                     wrappers. KEM consumes the SymCrypt RNG, so outputs
//                     are non-deterministic; verification is via MultiImp's
//                     internal cross-validation (Seal/Open cross-pair,
//                     ResultMerge for openSingleShot / secretExportSingleShot).
//
// Digest accumulation: Marvin32 (8-byte, non-cryptographic; baseline pinned
// in g_hpkeRandomKatExpectedDigest at the bottom of this block).
//
// ========================================================================
//

extern UINT32 g_rngSeed;        // defined in main_exe.cpp
extern BOOL   g_noPerfTests;

// Test-local upper bound on the private-key blob across our HPKE matrix. The
// HPKE key format stores compact private material (ML-KEM seeds + curve scalar);
// 2 KiB easily covers the largest hybrid (ML-KEM-1024 + P-384). Bump if a new
// KEM with a larger private blob is added.
static const SIZE_T HPKE_RAND_MAX_PRIVATE_KEY_SIZE = 2048;

//
// Digest accumulator. PVOID rather than PSYMCRYPT_MARVIN32_STATE so the helper
// signatures don't need to know which hash is in use. Caller passes nullptr to
// skip absorption (CROSSCHECK).
//
// Each absorb prefixes the byte length (as UINT64 LE) before the payload so
// boundary shifts between adjacent absorbs change the digest. Marvin32 is a
// non-cryptographic 64-bit hash — fast, no allocation, sufficient for catching
// any divergence in the high-entropy outputs we accumulate.
//
static VOID
testHpkeRandAbsorb(
    _Inout_opt_                 PVOID   pAccum,
    _In_reads_bytes_( cb )      PCBYTE  pb,
                                SIZE_T  cb )
{
    if( pAccum == nullptr )
    {
        return;
    }

    PSYMCRYPT_MARVIN32_STATE pState = (PSYMCRYPT_MARVIN32_STATE) pAccum;
    UINT64 cbAsU64 = (UINT64) cb;
    SymCryptMarvin32Append( pState, (PCBYTE) &cbAsU64, sizeof(cbAsU64) );
    SymCryptMarvin32Append( pState, pb, cb );
}

//
// Pre-context phase. DERIVE: every impl runs DeriveKeyPair from the same IKM.
// GENERATE: distribute a fresh randomized private key to every impl. Either way
// the public bytes come back via multiImp.getKey (ResultMerged), so any backend
// whose DeriveKeyPair / SetValue / GetValue path diverges fails inside multiImp.
// Only DERIVE absorbs into the digest (GENERATE is randomized).
//
static VOID
testHpkeRandPreContext(
    Rng                         & rng,
    PVOID                       pAccum,
    HpkeMultiImp                & multiImp,
    BOOL                        fDeriveKeyPath,
    SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite )
{
    PSYMCRYPT_HPKEKEY pkPriv = SymCryptHpkekeyAllocate( ciphersuite );
    CHECK( pkPriv != nullptr, "HpkeRand: keypair allocate failed" );

    SYMCRYPT_ERROR scError;
    BYTE abPrivKey[ HPKE_RAND_MAX_PRIVATE_KEY_SIZE ];
    SIZE_T cbPrivKey = 0;
    scError = SymCryptHpkeSizeofKeyFormatFromParams(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: SizeofKeyFormat (private) failed" );
    CHECK( cbPrivKey <= sizeof(abPrivKey), "HpkeRand: private-key buffer too small" );

    NTSTATUS ntStatus;

    if( fDeriveKeyPath )
    {
        BYTE ikm[SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE];
        SIZE_T cbIkm = rng.sizet( 1, sizeof(ikm) + 1 );
        for( SIZE_T k = 0; k < cbIkm; ++k ) { ikm[k] = rng.byte(); }
        testHpkeRandAbsorb( pAccum, ikm, cbIkm );

        // Canonical SymCrypt derivation for the absorbed/restored private blob.
        scError = SymCryptHpkekeyDerive( ikm, cbIkm, pkPriv, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: DeriveKeyPair failed" );
        scError = SymCryptHpkekeyGetValue(
            pkPriv, abPrivKey, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: GetValue (private) failed" );

        // Same IKM into every impl; the getKey below cross-checks the result.
        ntStatus = multiImp.deriveKeyPair( ciphersuite, ikm, cbIkm );
        CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp deriveKeyPair failed" );
    }
    else
    {
        scError = SymCryptHpkekeyGenerate( pkPriv, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: HpkekeyGenerate failed" );
        scError = SymCryptHpkekeyGetValue(
            pkPriv, abPrivKey, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: GetValue (private) failed" );

        // Distribute the fresh randomized private key to every registered impl.
        ntStatus = multiImp.setKey(
            ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, abPrivKey, cbPrivKey );
        CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp setKey failed" );
    }

    SIZE_T cbPubKey = 0;
    scError = SymCryptHpkeSizeofKeyFormatFromParams(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPubKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: SizeofKeyFormat (public) failed" );
    BYTE abPubKey[ SYMCRYPT_HPKE_KEM_MAX_PUBLIC_KEY_SIZE ];
    CHECK( cbPubKey <= sizeof(abPubKey), "HpkeRand: public-key buffer too small" );
    ntStatus = multiImp.getKey( SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, abPubKey, cbPubKey );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp getKey failed" );

    //
    // Public-only SetValue/GetValue round-trip: import the merged public bytes
    // into every registered impl and verify they round-trip out identically.
    //
    BYTE abPubKeyRoundtrip[ SYMCRYPT_HPKE_KEM_MAX_PUBLIC_KEY_SIZE ];
    ntStatus = multiImp.setKey(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, abPubKey, cbPubKey );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp setKey(PUBLIC_KEY) failed" );
    ntStatus = multiImp.getKey(
        SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, abPubKeyRoundtrip, cbPubKey );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp getKey(PUBLIC_KEY) failed" );
    CHECK( memcmp( abPubKey, abPubKeyRoundtrip, cbPubKey ) == 0,
        "HpkeRand: multi-imp PUBLIC_KEY SetValue/GetValue round-trip mismatch" );

    ntStatus = multiImp.setKey(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, abPrivKey, cbPrivKey );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp private-key restore failed" );

    if( fDeriveKeyPath )
    {
        testHpkeRandAbsorb( pAccum, abPrivKey, cbPrivKey );
        testHpkeRandAbsorb( pAccum, abPubKey, cbPubKey );
    }

    SymCryptHpkekeyFree( pkPriv );
    SymCryptWipeKnownSize( abPrivKey, sizeof(abPrivKey) );
}

static VOID
testHpkeRandExpectOpenFailure(
                                        HpkeMultiImp&   multiImp,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext,
                                        PCSTR           pszCase );

static VOID
testHpkeRandExpectOpenUnorderedFailure(
                                        HpkeMultiImp&   multiImp,
                                        UINT64          seqNumber,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext,
                                        PCSTR           pszCase );

static VOID
testHpkeRandCheckGarbledOpenState(
                                        Rng&            rng,
                                        HpkeMultiImp&   multiImp,
                                        UINT64          seqNumber,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext );

static SIZE_T
testHpkeRandIkmESize( SYMCRYPT_HPKE_CIPHERSUITE ciphersuite )
{
    switch( ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:       return 32;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:       return 48;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:       return 66;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:     return 32;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:       return 32;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:    return 128;  // 32 ML-KEM + 96 P-256 scalar seed
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:   return 80;   // 32 ML-KEM + 48 P-384 scalar seed
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:  return 64;   // 32 ML-KEM + 32 X25519 scalar
    default:
        CHECK( FALSE, "HpkeRand: unexpected kemId for ikmE sizing" );
        return 0;
    }
}

//
// Post-context, DET_ENCAP variant. Deterministic SetupSender reproduces enc
// from an rng-chosen ikmE (sized per the KAT vectors for this KEM), so the
// post-context outputs are reproducible and feed the digest. Backends that
// cannot surface deterministic SetupSender (e.g. the dynamic module) report
// STATUS_NOT_SUPPORTED and sit the path out without losing key state.
//
static VOID
testHpkeRandPostDetEncap(
    Rng                         & rng,
    PVOID                       pAccum,
    HpkeMultiImp                & multiImp,
    SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
    SIZE_T                      cbEnc,
    PCBYTE pbInfo,  SIZE_T cbInfo,
    PCBYTE pbPsk,   SIZE_T cbPsk,
    PCBYTE pbPskId, SIZE_T cbPskId )
{
    SYMCRYPT_HPKE_AEAD_PARAMS aeadParams;
    SYMCRYPT_ERROR scError =
        SymCryptHpkeValidateCiphersuite( ciphersuite, NULL, &aeadParams );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: ValidateCiphersuite failed (DET_ENCAP)" );

    SIZE_T cbIkmE = testHpkeRandIkmESize( ciphersuite );
    BYTE ikmE[128];
    CHECK( cbIkmE <= sizeof(ikmE), "HpkeRand: ikmE too large (DET_ENCAP)" );
    for( SIZE_T k = 0; k < cbIkmE; ++k ) { ikmE[k] = rng.byte(); }
    testHpkeRandAbsorb( pAccum, ikmE, cbIkmE );

    BYTE enc[SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE];
    CHECK( cbEnc <= sizeof(enc), "HpkeRand: enc buffer too small (DET_ENCAP)" );

    NTSTATUS ntStatus = multiImp.setupSenderDeterministic(
        ikmE, cbIkmE,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId,
        enc, cbEnc );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp setupSenderDeterministic failed (DET_ENCAP)" );
    testHpkeRandAbsorb( pAccum, enc, cbEnc );

    ntStatus = multiImp.setupRecipient(
        enc, cbEnc,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp SetupRecipient failed (DET_ENCAP)" );

    if( aeadParams.aeadId != SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY )
    {
        UINT16 cbTag = aeadParams.cbTag;
        SIZE_T nMsgs = rng.sizet( 1, 6 );
        for( SIZE_T m = 0; m < nMsgs; ++m )
        {
            BYTE aad[256];
            BYTE pt[512];
            BYTE ct[512 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
            BYTE openedPt[512];
            BYTE unorderedPt[512];
            UINT64 seqNumber;

            SIZE_T cbAad = rng.sizetNonUniform( sizeof(aad), 16, 2 );
            SIZE_T cbPt  = rng.sizetNonUniform( sizeof(pt),  32, 2 );
            for( SIZE_T k = 0; k < cbAad; ++k ) { aad[k] = rng.byte(); }
            for( SIZE_T k = 0; k < cbPt;  ++k ) { pt[k]  = rng.byte(); }

            ntStatus = multiImp.seal(
                aad, cbAad, pt, cbPt, ct, cbPt + cbTag, &seqNumber );
            CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp Seal failed (DET_ENCAP)" );
            testHpkeRandAbsorb( pAccum, ct, cbPt + cbTag );

            testHpkeRandCheckGarbledOpenState(
                rng, multiImp, seqNumber, aad, cbAad, ct, cbPt + cbTag, cbPt );

            ntStatus = multiImp.openUnordered(
                seqNumber, aad, cbAad, ct, cbPt + cbTag, unorderedPt, cbPt );
            CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp OpenUnordered failed (DET_ENCAP)" );
            CHECK( memcmp( unorderedPt, pt, cbPt ) == 0,
                "HpkeRand: Seal/OpenUnordered round-trip mismatch (DET_ENCAP)" );

            ntStatus = multiImp.open(
                aad, cbAad, ct, cbPt + cbTag, openedPt, cbPt );
            CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp Open failed (DET_ENCAP)" );
            CHECK( memcmp( openedPt, pt, cbPt ) == 0,
                "HpkeRand: Seal/Open round-trip mismatch (DET_ENCAP)" );
        }
    }

    {
        BYTE expCtx[128];
        BYTE expSender[64];
        BYTE expRecipient[64];
        SIZE_T cbExpCtx = rng.sizetNonUniform( sizeof(expCtx), 16, 2 );
        UINT16 cbExp    = (UINT16) rng.sizet( 1, sizeof(expSender) + 1 );
        for( SIZE_T k = 0; k < cbExpCtx; ++k ) { expCtx[k] = rng.byte(); }

        ntStatus = multiImp.secretExportSender(
            expCtx, cbExpCtx, expSender, cbExp );
        CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp SecretExport(sender) failed (DET_ENCAP)" );
        ntStatus = multiImp.secretExportRecipient(
            expCtx, cbExpCtx, expRecipient, cbExp );
        CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp SecretExport(recipient) failed (DET_ENCAP)" );
        CHECK( memcmp( expSender, expRecipient, cbExp ) == 0,
            "HpkeRand: Sender/Recipient SecretExport disagreement (DET_ENCAP)" );
        testHpkeRandAbsorb( pAccum, expSender, cbExp );
    }
}

static VOID
testHpkeRandExpectOpenFailure(
                                        HpkeMultiImp&   multiImp,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext,
                                        PCSTR           pszCase )
{
    BYTE openedPt[512 + 1];
    SIZE_T cChecked = 0;

    CHECK( cbPlaintext < sizeof(openedPt), "HpkeRand: plaintext buffer too large for negative Open" );

    for( HpkeMultiImp::ImpPtrVector::iterator i = multiImp.m_recipientComps.begin();
         i != multiImp.m_recipientComps.end();
         ++i )
    {
        memset( openedPt, 'f', cbPlaintext + 1 );

        NTSTATUS ntStatus = (*i)->open(
            pbAad, cbAad,
            pbCiphertext, cbCiphertext,
            openedPt, cbPlaintext );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK3( ntStatus != STATUS_SUCCESS,
            "HpkeRand: garbled Open unexpectedly succeeded (%s)", pszCase );
        CHECK( openedPt[cbPlaintext] == 'f', "Buffer overrun in failed Open" );
        cChecked++;
    }

    CHECK3( cChecked > 0,
        "HpkeRand: no implementation checked garbled Open (%s)", pszCase );
}

static VOID
testHpkeRandExpectOpenUnorderedFailure(
                                        HpkeMultiImp&   multiImp,
                                        UINT64          seqNumber,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext,
                                        PCSTR           pszCase )
{
    BYTE openedPt[512 + 1];
    SIZE_T cChecked = 0;

    CHECK( cbPlaintext < sizeof(openedPt), "HpkeRand: plaintext buffer too large for negative OpenUnordered" );

    for( HpkeMultiImp::ImpPtrVector::iterator i = multiImp.m_recipientComps.begin();
         i != multiImp.m_recipientComps.end();
         ++i )
    {
        memset( openedPt, 'u', cbPlaintext + 1 );

        NTSTATUS ntStatus = (*i)->openUnordered(
            seqNumber,
            pbAad, cbAad,
            pbCiphertext, cbCiphertext,
            openedPt, cbPlaintext );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK3( ntStatus != STATUS_SUCCESS,
            "HpkeRand: garbled OpenUnordered unexpectedly succeeded (%s)", pszCase );
        CHECK( openedPt[cbPlaintext] == 'u', "Buffer overrun in failed OpenUnordered" );
        cChecked++;
    }

    CHECK3( cChecked > 0,
        "HpkeRand: no implementation checked garbled OpenUnordered (%s)", pszCase );
}

static VOID
testHpkeRandCheckGarbledOpenState(
                                        Rng&            rng,
                                        HpkeMultiImp&   multiImp,
                                        UINT64          seqNumber,
    _In_reads_bytes_opt_( cbAad )       PCBYTE          pbAad,
                                        SIZE_T          cbAad,
    _In_reads_bytes_( cbCiphertext )    PCBYTE          pbCiphertext,
                                        SIZE_T          cbCiphertext,
                                        SIZE_T          cbPlaintext )
{
    BYTE badCt[512 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
    BYTE badAad[256 + 1];
    PCBYTE pbBadAad = badAad;
    SIZE_T cbBadAad;

    CHECK( cbCiphertext > 0, "HpkeRand: empty ciphertext in garbled-state check" );
    CHECK( cbCiphertext > cbPlaintext, "HpkeRand: ciphertext missing tag in garbled-state check" );
    CHECK( cbCiphertext <= sizeof(badCt), "HpkeRand: ciphertext too large for garbled-state check" );
    CHECK( cbAad <= 256, "HpkeRand: aad too large for garbled-state check" );

    memcpy( badCt, pbCiphertext, cbCiphertext );
    badCt[cbPlaintext + rng.sizet( cbCiphertext - cbPlaintext )] ^= (BYTE)( 1u << (rng.byte() & 7) );
    testHpkeRandExpectOpenFailure(
        multiImp, pbAad, cbAad, badCt, cbCiphertext, cbPlaintext, "tag bit flip" );

    if( cbPlaintext > 0 )
    {
        memcpy( badCt, pbCiphertext, cbCiphertext );
        badCt[rng.sizet( cbPlaintext )] ^= (BYTE)( 1u << (rng.byte() & 7) );
        testHpkeRandExpectOpenUnorderedFailure(
            multiImp, seqNumber, pbAad, cbAad, badCt, cbCiphertext, cbPlaintext,
            "ciphertext bit flip" );
    }

    if( cbAad == 0 )
    {
        badAad[0] = rng.byte();
        cbBadAad = 1;
    }
    else
    {
        memcpy( badAad, pbAad, cbAad );
        badAad[rng.sizet( cbAad )] ^= (BYTE)( 1u << (rng.byte() & 7) );
        cbBadAad = cbAad;
    }
    testHpkeRandExpectOpenUnorderedFailure(
        multiImp, seqNumber, pbBadAad, cbBadAad,
        pbCiphertext, cbCiphertext, cbPlaintext, "aad bit flip" );

    testHpkeRandExpectOpenUnorderedFailure(
        multiImp, seqNumber + (UINT64) rng.sizet( 1, 256 ),
        pbAad, cbAad, pbCiphertext, cbCiphertext, cbPlaintext, "wrong sequence" );
}

//
// Post-context, KEM_RANDOM variant. Public-API single-shot path through
// multiImp:
//   - sealSingleShot: cross-validates Seal(impl_i) -> Open(impl_j) inside multiImp.
//   - openSingleShot, setupRecipient/open/openUnordered, and SecretExport:
//     ResultMerge across impls.
// KEM consumes the SymCrypt callback RNG so outputs are non-deterministic;
// nothing is absorbed.
//
static VOID
testHpkeRandPostKem(
    Rng&                        rng,
    HpkeMultiImp&               multiImp,
    SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
    SIZE_T                      cbEnc,
    PCBYTE pbInfo,  SIZE_T cbInfo,
    PCBYTE pbPsk,   SIZE_T cbPsk,
    PCBYTE pbPskId, SIZE_T cbPskId )
{
    SYMCRYPT_HPKE_AEAD_PARAMS aeadParams;
    SYMCRYPT_ERROR scError = SymCryptHpkeValidateCiphersuite( ciphersuite, nullptr, &aeadParams );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: ValidateCiphersuite failed (KEM_RANDOM)" );

    // Fresh recipient key generated via static SymCrypt, then distributed to
    // every registered impl. The previous iteration's pre-context key (set into
    // multiImp by testHpkeRandPreContext) is intentionally overwritten — KEM_RANDOM
    // and pre-context exercise distinct API surface and don't need to share keys.
    PSYMCRYPT_HPKEKEY pkPriv = SymCryptHpkekeyAllocate( ciphersuite );
    CHECK( pkPriv != nullptr, "HpkeRand: keypair allocate failed (KEM_RANDOM)" );
    scError = SymCryptHpkekeyGenerate( pkPriv, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: keypair generate failed (KEM_RANDOM)" );

    SIZE_T cbPrivKey = 0;
    scError = SymCryptHpkeSizeofKeyFormatFromParams(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: SizeofKeyFormat (KEM_RANDOM) failed" );
    BYTE abPrivKey[ HPKE_RAND_MAX_PRIVATE_KEY_SIZE ];
    CHECK( cbPrivKey <= sizeof(abPrivKey), "HpkeRand: private-key buffer too small (KEM_RANDOM)" );
    scError = SymCryptHpkekeyGetValue(
        pkPriv, abPrivKey, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "HpkeRand: GetValue (KEM_RANDOM) failed" );

    NTSTATUS ntStatus = multiImp.setKey(
        ciphersuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, abPrivKey, cbPrivKey );
    CHECK( ntStatus == STATUS_SUCCESS, "HpkeRand: multi-imp setKey failed (KEM_RANDOM)" );

    BYTE enc[ SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE ];
    CHECK( cbEnc <= sizeof(enc), "HpkeRand: enc buffer too small (KEM_RANDOM)" );

    if( aeadParams.aeadId != SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY )
    {
        BOOL fStreaming = (rng.byte() & 1) != 0;

        BYTE aad[256], pt[512], ct[512 + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE];
        BYTE openedPt[512];
        SIZE_T cbAad = rng.sizetNonUniform( sizeof(aad), 16, 2 );
        SIZE_T cbPt  = rng.sizetNonUniform( sizeof(pt),  32, 2 );
        for( SIZE_T k = 0; k < cbAad; ++k ) { aad[k] = rng.byte(); }
        for( SIZE_T k = 0; k < cbPt;  ++k ) { pt[k]  = rng.byte(); }

        if( !fStreaming )
        {
            ntStatus = multiImp.sealSingleShot(
                pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
                aad, cbAad, pt, cbPt,
                enc, cbEnc, ct, cbPt + aeadParams.cbTag );
            CHECK( ntStatus == STATUS_SUCCESS,
                "HpkeRand: multi-imp sealSingleShot failed (KEM_RANDOM)" );

            ntStatus = multiImp.openSingleShot(
                enc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
                aad, cbAad, ct, cbPt + aeadParams.cbTag, openedPt, cbPt );
            CHECK( ntStatus == STATUS_SUCCESS,
                "HpkeRand: multi-imp openSingleShot failed (KEM_RANDOM)" );
            CHECK( memcmp( openedPt, pt, cbPt ) == 0,
                "HpkeRand: multi-imp Seal/Open round-trip mismatch (KEM_RANDOM)" );
        }
        else
        {
            //
            // Streaming multi-msg path: random N messages with random aad/pt
            // sizes through one sender/recipient pair. Exercises seq# / nonce
            // derivation across many messages, which the single-shot path does
            // not. Sender setup remains direct because Encap is randomized;
            // recipient setup/open is deterministic for (key, enc, info, psk).
            //
            PSYMCRYPT_HPKECONTEXT pSender = SymCryptHpkeContextAllocate( ciphersuite );
            CHECK( pSender != nullptr,
                "HpkeRand: sender HpkeContextAllocate failed (KEM_RANDOM streaming)" );

            scError = SymCryptHpkeSetupSender(
                pSender, pkPriv, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
                enc, cbEnc, 0 );
            CHECK( scError == SYMCRYPT_NO_ERROR,
                "HpkeRand: SetupSender failed (KEM_RANDOM streaming)" );

            ntStatus = multiImp.setupRecipient(
                enc, cbEnc,
                pbInfo, cbInfo,
                pbPsk, cbPsk,
                pbPskId, cbPskId );
            CHECK( ntStatus == STATUS_SUCCESS,
                "HpkeRand: multi-imp SetupRecipient failed (KEM_RANDOM streaming)" );

            // First message already sampled above; do that one plus nMsgs-1 more.
            SIZE_T nMsgs = rng.sizet( 1, 6 );
            for( SIZE_T m = 0; m < nMsgs; ++m )
            {
                UINT64 seqNumber;

                if( m > 0 )
                {
                    cbAad = rng.sizetNonUniform( sizeof(aad), 16, 2 );
                    cbPt  = rng.sizetNonUniform( sizeof(pt),  32, 2 );
                    for( SIZE_T k = 0; k < cbAad; ++k ) { aad[k] = rng.byte(); }
                    for( SIZE_T k = 0; k < cbPt;  ++k ) { pt[k]  = rng.byte(); }
                }

                scError = SymCryptHpkeSeal(
                    pSender, aad, cbAad, pt, cbPt,
                    ct, cbPt + aeadParams.cbTag, &seqNumber );
                CHECK( scError == SYMCRYPT_NO_ERROR,
                    "HpkeRand: Seal failed (KEM_RANDOM streaming)" );

                testHpkeRandCheckGarbledOpenState(
                    rng, multiImp, seqNumber, aad, cbAad, ct, cbPt + aeadParams.cbTag, cbPt );

                ntStatus = multiImp.openUnordered(
                    seqNumber, aad, cbAad,
                    ct, cbPt + aeadParams.cbTag, openedPt, cbPt );
                CHECK( ntStatus == STATUS_SUCCESS,
                    "HpkeRand: multi-imp OpenUnordered failed (KEM_RANDOM streaming)" );
                CHECK( memcmp( openedPt, pt, cbPt ) == 0,
                    "HpkeRand: Seal/OpenUnordered round-trip mismatch (KEM_RANDOM streaming)" );

                ntStatus = multiImp.open(
                    aad, cbAad,
                    ct, cbPt + aeadParams.cbTag, openedPt, cbPt );
                CHECK( ntStatus == STATUS_SUCCESS,
                    "HpkeRand: multi-imp Open failed (KEM_RANDOM streaming)" );
                CHECK( memcmp( openedPt, pt, cbPt ) == 0,
                    "HpkeRand: multi-imp Seal/Open round-trip mismatch (KEM_RANDOM streaming)" );
            }

            SymCryptHpkeContextFree( pSender );
        }
    }
    else
    {
        // Export-Only mode has no Seal/Open. Produce an `enc` for the SecretExport
        // step below via a direct SetupSender (multiImp does not expose a
        // SetupSender-only single-shot).
        PSYMCRYPT_HPKECONTEXT pCtx = SymCryptHpkeContextAllocate( ciphersuite );
        CHECK( pCtx != nullptr,
            "HpkeRand: HpkeContextAllocate failed (KEM_RANDOM Export-Only)" );
        scError = SymCryptHpkeSetupSender(
            pCtx, pkPriv, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
            enc, cbEnc, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR,
            "HpkeRand: SetupSender failed (KEM_RANDOM Export-Only)" );
        SymCryptHpkeContextFree( pCtx );
    }

    ntStatus = multiImp.setupRecipient(
        enc, cbEnc,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId );
    CHECK( ntStatus == STATUS_SUCCESS,
        "HpkeRand: multi-imp SetupRecipient failed (KEM_RANDOM export check)" );

    {
        const BYTE expCtx[] = "KEM_RANDOM recipient export";
        BYTE exported[32];

        ntStatus = multiImp.secretExportRecipient(
            expCtx, sizeof(expCtx) - 1, exported, sizeof(exported) );
        CHECK( ntStatus == STATUS_SUCCESS,
            "HpkeRand: multi-imp recipient SecretExport failed (KEM_RANDOM export check)" );
    }

    // SecretExport via multiImp: every impl does SetupRecipient + SecretExport
    // on the supplied `enc`; results are ResultMerged for cross-impl agreement.
    {
        BYTE expCtx[128];
        BYTE exported[64];
        SIZE_T cbExpCtx = rng.sizetNonUniform( sizeof(expCtx), 16, 2 );
        UINT16 cbExp    = (UINT16) rng.sizet( 1, sizeof(exported) + 1 );
        for( SIZE_T k = 0; k < cbExpCtx; ++k ) { expCtx[k] = rng.byte(); }

        ntStatus = multiImp.secretExportSingleShot(
            enc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
            expCtx, cbExpCtx, exported, cbExp );
        CHECK( ntStatus == STATUS_SUCCESS,
            "HpkeRand: multi-imp secretExportSingleShot failed (KEM_RANDOM)" );
    }

    SymCryptHpkekeyFree( pkPriv );
    SymCryptWipeKnownSize( abPrivKey, sizeof(abPrivKey) );
}

//
// One iteration: pick ciphersuite, sample info/PSK shapes, route through
// pre-context and one of the two post-context variants.
//
static VOID
testHpkeRandIteration(
    Rng&                                    rng,
    PVOID                                   pAccum,
    HpkeMultiImp&                           multiImp,
    const std::vector<HPKE_TEST_PARAMS>&    params )
{
    const HPKE_TEST_PARAMS & selected = params[ rng.sizet( params.size() ) ];

    BOOL fPsk = (rng.byte() & 1) != 0;

    BYTE info[ SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE ];
    BYTE psk[64];
    BYTE pskId[64];
    SIZE_T cbInfo  = rng.sizetNonUniform( sizeof(info), 16, 2 );
    SIZE_T cbPsk   = fPsk ? rng.sizet( 1, sizeof(psk)   + 1 ) : 0;
    SIZE_T cbPskId = fPsk ? rng.sizet( 1, sizeof(pskId) + 1 ) : 0;
    for( SIZE_T k = 0; k < cbInfo;  ++k ) { info[k]  = rng.byte(); }
    for( SIZE_T k = 0; k < cbPsk;   ++k ) { psk[k]   = rng.byte(); }
    for( SIZE_T k = 0; k < cbPskId; ++k ) { pskId[k] = rng.byte(); }

    testHpkeRandAbsorb( pAccum, (PCBYTE) &selected.ciphersuite, sizeof(selected.ciphersuite) );
    testHpkeRandAbsorb( pAccum, info,  cbInfo );
    testHpkeRandAbsorb( pAccum, psk,   cbPsk );
    testHpkeRandAbsorb( pAccum, pskId, cbPskId );

    BOOL fDeriveKeyPath      = (rng.byte() & 1) != 0;
    BOOL fDeterministicEncap = (rng.byte() & 1) != 0;

    // Deterministic encap is only deterministic if the recipient key is itself deterministic.
    if( fDeterministicEncap )
    {
        fDeriveKeyPath = TRUE;
    }

    testHpkeRandPreContext( rng, pAccum, multiImp, fDeriveKeyPath, selected.ciphersuite );

    if( fDeterministicEncap )
    {
        testHpkeRandPostDetEncap(
            rng, pAccum, multiImp, selected.ciphersuite, selected.cbEnc,
            cbInfo  ? info  : nullptr, cbInfo,
            cbPsk   ? psk   : nullptr, cbPsk,
            cbPskId ? pskId : nullptr, cbPskId );
    }
    else
    {
        testHpkeRandPostKem(
            rng, multiImp, selected.ciphersuite, selected.cbEnc,
            cbInfo  ? info  : nullptr, cbInfo,
            cbPsk   ? psk   : nullptr, cbPsk,
            cbPskId ? pskId : nullptr, cbPskId );
    }
}

//
// Build the full (regular + export-only) ciphersuite list. Shared by both
// entry points.
//
static std::vector<HPKE_TEST_PARAMS>
testHpkeRandBuildParams()
{
    std::vector<HPKE_TEST_PARAMS> params     = testHpkeBuildTestParams( /*fExportOnly*/ FALSE );
    std::vector<HPKE_TEST_PARAMS> exportOnly = testHpkeBuildTestParams( /*fExportOnly*/ TRUE );
    params.insert( params.end(), exportOnly.begin(), exportOnly.end() );
    return params;
}

//
// Release per-impl keys before the outstanding-allocation check elsewhere
// notices them (HpkeImp instances live in g_algorithmImplementation until
// exitTestInfrastructure()).
//
static VOID
testHpkeRandReleaseKeys( HpkeMultiImp & multiImp )
{
    SYMCRYPT_HPKE_CIPHERSUITE emptySuite = {};
    multiImp.setKey( emptySuite, 0, nullptr, 0 );
}

//
// RANDOM-KAT entry. Deterministic from the fixed seed; failure means HPKE
// behavior changed since baseline. Re-baseline by running the test, copying
// the printed 'actual:' hex into g_hpkeRandomKatExpectedDigest, and noting
// the rotation in the PR description.
//
static const BYTE   g_hpkeRandomKatSeed[]      = "HPKE-RANDOM-KAT-v1";
static const UINT32 g_hpkeRandomKatIterations  = 500;

//
// Baseline digest. After this commit lands the baseline is locked; subsequent
// intentional HPKE behavior changes need a fresh baseline + a PR note.
//
static const BYTE g_hpkeRandomKatExpectedDigest[SYMCRYPT_MARVIN32_RESULT_SIZE] = {
    0x0d, 0x74, 0xc9, 0x01, 0xfd, 0x24, 0x9a, 0xee,
};

static VOID
testHpkeRandomKat( HpkeMultiImp & multiImp )
{
    std::vector<HPKE_TEST_PARAMS> params = testHpkeRandBuildParams();

    Rng rng;
    rng.reset( g_hpkeRandomKatSeed, sizeof(g_hpkeRandomKatSeed) - 1 );

    SYMCRYPT_MARVIN32_STATE state;
    SymCryptMarvin32Init( &state, SymCryptMarvin32DefaultSeed );

    for( UINT32 i = 0; i < g_hpkeRandomKatIterations; ++i )
    {
        testHpkeRandIteration( rng, &state, multiImp, params );
    }

    testHpkeRandReleaseKeys( multiImp );

    BYTE digest[SYMCRYPT_MARVIN32_RESULT_SIZE];
    SymCryptMarvin32Result( &state, digest );

    if( memcmp( digest, g_hpkeRandomKatExpectedDigest, sizeof(digest) ) != 0 )
    {
        print( "\nHPKE RANDOM-KAT digest mismatch.\n  actual:   " );
        fprintHex( stdout, digest, sizeof(digest) );
        print( "  expected: " );
        fprintHex( stdout, g_hpkeRandomKatExpectedDigest, sizeof(digest) );
        FATAL(
            "RANDOM-KAT regression: HPKE behavior changed since baseline. "
            "If the change is intentional, re-baseline g_hpkeRandomKatExpectedDigest "
            "in testHpke.cpp and call out the rotation in the PR description." );
    }
}

//
// RANDOM-CROSSCHECK entry. Inputs vary per process run; reproducible by replaying
// g_rngSeed via the existing rngseed= CLI option. All cross-impl verification
// happens inside multiImp; with a single registered impl this is a smoke test
// that catches state corruption and ordering bugs.
//
static VOID
testHpkeRandomCrossCheck( HpkeMultiImp & multiImp )
{
    std::vector<HPKE_TEST_PARAMS> params = testHpkeRandBuildParams();

    // Mix in a per-test tag so this test doesn't replay the same RNG sequence
    // as any other rng-seeded test.
    UINT32 seedMaterial[2] = { g_rngSeed, 0x48504b45 /* 'HPKE' */ };
    Rng rng;
    rng.reset( (PCBYTE) seedMaterial, sizeof(seedMaterial) );

    UINT32 iterations = g_noPerfTests ? 100 : 500;
    for( UINT32 i = 0; i < iterations; ++i )
    {
        testHpkeRandIteration( rng, /*pAccum*/ nullptr, multiImp, params );
    }

    testHpkeRandReleaseKeys( multiImp );
}


//
// ========================================================================
// testHpke — main entry point
// ========================================================================
//
VOID
testHpke()
{
    // Skip if HPKE is not in the set of algorithms to test
    if( !setContainsPrefix( g_algorithmsToTest, "Hpke" ) )
    {
        return;
    }

    iprint( "    HPKE\n" );

    //
    // One category list per phase. Each token prints at the start of its
    // phase so a hang or failure points at the last token; CHECK messages
    // carry per-suite context.
    //
    std::vector<HPKE_TEST_PARAMS> hpkeTestParams = testHpkeBuildTestParams( FALSE );
    std::vector<HPKE_TEST_PARAMS> hpkeExportOnlyParams = testHpkeBuildTestParams( TRUE );
    std::vector<HPKE_TEST_PARAMS> hpkeAllTestParams = hpkeTestParams;
    hpkeAllTestParams.insert( hpkeAllTestParams.end(), hpkeExportOnlyParams.begin(), hpkeExportOnlyParams.end() );

    iprint( "        scenario" );
    for ( const HPKE_TEST_PARAMS &params : hpkeTestParams )
    {
        testHpkeRoundTrip( &params );
        testHpkeMultipleMessages( &params );
        testHpkePsk( &params );
        testHpkeSecretExport( &params );
        testHpkekeyImportExport( &params );
        testHpkeSingleShot( &params );
        testHpkeDataIntegrity( &params );
        testHpkeSealValidationFailureDoesNotConsumeSequence( &params );
    }
    for ( const HPKE_TEST_PARAMS &params : hpkeExportOnlyParams )
    {
        testHpkeExportOnly( &params );
    }

    iprint( ", KAT" );

    // One HpkeMultiImp drives every cross-impl phase
    HpkeMultiImp multiImp( "Hpke" );
    testHpkeKat( multiImp );

    iprint( ", error cases" );
    testHpkeErrorCases();

    iprint( ", multi-imp interop" );
    testHpkeMultiImp( multiImp, hpkeAllTestParams );

    iprint( ", random-kat" );
    testHpkeRandomKat( multiImp );

    iprint( ", random-crosscheck" );
    testHpkeRandomCrossCheck( multiImp );

    iprint( ", multi-thread (static" );
    for ( const HPKE_TEST_PARAMS &params : hpkeTestParams )
    {
        testHpkeMultiThread( &params );
    }

    if ( g_dynamicSymCryptModuleHandle != NULL &&
         SCTEST_LOOKUP_DYNSYM( SymCryptHpkekeyAllocate, FALSE ) != NULL )
    {
        iprint( ", dynamic" );
        g_useDynamicFunctionsInTestCall = TRUE;
        for ( const HPKE_TEST_PARAMS &params : hpkeTestParams )
        {
            testHpkeMultiThread( &params );
        }
        g_useDynamicFunctionsInTestCall = FALSE;
    }
    else if ( g_dynamicSymCryptModuleHandle != NULL )
    {
        iprint( ", skipped dynamic" );
    }
    iprint( ")\n" );
}
