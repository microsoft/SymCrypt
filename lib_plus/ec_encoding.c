//
// ec_encoding.c
//
// IETF-standard EC encoding helpers. Thin wrappers around
// SymCryptEckey{Get,Set}Value that pre/post-process the wire format
// expected by IETF protocols built on top of SymCrypt's primitives.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#define SEC1_TAG_UNCOMPRESSED   (0x04)
#define CURVE25519_PRIVATE_KEY_SIZE (32)


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetValueIetfPrivateKey(
    _In_reads_bytes_( cbSrc )   PCBYTE                                   pbSrc,
                                SIZE_T                                   cbSrc,
                                SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT   format,
                                UINT32                                   flags,
    _Inout_                     PSYMCRYPT_ECKEY                          pEckey )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbPrivateKey;
    PCBYTE pbPrivateKey = pbSrc;
    BYTE privateKey[CURVE25519_PRIVATE_KEY_SIZE];
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT ecPointFormat;

    switch ( format )
    {
    case SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR:
        numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
        cbPrivateKey = SymCryptEckeySizeofPrivateKey( pEckey );
        break;

    case SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519:
        numFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
        cbPrivateKey = SymCryptEckeySizeofPrivateKey( pEckey );
        if ( cbPrivateKey != sizeof(privateKey) )
        {
            scError = SYMCRYPT_INVALID_ARGUMENT;
            goto cleanup;
        }
        break;

    default:
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( cbSrc != cbPrivateKey )
    {
        scError = SYMCRYPT_WRONG_KEY_SIZE;
        goto cleanup;
    }

    if ( format == SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519 )
    {
        // SymCrypt expects the key to already be clamped for Curve25519
        memcpy( privateKey, pbSrc, cbSrc );
        privateKey[0]  &= 0xF8;
        privateKey[31] &= 0x7F;
        privateKey[31] |= 0x40;
        pbPrivateKey = privateKey;
    }

    scError = SymCryptEckeySetValue(
                pbPrivateKey, cbPrivateKey,
                NULL, 0,
                numFormat,
                ecPointFormat,
                flags,
                pEckey );

cleanup:
    SymCryptWipeKnownSize( privateKey, sizeof(privateKey) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetValueIetfPublicKey(
    _In_reads_bytes_( cbSrc )   PCBYTE                                  pbSrc,
                                SIZE_T                                  cbSrc,
                                SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   format,
                                UINT32                                  flags,
    _Inout_                     PSYMCRYPT_ECKEY                         pEckey )
{
    PCBYTE pbCurr = pbSrc;
    SIZE_T cbPayload;
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT ecPointFormat;

    switch ( format )
    {
    case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED:
        numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
        cbPayload = SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat );

        if ( cbSrc != cbPayload + 1 )
        {
            return SYMCRYPT_WRONG_KEY_SIZE;
        }
        if ( *pbCurr++ != SEC1_TAG_UNCOMPRESSED )
        {
            return SYMCRYPT_INVALID_BLOB;
        }
        break;

    case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE:
        numFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
        cbPayload = SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat );

        if ( cbSrc != cbPayload )
        {
            return SYMCRYPT_WRONG_KEY_SIZE;
        }
        break;

    default:
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    return SymCryptEckeySetValue(
                NULL, 0,
                pbCurr, cbPayload,
                numFormat,
                ecPointFormat,
                flags,
                pEckey );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeyGetValueIetfPublicKey(
    _In_                        PCSYMCRYPT_ECKEY                        pEckey,
                                SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   format,
    _Out_writes_bytes_( cbDst ) PBYTE                                   pbDst,
                                SIZE_T                                  cbDst )
{
    PBYTE pbCurr = pbDst;
    SIZE_T cbPayload;
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT ecPointFormat;

    switch ( format )
    {
    case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED:
        numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
        cbPayload = SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat );

        if ( cbDst != cbPayload + 1 )
        {
            return SYMCRYPT_WRONG_KEY_SIZE;
        }
        *pbCurr++ = SEC1_TAG_UNCOMPRESSED;
        break;

    case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE:
        numFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        ecPointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
        cbPayload = SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat );

        if ( cbDst != cbPayload )
        {
            return SYMCRYPT_WRONG_KEY_SIZE;
        }
        break;

    default:
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    return SymCryptEckeyGetValue(
                pEckey,
                NULL, 0,
                pbCurr, cbPayload,
                numFormat,
                ecPointFormat,
                0 );
}
