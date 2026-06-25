//
// SymCrypt_ec_encoding.h
//
// EC key wire-format helpers for IETF protocols.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include "symcrypt.h"

//
// Supported EC private-key wire formats.
//
typedef enum SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT {
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NULL        = 0,
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR = 1,
        // Raw private scalar, big-endian.
        // Used with P-256, P-384, and P-521.
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519      = 2,
        // Raw private scalar, little-endian; clamped during import per RFC 7748.
        // Used with Curve25519.
} SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT;

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetValueIetfPrivateKey(
    _In_reads_bytes_( cbSrc )   PCBYTE                                   pbSrc,
                                SIZE_T                                   cbSrc,
                                SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT   format,
                                UINT32                                   flags,
    _Inout_                     PSYMCRYPT_ECKEY                          pEckey );
//
// Import a private key to an ECKEY object from one of the wire formats listed in
// SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT. pEckey must already be allocated for the
// curve that the encoded key belongs to. The corresponding public key is derived
// and stored by this call.
//
//  - (pbSrc, cbSrc): the encoded private key. cbSrc must match the size implied by
//    pEckey's curve and the selected format.
//  - format: see SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT for supported values and the
//    curves each is intended for.
//  - flags: same key-usage and validation flags as SymCryptEckeySetValue.
//  - pEckey: the ECKEY to populate.
//
// Returns:
//  - SYMCRYPT_NO_ERROR on success.
//  - SYMCRYPT_INVALID_ARGUMENT if format is not a supported value, or is not compatible
//    with pEckey's curve.
//  - SYMCRYPT_WRONG_KEY_SIZE if cbSrc does not match the expected size.
//  - Any error returned by SymCryptEckeySetValue.
//

//
// Supported EC public-key wire formats.
//
typedef enum SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT {
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL              = 0,
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED = 1,
        // 0x04 || X || Y, big-endian.
        // Used with P-256, P-384, and P-521.
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE          = 2,
        // X, little-endian.
        // Used with Curve25519.
} SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT;

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetValueIetfPublicKey(
    _In_reads_bytes_( cbSrc )   PCBYTE                                  pbSrc,
                                SIZE_T                                  cbSrc,
                                SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   format,
                                UINT32                                  flags,
    _Inout_                     PSYMCRYPT_ECKEY                         pEckey );
//
// Import the public key to an ECKEY object from one of the wire formats listed in
// SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT. pEckey must already be allocated for the
// curve that the encoded key belongs to.
//
//  - (pbSrc, cbSrc): the encoded public key. cbSrc must match the size implied by
//    pEckey's curve and the selected format.
//  - format: see SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT for supported values and the
//    curves each is intended for.
//  - flags: same key-usage and validation flags as SymCryptEckeySetValue.
//  - pEckey: the ECKEY to populate.
//
// Returns:
//  - SYMCRYPT_NO_ERROR on success.
//  - SYMCRYPT_INVALID_ARGUMENT if format is not a supported value, or is not compatible
//    with pEckey's curve.
//  - SYMCRYPT_WRONG_KEY_SIZE if cbSrc does not match the expected size.
//  - SYMCRYPT_INVALID_BLOB if the encoded public key is malformed.
//  - Any error returned by SymCryptEckeySetValue.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeyGetValueIetfPublicKey(
    _In_                        PCSYMCRYPT_ECKEY                        pEckey,
                                SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   format,
    _Out_writes_bytes_( cbDst ) PBYTE                                   pbDst,
                                SIZE_T                                  cbDst );
//
// Export the public component of an ECKEY in one of the wire formats listed in
// SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT.
//
//  - pEckey: the ECKEY holding the public key to export.
//  - format: see SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT for supported values and the
//    curves each is intended for.
//  - (pbDst, cbDst): the destination buffer. cbDst must match the size implied by the
//    pEckey's curve and the selected format.
//
// Returns:
//  - SYMCRYPT_NO_ERROR on success.
//  - SYMCRYPT_INVALID_ARGUMENT if format is not a supported value, or is not compatible
//    with pEckey's curve.
//  - SYMCRYPT_WRONG_KEY_SIZE if cbDst does not match the expected size.
//  - Any error returned by SymCryptEckeyGetValue.
//

#ifdef __cplusplus
}
#endif
