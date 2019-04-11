//
// pbkdf2_hmacsha1.c
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include "precomp.h"


//
// The SP800-108 SHA-1 test 
// This is in a separate module to avoid pullingin SHA-1 whenever we use PBKDF-SHA-256
//

static const BYTE    sp800_108_sha256Answer[] =
{
    0x00, 0x26, 0x4b, 0xbb, 0x14, 0x97, 0x40, 0x54,
};

VOID
SYMCRYPT_CALL
SymCryptSp800_108_HmacSha256SelfTest()
{
    BYTE    res[sizeof(sp800_108_sha256Answer)];
    
    SymCryptSp800_108(
        SymCryptHmacSha256Algorithm,
        &SymCryptTestKey32[0], 8,       // key
        (PCBYTE)"Label", 5,             // label
        &SymCryptTestKey32[16], 16,     // context
        res,
        sizeof(res));

    SymCryptInjectError( res, sizeof( res ) );

    if (memcmp(res, sp800_108_sha256Answer, sizeof(res)) !=0)
    {
        SymCryptFatal('8108');
    }
}

