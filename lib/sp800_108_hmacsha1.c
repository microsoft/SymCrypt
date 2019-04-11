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

static const BYTE    sp800_108_sha1Answer[] =
{
    0xcf, 0x4b, 0xfe, 0x4f, 0x85, 0xa1, 0x0b, 0xad,
};

VOID
SYMCRYPT_CALL
SymCryptSp800_108_HmacSha1SelfTest()
{
    BYTE    res[sizeof(sp800_108_sha1Answer)];
    
    SymCryptSp800_108(
        SymCryptHmacSha1Algorithm,
        &SymCryptTestKey32[0], 8,       // key
        (PCBYTE)"Label", 5,             // label
        &SymCryptTestKey32[16], 16,     // context
        res,
        sizeof(res));

    SymCryptInjectError( res, sizeof( res ) );

    if (memcmp(res, sp800_108_sha1Answer, sizeof(res)) !=0)
    {
        SymCryptFatal('8108');
    }
}

