//
// ssh_kdf_sha512.c
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"



static const BYTE pbKey[] =
{
    0x00, 0x00, 0x00, 0x80, 0x57, 0x53, 0x08, 0xca, 0x39, 0x57, 0x98, 0xbb, 0x21, 0xec, 0x54, 0x38,
    0xc4, 0x6a, 0x88, 0xff, 0xa3, 0xf7, 0xf7, 0x67, 0x1c, 0x06, 0xf9, 0x24, 0xab, 0xf7, 0xc3, 0xcf,
    0xb4, 0x6c, 0x78, 0xc0, 0x25, 0x59, 0x6e, 0x4a, 0xba, 0x50, 0xc3, 0x27, 0x10, 0x89, 0x18, 0x4a,
    0x44, 0x7a, 0x57, 0x1a, 0xbb, 0x7f, 0x4a, 0x1b, 0x1c, 0x41, 0xf5, 0xd5, 0xca, 0x80, 0x62, 0x94,
    0x0d, 0x43, 0x69, 0x77, 0x85, 0x89, 0xfd, 0xe8, 0x1a, 0x71, 0xb2, 0x22, 0x8f, 0x01, 0x8c, 0x4c,
    0x83, 0x6c, 0xf3, 0x89, 0xf8, 0x54, 0xf8, 0x6d, 0xe7, 0x1a, 0x68, 0xb1, 0x69, 0x3f, 0xe8, 0xff,
    0xa1, 0xc5, 0x9c, 0xe7, 0xe9, 0xf9, 0x22, 0x3d, 0xeb, 0xad, 0xa2, 0x56, 0x6d, 0x2b, 0x0e, 0x56,
    0x78, 0xa4, 0x8b, 0xfb, 0x53, 0x0e, 0x7b, 0xee, 0x42, 0xbd, 0x2a, 0xc7, 0x30, 0x4a, 0x0a, 0x5a,
    0xe3, 0x39, 0xa2, 0xcd
};

static const BYTE pbHash[] =
{
    0xa4, 0x12, 0x5a, 0xa9, 0x89, 0x80, 0x92, 0xca, 0x50, 0xc3, 0xc1, 0x63, 0x1c, 0x03, 0xdc, 0xbc,
    0x9d, 0xf9, 0x5c, 0xeb, 0xb4, 0x09, 0x88, 0x1e, 0x58, 0x01, 0x08, 0xb6, 0xcc, 0x47, 0x04, 0xb7,
    0x6c, 0xc7, 0x7b, 0x87, 0x95, 0xfd, 0x59, 0x40, 0x56, 0x1e, 0x32, 0x24, 0xcc, 0x75, 0x84, 0x85,
    0x18, 0x99, 0x2b, 0xd8, 0xd9, 0xb7, 0x0f, 0xe0, 0xfc, 0x97, 0x7a, 0x47, 0x60, 0x63, 0xc8, 0xbf
};

static const BYTE pbSessionId[] =
{
    0xa4, 0x12, 0x5a, 0xa9, 0x89, 0x80, 0x92, 0xca, 0x50, 0xc3, 0xc1, 0x63, 0x1c, 0x03, 0xdc, 0xbc,
    0x9d, 0xf9, 0x5c, 0xeb, 0xb4, 0x09, 0x88, 0x1e, 0x58, 0x01, 0x08, 0xb6, 0xcc, 0x47, 0x04, 0xb7,
    0x6c, 0xc7, 0x7b, 0x87, 0x95, 0xfd, 0x59, 0x40, 0x56, 0x1e, 0x32, 0x24, 0xcc, 0x75, 0x84, 0x85,
    0x18, 0x99, 0x2b, 0xd8, 0xd9, 0xb7, 0x0f, 0xe0, 0xfc, 0x97, 0x7a, 0x47, 0x60, 0x63, 0xc8, 0xbf
};

static const BYTE label = SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER;

static const BYTE pbResult[] =
{
    0x7e, 0x4a, 0x72, 0x1f, 0xb7, 0x37, 0x9e, 0xbb, 0x42, 0x33, 0x06, 0x46, 0x4d, 0x57, 0xdb, 0x46,
    0xaf, 0xa3, 0xcc, 0xa1, 0x0a, 0x1d, 0x7f, 0xeb
};

VOID
SYMCRYPT_CALL
SymCryptSshKdfSha512SelfTest(void)
{
    SYMCRYPT_SSHKDF_EXPANDED_KEY expandedKey;
    SYMCRYPT_ALIGN BYTE rbResult[sizeof(pbResult)];

    SymCryptSshKdfExpandKey(&expandedKey, SymCryptSha512Algorithm, pbKey, sizeof(pbKey));

    SymCryptSshKdfDerive(&expandedKey,
                    pbHash, sizeof(pbHash),
                    label,
                    pbSessionId, sizeof(pbSessionId),
                    rbResult, sizeof(rbResult)
                    );

    SymCryptInjectError(rbResult, sizeof(rbResult));

    if (memcmp(rbResult, pbResult, sizeof(pbResult)) != 0)
    {
        SymCryptFatal('sshk');
    }
}
