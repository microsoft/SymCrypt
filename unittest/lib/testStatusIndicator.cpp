//
// Test FIPS Approved Services Status Indicator
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#define SYMCRYPT_FIPS_STATUS_INDICATOR
#include "../modules/statusindicator_common.h"
#include "../lib/status_indicator.h"


VOID
testStatusIndicator(BOOL bPrintString)
{
    UINT32 bufferLength = 0, bytesCopied = 0;
    PBYTE pbStatusIndicator = NULL;

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptDeprecatedStatusIndicator))
    {
        print("testStatusIndicator skipped\n");
        return;
    }

    print( "status-indicator\n" );

    bufferLength = ScDispatchSymCryptDeprecatedStatusIndicator(nullptr, 0);

    CHECK( bufferLength > 0, "SymCryptDeprecatedStatusIndicator returned buffer length=0");

    pbStatusIndicator = (PBYTE)malloc(bufferLength);

    CHECK3(pbStatusIndicator != NULL, "SymCryptDeprecatedStatusIndicator cannot allocate memory of size %d", bufferLength);

    if (pbStatusIndicator != NULL)
    {
        bytesCopied = ScDispatchSymCryptDeprecatedStatusIndicator(pbStatusIndicator, bufferLength);

        if (bPrintString)
        {
            print("---BEGIN STATUS INDICATOR STRING\n");
            print((const char*)pbStatusIndicator);
            print("---END STATUS INDICATOR STRING\n");
        }

        CHECK4(bytesCopied == bufferLength, "bytesCopied %d is not equal to bufferLength %d", bytesCopied, bufferLength);
        CHECK(strstr((const char*)pbStatusIndicator, "Algorithm Providers and Properties") != NULL, "Service string does not exist in SymCryptDeprecatedStatusIndicator: Algorithm Providers and Properties");
        CHECK(strstr((const char*)pbStatusIndicator, "Zeroizing Cryptographic Material") != NULL, "Service string does not exist in SymCryptDeprecatedStatusIndicator: Zeroizing Cryptographic Material");

        free(pbStatusIndicator);
    }

    print ( "\n" );
}
