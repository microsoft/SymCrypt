//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#define MAX_BUFFER_SIZE         10000
#define MAX_PKCS7_BLOCK_SIZE    128
#define MAX_DEST_BUFFER_SIZE    2 * (MAX_BUFFER_SIZE + MAX_PKCS7_BLOCK_SIZE)

SIZE_T
verifyAddPadding(SIZE_T cbBlockSize, PCBYTE pbSrc, UINT32 cbSrc, PBYTE pbDst, UINT32 cbDst)
{
    SIZE_T cbResult = cbSrc;

    // Making copy of the Dst buffer before padding for validation
    PBYTE pbDstCpy = new BYTE[cbDst];
    CHECK(pbDstCpy != NULL, "Out of memory in verifyAddPadding");
    memcpy(pbDstCpy, pbDst, cbDst);

    // Calculating padding parameters for validation
    UINT32 cbPadVal = (UINT32)(cbBlockSize - (cbSrc % cbBlockSize));
    UINT32 cbPredictedResult = cbSrc + cbPadVal;

    ScDispatchSymCryptPaddingPkcs7Add(cbBlockSize, pbSrc, cbSrc, pbDst, cbDst, &cbResult);

    // Verify cbResult value
    CHECK(cbResult == cbPredictedResult, "testPaddingPkcs7Add : cbResult is incorrect.");

    // Verify pbDst data (msg, padding, unchanged data)
    for (UINT32 i = 0; i < cbDst; ++i)
    {
        if (i < cbSrc)
        {
            CHECK(pbSrc[i] == pbDst[i], "testPaddingPkcs7Add: message was not copied to destination as expected!");
            continue;
        }
        if (i < cbResult)
        {
            CHECK((BYTE)cbPadVal == pbDst[i], "testPaddingPkcs7Add: invalid padded value!");
            continue;
        }
        CHECK(pbDst[i] == pbDstCpy[i], "testPaddingPkcs7Add: data after padding was changed!");
    }

    delete [] pbDstCpy;
    return cbResult;
}

VOID
verifyRemovePadding(SIZE_T cbBlockSize, PCBYTE pbSrc, UINT32 cbSrc, PBYTE pbDst, UINT32 cbDst)
{
    
    SIZE_T cbResult = cbSrc;
    UINT32 cbPadVal = pbSrc[cbSrc - 1];
    UINT32 cbMsg = cbSrc - (cbPadVal % (cbBlockSize + 1 ));
    
    bool validPadding = (cbPadVal != 0 && cbPadVal <= cbBlockSize) ? true : false;
    bool bufferTooSmall = (cbDst < cbSrc - cbBlockSize) ? true : false;
    bool validBuffer = (cbDst < cbMsg) ? false : true;

    // Making copy of the Dst buffer for validation
    PBYTE pbDstCpy = new BYTE[cbDst];
    CHECK(pbDstCpy != NULL, "Out of memory in verifyRemovePadding");
    memcpy(pbDstCpy, pbDst, cbDst);

    SYMCRYPT_ERROR err = ScDispatchSymCryptPaddingPkcs7Remove(cbBlockSize, pbSrc, cbSrc, pbDst, cbDst, &cbResult);

    // if cbDst is less than block size, we don't need to check the padding.
    if (!bufferTooSmall)
    {
        for (UINT32 i = cbMsg; i < cbSrc; ++i)
        {
            if (pbSrc[i] != cbPadVal)
            {
                validPadding = false;
            }
        }
    }
    else
    {
        if (!validPadding)
        {
            CHECK(((err == SYMCRYPT_BUFFER_TOO_SMALL) || (err == SYMCRYPT_INVALID_ARGUMENT)),
                "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
        }
        else
        {
            CHECK(err == SYMCRYPT_BUFFER_TOO_SMALL, "testPaddingPkcs7Remove: not the expected error was returned.");
        }
    }

    if (validBuffer && validPadding)
    {
        CHECK(err == SYMCRYPT_NO_ERROR,
            "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
        CHECK(cbResult == cbMsg, "testPaddingPkcs7Remove: cbResult is incorrect.");

        // validate data at pbDst
        for (UINT32 i = 0; i < cbDst; ++i)
        {
            if (i < cbMsg)
            {
                CHECK(pbSrc[i] == pbDst[i], "testPaddingPkcs7Remove: message was not copied to destination as expected!");
                continue;
            }

            CHECK(pbDstCpy[i] == pbDst[i], "testPaddingPkcs7Remove: data after padding was changed!");
        }
    }
    else if (validBuffer && !validPadding)
    {
        CHECK(err == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
    }
    else if (!validBuffer && validPadding)
    {
        CHECK(err == SYMCRYPT_BUFFER_TOO_SMALL,
            "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
    }
    else if (!validBuffer && !validPadding)
    {
        CHECK(((err == SYMCRYPT_BUFFER_TOO_SMALL) || (err == SYMCRYPT_INVALID_ARGUMENT)),
            "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
    }

    delete [] pbDstCpy;
}


VOID
testPaddingPkcs7()
{
    UINT32 cbMsg;
    UINT32 cbAddPad;
    UINT32 cbRemovePad;
    
    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptPaddingPkcs7Add) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptPaddingPkcs7Remove) )
    {
        print("    testPaddingPkcs7 skipped\n");
        return;
    }

    // Prerequisites: cbBlockSize is a power of 2 and <= 128
    SIZE_T cbBlockSize;
    GENRANDOM(&cbBlockSize, sizeof(cbBlockSize));
    cbBlockSize = SymCryptRoundUpPow2Sizet(1 + (cbBlockSize % MAX_PKCS7_BLOCK_SIZE));

    GENRANDOM(&cbMsg, sizeof(cbMsg));
    cbMsg = cbMsg % MAX_BUFFER_SIZE;

    GENRANDOM(&cbRemovePad, sizeof(cbRemovePad));
    cbRemovePad = cbRemovePad % MAX_BUFFER_SIZE;

    // Prerequisites: cbDst >= cbSrc - cbSrc % cbBlockSize + cbBlockSize
    GENRANDOM(&cbAddPad, sizeof(cbAddPad));
    cbAddPad = cbAddPad % MAX_DEST_BUFFER_SIZE;
    cbAddPad = cbAddPad + (cbMsg + (UINT32)cbBlockSize - (cbMsg % cbBlockSize));

    
    // Generating both Src and Dst random buffers
    PBYTE pbMsg = new BYTE[cbMsg];
    CHECK(pbMsg != NULL, "Out of memory in testPaddingPkcs7");
    PBYTE pbAddPad = new BYTE[cbAddPad];
    CHECK(pbAddPad != NULL, "Out of memory in testPaddingPkcs7");
    PBYTE pbRemovePad = new BYTE[cbRemovePad];
    CHECK(pbRemovePad != NULL, "Out of memory in testPaddingPkcs7");
    
    GENRANDOM(pbMsg, cbMsg);
    GENRANDOM(pbAddPad, cbAddPad);
    GENRANDOM(pbRemovePad, cbRemovePad);

    // Check Add padding process 
    UINT32 cbResult = (UINT32) verifyAddPadding(cbBlockSize, pbMsg, cbMsg, pbAddPad, cbAddPad);

    // Check Remove padding process with validated padded buffer
    verifyRemovePadding(cbBlockSize, pbAddPad, cbResult, pbRemovePad, cbRemovePad);

    // Checking the remove padding process with manipulated padded data.
    // In this test we will generate a padding value and a position and replace one of 
    // the padded bytes with this random value. Then we will validate the remove padding.
    UINT32 cbPadValDummy;
    GENRANDOM(&cbPadValDummy, sizeof(cbPadValDummy));
    if (MAX_PKCS7_BLOCK_SIZE <= cbPadValDummy)
    {
        cbPadValDummy = cbPadValDummy % MAX_PKCS7_BLOCK_SIZE;
    }
    UINT32 cbPadVal = cbResult - cbMsg;
    UINT32 rndPadPos = cbMsg;
    if (cbPadVal != 0)
    {
        rndPadPos = rndPadPos + (cbPadValDummy % cbPadVal);
    }
    UINT32 cbSrcDummy = cbResult;
    PBYTE pbSrcDummy = new BYTE[cbSrcDummy];
    CHECK(pbSrcDummy != NULL, "Out of memory in testPaddingPkcs7");
    memcpy(pbSrcDummy, pbAddPad, cbResult);
    memset(pbSrcDummy + rndPadPos, cbPadValDummy, 1);

    UINT32 cbDstDummy;
    GENRANDOM(&cbDstDummy, sizeof(cbDstDummy));
    cbDstDummy = cbDstDummy % MAX_BUFFER_SIZE;
    PBYTE pbDstDummy = new BYTE[cbDstDummy];
    CHECK(pbDstDummy != NULL, "Out of memory in testPaddingPkcs7");
    GENRANDOM(pbDstDummy, cbDstDummy);

    verifyRemovePadding(cbBlockSize, pbSrcDummy, cbSrcDummy, pbDstDummy, cbDstDummy);

    // Cleanup
    delete [] pbMsg;
    delete [] pbAddPad;
    delete [] pbRemovePad;
    delete [] pbSrcDummy;
    delete [] pbDstDummy;
}
