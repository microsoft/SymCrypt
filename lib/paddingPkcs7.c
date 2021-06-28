//
// paddingPkcs7.c   Add/Remove PKCS7 padding
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"    


VOID
SYMCRYPT_CALL
SymCryptPaddingPkcs7Add(
                                            SIZE_T  cbBlockSize,
    _In_reads_(cbSrc)                       PCBYTE  pbSrc,
                                            SIZE_T  cbSrc,
    _Out_writes_to_(cbDst, *pcbResult)      PBYTE   pbDst,
                                            SIZE_T  cbDst,
                                            SIZE_T* pcbResult)
{
    SIZE_T          padVal;                                                     // PadVal is the number of bytes to pad.
    SIZE_T          dwDataLastBlock;                                            // dwDataLastBlock is the number of bytes of data at the final block.
    SIZE_T          cbResult = 0;                                               // This variable must always have a valid value when we finish the function.
  
    SYMCRYPT_ASSERT(cbBlockSize <= 256);                                        // cbBlockSize must be <= 256
    SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);                    // cbBlockSize must be a power of 2

    //
    // Compute the padding parameters.
    //

    dwDataLastBlock = (cbSrc & (cbBlockSize - 1));

    SYMCRYPT_ASSERT(cbDst >= cbSrc - dwDataLastBlock + cbBlockSize);            // cbDst >= cbSrc - cbSrc % cbBlockSize + cbBlockSize

    cbResult = (cbSrc - dwDataLastBlock + cbBlockSize);

    if (cbResult > cbDst)
    {
        goto cleanup;
    }

    padVal = (cbBlockSize - dwDataLastBlock);

    //
    //  perform the padding
    //

    // cbSrc must be greater than zero. memcpy(,,0) is not defined!
    if (pbDst != pbSrc && cbSrc > 0)
    {
        memcpy(pbDst, pbSrc, cbSrc);
    }
   
    memset(pbDst + cbSrc, (int)padVal, padVal);

cleanup:                                                                                       
    *pcbResult = cbResult;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptPaddingPkcs7Remove(
                                            SIZE_T  cbBlockSize,
    _In_reads_(cbSrc)                       PCBYTE  pbSrc,
                                            SIZE_T  cbSrc,
    _Out_writes_to_(cbDst, *pcbResult)      PBYTE   pbDst,
                                            SIZE_T  cbDst,
                                            SIZE_T* pcbResult)
{
    SYMCRYPT_ERROR          scError             = SYMCRYPT_NO_ERROR;

    UINT32                  mPaddingError       = 0;                    // Indicates whether there is an error in padding or not.
    UINT32                  mBufferSizeError    = 0;                    // Indicates whether pbDst is large enough to contain the entire message or not (not including the padding).
    UINT32                  isData              = 0;                    // isData is a mask for padding validation. It equals to zero for padded bytes.
    UINT32                  mask                = 0;
    UINT32                  padVal;                                     // dwPadVal is the number of padded bytes.
    UINT32                  lastDataBytePos;                            // dwLastDataByte is the positin of the last byte of data before padding at the final block.
    UINT32                  cbSrc32;
    UINT32                  cbDst32;
    UINT32                  cbMsg32;
                                                                 
    SIZE_T                  cbResult;                                   // This variable must always have a valid value when we finish the function
    SIZE_T                  cbBulk              = 0;        

    SYMCRYPT_ASSERT(cbBlockSize <= 256);                                // cbBlockSize must be <= 256
    SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);            // cbBlockSize must be a power of 2
    SYMCRYPT_ASSERT((cbSrc & (cbBlockSize - 1)) == 0);                  // cbSrc is a multiple of cbBlockSize
    SYMCRYPT_ASSERT(cbSrc > 0);                                         // cbSrc is greaten than zero

    padVal = (DWORD)pbSrc[cbSrc - 1];
    lastDataBytePos = padVal + 1;
    cbResult = cbSrc - padVal;
    
    //
    // Bulk processing
    //

    cbDst = min(cbDst, cbSrc);

    cbBulk = cbSrc - cbBlockSize;

    // cbSrc, cbDst, and blockSize are not secrets. 
    // This condition can be checked in a non-side channel safe way. 
    if (cbDst < cbBulk)
    {
        scError = SYMCRYPT_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (pbDst != pbSrc)
    {
        memcpy(pbDst, pbSrc, cbBulk);
    }

    // Updating parameters
    pbSrc += cbBulk; cbSrc -= cbBulk;
    pbDst += cbBulk; cbDst -= cbBulk;

    cbSrc32 = (UINT32)cbSrc;
    cbDst32 = (UINT32)cbDst;

    //
    // Validating padding
    //

    cbMsg32 = (UINT32)(cbBlockSize - padVal);

    //check Dst buffer length to make sure it is possible copy the whole message (not including the padding).
    mBufferSizeError |= SymCryptMask32LtU31(cbDst32, cbMsg32);

    // check the Padding to make sure it is valid.
    mPaddingError |= SymCryptMask32IsZeroU31(padVal) | SymCryptMask32LtU31((UINT32)cbBlockSize, padVal);

    // loop through the last block to check the padding.
    for (UINT32 i = 2; i <= cbBlockSize; ++i)
    {
        isData |= SymCryptMask32IsZeroU31(i ^ lastDataBytePos);
        mPaddingError |= (SymCryptMask32IsNonzeroU31((UINT32)pbSrc[cbSrc - i] ^ padVal) & ~isData);
    }

    //
    // Final Block processing
    //

    // If cbDst is large enough, the code will write cbSrc-1 bytes to pbDst, using masking to only update the bytes of the
    // message and leaving the other bytes in pbDst unchanged.

    for (UINT32 i = 0; i <= cbDst; ++i)
    {
        mask = SymCryptMask32LtU31(i, cbMsg32);
        pbDst[i] ^= (pbDst[i] ^ pbSrc[i]) & mask;
    }

    // Even if an error is returned, the pbDst buffer receives a copy of the data (up to cbDst bytes).
    cbResult = (mBufferSizeError & (cbDst + cbBulk)) | ((~mBufferSizeError) & cbResult);

cleanup:

    *pcbResult = cbResult;

    // Update scError with the two error masks.
    scError ^= mBufferSizeError & (scError ^ SYMCRYPT_BUFFER_TOO_SMALL);
    scError ^= mPaddingError & (scError ^ SYMCRYPT_INVALID_ARGUMENT);

    return scError;
}


