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
    SIZE_T          padVal          = 0;                                            // PadVal is the number of bytes to pad.
    SIZE_T          dwDataLastBlock = 0;                                            // dwDataLastBlock is the number of bytes of data at the final block.
    SIZE_T          cbResult        = cbSrc;                                        // This variable must always have a valid value when we finish the function.
  
    SYMCRYPT_ASSERT(cbBlockSize <= 256);                                            // cbBlockSize must be <= 256
    SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);                        // cbBlockSize must be a power of 2
    SYMCRYPT_ASSERT(cbDst >= cbSrc - (cbSrc % cbBlockSize) + cbBlockSize);          // cbDst >= cbSrc - cbSrc % cbBlockSize + cbBlockSize

    //
    // Compute the padding parameters.
    //

    dwDataLastBlock = cbSrc % cbBlockSize;

    cbResult = (cbSrc - dwDataLastBlock + cbBlockSize);

    if (cbResult > cbDst)
    {
        goto cleanup;
    }

    padVal = (cbBlockSize - dwDataLastBlock);

    //
    //  perform the padding
    //

    if (pbDst != pbSrc)
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
    BYTE                    mPaddingError       = 0;                // Indicates whether there is an error in padding or not.
    BYTE                    mBufferSizeError    = 0;                // Indicates whether pbDst is large enough to contain the entire message or not (not including the padding).
    BYTE                    isDstBiggerthanSrc  = 0;                // Indicates whether pbDst is large enough to copy cbSrc-1 bytes to it.
    BYTE                    isData              = 0;                // isData is a mask for padding validation. It equals to zero for padded bytes.
    

    DWORD                   dwPadVal;                               // dwPadVal is the number of padded bytes.
    DWORD                   dwLastDataByte;                         // dwLastDataByte is the positin of the last byte of data before padding at the final block.                                                               
    SIZE_T                  cbResult;                               // This variable must always have a valid value when we finish the function
    SIZE_T                  cbOutput = cbSrc - 1;

    SYMCRYPT_ASSERT(cbBlockSize <= 256);                            // cbBlockSize must be <= 256
    SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);        // cbBlockSize must be a power of 2
    SYMCRYPT_ASSERT(cbSrc % cbBlockSize == 0);                      // cbSrc is a multiple of cbBlockSize
    SYMCRYPT_ASSERT(cbSrc > 0);                                     // cbSrc is greaten than zero

    dwPadVal = (DWORD)pbSrc[cbSrc - 1];                                                         
    dwLastDataByte = dwPadVal + 1;
    cbResult = cbSrc - dwPadVal;

    if (cbDst < cbSrc - cbBlockSize)
    {
        scError = SYMCRYPT_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    isDstBiggerthanSrc = (cbDst < cbSrc - 1) ? 0 : 0xff;
    
    //check Dst buffer length to make sure it is possible copy the whole message (not including the padding).
    mBufferSizeError |= ((BYTE)SymCryptMask32LtU31((cbDst % cbBlockSize) & 0xFFFFFFFF, (cbBlockSize - dwPadVal) & 0xFFFFFFFF) & ~isDstBiggerthanSrc);

    // check the Padding to make sure it is valid.
    mPaddingError |= (BYTE)(SymCryptMask32IsZeroU31(dwPadVal) | SymCryptMask32LtU31(cbBlockSize & 0xFFFFFFFF, dwPadVal));

    // loop through the last block to check the padding.
    for (DWORD i = 2; i <= cbBlockSize; ++i)
    {
        isData |= (BYTE)SymCryptMask32IsZeroU31(i ^ dwLastDataByte);
        mPaddingError |= ((BYTE)SymCryptMask32IsNonzeroU31(pbSrc[cbSrc - i] ^ (BYTE)dwPadVal) & ~isData);
    }

    // If cbDst is large enough, the code will write cbSrc-1 bytes to pbDst, using masking to only update the bytes of the
    // message and leaving the other bytes in pbDst unchanged.

    cbOutput = (~isDstBiggerthanSrc & cbDst) | ((isDstBiggerthanSrc) & (cbSrc - 1));

    if (pbDst != pbSrc)
    {
        memcpy(pbDst, pbSrc, cbOutput);
    }

    // Even if an error is returned, the pbDst buffer receives a copy of the data (up to cbDst bytes).
    cbResult = (mBufferSizeError & cbDst) | ((~mBufferSizeError) & cbResult);

cleanup:

    *pcbResult = cbResult;

    // Update scError with the two error masks.
    scError ^= mBufferSizeError & (scError ^ SYMCRYPT_BUFFER_TOO_SMALL);
    scError ^= mPaddingError & (scError ^ SYMCRYPT_INVALID_ARGUMENT);     

    return scError;
}


