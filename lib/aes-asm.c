//
// aes-asm.c   code for AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include "precomp.h"

VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptAsm( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SIZE_T cbToDo = cbData & ~(SYMCRYPT_AES_BLOCK_SIZE - 1);
    SIZE_T i;

    //
    // This loop condition is slightly strange.
    // If I use i < cbToDo (which is correct) then Prefast complains about buffer overflows.
    // Even using SYMCRYPT_ASSERT which does an _Analysis_assume_ I can't fix the Prefast issue.
    // The +15 in the code is slightly slower but it solves the Prefast issue.
    //

    for( i=0; (i+SYMCRYPT_AES_BLOCK_SIZE-1) < cbToDo; i+= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptAesEncryptAsm( pExpandedKey, pbSrc + i, pbDst + i );
    }
}

VOID
SYMCRYPT_CALL
SymCryptAesEcbDecryptAsm( 
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SIZE_T cbToDo = cbData & ~(SYMCRYPT_AES_BLOCK_SIZE - 1);
    SIZE_T i;

    //
    // This loop condition is slightly strange.
    // If I use i < cbToDo (which is correct) then Prefast complains about buffer overflows.
    // Even using SYMCRYPT_ASSERT which does an _Analysis_assume_ I can't fix the Prefast issue.
    // The +15 in the code is slightly slower but it solves the Prefast issue.
    //

    for( i=0; (i+SYMCRYPT_AES_BLOCK_SIZE-1) < cbToDo; i+= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptAesDecryptAsm( pExpandedKey, pbSrc + i, pbDst + i );
    }
}
