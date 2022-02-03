//
// xtsaes.c   code for XTS-AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptXtsAesExpandKey(
    _Out_               PSYMCRYPT_XTS_AES_EXPANDED_KEY  pExpandedKey,
    _In_reads_( cbKey ) PCBYTE                          pbKey,
                        SIZE_T                          cbKey )
{
    SYMCRYPT_ERROR  scError;
    SIZE_T          halfKeySize = cbKey / 2;

    scError = SymCryptAesExpandKey( &pExpandedKey->key1, pbKey, halfKeySize );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // Pass the 'rest' of the key to the second one. This catches errors such as
    // an attempt to pass a 33 byte key.
    // halfKeySize = 16, which is valid, but this expansion gets a 17-byte key which will fail.
    // Key2 is only used for tweak encryption, so we can use the EncryptOnly key expansion.
    //
    scError = SymCryptAesExpandKeyEncryptOnly( &pExpandedKey->key2, pbKey + halfKeySize, cbKey - halfKeySize );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

cleanup:

    return scError;
}

#define N_PARALLEL_TWEAKS   16


VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptC(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptC( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitC( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_ARM

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptAsm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptAsm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitAsm( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}
#endif

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptXmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitXmm( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}

#if 0 //do not compile Zmm code for now
VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptZmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitZmm_2048( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}
#endif

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptYmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitYmm_2048( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}
#endif

#if SYMCRYPT_CPU_ARM64
VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptNeon(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptNeon( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesEncryptDataUnitNeon( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptNeon(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptNeon( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitNeon( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}


#endif

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncrypt(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
#if SYMCRYPT_CPU_AMD64
    SYMCRYPT_EXTENDED_SAVE_DATA SaveData;
    /* if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_VAES_512_CODE ) ) {
        SymCryptXtsAesEncryptZmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else */
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE ) &&
        SymCryptSaveYmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptXtsAesEncryptYmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
        SymCryptRestoreYmm( &SaveData );
    } else if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) ) {
        SymCryptXtsAesEncryptXmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else {
        SymCryptXtsAesEncryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptXtsAesEncryptXmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptXtsAesEncryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptXtsAesEncryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptXtsAesEncryptNeon( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else {
        SymCryptXtsAesEncryptC( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#else
    SymCryptXtsAesEncryptC( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
#endif
}


VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptC(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptC( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitC( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}

#if SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_ARM

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptAsm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    SYMCRYPT_ALIGN BYTE     tweakBuf[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T                  tweakbytes;
    SIZE_T                  i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptAsm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitAsm( &pExpandedKey->key1, &tweakBuf[i], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( tweakBuf, sizeof( tweakBuf ) );
}
#endif

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptXmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitXmm( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}

#if 0 //do not compile Zmm code for now
VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptZmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitZmm_2048( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}
#endif

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptYmm(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
    // Defining localScratch as a buffer of __m128is ensures there is required 16B alignment on x86
    __m128i localScratch[ N_PARALLEL_TWEAKS + 16 ];
    PBYTE               tweakBuf        = (PBYTE) &localScratch[0];
    PBYTE               dataUnitScratch = (PBYTE) &localScratch[N_PARALLEL_TWEAKS];
    SIZE_T              tweakbytes;
    SIZE_T              i;

    SYMCRYPT_ASSERT( (cbDataUnit & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0 && cbData % cbDataUnit == 0);

    cbDataUnit &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    while( cbData >= cbDataUnit )
    {
        //
        // We encrypt the tweaks of many data units in parallel for best performance.
        // In the first loop we build the tweaks and decrement cbData.
        // In the second loop we use up all the tweaks, and update the pointers.
        // Both loops are executed the same number of times.
        //
        tweakbytes = 0;

        do // do-while because we know we are going to go through at least once.
        {
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes    ], tweak);
            SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[tweakbytes + 8], 0);
            tweak++;
            cbData -= cbDataUnit;
            tweakbytes += SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= cbDataUnit && tweakbytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS );

        SymCryptAesEcbEncryptXmm( &pExpandedKey->key2, &tweakBuf[0], &tweakBuf[0], tweakbytes );

        i = 0;
        while( i < tweakbytes )
        {
            SymCryptXtsAesDecryptDataUnitYmm_2048( &pExpandedKey->key1, &tweakBuf[i], &dataUnitScratch[0], pbSrc, pbDst, cbDataUnit );
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
            i += SYMCRYPT_AES_BLOCK_SIZE;
        }
    }

    SymCryptWipeKnownSize( localScratch, sizeof( localScratch ) );
}
#endif

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecrypt(
    _In_                    PCSYMCRYPT_XTS_AES_EXPANDED_KEY pExpandedKey,
                            SIZE_T                          cbDataUnit,
                            UINT64                          tweak,
    _In_reads_( cbData )    PCBYTE                          pbSrc,
    _Out_writes_( cbData )  PBYTE                           pbDst,
                            SIZE_T                          cbData )
{
#if SYMCRYPT_CPU_AMD64
    SYMCRYPT_EXTENDED_SAVE_DATA SaveData;
    /* if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_VAES_512_CODE ) ) {
        SymCryptXtsAesDecryptZmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else */
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE ) &&
        SymCryptSaveYmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptXtsAesDecryptYmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
        SymCryptRestoreYmm( &SaveData );
    } else if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) ) {
        SymCryptXtsAesDecryptXmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else {
        SymCryptXtsAesDecryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_X86
    SYMCRYPT_EXTENDED_SAVE_DATA  SaveData;

    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE ) &&
        SymCryptSaveXmm( &SaveData ) == SYMCRYPT_NO_ERROR )
    {
        SymCryptXtsAesDecryptXmm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
        SymCryptRestoreXmm( &SaveData );
    } else {
        SymCryptXtsAesDecryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#elif SYMCRYPT_CPU_ARM
    SymCryptXtsAesDecryptAsm( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
#elif SYMCRYPT_CPU_ARM64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_NEON_AES ) )
    {
        SymCryptXtsAesDecryptNeon( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    } else {
        SymCryptXtsAesDecryptC( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
    }
#else
    SymCryptXtsAesDecryptC( pExpandedKey, cbDataUnit, tweak, pbSrc, pbDst, cbData );
#endif
}

VOID
SYMCRYPT_CALL
SymCryptXtsUpdateTweak(
    _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE)    PBYTE   buf )
{
/*
    UINT32 b0 = LOAD_LSBFIRST32( buf      );
    UINT32 b1 = LOAD_LSBFIRST32( buf +  4 );
    UINT32 b2 = LOAD_LSBFIRST32( buf +  8 );
    UINT32 b3 = LOAD_LSBFIRST32( buf + 12 );
    UINT32 msbit = b3 >> 31;

    //
    // The STORE_* macros re-evaluate their arguments sometimes, so we
    // keep all computations in local variables.
    //
    UINT32 r0 = (b0 << 1) ^ (135 * msbit);
    UINT32 r1 = (b1 << 1) | (b0 >> 31);
    UINT32 r2 = (b2 << 1) | (b1 >> 31);
    UINT32 r3 = (b3 << 1) | (b2 >> 31);

    STORE_LSBFIRST32( buf     , r0 );
    STORE_LSBFIRST32( buf +  4, r1 );
    STORE_LSBFIRST32( buf +  8, r2 );
    STORE_LSBFIRST32( buf + 12, r3 );
*/
    UINT64 b0 = SYMCRYPT_LOAD_LSBFIRST64( buf     );
    UINT64 b1 = SYMCRYPT_LOAD_LSBFIRST64( buf + 8 );

    /*
    UINT32 msbit = (UINT32)(b1 >> 63);
    //UINT32 feedback = 135 * msbit;
    UINT32 feedback = (msbit << 7) + (msbit << 3) - msbit;
    */
    UINT32 feedback = (((INT64)b1) >> 63) & 135;

    UINT64 r0 = (b0 << 1) ^ feedback;
    UINT64 r1 = (b1 << 1) | (b0 >> 63);

    SYMCRYPT_STORE_LSBFIRST64( buf    , r0 );
    SYMCRYPT_STORE_LSBFIRST64( buf + 8, r1 );
}

VOID
SYMCRYPT_CALL
SymCryptXtsEncryptDataUnit(
    _In_                                        PCSYMCRYPT_BLOCKCIPHER      pBlockCipher,
    _In_                                        PCVOID                      pExpandedKey,
    _Inout_updates_( pBlockCipher->blockSize )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    BYTE    buf[SYMCRYPT_AES_BLOCK_SIZE];

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXorBytes( pbTweakBlock, pbSrc, buf, SYMCRYPT_AES_BLOCK_SIZE );
        (*pBlockCipher->encryptFunc)( pExpandedKey, buf, buf );
        SymCryptXorBytes( pbTweakBlock, buf, pbDst, SYMCRYPT_AES_BLOCK_SIZE );

        SYMCRYPT_ASSERT( pBlockCipher->blockSize == SYMCRYPT_AES_BLOCK_SIZE );
        SymCryptXtsUpdateTweak( pbTweakBlock );

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsDecryptDataUnit(
    _In_                                        PCSYMCRYPT_BLOCKCIPHER      pBlockCipher,
    _In_                                        PCVOID                      pExpandedKey,
    _Inout_updates_( pBlockCipher->blockSize )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    BYTE    buf[SYMCRYPT_AES_BLOCK_SIZE];

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXorBytes( pbTweakBlock, pbSrc, buf, SYMCRYPT_AES_BLOCK_SIZE );
        (*pBlockCipher->decryptFunc)( pExpandedKey, buf, buf );
        SymCryptXorBytes( pbTweakBlock, buf, pbDst, SYMCRYPT_AES_BLOCK_SIZE );

        SYMCRYPT_ASSERT( pBlockCipher->blockSize == SYMCRYPT_AES_BLOCK_SIZE );
        SymCryptXtsUpdateTweak( pbTweakBlock );

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE ); // keep Prefast happy
    SymCryptXtsEncryptDataUnit(
            &SymCryptAesBlockCipherNoOpt,
            pExpandedKey,
            pbTweakBlock,
            pbSrc,
            pbDst,
            cbData );
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE ); // keep Prefast happy
    SymCryptXtsDecryptDataUnit(
            &SymCryptAesBlockCipherNoOpt,
            pExpandedKey,
            pbTweakBlock,
            pbSrc,
            pbDst,
            cbData );
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    // No special optimizations...
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE ); // keep Prefast happy
    SymCryptXtsEncryptDataUnit(
        &SymCryptAesBlockCipherNoOpt,
        pExpandedKey,
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData );
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    SYMCRYPT_ASSERT( SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE ); // keep Prefast happy
    SymCryptXtsDecryptDataUnit(
        &SymCryptAesBlockCipherNoOpt,
        pExpandedKey,
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData );

}

static const BYTE SymCryptXtsAesCiphertext[32] = {
    0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec,
    0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd, 0xa6, 0x92,
    0xcd, 0x43, 0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85,
    0x8c, 0x02, 0xc2, 0x65, 0x2f, 0xbf, 0x92, 0x2e,
};

VOID
SYMCRYPT_CALL
SymCryptXtsAesSelftest()
{
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
    BYTE buf[32];
    BYTE zero[sizeof( buf ) ];

    SymCryptWipeKnownSize( buf, sizeof( buf ) );

    SymCryptXtsAesExpandKey( &key, buf, sizeof( buf ) );

    SymCryptXtsAesEncrypt( &key, sizeof( buf ), 0, buf, buf, sizeof( buf ) );

    SymCryptInjectError( buf, sizeof( buf ) );
    if( memcmp( buf, SymCryptXtsAesCiphertext, sizeof( buf ) ) != 0 )
    {
        SymCryptFatal( 'xtsa' );
    }

    SymCryptXtsAesDecrypt( &key, sizeof( buf ), 0, buf, buf, sizeof( buf ) );

    SymCryptInjectError( buf, sizeof( buf ) );

    SymCryptWipeKnownSize( zero, sizeof( zero ) );
    if( memcmp( buf, zero, sizeof( buf ) ) != 0 )
    {
        SymCryptFatal( 'xtsa' );
    }
}

