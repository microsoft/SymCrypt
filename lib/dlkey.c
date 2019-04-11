//
// dlkey.c   Dlkey functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
//

#include "precomp.h"

PSYMCRYPT_DLKEY
SYMCRYPT_CALL
SymCryptDlkeyAllocate( _In_ PCSYMCRYPT_DLGROUP pDlgroup )
{
    PVOID               p;
    SIZE_T              cb;
    PSYMCRYPT_DLKEY     res = NULL;

    cb = SymCryptSizeofDlkeyFromDlgroup( pDlgroup );

    p = SymCryptCallbackAlloc( cb );

    if ( p==NULL )
    {
        goto cleanup;
    }

    res = SymCryptDlkeyCreate( p, cb, pDlgroup );

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptDlkeyFree( _Out_ PSYMCRYPT_DLKEY pkObj )
{
    SYMCRYPT_CHECK_MAGIC( pkObj );
    SymCryptDlkeyWipe( pkObj );
    SymCryptCallbackFree( pkObj );
}

UINT32
SYMCRYPT_CALL
SymCryptSizeofDlkeyFromDlgroup( _In_ PCSYMCRYPT_DLGROUP pDlgroup )
{
    // Always allocate memory for large private keys
    return sizeof(SYMCRYPT_DLKEY) + SymCryptSizeofModElementFromModulus( pDlgroup->pmP ) + SymCryptSizeofIntFromDigits( pDlgroup->nDigitsOfP );
}

PSYMCRYPT_DLKEY
SYMCRYPT_CALL
SymCryptDlkeyCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer,
                                    SIZE_T              cbBuffer,
    _In_                            PCSYMCRYPT_DLGROUP  pDlgroup )
{
    PSYMCRYPT_DLKEY pkRes = NULL;
    UINT32 cbModElement = 0;

    UNREFERENCED_PARAMETER( cbBuffer );     // only referenced in an ASSERT...
    SYMCRYPT_ASSERT( cbBuffer >=  SymCryptSizeofDlkeyFromDlgroup( pDlgroup ) );

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );

    pkRes = (PSYMCRYPT_DLKEY) pbBuffer;

    // DLKEY parameters
    pkRes->pDlgroup = pDlgroup;
    pkRes->fHasPrivateKey = FALSE;
    pkRes->fPrivateModQ = FALSE;            // This will be properly set during generate or setvalue

    // Create SymCrypt objects
    pbBuffer += sizeof(SYMCRYPT_DLKEY);

    cbModElement = SymCryptSizeofModElementFromModulus( pDlgroup->pmP );
    pkRes->pePublicKey = SymCryptModElementCreate( pbBuffer, cbModElement, pDlgroup->pmP );
    if (pkRes->pePublicKey == NULL)
    {
        goto cleanup;
    }
    pbBuffer += cbModElement;

    //
    // **** Always defer the creation of the private key until the key generation or
    // set value.
    //
    // In place of the pbPrivate pointer store the pointer to the allocated buffer.
    //
    pkRes->pbPrivate = pbBuffer;
    pkRes->piPrivateKey = NULL;

    // Setting the magic
    SYMCRYPT_SET_MAGIC( pkRes );

cleanup:
    return pkRes;
}

VOID
SYMCRYPT_CALL
SymCryptDlkeyWipe( _Out_ PSYMCRYPT_DLKEY pkDst )
{
    SymCryptWipe( (PBYTE) pkDst, SymCryptSizeofDlkeyFromDlgroup(pkDst->pDlgroup) );
}

VOID
SYMCRYPT_CALL
SymCryptDlkeyCopy(
    _In_    PCSYMCRYPT_DLKEY   pkSrc,
    _Out_   PSYMCRYPT_DLKEY    pkDst )
{
    PCSYMCRYPT_DLGROUP pDlgroup = pkSrc->pDlgroup;

    //
    // in-place copy is somewhat common...
    //
    if( pkSrc != pkDst )
    {
        pkDst->fHasPrivateKey = pkSrc->fHasPrivateKey;
        pkDst->fPrivateModQ = pkSrc->fPrivateModQ;

        // Copy the public key
        SymCryptModElementCopy( pDlgroup->pmP, pkSrc->pePublicKey, pkDst->pePublicKey );

        // Copy the private key
        SymCryptIntCopy( pkSrc->piPrivateKey, pkDst->piPrivateKey );
    }
}


// DLKEY specific functions

PCSYMCRYPT_DLGROUP
SYMCRYPT_CALL
SymCryptDlkeyGetGroup( _In_ PCSYMCRYPT_DLKEY pkDlkey )
{
    return pkDlkey->pDlgroup;
}

UINT32
SYMCRYPT_CALL
SymCryptDlkeySizeofPublicKey( _In_ PCSYMCRYPT_DLKEY pkDlkey )
{
    return pkDlkey->pDlgroup->cbPrimeP;
}

UINT32
SYMCRYPT_CALL
SymCryptDlkeySizeofPrivateKey( _In_ PCSYMCRYPT_DLKEY pkDlkey )
{
    PCSYMCRYPT_DLGROUP pDlgroup = pkDlkey->pDlgroup;

    if (pkDlkey->fPrivateModQ)
    {
        if (pDlgroup->fHasPrimeQ)
        {
            return pDlgroup->cbPrimeQ;
        }
        else
        {
            return pDlgroup->cbPrimeP;  // Somehow the group has no prime Q but the key was set with prime Q, return the safe option
        }
    }
    else
    {
        return pDlgroup->cbPrimeP;
    }
}

BOOLEAN
SYMCRYPT_CALL
SymCryptDlkeyHasPrivateKey( _In_ PCSYMCRYPT_DLKEY pkDlkey )
{
    return pkDlkey->fHasPrivateKey;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptDlkeyGenerate(
    _In_  UINT32                     flags,
    _Out_ PSYMCRYPT_DLKEY            pkDlkey )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE pbScratch = NULL;
    SIZE_T cbScratch = 0;
    PBYTE pbScratchInternal = NULL;
    SIZE_T cbScratchInternal = 0;

    PCSYMCRYPT_DLGROUP pDlgroup = pkDlkey->pDlgroup;

    PSYMCRYPT_MODELEMENT pePrivateKey = NULL;
    UINT32 cbPrivateKey = 0;

    PSYMCRYPT_MODULUS pmPriv = NULL;
    UINT32 nDigitsPriv = 0;
    UINT32 nBitsPriv = 0;
    UINT32 fFlagsForModSetRandom = 0;

    // Check that only the verify flag is specified
    if ((flags & ~SYMCRYPT_FLAG_DLKEY_GEN_MODP)!=0)
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    pkDlkey->fPrivateModQ = (((flags & SYMCRYPT_FLAG_DLKEY_GEN_MODP)==0) && (pDlgroup->fHasPrimeQ));

    if (pkDlkey->fPrivateModQ)
    {
        pmPriv = pDlgroup->pmQ;
        nDigitsPriv = pDlgroup->nDigitsOfQ;
        nBitsPriv = pDlgroup->nBitsOfQ;
        fFlagsForModSetRandom = SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE;     // 1 to Q-1
    }
    else
    {
        pmPriv = pDlgroup->pmP;
        nDigitsPriv = pDlgroup->nDigitsOfP;
        nBitsPriv = pDlgroup->nBitsOfP;
        fFlagsForModSetRandom = SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE;                                              // 1 to P-2
    }

    cbPrivateKey = SymCryptSizeofModElementFromModulus( pmPriv );

    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    //
    cbScratch = cbPrivateKey +
                max(SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsPriv),
                    SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup->nDigitsOfP));
    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if (pbScratch == NULL)
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    // Create the private key modelement
    pePrivateKey = SymCryptModElementCreate( pbScratch, cbPrivateKey, pmPriv );
    pbScratchInternal = pbScratch + cbPrivateKey;
    cbScratchInternal = cbScratch - cbPrivateKey;

    // Create the private key integer
    pkDlkey->piPrivateKey = SymCryptIntCreate( pkDlkey->pbPrivate, SymCryptSizeofIntFromDigits(nDigitsPriv), nDigitsPriv );

    // Set a modelement from 1 to q-1 (or 1 to p-2)
    SymCryptModSetRandom(
        pmPriv,
        pePrivateKey,
        fFlagsForModSetRandom,
        pbScratchInternal,
        cbScratchInternal );

    // Set the private key
    SymCryptModElementToInt(
        pmPriv,
        pePrivateKey,
        pkDlkey->piPrivateKey,
        pbScratchInternal,
        cbScratchInternal );

    // Calculate the public key
    SymCryptModExp(
        pDlgroup->pmP,
        pDlgroup->peG,
        pkDlkey->piPrivateKey,
        nBitsPriv,
        0,      // Side-channel safe
        pkDlkey->pePublicKey,
        pbScratchInternal,
        cbScratchInternal );

    // Set the fHasPrivateKey flag
    pkDlkey->fHasPrivateKey = TRUE;

cleanup:
    if (pbScratch!=NULL)
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }
    return scError;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptDlkeySetValue(
    _In_reads_bytes_( cbPrivateKey )    PCBYTE                  pbPrivateKey,
                                        SIZE_T                  cbPrivateKey,
    _In_reads_bytes_( cbPublicKey )     PCBYTE                  pbPublicKey,
                                        SIZE_T                  cbPublicKey,
                                        SYMCRYPT_NUMBER_FORMAT  numFormat,
                                        UINT32                  flags,
    _Out_                               PSYMCRYPT_DLKEY         pkDlkey )
{
    SYMCRYPT_ERROR      scError = SYMCRYPT_NO_ERROR;
    PBYTE               pbScratch = NULL;
    UINT32              cbScratch = 0;
    PBYTE               pbScratchInternal = NULL;
    UINT32              cbScratchInternal = 0;

    PCSYMCRYPT_DLGROUP pDlgroup = pkDlkey->pDlgroup;

    PSYMCRYPT_MODULUS pmPriv = NULL;
    UINT32 nDigitsPriv = 0;
    UINT32 nBitsPriv = 0;

    PSYMCRYPT_MODELEMENT peTmp = NULL;
    UINT32 cbModElement = SymCryptSizeofModElementFromModulus( pDlgroup->pmP );

    if ( ((pbPrivateKey==NULL) && (cbPrivateKey!=0)) ||
         ((pbPublicKey==NULL) && (cbPublicKey!=0)) ||
         ((pbPrivateKey==NULL) && (pbPublicKey==NULL)) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Check that only the verify flag is specified
    if ((flags & ~SYMCRYPT_FLAG_DLKEY_VERIFY)!=0)
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    //
    cbScratch = max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup->nDigitsOfP),
                     cbModElement + SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup->nDigitsOfP) );
    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if (pbScratch == NULL)
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    if (pbPrivateKey != NULL)
    {
        //
        // Check the size of the imported private key to detect if it is mod P or mod Q
        // If the group does not have a Q assume that the imported key is modulo P as
        // it wouldn't help us assume otherwise (the bitsize of the private key should be kept
        // secret from SC attacks).
        //
        pkDlkey->fPrivateModQ = ((pDlgroup->fHasPrimeQ) && (cbPrivateKey <= pDlgroup->cbPrimeQ));

        if (pkDlkey->fPrivateModQ)
        {
            pmPriv = pDlgroup->pmQ;
            nDigitsPriv = pDlgroup->nDigitsOfQ;
            nBitsPriv = pDlgroup->nBitsOfQ;
        }
        else
        {
            pmPriv = pDlgroup->pmP;
            nDigitsPriv = pDlgroup->nDigitsOfP;
            nBitsPriv = pDlgroup->nBitsOfP;
        }

        pkDlkey->piPrivateKey = SymCryptIntCreate( pkDlkey->pbPrivate, SymCryptSizeofIntFromDigits(nDigitsPriv), nDigitsPriv );

        scError = SymCryptIntSetValue(
                        pbPrivateKey,
                        cbPrivateKey,
                        numFormat,
                        pkDlkey->piPrivateKey );
        if (scError!=SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }

        pkDlkey->fHasPrivateKey = TRUE;
    }

    if (pbPublicKey != NULL)
    {
        scError = SymCryptModElementSetValue(
                        pbPublicKey,
                        cbPublicKey,
                        numFormat,
                        pDlgroup->pmP,
                        pkDlkey->pePublicKey,
                        pbScratch,
                        cbScratch );
        if (scError!=SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }
    }


    // Calculating the public key if no key was provided
    // and verifying if needed
    if ( (pbPublicKey==NULL) ||
         (((flags&SYMCRYPT_FLAG_DLKEY_VERIFY)!=0) && (pbPrivateKey!=NULL) && (pbPublicKey!=NULL))
        )
    {
        pbScratchInternal = pbScratch;
        cbScratchInternal = cbScratch;

        // Calculate the public key from the private key
        peTmp = SymCryptModElementCreate( pbScratchInternal, cbModElement, pDlgroup->pmP);
        pbScratchInternal += cbModElement;
        cbScratchInternal -= cbModElement;

        SymCryptModExp(
                pDlgroup->pmP,
                pDlgroup->peG,
                pkDlkey->piPrivateKey,
                nBitsPriv,  // This is either bits of P or of Q i.e. public values
                0,          // Side-channel safe
                peTmp,
                pbScratchInternal,
                cbScratchInternal );

        if (pbPublicKey!=NULL)
        {
            if (!SymCryptModElementIsEqual(pDlgroup->pmP, peTmp, pkDlkey->pePublicKey))
            {
                scError = SYMCRYPT_AUTHENTICATION_FAILURE;
                goto cleanup;
            }
        }

        SymCryptModElementCopy(pDlgroup->pmP, peTmp, pkDlkey->pePublicKey);
    }

cleanup:
    if (pbScratch!=NULL)
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }
    return scError;
}


_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptDlkeyGetValue(
    _In_    PCSYMCRYPT_DLKEY        pkDlkey,
    _Out_writes_bytes_( cbPrivateKey )
            PBYTE                   pbPrivateKey,
            SIZE_T                  cbPrivateKey,
    _Out_writes_bytes_( cbPublicKey )
            PBYTE                   pbPublicKey,
            SIZE_T                  cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT  numFormat,
            UINT32                  flags )
{
    SYMCRYPT_ERROR      scError = SYMCRYPT_NO_ERROR;
    PBYTE               pbScratch = NULL;
    UINT32              cbScratch = 0;

    PCSYMCRYPT_DLGROUP pDlgroup = pkDlkey->pDlgroup;

    UNREFERENCED_PARAMETER( flags );

    if ( ((pbPrivateKey==NULL) && (cbPrivateKey!=0)) ||
         ((pbPublicKey==NULL) && (cbPublicKey!=0)) ||
         ((pbPrivateKey==NULL) && (pbPublicKey==NULL)) ||
         ((pbPrivateKey!=NULL) && !pkDlkey->fHasPrivateKey) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if (pbPrivateKey != NULL)
    {
        scError = SymCryptIntGetValue(
                        pkDlkey->piPrivateKey,
                        pbPrivateKey,
                        cbPrivateKey,
                        numFormat );
        if (scError!=SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }
    }

    if (pbPublicKey != NULL)
    {
        cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup->nDigitsOfP);
        pbScratch = SymCryptCallbackAlloc( cbScratch );
        if (pbScratch == NULL)
        {
            scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
            goto cleanup;
        }

        scError = SymCryptModElementGetValue(
                        pDlgroup->pmP,
                        pkDlkey->pePublicKey,
                        pbPublicKey,
                        cbPublicKey,
                        numFormat,
                        pbScratch,
                        cbScratch );
        if (scError!=SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }
    }

cleanup:
    if (pbScratch!=NULL)
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }
    return scError;
}