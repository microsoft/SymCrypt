//
// Sha3.c
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

//
// See the symcrypt.h file for documentation on what the various functions do.
//


//
// Keccak state
// 
// Keccak-f[1600] state consists of 25 64-bit words. We represent this state as a single
// dimensional array of 25 elements (Wi being the i^th element of the array for i=0..24) 
// with the following mapping to two dimensional coordinates. Note that in FIPS 202 Figure 2,
// the element W0 at (x,y)=(0,0) is depicted in the middle of the 5x5 array. We set W0
// to be the first element so that the rate part of the permutation maps to the beginning
// of the state.
//
//       x=0  x=1  x=2  x=3  x=4
//       -----------------------
// y=0    W0   W1   W2   W3   W4
// y=1    W5   W6   W7   W8   W9
// y=2   W10  W11  W12  W13  W14
// y=3   W15  W16  W17  W18  W19
// y=4   W20  W21  W22  W23  W24



// Rotation constants for Keccak Rho transformation
static const UINT8 KeccakRhoK[25] = {
     0,  1, 62, 28, 27,     // y = 0
    36, 44,  6, 55, 20,     // y = 1
     3, 10, 43, 25, 39,     // y = 2
    41, 45, 15, 21,  8,     // y = 3
    18,  2, 61, 56, 14,     // y = 4
};

// Keccak round constants
static UINT64 KeccakIotaK[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// XOR sum of column c of the state
#define KECCAK_COLUMN_SUM(state, c) \
    (state[0 + (c)] ^ state[5 + (c)] ^ state[10 + (c)] ^ state[15 + (c)] ^ state[20 + (c)])

// XOR w to all the lanes in column c of the state
// 
// Note: The expression to be XORed is copied to a temporary variable to avoid reevaluation
#define KECCAK_COLUMN_UPDATE(state, c, w) { \
    UINT64 t = (w); \
    state[ 0 + (c)] ^= t; \
    state[ 5 + (c)] ^= t; \
    state[10 + (c)] ^= t; \
    state[15 + (c)] ^= t; \
    state[20 + (c)] ^= t; \
}

// Apply Theta transformation to the state
#define KECCAK_THETA(state) { \
    UINT64 colSum[5]; \
    colSum[0] = KECCAK_COLUMN_SUM(state, 0); \
    colSum[1] = KECCAK_COLUMN_SUM(state, 1); \
    colSum[2] = KECCAK_COLUMN_SUM(state, 2); \
    colSum[3] = KECCAK_COLUMN_SUM(state, 3); \
    colSum[4] = KECCAK_COLUMN_SUM(state, 4); \
    KECCAK_COLUMN_UPDATE(state, 0, colSum[4] ^ ROL64(colSum[1], 1)); \
    KECCAK_COLUMN_UPDATE(state, 1, colSum[0] ^ ROL64(colSum[2], 1)); \
    KECCAK_COLUMN_UPDATE(state, 2, colSum[1] ^ ROL64(colSum[3], 1)); \
    KECCAK_COLUMN_UPDATE(state, 3, colSum[2] ^ ROL64(colSum[4], 1)); \
    KECCAK_COLUMN_UPDATE(state, 4, colSum[3] ^ ROL64(colSum[0], 1)); \
}

// Apply Rho transformation to row r of the state
#define KECCAK_RHO_ROW(state, r) { \
    state[5 * (r) + 0] = ROL64(state[5 * (r) + 0], KeccakRhoK[5 * (r) + 0]); \
    state[5 * (r) + 1] = ROL64(state[5 * (r) + 1], KeccakRhoK[5 * (r) + 1]); \
    state[5 * (r) + 2] = ROL64(state[5 * (r) + 2], KeccakRhoK[5 * (r) + 2]); \
    state[5 * (r) + 3] = ROL64(state[5 * (r) + 3], KeccakRhoK[5 * (r) + 3]); \
    state[5 * (r) + 4] = ROL64(state[5 * (r) + 4], KeccakRhoK[5 * (r) + 4]); \
}

// Apply Rho transformation to row 0 of the state
// 
// The first row contains a rotation by 0 on the first lane that uses a shift 
// by 64 which we want to avoid. Rho operation below omits the rotation on the first lane.
#define KECCAK_RHO_ROW0(state) { \
    state[1] = ROL64(state[1], KeccakRhoK[1]); \
    state[2] = ROL64(state[2], KeccakRhoK[2]); \
    state[3] = ROL64(state[3], KeccakRhoK[3]); \
    state[4] = ROL64(state[4], KeccakRhoK[4]); \
}

// Apply Rho transformation to the state
#define KECCAK_RHO(state) { \
    KECCAK_RHO_ROW0(state); \
    KECCAK_RHO_ROW(state, 1); \
    KECCAK_RHO_ROW(state, 2); \
    KECCAK_RHO_ROW(state, 3); \
    KECCAK_RHO_ROW(state, 4); \
}

// Apply Pi transformation to the state
#define KECCAK_PI(state) { \
    UINT64 t  = state[ 1]; state[ 1] = state[ 6]; state[ 6] = state[ 9]; state[ 9] = state[22]; state[22] = state[14]; \
    state[14] = state[20]; state[20] = state[ 2]; state[ 2] = state[12]; state[12] = state[13]; state[13] = state[19]; \
    state[19] = state[23]; state[23] = state[15]; state[15] = state[ 4]; state[ 4] = state[24]; state[24] = state[21]; \
    state[21] = state[ 8]; state[ 8] = state[16]; state[16] = state[ 5]; state[ 5] = state[ 3]; state[ 3] = state[18]; \
    state[18] = state[17]; state[17] = state[11]; state[11] = state[ 7]; state[ 7] = state[10]; state[10] = t; \
}

// Apply Chi transformation on row r of state
#define KECCAK_CHI_ROW(state, r) { \
    UINT64 t1 = state[5 * (r) + 0] ^ (~state[5 * (r) + 1] & state[5 * (r) + 2]); \
    UINT64 t2 = state[5 * (r) + 1] ^ (~state[5 * (r) + 2] & state[5 * (r) + 3]); \
    state[5 * (r) + 2] = state[5 * (r) + 2] ^ (~state[5 * (r) + 3] & state[5 * (r) + 4]); \
    state[5 * (r) + 3] = state[5 * (r) + 3] ^ (~state[5 * (r) + 4] & state[5 * (r) + 0]); \
    state[5 * (r) + 4] = state[5 * (r) + 4] ^ (~state[5 * (r) + 0] & state[5 * (r) + 1]); \
    state[5 * (r) + 0] = t1; \
    state[5 * (r) + 1] = t2; \
}

// Apply Chi transformation to state
#define KECCAK_CHI(state) { \
    KECCAK_CHI_ROW(state, 0); \
    KECCAK_CHI_ROW(state, 1); \
    KECCAK_CHI_ROW(state, 2); \
    KECCAK_CHI_ROW(state, 3); \
    KECCAK_CHI_ROW(state, 4); \
}

// Add round constant to state
#define KECCAK_IOTA(state, rnd) state[0] ^= KeccakIotaK[rnd]

// Perform one round of Keccak permutation on state
#define KECCAK_PERM_ROUND(state, rnd) { \
    KECCAK_THETA(state); \
    KECCAK_RHO(state); \
    KECCAK_PI(state); \
    KECCAK_CHI(state); \
    KECCAK_IOTA(state, rnd); \
}


//
// SymCryptKeccakPermute
//
VOID
SYMCRYPT_CALL
SymCryptKeccakPermute(_Inout_updates_(25) UINT64* pState)
{
    for (int r = 0; r < 24; r++)
    {
        KECCAK_PERM_ROUND(pState, r);
    }
}


//
// SymCryptSha3Init
//
SYMCRYPT_NOINLINE
VOID
SYMCRYPT_CALL
SymCryptSha3Init(_Out_ PSYMCRYPT_SHA3_STATE pState, UINT32 uOutputBits)
{
    SYMCRYPT_ASSERT(uOutputBits == 256 || uOutputBits == 384 || uOutputBits == 512);

    SYMCRYPT_SET_MAGIC(pState);

    pState->resultSize = uOutputBits / 8;
    pState->inputBlockSize = (UINT32)(200 - (2 * pState->resultSize));    // rate = state - capacity, capacity = 2 * resultSize
    pState->mergedBytes = 0;

    SymCryptWipeKnownSize(pState->state, sizeof(pState->state));
}


//
// SymCryptSha3Append
//
SYMCRYPT_NOINLINE
VOID
SYMCRYPT_CALL
SymCryptSha3Append(
    _Inout_                 PSYMCRYPT_SHA3_STATE    pState,
    _In_reads_(cbData)      PCBYTE                  pbData,
                            SIZE_T                  cbData)
{
    PBYTE   pbState = (PBYTE)pState->state;
    SIZE_T  cbFree = pState->inputBlockSize - pState->mergedBytes;

    // If there are already merged bytes and appended bytes fill one block,
    // consume them here.
    if (pState->mergedBytes > 0 && cbData >= cbFree)
    {
        for (SIZE_T i = 0; i < cbFree; i++)
        {
            pbState[pState->mergedBytes + i] ^= pbData[i];
        }

        pbData += cbFree;
        cbData -= cbFree;
        pState->mergedBytes = 0;

        SymCryptKeccakPermute(pState->state);
    }

    // Process full blocks
    while (cbData >= pState->inputBlockSize)
    {
        // Absorb
        for (SIZE_T i = 0; i < pState->inputBlockSize / sizeof(UINT64); i++)
        {
            pState->state[i] ^= SYMCRYPT_LOAD_LSBFIRST64(pbData + i * sizeof(UINT64));
        }

        SymCryptKeccakPermute(pState->state);

        pbData += pState->inputBlockSize;
        cbData -= pState->inputBlockSize;
    }

    SYMCRYPT_ASSERT(cbData < pState->inputBlockSize);

    // Merge remaining bytes if any into the state
    if (cbData > 0)
    {
        for (SIZE_T i = 0; i < cbData; i++)
        {
            pbState[pState->mergedBytes + i] ^= pbData[i];
        }

        pState->mergedBytes += (UINT32)cbData;
    }
}


//
// SymCryptSha3Result
//
SYMCRYPT_NOINLINE
VOID
SYMCRYPT_CALL
SymCryptSha3Result(
    _Inout_                             PSYMCRYPT_SHA3_STATE    pState,
    _Out_writes_(pState->resultSize)    PBYTE                   pbResult)
{
    PBYTE   pbState = (PBYTE)pState->state;

    SYMCRYPT_CHECK_MAGIC(pState);

    // Apply padding:
    // 01 domain separator represents SHA-3 (0x2 in little endian bit ordering)
    // This is immediately followed by first 1 in 10*1 Keccak multi-rate padding giving us 0x06
    pbState[pState->mergedBytes] ^= 0x06;

    // Pad the final 1 bit
    pbState[pState->inputBlockSize - 1] ^= 0x80;

    SymCryptKeccakPermute(pState->state);

    // Squeeze
    for (int i = 0; i < pState->resultSize / sizeof(UINT64); i++)
    {
        SYMCRYPT_STORE_LSBFIRST64(pbResult + i * sizeof(UINT64), pState->state[i]);
    }

    //
    // Wipe & re-initialize
    //
    // We don't have to call the Init function as wiping the Keccak state and
    // setting the mergedBytes to zero has the desired effect. The other state 
    // variables remain unchanged.
    SymCryptWipeKnownSize(pState->state, sizeof(pState->state));
    pState->mergedBytes = 0;
}


//
// SymCryptSha3StateExport
//
VOID
SYMCRYPT_CALL
SymCryptSha3StateExport(
                                                        SYMCRYPT_BLOB_TYPE      type,
    _In_                                                PCSYMCRYPT_SHA3_STATE   pState,
    _Out_writes_bytes_(SYMCRYPT_SHA3_STATE_EXPORT_SIZE) PBYTE                   pbBlob)
{

    SYMCRYPT_ALIGN SYMCRYPT_SHA3_STATE_EXPORT_BLOB    blob;           // local copy to have proper alignment.
    C_ASSERT(sizeof(blob) == SYMCRYPT_SHA3_STATE_EXPORT_SIZE);

    SYMCRYPT_CHECK_MAGIC(pState);

    SymCryptWipeKnownSize(&blob, sizeof(blob)); // wipe to avoid any data leakage

    blob.header.magic = SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_SHA3_STATE_EXPORT_SIZE;
    blob.header.type = type;

    //
    // Copy the relevant data. Buffer will be 0-padded.
    //

    SymCryptUint64ToMsbFirst(&pState->state[0], &blob.state[0], 25);
    blob.mergedBytes = pState->mergedBytes;

    SYMCRYPT_ASSERT((PCBYTE)&blob + sizeof(blob) - sizeof(SYMCRYPT_BLOB_TRAILER) == (PCBYTE)&blob.trailer);
    SymCryptMarvin32(SymCryptMarvin32DefaultSeed, (PCBYTE)&blob, sizeof(blob) - sizeof(SYMCRYPT_BLOB_TRAILER), &blob.trailer.checksum[0]);

    memcpy(pbBlob, &blob, sizeof(blob));

    SymCryptWipeKnownSize(&blob, sizeof(blob));
    return;
}


//
// SymCryptSha3StateImport
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSha3StateImport(
                                                        SYMCRYPT_BLOB_TYPE      type,
    _Out_                                               PSYMCRYPT_SHA3_STATE    pState,
    _In_reads_bytes_(SYMCRYPT_SHA3_STATE_EXPORT_SIZE)   PCBYTE                  pbBlob)
{
    SYMCRYPT_ERROR                  scError = SYMCRYPT_NO_ERROR;

    SYMCRYPT_ALIGN SYMCRYPT_SHA3_STATE_EXPORT_BLOB blob;                       // local copy to have proper alignment.
    BYTE checksum[8];

    C_ASSERT(sizeof(blob) == SYMCRYPT_SHA3_STATE_EXPORT_SIZE);
    memcpy(&blob, pbBlob, sizeof(blob));

    if (blob.header.magic != SYMCRYPT_BLOB_MAGIC ||
        blob.header.size != SYMCRYPT_SHA3_STATE_EXPORT_SIZE ||
        blob.header.type != (UINT32)type)
    {
        scError = SYMCRYPT_INVALID_BLOB;
        goto cleanup;
    }

    SymCryptMarvin32(SymCryptMarvin32DefaultSeed, (PCBYTE)&blob, sizeof(blob) - sizeof(SYMCRYPT_BLOB_TRAILER), checksum);
    if (memcmp(checksum, &blob.trailer.checksum[0], 8) != 0)
    {
        scError = SYMCRYPT_INVALID_BLOB;
        goto cleanup;
    }

    SymCryptMsbFirstToUint64(&blob.state[0], &pState->state[0], 25);
    pState->mergedBytes = blob.mergedBytes;

    if (type == SymCryptBlobTypeSha3_256State)
    {
        pState->inputBlockSize = SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE;
        pState->resultSize = SYMCRYPT_SHA3_256_RESULT_SIZE;
    }
    else if (type == SymCryptBlobTypeSha3_384State)
    {
        pState->inputBlockSize = SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE;
        pState->resultSize = SYMCRYPT_SHA3_384_RESULT_SIZE;
    }
    else if (type == SymCryptBlobTypeSha3_512State)
    {
        pState->inputBlockSize = SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE;
        pState->resultSize = SYMCRYPT_SHA3_512_RESULT_SIZE;
    }

    SYMCRYPT_SET_MAGIC(pState);

cleanup:
    SymCryptWipeKnownSize(&blob, sizeof(blob));

    return scError;
}
