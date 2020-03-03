//
// testInterop.h    Header file for SymCrypt RSA, DSA, and DH Interop tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "bigpriv.h"
#include "ms_rsa.h"

#include "cryptdsa.h"
#include "cryptdh.h"

#define IMPSC_INDEX             (0)
#define IMPMSBIGNUM_INDEX       (1)
#define IMPCNG_INDEX            (2)

typedef struct _IMPLEMENTATION_DATA {
    char *  name;
    UINT32  index;
} IMPLEMENTATION_DATA;

#define TEST_INTEROP_NUMOF_IMPS         (3)
extern IMPLEMENTATION_DATA g_Implementations[TEST_INTEROP_NUMOF_IMPS];


typedef struct _HASHALG_DATA {
    PCSYMCRYPT_HASH pHashAlgorithm;
    LPCSTR          shortName;
    LPCWSTR         cngName;
    pfnHash         msBignumHashFunc;
} HASHALG_DATA;

#define TEST_INTEROP_NUMOF_HASHALGS     (5)
extern HASHALG_DATA g_HashAlgs[TEST_INTEROP_NUMOF_HASHALGS];

// Helper functions
UINT32 testInteropImplToInd( AlgorithmImplementation * pImpl );

VOID testInteropScToHashContext( PCSYMCRYPT_HASH pHashAlgorithm, PBYTE rgbDigest, hash_function_context* pHashFunCxt);

LPCWSTR testInteropScToCngHash( PSYMCRYPT_HASH pHashAlgorithm );

PCSYMCRYPT_HASH testInteropRandomHash();

LPCSTR testInteropHashAlgToString( PCSYMCRYPT_HASH pHashAlgorithm );

VOID testInteropReverseMemCopy( PBYTE pbDst, PBYTE pbSrc, SIZE_T cbSrc );

//
// Algorithm implementations
//

// Function for randomizing inputs of algorithms
typedef VOID (*InteropRandFn )(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T*         pcbBufferA,
            PBYTE           pbBufferB,
            SIZE_T*         pcbBufferB,
            PBYTE           pbBufferC,
            SIZE_T*         pcbBufferC,
            PCSYMCRYPT_HASH* ppHashAlgorithm );

// Encryption / Decryption / Signing / Verify / Secret agreement
typedef VOID (*InteropDataFn )(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm );

// FunctionalInteropImplementation class is only used for functional tests of RSA
class FunctionalInteropImplementation: public AlgorithmImplementation
{
public:
    FunctionalInteropImplementation() {};
    virtual ~FunctionalInteropImplementation() {};

private:
    FunctionalInteropImplementation( const FunctionalInteropImplementation & );
    VOID operator=( const FunctionalInteropImplementation & );

public:
    InteropRandFn   m_RandFunction;

    InteropDataFn   m_QueryFunction;
    InteropDataFn   m_ReplyFunction;
};

// FunctionalInteropImp class is the template class of FunctionalInteropImplementation
template< class Implementation, class Algorithm>
class FunctionalInteropImp: public FunctionalInteropImplementation
{
public:
    FunctionalInteropImp();
    virtual ~FunctionalInteropImp();

private:
    FunctionalInteropImp( const FunctionalInteropImp & );
    VOID operator=( const FunctionalInteropImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};

template< class Implementation, class Algorithm>
const String FunctionalInteropImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String FunctionalInteropImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String FunctionalInteropImp<Implementation, Algorithm>::s_modeName;

//
// Interop functions
//

// Function that generates random key(s) on one implementation and stores them into a key entry
template< class Implementation > VOID algImpTestInteropGenerateKeyEntry(PBYTE pKeyEntry);

// Function that fills the key entry buffers with the group/key material
template< class Implementation > VOID algImpTestInteropFillKeyEntryBuffers(PBYTE pKeyEntry);

// Function that creates the keys on one implementation from the key entry buffers
template< class Implementation > VOID algImpTestInteropImportKeyEntryBuffers(PBYTE pKeyEntry);

// Function that cleans the key entry on one implementation (by deallocating memory etc.)
template< class Implementation > VOID algImpTestInteropCleanKeyEntry(PBYTE pKeyEntry);

template< class Implementation, class Algorithm >
VOID algImpTestInteropRandFunction(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T*         pcbBufferA,
            PBYTE           pbBufferB,
            SIZE_T*         pcbBufferB,
            PBYTE           pbBufferC,
            SIZE_T*         pcbBufferC,
            PCSYMCRYPT_HASH* ppHashAlgorithm );

template< class Implementation, class Algorithm >
VOID algImpTestInteropQueryFunction(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm );

template< class Implementation, class Algorithm >
VOID algImpTestInteropReplyFunction(
            PBYTE           pKeyEntry,
            PBYTE           pbBufferA,
            SIZE_T          cbBufferA,
            PBYTE           pbBufferB,
            SIZE_T          cbBufferB,
            PBYTE           pbBufferC,
            SIZE_T          cbBufferC,
            PCSYMCRYPT_HASH pHashAlgorithm );

// DL GROUPS - DSA - DH
#define TEST_DL_MAX_NUMOF_BITS          (2048)
#define TEST_DL_MAX_NUMOF_BYTES         (TEST_DL_MAX_NUMOF_BITS/8)

typedef struct {
    UINT32  nBitsOfP;
    UINT32  nBitsOfQ;
} TEST_DL_BITSIZEENTRY, * PTEST_DL_BITSIZEENTRY;

typedef struct {
    UINT32          nBitsOfP;
    UINT32          cbPrimeP;

    UINT32          nBitsOfQ;
    UINT32          cbPrimeQ;

    UINT32          nBitsOfQSet;                            // This can be 0 if initialized by 0 (SymCrypt calls them like this)

    SYMCRYPT_DLGROUP_FIPS
                    eFipsStandard;                          // Specified FIPS standard

    // Buffers of parameters
    BYTE            rbPrimeP[TEST_DL_MAX_NUMOF_BYTES];      // Buffer that holds prime P in MSB_FIRST format (size: cbPrimeP)
    BYTE            rbPrimeQ[TEST_DL_MAX_NUMOF_BYTES];      // Buffer that holds prime Q in MSB_FIRST format (size: cbPrimeQ)
    BYTE            rbGenG[TEST_DL_MAX_NUMOF_BYTES];        // Buffer that holds the generator G in MSB_FIRST format (size: cbPrimeP)

    PCSYMCRYPT_HASH pHashAlgorithm;                         // Hash algorithm used in FIPS generation
    BYTE            rbSeed[TEST_DL_MAX_NUMOF_BYTES];        // Buffer that holds the seed used in FIPS generation (size: cbPrimeQ)
    UINT32          dwGenCounter;                           // Counter used in FIPS generation

    BYTE            rbPublicKeyA[TEST_DL_MAX_NUMOF_BYTES];  // Public part for the DSA key and the first DH key (size: cbPrimeP)
    BYTE            rbPrivateKeyA[TEST_DL_MAX_NUMOF_BYTES]; // Private part for the DSA key and the first DH key (size: cbPrimeQ) (Always of small size)

    BYTE            rbPublicKeyB[TEST_DL_MAX_NUMOF_BYTES];  // Public part for the second DH key (size: cbPrimeP)
    BYTE            rbPrivateKeyB[TEST_DL_MAX_NUMOF_BYTES]; // Private part for the second DH key (size: cbPrivateKeyB) **CNG generates a bigger key
    UINT32          cbPrivateKeyB;                          // See above

    // Pointers to objects
    PBYTE           pGroups[TEST_INTEROP_NUMOF_IMPS];       // Pointers to the DL group structures (only used for SymCrypt)
    PBYTE           pKeysDsa[TEST_INTEROP_NUMOF_IMPS];      // Pointers to the DSA keys
    PBYTE           pKeysDhA[TEST_INTEROP_NUMOF_IMPS];      // Pointers to the first DH keys (**in SymCrypt these are the same pointers as the above)
    PBYTE           pKeysDhB[TEST_INTEROP_NUMOF_IMPS];      // Pointers to the second DH keys

} TEST_DL_KEYENTRY, * PTEST_DL_KEYENTRY;


















