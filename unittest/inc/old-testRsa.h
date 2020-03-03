//
// testRsa.h    Header file for SymCrypt RSA tests 
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "bigpriv.h"
#include "ms_rsa.h"

#define TEST_RSA_MIN_NUMOF_BYTES        (64)    // Cng does not accept less than 512 bits (not even imported keys)
#define TEST_RSA_MAX_NUMOF_BYTES        (256)
#define TEST_RSA_NUMOF_IMPS             (3)     // SymCrypt, MsBignum, Cng
#define TEST_RSA_MIN_NUMOF_PRIME_BITS   (128)   // Minimum size of bits for each prime

typedef struct {
    UINT32  nBitsOfModulus;
    BOOLEAN fUneqSizedPrimes;
} TEST_RSA_BITSIZEENTRY, * PTEST_RSA_BITSIZEENTRY;

//
// Each entry will hold the same key in all implementations
//
typedef struct {
    UINT32  bitSize;
    UINT32  keySize;
    PBYTE   pKeys[TEST_RSA_NUMOF_IMPS];     // Pointers to the RSA keys
} TEST_RSA_KEYENTRY, * PTEST_RSA_KEYENTRY;

// Number of bytes that have to be subtracted from the
// full modulus size to give the available space for the message.
// Exceptions:
//      - For PKCS1 sign we should also subtract the cbHashOIDs size
#define TEST_RSA_PKCS1_ENC_LESS_BYTES           (11)
#define TEST_RSA_OAEP_LESS_BYTES( _hashSize )   (2*(_hashSize) + 2)
#define TEST_RSA_PKCS1_SIGN_LESS_BYTES          (17)
#define TEST_RSA_PSS_LESS_BYTES                 (2)

LPCWSTR testRsaScToCngHash( PSYMCRYPT_HASH pHashAlgorithm );
PSYMCRYPT_HASH testRsaRandomHash();
VOID testRsaGetCngOidList(
    PSYMCRYPT_HASH  pHashAlgorithm,
    PBYTE           pbOut,
    SIZE_T          cbOut,
    SIZE_T *        pcbOut );

//
// Algorithm implementations
//

// Function for randomizing inputs of algorithms
typedef VOID (*FuncRandFn )(
            UINT32          keySize,            // Size of the key
            PBYTE           pbSrc,              // Buffer of TEST_RSA_MAX_NUMOF_BYTES bytes that will store the message
            SIZE_T*         pcbSrc,             // Actual size of the Src buffer that will be used
            SIZE_T*         pcbDst,             // Actual size of the Dst buffer that will be used
            PBYTE           pbExtra,            // Buffer of TEST_RSA_MAX_NUMOF_BYTES bytes that will store the label or the OID
            SIZE_T*         cbExtra,            // Actual size of the label or the OIDs
            PSYMCRYPT_HASH* ppHashAlgorithm     // A random hash algorithm when needed
);

// Encryption / Decryption / Signing / Verify function
typedef VOID (*FuncDataFn )(
            UINT32          keySize,
            PBYTE           pkKey,
            PBYTE           pbSrc,
            SIZE_T          cbSrc,
            PBYTE           pbDst,
            SIZE_T          cbDst,
            PBYTE           pbExtra,
            SIZE_T          cbExtra,
            PSYMCRYPT_HASH  pHashAlgorithm );

// FunctionalRsaImplementation class is only used for functional tests of RSA
class FunctionalRsaImplementation: public AlgorithmImplementation
{
public:
    FunctionalRsaImplementation() {};
    virtual ~FunctionalRsaImplementation() {};

private:
    FunctionalRsaImplementation( const FunctionalRsaImplementation & );
    VOID operator=( const FunctionalRsaImplementation & );

public:
    FuncRandFn  m_funcRandFunction;         // Randomizing function

    FuncDataFn  m_funcQueryFunction;        // Encryption or signing function
    FuncDataFn  m_funcReplyFunction;        // Decryption or verifying function (this also verifies the results)
};

// FunctionalRsaImp class is the template class of FunctionalRsaImplementation
template< class Implementation, class Algorithm>
class FunctionalRsaImp: public FunctionalRsaImplementation
{
public:
    FunctionalRsaImp();
    virtual ~FunctionalRsaImp();

private:
    FunctionalRsaImp( const FunctionalRsaImp & );
    VOID operator=( const FunctionalRsaImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};

template< class Implementation, class Algorithm>
const String FunctionalRsaImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String FunctionalRsaImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String FunctionalRsaImp<Implementation, Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
VOID algImpTestRsaRandFunction(
            UINT32          keySize,
            PBYTE           pbSrc,
            SIZE_T*         pcbSrc,
            SIZE_T*         pcbDst,
            PBYTE           pbExtra,
            SIZE_T*         pcbExtra,
            PSYMCRYPT_HASH* ppHashAlgorithm );

template< class Implementation, class Algorithm >
VOID algImpTestRsaQueryFunction(
            UINT32          keySize,
            PBYTE           pkKey,
            PBYTE           pbSrc,
            SIZE_T          cbSrc,
            PBYTE           pbDst,
            SIZE_T          cbDst,
            PBYTE           pbExtra,
            SIZE_T          cbExtra,
            PSYMCRYPT_HASH  pHashAlgorithm );

template< class Implementation, class Algorithm >
VOID algImpTestRsaReplyFunction(
            UINT32          keySize,
            PBYTE           pkKey,
            PBYTE           pbSrc,
            SIZE_T          cbSrc,
            PBYTE           pbDst,
            SIZE_T          cbDst,
            PBYTE           pbExtra,
            SIZE_T          cbExtra,
            PSYMCRYPT_HASH  pHashAlgorithm );
