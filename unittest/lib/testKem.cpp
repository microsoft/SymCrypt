//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#if SYMCRUST_EXPERIMENTAL_BUILD == 0
////////////////////////////////////////////////
// SymCrypt-specific testing
////////////////////////////////////////////////

// R = 2^16
#define SYMCRYPT_TEST_MLKEM_Rlog2        (16)

// NegQInvModR = -Q^(-1) mod R
#define SYMCRYPT_TEST_MLKEM_NegQInvModR  (3327)

// Rsqr = R^2 = (1<<32) mod Q
#define SYMCRYPT_TEST_MLKEM_Rsqr         (1353)

BOOL
testSymCryptMlKemPolyEqual(
    _In_    PCSYMCRYPT_MLKEM_POLYELEMENT peSrc1,
    _In_    PCSYMCRYPT_MLKEM_POLYELEMENT peSrc2 )
{
    // WARNING! THIS IS NOT SIDECHANNEL SAFE - it is only for use in TEST code
    UINT32 i;

    for( i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        if( peSrc1->coeffs[i] != peSrc2->coeffs[i] )
        {
            return FALSE;
        }
    }
    return TRUE;
}

VOID
testSymCryptMlKemNaivePolyMul(
    _In_    PCSYMCRYPT_MLKEM_POLYELEMENT peSrc1,
    _In_    PCSYMCRYPT_MLKEM_POLYELEMENT peSrc2,
    _Out_   PSYMCRYPT_MLKEM_POLYELEMENT  peDst )
{
    UINT32 i, j;

    UINT32 a, b, c, ab;
    UINT16 inv;
    INT32 diff;

    for( i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        peDst->coeffs[i] = 0;
    }

    // schoolbook polynomial modular multiplication
    // polynomial modulo X^256 + 1;

    // Products which result in a coefficient < X^256 are positive
    for( i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        a = peSrc1->coeffs[i];
        SYMCRYPT_ASSERT( a < SYMCRYPT_MLKEM_Q );

        for( j=0; j<(SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS-i); j++ )
        {
            b = peSrc2->coeffs[j];
            SYMCRYPT_ASSERT( b < SYMCRYPT_MLKEM_Q );

            SYMCRYPT_ASSERT( i+j < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS );
            c = peDst->coeffs[i+j];
            SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

            ab = a * b;

            inv = (UINT16)ab * SYMCRYPT_TEST_MLKEM_NegQInvModR;
            ab = (ab + (((UINT32)inv) * SYMCRYPT_MLKEM_Q)) >> SYMCRYPT_TEST_MLKEM_Rlog2;
            SYMCRYPT_ASSERT( ab <= 3494 );

            c += ab;
            diff = c - SYMCRYPT_MLKEM_Q;
            c -= SYMCRYPT_MLKEM_Q & ~(diff >> 31);

            diff = c - SYMCRYPT_MLKEM_Q;
            c -= SYMCRYPT_MLKEM_Q & ~(diff >> 31);
            SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

            peDst->coeffs[(i + j) & (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS-1)] = (UINT16) c;
        }
    }

    // Products which result in a coefficient >= X^256 are negative
    for( i=1; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        a = peSrc1->coeffs[i];
        SYMCRYPT_ASSERT( a < SYMCRYPT_MLKEM_Q );

        for( j=(SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS-i); j<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; j++ )
        {
            b = peSrc2->coeffs[j];
            SYMCRYPT_ASSERT( b < SYMCRYPT_MLKEM_Q );

            SYMCRYPT_ASSERT( i+j >= SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS );
            SYMCRYPT_ASSERT( i+j < (2*SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) );
            c = peDst->coeffs[(i + j) - SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS];
            SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

            ab = a * b;

            inv = (UINT16)ab * SYMCRYPT_TEST_MLKEM_NegQInvModR;
            ab = (ab + (((UINT32)inv) * SYMCRYPT_MLKEM_Q)) >> SYMCRYPT_TEST_MLKEM_Rlog2;
            SYMCRYPT_ASSERT( ab <= 3494 );

            diff = ab - SYMCRYPT_MLKEM_Q;
            ab -= SYMCRYPT_MLKEM_Q & ~(diff >> 31);
            SYMCRYPT_ASSERT( ab < SYMCRYPT_MLKEM_Q );

            diff = c - ab;
            c = (c - ab) + (SYMCRYPT_MLKEM_Q & (diff >> 31));
            SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

            peDst->coeffs[(i + j) & (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS-1)] = (UINT16) c;
        }
    }

    // Multiply destination by R
    for( i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        c = peDst->coeffs[i];
        SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

        c = SYMCRYPT_TEST_MLKEM_Rsqr * c;
        inv = ((UINT16)c) * SYMCRYPT_TEST_MLKEM_NegQInvModR;
        c = (c + (((UINT32)inv) * SYMCRYPT_MLKEM_Q)) >> SYMCRYPT_TEST_MLKEM_Rlog2; // in range [0, 3388]
        SYMCRYPT_ASSERT( c <= 3388 );

        diff = c - SYMCRYPT_MLKEM_Q;               // in range [-Q, 59]
        c -= SYMCRYPT_MLKEM_Q & ~(diff >> 31);     // in range [0, Q-1]
        SYMCRYPT_ASSERT( c < SYMCRYPT_MLKEM_Q );

        peDst->coeffs[i] = (UINT16) c;
    }
}

VOID
testMlKemArithmetic()
{
    SYMCRYPT_MLKEM_POLYELEMENT eA, eB, eC, eD, eE, eZero, eOne, eOneNTT;
    SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR aA;


    BYTE encodeBuffer[SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT];

    PSYMCRYPT_MLKEM_POLYELEMENT peA = SymCryptMlKemPolyElementCreate( (PBYTE) &eA, sizeof(eA) );
    PSYMCRYPT_MLKEM_POLYELEMENT peB = SymCryptMlKemPolyElementCreate( (PBYTE) &eB, sizeof(eB) );
    PSYMCRYPT_MLKEM_POLYELEMENT peC = SymCryptMlKemPolyElementCreate( (PBYTE) &eC, sizeof(eC) );
    PSYMCRYPT_MLKEM_POLYELEMENT peD = SymCryptMlKemPolyElementCreate( (PBYTE) &eD, sizeof(eD) );
    PSYMCRYPT_MLKEM_POLYELEMENT peE = SymCryptMlKemPolyElementCreate( (PBYTE) &eE, sizeof(eE) );

    PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR paTmp = SymCryptMlKemPolyElementAccumulatorCreate( (PBYTE) &aA, sizeof(aA) );

    PCSYMCRYPT_MLKEM_POLYELEMENT peZero   = SymCryptMlKemPolyElementCreate( (PBYTE) &eZero,   sizeof(eZero)   );
    PCSYMCRYPT_MLKEM_POLYELEMENT peOne    = SymCryptMlKemPolyElementCreate( (PBYTE) &eOne,    sizeof(eOne)    );
    PCSYMCRYPT_MLKEM_POLYELEMENT peOneNTT = SymCryptMlKemPolyElementCreate( (PBYTE) &eOneNTT, sizeof(eOneNTT) );

    for( int i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        ((PSYMCRYPT_MLKEM_POLYELEMENT)peZero  )->coeffs[i] = 0;
        ((PSYMCRYPT_MLKEM_POLYELEMENT)peOne   )->coeffs[i] = 0;
        ((PSYMCRYPT_MLKEM_POLYELEMENT)peOneNTT)->coeffs[i] = 0;
        paTmp->coeffs[i] = 0;
    }

    // multiplicative identity will have 1 in the 0th coefficient and 0s in all other coefficients
    ((PSYMCRYPT_MLKEM_POLYELEMENT)peOne   )->coeffs[0] = 1;
    ((PSYMCRYPT_MLKEM_POLYELEMENT)peOneNTT)->coeffs[0] = 1;

    SymCryptMlKemPolyElementNTT( (PSYMCRYPT_MLKEM_POLYELEMENT)peOneNTT );

    SymCryptMlKemPolyElementAdd( peZero, peZero, peD );
    CHECK( testSymCryptMlKemPolyEqual( peD, peZero ), "(0+0) != 0" );

    SymCryptMlKemPolyElementNTT( peD );
    CHECK( testSymCryptMlKemPolyEqual( peD, peZero ), "NTT(0) != 0" );

    SymCryptMlKemPolyElementINTTAndMulR( peD );
    CHECK( testSymCryptMlKemPolyEqual( peD, peZero ), "INTT(0) .* R != 0" );

    SymCryptMlKemPolyElementAdd( peOne, peZero, peD );

    CHECK( testSymCryptMlKemPolyEqual( peD, peOne ), "1 + 0 != 1" );

    SymCryptMlKemPolyElementSub( peOne, peOne, peD );

    CHECK( testSymCryptMlKemPolyEqual( peD, peZero ), "1 - 1 != 0" );

    SymCryptMlKemPolyElementMulAndAccumulate( peOneNTT, peOneNTT, paTmp );
    SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peD );
    SymCryptMlKemPolyElementINTTAndMulR( peD );

    CHECK( testSymCryptMlKemPolyEqual( peD, peOne ), "INTT(((NTT(1) o NTT(1)) ./ R) + 0) .* R != 1" );

    // Exhaustive tests testing identities and should trigger any debug assertions
    // For each coefficient we test 1/testStepValue possible values; set testStepValue->1 for exhaustive test
    const int testStepValue = 29;
    for( int i=0; i<SYMCRYPT_MLKEM_Q; i+=testStepValue )
    {
        for( int k=0; k<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; k++ )
        {
            peA->coeffs[k] = (i+k) % SYMCRYPT_MLKEM_Q;
        }

        for( int k=1; k<=12; k++)
        {
            SymCryptMlKemPolyElementCompressAndEncode( peA, k, encodeBuffer );

            SymCryptMlKemPolyElementDecodeAndDecompress( encodeBuffer, k, peB );

            if( k == 12 )
            {
                CHECK3( testSymCryptMlKemPolyEqual( peA, peB ), "(%i): decode_12(encode_12(A)) != A", i );
            }

            SymCryptMlKemPolyElementCompressAndEncode( peB, k, encodeBuffer );

            SymCryptMlKemPolyElementDecodeAndDecompress( encodeBuffer, k, peA );

            CHECK4( testSymCryptMlKemPolyEqual( peA, peB ), "(%i, %i): decode(encode(decode(encode(A)) != decode(encode(A))", i, k );
        }

        SymCryptMlKemPolyElementSub( peA, peA, peD );
        CHECK3( testSymCryptMlKemPolyEqual( peD, peZero ), "(%i): (A-A) != 0", i );

        SymCryptMlKemPolyElementAdd( peA, peZero, peC );
        CHECK3( testSymCryptMlKemPolyEqual( peC, peA ), "(%i): (A+0) != A", i );

        SymCryptMlKemPolyElementAdd( peZero, peA, peC );
        CHECK3( testSymCryptMlKemPolyEqual( peC, peA ), "(%i): (0+A) != A", i );

        SymCryptMlKemPolyElementMulAndAccumulate( peA, peZero, paTmp );
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peD );

        CHECK3( testSymCryptMlKemPolyEqual( peD, peZero ), "(%i): ((A o 0) ./ R) + 0 != 0", i );

        SymCryptMlKemPolyElementMulR( peC, peC );
        SymCryptMlKemPolyElementMulAndAccumulate( peC, peOneNTT, paTmp );
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peD );

        CHECK3( testSymCryptMlKemPolyEqual( peD, peA ), "(%i): (((A .* R) o NTT(1)) ./ R) + 0 != A", i );


        SymCryptMlKemPolyElementAdd( peA, peZero, peC );
        SymCryptMlKemPolyElementAdd( peZero, peZero, peD );

        SymCryptMlKemPolyElementNTT( peC );
        SymCryptMlKemPolyElementMulAndAccumulate( peC, peOneNTT, paTmp );
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peD );
        SymCryptMlKemPolyElementINTTAndMulR( peD );

        CHECK3( testSymCryptMlKemPolyEqual( peD, peA ), "(%i): INTT( ((NTT(A) o NTT(1)) ./ R) + 0 ) .* R != A", i );

        for( int j=0; j<SYMCRYPT_MLKEM_Q; j+=testStepValue )
        {
            for( int k=0; k<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; k++ )
            {
                peB->coeffs[k] = (j+(3*k)) % SYMCRYPT_MLKEM_Q;
            }

            SymCryptMlKemPolyElementAdd( peA, peB, peC ); // C = A+B
            SymCryptMlKemPolyElementAdd( peB, peA, peD ); // D = B+A

            CHECK4( testSymCryptMlKemPolyEqual( peC, peD ), "(%i, %i): (A+B) != (B+A)", i, j );

            SymCryptMlKemPolyElementSub( peC, peB, peD ); // D = (A+B)-B

            CHECK4( testSymCryptMlKemPolyEqual( peD, peA ), "(%i, %i): (A+B)-B != A", i, j );

            SymCryptMlKemPolyElementNTT( peC ); // C = NTT(A+B)
            SymCryptMlKemPolyElementNTT( peD ); // D = NTT(A)
            SymCryptMlKemPolyElementAdd( peB, peZero, peE ); // E = B
            SymCryptMlKemPolyElementNTT( peE ); // E = NTT(B)

            SymCryptMlKemPolyElementSub( peC, peD, peC ); // C = NTT(A+B) - NTT(A)

            CHECK4( testSymCryptMlKemPolyEqual( peC, peE ), "(%i, %i): NTT(A+B)-NTT(A) != NTT(B)", i, j );

            SymCryptMlKemPolyElementSub( peE, peE, peE );
            SymCryptMlKemPolyElementMulAndAccumulate( peC, peD, paTmp );
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peE ); // E = (NTT(A) o NTT(B)) ./ R
            SymCryptMlKemPolyElementINTTAndMulR( peE ); // E = INTT( (NTT(A) o NTT(B)) ./ R ) .* R

            testSymCryptMlKemNaivePolyMul( peA, peB, peC ); // C = naiveMul( A, B )

            CHECK4( testSymCryptMlKemPolyEqual( peC, peE ), "(%i, %i): INTT(((NTT(A) o NTT(B)) ./ R) + 0) .* R != (A o B)", i, j );

            SymCryptMlKemPolyElementAdd( peA, peB, peC ); // C = A+B
            SymCryptMlKemPolyElementSub( peA, peB, peD ); // D = A-B

            SymCryptMlKemPolyElementMulAndAccumulate( peC, peD, paTmp );
            SymCryptMlKemPolyElementSub( peC, peC, peC );
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peC ); // C = ((A+B) o (A-B)) ./ R;

            SymCryptMlKemPolyElementSub( peZero, peB, peD ); // D = -B
            SymCryptMlKemPolyElementMulAndAccumulate( peA, peA, paTmp ); // Tmp = AoA
            SymCryptMlKemPolyElementMulAndAccumulate( peB, peD, paTmp ); // Tmp = (AoA) + (Bo-B)
            SymCryptMlKemPolyElementSub( peD, peD, peD );
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement( paTmp, peD ); // D = ((A o A) + (B o -B)) ./ R;

            CHECK4( testSymCryptMlKemPolyEqual( peC, peD ), "(%i, %i): (A+B) o (A-B) != (A o A) + (B o -B)", i, j );
        }
    }
}
#endif

////////////////////////////////////////////////
// Multi-implementation testing
////////////////////////////////////////////////

class KemMultiImp: public KemImplementation
{
public:
    KemMultiImp( String algName );
    ~KemMultiImp();

private:
    KemMultiImp( const KemMultiImp & );
    VOID operator=( const KemMultiImp & );

public:

    typedef std::vector<KemImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;                    // Implementations we use

    ImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    virtual NTSTATUS setKeyFromTestBlob(
        _In_reads_bytes_( cbTestKeyBlob )       PCBYTE              pcbTestKeyBlob,
                                                SIZE_T              cbTestKeyBlob,
                                                BOOL                canDecapsulate );

    virtual NTSTATUS getBlobFromKey(
                                                UINT32              blobType,
        _Out_writes_bytes_( cbBlob )            PBYTE               pbBlob,
                                                SIZE_T              cbBlob );

    virtual NTSTATUS encapsulate(
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret,
        _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                                SIZE_T              cbCiphertext );

    virtual NTSTATUS encapsulateEx(
        _In_reads_bytes_( cbRandom )            PCBYTE              pbRandom,
                                                SIZE_T              cbRandom,
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret,
        _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                                SIZE_T              cbCiphertext );

    virtual NTSTATUS decapsulate(
        _In_reads_bytes_( cbCiphertext )        PCBYTE              pbCiphertext,
                                                SIZE_T              cbCiphertext,
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret );

    BOOL m_canDecapsulate;
};

KemMultiImp::KemMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<KemImplementation>( algName, &m_imps );
}

KemMultiImp::~KemMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

NTSTATUS
KemMultiImp::setKeyFromTestBlob(
        _In_reads_bytes_( cbKeyBlob )           PCBYTE              pcbTestKeyBlob,
                                                SIZE_T              cbKeyBlob,
                                                BOOL                canDecapsulate )
{
    // m_imps is the set of implementations we support, but an implementation can opt out of any one key.
    // m_comps is the set of algorithm implementations that we are working with.
    // m_canDecapsulate tracks whether this key blob can be used in decapsulation

    m_comps.clear();
    m_canDecapsulate = canDecapsulate;

    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKeyFromTestBlob( pcbTestKeyBlob, cbKeyBlob, canDecapsulate ) == STATUS_SUCCESS )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
KemMultiImp::getBlobFromKey(
                                                UINT32              blobType,
        _Out_writes_bytes_( cbBlob )            PBYTE               pbBlob,
                                                SIZE_T              cbBlob )
{
    BYTE abBlob[3169];
    ResultMerge resAgreedSecret;
    NTSTATUS ntStatus;

    CHECK( cbBlob < sizeof( abBlob ), "Buffer too small" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abBlob, 'b', cbBlob + 1 );
        ntStatus = (*i)->getBlobFromKey(
            blobType,
            abBlob, cbBlob );
        CHECK( (ntStatus == STATUS_SUCCESS) || (ntStatus == STATUS_NOT_SUPPORTED), "Failure during KEM getBlobFromKey" );
        CHECK( abBlob[ cbBlob ] == 'b', "?" );

        if( ntStatus == STATUS_SUCCESS )
        {
            resAgreedSecret.addResult( (*i), abBlob, cbBlob );
        }
    }

    resAgreedSecret.getResult( pbBlob, cbBlob );

    return STATUS_SUCCESS;
}

NTSTATUS
KemMultiImp::encapsulate(
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret,
        _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                                SIZE_T              cbCiphertext )
{
    // Encapsulation is not deterministic, so we do the following:
    // - Have every implementation encapsulate
    // - Have every implementation decapsulate each ciphertext
    // - return a random encapsulation
    BYTE abEncapsAgreedSecret[33];
    BYTE abEncapsCiphertext[1666];
    BYTE abDecapsAgreedSecret[33];
    NTSTATUS ntStatus;
    int nEncapsulations = 0;

    CHECK( cbAgreedSecret < sizeof( abEncapsAgreedSecret ), "Buffer too small" );
    CHECK( cbCiphertext   < sizeof( abEncapsCiphertext ), "Buffer too small" );
    CHECK( cbAgreedSecret < sizeof( abDecapsAgreedSecret ), "Buffer too small" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abEncapsAgreedSecret, 'd', cbAgreedSecret + 1 );
        memset( abEncapsCiphertext, 'c', cbCiphertext + 1 );
        ntStatus = (*i)->encapsulate(
            abEncapsAgreedSecret, cbAgreedSecret,
            abEncapsCiphertext, cbCiphertext );
        CHECK( ntStatus == STATUS_SUCCESS, "Failure during KEM Encapsulate" );
        CHECK( abEncapsAgreedSecret[ cbAgreedSecret ] == 'd', "?" );
        CHECK( abEncapsCiphertext[ cbCiphertext ] == 'c', "?" );
        if( m_canDecapsulate )
        {
            for( ImpPtrVector::iterator j = m_comps.begin(); j != m_comps.end(); ++j )
            {
                ntStatus = (*j)->decapsulate(
                    abEncapsCiphertext, cbCiphertext,
                    abDecapsAgreedSecret, cbAgreedSecret );
                CHECK4( ntStatus == STATUS_SUCCESS, "KEM encapsulate -> decapsulate failure %s, %s",
                        (*i)->m_implementationName.c_str(),
                        (*j)->m_implementationName.c_str() );
                CHECK4( memcmp( abEncapsAgreedSecret, abDecapsAgreedSecret, cbAgreedSecret ) == 0,
                        "KEM encapsulate -> decapsulate agreed secret mismatch %s, %s",
                        (*i)->m_implementationName.c_str(),
                        (*j)->m_implementationName.c_str() );
            }
        }

        // Copy a random encapsulation to the output
        nEncapsulations += 1;
        if( (g_rng.byte() % nEncapsulations) == 0 )
        {
            memcpy( pbAgreedSecret, abEncapsAgreedSecret, cbAgreedSecret );
            memcpy( pbCiphertext, abEncapsCiphertext, cbCiphertext );
        }

    }

    return STATUS_SUCCESS;
}

NTSTATUS
KemMultiImp::encapsulateEx(
        _In_reads_bytes_( cbRandom )            PCBYTE              pbRandom,
                                                SIZE_T              cbRandom,
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret,
        _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                                SIZE_T              cbCiphertext )
{
    BYTE abEncapsAgreedSecret[33];
    BYTE abEncapsCiphertext[1666];
    ResultMerge resAgreedSecret;
    ResultMerge resCipherText;
    NTSTATUS ntStatus;

    CHECK( cbAgreedSecret < sizeof( abEncapsAgreedSecret ), "Buffer too small" );
    CHECK( cbCiphertext   < sizeof( abEncapsCiphertext ), "Buffer too small" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abEncapsAgreedSecret, 'd', cbAgreedSecret + 1 );
        memset( abEncapsCiphertext, 'c', cbCiphertext + 1 );
        ntStatus = (*i)->encapsulateEx(
            pbRandom, cbRandom,
            abEncapsAgreedSecret, cbAgreedSecret,
            abEncapsCiphertext, cbCiphertext);
        CHECK( abEncapsAgreedSecret[ cbAgreedSecret ] == 'd', "?" );
        CHECK( abEncapsCiphertext[ cbCiphertext ] == 'c', "?" );

        if( ntStatus != STATUS_NOT_SUPPORTED )
        {
            CHECK( ntStatus == STATUS_SUCCESS, "Failure during KEM EncapsulateEx" );
            resAgreedSecret.addResult( (*i), abEncapsAgreedSecret, cbAgreedSecret );
            resCipherText.addResult( (*i), abEncapsCiphertext, cbCiphertext );
        }
    }

    resAgreedSecret.getResult( pbAgreedSecret, cbAgreedSecret );
    resCipherText.getResult( pbCiphertext, cbCiphertext, FALSE );

    return STATUS_SUCCESS;
}

NTSTATUS
KemMultiImp::decapsulate(
        _In_reads_bytes_( cbCiphertext )        PCBYTE              pbCiphertext,
                                                SIZE_T              cbCiphertext,
        _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                                SIZE_T              cbAgreedSecret )
{
    BYTE abDecapsAgreedSecret[33];
    ResultMerge resAgreedSecret;
    ResultMerge resStatus;
    BYTE b[4];
    NTSTATUS ntStatus;

    CHECK( cbAgreedSecret < sizeof( abDecapsAgreedSecret ), "Buffer too small" );
    CHECK( m_canDecapsulate, "Attempt to decapsulate with a key that does not support it" );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abDecapsAgreedSecret, 'd', cbAgreedSecret + 1 );
        ntStatus = (*i)->decapsulate(
            pbCiphertext, cbCiphertext,
            abDecapsAgreedSecret, cbAgreedSecret );
        CHECK( abDecapsAgreedSecret[ cbAgreedSecret ] == 'd', "?" );

        // Process result as MSBfirst array to get errors to print correctly.
        SYMCRYPT_STORE_MSBFIRST32( b, ntStatus );
        resStatus.addResult( *i, b, 4 );
        resAgreedSecret.addResult( (*i), abDecapsAgreedSecret, cbAgreedSecret );
    }

    resAgreedSecret.getResult( pbAgreedSecret, cbAgreedSecret );
    resStatus.getResult( b, 4, FALSE );
    ntStatus = SYMCRYPT_LOAD_MSBFIRST32( b );

    return ntStatus;
}

#define SYMCRYPT_MLKEM_512_PARAMS_NAME  "ML-KEM-512"
#define SYMCRYPT_MLKEM_768_PARAMS_NAME  "ML-KEM-768"
#define SYMCRYPT_MLKEM_1024_PARAMS_NAME "ML-KEM-1024"

typedef struct _SYMCRYPT_TEST_MLKEMPARAMS {
    LPSTR                   pszParamsName;
    SYMCRYPT_MLKEM_PARAMS   params;
} SYMCRYPT_TEST_MLKEM_PARAMS, *PSYMCRYPT_TEST_MLKEM_PARAMS;

SYMCRYPT_TEST_MLKEM_PARAMS rgTestMlKemParams[] = {
    //pszParamsName                     //params
    { SYMCRYPT_MLKEM_512_PARAMS_NAME,   SYMCRYPT_MLKEM_PARAMS_MLKEM512  },
    { SYMCRYPT_MLKEM_768_PARAMS_NAME,   SYMCRYPT_MLKEM_PARAMS_MLKEM768  },
    { SYMCRYPT_MLKEM_1024_PARAMS_NAME,  SYMCRYPT_MLKEM_PARAMS_MLKEM1024 },
};

#define NUM_OF_MLKEM_TEST_PARAMS       (sizeof(rgTestMlKemParams) / sizeof(rgTestMlKemParams[0]))

struct MlKemDef {
    using TestParamsType = SYMCRYPT_TEST_MLKEM_PARAMS;
    using ParamsType     = SYMCRYPT_MLKEM_PARAMS;
    using FormatType     = SYMCRYPT_MLKEMKEY_FORMAT;
    using TestBlobType   = MLKEMKEY_TESTBLOB;
    using PKeyType       = PSYMCRYPT_MLKEMKEY;
    using PCKeyType      = PCSYMCRYPT_MLKEMKEY;

    static constexpr FormatType FormatFull   = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    static constexpr FormatType FormatDecaps = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    static constexpr FormatType FormatEncaps = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;

    static constexpr SIZE_T MaxCiphertextSize = 1568;
    static constexpr SIZE_T AgreedSecretSize = 32;
    static constexpr SIZE_T MaxEncapsKeyBlobSize = 1568;
    static constexpr SIZE_T MaxDecapsKeyBlobSize = 3168;
    static constexpr SIZE_T PrivateSeedSize = 64;
};

#define SYMCRYPT_COMPOSITE_MLKEM_768_P256_PARAMS_NAME    "ML-KEM-768-P256"
#define SYMCRYPT_COMPOSITE_MLKEM_768_X25519_PARAMS_NAME  "ML-KEM-768-X25519"
#define SYMCRYPT_COMPOSITE_MLKEM_1024_P384_PARAMS_NAME   "ML-KEM-1024-P384"

typedef struct _SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS {
    LPSTR                               pszParamsName;
    SYMCRYPT_COMPOSITE_MLKEM_PARAMS     params;
    SYMCRYPT_CACHED_ECURVE_ID           curveId;
} SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS, *PSYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS;

SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS rgTestCompositeMlKemParams[] = {
    //pszParamsName                                     //params
    { SYMCRYPT_COMPOSITE_MLKEM_768_P256_PARAMS_NAME,    SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256, SYMCRYPT_CACHED_ECURVE_ID_NIST_P256   },
    { SYMCRYPT_COMPOSITE_MLKEM_768_X25519_PARAMS_NAME,  SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519, SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 },
    { SYMCRYPT_COMPOSITE_MLKEM_1024_P384_PARAMS_NAME,   SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384, SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 },
};

#define NUM_OF_COMPOSITE_MLKEM_TEST_PARAMS  (sizeof(rgTestCompositeMlKemParams) / sizeof(rgTestCompositeMlKemParams[0]))

struct CompositeMlKemDef {
    using TestParamsType = SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS;
    using ParamsType     = SYMCRYPT_COMPOSITE_MLKEM_PARAMS;
    using FormatType     = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT;
    using TestBlobType   = COMPOSITE_MLKEMKEY_TESTBLOB;
    using PKeyType       = PSYMCRYPT_COMPOSITE_MLKEMKEY;
    using PCKeyType      = PCSYMCRYPT_COMPOSITE_MLKEMKEY;

    static constexpr FormatType FormatFull   = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED;
    static constexpr FormatType FormatDecaps = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY;
    static constexpr FormatType FormatEncaps = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY;

    static constexpr SIZE_T MaxCiphertextSize = 1665;
    static constexpr SIZE_T AgreedSecretSize = 32;
    static constexpr SIZE_T MaxEncapsKeyBlobSize = 1665;
    static constexpr SIZE_T MaxDecapsKeyBlobSize = 128;
    static constexpr SIZE_T PrivateSeedSize = 32;
};

// Function table definitions

template<typename KemDef>
struct SymCryptKemFunctionTable
{
    using ParamsType = typename KemDef::ParamsType;
    using PKeyType = typename KemDef::PKeyType;
    using PCKeyType = typename KemDef::PCKeyType;
    using FormatType = typename KemDef::FormatType;

    PKeyType (SYMCRYPT_CALL *KeyAllocate)( ParamsType params );
    void (SYMCRYPT_CALL *KeyFree)( PKeyType pKey );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *KeyGenerate)( PKeyType pKey, UINT32 flags );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *KeySetValue)( PCBYTE pbSrc, SIZE_T cbSrc, FormatType format, UINT32 flags, PKeyType pKey );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *KeyGetValue)( PCKeyType pKey, PBYTE pbDst, SIZE_T cbDst, FormatType format, UINT32 flags );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *SizeofKeyFormatFromParams)( ParamsType params, FormatType format, SIZE_T* pcbFormat );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *SizeofCiphertextFromParams)( ParamsType params, SIZE_T* pcbCiphertext );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *Encapsulate)( PCKeyType pKey, PBYTE pbSharedSecret, SIZE_T cbSharedSecret, PBYTE pbCiphertext, SIZE_T cbCiphertext );
    SYMCRYPT_ERROR (SYMCRYPT_CALL *Decapsulate)( PCKeyType pKey, PCBYTE pbCiphertext, SIZE_T cbCiphertext, PBYTE pbSharedSecret, SIZE_T cbSharedSecret );
};

const SymCryptKemFunctionTable<MlKemDef> g_MlKemFunctionTable = {
    SymCryptMlKemkeyAllocate,
    SymCryptMlKemkeyFree,
    SymCryptMlKemkeyGenerate,
    SymCryptMlKemkeySetValue,
    SymCryptMlKemkeyGetValue,
    SymCryptMlKemSizeofKeyFormatFromParams,
    SymCryptMlKemSizeofCiphertextFromParams,
    SymCryptMlKemEncapsulate,
    SymCryptMlKemDecapsulate,
};

const SymCryptKemFunctionTable<CompositeMlKemDef> g_CompositeMlKemFunctionTable = {
    SymCryptCompositeMlKemkeyAllocate,
    SymCryptCompositeMlKemkeyFree,
    SymCryptCompositeMlKemkeyGenerate,
    SymCryptCompositeMlKemkeySetValue,
    SymCryptCompositeMlKemkeyGetValue,
    SymCryptCompositeMlKemSizeofKeyFormatFromParams,
    SymCryptCompositeMlKemSizeofCiphertextFromParams,
    SymCryptCompositeMlKemEncapsulate,
    SymCryptCompositeMlKemDecapsulate,
};

// High level API test definitions

template <typename KemDef>
struct HighLevelKemTestConfig
{
    using TestParamsType = typename KemDef::TestParamsType;
    using ParamsType     = typename KemDef::ParamsType;
    using FormatType     = typename KemDef::FormatType;

    const char*     algName;
    TestParamsType* pTestParams;
    SIZE_T          cTestParams;

    const SymCryptKemFunctionTable<KemDef>* pFunctionTable;
};

template<typename KemDef>
VOID
testKemHighLevelAPIGeneric( const HighLevelKemTestConfig<KemDef>& config )
{
    using TestBlobType = typename KemDef::TestBlobType;
    using ParamsType = typename KemDef::ParamsType;

    std::unique_ptr<KemMultiImp> pKemImplementation(new KemMultiImp( config.algName ));

    NTSTATUS ntStatus;
    SYMCRYPT_ERROR scError;
    UINT32 i;

    TestBlobType keyTestBlobFull;
    TestBlobType keyTestBlobDecaps;
    TestBlobType keyTestBlobEncaps;

    BYTE abCipherText[KemDef::MaxCiphertextSize];
    BYTE abAgreedSecretEncaps[KemDef::AgreedSecretSize];
    BYTE abAgreedSecretDecaps[KemDef::AgreedSecretSize];
    SIZE_T cbCipherText;

    keyTestBlobFull.format = KemDef::FormatFull;
    keyTestBlobDecaps.format = KemDef::FormatDecaps;
    keyTestBlobEncaps.format = KemDef::FormatEncaps;

    for( UINT32 paramIdx = 0; paramIdx < config.cTestParams; paramIdx++ )
    {
        ParamsType params = config.pTestParams[paramIdx].params;

        keyTestBlobFull.params   = params;
        keyTestBlobDecaps.params = params;
        keyTestBlobEncaps.params = params;

        scError = (config.pFunctionTable)->SizeofKeyFormatFromParams( params, KemDef::FormatFull, &keyTestBlobFull.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for full key failed with 0x%x", scError );
        CHECK( keyTestBlobFull.cbKeyBlob <= sizeof(keyTestBlobFull.abKeyBlob), "?" );

        scError = (config.pFunctionTable)->SizeofKeyFormatFromParams( params, KemDef::FormatDecaps, &keyTestBlobDecaps.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for decapsulation key failed with 0x%x", scError );
        CHECK( keyTestBlobDecaps.cbKeyBlob <= sizeof(keyTestBlobDecaps.abKeyBlob), "?" );

        scError = (config.pFunctionTable)->SizeofKeyFormatFromParams( params, KemDef::FormatEncaps, &keyTestBlobEncaps.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for encapsulation key failed with 0x%x", scError );
        CHECK( keyTestBlobEncaps.cbKeyBlob <= sizeof(keyTestBlobEncaps.abKeyBlob), "?" );

        scError = (config.pFunctionTable)->SizeofCiphertextFromParams( params, &cbCipherText );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SizeOfCiphertextFromParams failed with 0x%x", scError );
        CHECK( cbCipherText <= sizeof(abCipherText), "?" );

        for( i=0; i<100; i++ )
        {
            GENRANDOM( keyTestBlobFull.abKeyBlob, (UINT32) keyTestBlobFull.cbKeyBlob );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->getBlobFromKey( KemDef::FormatDecaps, keyTestBlobDecaps.abKeyBlob, keyTestBlobDecaps.cbKeyBlob );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob from full key");

            ntStatus = pKemImplementation->getBlobFromKey( KemDef::FormatEncaps, keyTestBlobEncaps.abKeyBlob, keyTestBlobEncaps.cbKeyBlob );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob from full key");

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, KemDef::AgreedSecretSize, abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with full key");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with full key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (full key) and decaps (full key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with full key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (full key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, KemDef::AgreedSecretSize, abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with decapsulation key");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with decapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (decaps key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with decapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (decaps key) and decaps (full key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobEncaps, sizeof(keyTestBlobEncaps), FALSE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob");

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, KemDef::AgreedSecretSize, abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with encapsulation key");

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with encapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (encaps key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with encapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) == 0, "Agreed secret mismatch between encaps (encaps key) and decaps (full key)" );

            // modify the ciphertext and verify errors
            // either should induce an error (modification meant that value was publicly malformed), or success with implicit rejection value != to encaps secret
            UINT32 t = g_rng.uint32();
            abCipherText[ (t/8) % cbCipherText ] ^= 1 << (t%8);

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( (ntStatus != STATUS_SUCCESS) || memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) != 0, "Modified ciphertext does not cause failure" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, KemDef::AgreedSecretSize );
            CHECK( (ntStatus != STATUS_SUCCESS) || memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, KemDef::AgreedSecretSize) != 0, "Modified ciphertext does not cause failure" );
        }
    }

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testMlKemHighLevelAPI()
{
    HighLevelKemTestConfig<MlKemDef> config = {
        "MlKem",
        rgTestMlKemParams,
        NUM_OF_MLKEM_TEST_PARAMS,
        &g_MlKemFunctionTable,
    };

    testKemHighLevelAPIGeneric<MlKemDef>( config );
}

VOID
testCompositeMlKemHighLevelAPI()
{
    HighLevelKemTestConfig<CompositeMlKemDef> config = {
        "CompositeMlKem",
        rgTestCompositeMlKemParams,
        NUM_OF_COMPOSITE_MLKEM_TEST_PARAMS,
        &g_CompositeMlKemFunctionTable,
    };

    testKemHighLevelAPIGeneric<CompositeMlKemDef>( config );
}

////////////////////////////////////////////////
// Negative testing
////////////////////////////////////////////////

template<typename KemDef>
struct SymCryptKemNegativeTestConfig
{
    using TestParamsType = typename KemDef::TestParamsType;

    const SymCryptKemFunctionTable<KemDef>* pFuncTable;
    TestParamsType* pTestParams;
    SIZE_T cTestParams;
};

template<typename KemDef>
VOID
testSymCryptKemNegativeTests(
    SymCryptKemNegativeTestConfig<KemDef> config )
{
    using ParamsType = typename KemDef::ParamsType;
    using PKeyType = typename KemDef::PKeyType;

    const auto pFuncTable = config.pFuncTable;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PKeyType pKey = nullptr;
    BYTE abPublicKeyBlob[KemDef::MaxEncapsKeyBlobSize];
    BYTE abPrivateKeyBlob[KemDef::MaxDecapsKeyBlobSize];
    BYTE abPrivateSeedBlob[KemDef::PrivateSeedSize];
    BYTE abCiphertext[KemDef::MaxCiphertextSize];
    BYTE abSharedSecret[KemDef::AgreedSecretSize];
    SIZE_T cbPublicKey = 0;
    SIZE_T cbPrivateKey = 0;
    SIZE_T cbPrivateSeed = 0;
    SIZE_T cbCiphertext = 0;

    for( UINT32 paramIdx = 0; paramIdx < config.cTestParams; paramIdx++ )
    {
        ParamsType params = config.pTestParams[paramIdx].params;

        scError = pFuncTable->SizeofKeyFormatFromParams( params, KemDef::FormatEncaps, &cbPublicKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get public key size" );

        scError = pFuncTable->SizeofKeyFormatFromParams( params, KemDef::FormatDecaps, &cbPrivateKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get private key size" );

        scError = pFuncTable->SizeofKeyFormatFromParams( params, KemDef::FormatFull, &cbPrivateSeed );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get private seed size" );

        scError = pFuncTable->SizeofCiphertextFromParams( params, &cbCiphertext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get ciphertext size" );

        pKey = pFuncTable->KeyAllocate( params );
        CHECK( pKey != NULL, "Failed to allocate key" );

        // Import key blob with invalid sizes, then import correct one

        scError = pFuncTable->KeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to generate key" );

        scError = pFuncTable->KeyGetValue( pKey, abPublicKeyBlob, cbPublicKey, KemDef::FormatEncaps, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to export public key" );

        scError = pFuncTable->KeySetValue( abPublicKeyBlob, 0, KemDef::FormatEncaps, 0, pKey );
        CHECK( scError != SYMCRYPT_NO_ERROR, "SetValue with size 0 should fail" );

        scError = pFuncTable->KeySetValue( abPublicKeyBlob, cbPublicKey - 1, KemDef::FormatEncaps, 0, pKey );
        CHECK( scError != SYMCRYPT_NO_ERROR, "SetValue with size - 1 should fail" );

        scError = pFuncTable->KeySetValue( abPublicKeyBlob, cbPublicKey + 1, KemDef::FormatEncaps, 0, pKey );
        CHECK( scError != SYMCRYPT_NO_ERROR, "SetValue with size + 1 should fail" );

        scError = pFuncTable->KeySetValue( abPublicKeyBlob, cbPublicKey, KemDef::FormatEncaps, 0, pKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetValue with correct size should succeed" );

        // Export private seed/key from public-only key, encapsulate/decapsulate with public-only key

        scError = pFuncTable->KeyGetValue( pKey, abPrivateSeedBlob, cbPrivateSeed, KemDef::FormatFull, 0 );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Exporting private seed from public-only key should fail" );

        scError = pFuncTable->KeyGetValue( pKey, abPrivateKeyBlob, cbPrivateKey, KemDef::FormatDecaps, 0 );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Exporting private key from public-only key should fail" );

        scError = pFuncTable->Encapsulate( pKey, abSharedSecret, KemDef::AgreedSecretSize, abCiphertext, cbCiphertext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Encapsulate with public-only key should succeed" );

        scError = pFuncTable->Decapsulate( pKey, abCiphertext, cbCiphertext, abSharedSecret, KemDef::AgreedSecretSize );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Decapsulate with public-only key should fail" );

        // Encapsulate/Decapsulate with wrong buffer sizes

        scError = pFuncTable->KeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to generate key" );

        scError = pFuncTable->Encapsulate( pKey, abSharedSecret, KemDef::AgreedSecretSize, abCiphertext, cbCiphertext - 1 );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Encapsulate with wrong ciphertext size should fail" );

        scError = pFuncTable->Encapsulate( pKey, abSharedSecret, KemDef::AgreedSecretSize - 1, abCiphertext, cbCiphertext );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Encapsulate with wrong shared secret size should fail" );

        scError = pFuncTable->Encapsulate( pKey, abSharedSecret, KemDef::AgreedSecretSize, abCiphertext, cbCiphertext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Encapsulate with correct sizes should succeed" );

        scError = pFuncTable->Decapsulate( pKey, abCiphertext, cbCiphertext - 1, abSharedSecret, KemDef::AgreedSecretSize );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Decapsulate with wrong ciphertext size should fail" );

        scError = pFuncTable->Decapsulate( pKey, abCiphertext, cbCiphertext, abSharedSecret, KemDef::AgreedSecretSize - 1 );
        CHECK( scError != SYMCRYPT_NO_ERROR, "Decapsulate with wrong shared secret size should fail" );

        pFuncTable->KeyFree( pKey );
        pKey = NULL;
    }
}

#define SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED  (32)
#define SYMCRYPT_TEST_MLKEM_SIZEOF_ENCAPS_HASH  (32)
#define SYMCRYPT_TEST_MLKEM_SIZEOF_Z            (32)

VOID
testSymCryptMlKemSetInvalidDecapsKeyBlob()
{
    SYMCRYPT_ERROR scError;
    MLKEMKEY_TESTBLOB keyTestBlobFull;
    MLKEMKEY_TESTBLOB keyTestBlobDecaps;

    for( SYMCRYPT_TEST_MLKEM_PARAMS testParams : rgTestMlKemParams )
    {
        SYMCRYPT_MLKEM_PARAMS params = testParams.params;
        PSYMCRYPT_MLKEMKEY pKey = SymCryptMlKemkeyAllocate( params );
        CHECK( pKey != NULL, "SymCryptMlKemkeyAllocate failed" );

        keyTestBlobFull.params = params;
        scError = SymCryptMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, &keyTestBlobFull.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED failed with 0x%x", scError );

        GENRANDOM( keyTestBlobFull.abKeyBlob, (UINT32) keyTestBlobFull.cbKeyBlob );

        scError = SymCryptMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &keyTestBlobDecaps.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY failed with 0x%x", scError );

        keyTestBlobDecaps.params = params;

        scError = SymCryptMlKemkeySetValue(
                    &(keyTestBlobFull.abKeyBlob[0]), keyTestBlobFull.cbKeyBlob,
                    SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
                    0,
                    pKey);
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemkeySetValue SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED failed with 0x%x", scError );

        scError = SymCryptMlKemkeyGetValue(
                    pKey,
                    &(keyTestBlobDecaps.abKeyBlob[0]), keyTestBlobDecaps.cbKeyBlob,
                    SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
                    0);
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemkeyGetValue SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY failed with 0x%x", scError );

        // ML-KEM decaps key blob format is [ s || t || public seed || H(encaps key) || z ]
        SIZE_T decapsPublicSeedOffset = keyTestBlobDecaps.cbKeyBlob - SYMCRYPT_TEST_MLKEM_SIZEOF_Z
                                                                    - SYMCRYPT_TEST_MLKEM_SIZEOF_ENCAPS_HASH
                                                                    - SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED;
        UINT32 t = g_rng.uint32();
        UINT32 byteIndex = t % SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED;
        UINT32 bitIndex = t % 8;

        keyTestBlobDecaps.abKeyBlob[ decapsPublicSeedOffset + byteIndex ] ^= 1 << bitIndex;
        scError = SymCryptMlKemkeySetValue(
                    &(keyTestBlobDecaps.abKeyBlob[0]), keyTestBlobDecaps.cbKeyBlob,
                    SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
                    0,
                    pKey);
        CHECK3( scError == SYMCRYPT_INVALID_BLOB, "SymCryptMlKemkeySetValue with corrupted public seed got something other than SYMCRYPT_INVALID_BLOB: 0x%x", scError );

        SymCryptMlKemkeyFree( pKey );
    }
}

VOID
testSymCryptMlKemNegativeTests()
{
    SymCryptKemNegativeTestConfig<MlKemDef> config = {
        &g_MlKemFunctionTable,
        rgTestMlKemParams,
        NUM_OF_MLKEM_TEST_PARAMS,
    };

    testSymCryptKemNegativeTests<MlKemDef>( config );

    testSymCryptMlKemSetInvalidDecapsKeyBlob();
}

// Main purpose of this test is to check that setting a corrupted key blob
// does not leave the internal representation in a broken state such that
// subsequent correct SetValue calls fail.
VOID
testSymCryptCompositeMlKemCorruptEcPrivateKey()
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_COMPOSITE_MLKEMKEY pKey;
    BYTE abPrivateKeyBlob[CompositeMlKemDef::MaxDecapsKeyBlobSize];
    BYTE abSharedSecret[CompositeMlKemDef::AgreedSecretSize];
    BYTE abDecapsSecret[CompositeMlKemDef::AgreedSecretSize];
    BYTE abCiphertext[CompositeMlKemDef::MaxCiphertextSize];
    SIZE_T cbPrivateKey = 0;
    SIZE_T cbCiphertext = 0;

    for( UINT32 paramIdx = 0; paramIdx < NUM_OF_COMPOSITE_MLKEM_TEST_PARAMS; paramIdx++ )
    {
        SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS testParams = rgTestCompositeMlKemParams[paramIdx];
        SYMCRYPT_COMPOSITE_MLKEM_PARAMS params = testParams.params;

        // Skip X25519 since LAMPS private key format uses raw scalar with no special encoding
        if( testParams.curveId == SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 )
        {
            continue;
        }

        scError = SymCryptCompositeMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, &cbPrivateKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = SymCryptCompositeMlKemSizeofCiphertextFromParams( params, &cbCiphertext );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        pKey = SymCryptCompositeMlKemkeyAllocate( params );
        CHECK( pKey != NULL, "?" );

        scError = SymCryptCompositeMlKemkeyGenerate( pKey, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = SymCryptCompositeMlKemkeyGetValue( pKey, abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        // Corrupt ASN.1 sequence tag byte of the EC private key
        SIZE_T cbEcSkOffset = cbPrivateKey - SymCryptCompositeGetSizeOfEncodedEcSk( testParams.curveId );
        abPrivateKeyBlob[cbEcSkOffset] ^= 0xFF;

        scError = SymCryptCompositeMlKemkeySetValue( abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0, pKey );
        CHECK3( scError != SYMCRYPT_NO_ERROR,
            "SetValue with corrupted EC private key ASN.1 header should fail for param %s", testParams.pszParamsName );

        abPrivateKeyBlob[cbEcSkOffset] ^= 0xFF;  // Restore ASN.1 sequence tag byte
        scError = SymCryptCompositeMlKemkeySetValue( abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0, pKey );
        CHECK3( scError == SYMCRYPT_NO_ERROR,
            "SetValue should succeed after prior failure for param %s", testParams.pszParamsName );

        // Verify the key is usable
        scError = SymCryptCompositeMlKemEncapsulate( pKey, abSharedSecret, CompositeMlKemDef::AgreedSecretSize, abCiphertext, cbCiphertext );
        CHECK3( scError == SYMCRYPT_NO_ERROR,
            "Encapsulate should succeed after recovery for param %s", testParams.pszParamsName );

        scError = SymCryptCompositeMlKemDecapsulate( pKey, abCiphertext, cbCiphertext, abDecapsSecret, CompositeMlKemDef::AgreedSecretSize );
        CHECK3( scError == SYMCRYPT_NO_ERROR,
            "Decapsulate should succeed after recovery for param %s", testParams.pszParamsName );

        CHECK3( memcmp( abSharedSecret, abDecapsSecret, CompositeMlKemDef::AgreedSecretSize ) == 0,
            "Shared secrets should match after recovery for param %s", testParams.pszParamsName );

        SymCryptCompositeMlKemkeyFree( pKey );
        pKey = NULL;
    }
}

VOID
testSymCryptCompositeMlKemNegativeTests()
{
    SymCryptKemNegativeTestConfig<CompositeMlKemDef> config = {
        &g_CompositeMlKemFunctionTable,
        rgTestCompositeMlKemParams,
        NUM_OF_COMPOSITE_MLKEM_TEST_PARAMS,
    };

    testSymCryptKemNegativeTests<CompositeMlKemDef>( config );

    testSymCryptCompositeMlKemCorruptEcPrivateKey();
}

////////////////////////////////////////////////
// KATS testing
////////////////////////////////////////////////

template<typename KemDef>
struct KemKatTester
{
    protected:
        using TestParamsType = typename KemDef::TestParamsType;
        using ParamsType     = typename KemDef::ParamsType;
        using FormatType     = typename KemDef::FormatType;
        using TestBlobType   = typename KemDef::TestBlobType;

        const char* algName;
        char* katResourceName;
        char* katResourceType;
        const TestParamsType* rgTestParams;
        const SIZE_T cTestParams;

        KemKatTester(
            const char* algName_,
            char* katResourceName_,
            char* katResourceType_,
            const TestParamsType* rgTestParams_,
            SIZE_T cTestParams_ ) :

            algName( algName_ ),
            katResourceName( katResourceName_ ),
            katResourceType( katResourceType_ ),
            rgTestParams( rgTestParams_ ),
            cTestParams( cTestParams_ )
        {}

        virtual void testKeyGen( KemImplementation* pImpl, TestParamsType testParams, KAT_ITEM& katItem, ULONGLONG line ) = 0;
        virtual void testEncaps( KemImplementation* pImpl, TestParamsType testParams, KAT_ITEM& katItem, ULONGLONG line ) = 0;
        virtual void testDecaps( KemImplementation* pImpl, TestParamsType testParams, KAT_ITEM& katItem, ULONGLONG line );

    public:
        virtual ~KemKatTester() {}
        void runKatTests();
};

//
// Default functions
//

template <typename KemDef>
VOID
KemKatTester<KemDef>::runKatTests()
{
    std::unique_ptr<KatData> katData( getCustomResource( katResourceName, katResourceType ) );
    KAT_ITEM katItem;

    String sep = "";
    UINT32 cKeyGen = 0;
    UINT32 cEncaps = 0;
    UINT32 cDecaps = 0;
    TestParamsType testParams = {};
    BOOLEAN bParamsFound = FALSE;

    SIZE_T i;

    std::unique_ptr<KemMultiImp> pKemMultiImp( new KemMultiImp( algName ) );

    while( 1 )
    {
        katData->getKatItem( &katItem );
        ULONGLONG line = katItem.line;

        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            // We never skip data and the algorithm is
            // specified by the data item.
            iprint( "%s%s", sep.c_str(), katItem.categoryName.c_str() );
            sep = ", ";

            bParamsFound = FALSE;
            for( i=0; i < cTestParams; i++ )
            {
                // Compare with the category name with known ML-KEM params
                if ( strcmp( katItem.categoryName.c_str(), rgTestParams[i].pszParamsName ) == 0 )
                {
                    bParamsFound = TRUE;
                    break;
                }
            }
            CHECK3( bParamsFound, "KEM header at line %lld specifies unknown KAT KEM params!", line) ;

            testParams = rgTestParams[i];
        }

        if( katItem.type == KAT_TYPE_DATASET )
        {
            if( katIsFieldPresent( katItem, "z" ) )
            {
                testKeyGen( pKemMultiImp.get(), testParams, katItem, line );
                cKeyGen++;
            }
            else if( katIsFieldPresent( katItem, "ek" ) )
            {
                testEncaps( pKemMultiImp.get(), testParams, katItem, line );
                cEncaps++;
            }
            else if( katIsFieldPresent( katItem, "dk" ) )
            {
                testDecaps( pKemMultiImp.get(), testParams, katItem, line );
                cDecaps++;
            }
            else
            {
                FATAL2( "Unknown data record at line %lld", line );
            }
        }
    }

    iprint( "\n        Total samples: %d KeyGen, %d Encaps, %d Decaps\n", cKeyGen, cEncaps, cDecaps );
}

 template <typename KemDef>
 VOID
 KemKatTester<KemDef>::testDecaps(
        _In_ KemImplementation* pImpl,
        TestParamsType testParams,
        _Inout_ KAT_ITEM& katItem,
        ULONGLONG line )
{
    CHECK3( katItem.dataItems.size() == 3, "Wrong number of items in KEM Decapsulation record at line %lld", line );

    BString katDecapsKeyBlob = katParseData( katItem, "dk" );
    BString katCipherText    = katParseData( katItem, "c" );
    BString katAgreedSecret  = katParseData( katItem, "k" );

    NTSTATUS ntStatus;
    BYTE abComputedAgreedSecret[KemDef::AgreedSecretSize];
    BYTE abExportedDecapsKeyBlob[KemDef::MaxDecapsKeyBlobSize];
    TestBlobType keyTestBlob;

    CHECK( katAgreedSecret.size() <= sizeof(abComputedAgreedSecret), "?" );
    CHECK( katDecapsKeyBlob.size() <= sizeof(keyTestBlob.abKeyBlob), "?" );

    keyTestBlob.params = testParams.params;
    keyTestBlob.format = KemDef::FormatDecaps;
    memcpy( keyTestBlob.abKeyBlob, katDecapsKeyBlob.data(), katDecapsKeyBlob.size() );
    keyTestBlob.cbKeyBlob = katDecapsKeyBlob.size();

    ntStatus = pImpl->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), TRUE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob at line %lld", line );

    ntStatus = pImpl->decapsulate(
        katCipherText.data(), katCipherText.size(),
        abComputedAgreedSecret, katAgreedSecret.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in decapsulate at line %lld", line );
    CHECK3( memcmp( katAgreedSecret.data(), abComputedAgreedSecret, katAgreedSecret.size() ) == 0,
            "Agreed Secret doesn't match at line %lld", line );

    // Sanity check that exporting the decaps key matches the original blob
    ntStatus = pImpl->getBlobFromKey( KemDef::FormatDecaps, abExportedDecapsKeyBlob, katDecapsKeyBlob.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure exporting decapsulation key blob at line %lld", line );
    CHECK3( memcmp( katDecapsKeyBlob.data(), abExportedDecapsKeyBlob, katDecapsKeyBlob.size() ) == 0,
            "Exported decapsulation key doesn't match original at line %lld", line );

    CHECK( pImpl->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

//
// ML-KEM KAT tester definitions
//

struct MlKemKatTester : KemKatTester<MlKemDef>
{
    MlKemKatTester() :
        KemKatTester<MlKemDef>(
            "MlKem",
            "kat_kem.dat",
            "KAT_KEM",
            rgTestMlKemParams,
            NUM_OF_MLKEM_TEST_PARAMS )
    {}

    VOID testKeyGen( KemImplementation* pImpl, SYMCRYPT_TEST_MLKEM_PARAMS testParams, KAT_ITEM& katItem, ULONGLONG line ) override;
    VOID testEncaps( KemImplementation* pImpl, SYMCRYPT_TEST_MLKEM_PARAMS testParams, KAT_ITEM& katItem, ULONGLONG line ) override;
};

VOID
MlKemKatTester::testKeyGen(
        KemImplementation*          pKemImplementation,
        SYMCRYPT_TEST_MLKEM_PARAMS  testParams,
        KAT_ITEM&                   katItem,
        ULONGLONG                   line )
{
    NTSTATUS ntStatus;
    BYTE abComputedEncapsKeyBlob[MlKemDef::MaxEncapsKeyBlobSize];
    BYTE abComputedDecapsKeyBlob[MlKemDef::MaxDecapsKeyBlobSize];
    MLKEMKEY_TESTBLOB keyTestBlob;

    CHECK3( katItem.dataItems.size() == 4, "Wrong number of items in KEM KeyGen record at line %lld", line );

    BString katPrivateRandom  = katParseData( katItem, "z" );
    BString katPrivateSeed    = katParseData( katItem, "d" );
    BString katEncapsKeyBlob  = katParseData( katItem, "ek" );
    BString katDecapsKeyBlob  = katParseData( katItem, "dk" );

    CHECK( katPrivateSeed.size() == 32, "?" );
    CHECK( katPrivateRandom.size() == 32, "?" );

    keyTestBlob.params = testParams.params;
    keyTestBlob.format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    memcpy( keyTestBlob.abKeyBlob, katPrivateSeed.data(), katPrivateSeed.size() );
    memcpy( keyTestBlob.abKeyBlob + katPrivateSeed.size(), katPrivateRandom.data(), katPrivateRandom.size() );
    keyTestBlob.cbKeyBlob = 64;

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), TRUE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, abComputedEncapsKeyBlob, katEncapsKeyBlob.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob for ML-KEM record at line %lld", line);
    CHECK3( memcmp( katEncapsKeyBlob.data(), abComputedEncapsKeyBlob, katEncapsKeyBlob.size() ) == 0, "Encapsulation Key doesn't match for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, abComputedDecapsKeyBlob, katDecapsKeyBlob.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob for ML-KEM record at line %lld", line);
    CHECK3( memcmp( katDecapsKeyBlob.data(), abComputedDecapsKeyBlob, katDecapsKeyBlob.size() ) == 0, "Decapsulation Key doesn't match for ML-KEM record at line %lld", line);

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
MlKemKatTester::testEncaps(
    KemImplementation*          pKemImplementation,
    SYMCRYPT_TEST_MLKEM_PARAMS  testParams,
    KAT_ITEM&                   katItem,
    ULONGLONG                   line )
{
    CHECK3( katItem.dataItems.size() == 4, "Wrong number of items in KEM Encapsulation record at line %lld", line );

    BString katEncapsKeyBlob = katParseData( katItem, "ek" );
    BString katInputRandom   = katParseData( katItem, "m" );
    BString katAgreedSecret  = katParseData( katItem, "k" );
    BString katCipherText    = katParseData( katItem, "c" );

    NTSTATUS ntStatus;
    BYTE abComputedAgreedSecret[MlKemDef::AgreedSecretSize];
    BYTE abComputedCiphertext[MlKemDef::MaxCiphertextSize];
    MLKEMKEY_TESTBLOB keyTestBlob;

    CHECK( katAgreedSecret.size() <= sizeof(abComputedAgreedSecret), "?" );
    CHECK( katCipherText.size() <= sizeof(abComputedCiphertext), "?" );
    CHECK( katEncapsKeyBlob.size() <= sizeof(keyTestBlob.abKeyBlob), "?" );

    keyTestBlob.params = testParams.params;
    keyTestBlob.format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    memcpy( keyTestBlob.abKeyBlob, katEncapsKeyBlob.data(), katEncapsKeyBlob.size() );
    keyTestBlob.cbKeyBlob = katEncapsKeyBlob.size();

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), FALSE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob at line %lld", line );

    ntStatus = pKemImplementation->encapsulateEx(
                                    katInputRandom.data(), katInputRandom.size(),
                                    abComputedAgreedSecret, katAgreedSecret.size(),
                                    abComputedCiphertext, katCipherText.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in encapsulateEx at line %lld", line );
    CHECK3( memcmp( katAgreedSecret.data(), abComputedAgreedSecret, katAgreedSecret.size() ) == 0,
            "Agreed Secret doesn't match at line %lld", line );
    CHECK3( memcmp( katCipherText.data(), abComputedCiphertext, katCipherText.size() ) == 0,
            "Ciphertext doesn't match at line %lld", line );

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

//
// Composite ML-KEM KAT tester definitions
//

struct CompositeMlKemKatTester : KemKatTester<CompositeMlKemDef>
{
    CompositeMlKemKatTester() :
        KemKatTester<CompositeMlKemDef>(
            "CompositeMlKem",
            "kat_composite_kem.dat",
            "KAT_COMPOSITE_KEM",
            rgTestCompositeMlKemParams,
            NUM_OF_COMPOSITE_MLKEM_TEST_PARAMS )
    {}

    VOID testKeyGen( KemImplementation* pKemImplementation, SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS testParams, KAT_ITEM& katItem, ULONGLONG line ) override;
    VOID testEncaps( KemImplementation* pKemImplementation, SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS testParams, KAT_ITEM& katItem, ULONGLONG line ) override;
};

VOID
CompositeMlKemKatTester::testEncaps(
    KemImplementation*                      pKemImplementation,
    SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS    testParams,
    KAT_ITEM&                               katItem,
    ULONGLONG                               line )
{
    // Currently LAMPS doesn't have randomness in the test vectors,
    // so we can only verify the success of the encapsulation operation.

    CHECK3( katItem.dataItems.size() == 1, "Wrong number of items in Composite KEM Encapsulation record at line %lld", line );

    BString katEncapsKeyBlob = katParseData( katItem, "ek" );

    NTSTATUS ntStatus;
    BYTE abComputedAgreedSecret[CompositeMlKemDef::AgreedSecretSize];
    BYTE abComputedCiphertext[CompositeMlKemDef::MaxCiphertextSize];
    COMPOSITE_MLKEMKEY_TESTBLOB keyTestBlob;
    SIZE_T cbCipherText = 0;
    SIZE_T cbAgreedSecret = CompositeMlKemDef::AgreedSecretSize;

    SymCryptCompositeMlKemSizeofCiphertextFromParams( testParams.params, &cbCipherText );

    CHECK( cbAgreedSecret <= sizeof(abComputedAgreedSecret), "?" );
    CHECK( cbCipherText <= sizeof(abComputedCiphertext), "?" );
    CHECK( katEncapsKeyBlob.size() <= sizeof(keyTestBlob.abKeyBlob), "?" );

    keyTestBlob.params = testParams.params;
    keyTestBlob.format = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY;
    memcpy( keyTestBlob.abKeyBlob, katEncapsKeyBlob.data(), katEncapsKeyBlob.size() );
    keyTestBlob.cbKeyBlob = katEncapsKeyBlob.size();

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), FALSE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob for Composite ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->encapsulate(
                abComputedAgreedSecret, cbAgreedSecret,
                abComputedCiphertext, cbCipherText );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in encapsulate for Composite ML-KEM record at line %lld", line);

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
CompositeMlKemKatTester::testKeyGen(
        KemImplementation*                      pKemImplementation,
        SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS    testParams,
        KAT_ITEM&                               katItem,
        ULONGLONG                               line )
{
    CHECK3( katItem.dataItems.size() == 5, "Wrong number of items in Composite KEM KeyGen record at line %lld", line );

    BString katPrivateRandom = katParseData( katItem, "z" );
    BString katPrivateSeed   = katParseData( katItem, "d" );
    BString katEncapsKeyBlob = katParseData( katItem, "ek" );
    BString katCipherText    = katParseData( katItem, "c" );
    BString katAgreedSecret  = katParseData( katItem, "k" );

    NTSTATUS ntStatus;
    SYMCRYPT_ERROR scError;
    BYTE abComputedEncapsKeyBlob[CompositeMlKemDef::MaxEncapsKeyBlobSize];
    BYTE abComputedCipherText[CompositeMlKemDef::MaxCiphertextSize];
    BYTE abComputedAgreedSecret[CompositeMlKemDef::AgreedSecretSize];
    BYTE abComputedIrtfSeed[32];
    COMPOSITE_MLKEMKEY_TESTBLOB keyTestBlob;

    SIZE_T cbMlKemRandom = 32;
    SYMCRYPT_NUMBER_FORMAT ecNumFormat;
    PCSYMCRYPT_ECURVE pCurve = SymCryptGetCachedEcurve( testParams.curveId );

    CHECK( pCurve != NULL, "Failed to get curve for Composite ML-KEM" );

    SIZE_T cbScalar = SymCryptEcurveSizeofScalarMultiplier( pCurve );
    BYTE abEncapsRandom[32 + 48];

    CHECK( katEncapsKeyBlob.size() <= sizeof(abComputedEncapsKeyBlob), "?" );
    CHECK( katCipherText.size() <= sizeof(abComputedCipherText), "?" );
    CHECK( katAgreedSecret.size() <= sizeof(abComputedAgreedSecret), "?" );
    CHECK3( katPrivateSeed.size() == 32, "Unexpected private seed size for Composite ML-KEM record at line %lld", line );
    CHECK3( katAgreedSecret.size() == CompositeMlKemDef::AgreedSecretSize, "Unexpected agreed secret size for Composite ML-KEM record at line %lld", line );
    CHECK( cbMlKemRandom + cbScalar <= sizeof(abEncapsRandom), "?" );

    // Generate key from IRTF private seed and verify encapsulation key matches

    keyTestBlob.params = testParams.params;
    keyTestBlob.format = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED;
    memcpy( keyTestBlob.abKeyBlob, katPrivateSeed.data(), katPrivateSeed.size() );
    keyTestBlob.cbKeyBlob = katPrivateSeed.size();

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), TRUE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from IRTF private seed for Composite ML-KEM record at line %lld", line );

    // Sanity check: verify that getting the IRTF seed matches the original KAT seed
    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED, abComputedIrtfSeed, katPrivateSeed.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting IRTF private seed for Composite ML-KEM record at line %lld", line );
    CHECK3( memcmp( katPrivateSeed.data(), abComputedIrtfSeed, katPrivateSeed.size() ) == 0,
            "IRTF private seed doesn't match for Composite ML-KEM record at line %lld", line );

    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY, abComputedEncapsKeyBlob, katEncapsKeyBlob.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob for Composite ML-KEM record at line %lld", line );
    CHECK3( memcmp( katEncapsKeyBlob.data(), abComputedEncapsKeyBlob, katEncapsKeyBlob.size() ) == 0,
            "Encapsulation key doesn't match for Composite ML-KEM record at line %lld", line );

    // Convert the randomness into the format expected by encapsulateEx, and then
    // check our computed ciphertext and agreed secret against the KAT values

    memcpy( abEncapsRandom, katPrivateRandom.data(), cbMlKemRandom );

    switch ( testParams.curveId )
    {
        case SYMCRYPT_CACHED_ECURVE_ID_NIST_P256:
        case SYMCRYPT_CACHED_ECURVE_ID_NIST_P384:
            ecNumFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            break;
        case SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519:
            // Technically ignored for getting a random scalar
            // for Curve25519, but set it for correctness.
            ecNumFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            break;
        default:
            CHECK( FALSE, "Unsupported curve for Composite ML-KEM KAT" );
    }

    scError = SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
                testParams.curveId,
                ecNumFormat,
                katPrivateRandom.data() + cbMlKemRandom,
                katPrivateRandom.size() - cbMlKemRandom,
                abEncapsRandom + cbMlKemRandom,
                cbScalar );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "GetRandomScalarForEcKey failed for Composite ML-KEM record at line %lld", line );

    ntStatus = pKemImplementation->encapsulateEx(
        abEncapsRandom, cbMlKemRandom + cbScalar,
        abComputedAgreedSecret, katAgreedSecret.size(),
        abComputedCipherText, katCipherText.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in encapsulateEx for Composite ML-KEM record at line %lld", line );
    CHECK3( memcmp( katCipherText.data(), abComputedCipherText, katCipherText.size() ) == 0,
            "Ciphertext doesn't match for Composite ML-KEM record at line %lld", line );
    CHECK3( memcmp( katAgreedSecret.data(), abComputedAgreedSecret, katAgreedSecret.size() ) == 0,
            "Agreed secret from encapsulateEx doesn't match for Composite ML-KEM record at line %lld", line );

    // Decapsulate provided ciphertext and check that the computed agreed secret matches the provided value

    ntStatus = pKemImplementation->decapsulate(
        katCipherText.data(), katCipherText.size(),
        abComputedAgreedSecret, katAgreedSecret.size() );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in decapsulate for Composite ML-KEM record at line %lld", line );
    CHECK3( memcmp( katAgreedSecret.data(), abComputedAgreedSecret, katAgreedSecret.size() ) == 0,
            "Agreed secret from decapsulate doesn't match for Composite ML-KEM record at line %lld", line );

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testCompositeMlKemKats()
{
    CompositeMlKemKatTester katTester;
    katTester.runKatTests();
}

VOID
testMlKemKats()
{
    MlKemKatTester katTester;
    katTester.runKatTests();
}

VOID
testKem()
{
    INT64 nOutstandingAllocs = 0;

    if ( !isAlgorithmPresent( "CompositeMlKem", TRUE ) && !isAlgorithmPresent( "MlKem", TRUE ) )
    {
        return;
    }

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs  == 0, "Memory leak %d outstanding", nOutstandingAllocs );

    if ( isAlgorithmPresent( "CompositeMlKem", TRUE ) )
    {
        iprint( "    Composite ML-KEM\n" );

        testCompositeMlKemKats();
        testCompositeMlKemHighLevelAPI();
        testSymCryptCompositeMlKemNegativeTests();

        iprint("\n");
    }

    if ( isAlgorithmPresent( "MlKem", TRUE ) )
    {
        iprint( "    ML-KEM\n" );

        testMlKemKats();

        #if SYMCRUST_EXPERIMENTAL_BUILD == 0
            testMlKemArithmetic();
        #endif

        testMlKemHighLevelAPI();
        testSymCryptMlKemNegativeTests();

        iprint("\n");
    }

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );
}