//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

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
    BYTE abEncapsCiphertext[1569];
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
    BYTE abEncapsCiphertext[1569];
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

VOID
testMlKemHighLevelAPI()
{
    std::unique_ptr<KemMultiImp> pKemImplementation(new KemMultiImp( "MlKem" ));

    NTSTATUS ntStatus;
    SYMCRYPT_ERROR scError;
    UINT32 i;
    
    MLKEMKEY_TESTBLOB keyTestBlobFull;
    MLKEMKEY_TESTBLOB keyTestBlobDecaps;
    MLKEMKEY_TESTBLOB keyTestBlobEncaps;

    BYTE abCipherText[1568];
    BYTE abAgreedSecretEncaps[32];
    BYTE abAgreedSecretDecaps[32];
    SIZE_T cbCipherText;

    keyTestBlobFull.format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    keyTestBlobDecaps.format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    keyTestBlobEncaps.format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;

    for( SYMCRYPT_TEST_MLKEM_PARAMS testParams : rgTestMlKemParams )
    {
        SYMCRYPT_MLKEM_PARAMS params = testParams.params;

        keyTestBlobFull.params   = params;
        keyTestBlobDecaps.params = params;
        keyTestBlobEncaps.params = params;

        scError = SymCryptMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, &keyTestBlobFull.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED failed with 0x%x", scError );
        CHECK( keyTestBlobFull.cbKeyBlob <= sizeof(keyTestBlobFull.abKeyBlob), "?" );

        scError = SymCryptMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &keyTestBlobDecaps.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY failed with 0x%x", scError );
        CHECK( keyTestBlobDecaps.cbKeyBlob <= sizeof(keyTestBlobDecaps.abKeyBlob), "?" );

        scError = SymCryptMlKemSizeofKeyFormatFromParams( params, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, &keyTestBlobEncaps.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY failed with 0x%x", scError );
        CHECK( keyTestBlobEncaps.cbKeyBlob <= sizeof(keyTestBlobEncaps.abKeyBlob), "?" );

        scError = SymCryptMlKemSizeofCiphertextFromParams( params, &cbCipherText );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofCiphertextFromParams failed with 0x%x", scError );
        CHECK( cbCipherText <= sizeof(abCipherText), "?" );

        for( i=0; i<100; i++ )
        {
            GENRANDOM( keyTestBlobFull.abKeyBlob, (UINT32) keyTestBlobFull.cbKeyBlob );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, keyTestBlobDecaps.abKeyBlob, keyTestBlobDecaps.cbKeyBlob );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob from full key");
            
            ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, keyTestBlobEncaps.abKeyBlob, keyTestBlobEncaps.cbKeyBlob );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob from full key");

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, sizeof(abAgreedSecretEncaps), abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with full key");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with full key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (full key) and decaps (full key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with full key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (full key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, sizeof(abAgreedSecretEncaps), abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with decapsulation key");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with decapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (decaps key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with decapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (decaps key) and decaps (full key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobEncaps, sizeof(keyTestBlobEncaps), FALSE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob");

            ntStatus = pKemImplementation->encapsulate( abAgreedSecretEncaps, sizeof(abAgreedSecretEncaps), abCipherText, cbCipherText );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in encapsulate with encapsulation key");

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with encapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (encaps key) and decaps (decaps key)" );

            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobFull, sizeof(keyTestBlobFull), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with encapsulation key)");
            CHECK( memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) == 0, "Agreed secret mismatch between encaps (encaps key) and decaps (full key)" );

            // modify the ciphertext and verify errors
            // either should induce an error (modification meant that value was publicly malformed), or success with implicit rejection value != to encaps secret
            UINT32 t = g_rng.uint32();
            abCipherText[ (t/8) % cbCipherText ] ^= 1 << (t%8);

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( (ntStatus != STATUS_SUCCESS) || memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) != 0, "Modified ciphertext does not cause failure" );
            
            ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlobDecaps, sizeof(keyTestBlobDecaps), TRUE );
            CHECK( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = pKemImplementation->decapsulate( abCipherText, cbCipherText, abAgreedSecretDecaps, sizeof(abAgreedSecretDecaps) );
            CHECK( (ntStatus != STATUS_SUCCESS) || memcmp(abAgreedSecretEncaps, abAgreedSecretDecaps, sizeof(abAgreedSecretEncaps)) != 0, "Modified ciphertext does not cause failure" );
        }
    }
    
    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testMlKemKeyGen(
        KemImplementation*      pKemImplementation,
        SYMCRYPT_MLKEM_PARAMS   params,
    _In_reads_( cbPrivateRandom )
        PCBYTE                  pbPrivateRandom,
        SIZE_T                  cbPrivateRandom,
    _In_reads_( cbPrivateSeed )
        PCBYTE                  pbPrivateSeed,
        SIZE_T                  cbPrivateSeed,
    _In_reads_( cbEncapsKeyBlob )
        PCBYTE                  pbEncapsKeyBlob,
        SIZE_T                  cbEncapsKeyBlob,
    _In_reads_( cbDecapsKeyBlob )
        PCBYTE                  pbDecapsKeyBlob,
        SIZE_T                  cbDecapsKeyBlob,
        ULONGLONG               line )
{
    NTSTATUS ntStatus;
    BYTE abComputedEncapsKeyBlob[1568];
    BYTE abComputedDecapsKeyBlob[3168];
    MLKEMKEY_TESTBLOB keyTestBlob;

    CHECK( cbPrivateSeed == 32, "?" );
    CHECK( cbPrivateRandom == 32, "?" );

    keyTestBlob.params = params;
    keyTestBlob.format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    memcpy( keyTestBlob.abKeyBlob, pbPrivateSeed, 32 );
    memcpy( keyTestBlob.abKeyBlob+32, pbPrivateRandom, 32 );
    keyTestBlob.cbKeyBlob = 64;

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), TRUE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from private seed for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, abComputedEncapsKeyBlob, cbEncapsKeyBlob );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob for ML-KEM record at line %lld", line);
    CHECK3( memcmp( pbEncapsKeyBlob, abComputedEncapsKeyBlob, cbEncapsKeyBlob ) == 0, "Encapsulation Key doesn't match for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->getBlobFromKey( SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, abComputedDecapsKeyBlob, cbDecapsKeyBlob );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob for ML-KEM record at line %lld", line);
    CHECK3( memcmp( pbDecapsKeyBlob, abComputedDecapsKeyBlob, cbDecapsKeyBlob ) == 0, "Decapsulation Key doesn't match for ML-KEM record at line %lld", line);

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testMlKemEncaps(
        KemImplementation*      pKemImplementation,
        SYMCRYPT_MLKEM_PARAMS   params,
    _In_reads_( cbEncapsKeyBlob )
        PCBYTE                  pbEncapsKeyBlob,
        SIZE_T                  cbEncapsKeyBlob,
    _In_reads_( cbInputRandom )
        PCBYTE                  pbInputRandom,
        SIZE_T                  cbInputRandom,
    _In_reads_( cbAgreedSecret )
        PCBYTE                  pbAgreedSecret,
        SIZE_T                  cbAgreedSecret,
    _In_reads_( cbCipherText )
        PCBYTE                  pbCipherText,
        SIZE_T                  cbCipherText,
        ULONGLONG               line )
{
    NTSTATUS ntStatus;
    BYTE abComputedAgreedSecret[32];
    BYTE abComputedCiphertext[1568];
    MLKEMKEY_TESTBLOB keyTestBlob;

    CHECK( cbAgreedSecret <= sizeof(abComputedAgreedSecret), "?" );
    CHECK( cbCipherText <= sizeof(abComputedCiphertext), "?" );
    CHECK( cbEncapsKeyBlob <= sizeof(keyTestBlob.abKeyBlob), "?" );

    keyTestBlob.params = params;
    keyTestBlob.format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    memcpy( keyTestBlob.abKeyBlob, pbEncapsKeyBlob, cbEncapsKeyBlob );
    keyTestBlob.cbKeyBlob = cbEncapsKeyBlob;

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), FALSE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->encapsulateEx(
        pbInputRandom, cbInputRandom,
        abComputedAgreedSecret, cbAgreedSecret,
        abComputedCiphertext, cbCipherText );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in encapsulateEx for ML-KEM record at line %lld", line);
    CHECK3( memcmp( pbAgreedSecret, abComputedAgreedSecret, cbAgreedSecret ) == 0, "Agreed Secret doesn't match for ML-KEM record at line %lld", line);
    CHECK3( memcmp( pbCipherText, abComputedCiphertext, cbCipherText ) == 0, "Ciphertext doesn't match for ML-KEM record at line %lld", line);

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testMlKemDecaps(
        KemImplementation*      pKemImplementation,
        SYMCRYPT_MLKEM_PARAMS   params,
    _In_reads_( cbDecapsKeyBlob )
        PCBYTE                  pbDecapsKeyBlob,
        SIZE_T                  cbDecapsKeyBlob,
    _In_reads_( cbCipherText )
        PCBYTE                  pbCipherText,
        SIZE_T                  cbCipherText,
    _In_reads_( cbAgreedSecret )
        PCBYTE                  pbAgreedSecret,
        SIZE_T                  cbAgreedSecret,
        ULONGLONG               line )
{
    NTSTATUS ntStatus;
    BYTE abComputedAgreedSecret[32];
    MLKEMKEY_TESTBLOB keyTestBlob;

    CHECK( cbAgreedSecret <= sizeof(abComputedAgreedSecret), "?" );
    CHECK( cbDecapsKeyBlob <= sizeof(keyTestBlob.abKeyBlob), "?" );

    keyTestBlob.params = params;
    keyTestBlob.format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    memcpy( keyTestBlob.abKeyBlob, pbDecapsKeyBlob, cbDecapsKeyBlob );
    keyTestBlob.cbKeyBlob = cbDecapsKeyBlob;

    ntStatus = pKemImplementation->setKeyFromTestBlob( (PCBYTE) &keyTestBlob, sizeof(keyTestBlob), TRUE );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob for ML-KEM record at line %lld", line);

    ntStatus = pKemImplementation->decapsulate(
        pbCipherText, cbCipherText,
        abComputedAgreedSecret, cbAgreedSecret );
    CHECK3( ntStatus == STATUS_SUCCESS, "Failure in decapsulate for ML-KEM record at line %lld", line);
    CHECK3( memcmp( pbAgreedSecret, abComputedAgreedSecret, cbAgreedSecret ) == 0, "Agreed Secret doesn't match for ML-KEM record at line %lld", line);

    CHECK( pKemImplementation->setKeyFromTestBlob( NULL, 0, FALSE ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testKemKats()
{
    std::unique_ptr<KatData> katMlKem( getCustomResource( "kat_kem.dat", "KAT_KEM" ) );
    KAT_ITEM katItem;

    String sep = "";

    SIZE_T i = 0;
    BOOLEAN bParamsFound = FALSE;

    // NOTE - currently only supporting ML-KEM KATs; need to move to generic KEM params
    SYMCRYPT_MLKEM_PARAMS params = SYMCRYPT_MLKEM_PARAMS_NULL;

    UINT32 cKemKeyGenSamples = 0;
    UINT32 cKemEncapsSamples = 0;
    UINT32 cKemDecapsSamples = 0;

    // For now we only support one Kem algorithm
    // We can reset this multi-imp pointer based on category in the future
    std::unique_ptr<KemMultiImp> pKemMultiImp(new KemMultiImp( "MlKem" ));

    while( 1 )
    {
        katMlKem->getKatItem( & katItem );
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
            for( i=0; i < NUM_OF_MLKEM_TEST_PARAMS; i++ )
            {
                // Compare with the category name with known ML-KEM params
                if ( strcmp( katItem.categoryName.c_str(), rgTestMlKemParams[i].pszParamsName ) == 0 )
                {
                    bParamsFound = TRUE;
                    break;
                }
            }
            CHECK3( bParamsFound, "KEM header at line %lld specifies unknown KAT KEM params!", line) ;
            
            params = rgTestMlKemParams[i].params;
        }

        if( katItem.type == KAT_TYPE_DATASET )
        {
            
            if (katIsFieldPresent( katItem, "z" ) )
            {
                //
                // KeyGen
                //
                CHECK3( katItem.dataItems.size() == 4, "Wrong number of items in KEM KeyGen record at line %lld", line );

                BString katPrivateRandom = katParseData( katItem, "z" );
                BString katPrivateSeed   = katParseData( katItem, "d" );
                BString katEncapsKeyBlob = katParseData( katItem, "ek" );
                BString katDecapsKeyBlob = katParseData( katItem, "dk" );

                testMlKemKeyGen(
                    pKemMultiImp.get(),
                    params,
                    katPrivateRandom.data(), katPrivateRandom.size(),
                    katPrivateSeed.data(), katPrivateSeed.size(),
                    katEncapsKeyBlob.data(), katEncapsKeyBlob.size(),
                    katDecapsKeyBlob.data(), katDecapsKeyBlob.size(),
                    line );

                cKemKeyGenSamples++;
                continue;
            }
            else if (katIsFieldPresent( katItem, "ek" ))
            {
                //
                // Encapsulation
                //
                CHECK3( katItem.dataItems.size() == 4, "Wrong number of items in KEM Encapsulation record at line %lld", line );

                BString katEncapsKeyBlob = katParseData( katItem, "ek" );
                BString katInputRandom   = katParseData( katItem, "m" );
                BString katAgreedSecret  = katParseData( katItem, "k" );
                BString katCipherText    = katParseData( katItem, "c" );

                testMlKemEncaps(
                    pKemMultiImp.get(),
                    params,
                    katEncapsKeyBlob.data(), katEncapsKeyBlob.size(),
                    katInputRandom.data(), katInputRandom.size(),
                    katAgreedSecret.data(), katAgreedSecret.size(),
                    katCipherText.data(), katCipherText.size(),
                    line );

                cKemEncapsSamples++;
                continue;
            }
            else if (katIsFieldPresent( katItem, "dk" ))
            {
                //
                // Decapsulation
                //
                CHECK3( katItem.dataItems.size() == 3, "Wrong number of items in KEM Decapsulation record at line %lld", line );

                BString katDecapsKeyBlob = katParseData( katItem, "dk" );
                BString katCipherText    = katParseData( katItem, "c" );
                BString katAgreedSecret  = katParseData( katItem, "k" );

                testMlKemDecaps(
                    pKemMultiImp.get(),
                    params,
                    katDecapsKeyBlob.data(), katDecapsKeyBlob.size(),
                    katCipherText.data(), katCipherText.size(),
                    katAgreedSecret.data(), katAgreedSecret.size(),
                    line );

                cKemDecapsSamples++;
                continue;
            }
            
            FATAL2( "Unknown data record at line %lld", line );
        }
    }

    iprint( "\n        Total samples: %d MlKemKeyGen, %d MlKemEncaps, %d MlKemDecaps\n", cKemKeyGenSamples, cKemEncapsSamples, cKemDecapsSamples);
}

VOID
testKem()
{
    INT64 nOutstandingAllocs = 0;

    // Skip if there is no Kem algorithm to test.
    if( !isAlgorithmPresent( "MlKem", TRUE ) )
    {
        return;
    }

    iprint( "    KEM\n" );
    
    testKemKats();

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs  == 0, "Memory leak %d outstanding", nOutstandingAllocs );

    testMlKemArithmetic();
    testMlKemHighLevelAPI();

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );

    iprint("\n");
}