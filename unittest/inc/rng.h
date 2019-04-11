//
// rng.h Header file for test RNG
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//
// We use our own predictable RNG so that we can be repeatable.
//


class Rng
{
public:
    Rng();
    ~Rng();

private:
    Rng( const Rng &);
    void operator=( const Rng & );

public:
    VOID reset( PCBYTE pbData, SIZE_T cbData );

    _Ret_range_( min, upb-1 )
    SIZE_T sizet( SIZE_T min, SIZE_T upb ); // Return random value in range min,...,upb-1

    _Ret_range_( 0, upb-1 )
    SIZE_T sizet( SIZE_T upb );             // Return random value in range 0,...,upb-1

    _Ret_range_( 0, upb-1 )
    SIZE_T sizetNonUniform( SIZE_T upb, SIZE_T UniformProbLimit, ULONG logIncrease );
        // Return random value in range 0..upb-1
        // Distribution is nonuniform.
        // Distribution is the sum of a number of uniform distributions.
        // The first one has prob 1/2 and extend 0..UniformProbLimit -1;
        // Subsequent ones have half the probability and are 2^logIncrease bigger,
        // limited by the upb.

    VOID randomSubRange( SIZE_T bufSize, SIZE_T * pStart, SIZE_T * pLen );
        // Returns start & length of a random subrange in a buffer of size bufSize.

    BYTE byte();

    UINT32 uint32();
        
private:

    BYTE        m_seed[SYMCRYPT_SHA1_RESULT_SIZE];
    ULONGLONG   m_blockCtr;
    SIZE_T      m_bytesInBuf;
    BYTE        m_buf[SYMCRYPT_SHA1_RESULT_SIZE];
    
};

