
//
// Pattern file for SymCrypt RsaKeyGenPerf functions. Allows perf testing of both static and dynamic
// SymCrypt functions.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

template<>
VOID
addRsaKeyGenPerfSymCrypt<ImpXxx>( PrintTable &table )
{
    UINT32 bitSizes[] = {512, 3*256, 1024, 3*512, 2048, 3*1024, 4096, 3*2048, 8192, };
    SYMCRYPT_RSA_PARAMS scRsaParams = { 0 };

    if constexpr ( std::is_same<ImpXxx, ImpScStatic>::value )
    {
        iprint( "\n"
                " Trial division limits: \n" );
        for( UINT32 i=0; i<ARRAY_SIZE( bitSizes ); i++ )
        {
            PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = SymCryptCreateTrialDivisionContext( SymCryptDigitsFromBits( bitSizes[i] / 2 ) );
            CHECK( pContext != NULL, "Out of memory" );
            iprint( "%5d -> %7d\n", bitSizes[i], SymCryptTestTrialdivisionMaxSmallPrime( pContext ) );
            SymCryptFreeTrialDivisionContext( pContext );
        }
    }

    for( UINT32 i=0; i<ARRAY_SIZE( bitSizes ); i++ )
    {
        UINT32 bitSize = bitSizes[i];
        UINT32 generateFlags = SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
        if( bitSize < SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS )
        {
            generateFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        }

        UINT64 scTicks;
        double scCost;
        double scTotal = 0.0;

        scRsaParams.version = 1;
        scRsaParams.nBitsOfModulus = bitSize;
        scRsaParams.nPrimes = 2;
        scRsaParams.nPubExp = 1;

        for( UINT32 j=0; j<10; j++ )
        {
            UINT64 start = GET_PERF_CLOCK();

            PSYMCRYPT_RSAKEY pScKey = ScShimSymCryptRsakeyAllocate( &scRsaParams, 0 );
            ScShimSymCryptRsakeyGenerate( pScKey, nullptr, 0, generateFlags );
            ScShimSymCryptRsakeyFree( pScKey );

            UINT64 stop = GET_PERF_CLOCK();
            scTicks = stop - start;

            scCost = scTicks * g_perfScaleFactor - g_perfMeasurementOverhead;
            scTotal += scCost;

            String row = formatNumber( bitSize ) + "-" + formatNumber(j+1);
            table.addItem( row, IMP_PrettyNameStr, formatNumber( scCost ) );
            table.addItem( row, IMP_PrettyNameStr "av", formatNumber( scTotal / (j+1) ));
        }
    }
}
