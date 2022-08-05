//
// Pattern file for the CNG PBKDF2 implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

VOID
KdfImp<ImpXxx,AlgPbkdf2,BaseAlgXxx>::derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  pArgs,
        _Out_writes_( cbDst )   PBYTE           pbDst, 
                                SIZE_T          cbDst )
{
    BYTE    buf[1024];
    BCRYPT_KEY_HANDLE hKey;

    BCryptBuffer        buffer[5];
    BCryptBufferDesc    bufferDesc;

    CHECK( cbDst <= sizeof( buf ), "Result too large" );

    CHECK3( NT_SUCCESS( CngGenerateSymmetricKeyFn( state.hAlg, &hKey, NULL, 0, (PBYTE) pbKey, (ULONG) cbKey, 0 ) ), "Could not generate key for PBKDF2-%s", STRING( BASE_Alg ) );

    bufferDesc.ulVersion = BCRYPTBUFFER_VERSION;
    bufferDesc.cBuffers = 0;
    bufferDesc.pBuffers = &buffer[0];

    AddBCryptBuffer( &bufferDesc, KDF_HASH_ALGORITHM, CNG_XXX_HASH_ALG_NAMEU, 2*wcslen( CNG_XXX_HASH_ALG_NAMEU ) );

    ULONGLONG iterCnt;
    PCBYTE pbSalt;
    SIZE_T cbSalt;
    switch( pArgs->argType )
    {
    case KdfArgumentGeneric:
        pbSalt = pArgs->uGeneric.pbSelector;
        cbSalt = (ULONG) pArgs->uGeneric.cbSelector;
        iterCnt = 1;
        break;
    case KdfArgumentPbkdf2:
        pbSalt = pArgs->uPbkdf2.pbSalt;
        cbSalt = (ULONG) pArgs->uPbkdf2.cbSalt;
        iterCnt = pArgs->uPbkdf2.iterationCnt;
        break;
    default:
        CHECK( FALSE, "?" );
        return;
    }

    AddBCryptBuffer( &bufferDesc, KDF_GENERIC_PARAMETER, pbSalt, cbSalt );
    AddBCryptBuffer( &bufferDesc, KDF_ITERATION_COUNT, &iterCnt, sizeof( iterCnt ) );

    ULONG cbResult;
    CHECK( NT_SUCCESS( (*CngKeyDerivationFn)( hKey, &bufferDesc, pbDst, (ULONG) cbDst, &cbResult, 0 ) ), "Failure in CNG PBKDF2 call" );
    CHECK( cbResult == cbDst, "PBKDF2 result size mismatch" );

    SymCryptWipe( buf, cbDst );
    CHECK( NT_SUCCESS( (*CngPbkdf2Fn) ( state.hBaseAlg,
                                                (PBYTE)pbKey, (ULONG) cbKey,
                                                (PBYTE)pbSalt, (ULONG) cbSalt,
                                                iterCnt,
                                                buf, (ULONG) cbDst,
                                                0 ) ), "Pbkdf2 failure" );
    
    CHECK( memcmp( buf, pbDst, cbDst ) == 0, "CNG/Pbkdf2 disagreement" );

}

VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCryptBuffer        buffer[5];
    BCryptBufferDesc    bufferDesc;
    ULONGLONG           iterCnt;
    ULONG               cbResult;

    BCRYPT_KEY_HANDLE hKey = *(BCRYPT_KEY_HANDLE *) buf1;

    bufferDesc.ulVersion = BCRYPTBUFFER_VERSION;
    bufferDesc.cBuffers = 0;
    bufferDesc.pBuffers = &buffer[0];

    AddBCryptBuffer( &bufferDesc, KDF_HASH_ALGORITHM, CNG_XXX_HASH_ALG_NAMEU, 2*wcslen( CNG_XXX_HASH_ALG_NAMEU ) );
    AddBCryptBuffer( &bufferDesc, KDF_GENERIC_PARAMETER, buf2, 32 );
    iterCnt = 1;
    AddBCryptBuffer( &bufferDesc, KDF_ITERATION_COUNT, &iterCnt, sizeof( iterCnt ) );


    (*CngKeyDerivationFn)( hKey, &bufferDesc, buf3, (ULONG)dataSize, &cbResult, 0 );
}
