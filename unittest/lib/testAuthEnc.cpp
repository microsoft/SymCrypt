//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

class AuthEncMultiImp: public AuthEncImplementation
{
public:
    AuthEncMultiImp( String algName );
    ~AuthEncMultiImp();

private:
    AuthEncMultiImp( const AuthEncMultiImp & );
    VOID operator=( const AuthEncMultiImp & );

public:
    virtual std::set<SIZE_T> getNonceSizes();

    virtual std::set<SIZE_T> getTagSizes();

    virtual std::set<SIZE_T> getKeySizes();

    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey );

    virtual VOID setTotalCbData( SIZE_T cbData );

    virtual NTSTATUS encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags );

    virtual NTSTATUS decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags );

    typedef std::vector<AuthEncImplementation *> AuthEncImpPtrVector;

    AuthEncImpPtrVector m_imps;                    // Implementations we use

    AuthEncImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations


};

AuthEncMultiImp::AuthEncMultiImp( String algName )
{
    getAllImplementations<AuthEncImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumAlgName;
    char * sepStr = "<";

    for( AuthEncImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

AuthEncMultiImp::~AuthEncMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( AuthEncImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


std::set<SIZE_T> AuthEncMultiImp::getNonceSizes()
{
    std::set<SIZE_T> res;
    for( AuthEncImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getNonceSizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

std::set<SIZE_T> AuthEncMultiImp::getTagSizes()
{
    std::set<SIZE_T> res;
    for( AuthEncImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getTagSizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

std::set<SIZE_T> AuthEncMultiImp::getKeySizes()
{
    std::set<SIZE_T> res;
    for( AuthEncImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        std::set<SIZE_T> r = (*i)->getKeySizes();
        res.insert( r.begin(), r.end() );
    }

    return res;
}

NTSTATUS AuthEncMultiImp::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    //
    // copy list of implementations to the ongoing computation list
    //
    m_comps.clear();

    for( AuthEncImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pbKey, cbKey ) == 0 )
        {
            m_comps.push_back( *i );
        }
    }
    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

VOID AuthEncMultiImp::setTotalCbData( SIZE_T cbData )
{
    for( AuthEncImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        (*i)->setTotalCbData( cbData );
    }
}

NTSTATUS
AuthEncMultiImp::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS res;
    BYTE bufData[1 << 13];
    BYTE bufTag[32];
    ResultMerge resData;
    ResultMerge resTag;

    CHECK( cbData < sizeof( bufData ), "Buffer too small" );
    CHECK( cbTag < sizeof( bufTag ), "Buf too small" );
    CHECK( pbTag != NULL || (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" )

    res = STATUS_UNSUCCESSFUL;
    for( AuthEncImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1);
        memset( bufTag, 't', cbTag + 1);
        status = (*i)->encrypt( pbNonce, cbNonce, pbAuthData, cbAuthData, pbSrc, bufData, cbData, pbTag == NULL ? NULL : bufTag, cbTag, flags );
        CHECK( bufData[cbData] == 'd', "?" );
        CHECK( bufTag[cbTag] == 't', "?" );
        if( NT_SUCCESS( status ) )
        {
            resData.addResult( (*i), bufData, cbData );
            if( pbTag != NULL )
            {
                resTag.addResult( (*i), bufTag, cbTag );
            }
            res = STATUS_SUCCESS;   // At least one implementation liked it.
         }
    }

    if( pbTag != NULL )
    {
        resTag.getResult( pbTag, cbTag );
    }

    resData.getResult( pbDst, cbData, FALSE );

    return res;
}

NTSTATUS
AuthEncMultiImp::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    BYTE bufData[1 << 13];
    ResultMerge resData;
    ResultMerge resTagError;
    BOOL tagError = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS res;

    CHECK( cbData < sizeof( bufData ), "Buffer too small" );

    res = STATUS_UNSUCCESSFUL;
    for( AuthEncImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( bufData, 'd', cbData + 1 );
        status = (*i)->decrypt( pbNonce, cbNonce, pbAuthData, cbAuthData, pbSrc, bufData, cbData, pbTag, cbTag, flags );
        CHECK( bufData[ cbData ] == 'd', "?" );
        if( status != STATUS_NOT_SUPPORTED )
        {
            if( pbTag != NULL )
            {
                tagError = !NT_SUCCESS( status );
                resTagError.addResult( (*i), (PCBYTE)&tagError, sizeof( tagError ) );
            }
            resData.addResult( (*i), bufData, cbData );
        }
    }

    if( pbTag != NULL )
    {
        resTagError.getResult( (PBYTE)&tagError, sizeof( tagError ) );
    }

    if( !tagError )
    {
        resData.getResult( pbDst, cbData, FALSE );  // We only count the tag results, one count per message
    }

    return tagError ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}


VOID
katAuthEncSingle(
                                AuthEncImplementation     * pImp,
    _In_reads_( cbKey )         PCBYTE                      pbKey,
                                SIZE_T                      cbKey,
    _In_reads_( cbNonce )       PCBYTE                      pbNonce,
                                SIZE_T                      cbNonce,
    _In_reads_( cbAuthData )    PCBYTE                      pbAuthData,
                                SIZE_T                      cbAuthData,
    _In_reads_( cbPlaintext )   PCBYTE                      pbPlaintext,
                                SIZE_T                      cbPlaintext,
    _In_reads_( cbCiphertext )  PCBYTE                      pbCiphertext,
                                SIZE_T                      cbCiphertext,
    _In_reads_( cbTag )         PCBYTE                      pbTag,
                                SIZE_T                      cbTag,
                                ULONGLONG                   line)
{
    BYTE bufData[512];
    BYTE bufTag[32];
    NTSTATUS status;

    CHECK3( cbPlaintext <= sizeof( bufData ), "Buffer too small, need %lld bytes", cbPlaintext );
    CHECK( cbTag <= sizeof( bufTag ), "?" );
    CHECK3( cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line );

    //
    // Do single encryption
    //
    memset( bufData, 0, sizeof( bufData ) );
    memset( bufTag, 0, sizeof( bufTag ) );

    CHECK4( NT_SUCCESS(pImp->setKey( pbKey, cbKey )), "Failed to set key size %d in line %lld", cbKey, line );

    pImp->encrypt( pbNonce, cbNonce, pbAuthData, cbAuthData, pbPlaintext, bufData, cbPlaintext, bufTag, cbTag, 0 );
    CHECK3( memcmp( bufData, pbCiphertext, cbPlaintext ) == 0, "Ciphertext mismatch in line %lld", line );
    CHECK3( memcmp( bufTag, pbTag, cbTag ) == 0, "Tag mismatch in line %lld", line );

    //
    // Do single decryption
    //

    memset( bufData, 0, sizeof( bufData ) );

    status = pImp->decrypt( pbNonce, cbNonce, pbAuthData, cbAuthData, pbCiphertext, bufData, cbPlaintext, bufTag, cbTag, 0 );
    CHECK4( NT_SUCCESS( status ), "Decryption signaled error %08x in line %lld", status, line );
    CHECK3( memcmp( bufData, pbPlaintext, cbPlaintext ) == 0, "Plaintext mismatch in line %lld", line );

}


VOID
testAuthEncRandom( AuthEncMultiImp * pImp, int rrep, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line, BOOLEAN fSupportsPartialEncryption )
{
    const SIZE_T bufSize = 1 << 13;
    BYTE buf[ bufSize ];
    BYTE tmp1[ bufSize ];
    BYTE tmp2[ bufSize ];
    BYTE tagBuf[ 32 ];
    BYTE tagTmp[ 32 ];
    NTSTATUS status;
    Rng rng;

    //
    // Seed our RNG with the algorithm name
    //
    // print( "%s\n", pImp->m_algorithmName.c_str() );
    rng.reset( (PCBYTE) pImp->m_algorithmName.data(), pImp->m_algorithmName.size() );

    std::set<SIZE_T>keySizesSet = pImp->getKeySizes();
    std::set<SIZE_T>nonceSizesSet = pImp->getNonceSizes();
    std::set<SIZE_T>tagSizesSet = pImp->getTagSizes();

    std::vector<SIZE_T>keySizes( keySizesSet.begin(), keySizesSet.end() );
    std::vector<SIZE_T>nonceSizes( nonceSizesSet.begin(), nonceSizesSet.end() );
    std::vector<SIZE_T>tagSizes( tagSizesSet.begin(), tagSizesSet.end() );

    std::sort( keySizes.begin(), keySizes.end() );
    std::sort( nonceSizes.begin(), nonceSizes.end() );
    std::sort( tagSizes.begin(), tagSizes.end() );

    //iprint( "# sizes: %d, %d, %d\n", keySizes.size(), nonceSizes.size(), tagSizes.size() );
    //
    //for( int i=0; i< tagSizes.size(); i++ )
    //{
    //    iprint( "tag %d: %d\n", i, tagSizes[i] );
    //}

    memset( buf, 0, sizeof( buf ) );


    for( int i=0; i<rrep; i++ )
    {
        SIZE_T cbKey = keySizes[ rng.sizet( keySizes.size() )];
        SIZE_T cbNonce = nonceSizes[ rng.sizet( nonceSizes.size() )];
        SIZE_T cbTag = tagSizes[ rng.sizet( tagSizes.size() )];

        CHECK( cbKey <= bufSize && cbNonce <= bufSize && cbTag <= sizeof( tagBuf ), "??" );

        SIZE_T nonceIdx = rng.sizet( bufSize - cbNonce );
        SIZE_T tagIdx = rng.sizet( bufSize - cbTag );

        SIZE_T cbAuthData;
        SIZE_T authDataIdx;
        rng.randomSubRange( bufSize, &authDataIdx, &cbAuthData );

        SIZE_T cbData;
        SIZE_T srcIdx;
        rng.randomSubRange( bufSize, &srcIdx, &cbData );
        SIZE_T dstIdx = rng.sizet( bufSize - cbData );

        pImp->encrypt( &buf[nonceIdx], cbNonce,
                        &buf[authDataIdx], cbAuthData,
                        &buf[srcIdx], tmp1, cbData,
                        &tagBuf[0], cbTag, 0 );

        if ( fSupportsPartialEncryption )
        {
            // Encrypt again piecewise

            pImp->setTotalCbData( cbData );
            {
                SIZE_T idx = 0;

                // We have to do the partial encrypt once even for cbData = 0
                do
                {
                    SIZE_T todo = g_rng.sizet( cbData - idx + cbData/10 + 10);
                    todo = SYMCRYPT_MIN( todo, cbData - idx );
                    BOOLEAN last = todo == cbData - idx;

                    pImp->encrypt(  &buf[nonceIdx], cbNonce,
                                    &buf[authDataIdx], cbAuthData,
                                    &buf[srcIdx + idx], &tmp2[idx], todo,
                                    last ? &tagTmp[0] : NULL, cbTag, AUTHENC_FLAG_PARTIAL );
                    idx += todo;
                } while( idx < cbData );
            }
            CHECK( memcmp( tmp1, tmp2, cbData ) == 0, "Partial/full encryption data mismatch" );
            CHECK( memcmp( tagBuf, tagTmp, cbTag ) == 0, "Partial/full encryption tag mismatch" );
        }

        //
        // We first inject an error in the tag to test that it is caught.
        // If the implementation can tell correct tags from incorrect ones, then the tag
        // computation must be correct, and there is no point in injecting
        // errors in the data or authdata.
        //
        // Copy tag to temp buffer, inject an error, and check we get an error.
        //

        memcpy( tagTmp, tagBuf, cbTag );
        SIZE_T errorIdx = rng.sizet( cbTag );
        tagTmp[errorIdx] ^= (BYTE)(1 << (rng.byte() & 7));
        status = pImp->decrypt( &buf[nonceIdx], cbNonce,
                                &buf[authDataIdx], cbAuthData,
                                &tmp1[0], &tmp2[0], cbData,
                                &tagTmp[0], cbTag, 0 );
        CHECK3( !NT_SUCCESS( status ), "No decryption error, line %lld", line );

        status = pImp->decrypt( &buf[nonceIdx], cbNonce,
                                &buf[authDataIdx], cbAuthData,
                                &tmp1[0], &tmp2[0], cbData,
                                &tagBuf[0], cbTag, 0 );

        CHECK3( NT_SUCCESS( status ), "Decryption error, line %lld", line );
        CHECK3( memcmp( tmp2, &buf[srcIdx], cbData ) == 0, "Decryption mismatch, line %lld", line );

        if ( fSupportsPartialEncryption )
        {
            // Now repeat the decryption check with partial calls
            pImp->setTotalCbData( cbData );
            {
                SIZE_T idx = 0;

                do
                {
                    SIZE_T todo = g_rng.sizet( cbData - idx + cbData/10 + 10);
                    todo = SYMCRYPT_MIN( todo, cbData - idx );
                    BOOLEAN last = todo == cbData - idx;
                    if( last && (g_rng.byte() & 1) == 0 )
                    {
                        // Check that we get a failure if we modify the tag
                        // Don't do that always because we perform a different partial decryption for the final
                        // check.
                        tagBuf[0] ^= 1;
                        status = pImp->decrypt(  &buf[nonceIdx], cbNonce,
                                        &buf[authDataIdx], cbAuthData,
                                        &tmp1[idx], &tmp2[idx], todo,
                                        last ? &tagBuf[0] : NULL, cbTag, AUTHENC_FLAG_PARTIAL );
                        CHECK( !NT_SUCCESS( status ), "No partial decrypt error" );
                        tagBuf[0] ^= 1;
                        // Re-establish the partial encryption state
                        if( idx > 0 )
                        {
                            status = pImp->decrypt(  &buf[nonceIdx], cbNonce,
                                            &buf[authDataIdx], cbAuthData,
                                            &tmp1[0], &tmp2[0], idx,
                                            NULL, cbTag, AUTHENC_FLAG_PARTIAL );
                        }
                    }
                    status = pImp->decrypt(  &buf[nonceIdx], cbNonce,
                                    &buf[authDataIdx], cbAuthData,
                                    &tmp1[idx], &tmp2[idx], todo,
                                    last ? &tagBuf[0] : NULL, cbTag, AUTHENC_FLAG_PARTIAL );
                    CHECK( NT_SUCCESS( status ), "Decrypt error" );
                    CHECK( memcmp( &tmp2[idx], &buf[srcIdx + idx], todo ) == 0, "Partial decryption mismatch" );
                    idx += todo;
                } while( idx < cbData );

            }
            CHECK3( memcmp( tmp2, &buf[srcIdx], cbData ) == 0, "Decryption mismatch, line %lld", line );
        }
        memcpy( &buf[dstIdx], tmp1, cbData );
        memcpy( &buf[tagIdx], tagBuf, cbTag );
    }

    memset( tagBuf, 0, sizeof( tagBuf ) );
    SIZE_T blockLen = tagSizes[ tagSizes.size() - 1 ];

    for( SIZE_T i=0; i<bufSize; i++ )
    {
        tagBuf[ i % blockLen ]  ^= buf[i];
    }

//    iprint( "%lld, %lld, [%lld,%lld,%lld,%lld,%lld] %lld\n", cntFnc, cntEnc,
//        cntPc[0], cntPc[1], cntPc[2], cntPc[3], cntPc[4], bytes );

    CHECK3( cbResult == blockLen, "Result size is wrong in line %lld", line );
    if( memcmp( tagBuf, pbResult, blockLen ) != 0 )
    {
        print( "\nWrong authEnc result in line %lld. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( tagBuf, cbResult );
        iprint( "\n" );

        pImp->m_nErrorKatFailure++;
    }
}



VOID
testAuthEncKats()
{
    std::unique_ptr<KatData> katAuthEnc( getCustomResource( "kat_authenc.dat", "KAT_AUTHENC" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<AuthEncMultiImp> pAuthEncMultiImp;

    while( 1 )
    {
        katAuthEnc->getKatItem( & katItem );
        ULONGLONG line = katItem.line;


        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pAuthEncMultiImp.reset( new AuthEncMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pAuthEncMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "ciphertext" ) )
            {
                BString katKey = katParseData( katItem, "key" );
                BString katNonce = katParseData( katItem, "nonce" );
                BString katAuthData = katParseData( katItem, "authdata" );
                BString katPlaintext = katParseData( katItem, "plaintext" );
                BString katCiphertext = katParseData( katItem, "ciphertext" );
                BString katTag = katParseData( katItem, "tag" );

                katAuthEncSingle( pAuthEncMultiImp.get(),
                    katKey.data(), katKey.size(),
                    katNonce.data(), katNonce.size(),
                    katAuthData.data(), katAuthData.size(),
                    katPlaintext.data(), katPlaintext.size(),
                    katCiphertext.data(), katCiphertext.size(),
                    katTag.data(), katTag.size(),
                    line );

            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() == 3, "Wrong # items in RND record ending at line %lld", line );
                int rrep = (int) katParseInteger( katItem, "rrep" );
                BString katRnd = katParseData( katItem, "rnd" );
                BOOLEAN fSupportsPartialEncryption = (BOOLEAN) katParseInteger( katItem, "partial" );
                testAuthEncRandom( pAuthEncMultiImp.get(), rrep, katRnd.data(), katRnd.size(), line, fSupportsPartialEncryption );
            } else
            {
                FATAL2( "Unknown data record ending at line %lld", line );
            }

        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

VOID
testSessionRandom()
{
    Rng rng;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptGcmExpandKey) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSessionSenderInit) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSessionReceiverInit) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSessionGcmEncrypt) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptGcmEncrypt) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSessionGcmDecrypt) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSessionDestroy) )
    {
        print("    skipped\n");
        return;
    }

    SYMCRYPT_SESSION senderSession;
    SYMCRYPT_SESSION receiverSession;
    SIZE_T seed = g_rng.sizet( (SIZE_T)-1 );

    //
    // Seed our from g_rng
    //
    rng.reset( (PCBYTE) &seed, sizeof(seed) );

    UINT32 senderId = rng.uint32();
    BYTE key[32] = { 0 };
    BYTE nonce[12] = { 0 };
    BYTE authData[16] = { 0 };
    BYTE sessionPlainText[128] = { 0 };
    BYTE testPlainText[128] = { 0 };
    BYTE sessionCipherText[128] = { 0 };
    BYTE testCipherText[128] = { 0 };
    BYTE backupCipherText[128] = { 0 };
    BYTE sessionTag[16] = { 0 };
    BYTE testTag[16] = { 0 };
    BYTE backupTag[16] = { 0 };
    UINT64 messageNumber;
    UINT64 testMessageNumber;
    UINT64 backupMessageNumber;
    SYMCRYPT_GCM_EXPANDED_KEY gcmExpandedKey;

    for (int i = 0; i < sizeof(key); i++)
    {
        key[i] = rng.byte();
    }
    for (int i = 0; i < sizeof(authData); i++)
    {
        authData[i] = rng.byte();
    }
    for (int i = 0; i < sizeof(sessionPlainText); i++)
    {
        sessionPlainText[i] = rng.byte();
    }

    scError = ScDispatchSymCryptGcmExpandKey(&gcmExpandedKey, ScDispatchSymCryptAesBlockCipher, key, sizeof(key));
    CHECK(scError == SYMCRYPT_NO_ERROR, "SymCryptGcmExpandKey failed");

    scError = ScDispatchSymCryptSessionSenderInit(&senderSession, senderId, 0);
    CHECK(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionSenderInit failed");

    scError = ScDispatchSymCryptSessionReceiverInit(&receiverSession, senderId, 0);
    CHECK(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionReceiverInit failed");

    SYMCRYPT_STORE_MSBFIRST32(&nonce[0], senderId);
    SYMCRYPT_STORE_MSBFIRST64(&nonce[4], 1ull);

    scError = ScDispatchSymCryptSessionGcmEncrypt(
        &senderSession,
        &gcmExpandedKey,
        authData, sizeof(authData),
        sessionPlainText, sessionCipherText, sizeof(sessionPlainText),
        sessionTag, sizeof(sessionTag),
        &messageNumber);
    CHECK3(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionGcmEncrypt failed with 0x%x", scError);

    ScDispatchSymCryptGcmEncrypt(
        &gcmExpandedKey,
        nonce, sizeof(nonce),
        authData, sizeof(authData),
        sessionPlainText, testCipherText, sizeof(sessionPlainText),
        testTag, sizeof(testTag));
    CHECK(memcmp(sessionCipherText, testCipherText, sizeof(sessionCipherText)) == 0, "Session/Non-Session encryption data mismatch");
    CHECK(memcmp(sessionTag, testTag, sizeof(sessionTag)) == 0, "Session/Non-Session encryption tag mismatch");

    // backup the first encryption
    memcpy(backupCipherText, sessionCipherText, sizeof(sessionCipherText));
    memcpy(backupTag, sessionTag, sizeof(sessionTag));
    backupMessageNumber = messageNumber;

    // Encrypt a stream of messages, and semi-randomly attempt to decrypt them.
    // Would be good to make a multi-threaded version, but we don't have multi-threaded Linux unit tests yet.
    for (int i = 0; i < 1024; i++)
    {
        scError = ScDispatchSymCryptSessionGcmEncrypt(
            &senderSession,
            &gcmExpandedKey,
            authData, sizeof(authData),
            sessionPlainText, sessionCipherText, sizeof(sessionPlainText),
            sessionTag, sizeof(sessionTag),
            &messageNumber);
        CHECK3(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionGcmEncrypt failed with 0x%x", scError);
        CHECK(messageNumber == i+2, "SymCryptSessionGcmEncrypt returned unexpected messageNumber");

        SYMCRYPT_STORE_MSBFIRST64(&nonce[4], messageNumber);

        ScDispatchSymCryptGcmEncrypt(
            &gcmExpandedKey,
            nonce, sizeof(nonce),
            authData, sizeof(authData),
            sessionPlainText, testCipherText, sizeof(sessionPlainText),
            testTag, sizeof(testTag));
        CHECK(memcmp(sessionCipherText, testCipherText, sizeof(sessionCipherText)) == 0, "Session/Non-Session encryption data mismatch");
        CHECK(memcmp(sessionTag, testTag, sizeof(sessionTag)) == 0, "Session/Non-Session encryption tag mismatch");

        switch (rng.byte() & 3)
        {
        // directly decrypt the most recently encrypted message
        case 0:
            scError = ScDispatchSymCryptSessionGcmDecrypt(
                &receiverSession,
                messageNumber,
                &gcmExpandedKey,
                authData, sizeof(authData),
                sessionCipherText, testPlainText, sizeof(sessionCipherText),
                sessionTag, sizeof(sessionTag));
            CHECK3(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionGcmDecrypt failed with 0x%x", scError);

            CHECK(memcmp(sessionPlainText, testPlainText, sizeof(sessionPlainText)) == 0, "Plaintext mismatch in SymCryptSessionGcm");

            testMessageNumber = receiverSession.replayState.messageNumber;

            // try decrypting the same message with an incorrect messageNumber from the future
            scError = ScDispatchSymCryptSessionGcmDecrypt(
                &receiverSession,
                messageNumber + rng.sizet(1,512),
                &gcmExpandedKey,
                authData, sizeof(authData),
                sessionCipherText, testPlainText, sizeof(sessionCipherText),
                sessionTag, sizeof(sessionTag));
            CHECK3(scError == SYMCRYPT_AUTHENTICATION_FAILURE,
                "SymCryptSessionGcmDecrypt did not return SYMCRYPT_AUTHENTICATION_FAILURE but 0x%x", scError);
            CHECK4(receiverSession.replayState.messageNumber == testMessageNumber,
                "Unexpected value for receiverSession messageNumber after failed decryption. Expected %d but is %d",
                testMessageNumber, receiverSession.replayState.messageNumber)
            break;

        // decrypt the backup message and ensure it can't be decrypted twice
        case 1:
            scError = ScDispatchSymCryptSessionGcmDecrypt(
                &receiverSession,
                backupMessageNumber,
                &gcmExpandedKey,
                authData, sizeof(authData),
                backupCipherText, testPlainText, sizeof(backupCipherText),
                backupTag, sizeof(backupTag));
            if (backupMessageNumber > receiverSession.replayState.messageNumber - 64)
            {
                CHECK3(scError == SYMCRYPT_NO_ERROR, "SymCryptSessionGcmDecrypt failed with 0x%x", scError);
                CHECK(memcmp(sessionPlainText, testPlainText, sizeof(sessionPlainText)) == 0, "Plaintext mismatch in SymCryptSessionGcm");
            }
            else
            {
                CHECK3(scError == SYMCRYPT_SESSION_REPLAY_FAILURE,
                    "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x", scError);
            }

            scError = ScDispatchSymCryptSessionGcmDecrypt(
                &receiverSession,
                backupMessageNumber,
                &gcmExpandedKey,
                authData, sizeof(authData),
                backupCipherText, testPlainText, sizeof(backupCipherText),
                backupTag, sizeof(backupTag));
            CHECK3(scError == SYMCRYPT_SESSION_REPLAY_FAILURE,
                "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x", scError);
            // Intentional fallthrough - once we've used the backup we need to replace with a new valid message

        // backup the most recently encrypted message to decrypt later
        case 2:
            memcpy(backupCipherText, sessionCipherText, sizeof(sessionCipherText));
            memcpy(backupTag, sessionTag, sizeof(sessionTag));
            backupMessageNumber = messageNumber;
            break;

        // check a too-old message cannot be decrypted
        case 3:
            if (receiverSession.replayState.messageNumber > 64)
            {
                // Note that trying to decrypt with a modified messageNumber should not succeed in
                // decryption, but we are testing here that we fail early because the messageNumber
                // is too low to even bother trying decryption
                scError = ScDispatchSymCryptSessionGcmDecrypt(
                    &receiverSession,
                    receiverSession.replayState.messageNumber - 64,
                    &gcmExpandedKey,
                    authData, sizeof(authData),
                    backupCipherText, testPlainText, sizeof(backupCipherText),
                    backupTag, sizeof(backupTag));
                CHECK3(scError == SYMCRYPT_SESSION_REPLAY_FAILURE,
                    "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x", scError);
            }
            break;

        // do nothing with encryption result
        default:
            break;
        }
    }

    // Cleanup
    ScDispatchSymCryptSessionDestroy(&senderSession);
    ScDispatchSymCryptSessionDestroy(&receiverSession);
}

VOID
testAuthEncAlgorithms()
{
    testAuthEncKats();

    print("    testSessionRandom static\n");
    testSessionRandom();

    if (g_dynamicSymCryptModuleHandle != NULL)
    {
        print("    testSessionRandom dynamic\n");
        g_useDynamicFunctionsInTestCall = TRUE;
        testSessionRandom();
        g_useDynamicFunctionsInTestCall = FALSE;
    }
}



