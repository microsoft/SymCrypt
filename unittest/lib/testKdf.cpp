//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

//
// TLS PRF constant labels for the KAT tests
//

static const BYTE       pbMasterSecretLabel[] = { 'm', 'a', 's', 't', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't', };
static const BString    g_katMasterSecretLabel(pbMasterSecretLabel, sizeof(pbMasterSecretLabel));
static const BYTE       pbKeyExpansionLabel[] = { 'k', 'e', 'y', ' ', 'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n', };
static const BString    g_katKeyExpansionLabel(pbKeyExpansionLabel, sizeof(pbKeyExpansionLabel));

class KdfMultiImp: public KdfImplementation
{
public:
    KdfMultiImp( String algName );
    ~KdfMultiImp();

private:
    KdfMultiImp( const KdfMultiImp & );
    VOID operator=( const KdfMultiImp & );

public:

    virtual VOID derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  args,
        _Out_writes_( cbDst )   PBYTE           pbDst,
                                SIZE_T          cbDst );

    typedef std::vector<KdfImplementation *> KdfImpPtrVector;

    KdfImpPtrVector m_imps;                    // Implementations we use

    KdfImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

};

KdfMultiImp::KdfMultiImp( String algName )
{
    getAllImplementations<KdfImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( KdfImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

KdfMultiImp::~KdfMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( KdfImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}



VOID KdfMultiImp::derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  args,
        _Out_writes_( cbDst )   PBYTE           pbDst,
                                SIZE_T          cbDst )
{
    BYTE    buf[1024];
    ResultMerge res;

    CHECK( cbDst <= sizeof( buf ), "Buffer too small" );

    for( KdfImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); i++ )
    {
        SymCryptWipe( buf, cbDst );
        (*i)->derive( pbKey, cbKey, args, buf, cbDst );
        res.addResult( (*i), buf, cbDst );
    }

    res.getResult( pbDst, cbDst );
}


VOID
katKdfSingle(
                                KdfImplementation * pImp,
    _In_reads_( cbKey )         PCBYTE              pbKey,
                                SIZE_T              cbKey,
    _In_                        PKDF_ARGUMENTS      pArgs,
    _In_reads_( cbResult )      PCBYTE              pbResult,
                                SIZE_T              cbResult,
                                ULONGLONG           line)
{
    BYTE buf[512];

    CHECK( cbResult <= sizeof( buf ), "Buffer too small" );

    pImp->derive( pbKey, cbKey, pArgs, buf, cbResult );

    CHECK3( memcmp( buf, pbResult, cbResult ) == 0, "Result mismatch in line %lld", line );
}


VOID
testKdfRandom( KdfMultiImp * pImp, KDF_ARGUMENT_TYPE argType, int rrep, SIZE_T keyLen, PCBYTE pbResult, SIZE_T cbResult, ULONGLONG line )
//
// keyLen = 0xnn00kkkk
// if 0xnn != 0, keysize is random in the range 0..0xkkkk
// else the key size is 0xkkkk
//
{
    BYTE buf[ 1024 ];
    BYTE tmp1[256];
    Rng rng;

    //
    // Seed our RNG with the algorithm name and key size
    //
    SIZE_T algNameSize = pImp->m_algorithmName.size();
    CHECK( algNameSize < sizeof( buf ) - sizeof( ULONGLONG ), "Algorithm name too long" );
    memcpy( buf, pImp->m_algorithmName.data(), algNameSize );
    *(ULONGLONG SYMCRYPT_UNALIGNED *)&buf[algNameSize] = keyLen;
    rng.reset( buf, algNameSize + sizeof( ULONGLONG ) );

    memset( buf, 0, sizeof( buf ) );

    SIZE_T keyIdx = 0;
    SIZE_T pos;
    SIZE_T len;
    SIZE_T kLen;
    const SIZE_T bufSize = sizeof( buf );

    for( int i=0; i<rrep; i++ )
    {
        if( (keyLen & 0xff000000) != 0 )
        {
            kLen = rng.sizet( (keyLen & 0xffff) + 1 );
        } else
        {
            kLen = keyLen & 0xffff;
        }

        CHECK3( kLen <= bufSize, "Key length too large in line %lld", line )

        keyIdx = rng.sizet( bufSize - kLen );

        KDF_ARGUMENTS args;
        args.argType = argType;

        switch( argType )
        {
        case KdfArgumentGeneric:
            len = rng.sizet( bufSize );
            pos = rng.sizet( bufSize - len );
            args.uGeneric.pbSelector = &buf[pos];
            args.uGeneric.cbSelector = len;
            break;

        case KdfArgumentPbkdf2:
            len = rng.sizet( bufSize );
            pos = rng.sizet( bufSize - len );
            args.uPbkdf2.pbSalt = &buf[pos];
            args.uPbkdf2.cbSalt = len;
            args.uPbkdf2.iterationCnt = 1 + rng.sizetNonUniform( 1024, 4, 1 );
            break;

        case KdfArgumentSp800_108:
            SYMCRYPT_ASSERT( sizeof( tmp1 ) <= bufSize );
            len = rng.sizet( sizeof( tmp1 ) );
            pos = rng.sizet( bufSize - len );
            memcpy( tmp1, &buf[pos], len );
            tmp1[len] = 0;
            args.uSp800_108.pbLabel = tmp1;
            args.uSp800_108.cbLabel = len;

            len = rng.sizet( sizeof( tmp1 ) );
            pos = rng.sizet( bufSize - len );
            args.uSp800_108.pbContext = &buf[pos];
            args.uSp800_108.cbContext = len;

            break;

        default:
            CHECK( FALSE, "?" );
        }

        len = 1 + rng.sizetNonUniform( bufSize - 1, 32, 1 );
        CHECK( len <= bufSize, "?" );
        pos = rng.sizet( bufSize - len );
        pImp->derive( &buf[keyIdx], kLen, &args, &buf[pos], len );
    }

    //
    // Hash the buffer to get a single result value.
    //
    SymCryptSha256( &buf[0], bufSize, &buf[0] );

//    iprint( "%lld, %lld, [%lld,%lld,%lld,%lld,%lld] %lld\n", cntFnc, cntEnc,
//        cntPc[0], cntPc[1], cntPc[2], cntPc[3], cntPc[4], bytes );

    CHECK3( cbResult <= SYMCRYPT_SHA256_RESULT_SIZE, "Result size too long in line %lld", line );
    if( memcmp( buf, pbResult, cbResult ) != 0 )
    {

        print( "*\nWrong KDF result in line %d. \n"
            "Expected ", line );
        printHex( pbResult, cbResult );
        print( "\nGot      " );
        printHex( buf, cbResult );
        iprint( "\n" );

        pImp->m_nErrorKatFailure++;
    }
}


VOID
testKdfKats()
{
    std::unique_ptr<KatData> katBlockCipher( getCustomResource( "kat_kdf.dat", "KAT_KDF" ) );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<KdfMultiImp> pKdfMultiImp;

    while( 1 )
    {
        katBlockCipher->getKatItem( & katItem );
        ULONGLONG line = katItem.line;


        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pKdfMultiImp.reset( new KdfMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pKdfMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            KDF_ARGUMENTS args;

            if( katIsFieldPresent( katItem, "iterationcnt" ) )
            {
                // PBKDF2 test values
                args.argType = KdfArgumentPbkdf2;
                CHECK3( katItem.dataItems.size() == 4, "Too many items in PBKDF2 record at line %lld", line );

                BString katKey = katParseData( katItem, "key" );
                BString katSalt = katParseData( katItem, "salt" );
                ULONGLONG iterationCnt = (ULONGLONG) katParseInteger( katItem, "iterationcnt" );
                BString katRes = katParseData( katItem, "res" );

                args.uPbkdf2.pbSalt = katSalt.data();
                args.uPbkdf2.cbSalt = katSalt.size();
                args.uPbkdf2.iterationCnt = iterationCnt;

                katKdfSingle( pKdfMultiImp.get(), katKey.data(), katKey.size(), &args, katRes.data(), katRes.size(), line );
                continue;
            }

            if( katIsFieldPresent( katItem, "selector" ) )
            {
                args.argType = KdfArgumentGeneric;
                CHECK3( katItem.dataItems.size() == 3, "Too many items in KDF generic record in line %lld", line );

                BString katKey = katParseData( katItem, "key" );
                BString katSelector = katParseData( katItem, "selector" );
                BString katRes = katParseData( katItem, "res" );

                args.uGeneric.pbSelector = katSelector.data();
                args.uGeneric.cbSelector = katSelector.size();

                katKdfSingle( pKdfMultiImp.get(), katKey.data(), katKey.size(), &args, katRes.data(), katRes.size(), line );
                continue;
            }

            if( katIsFieldPresent( katItem, "label" ) )
            {
                args.argType = KdfArgumentSp800_108;
                CHECK3( katItem.dataItems.size() == 4, "Too many items in SP800-108 record in line %lld", line );

                BString katKey = katParseData( katItem, "key" );
                BString katLabel = katParseData( katItem, "label" );
                BString katContext = katParseData( katItem, "context" );
                BString katRes = katParseData( katItem, "res" );

                args.uSp800_108.pbLabel = katLabel.data();
                args.uSp800_108.cbLabel = katLabel.size();
                args.uSp800_108.pbContext = katContext.data();
                args.uSp800_108.cbContext = katContext.size ();

                katKdfSingle( pKdfMultiImp.get(), katKey.data(), katKey.size(), &args, katRes.data(), katRes.size(), line );
                continue;
            }

            if( katIsFieldPresent( katItem, "rnd" ) )
            {
                CHECK3( katItem.dataItems.size() == 4, "Too many items in KDF rnd record in line %lld", line );

                int rrep = (int) katParseInteger( katItem, "rrep" );
                int argType = (int) katParseInteger( katItem, "argtype" );
                SIZE_T keyLen = (SIZE_T) katParseInteger( katItem, "keylen" );
                BString katRnd = katParseData( katItem, "rnd" );

                CHECK3( argType >= KdfArgumentGeneric && argType <= KdfArgumentSp800_108, "Invalid argType value in line %lld", line );

                testKdfRandom( pKdfMultiImp.get(), (KDF_ARGUMENT_TYPE) argType, rrep, keyLen, katRnd.data(), katRnd.size(), line );

                continue;
            }

            if ( katIsFieldPresent( katItem, "pre_master_secret" ) )
            {
                args.argType = KdfArgumentTlsPrf;
                CHECK3(katItem.dataItems.size() == 8, "Too many items in TLS PRF record in line %lld", line);

                BString katPreMasterSecret = katParseData(katItem, "pre_master_secret");
                BString katClientHelloAndServerHello = katParseData(katItem, "clienthello_random") + katParseData(katItem, "serverhello_random");
                BString katServerRandomAndClientRandom = katParseData(katItem, "server_random") + katParseData(katItem, "client_random");
                BString katMasterSecret = katParseData(katItem, "master_secret");
                BString katKeyBlock = katParseData(katItem, "key_block");

                /////////////////////////////////////////////////////////////////////////////////
                //
                // Test routine for all versions (from RFCs 2246, 4336, 5246)
                //
                //      For all key exchange methods, the same algorithm is used to convert
                //      the pre_master_secret into the master_secret.The pre_master_secret
                //      should be deleted from memory once the master_secret has been
                //      computed.
                //
                //          master_secret = PRF(pre_master_secret, "master secret",
                //                              ClientHello.random + ServerHello.random)
                //                              [0..47];
                //
                //      The master secret is always exactly 48 bytes in length.The length
                //      of the premaster secret will vary depending on key exchange method.
                //
                //      ...
                //
                //      To generate the key material, compute
                //
                //          key_block = PRF(SecurityParameters.master_secret,
                //                          "key expansion",
                //                          SecurityParameters.server_random +
                //                          SecurityParameters.client_random);
                //
                //      until enough output has been generated.
                //
                /////////////////////////////////////////////////////////////////////////////////

                // Master secret generation
                args.uTlsPrf.pbLabel = g_katMasterSecretLabel.data();
                args.uTlsPrf.cbLabel = g_katMasterSecretLabel.size();
                args.uTlsPrf.pbSeed = katClientHelloAndServerHello.data();
                args.uTlsPrf.cbSeed = katClientHelloAndServerHello.size();

                katKdfSingle(pKdfMultiImp.get(), katPreMasterSecret.data(), katPreMasterSecret.size(), &args, katMasterSecret.data(), katMasterSecret.size(), line);

                // Key expansion
                args.uTlsPrf.pbLabel = g_katKeyExpansionLabel.data();
                args.uTlsPrf.cbLabel = g_katKeyExpansionLabel.size();
                args.uTlsPrf.pbSeed = katServerRandomAndClientRandom.data();
                args.uTlsPrf.cbSeed = katServerRandomAndClientRandom.size();

                katKdfSingle(pKdfMultiImp.get(), katMasterSecret.data(), katMasterSecret.size(), &args, katKeyBlock.data(), katKeyBlock.size(), line);

                continue;
            }

            if( katIsFieldPresent( katItem, "ikm" ) )
            {
                args.argType = KdfArgumentHkdf;
                CHECK3( katItem.dataItems.size() == 6, "Too many items in HKDF record in line %lld", line );

                BString katKey = katParseData( katItem, "ikm" );
                BString katSalt = katParseData( katItem, "salt" );
                BString katInfo = katParseData( katItem, "info" );
                BString katRes = katParseData( katItem, "okm" );

                args.uHkdf.pbSalt = katSalt.data();
                args.uHkdf.cbSalt = katSalt.size ();
                args.uHkdf.pbInfo = katInfo.data();
                args.uHkdf.cbInfo = katInfo.size ();

                katKdfSingle( pKdfMultiImp.get(), katKey.data(), katKey.size(), &args, katRes.data(), katRes.size(), line );
                continue;
            }

            if (katIsFieldPresent(katItem, "session_id"))
            {
                args.argType = KdfArgumentSshKdf;
                CHECK3(katItem.dataItems.size() == 14, "Incorrect number of fields in SSH-KDF record in line %lld", line);

                BString hashName = katParseData(katItem, "hash");

                // The following fields are not used.
                // We use the size of the data fields from the test vector..
                //SIZE_T cbSharedSecret = katParseInteger(katItem, "shared secret length");
                //SIZE_T cbIVLength = katParseInteger(katItem, "iv length");
                //SIZE_T cbEncryptionKeyLength = katParseInteger(katItem, "encryption key length");

                BString SharedKey = katParseData(katItem, "k");
                BString HashValue = katParseData(katItem, "h");
                BString SessionId = katParseData(katItem, "session_id");

                args.uSshKdf.pbHashValue = HashValue.data();
                args.uSshKdf.cbHashValue = HashValue.size();
                args.uSshKdf.pbSessionId = SessionId.data();
                args.uSshKdf.cbSessionId = SessionId.size();
                args.uSshKdf.hashName = (PCSTR)hashName.c_str();

                BString katInitialIV_ClientToServer = katParseData(katItem, "initial iv (client to server)");
                BString katInitialIV_ServerToClient = katParseData(katItem, "initial iv (server to client)");
                BString katEncryptionKey_ClientToServer = katParseData(katItem, "encryption key (client to server)");
                BString katEncryptionKey_ServerToClient = katParseData(katItem, "encryption key (server to client)");
                BString katIntegrityKey_ClientToServer = katParseData(katItem, "integrity key (client to server)");
                BString katIntegrityKey_ServerToClient = katParseData(katItem, "integrity key (server to client)");

                args.uSshKdf.label = SYMCRYPT_SSHKDF_IV_CLIENT_TO_SERVER;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katInitialIV_ClientToServer.data(), katInitialIV_ClientToServer.size(), line);

                args.uSshKdf.label = SYMCRYPT_SSHKDF_IV_SERVER_TO_CLIENT;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katInitialIV_ServerToClient.data(), katInitialIV_ServerToClient.size(), line);

                args.uSshKdf.label = SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katEncryptionKey_ClientToServer.data(), katEncryptionKey_ClientToServer.size(), line);

                args.uSshKdf.label = SYMCRYPT_SSHKDF_ENCRYPTION_KEY_SERVER_TO_CLIENT;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katEncryptionKey_ServerToClient.data(), katEncryptionKey_ServerToClient.size(), line);

                args.uSshKdf.label = SYMCRYPT_SSHKDF_INTEGRITY_KEY_CLIENT_TO_SERVER;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katIntegrityKey_ClientToServer.data(), katIntegrityKey_ClientToServer.size(), line);

                args.uSshKdf.label = SYMCRYPT_SSHKDF_INTEGRITY_KEY_SERVER_TO_CLIENT;
                katKdfSingle(pKdfMultiImp.get(), SharedKey.data(), SharedKey.size(), &args, katIntegrityKey_ServerToClient.data(), katIntegrityKey_ServerToClient.size(), line);

                continue;
            }

            if (katIsFieldPresent(katItem, "srtp k_e"))
            {
                args.argType = KdfArgumentSrtpKdf;
                CHECK3(katItem.dataItems.size() == 12, "Incorrect number of fields in SRTP-KDF record in line %lld", line);

                BString k_master = katParseData(katItem, "k_master");
                BString master_salt = katParseData(katItem, "master_salt");
                BString kdr = katParseData(katItem, "kdr");
                BString index = katParseData(katItem, "index");
                BString indexSRTCP = katParseData(katItem, "index (srtcp)");

                args.uSrtpKdf.pbSalt = master_salt.data();
                args.uSrtpKdf.cbSalt = master_salt.size();

                args.uSrtpKdf.uKeyDerivationRate = 0;
                for (auto x : kdr)
                {
                    args.uSrtpKdf.uKeyDerivationRate <<= 8;
                    args.uSrtpKdf.uKeyDerivationRate |= x;
                }

                BString katSRTPk_e = katParseData(katItem, "srtp k_e");
                BString katSRTPk_a = katParseData(katItem, "srtp k_a");
                BString katSRTPk_s = katParseData(katItem, "srtp k_s");
                BString katSRTCPk_e = katParseData(katItem, "srtcp k_e");
                BString katSRTCPk_a = katParseData(katItem, "srtcp k_a");
                BString katSRTCPk_s = katParseData(katItem, "srtcp k_s");

                {
                    args.uSrtpKdf.uIndexWidth = 48;

                    args.uSrtpKdf.uIndex = 0;
                    for (auto x : index)
                    {
                        args.uSrtpKdf.uIndex <<= 8;
                        args.uSrtpKdf.uIndex |= x;
                    }

                    args.uSrtpKdf.label = SYMCRYPT_SRTP_ENCRYPTION_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTPk_e.data(), katSRTPk_e.size(), line);

                    args.uSrtpKdf.label = SYMCRYPT_SRTP_AUTHENTICATION_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTPk_a.data(), katSRTPk_a.size(), line);

                    args.uSrtpKdf.label = SYMCRYPT_SRTP_SALTING_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTPk_s.data(), katSRTPk_s.size(), line);
                }

                {
                    args.uSrtpKdf.uIndexWidth = 32;

                    args.uSrtpKdf.uIndex = 0;
                    for (auto x : indexSRTCP)
                    {
                        args.uSrtpKdf.uIndex <<= 8;
                        args.uSrtpKdf.uIndex |= x;
                    }

                    args.uSrtpKdf.label = SYMCRYPT_SRTCP_ENCRYPTION_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTCPk_e.data(), katSRTCPk_e.size(), line);

                    args.uSrtpKdf.label = SYMCRYPT_SRTCP_AUTHENTICATION_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTCPk_a.data(), katSRTCPk_a.size(), line);

                    args.uSrtpKdf.label = SYMCRYPT_SRTCP_SALTING_KEY;
                    katKdfSingle(pKdfMultiImp.get(), k_master.data(), k_master.size(), &args, katSRTCPk_s.data(), katSRTCPk_s.size(), line);
                }

                continue;
            }

            FATAL2( "Unknown data record at line %lld", line );
        }

    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

VOID
testKdfAlgorithms()
{
    testKdfKats();
}



