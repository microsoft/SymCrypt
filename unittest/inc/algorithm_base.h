//
// Algorithm_base.h
// base classes for algorithm implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// AlgorithmImplementation class
// This is the abstract class that represents the common properties
// of all algorithm implementations.
//
class AlgorithmImplementation
{
public:
    AlgorithmImplementation();
    virtual ~AlgorithmImplementation() {};

private:
    AlgorithmImplementation( const AlgorithmImplementation & );
    VOID operator =( const AlgorithmImplementation & );

public:

    std::string m_algorithmName;                // Name of algorithm
    std::string m_modeName;                     // Name of algorithm mode
    std::string m_implementationName;           // Name of implementation

    virtual VOID setPerfKeySize( SIZE_T keySize ) {UNREFERENCED_PARAMETER(keySize);};
    PerfKeyFn   m_perfKeyFunction;
    PerfDataFn  m_perfDataFunction;
    PerfDataFn  m_perfDecryptFunction;
    PerfCleanFn m_perfCleanFunction;

    //
    // During functional testing we test all implementations of a single algorithm
    // in parallel. This makes debugging bugs triggered by the pseudo-random test cases
    // much easier.
    // When we check the (intermediate or final) result there are three types of errors we can encounter:
    // - Result disagrees with majority of other implementations of the same algorithm
    // - Results disagree but there is no majority to find out what result is correct
    // - Result agrees with majority but not with KAT values.
    //
    // These counters count how often each of these cases happens.
    //
    ULONGLONG   m_nErrorDisagreeWithMajority;
    ULONGLONG   m_nErrorNoMajority;
    ULONGLONG   m_nErrorKatFailure;

    //
    // Number of times this algorithm has produced a result during the test
    //
    ULONGLONG   m_nResults;

    //
    // Performance information
    //
    typedef struct _ALG_PERF_INFO
    {
        SIZE_T                  keySize;        // key size to add to row header. (0 if not used)
        SIZE_T                  dataSize;       // data size to add to row header. (only used with g_measure_specific_sizes)
        char *                  strPostfix;     // postfix string, must be 3 characters long
        double                  cFixed;         // clocks of fixed overhead.
        double                  cPerByte;       // clocks average cost per byte (used only for linear records, 0 for non-linear records)
        double                  cRange;         // 90 percentile of deviation from prediction by previous two numbers
    } ALG_PERF_INFO;

    std::vector<ALG_PERF_INFO> m_perfInfo;
};

class HashImplementation: public AlgorithmImplementation
{
public:
    HashImplementation() {};
    virtual ~HashImplementation() {};

private:
    HashImplementation( const HashImplementation & );
    VOID operator=( const HashImplementation & );

public:
    virtual SIZE_T resultLen() = 0;
        // Return the result length of this hash

    virtual SIZE_T inputBlockLen() = 0;
        // Return the input block length of this hash

    virtual VOID init() = 0;
        // Initialize for a new hash computation.

    virtual VOID append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData ) = 0;
        // Append data to the running hash computation.

    virtual VOID result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult ) = 0;
        // Get the result of the running hash computation.

    virtual VOID hash( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData,
                       _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult );
        // Single hash computation.
        // The default implementation calls init/append/result so implementations that do not
        // have a separate compute-hash function can call the generic implementation in this
        // class.

    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes ) = 0;
        // nBytes is a multiple of the input block length.
        // Set the computation to the state as if it has processed a message nBytes long
        // which resulted in the internal chaining state having the value with every
        // byte equal to the character 'b'.
        // This allows us to test carry-handling of the message length counters. (A known
        // problem area.)
        // Return zero if success, NT status error if not supported.

    virtual NTSTATUS exportSymCryptFormat(
            _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult,
            _In_                                                    SIZE_T  cbResultBufferSize,
            _Out_                                                   SIZE_T *pcbResult ) = 0;
};

class XofImplementation : public AlgorithmImplementation
{
public:
    XofImplementation() {};
    virtual ~XofImplementation() {};

private:
    XofImplementation(const XofImplementation&);
    VOID operator=(const XofImplementation&);

public:

    virtual SIZE_T inputBlockLen() = 0;
    // Return the input block length of this XOF

    virtual VOID init() = 0;
    // Initialize for a new XOF computation.

    virtual VOID append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData) = 0;
    // Append data to the running XOF computation.

    virtual VOID extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe) = 0;
    // XOF extraction.
    // Extracts cbResult bytes from the XOF. Wipes and re-initializes the state if bWipe=TRUE.

    virtual VOID result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult) = 0;
    // Get the result of the running XOF computation.
    // Default implementation calls extract with bWipe=TRUE.

    virtual VOID xof(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData,
                    _Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult);
    // Single-call XOF computation.
    // The default implementation calls init/append/result.
};

class CustomizableXofImplementation : public AlgorithmImplementation
{
public:
    CustomizableXofImplementation() {};
    virtual ~CustomizableXofImplementation() {};

private:
    CustomizableXofImplementation(const CustomizableXofImplementation&);
    VOID operator=(const CustomizableXofImplementation&);

public:

    virtual SIZE_T inputBlockLen() = 0;
    // Return the input block length of this XOF

	virtual VOID init(  _In_reads_(cbNstr)  PCBYTE pbNstr, 
                                            SIZE_T cbNstr,
                        _In_reads_(cbSstr)  PCBYTE pbSstr, 
                                            SIZE_T cbSstr) = 0;
    // Initialize for a new XOF computation.

    virtual VOID append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData) = 0;
    // Append data to the running XOF computation.

    virtual VOID extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe) = 0;
    // XOF extraction.
    // Extracts cbResult bytes from the XOF. Wipes and re-initializes the state if bWipe=TRUE.

    virtual VOID result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult) = 0;
    // Get the result of the running XOF computation.
    // Default implementation calls extract with bWipe=TRUE.

    virtual VOID xof(
        _In_reads_( cbNstr )        PCBYTE  pbNstr, SIZE_T  cbNstr,
        _In_reads_( cbSstr )        PCBYTE  pbSstr, SIZE_T  cbSstr,
        _In_reads_( cbData )        PCBYTE  pbData, SIZE_T cbData,
        _Out_writes_( cbResult )    PBYTE   pbResult, SIZE_T cbResult) = 0;
    // Single-call XOF computation.
    // The default implementation calls init/append/result.
};

#define MAX_PARALLEL_HASH_STATES        32
#define MAX_PARALLEL_HASH_OPERATIONS    128

class ParallelHashImplementation: public AlgorithmImplementation
{
public:
    ParallelHashImplementation() {};
    virtual ~ParallelHashImplementation() {};

private:
    ParallelHashImplementation( const ParallelHashImplementation & );
    VOID operator=( const ParallelHashImplementation & );

public:

    virtual PCSYMCRYPT_HASH SymCryptHash() = 0;
        // Return a pointer to the SymCrypt implementation of the equivalent hash algorithm.

    virtual SIZE_T resultLen() = 0;
        // Return the result length of this hash

    virtual SIZE_T inputBlockLen() = 0;
        // Return the input block length of this hash

    virtual VOID init( SIZE_T nHashes ) = 0;
        // Initialize for a new hash computation.
        // nHashes = # hash states, nHashes <= MAX_PARALLEL_HASH_STATES

    virtual VOID process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations ) = 0;
        // Process BCrypt-style operations on the parallel hash state

    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes ) = 0;
        // nBytes is a multiple of the input block length.
        // Set the computation to the state as if it has processed a message nBytes long
        // which resulted in the internal chaining state having the value with every
        // byte equal to the character 'b'.
        // This allows us to test carry-handling of the message length counters. (A known
        // problem area.)
        // Return zero if success, NT status error if not supported.

};

class MacImplementation: public AlgorithmImplementation
{
public:
    MacImplementation() {};
    ~MacImplementation() {};

private:
    MacImplementation( const MacImplementation & );
    VOID operator=( const MacImplementation & );

public:
    virtual SIZE_T resultLen() = 0;
        // return the result length of this MAC

    virtual SIZE_T inputBlockLen() = 0;
        // return the input block length of this MAC

    virtual NTSTATUS init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey ) = 0;
        // Start a new MAC computation with the given key.
        // Return zero if success, NT status error if not supported.

    virtual VOID append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData ) = 0;
        // Append data to the running MAC computation.

    virtual VOID result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult ) = 0;
        // Get the result of the running MAC computation.

    virtual NTSTATUS mac( _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey,
                          _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData,
                          _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult );
        // Complete a full MAC computation.
        // The default implementation merely calls the init/append/result members.
        // Return zero if success, NT status error if not supported.
};

class KmacImplementation : public AlgorithmImplementation
{
public:
    KmacImplementation() {};
    ~KmacImplementation() {};

private:
    KmacImplementation(const KmacImplementation&);
    VOID operator=(const KmacImplementation&);

public:

    virtual SIZE_T inputBlockLen() = 0;
    // return the input block length of this MAC

    virtual VOID init(
        _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
        _In_reads_(cbKey) PCBYTE pbKey, SIZE_T cbKey) = 0;
    // Start a new MAC computation with the given key and customization string.
    // Return zero if success, NT status error if not supported.

    virtual VOID append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData) = 0;
    // Append data to the running MAC computation.

    virtual VOID extract(_Out_writes_(cbData) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe) = 0;
    // Extract data in XOF mode.

    virtual VOID result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult) = 0;
    // Get the result of the running MAC computation.

    virtual VOID mac(
        _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
        _In_reads_(cbKey)      PCBYTE pbKey, SIZE_T cbKey,
        _In_reads_(cbData)     PCBYTE pbData, SIZE_T cbData,
        _Out_writes_(cbResult)  PBYTE pbResult, SIZE_T cbResult);
    // Complete a full MAC computation.
    // The default implementation merely calls the init/append/result members.
    // Return zero if success, NT status error if not supported.

    virtual VOID xof(
        _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
        _In_reads_(cbKey)      PCBYTE pbKey, SIZE_T cbKey,
        _In_reads_(cbData)     PCBYTE pbData, SIZE_T cbData,
        _Out_writes_(cbResult)  PBYTE pbResult, SIZE_T cbResult);
    // Generate a fixed size output in XOF mode.
    // The default implementation merely calls the init/append/extract members.
    // Return zero if success, NT status error if not supported.
};


class BlockCipherImplementation: public AlgorithmImplementation
//
// Implements block cipher encryption modes.
// Data is always a multiple of the block length.
// The chaining value is used for CBC/CTR/CFB/etc mode, but is length 0 for ECB
//
{
public:
    BlockCipherImplementation() {};
    virtual ~BlockCipherImplementation() {};

private:
    BlockCipherImplementation( const BlockCipherImplementation & );
    VOID operator=( const BlockCipherImplementation & );

public:
    virtual SIZE_T  msgBlockLen() = 0;

    virtual SIZE_T  chainBlockLen() = 0;

    virtual SIZE_T coreBlockLen() = 0;

    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey ) = 0;

    virtual VOID encrypt(
        _Inout_updates_opt_( cbChain )  PBYTE pbChain,
                                        SIZE_T cbChain,
        _In_reads_( cbData )            PCBYTE pbSrc,
        _Out_writes_( cbData )          PBYTE pbDst,
                                        SIZE_T cbData ) = 0;

    virtual VOID decrypt(
        _Inout_updates_opt_( cbChain )  PBYTE pbChain,
                                        SIZE_T cbChain,
        _In_reads_( cbData )            PCBYTE pbSrc,
        _Out_writes_( cbData )          PBYTE pbDst,
                                        SIZE_T cbData ) = 0;

};

class AuthEncImplementation: public AlgorithmImplementation
//
// Implements authenticated encryption modes.
//
{
public:
    AuthEncImplementation() {};
    virtual ~AuthEncImplementation() {};

private:
    AuthEncImplementation( const AuthEncImplementation & );
    VOID operator=( const AuthEncImplementation & );

public:
    virtual std::set<SIZE_T> getNonceSizes() = 0;

    virtual std::set<SIZE_T> getTagSizes() = 0;

    virtual std::set<SIZE_T> getKeySizes() = 0;

    virtual NTSTATUS setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey ) = 0;

    // The encrypt/decrypt can be called in two ways.
    // First: process an entire message in one call. This requires no flags.
    // Second: incremental processing of a message.
    // For incremental processing, the AUTHENC_FLAG_PARTIAL flag is passed to all
    // calls that are part of the incremental processing.
    // All authdata has to be passed in the first incremental call.
    // The last incremental call is marked by a nonzero pbTag.
    // setTotalCbData() must be called before each sequence of incremental calls.
    // Implementations that don't do incremental processing can simply return
    // STATUS_NOT_SUPPORTED for all incremental calls.

#define AUTHENC_FLAG_PARTIAL 1

    virtual VOID setTotalCbData( SIZE_T cbData ) = 0;   // Set total cbData up front for partial processing (used by CCM)

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
                                    ULONG   flags ) = 0;

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
                                    ULONG   flags ) = 0;
};

class XtsImplementation: public AlgorithmImplementation
{
public:
    XtsImplementation() {};
    virtual ~XtsImplementation() {};

private:
    XtsImplementation( const XtsImplementation & );
    VOID operator=( const XtsImplementation & );

public:
    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey ) = 0;

    virtual VOID encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData ) = 0;

    virtual VOID decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData ) = 0;

};

class StreamCipherImplementation: public AlgorithmImplementation
{
public:
    StreamCipherImplementation() {};
    virtual ~StreamCipherImplementation() {};

private:
    StreamCipherImplementation( const StreamCipherImplementation & );
    VOID operator=( const StreamCipherImplementation & );

public:
    virtual std::set<SIZE_T> getNonceSizes() = 0;

    virtual std::set<SIZE_T> getKeySizes() = 0;

    virtual NTSTATUS setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey ) = 0;

    virtual NTSTATUS setNonce( _In_reads_( cbNonce ) PCBYTE pbNonce, SIZE_T cbNonce ) = 0;

    virtual BOOL isRandomAccess() = 0;

    virtual VOID setOffset( UINT64 offset ) = 0;

    virtual VOID encrypt(
        _In_reads_( cbData )    PCBYTE  pbSrc,
        _Out_writes_( cbData )  PBYTE   pbDst,
                                SIZE_T  cbData ) = 0;
};

class RngSp800_90Implementation: public AlgorithmImplementation
{
public:
    RngSp800_90Implementation() {};
    virtual ~RngSp800_90Implementation() {};

private:
    RngSp800_90Implementation( const RngSp800_90Implementation & );
    VOID operator=( const RngSp800_90Implementation & );

public:
    virtual NTSTATUS instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy ) = 0;
    virtual NTSTATUS reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy ) = 0;
    virtual VOID generate( _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData ) = 0;
};


//
// KDF implementation
//

typedef enum _KDF_ARGUMENT_TYPE {
    KdfArgumentGeneric = 1,            // numeric values are used in KAT files, do not change.
    KdfArgumentPbkdf2 = 2,
    KdfArgumentSp800_108 = 3,
    KdfArgumentTlsPrf = 4,
    KdfArgumentHkdf = 5,
    KdfArgumentSshKdf = 6,
    KdfArgumentSrtpKdf = 7,
} KDF_ARGUMENT_TYPE;

typedef struct _KDF_GENERIC_ARGUMENTS {
    PCBYTE      pbSelector;
    SIZE_T      cbSelector;
} KDF_GENERIC_ARGUMENTS;

typedef struct _KDF_PBKDF2_ARGUMENTS {
    PCBYTE      pbSalt;
    SIZE_T      cbSalt;
    ULONGLONG   iterationCnt;
} KDF_PBKDF2_ARGUMENTS;

typedef struct _KDF_SP800_108_ARGUMENTS {
    PCBYTE      pbLabel;
    SIZE_T      cbLabel;
    PCBYTE      pbContext;
    SIZE_T      cbContext;
} KDF_SP800_108_ARGUMENTS;

typedef struct _KDF_TLSPRF_ARGUMENTS {
    PCBYTE      pbLabel;
    SIZE_T      cbLabel;
    PCBYTE      pbSeed;
    SIZE_T      cbSeed;
} KDF_TLSPRF_ARGUMENTS;

typedef struct _KDF_HKDF_ARGUMENTS {
    PCBYTE      pbSalt;
    SIZE_T      cbSalt;
    PCBYTE      pbInfo;
    SIZE_T      cbInfo;
} KDF_HKDF_ARGUMENTS;

typedef struct _KDF_SSHKDF_ARGUMENTS {
    PCSTR       hashName;
    PCBYTE      pbHashValue;
    SIZE_T      cbHashValue;
    PCBYTE      pbSessionId;
    SIZE_T      cbSessionId;
    BYTE        label;
} KDF_SSHKDF_ARGUMENTS;

typedef struct _KDF_SRTPKDF_ARGUMENTS {
    PCBYTE                      pbSalt;
    SIZE_T                      cbSalt;
    UINT32                      uKeyDerivationRate;
    UINT64                      uIndex;
    UINT32                      uIndexWidth;
    BYTE                        label;
} KDF_SRTPKDF_ARGUMENTS;

typedef struct _KDF_ARGUMENTS {
    KDF_ARGUMENT_TYPE   argType;
    union {
        KDF_GENERIC_ARGUMENTS   uGeneric;
        KDF_PBKDF2_ARGUMENTS    uPbkdf2;
        KDF_SP800_108_ARGUMENTS uSp800_108;
        KDF_TLSPRF_ARGUMENTS    uTlsPrf;
        KDF_HKDF_ARGUMENTS      uHkdf;
        KDF_SSHKDF_ARGUMENTS    uSshKdf;
        KDF_SRTPKDF_ARGUMENTS   uSrtpKdf;
    };
} KDF_ARGUMENTS, *PKDF_ARGUMENTS;
typedef const KDF_ARGUMENTS *PCKDF_ARGUMENTS;

class KdfImplementation: public AlgorithmImplementation
{
public:
    KdfImplementation() {};
    virtual ~KdfImplementation() {};

private:
    KdfImplementation( const KdfImplementation & );
    VOID operator=( const KdfImplementation & );

public:

    virtual VOID derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  args,
        _Out_writes_( cbDst )   PBYTE           pbDst,
                                SIZE_T          cbDst ) = 0;

};

class TlsCbcHmacImplementation: public AlgorithmImplementation
{
public:
    TlsCbcHmacImplementation() {};
    ~TlsCbcHmacImplementation() {};

private:
    TlsCbcHmacImplementation( const TlsCbcHmacImplementation & );
    VOID operator=( const TlsCbcHmacImplementation & );

public:

    virtual NTSTATUS verify(
        _In_reads_( cbKey )     PCBYTE  pbKey,
                                SIZE_T  cbKey,
        _In_reads_( cbHeader )  PCBYTE  pbHeader,
                                SIZE_T  cbHeader,
        _In_reads_( cbData )    PCBYTE  pbData,
                                SIZE_T  cbData ) = 0;
    // Verify a TLS 1.2 CBC HMAC padded record in constant time
};

// ArithImplementation class is only used for performance measurement
class ArithImplementation: public AlgorithmImplementation
{
public:
    ArithImplementation() {};
    virtual ~ArithImplementation() {};

private:
    ArithImplementation( const ArithImplementation & );
    VOID operator=( const ArithImplementation & );

public:
};

// We need an implementation-independent way to store RSA keys
// As RSA key gen is so expensive, we generate a bunch of keys up front and use
// them for all tests.

#define RSAKEY_MAXKEYSIZE   (1024)  // 8192 bits = 1024 bytes
typedef struct _RSAKEY_TESTBLOB {
    UINT32  nBitsModulus;
    UINT64  u64PubExp;
    UINT32  cbModulus;
    UINT32  cbPrime1;
    UINT32  cbPrime2;
    BYTE    abModulus[RSAKEY_MAXKEYSIZE];
    BYTE    abPrime1[RSAKEY_MAXKEYSIZE];
    BYTE    abPrime2[RSAKEY_MAXKEYSIZE];

    // And some fields to make debugging easier
    const char *    pcstrSource;    // Where did this key come from
    INT64  u64Line;                 // line # of test vector file (if applicable)
} RSAKEY_TESTBLOB, *PRSAKEY_TESTBLOB;
typedef const RSAKEY_TESTBLOB * PCRSAKEY_TESTBLOB;

class RsaSignImplementation: public AlgorithmImplementation
{
public:
    RsaSignImplementation() {};
    virtual ~RsaSignImplementation() {};

private:
    RsaSignImplementation( const RsaSignImplementation & );
    VOID operator=( const RsaSignImplementation & );

public:
    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob ) = 0; // Returns an error if this key can't be handled.

    // This is the abstraction that covers both PKCS1 and PSS. Both take a hash alg as parameter.
    // We also add a salt size used for PSS.
    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other,
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig ) = 0;        // cbSig == cbModulus of key

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other ) = 0;
};

class RsaEncImplementation: public AlgorithmImplementation
{
public:
    RsaEncImplementation() {};
    virtual ~RsaEncImplementation() {};

private:
    RsaEncImplementation( const RsaEncImplementation & );
    VOID operator=( const RsaEncImplementation & );

public:
    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob ) = 0; // Returns an error if this key can't be handled.

    // This is the abstraction that covers RAW, PKCS1 and OAEP.
    virtual NTSTATUS encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext ) = 0;        // == cbModulus of key

    virtual NTSTATUS decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg ) = 0;
};

#define DLKEY_MAXKEYSIZE    (1024)  // 8192 bits = 1024 bytes. Generating larger groups is too slow for testing
typedef struct _DLGROUP_TESTBLOB {
    UINT32                  nBitsP;             // P = field prime, Q = subgroup order, G = generator
    UINT32                  cbPrimeP;           //
    UINT32                  cbPrimeQ;           // can be 0 if group order is not known
    SYMCRYPT_DLGROUP_FIPS   fipsStandard;       // Which FIPS standard was used to generate this group
    PCSYMCRYPT_HASH         pHashAlgorithm;     // Used for FIPS group generation
    UINT32                  cbSeed;             // FIPS group generation seed
    UINT32                  genCounter;         // FIPS group generation counter

    BOOLEAN                 fHasPrimeQ;         // Flag that specifies whether the object has a Q parameter
    BOOLEAN                 isSafePrimeGroup;   // Boolean indicating if this is a Safe Prime group
    PCSTR                   pcstrHashAlgName;   // Used for FIPS group generation in multi-implementation tests

    BYTE    abPrimeP[DLKEY_MAXKEYSIZE];     // cbPrimeP bytes
    BYTE    abPrimeQ[DLKEY_MAXKEYSIZE];     // cbPrimeQ bytes (optional)
    BYTE    abGenG[DLKEY_MAXKEYSIZE];       // cbPrimeP bytes
    BYTE    abSeed[DLKEY_MAXKEYSIZE];       // cbSeed bytes, cbSeed = 0 or cbSeed = cbPrimeQ
} DLGROUP_TESTBLOB, *PDLGROUP_TESTBLOB;
typedef const DLGROUP_TESTBLOB * PCDLGROUP_TESTBLOB;

typedef struct _DLKEY_TESTBLOB {
    PCDLGROUP_TESTBLOB  pGroup;
    UINT32              nBitsPriv;                      // Non-zero value indicates Dlkey in DH safe-prime group with
                                                        // specified private key length
    UINT32              cbPrivKey;                      //
    BYTE                abPubKey[DLKEY_MAXKEYSIZE];     // cbPrimeP bytes
    BYTE                abPrivKey[DLKEY_MAXKEYSIZE];    // cbPrivKey bytes
    BOOL                fPrivateModP;                   // private key in range [1,P-2] - not [1,Q-1]
} DLKEY_TESTBLOB, *PDLKEY_TESTBLOB;
typedef const DLKEY_TESTBLOB * PCDLKEY_TESTBLOB;

class DhImplementation: public AlgorithmImplementation
{
public:
    DhImplementation() {};
    virtual ~DhImplementation() {};

private:
    DhImplementation( const DhImplementation & );
    VOID operator=( const DhImplementation & );

public:
    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob ) = 0; // Returns an error if this key can't be handled.

    virtual NTSTATUS sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,   // Must be on same group object
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret ) = 0;
};

class DsaImplementation: public AlgorithmImplementation
{
public:
    DsaImplementation() {};
    virtual ~DsaImplementation() {};

private:
    DsaImplementation( const DsaImplementation & );
    VOID operator=( const DsaImplementation & );

public:
    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob ) = 0; // Returns an error if this key can't be handled.

    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,             // Can be any size, but often = size of Q
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig ) = 0;        // cbSig == 2 * cbPrimeQ of group

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig ) = 0;
};

// RsaImplementation class is only used for performance measurements of RSA
/*
class RsaImplementation: public AlgorithmImplementation
{
public:
    RsaImplementation() {};
    virtual ~RsaImplementation() {};

private:
    RsaImplementation( const RsaImplementation & );
    VOID operator=( const RsaImplementation & );

public:
};
*/

// DlImplementation class is only used for performance measurements of Discrete Log group algorithms
class DlImplementation: public AlgorithmImplementation
{
public:
    DlImplementation() {};
    virtual ~DlImplementation() {};

private:
    DlImplementation( const DlImplementation & );
    VOID operator=( const DlImplementation & );

public:
};

// EccImplementation class is only used for performance measurements of elliptic curve cryptography
class EccImplementation: public AlgorithmImplementation
{
public:
    EccImplementation() {};
    virtual ~EccImplementation() {};

private:
    EccImplementation( const EccImplementation & );
    VOID operator=( const EccImplementation & );

public:
};


//////////////////////////////////////////////////////////////////////////////////
// Template classes for actual concrete implementations
//

//
// A template class to store the state of a hash implementation in.
//
template< class Implementation, class Algorithm> class HashImpState;

//
// A template class for the actual hash algorithm implementations
//
template< class Implementation, class Algorithm >
class HashImp: public HashImplementation
{
public:
    HashImp();
    virtual ~HashImp();

private:
    HashImp( const HashImp & );
    VOID operator=( const HashImp & );

public:

    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual SIZE_T resultLen();
    virtual SIZE_T inputBlockLen();

    virtual void init();
    virtual void append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData );
    virtual void result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult );
    virtual VOID hash(
        _In_reads_( cbData )       PCBYTE pbData,
                                    SIZE_T cbData,
        _Out_writes_( cbResult )    PBYTE pbResult,
                                    SIZE_T cbResult );
    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes );
    virtual NTSTATUS exportSymCryptFormat(
            _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult,
            _In_                                                    SIZE_T  cbResultBufferSize,
            _Out_                                                   SIZE_T *pcbResult );

    HashImpState<Implementation,Algorithm> state;
};

//
// A template class to store the state of a hash implementation in.
//
template< class Implementation, class Algorithm> class ParallelHashImpState;

//
// A template class for the actual hash algorithm implementations
//
template< class Implementation, class Algorithm >
class ParallelHashImp: public ParallelHashImplementation
{
public:
    ParallelHashImp();
    virtual ~ParallelHashImp();

private:
    ParallelHashImp( const ParallelHashImp & );
    VOID operator=( const ParallelHashImp & );

public:

    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual PCSYMCRYPT_HASH SymCryptHash();

    virtual SIZE_T resultLen();

    virtual SIZE_T inputBlockLen();

    virtual VOID init( SIZE_T nHashes );

    virtual VOID process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations );


    virtual NTSTATUS initWithLongMessage( ULONGLONG nBytes );

    ParallelHashImpState<Implementation,Algorithm> state;
};


//
// A template class to store the state of a XOF implementation in.
//
template< class Implementation, class Algorithm> class XofImpState;

//
// A template class for the actual XOF implementations
//
template< class Implementation, class Algorithm >
class XofImp: public XofImplementation
{
public:
    XofImp();
    virtual ~XofImp();

private:
    XofImp( const XofImp & );
    VOID operator=( const XofImp & );

public:

    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual SIZE_T inputBlockLen();

    virtual void init();
    virtual void append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData );
    virtual void extract( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual void result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult );
    virtual VOID xof(
        _In_reads_( cbData )        PCBYTE  pbData,
                                    SIZE_T  cbData,
        _Out_writes_( cbResult )    PBYTE   pbResult,
                                    SIZE_T  cbResult );

    XofImpState<Implementation,Algorithm> state;
};

//
// A template class to store the state of a customizable XOF implementation in.
//
template< class Implementation, class Algorithm> class CustomizableXofImpState;

//
// A template class for the actual XOF implementations
//
template< class Implementation, class Algorithm >
class CustomizableXofImp : public CustomizableXofImplementation
{
public:
    CustomizableXofImp();
    virtual ~CustomizableXofImp();

private:
    CustomizableXofImp(const CustomizableXofImp&);
    VOID operator=(const CustomizableXofImp&);

public:

    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual SIZE_T inputBlockLen();

    virtual void init(
        _In_reads_( cbNstr )        PCBYTE  pbNstr,
                                    SIZE_T  cbNstr,
        _In_reads_( cbSstr )        PCBYTE  pbSstr,
                                    SIZE_T  cbSstr);
    virtual void append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData);
    virtual void extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual void result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult);
    virtual VOID xof(
        _In_reads_( cbNstr )        PCBYTE  pbNstr,
                                    SIZE_T  cbNstr,
        _In_reads_( cbSstr )        PCBYTE  pbSstr,
                                    SIZE_T  cbSstr,
        _In_reads_( cbData )        PCBYTE  pbData,
                                    SIZE_T  cbData,
        _Out_writes_( cbResult )    PBYTE   pbResult,
                                    SIZE_T  cbResult );

    CustomizableXofImpState<Implementation, Algorithm> state;
};


//
// Template class to store the state of a MAC implementation
//
template< class Implementation, class Algorithm> class MacImpState;

//
// Template class for the actual MAC implementations
//
template< class Implementation, class Algorithm >
class MacImp: public MacImplementation
{
public:
    MacImp();
    virtual ~MacImp();

private:
    MacImp( const MacImp & );
    VOID operator=( const MacImp & );

public:

    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

    virtual SIZE_T resultLen();
    virtual SIZE_T inputBlockLen();

    virtual NTSTATUS init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey );
    virtual VOID append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData );
    virtual VOID result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult );
    virtual NTSTATUS mac(
        _In_reads_( cbKey )        PCBYTE pbKey,
                                    SIZE_T cbKey,
        _In_reads_( cbData )       PCBYTE pbData,
                                    SIZE_T cbData,
        _Out_writes_( cbResult )    PBYTE pbResult,
                                    SIZE_T cbResult );

    MacImpState<Implementation,Algorithm> state;
};

//
// A template class to store the state of a KMAC implementation in.
//
template< class Implementation, class Algorithm> class KmacImpState;

//
// Template class for the actual MAC implementations
//
template< class Implementation, class Algorithm >
class KmacImp : public KmacImplementation
{
public:
    KmacImp();
    virtual ~KmacImp();

private:
    KmacImp(const KmacImp&);
    VOID operator=(const KmacImp&);

public:

    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

    virtual SIZE_T inputBlockLen();

    virtual VOID init(
        _In_reads_(cbCustomizationStr)  PCBYTE  pbCustomizationStr,
                                        SIZE_T  cbCustomizationStr,
        _In_reads_(cbKey)               PCBYTE  pbKey, 
                                        SIZE_T  cbKey);

    virtual VOID append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData);
    virtual VOID result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult);
    virtual VOID extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);
    virtual VOID mac(
        _In_reads_(cbCustomizationStr)  PCBYTE  pbCustomizationStr,
                                        SIZE_T  cbCustomizationStr,
        _In_reads_(cbKey)               PCBYTE  pbKey,
                                        SIZE_T  cbKey,
        _In_reads_(cbData)              PCBYTE  pbData,
                                        SIZE_T  cbData,
        _Out_writes_(cbResult)          PBYTE   pbResult,
                                        SIZE_T  cbResult);

    virtual VOID xof(
        _In_reads_(cbCustomizationStr)  PCBYTE  pbCustomizationStr,
                                        SIZE_T  cbCustomizationStr,
        _In_reads_(cbKey)               PCBYTE  pbKey,
                                        SIZE_T  cbKey,
        _In_reads_(cbData)              PCBYTE  pbData,
                                        SIZE_T  cbData,
        _Out_writes_(cbResult)          PBYTE   pbResult,
                                        SIZE_T  cbResult);

    KmacImpState<Implementation, Algorithm> state;
};


template< class Implementation, class Algorithm, class Mode > class BlockCipherImpState;

template< class Implementation, class Algorithm, class Mode >
class BlockCipherImp: public BlockCipherImplementation
{
public:
    BlockCipherImp();
    virtual ~BlockCipherImp();

private:
    BlockCipherImp( const BlockCipherImp & );
    VOID operator=( const BlockCipherImp & );

public:
    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

    virtual SIZE_T msgBlockLen();       // block length of mode (msg must be multiple of this)
    virtual SIZE_T chainBlockLen();     // length of chaining field

    virtual SIZE_T coreBlockLen();      // block length of underlying cipher

    virtual NTSTATUS setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey );
    virtual VOID encrypt(
        _Inout_updates_opt_( cbChain )   PBYTE pbChain,
                                        SIZE_T cbChain,
        _In_reads_( cbData )           PCBYTE pbSrc,
        _Out_writes_( cbData )          PBYTE pbDst,
                                        SIZE_T cbData );
    virtual VOID decrypt(
        _Inout_updates_opt_( cbChain )   PBYTE pbChain,
                                        SIZE_T cbChain,
        _In_reads_( cbData )           PCBYTE pbSrc,
        _Out_writes_( cbData )          PBYTE pbDst,
                                        SIZE_T cbData );

    BlockCipherImpState< Implementation, Algorithm, Mode > state;

};

template< class Implementation, class Algorithm > class XtsImpState;

template< class Implementation, class Algorithm >
class XtsImp: public XtsImplementation
{
public:
    XtsImp();
    virtual ~XtsImp();

private:
    XtsImp( const XtsImp & );
    VOID operator=( const XtsImp & );

public:
    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

    virtual NTSTATUS setKey( PCBYTE pbKey, SIZE_T cbKey );

    virtual VOID encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    virtual VOID decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData );

    XtsImpState< Implementation, Algorithm > state;
};

template< class Implementation, class Algorithm, class Mode >
SIZE_T BlockCipherImp<Implementation, Algorithm, Mode>::chainBlockLen()
{
    if( (Mode::flags & MODE_FLAG_CHAIN) == 0 )
    {
        return 0;
    }

    return coreBlockLen();
}

template< class Implementation, class Algorithm, class Mode >
SIZE_T BlockCipherImp<Implementation, Algorithm, Mode>::msgBlockLen()
{
    if( (Mode::flags & MODE_FLAG_CFB) != 0 )
    {
        return g_modeCfbShiftParam;
    }

    return coreBlockLen();
}

template< class Implementation, class Algorithm, class Mode> class AuthEncImpState;

template< class Implementation, class Algorithm, class Mode >
class AuthEncImp: public AuthEncImplementation
{
public:
    AuthEncImp();
    virtual ~AuthEncImp();

private:
    AuthEncImp( const AuthEncImp & );
    VOID operator=( const AuthEncImp & );

public:
    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

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
        // returns an error only if the request is not supported; only allowed for partial requests.

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
        // returns STATUS_AUTH_TAG_MISMATCH if the tag is wrong.
        // returns STATUS_NOT_SUPPORTED if the request is not supported (only for partial requests)

    AuthEncImpState< Implementation, Algorithm, Mode > state;

};


template< class Implementation, class Algorithm> class StreamCipherImpState;

template< class Implementation, class Algorithm>
class StreamCipherImp: public StreamCipherImplementation
{
public:
    StreamCipherImp();
    virtual ~StreamCipherImp();

private:
    StreamCipherImp( const StreamCipherImp & );
    VOID operator=( const StreamCipherImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
    static const BOOL   s_isRandomAccess;

    virtual std::set<SIZE_T> getNonceSizes();

    virtual std::set<SIZE_T> getKeySizes();

    virtual NTSTATUS setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey );

    virtual NTSTATUS setNonce( _In_reads_( cbNonce ) PCBYTE pbNonce, SIZE_T cbNonce );

    virtual BOOL isRandomAccess() { return s_isRandomAccess; };

    virtual VOID setOffset( UINT64 offset );

    virtual VOID encrypt(
        _In_reads_( cbData )    PCBYTE  pbSrc,
        _Out_writes_( cbData )  PBYTE   pbDst,
                                SIZE_T  cbData );

    StreamCipherImpState< Implementation, Algorithm> state;
};


template< class Implementation, class Algorithm> class RngSp800_90ImpState;

template< class Implementation, class Algorithm>
class RngSp800_90Imp: public RngSp800_90Implementation
{
public:
    RngSp800_90Imp();
    virtual ~RngSp800_90Imp();

private:
    RngSp800_90Imp( const RngSp800_90Imp & );
    VOID operator=( const RngSp800_90Imp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;

    virtual NTSTATUS instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy ) ;
    virtual NTSTATUS reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy );
    virtual VOID generate( _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData );

    RngSp800_90ImpState< Implementation, Algorithm> state;
};

template< class Implementation, class Algorithm, class BaseAlg > class KdfImpState;

template< class Implementation, class Algorithm, class BaseAlg >
class KdfImp: public KdfImplementation
{
public:
    KdfImp();
    virtual ~KdfImp();

private:
    KdfImp( const KdfImp & );
    VOID operator=( const KdfImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;

    virtual VOID derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  args,
        _Out_writes_( cbDst )   PBYTE           pbDst,
                                SIZE_T          cbDst );

    KdfImpState<Implementation,Algorithm,BaseAlg> state;
};

template< class Implementation, class Algorithm >
class TlsCbcHmacImp: public TlsCbcHmacImplementation
{
public:
    TlsCbcHmacImp();
    virtual ~TlsCbcHmacImp();

private:
    TlsCbcHmacImp( const TlsCbcHmacImp & );
    VOID operator=( const TlsCbcHmacImp & );

public:
    static const String s_algName;
    static const String s_modeName;
    static const String s_impName;

    virtual NTSTATUS verify(
        _In_reads_( cbKey )     PCBYTE  pbKey,
                                SIZE_T  cbKey,
        _In_reads_( cbHeader )  PCBYTE  pbHeader,
                                SIZE_T  cbHeader,
        _In_reads_( cbData )    PCBYTE  pbData,
                                SIZE_T  cbData );

};

template< class Implementation, class Algorithm>
class ArithImp: public ArithImplementation
{
public:
    ArithImp();
    virtual ~ArithImp();

private:
    ArithImp( const ArithImp & );
    VOID operator=( const ArithImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};

/*
template< class Implementation, class Algorithm>
class RsaImp: public RsaImplementation
{
public:
    RsaImp();
    virtual ~RsaImp();

private:
    RsaImp( const RsaImp & );
    VOID operator=( const RsaImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};
*/

template< class Implementation, class Algorithm>
class DlImp: public DlImplementation
{
public:
    DlImp();
    virtual ~DlImp();

private:
    DlImp( const DlImp & );
    VOID operator=( const DlImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};

template< class Implementation, class Algorithm > class RsaSignImpState;

template< class Implementation, class Algorithm>
class RsaSignImp: public RsaSignImplementation
{
public:
    RsaSignImp();
    virtual ~RsaSignImp();

private:
    RsaSignImp( const RsaSignImp & );
    VOID operator=( const RsaSignImp & );

public:
    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob );

    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other,
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig );

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig,
                                PCSTR   pcstrHashAlgName,
                                UINT32  u32Other );

    RsaSignImpState<Implementation,Algorithm> state;
};



template< class Implementation, class Algorithm > class RsaEncImpState;

template< class Implementation, class Algorithm>
class RsaEncImp: public RsaEncImplementation
{
public:
    RsaEncImp();
    virtual ~RsaEncImp();

private:
    RsaEncImp( const RsaEncImp & );
    VOID operator=( const RsaEncImp & );

public:
    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual NTSTATUS setKey( PCRSAKEY_TESTBLOB pcKeyBlob );

    virtual NTSTATUS encrypt(
        _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                        SIZE_T  cbMsg,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                        SIZE_T  cbCiphertext );        // == cbModulus of key

    virtual NTSTATUS decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg );

    RsaEncImpState<Implementation,Algorithm> state;
};

template< class Implementation, class Algorithm > class DhImpState;

template< class Implementation, class Algorithm>
class DhImp: public DhImplementation
{
public:
    DhImp();
    virtual ~DhImp();

private:
    DhImp( const DhImp & );
    VOID operator=( const DhImp & );

public:
    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob );

    virtual NTSTATUS sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret );

    DhImpState<Implementation,Algorithm> state;
};

template< class Implementation, class Algorithm > class DsaImpState;

template< class Implementation, class Algorithm>
class DsaImp: public DsaImplementation
{
public:
    DsaImp();
    virtual ~DsaImp();

private:
    DsaImp( const DsaImp & );
    VOID operator=( const DsaImp & );

public:
    static const String s_algName;             // Algorithm name
    static const String s_modeName;
    static const String s_impName;             // Implementation name

    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob ); // Returns an error if this key can't be handled.

    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,             // Can be any size, but often = size of Q
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig );        // cbSig == cbModulus of group

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig );

    DsaImpState<Implementation,Algorithm> state;
};

template< class Implementation, class Algorithm>
class EccImp: public EccImplementation
{
public:
    EccImp();
    virtual ~EccImp();

private:
    EccImp( const EccImp & );
    VOID operator=( const EccImp & );

public:
    static const String s_impName;
    static const String s_modeName;
    static const String s_algName;
};


//
// The stub classes we use to distinguish our implementations and algorithms contain the
// name of said implementation/algorithm. We use this to auto-define the algorithm name
// and implementation name of the *Imp<imp,alg> classes.
//
template< class Implementation, class Algorithm >
const String HashImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String HashImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String HashImp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm >
const String ParallelHashImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String ParallelHashImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String ParallelHashImp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm >
const String XofImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String XofImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String XofImp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm >
const String CustomizableXofImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String CustomizableXofImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String CustomizableXofImp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm >
const String KmacImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String KmacImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String KmacImp<Implementation,Algorithm>::s_impName = Implementation::name;


template< class Implementation, class Algorithm >
const String MacImp<Implementation,Algorithm>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm >
const String MacImp<Implementation,Algorithm>::s_modeName;

template< class Implementation, class Algorithm >
const String MacImp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm, class Mode >
const String BlockCipherImp<Implementation,Algorithm,Mode>::s_algName = Algorithm::name ;

template< class Implementation, class Algorithm, class Mode >
const String BlockCipherImp<Implementation,Algorithm,Mode>::s_modeName = Mode::name ;

template< class Implementation, class Algorithm, class Mode >
const String BlockCipherImp<Implementation,Algorithm,Mode>::s_impName = Implementation::name;

template< class Implementation, class Algorithm, class Mode >
const String AuthEncImp<Implementation, Algorithm, Mode>::s_algName = Algorithm::name;

template< class Implementation, class Algorithm, class Mode >
const String AuthEncImp<Implementation,Algorithm,Mode>::s_modeName = Mode::name ;

template< class Implementation, class Algorithm, class Mode >
const String AuthEncImp<Implementation,Algorithm,Mode>::s_impName = Implementation::name;


template< class Implementation, class Algorithm>
const String StreamCipherImp<Implementation,Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String StreamCipherImp<Implementation,Algorithm>::s_modeName;
template< class Implementation, class Algorithm>
const String StreamCipherImp<Implementation,Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const BOOL StreamCipherImp<Implementation,Algorithm>::s_isRandomAccess = Algorithm::isRandomAccess;

template< class Implementation, class Algorithm>
const String RngSp800_90Imp<Implementation,Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String RngSp800_90Imp<Implementation,Algorithm>::s_modeName;
template< class Implementation, class Algorithm>
const String RngSp800_90Imp<Implementation,Algorithm>::s_impName = Implementation::name;

template< class Implementation, class Algorithm, class BaseAlg >
const String KdfImp<Implementation,Algorithm,BaseAlg>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm, class BaseAlg >
const String KdfImp<Implementation,Algorithm,BaseAlg>::s_modeName = BaseAlg::name;
template< class Implementation, class Algorithm, class BaseAlg >
const String KdfImp<Implementation,Algorithm,BaseAlg>::s_impName = Implementation::name;

template< class Implementation, class Algorithm>
const String XtsImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String XtsImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String XtsImp<Implementation, Algorithm>::s_modeName;

template< class Implementation, class Algorithm>
const String TlsCbcHmacImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String TlsCbcHmacImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String TlsCbcHmacImp<Implementation, Algorithm>::s_modeName;

template< class Implementation, class Algorithm>
const String ArithImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String ArithImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String ArithImp<Implementation, Algorithm>::s_modeName;

/*
template< class Implementation, class Algorithm>
const String RsaImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String RsaImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String RsaImp<Implementation, Algorithm>::s_modeName;
*/

template< class Implementation, class Algorithm>
const String DlImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String DlImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String DlImp<Implementation, Algorithm>::s_modeName;

template< class Implementation, class Algorithm>
const String EccImp<Implementation, Algorithm>::s_impName = Implementation::name;
template< class Implementation, class Algorithm>
const String EccImp<Implementation, Algorithm>::s_algName = Algorithm::name;
template< class Implementation, class Algorithm>
const String EccImp<Implementation, Algorithm>::s_modeName;

template< class Imp, class Alg>
const String RsaSignImp<Imp,Alg>::s_impName = Imp::name;
template< class Imp, class Alg>
const String RsaSignImp<Imp,Alg>::s_algName = Alg::name;
template< class Imp, class Alg>
const String RsaSignImp<Imp,Alg>::s_modeName;

template< class Imp, class Alg>
const String RsaEncImp<Imp,Alg>::s_impName = Imp::name;
template< class Imp, class Alg>
const String RsaEncImp<Imp,Alg>::s_algName = Alg::name;
template< class Imp, class Alg>
const String RsaEncImp<Imp,Alg>::s_modeName;

template< class Imp, class Alg>
const String DhImp<Imp,Alg>::s_impName = Imp::name;
template< class Imp, class Alg>
const String DhImp<Imp,Alg>::s_algName = Alg::name;
template< class Imp, class Alg>
const String DhImp<Imp,Alg>::s_modeName;

template< class Imp, class Alg>
const String DsaImp<Imp,Alg>::s_impName = Imp::name;
template< class Imp, class Alg>
const String DsaImp<Imp,Alg>::s_algName = Alg::name;
template< class Imp, class Alg>
const String DsaImp<Imp,Alg>::s_modeName;

//
// Template declaration for performance functions (for those implementations that wish to use them)
//
template< class Implementation, class Algorithm >
VOID algImpKeyPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );

template< class Implementation, class Algorithm, class Mode >
VOID algImpKeyPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );

template< class Implementation, class Algorithm >
VOID algImpDataPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template< class Implementation, class Algorithm, class Mode >
VOID algImpDataPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template< class Implementation, class Algorithm >
VOID algImpDecryptPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template< class Implementation, class Algorithm, class Mode >
VOID algImpDecryptPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template< class Implementation, class Algorithm >
VOID algImpCleanPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

template< class Implementation, class Algorithm, class Mode >
VOID algImpCleanPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

;


