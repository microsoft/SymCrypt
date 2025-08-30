//
// precomp.h    Precompiled header file for SymCrypt unit test
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Prevent Windows header files from defining min and max macros (breaks STL)
#define NOMINMAX

#ifdef KERNEL_MODE
    //#include <ntddksec.h>
    //#include <ntverp.h>

    //#include <stdio.h>

    #pragma warning(push)
    #pragma warning(disable:4201)
    #include <ntosp.h>
    #pragma warning(pop)

    #include <winerror.h>
    #include <windef.h>

    #include <string>
    #include <winternl.h>

#elif defined(__GNUC__)

    #include <stdio.h>
    #include <cstring>
    #include <cinttypes>
    #include <stdlib.h>
    #include <math.h>
    #include <unistd.h>
    #include <sys/utsname.h>

    #include <chrono>
    #include <vector>
    #include <array>
    #include <string>
    #include <memory>
    #include <algorithm>
    #include <map>
    #include <sstream>
    #include <set>
    #include <cstdarg>
    #include <type_traits>

    #include "symcrypt_no_sal.h"

    // Ignore the multi-character character constant warnings
    #pragma GCC diagnostic ignored "-Wmultichar"

    // Ignore the ISO C++ 11 does allow conversion from string literal to PSTR
    // #pragma GCC diagnostic ignored "-Wc++11-compat-deprecated-writable-strings"

    // Ignore the unused entity issue with UNREFERENCED PARAMETER
    #pragma GCC diagnostic ignored "-Wunused-value"


    #define DWORD       UINT32

    #define PSTR        char *
    #define PCSTR       CONST PSTR
    #define LPSTR       PSTR
    #define LPCSTR      CONST PSTR

    #define PUCHAR      unsigned char *

    #define WCHAR       wchar_t
    #define PWSTR       wchar_t *
    #define LPWSTR      PWSTR

    #define CONST       const
    #define LONGLONG    INT64
    #define ULONGLONG   UINT64

    #define ULONG_PTR   UINT_PTR

    #define LPVOID      PVOID
    #define NTSTATUS    INT32

    #define STATUS_INVALID_SIGNATURE         ((NTSTATUS)0xC000A000L)
    #define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
    #define STATUS_NO_MEMORY                 ((NTSTATUS)0xC0000017L)
    #define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
    #define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
    #define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
    #define NT_SUCCESS(Status)               (((NTSTATUS)(Status)) >= 0)
    #define STATUS_AUTH_TAG_MISMATCH         ((NTSTATUS)0xC000A002L)
    #define STATUS_ENCRYPTION_FAILED         ((NTSTATUS)0xC000028AL)

    #define UNREFERENCED_PARAMETER(x)       (x)

    #define __success(x)
    #define __out_bcount_part_opt(x, y)
    #define WINAPI

    #define BOOL_SUCCESS BOOL

    typedef size_t DWORDREG;
    typedef const DWORDREG DWORDREGC;

    typedef enum {
        BCRYPT_HASH_OPERATION_HASH_DATA = 1,
        BCRYPT_HASH_OPERATION_FINISH_HASH = 2,
    } BCRYPT_HASH_OPERATION_TYPE;

    typedef struct _BCRYPT_MULTI_HASH_OPERATION {
                                uint32_t                        iHash;          // index of hash object
                                BCRYPT_HASH_OPERATION_TYPE      hashOperation;  // operation to be performed
                                PUCHAR                          pbBuffer;       // data to be hashed, or result buffer
                                uint32_t                           cbBuffer;
    } BCRYPT_MULTI_HASH_OPERATION;

    #define InterlockedAdd64(ptr, val) __sync_fetch_and_add(ptr, val)
    #define InterlockedIncrement64(ptr) __sync_fetch_and_add(ptr, 1)
    #define InterlockedDecrement64(ptr) __sync_fetch_and_sub(ptr, 1)

    // aligned_alloc requires size to be integer multiple of alignment
    #define ALIGNED_ALLOC( alignment, size ) aligned_alloc( alignment, (size + (alignment - 1)) & ~(alignment - 1) )
    #define ALIGNED_FREE( ptr ) free( ptr )

    #include <unistd.h>
    #define Sleep(x) sleep((x)/1000)
#else // MSVC
    #include <ntstatus.h>

    // Ensure that windows.h doesn't re-define the status_* symbols
    #define WIN32_NO_STATUS
    #include <windows.h>
    #include <winternl.h>
    #include <winioctl.h>

    //
    // Hack to get all the BCrypt declarations even though our binaries target down-level platforms.
    //
    #pragma push_macro("NTDDI_VERSION")
    #undef NTDDI_VERSION
    #define NTDDI_VERSION NTDDI_WINTHRESHOLD
    #include <bcrypt.h>
    #pragma pop_macro("NTDDI_VERSION")

    #include <stdio.h>
    #include <stdlib.h>
    #include <math.h>
    #include <intrin.h>

    #include <powrprof.h>

    #include <chrono>
    #include <vector>
    #include <array>
    #include <string>
    #include <memory>
    #include <algorithm>
    #include <map>
    #include <sstream>
    #include <set>
    #include <strsafe.h>
    #include <type_traits>

    #ifndef PRIx64
    #define PRIx64       "llx"
    #endif
    #ifndef PRId64
    #define PRId64       "lld"
    #endif

    #define ALIGNED_ALLOC( alignment, size ) _aligned_malloc( size, alignment )
    #define ALIGNED_FREE( ptr ) _aligned_free( ptr )

#endif

#include "symcrypt.h"
#include "symcrypt_low_level.h"
extern "C" {
#include "../../lib/sc_lib.h"
}

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    #include <wmmintrin.h>
    #include <immintrin.h>

    #if SYMCRYPT_GNUC
        #include <x86intrin.h>
        #define _XCR_XFEATURE_ENABLED_MASK (0)
    #endif
#endif

//
// Disable certain strange warnings
//
#pragma warning( disable: 4505 )        // unreferenced local function has been removed.
                                        // Don't understand why I get that one; something about templates...
#pragma warning( disable: 4127 )        // conditional expression is constant
#pragma warning( disable: 6262 )        // excessive stack usage. This is test code, I don't care.
#pragma warning( disable: 4702 )        // unreachable code. The compilers are not equally smart, and some complain
                                        // about 'function must return a value' and some about 'unreachable code'
#pragma warning( disable: 4296 )        // expression is always false - this warning is forced to be an error by a
                                        // pragma in the SDK warning.h, but we don't consider it useful

//
// Macros for different environments
//

#if SYMCRYPT_MS_VC

    #define STRICMP                     _stricmp
    #define STRNICMP                    _strnicmp

    #define SNPRINTF_S(a,b,c,d,...)     _snprintf_s((a),(b),(c),(d),__VA_ARGS__)
    #define VSNPRINTF_S(a,b,c,d,...)    _vsnprintf_s((a),(b),(c),(d),__VA_ARGS__)

    #define GENRANDOM(pbBuf, cbBuf)     BCryptGenRandom( NULL, (PBYTE) (pbBuf), (cbBuf), BCRYPT_USE_SYSTEM_PREFERRED_RNG )

    FORCEINLINE
    PVOID ALLOCATE_FAST_INPROC_MUTEX()
    {
        LPCRITICAL_SECTION lpCriticalSection = new CRITICAL_SECTION;
        InitializeCriticalSection(lpCriticalSection);
        return (PVOID)lpCriticalSection;
    }

    FORCEINLINE
    VOID FREE_FAST_INPROC_MUTEX(PVOID pMutex)
    {
        LPCRITICAL_SECTION lpCriticalSection = (LPCRITICAL_SECTION)pMutex;
        DeleteCriticalSection(lpCriticalSection);
        delete lpCriticalSection;
    }

    #define ACQUIRE_FAST_INPROC_MUTEX(pMutex)  EnterCriticalSection((LPCRITICAL_SECTION)pMutex)
    #define RELEASE_FAST_INPROC_MUTEX(pMutex)  LeaveCriticalSection((LPCRITICAL_SECTION)pMutex)

    #define SLEEP                       Sleep

    #if defined( _X86_ ) | defined( _ARM_ )
        #define BitScanReverseSizeT  _BitScanReverse
    #elif defined( _AMD64_ ) || defined( _ARM64_ )
        #define BitScanReverseSizeT _BitScanReverse64
    #endif

    #define SECUREZEROMEMORY(dest, sz)  RtlSecureZeroMemory( (dest), (sz) )

    #define TRAP_DEBUGGER() do \
    { \
        if( IsDebuggerPresent() ) { DebugBreak(); } \
    } while (false)

#elif SYMCRYPT_GNUC

    #define STRICMP                     strcasecmp
    #define STRNICMP                    strncasecmp

    #define SNPRINTF_S(a,b,c,d,...)     std::snprintf((a),(b),(d),__VA_ARGS__)
    #define VSNPRINTF_S(a,b,c,d,...)    std::vsnprintf((a),(b),(d),__VA_ARGS__)

    #if SYMCRYPT_PLATFORM_APPLE
        #include <Security/Security.h>
        #define GENRANDOM(pbBuf, cbBuf)     SecRandomCopyBytes( kSecRandomDefault, cbBuf, (PBYTE) pbBuf )
    #else
        #include <sys/random.h>
        // write as a function wrapper to handle unexpected return values as errors
        FORCEINLINE
        ssize_t GENRANDOM(void * pbBuf, size_t cbBuf) {
            return (getrandom( pbBuf, cbBuf, 0 ) == (ssize_t) cbBuf) ? 0 : -1;
        }
    #endif

    #include <pthread.h>
    FORCEINLINE
    PVOID ALLOCATE_FAST_INPROC_MUTEX()
    {
        PVOID ptr = malloc(sizeof(pthread_mutex_t));

        if( ptr )
        {
            if( pthread_mutex_init( (pthread_mutex_t *)ptr, NULL ) != 0 )
            {
                free(ptr);
                ptr = NULL;
            }
        }

        return ptr;
    }

    FORCEINLINE
    VOID FREE_FAST_INPROC_MUTEX(PVOID pMutex)
    {
        pthread_mutex_destroy( (pthread_mutex_t *)pMutex );

        free(pMutex);
    }

    #define ACQUIRE_FAST_INPROC_MUTEX(pMutex)   pthread_mutex_lock((pthread_mutex_t *)pMutex)
    #define RELEASE_FAST_INPROC_MUTEX(pMutex)   pthread_mutex_unlock((pthread_mutex_t *)pMutex)

    #define SLEEP                       usleep

    #if defined(__LP64__)
        #define SIZET_BITS_1            63
    #else
        #define SIZET_BITS_1            31
    #endif

    #define BitScanReverseSizeT(pInd, mask)  \
            ({*(pInd) = SIZET_BITS_1 - __builtin_clzl( (mask) ); \
            ( (mask)==0 )? 0 : 1; })

    #define SECUREZEROMEMORY(dest, sz)  ({ \
        memset(dest, 0, sz);               \
        asm volatile("" ::: "memory");      \
    })

#if __linux__
#include <sys/ptrace.h>
#include <csignal>
    #define TRAP_DEBUGGER() do \
    { \
        if( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 ) { raise(SIGTRAP); } \
    } while (false)
#else
    #define TRAP_DEBUGGER()
#endif // __linux__

#endif

#if !defined( INCLUDE_IMPL_RSA32 )
#define INCLUDE_IMPL_RSA32     (1)
#endif

#if !defined( INCLUDE_IMPL_MSBIGNUM )
#define INCLUDE_IMPL_MSBIGNUM  (1)
#endif

#if !defined( INCLUDE_IMPL_CAPI )
#define INCLUDE_IMPL_CAPI      (1)
#endif

#if !defined( INCLUDE_IMPL_CNG )
#define INCLUDE_IMPL_CNG       (1)
#endif

#if !defined( INCLUDE_IMPL_OPENSSL )
// OpenSSL implementation is disabled by default
#define INCLUDE_IMPL_OPENSSL   (0)
#endif

#if !defined( INCLUDE_IMPL_LIBCRUX )
// libcrux implementation is disabled by default
#define INCLUDE_IMPL_LIBCRUX   (0)
#endif

#if !defined( INCLUDE_IMPL_REF )
#define INCLUDE_IMPL_REF       (1)
#endif

// Per https://github.com/llvm/llvm-project/blob/release/17.x/libcxx/docs/ReleaseNotes/17.rst#llvm-18
// LLVM 18+ no longer implements the base template for std::char_traits
// For BString to continue to work, we need to define our own char_traits for BYTE.
// We only implement the functions that are currently required by the use of BString in the test code,
// use of new BString functions may cause compile time errors which can be fixed by adding implementations
// of missing functions.
struct byte_char_traits
{
    using char_type = BYTE;
    using int_type = unsigned int;

    static void assign(BYTE& value1, const BYTE& value2)
    {
        value1 = value2;
    }

    static BYTE* assign(BYTE* ptr, SIZE_T count, BYTE value)
    {
        return static_cast<BYTE*>(memset(ptr, value, count));
    }

    static int compare(const BYTE* ptr1, const BYTE* ptr2, size_t count)
    {
        return memcmp(ptr1, ptr2, count);
    }

    static BYTE* move(BYTE* dest, const BYTE* src, size_t count)
    {
        return static_cast<BYTE*>(memmove(dest, src, count));
    }

    static BYTE* copy(BYTE* dest, const BYTE* src, size_t count)
    {
        return static_cast<BYTE*>(memcpy(dest, src, count));
    }
};

//
// Our own header info
//
typedef std::string String;                                 // String of characters
typedef std::basic_string<BYTE, byte_char_traits> BString;  // String of bytes

#define ARRAY_SIZE( x ) (sizeof(x)/sizeof(x[0]))

#define STRING_INT( x )     #x
#define STRING( x )         STRING_INT( x )         // This extra macro indirection ensures we get enough macro expansion.
#define LSTRING_INT( x )    L#x
#define LSTRING( x )        LSTRING_INT( x )

#define CONCAT_I2( a, b )       a##b
#define CONCAT_I3( a, b, c )    a##b##c
#define CONCAT_I4( a, b, c, d ) a##b##c##d


#define CONCAT2( a, b )         CONCAT_I2( a, b )
#define CONCAT3( a, b, c )      CONCAT_I3( a, b, c )
#define CONCAT4( a, b, c, d )   CONCAT_I4( a, b, c, d )

#define ImpXxx              CONCAT2( Imp, IMP_Name )
#define AlgXxx              CONCAT2( Alg, ALG_Name )
#define ModeXxx             CONCAT2( Mode, ALG_Mode )
#define BaseAlgXxx          CONCAT2( Alg, ALG_Base )


#define SCSHIM_Xxx(...)                 CONCAT2( ScShimSymCrypt, ALG_Name )(__VA_ARGS__)
#define SCSHIM_XXX_STATE                CONCAT3( SYMCRYPT_, ALG_NAME, _STATE )
#define SCSHIM_XXX_EXPANDED_KEY         CONCAT3( SYMCRYPT_, ALG_NAME, _EXPANDED_KEY )

#define SCSHIM_XxxStateCopy(...)        CONCAT3( ScShimSymCrypt, ALG_Name, StateCopy )(__VA_ARGS__)
#define SCSHIM_XxxInit(...)             CONCAT3( ScShimSymCrypt, ALG_Name, Init )(__VA_ARGS__)
#define SCSHIM_XxxAppend(...)           CONCAT3( ScShimSymCrypt, ALG_Name, Append )(__VA_ARGS__)
#define SCSHIM_XxxResult(...)           CONCAT3( ScShimSymCrypt, ALG_Name, Result )(__VA_ARGS__)
#define SCSHIM_XxxResultEx(...)         CONCAT3( ScShimSymCrypt, ALG_Name, ResultEx )(__VA_ARGS__)
#define SCSHIM_XxxExtract(...)          CONCAT3( ScShimSymCrypt, ALG_Name, Extract )(__VA_ARGS__)
#define SCSHIM_XxxAppendBlocks(...)     CONCAT3( ScShimSymCrypt, ALG_Name, AppendBlocks )(__VA_ARGS__)
#define SCSHIM_XxxExpandKey(...)        CONCAT3( ScShimSymCrypt, ALG_Name, ExpandKey )(__VA_ARGS__)
#define SCSHIM_XxxExpandKeyEx(...)      CONCAT3( ScShimSymCrypt, ALG_Name, ExpandKeyEx )(__VA_ARGS__)
#define SCSHIM_XxxKeyCopy(...)          CONCAT3( ScShimSymCrypt, ALG_Name, KeyCopy )(__VA_ARGS__)
#define SCSHIM_XxxEncrypt(...)          CONCAT3( ScShimSymCrypt, ALG_Name, Encrypt )(__VA_ARGS__)
#define SCSHIM_XxxDecrypt(...)          CONCAT3( ScShimSymCrypt, ALG_Name, Decrypt )(__VA_ARGS__)
#define SCSHIM_XxxXxxEncrypt(...)       CONCAT4( ScShimSymCrypt, ALG_Name, ALG_Mode, Encrypt )(__VA_ARGS__)
#define SCSHIM_XxxXxxDecrypt(...)       CONCAT4( ScShimSymCrypt, ALG_Name, ALG_Mode, Decrypt )(__VA_ARGS__)
#define SCSHIM_XxxStateExport(...)      CONCAT3( ScShimSymCrypt, ALG_Name, StateExport )(__VA_ARGS__)
#define SCSHIM_XxxStateImport(...)      CONCAT3( ScShimSymCrypt, ALG_Name, StateImport )(__VA_ARGS__)
#define SCSHIM_XxxAlgorithm             CONCAT3( ScShimSymCrypt, ALG_Name, Algorithm )

#define SCSHIM_BaseXxxAlgorithm         CONCAT3( ScShimSymCrypt, ALG_Base, Algorithm )

#define SCSHIM_XXX_BLOCK_SIZE           CONCAT3( SYMCRYPT_, ALG_NAME, _BLOCK_SIZE )
#define SCSHIM_XXX_INPUT_BLOCK_SIZE     CONCAT3( SYMCRYPT_, ALG_NAME, _INPUT_BLOCK_SIZE )
#define SCSHIM_XXX_RESULT_SIZE          CONCAT3( SYMCRYPT_, ALG_NAME, _RESULT_SIZE )
#define SCSHIM_XXX_STATE_EXPORT_SIZE    CONCAT3( SYMCRYPT_, ALG_NAME, _STATE_EXPORT_SIZE )


#define RSA32_XXX_INPUT_BLOCK_SIZE      CONCAT3( RSA32_, ALG_NAME, _INPUT_BLOCK_SIZE )
#define RSA32_XXX_RESULT_SIZE           CONCAT3( RSA32_, ALG_NAME, _RESULT_SIZE )
#define RSA32_XXX_BLOCK_SIZE            CONCAT3( RSA32_, ALG_NAME, _BLOCK_SIZE )

#define CNG_XXX_CHAIN_MODE              CONCAT2( BCRYPT_CHAIN_MODE_, ALG_MODE )

#define CNG_XXX_HASH_ALG_NAMEU          CONCAT3( Cng, ALG_Base, HashAlgNameU )

#define SYMCRYPT_2DES_BLOCK_SIZE        SYMCRYPT_3DES_BLOCK_SIZE
#define BCRYPT_2DES_ALGORITHM           BCRYPT_3DES_112_ALGORITHM


#define MAX_SIZE_T                      ((SIZE_T) -1)

//
// Discriminator classes, one for each algorithm.
// These are used to specialize our algorithm implementation template classes.
//

class AlgMd2{
public:
    static constexpr const char * name = "Md2";
};

class AlgMd4{
public:
    static constexpr const char * name = "Md4";
};

class AlgMd5{
public:
    static constexpr const char * name = "Md5";
};

class AlgSha1{
public:
    static constexpr const char * name = "Sha1";
};

class AlgSha224{
public:
    static constexpr const char * name = "Sha224";
};

class AlgSha256{
public:
    static constexpr const char * name = "Sha256";
};

class AlgSha384{
public:
    static constexpr const char * name = "Sha384";
};

class AlgSha512{
public:
    static constexpr const char * name = "Sha512";
};

class AlgSha512_224{
public:
    static constexpr const char * name = "Sha512-224";
};

class AlgSha512_256{
public:
    static constexpr const char * name = "Sha512-256";
};

class AlgSha3_224{
public:
    static constexpr const char * name = "Sha3-224";
};

class AlgSha3_256{
public:
    static constexpr const char * name = "Sha3-256";
};

class AlgSha3_384{
public:
    static constexpr const char * name = "Sha3-384";
};

class AlgSha3_512{
public:
    static constexpr const char * name = "Sha3-512";
};

class AlgShake128{
public:
    static constexpr const char * name = "Shake128";
};

class AlgShake256{
public:
    static constexpr const char * name = "Shake256";
};

class AlgCShake128{
public:
    static constexpr const char * name = "CShake128";
};

class AlgCShake256{
public:
    static constexpr const char * name = "CShake256";
};

class AlgKmac128{
public:
    static constexpr const char * name = "Kmac128";
};

class AlgKmac256{
public:
    static constexpr const char * name = "Kmac256";
};

class AlgHmacMd5{
public:
    static constexpr const char * name = "HmacMd5";
};

class AlgHmacSha1{
public:
    static constexpr const char * name = "HmacSha1";
};

class AlgHmacSha224{
public:
    static constexpr const char * name = "HmacSha224";
};

class AlgHmacSha256{
public:
    static constexpr const char * name = "HmacSha256";
};

class AlgHmacSha384{
public:
    static constexpr const char * name = "HmacSha384";
};

class AlgHmacSha512{
public:
    static constexpr const char * name = "HmacSha512";
};

class AlgHmacSha512_224{
public:
    static constexpr const char * name = "HmacSha512-224";
};

class AlgHmacSha512_256{
public:
    static constexpr const char * name = "HmacSha512-256";
};

class AlgHmacSha3_224{
public:
    static constexpr const char * name = "HmacSha3-224";
};

class AlgHmacSha3_256{
public:
    static constexpr const char * name = "HmacSha3-256";
};

class AlgHmacSha3_384{
public:
    static constexpr const char * name = "HmacSha3-384";
};

class AlgHmacSha3_512{
public:
    static constexpr const char * name = "HmacSha3-512";
};

class AlgAesCmac{
public:
	static constexpr const char * name = "AesCmac";
};

class AlgMarvin32{
public:
	static constexpr const char * name = "Marvin32";
};

class AlgAes{
public:
    static constexpr const char * name = "Aes";
};

class AlgDes{
public:
    static constexpr const char * name = "Des";
};

class Alg2Des{
public:
    static constexpr const char * name = "Des2";
};

class Alg3Des{
public:
    static constexpr const char * name = "Des3";
};

class AlgDesx{
public:
    static constexpr const char * name = "Desx";
};

class AlgRc2{
public:
    static constexpr const char * name = "Rc2";
};

class AlgRc4{
public:
    static constexpr const char * name = "Rc4";
    static BOOL isRandomAccess;
};

class AlgChaCha20 {
public:
    static constexpr const char * name = "ChaCha20";
    static BOOL isRandomAccess;
};

class AlgPoly1305 {
public:
    static constexpr const char * name = "Poly1305";
};

class AlgChaCha20Poly1305 {
public:
    static constexpr const char * name = "ChaCha20Poly1305";
};

class AlgAesCtrDrbg{
public:
    static constexpr const char * name = "AesCtrDrbg";
};

class AlgAesCtrF142{
public:
    static constexpr const char * name = "AesCtrF142";
};

class AlgDynamicRandom{
public:
    static constexpr const char * name = "DynamicRandom";
};

class AlgParallelSha256{
public:
    static constexpr const char * name = "ParSha256";
    static constexpr const WCHAR * pwstrBasename = L"SHA256";
};

class AlgParallelSha384{
public:
    static constexpr const char * name = "ParSha384";
    static constexpr const WCHAR * pwstrBasename = L"SHA384";
};

class AlgParallelSha512{
public:
    static constexpr const char * name = "ParSha512";
    static constexpr const WCHAR * pwstrBasename = L"SHA512";
};

class AlgPbkdf2{
public:
    static constexpr const char * name = "Pbkdf2";
};

class AlgSp800_108{
public:
    static constexpr const char * name = "Sp800_108";
};

class AlgTlsPrf1_1{
public:
    static constexpr const char * name = "TlsPrf1_1";
};

class AlgTlsPrf1_2{
public:
    static constexpr const char * name = "TlsPrf1_2";
};

class AlgSshKdf{
public:
    static constexpr const char * name = "SshKdf";
};

class AlgSrtpKdf{
public:
    static constexpr const char * name = "SrtpKdf";
};

class AlgHkdf{
public:
    static constexpr const char * name = "Hkdf";
};

class AlgSskdfMac{
public:
    static constexpr const char * name = "SskdfMac";
};

class AlgSskdfHash{
public:
    static constexpr const char * name = "SskdfHash";
};

class AlgXtsAes{
public:
    static constexpr const char * name = "XtsAes";
};

class AlgAesKw{
public:
    static constexpr const char * name = "AesKw";
};

class AlgAesKwp{
public:
    static constexpr const char * name = "AesKwp";
};

class AlgTlsCbcHmacSha1 {
public:
    static constexpr const char * name = "TlsCbcHmacSha1";
};

class AlgTlsCbcHmacSha256 {
public:
    static constexpr const char * name = "TlsCbcHmacSha256";
};

class AlgTlsCbcHmacSha384 {
public:
    static constexpr const char * name = "TlsCbcHmacSha384";
};

#define MODE_FLAG_CHAIN 1
#define MODE_FLAG_CFB   2

class ModeEcb{
public:
    static constexpr const char * name = "Ecb";
    static ULONG flags;
};

class ModeCbc{
public:
    static constexpr const char * name = "Cbc";
    static ULONG flags;
};

class ModeCfb{
public:
    static constexpr const char * name = "Cfb";
    static ULONG flags;
};

class ModeCcm{
public:
    static constexpr const char * name = "Ccm";
};

class ModeGcm{
public:
    static constexpr const char * name = "Gcm";
};

class ModeNone {
public:
    static constexpr const char * name = "";
};

class AlgIntAdd{
public:
    static constexpr const char * name = "IntAdd";
};

class AlgIntSub{
public:
    static constexpr const char * name = "IntSub";
};

class AlgIntMul{
public:
    static constexpr const char * name = "IntMul";
};

class AlgIntSquare{
public:
    static constexpr const char * name = "IntSquare";
};

class AlgIntDivMod{
public:
    static constexpr const char * name = "IntDivMod";
};

class AlgModAdd{
public:
    static constexpr const char * name = "ModAdd";
};

class AlgModSub{
public:
    static constexpr const char * name = "ModSub";
};

class AlgModMul{
public:
    static constexpr const char * name = "ModMul";
};

class AlgModSquare{
public:
    static constexpr const char * name = "ModSquare";
};

class AlgModInv{
public:
    static constexpr const char * name = "ModInv";
};

class AlgModExp{
public:
    static constexpr const char * name = "ModExp";
};

class AlgScsTable{
public:
    static constexpr const char * name = "ScsTable";
};

class AlgIEEE802_11SaeCustom{
public:
    static constexpr const char * name = "IEEE802_11SaeCustom";
};

class AlgTrialDivision{
public:
    static constexpr const char * name = "TrialDivision";
};

class AlgTrialDivisionContext{
public:
    static constexpr const char * name = "TrialDivisionContext";
};

class AlgWipe{
public:
    static constexpr const char * name = "Wipe";
};

class AlgRsaEncRaw{
public:
    static constexpr const char * name = "RsaEncRaw";
};

class AlgRsaEncPkcs1{
public:
    static constexpr const char * name = "RsaEncPkcs1";
};

class AlgRsaEncOaep{
public:
    static constexpr const char * name = "RsaEncOaep";
};

class AlgRsaSignPkcs1{
public:
    static constexpr const char * name = "RsaSignPkcs1";
};

class AlgRsaSignPss{
public:
    static constexpr const char * name = "RsaSignPss";
};

// Used only for performance testing
class AlgRsakeySetValue{
public:
    static constexpr const char * name = "RsakeySetValue";
};

class AlgRsakeySetValueFromPrivateExponent{
public:
    static constexpr const char * name = "RsakeySetValueFromPrivateExponent";
};

class AlgDsaSign{
public:
    static constexpr const char * name = "DsaSign";
};

class AlgDsaVerify{
public:
    static constexpr const char * name = "DsaVerify";
};

class AlgDh{
public:
    static constexpr const char * name = "Dh";
};

class AlgDsa{
public:
    static constexpr const char * name = "Dsa";
};

class AlgEcurveAllocate{
public:
    static constexpr const char * name = "EcurveAllocateAndFree";
};

class AlgEckeySetRandom{
public:
    static constexpr const char * name = "EckeySetRandom";
};

class AlgEcpointSetZero{
public:
    static constexpr const char * name = "EcpointSetZero";
};

class AlgEcpointSetDistinguished{
public:
    static constexpr const char * name = "EcpointSetDistinguished";
};

class AlgEcpointSetRandom{
public:
    static constexpr const char * name = "EcpointSetRandom";
};

class AlgEcpointIsEqual{
public:
    static constexpr const char * name = "EcpointIsEqual";
};

class AlgEcpointIsZero{
public:
    static constexpr const char * name = "EcpointIsZero";
};

class AlgEcpointOnCurve{
public:
    static constexpr const char * name = "EcpointOnCurve";
};

class AlgEcpointAdd{
public:
    static constexpr const char * name = "EcpointAdd";
};

class AlgEcpointAddDiffNz{
public:
    static constexpr const char * name = "EcpointAddDiffNz";
};

class AlgEcpointDouble{
public:
    static constexpr const char * name = "EcpointDouble";
};

class AlgEcpointScalarMul{
public:
    static constexpr const char * name = "EcpointScalarMul";
};

class AlgEcdsaSign{
public:
    static constexpr const char * name = "EcdsaSign";
};

class AlgEcdsaVerify{
public:
    static constexpr const char * name = "EcdsaVerify";
};

class AlgEcdh{
public:
    static constexpr const char * name = "Ecdh";
};

// Used only for performance testing
class AlgEckeySetValue{
public:
    static constexpr const char * name = "EckeySetValue";
};

class AlgXmss {
public:
    static constexpr const char * name = "Xmss";
};

class AlgLms {
public:
    static constexpr const char * name = "Lms";
};

class AlgMlKem{
public:
    static constexpr const char * name = "MlKem";
};

// Used only for performance testing
// In ML-KEM, an important operation is importing an encapsulation key to a key object
class AlgMlKemkeySetValue{
public:
    static constexpr const char * name = "MlKemkeySetValue";
};

class AlgMlDsa{
public:
    static constexpr const char * name = "MlDsa";
};

// Used only for performance testing
class AlgMlDsakeySetValue{
public:
    static constexpr const char * name = "MlDsakeySetValue";
};

class AlgDeveloperTest{
public:
    static constexpr const char * name = "DeveloperTest";
};

//
// Macros for easy testing
//
#define FATAL( text ) {fatal( __FILE__, __LINE__, text );}
#define FATAL2( text, a ) {fatal( __FILE__, __LINE__, text, a );}
#define FATAL3( text, a, b ) {fatal( __FILE__, __LINE__, text, a, b );}
#define FATAL4( text, a, b, c  ) {fatal( __FILE__, __LINE__, text, a, b, c );}
#define FATAL5( text, a, b, c, d ) {fatal( __FILE__, __LINE__, text, a, b, c, d );}
#define FATAL6( text, a, b, c, d, e ) {fatal( __FILE__, __LINE__, text, a, b, c, d, e );}
#define CHECK( cond, text )           { if( !(cond) ) { fatal(__FILE__, __LINE__, text          );}; _Analysis_assume_( cond );}
#define CHECK3( cond, text, a )       { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a       );}; _Analysis_assume_( cond );}
#define CHECK4( cond, text, a, b )    { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a, b    );}; _Analysis_assume_( cond );}
#define CHECK5( cond, text, a, b, c ) { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a, b, c );}; _Analysis_assume_( cond );}
#define SOFTCHECK( cond, text ) if( !(cond) ) { print( "%s(%d): %s\n", __FILE__, __LINE__, text ); }

extern DWORD g_osVersion;       // 0xaabb for major version aa and minor version bb

#define OS_VERSION_VISTA    0x0600
#define OS_VERSION_WIN7     0x0601
#define OS_VERSION_WIN8     0x0602
#define OS_VERSION_WIN8_1   0x0603

_Analysis_noreturn_
VOID
fatal( _In_ PCSTR file, ULONG line, _In_ PCSTR text, ... );

typedef CONST CHAR * PCCHAR;

#include "kat.h"
#include "rng.h"
#include "perf.h"

extern SIZE_T   g_modeCfbShiftParam;

#include "algorithm_base.h"

typedef std::vector<AlgorithmImplementation *> AlgorithmImplementationVector;
extern AlgorithmImplementationVector g_algorithmImplementation;

#include "perfprint.h"

typedef std::set<String> StringSet;
extern StringSet g_algorithmsToTest;
extern StringSet g_implementationsToTest;
BOOL setContainsPrefix( const StringSet & set, const std::string & str );

#include "main_inline.h"
#include "resultMerge.h"

extern const char * g_implementationNames[];

//
// Include the info from the implementations we support on this compilation
//

// We always include the SymCrypt implementation
#include "sc_implementations.h"

#if INCLUDE_IMPL_CAPI
#include "capi_implementations.h"
#endif

#if INCLUDE_IMPL_CNG
#include "cng_implementations.h"
#endif

#if INCLUDE_IMPL_MSBIGNUM
#include "msbignum_implementations.h"
#endif

#if INCLUDE_IMPL_REF
#include "ref_implementations.h"
#endif

#if INCLUDE_IMPL_RSA32
#include "rsa32_implementations.h"
#endif

#if INCLUDE_IMPL_OPENSSL
#include "openssl_implementations.h"
#endif

#if INCLUDE_IMPL_LIBCRUX
#include "libcrux_implementations.h"
#endif

#include "printtable.h"

#include "rndDriver.h"

extern Rng g_rng;

extern BOOL g_showPerfRangeInfo;

extern BOOL g_verbose;

extern BOOL g_profile;
extern UINT32 g_profile_iterations;
extern UINT32 g_profile_key;

extern BOOL g_measure_specific_sizes;
extern UINT32 g_measure_sizes_start;
extern UINT32 g_measure_sizes_end;
extern UINT32 g_measure_sizes_increment;
extern UINT32 g_measure_sizes_repetitions;
extern String g_measure_sizes_stringPrefix;

extern BOOL g_perfTestsRunning;

extern ULONG    g_rc2EffectiveKeyLength;

extern ULONG g_cngKeySizeFlag;

extern double g_tscFreq;

extern BOOL g_sgx;

extern PVOID g_dynamicSymCryptModuleHandle;

extern BOOL g_useDynamicFunctionsInTestCall;

// Environment specific functions for handling dynamic modules

PVOID loadDynamicModuleFromPath(PCSTR dynamicModulePath);
// dlopen on Linux, LoadLibraryA on Windows

typedef enum {
    SCTEST_DYNSYM_FUNCTION_PTR = 1,
    SCTEST_DYNSYM_SYMBOL_PTR = 2,
    SCTEST_DYNSYM_ARRAY = 3,
} SCTEST_DYNSYM_TYPE;

PVOID getDynamicSymbolPointerFromString(PVOID hModule, PCSTR pSymbolName, SCTEST_DYNSYM_TYPE symbolType);
// dlsym on Linux, GetProcAddress on Windows
//
// We distinguish between looking up function pointers and symbols
// Looked up function pointers must be callable by the unit test executable, so the
// pointers must be to functions in the address space of the unit tests, which invoke
// the SymCrypt API in the module under test
//
// Looked up symbols may or may not be in the address space of the unit tests.
// Looked up extern arrays (i.e. SymCryptSha256OidList) are _not_ dereferenced by the unit tests
// before being passed back to dynamic SymCrypt functions. They must be a symbol address which is
// directly consumed by the eventual SymCrypt module under test (i.e. may not be in the address
// space of the unit tests)
// Looked up extern pointers (i.e. SymCryptSha256Algorithm) _are_ dereferenced by the unit tests
// before being passed back to dynamic SymCrypt functions. They must be an address in the unit tests'
// address space which contains a value of the pointer which is consumed by the SymCrypt module under
// test

SYMCRYPT_CPU_FEATURES SctestDisableCpuFeatures(SYMCRYPT_CPU_FEATURES disable);
// Optional function that dynamic test modules may expose to enable the unit tests to disable certain
// CPU features from being used.
//
// If present must only be called once just after a call to SymCryptModuleInit as some test modules may
// defer full initialization until they know which features to disable. We do it this way as CPU features
// may affect the memory layout of internal SymCrypt structures, so for the lifetime of the module the
// CPU features available must be consistent.
//
// Returns the CPU features mask that will be used in the dynamic test module.
//
// Currently assumes that the unit test binary will have the same CPU architecture as the module under test

VOID
initVectorRegisters();

VOID
verifyVectorRegisters();

VOID
cleanVectorRegisters();

//
// Wrappers for calls into SymCrypt which check that vector registers are saved/restored appropriately
//
// initVectorRegisters sets up vector registers to be in a state that should not be modified by a call
// verifyVectorRegisters checks that the state that should not have been modified has not been modified
//
// These additional calls may do nothing if TestSaveXXXEnabled is FALSE, but it can also:
//  On Windows AMD64 set Xmm6-Xmm15 to random values
//    these values are non-volatile in Window x64 ABI, so should be preserved. If they are not
//    preserved it indicates a problem with our assembly not adhering to the Windows ABI
//  On Linux AMD64 set Ymm0-Ymm15 to random values
//    these values are naturally volatile on Linux, but symcryptunittest callers may specify the
//    following environment variable:
//      GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX_Usable,-AVX_Fast_Unaligned_Load,-AVX2_Usable
//    to avoid use of AVX in glibc. This means we can test the Ymm save/restore logic that is
//    used in Windows kernel using Linux user mode.
//
template<typename Functor, typename... Args>
auto ScTestCallFunctionWithVectorRegistersTest(Functor f, Args&&... args)
-> typename std::enable_if < std::is_same<decltype(f(std::forward<Args>(args)...)), void>::value, void>::type
{
    initVectorRegisters();
    f(std::forward<Args>(args)...);
    verifyVectorRegisters();
    return;
}

template<typename Functor, typename... Args>
auto ScTestCallFunctionWithVectorRegistersTest(Functor f, Args&&... args)
-> typename std::enable_if < !std::is_same<decltype(f(std::forward<Args>(args)...)), void>::value, decltype(f(std::forward<Args>(args)...))>::type
{
    initVectorRegisters();
    auto result = f(std::forward<Args>(args)...);
    verifyVectorRegisters();
    return result;
}

//
// Lookup dynamic symbol, may return NULL if symbol cannot be found
//
// Note that because we use static variables here, 1 call to getDynamicSymbolPointerFromString (the
// actual environment specific dynamic symbol lookup function) is performed per scope in which this
// lambda function is instantiated
// This means we have a few more (maybe ~10x - depending on how many locations lookup the same symbol)
// dynamic symbol lookups than are strictly needed, but it does not materially impact on unit test
// runtime, and our performance testing infrastructure can easily handle the first run of a function
// of interest being more costly
//
// We have the IsCallable parameter to distinguish between symbols the unit tests are looking up in
// the module to call vs. symbols the module is looking up to pass back to the module.
//
#define SCTEST_LOOKUP_DYNSYM(SymCryptSymbol, IsCallable) \
    []() { \
        static PVOID dynamicSymbolStatic = NULL; \
        static bool lookupAttempted = false; \
        if (!lookupAttempted) \
        { \
            SCTEST_DYNSYM_TYPE symbolType = SCTEST_DYNSYM_SYMBOL_PTR; \
            if( IsCallable ) \
            { \
                symbolType = SCTEST_DYNSYM_FUNCTION_PTR; \
            } else if( std::is_array<decltype(SymCryptSymbol)>::value ) { \
                symbolType = SCTEST_DYNSYM_ARRAY; \
            } \
            dynamicSymbolStatic = getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, #SymCryptSymbol, symbolType); \
            lookupAttempted = true; \
        } \
        return (decltype(&SymCryptSymbol)) dynamicSymbolStatic; \
    }()

// Get dynamic symbol - Fatal if symbol cannot be found
#define SCTEST_GET_DYNSYM(SymCryptSymbol, IsCallable) \
    []() { \
        decltype(&SymCryptSymbol) dynamicSymbol = SCTEST_LOOKUP_DYNSYM(SymCryptSymbol, IsCallable); \
        CHECK4(dynamicSymbol != NULL, "Could not find %s %s", #SymCryptSymbol, "Function" ); \
        return dynamicSymbol; \
    }()

// In a template for ImpSc call statically linked function with Vector register save/restore tests
// In a template for ImpScStatic call statically linked function directly
// In a template for ImpScDynamic call dynamically linked function
#define SCTEST_CALL_SCIMPFN_0(SymCryptFunction) \
    [&]() { \
        if constexpr ( std::is_same<ImpXxx, ImpSc>::value ) \
        { \
            return ScTestCallFunctionWithVectorRegistersTest(SymCryptFunction); \
        } \
        else if constexpr ( std::is_same<ImpXxx, ImpScStatic>::value ) \
        { \
            return SymCryptFunction(); \
        } \
        else if constexpr ( std::is_same<ImpXxx, ImpScDynamic>::value ) \
        { \
            return SCTEST_GET_DYNSYM(SymCryptFunction, TRUE)(); \
        } \
        else \
        { \
            CHECK(FALSE, "Instantiation of SCTEST_CALL_SCIMPFN_0 in unexpected scope"); \
        } \
    }()

#define SCTEST_CALL_SCIMPFN(SymCryptFunction, ...) \
    [&]() { \
        if constexpr ( std::is_same<ImpXxx, ImpSc>::value ) \
        { \
            return ScTestCallFunctionWithVectorRegistersTest(SymCryptFunction, __VA_ARGS__); \
        } \
        else if constexpr ( std::is_same<ImpXxx, ImpScStatic>::value ) \
        { \
            return SymCryptFunction(__VA_ARGS__); \
        } \
        else if constexpr ( std::is_same<ImpXxx, ImpScDynamic>::value ) \
        { \
            return SCTEST_GET_DYNSYM(SymCryptFunction, TRUE)(__VA_ARGS__); \
        } \
        else \
        { \
            CHECK(FALSE, "Instantiation of SCTEST_CALL_SCIMPFN in unexpected scope"); \
        } \
    }()

// In a template for ImpSc or ImpScStatic return pointer to statically linked symbol
// In a template for ImpScDynamic return pointer to dynamically linked symbol if it is available
#define SCTEST_LOOKUP_SCIMPSYM(SymCryptSymbol) \
    []() { \
        if constexpr (  std::is_same<ImpXxx, ImpSc>::value || \
                        std::is_same<ImpXxx, ImpScStatic>::value ) \
        { \
            return &SymCryptSymbol; \
        } \
        else if constexpr ( std::is_same<ImpXxx, ImpScDynamic>::value ) \
        { \
            return SCTEST_LOOKUP_DYNSYM(SymCryptSymbol, FALSE); \
        } \
        else \
        { \
            CHECK(FALSE, "Instantiation of SCTEST_LOOKUP_SCIMPSYM in unexpected scope"); \
        } \
    }()

// Some tests do not use the multi-implementation setup with templates, but instead call the SymCrypt
// API directly. We can refactor these tests to optionally call the static or dynamic functions based
// on the value of g_useDynamicFunctionsInTestCall, using the following SCTEST_CALL_DISPATCHFN macros

#define SCTEST_CALL_DISPATCHFN_0(SymCryptFunction) \
    []() { \
        if( g_useDynamicFunctionsInTestCall ) \
        { \
            return SCTEST_GET_DYNSYM(SymCryptFunction, TRUE)(); \
        } \
        return ScTestCallFunctionWithVectorRegistersTest(SymCryptFunction); \
    }()

#define SCTEST_CALL_DISPATCHFN(SymCryptFunction, ...) \
    [&]() { \
        if( g_useDynamicFunctionsInTestCall ) \
        { \
            return SCTEST_GET_DYNSYM(SymCryptFunction, TRUE)(__VA_ARGS__); \
        } \
        return ScTestCallFunctionWithVectorRegistersTest(SymCryptFunction, __VA_ARGS__); \
    }()

#define SCTEST_LOOKUP_DISPATCHSYM(SymCryptSymbol) \
    []() { \
        if( g_useDynamicFunctionsInTestCall ) \
        { \
            return SCTEST_LOOKUP_DYNSYM(SymCryptSymbol, FALSE); \
        } \
        return &SymCryptSymbol; \
    }()

#include "sc_dispatch_shims.h"

template< typename AlgType >
std::unique_ptr<std::vector<AlgType *>> getAlgorithmsOfOneType( );


extern BOOLEAN     TestSelftestsEnabled;
extern BOOLEAN     TestSaveXmmEnabled;
extern BOOLEAN     TestSaveYmmEnabled;

extern ULONGLONG   TestFatalCount;
extern ULONGLONG   TestErrorInjectionCount;
extern ULONGLONG   TestErrorInjectionCalls;
extern ULONG       TestErrorInjectionProb;

extern BYTE TestErrorInjectionSeed[ SYMCRYPT_SHA1_RESULT_SIZE ];

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
//
// These Save/Restore functions are used by user mode SaveXmm and Ymm code, plus the testing code.
//
extern "C" {
VOID SYMCRYPT_CALL SymCryptEnvUmSaveXmmRegistersAsm( __m128i * buffer );
VOID SYMCRYPT_CALL SymCryptEnvUmRestoreXmmRegistersAsm( __m128i * buffer );

VOID SYMCRYPT_CALL SymCryptEnvUmSaveYmmRegistersAsm( __m256i * buffer );
VOID SYMCRYPT_CALL SymCryptEnvUmRestoreYmmRegistersAsm( __m256i * buffer );
}
#endif


VOID
testWipe();

VOID
testUtil();

VOID
testDataAccessors();

VOID
testHashAlgorithms();

VOID
testMacAlgorithms();

VOID
testXofAlgorithms();

VOID
testCustomizableXofAlgorithms();

VOID
testKmacAlgorithms();

VOID
testBlockCipherAlgorithms();

VOID
testKeyWrapAlgorithms();

VOID
testAuthEncAlgorithms();

VOID
testStreamCipherAlgorithms();

VOID
testKdfAlgorithms();

VOID
testXtsAlgorithms();

VOID
testIEEE802_11SaeCustom();

VOID
testTlsCbcHmacAlgorithms();

VOID
testAesCtrDrbg();

VOID
testArithmetic();

VOID
testKem();

VOID
testScsTable();

VOID
testScsTools();

VOID
testPaddingPkcs7();

VOID
testEcc();

VOID
testRsaSignAlgorithms();

VOID
testRsaEncAlgorithms();

VOID
testDhAlgorithms();

VOID
testDsaAlgorithms();

VOID
testPqDsa();

VOID
testStatusIndicator(BOOL);

VOID
testServiceIndicator();

VOID
testHbs();

KatData *
getCustomResource( _In_ PSTR resourceName, _In_ PSTR resourceType );

VOID
randomTestGetSubstringPosition( _In_reads_( bufSize )  PCBYTE buf,
                                                        SIZE_T bufSize,
                                _Inout_                 SIZE_T * idx,
                                _Out_                   SIZE_T * pos,
                                _Out_                   SIZE_T * len );


VOID measurePerf( AlgorithmImplementation * pAlgImp );

VOID measurePerfOfWipe();

VOID initPerfSystem();

VOID testSelftestPerf();

VOID testSelftest();

CHAR charToLower( CHAR c );

#define PERF_WIPE_MAX_SIZE  64
#define PERF_WIPE_N_OFFSETS      16

extern double g_wipePerf[PERF_WIPE_MAX_SIZE+1][PERF_WIPE_N_OFFSETS];


VOID
addAllAlgs();

VOID
addCapiAlgs();

VOID
addCngAlgs();

VOID
addRsa32Algs();

VOID
addMsBignumAlgs();

VOID
addSymCryptAlgs();

VOID
updateSymCryptStaticAlgs();

VOID
addRefAlgs();

VOID
initTestInfrastructure( int argc, _In_reads_( argc ) char * argv[] );

VOID
runFunctionalTests();

VOID
runPerfTests();

VOID
runProfiling();

VOID
exitTestInfrastructure();

//
// Function pointers to deal with various BCrypt versions
//
#if INCLUDE_IMPL_CNG

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDeriveKeyPBKDF2Fn)(
    _In_                            BCRYPT_ALG_HANDLE   hPrf,
    _In_reads_bytes_( cbPassword )       PUCHAR              pbPassword,
    _In_                            ULONG               cbPassword,
    _In_reads_bytes_opt_( cbSalt )       PUCHAR              pbSalt,
    _In_                            ULONG               cbSalt,
    _In_                            ULONGLONG           cIterations,
    _Out_writes_bytes_( cbDerivedKey )    PUCHAR              pbDerivedKey,
    _In_                            ULONG               cbDerivedKey,
    _In_                            ULONG               dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptKeyDerivationFn)(
    _In_        BCRYPT_KEY_HANDLE hKey,
    _In_opt_    BCryptBufferDesc     *pParameterList,
    _Out_writes_bytes_to_(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    _In_        ULONG                cbDerivedKey,
    _Out_       ULONG                *pcbResult,
    _In_        ULONG                dwFlags);

typedef _Must_inspect_result_
NTSTATUS
(WINAPI * BCryptCreateMultiHashFn)(
    _Inout_                                     BCRYPT_ALG_HANDLE   hAlgorithm,
    _Out_                                       BCRYPT_HASH_HANDLE *phHash,
    _In_                                        ULONG               nHashes,
    _Out_writes_bytes_all_opt_(cbHashObject)    PUCHAR              pbHashObject,
    _In_                                        ULONG               cbHashObject,
    _In_reads_bytes_opt_(cbSecret)              PUCHAR              pbSecret,   // optional
    _In_                                        ULONG               cbSecret,   // optional
    _In_                                        ULONG               dwFlags);

typedef _Must_inspect_result_
NTSTATUS
(WINAPI * BCryptProcessMultiOperationsFn)(
    _Inout_                         BCRYPT_HANDLE                   hObject,
    _In_                            BCRYPT_MULTI_OPERATION_TYPE     operationType,
    _In_reads_bytes_(cbOperations)  PVOID                           pOperations,
    _In_                            ULONG                           cbOperations,
    _In_                            ULONG                           dwFlags );

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptOpenAlgorithmProviderFn)(
    _Out_ BCRYPT_ALG_HANDLE *phAlgorithm,
    _In_ LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszImplementation,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptGetPropertyFn)(
    _In_ BCRYPT_HANDLE hObject,
    _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptSetPropertyFn)(
    _Inout_ BCRYPT_HANDLE hObject,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptCloseAlgorithmProviderFn)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptGenerateSymmetricKeyFn)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_ BCRYPT_KEY_HANDLE *phKey,
    _Out_writes_bytes_all_opt_(cbKeyObject) PUCHAR pbKeyObject,
    _In_ ULONG cbKeyObject,
    _In_reads_bytes_(cbSecret) PUCHAR pbSecret,
    _In_ ULONG cbSecret,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptGenerateKeyPairFn)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_ BCRYPT_KEY_HANDLE *phKey,
    _In_ ULONG dwLength,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptEncryptFn)(
    _Inout_ BCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_opt_ VOID *pPaddingInfo,
    _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV,
    _In_ ULONG cbIV,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDecryptFn)(
    _Inout_ BCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_opt_ VOID *pPaddingInfo,
    _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV,
    _In_ ULONG cbIV,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptExportKeyFn)(
    _In_ BCRYPT_KEY_HANDLE hKey,
    _In_opt_ BCRYPT_KEY_HANDLE hExportKey,
    _In_ LPCWSTR pszBlobType,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptImportKeyFn)(
    _In_ BCRYPT_ALG_HANDLE hAlgorithm,
    _In_opt_ BCRYPT_KEY_HANDLE hImportKey,
    _In_ LPCWSTR pszBlobType,
    _Out_ BCRYPT_KEY_HANDLE *phKey,
    _Out_writes_bytes_all_opt_(cbKeyObject) PUCHAR pbKeyObject,
    _In_ ULONG cbKeyObject,
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptImportKeyPairFn)(
    _In_ BCRYPT_ALG_HANDLE hAlgorithm,
    _In_opt_ BCRYPT_KEY_HANDLE hImportKey,
    _In_ LPCWSTR pszBlobType,
    _Out_ BCRYPT_KEY_HANDLE *phKey,
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDuplicateKeyFn)(
    _In_ BCRYPT_KEY_HANDLE hKey,
    _Out_ BCRYPT_KEY_HANDLE *phNewKey,
    _Out_writes_bytes_all_opt_(cbKeyObject) PUCHAR pbKeyObject,
    _In_ ULONG cbKeyObject,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptFinalizeKeyPairFn)(
    _Inout_ BCRYPT_KEY_HANDLE hKey,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDestroyKeyFn)(
    _Inout_ BCRYPT_KEY_HANDLE hKey);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDestroySecretFn)(
    _Inout_ BCRYPT_SECRET_HANDLE hSecret);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptSignHashFn)(
    _In_ BCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID *pPaddingInfo,
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptVerifySignatureFn)(
    _In_ BCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID *pPaddingInfo,
    _In_reads_bytes_(cbHash) PUCHAR pbHash,
    _In_ ULONG cbHash,
    _In_reads_bytes_(cbSignature) PUCHAR pbSignature,
    _In_ ULONG cbSignature,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptSecretAgreementFn)(
    _In_ BCRYPT_KEY_HANDLE hPrivKey,
    _In_ BCRYPT_KEY_HANDLE hPubKey,
    _Out_ BCRYPT_SECRET_HANDLE *phAgreedSecret,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDeriveKeyFn)(
    _In_ BCRYPT_SECRET_HANDLE hSharedSecret,
    _In_ LPCWSTR pwszKDF,
    _In_opt_ BCryptBufferDesc *pParameterList,
    _Out_writes_bytes_to_opt_(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    _In_ ULONG cbDerivedKey,
    _Out_ ULONG *pcbResult,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptHashFn)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _In_reads_bytes_opt_(cbSecret) PUCHAR pbSecret, // for keyed algs
    _In_ ULONG cbSecret, // for keyed algs
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _Out_writes_bytes_all_(cbOutput) PUCHAR pbOutput,
    _In_ ULONG cbOutput);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptCreateHashFn)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_ BCRYPT_HASH_HANDLE *phHash,
    _Out_writes_bytes_all_opt_(cbHashObject) PUCHAR pbHashObject,
    _In_ ULONG cbHashObject,
    _In_reads_bytes_opt_(cbSecret) PUCHAR pbSecret, // optional
    _In_ ULONG cbSecret, // optional
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptHashDataFn)(
    _Inout_ BCRYPT_HASH_HANDLE hHash,
    _In_reads_bytes_(cbInput) PUCHAR pbInput,
    _In_ ULONG cbInput,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptFinishHashFn)(
    _Inout_ BCRYPT_HASH_HANDLE hHash,
    _Out_writes_bytes_all_(cbOutput) PUCHAR pbOutput,
    _In_ ULONG cbOutput,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDuplicateHashFn)(
    _In_ BCRYPT_HASH_HANDLE hHash,
    _Out_ BCRYPT_HASH_HANDLE *phNewHash,
    _Out_writes_bytes_all_opt_(cbHashObject) PUCHAR pbHashObject,
    _In_ ULONG cbHashObject,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDestroyHashFn)(
    _Inout_ BCRYPT_HASH_HANDLE hHash);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptGenRandomFn)(
    _In_opt_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_writes_bytes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ ULONG dwFlags);

typedef _Must_inspect_result_ NTSTATUS
(WINAPI * BCryptDeriveKeyCapiFn)(
    _In_ BCRYPT_HASH_HANDLE hHash,
    _In_opt_ BCRYPT_ALG_HANDLE hTargetAlg,
    _Out_writes_bytes_(cbDerivedKey) PUCHAR pbDerivedKey,
    _In_ ULONG cbDerivedKey,
    _In_ ULONG dwFlags);

extern BCryptDeriveKeyPBKDF2Fn          CngPbkdf2Fn;
extern BCryptKeyDerivationFn            CngKeyDerivationFn;
extern BCryptCreateMultiHashFn          CngCreateMultiHashFn;
extern BCryptProcessMultiOperationsFn   CngProcessMultiOperationsFn;
extern BCryptCloseAlgorithmProviderFn   CngCloseAlgorithmProviderFn;
extern BCryptCreateHashFn               CngCreateHashFn;
extern BCryptDecryptFn                  CngDecryptFn;
extern BCryptDeriveKeyFn                CngDeriveKeyFn;
extern BCryptDeriveKeyCapiFn            CngDeriveKeyCapiFn;
extern BCryptDestroyHashFn              CngDestroyHashFn;
extern BCryptDestroyKeyFn               CngDestroyKeyFn;
extern BCryptDestroySecretFn            CngDestroySecretFn;
extern BCryptDuplicateHashFn            CngDuplicateHashFn;
extern BCryptDuplicateKeyFn             CngDuplicateKeyFn;
extern BCryptEncryptFn                  CngEncryptFn;
extern BCryptExportKeyFn                CngExportKeyFn;
extern BCryptFinalizeKeyPairFn          CngFinalizeKeyPairFn;
extern BCryptFinishHashFn               CngFinishHashFn;
extern BCryptGenerateKeyPairFn          CngGenerateKeyPairFn;
extern BCryptGenerateSymmetricKeyFn     CngGenerateSymmetricKeyFn;
extern BCryptGenRandomFn                CngGenRandomFn;
extern BCryptGetPropertyFn              CngGetPropertyFn;
extern BCryptHashFn                     CngHashFn;
extern BCryptHashDataFn                 CngHashDataFn;
extern BCryptImportKeyFn                CngImportKeyFn;
extern BCryptImportKeyPairFn            CngImportKeyPairFn;
extern BCryptOpenAlgorithmProviderFn    CngOpenAlgorithmProviderFn;
extern BCryptSecretAgreementFn          CngSecretAgreementFn;
extern BCryptSetPropertyFn              CngSetPropertyFn;
extern BCryptSignHashFn                 CngSignHashFn;
extern BCryptVerifySignatureFn          CngVerifySignatureFn;

#endif //SYMCRYPT_MS_VC


extern BOOLEAN g_fExitMultithreadTest;
extern ULONGLONG g_nMultithreadTestsRun;

typedef VOID (SYMCRYPT_CALL * SelfTestFn)();
typedef struct _SELFTEST_INFO
{
    SelfTestFn  f;
    LPSTR       name;
} SELFTEST_INFO;

extern const SELFTEST_INFO g_selfTests[];
// Some selftests require allocations, and we do not support them in KM test driver yet
extern const SELFTEST_INFO g_selfTests_allocating[];

VOID
runTestThread( VOID * seed );

VOID
printHexArray( PCBYTE pData, SIZE_T nElements, SIZE_T elementSize );

#define XMM_SAVE_ERR 4506

extern "C" {
extern ULONG g_nXmmSaves;

VOID
printXmmRegisters( PCSTR text );
}

#define MAX_INT_BITS        (1 << 10)
#define MAX_INT_BYTES       (MAX_INT_BITS/8)

#define PERF_KEY_FLAGS_MASK (0xff000000)

//
// For testing the different moduli types, we signal the type of modulus in the upper bits of the size parameter.
//
#define PERF_KEY_SECRET     0x01000000  // Modulus is secret (Requires generic implementation)
#define PERF_KEY_PUB_ODD    0x02000000  // Modulus parity is public & odd (allows Montgomery reduction)
#define PERF_KEY_PUBLIC     0x03000000  // Modulus is public
#define PERF_KEY_PUB_PM     0x04000000  // Modulus is public & Pseudo-Mersenne
#define PERF_KEY_PUB_NIST   0x05000000  // Modulus is public & NIST curve prime

//
// For testing the different XTS data unit sizes
//
#define PERF_KEY_XTS_DATA_UNIT_512     0x06000000  // 512-byte data unit
#define PERF_KEY_XTS_DATA_UNIT_4096    0x07000000  // 4096-byte data unit

#define PERF_KEY_PRIME      0x80000000  // Modulus is prime (orthogonal to the other flags)

//
// For testing the different internal curves
// The first byte denotes the type of curve while the lower bytes the field length
//
#define PERF_KEY_NIST_CURVE    0x10000000  // NIST curve
#define PERF_KEY_NUMS_CURVE    0x20000000  // NUMS curve
#define PERF_KEY_C255_CURVE    0x30000000  // 25519 curve
#define PERF_KEY_SW_TEST_CURVE 0x40000000  // Short-Weierstrass test curve (curve which is included in test program)

#define PERF_KEY_NIST192    ( PERF_KEY_NIST_CURVE | 24 )
#define PERF_KEY_NIST224    ( PERF_KEY_NIST_CURVE | 28 )
#define PERF_KEY_NIST256    ( PERF_KEY_NIST_CURVE | 32 )
#define PERF_KEY_NIST384    ( PERF_KEY_NIST_CURVE | 48 )
#define PERF_KEY_NIST521    ( PERF_KEY_NIST_CURVE | 66 )

#define PERF_KEY_NUMS256    ( PERF_KEY_NUMS_CURVE | 32 )
#define PERF_KEY_NUMS384    ( PERF_KEY_NUMS_CURVE | 48 )
#define PERF_KEY_NUMS512    ( PERF_KEY_NUMS_CURVE | 64 )

#define PERF_KEY_C255_19    ( PERF_KEY_C255_CURVE | 32 )

#define PERF_KEY_W22519     ( PERF_KEY_SW_TEST_CURVE | 32 )
#define PERF_KEY_W448       ( PERF_KEY_SW_TEST_CURVE | 56 )

#define PERF_KEY_XMSS_SHA2_10_256       (SYMCRYPT_XMSS_SHA2_10_256)
#define PERF_KEY_XMSS_SHA2_16_256       (SYMCRYPT_XMSS_SHA2_16_256)
#define PERF_KEY_XMSS_SHA2_20_256       (SYMCRYPT_XMSS_SHA2_20_256)
#define PERF_KEY_XMSS_SHA2_10_512       (SYMCRYPT_XMSS_SHA2_10_512)
#define PERF_KEY_XMSS_SHA2_16_512       (SYMCRYPT_XMSS_SHA2_16_512)
#define PERF_KEY_XMSS_SHA2_20_512       (SYMCRYPT_XMSS_SHA2_20_512)
#define PERF_KEY_XMSS_SHAKE256_10_256   (SYMCRYPT_XMSS_SHAKE256_10_256)
#define PERF_KEY_XMSS_SHAKE256_16_256   (SYMCRYPT_XMSS_SHAKE256_16_256)
#define PERF_KEY_XMSS_SHAKE256_20_256   (SYMCRYPT_XMSS_SHAKE256_20_256)

#define PERF_KEY_LMOTS_MASK 0xff000000
#define PERF_KEY_LMOTS_W1   0x01000000
#define PERF_KEY_LMOTS_W2   0x02000000
#define PERF_KEY_LMOTS_W4   0x04000000
#define PERF_KEY_LMOTS_W8   0x08000000

#define PERF_KEY_LMS_SHA256_M32_H5_W1   (SYMCRYPT_LMS_SHA256_M32_H5 | PERF_KEY_LMOTS_W1)
#define PERF_KEY_LMS_SHA256_M32_H5_W2   (SYMCRYPT_LMS_SHA256_M32_H5 | PERF_KEY_LMOTS_W2)
#define PERF_KEY_LMS_SHA256_M32_H5_W4   (SYMCRYPT_LMS_SHA256_M32_H5 | PERF_KEY_LMOTS_W4)
#define PERF_KEY_LMS_SHA256_M32_H5_W8   (SYMCRYPT_LMS_SHA256_M32_H5 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHA256_M32_H10_W8  (SYMCRYPT_LMS_SHA256_M32_H10 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHA256_M32_H15_W8  (SYMCRYPT_LMS_SHA256_M32_H15 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHA256_M32_H20_W8  (SYMCRYPT_LMS_SHA256_M32_H20 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHA256_M32_H25_W8  (SYMCRYPT_LMS_SHA256_M32_H25 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHAKE_M32_H5_W8    (SYMCRYPT_LMS_SHAKE_M32_H5 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHAKE_M32_H10_W8   (SYMCRYPT_LMS_SHAKE_M32_H10 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHAKE_M32_H15_W8   (SYMCRYPT_LMS_SHAKE_M32_H15 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHAKE_M32_H20_W8   (SYMCRYPT_LMS_SHAKE_M32_H20 | PERF_KEY_LMOTS_W8)
#define PERF_KEY_LMS_SHAKE_M32_H25_W8   (SYMCRYPT_LMS_SHAKE_M32_H25 | PERF_KEY_LMOTS_W8)


//
// For testing ML-KEM parameters. These are not the key sizes, but refer to the different
// ML-KEM parameter sets defined in FIPS 203.
//
#define PERF_KEY_MLKEM_512  (512 / 8)   // ML-KEM-512
#define PERF_KEY_MLKEM_768  (768 / 8)   // ML-KEM-768
#define PERF_KEY_MLKEM_1024 (1024 / 8)  // ML-KEM-1024

//
// ML-DSA parameters. As with ML-KEM, these are not actual key sizes, but ML-KEM parameter sets.
//
#define PERF_KEY_MLDSA_44   (44)   // ML-DSA-44
#define PERF_KEY_MLDSA_65   (65)   // ML-DSA-65
#define PERF_KEY_MLDSA_87   (87)   // ML-DSA-87

PCBYTE
getPerfTestModulus( UINT32 exKeySize );

//
// Checked alloc definitions
//
extern volatile INT64 g_nOutstandingCheckedAllocs;  // Global to track the number of outstanding allocations
extern volatile INT64 g_nAllocs;                    // Global to track the number of allocations (only in single threaded runs)

extern volatile INT64 g_nOutstandingCheckedAllocsMsBignum;
extern volatile INT64 g_nAllocsMsBignum;

VOID SYMCRYPT_CALL AllocWithChecksInit();

PVOID SYMCRYPT_CALL AllocWithChecksSc( SIZE_T nBytes );
VOID FreeWithChecksSc( PVOID ptr );

PVOID SYMCRYPT_CALL AllocWithChecksMsBignum( SIZE_T nBytes );
VOID FreeWithChecksMsBignum( PVOID ptr );

////////
//
// Elliptic Curve parameters we want to test against but do not yet want to include in production binaries
//
////////

// As we have introduced NIST-prime specific SW code, we now need to test SW curves which
// are not NIST prime curves to catch any bugs with the non-specialized codepaths.

// W25519 from SP800-186; this is isomorphic to Curve25519, but is in SW form rather
// than Montgomery form. It should not be used in any real use case, but is helpful
// for testing
static const BYTE rgbW25519[] = {
    //dwVersion
    0x01, 0x00, 0x00, 0x00,
    //dwCurveType
    0x01, 0x00, 0x00, 0x00,
    //dwCurveGenerationAlgId
    0x00, 0x00, 0x00, 0x00,
    //cbFieldLength
    0x20, 0x00, 0x00, 0x00,
    //cbSubgroupOrder
    0x20, 0x00, 0x00, 0x00,
    //cbCofactor
    0x01, 0x00, 0x00, 0x00,
    //cbSeed
    0x00, 0x00, 0x00, 0x00,
    //p
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
    //A
    0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0x98, 0x49, 0x14, 0xA1, 0x44,
    //B
    0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED,
    0x09, 0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25,
    0xED, 0x09, 0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4,
    0x26, 0x0B, 0x5E, 0x9C, 0x77, 0x10, 0xC8, 0x64,
    //x
    0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAD, 0x24, 0x5A,
    //y
    0x5F, 0x51, 0xE6, 0x5E, 0x47, 0x5F, 0x79, 0x4B,
    0x1F, 0xE1, 0x22, 0xD3, 0x88, 0xB7, 0x2E, 0xB3,
    0x6D, 0xC2, 0xB2, 0x81, 0x92, 0x83, 0x9E, 0x4D,
    0xD6, 0x16, 0x3A, 0x5D, 0x81, 0x31, 0x2C, 0x14,
    //q
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
    //h
    0x08,
};
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsW25519 = (PCSYMCRYPT_ECURVE_PARAMS) rgbW25519;

// W448 from SP800-186; this is isomorphic to Curve448, but is in SW form rather
// than Montgomery form. It should not be used in any real use case, but is helpful
// for testing
static const BYTE rgbW448[] = {
    //dwVersion
    0x01, 0x00, 0x00, 0x00,
    //dwCurveType
    0x01, 0x00, 0x00, 0x00,
    //dwCurveGenerationAlgId
    0x00, 0x00, 0x00, 0x00,
    //cbFieldLength
    0x38, 0x00, 0x00, 0x00,
    //cbSubgroupOrder
    0x38, 0x00, 0x00, 0x00,
    //cbCofactor
    0x01, 0x00, 0x00, 0x00,
    //cbSeed
    0x00, 0x00, 0x00, 0x00,
    //p
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    //A
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xA9, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0x1A, 0x76, 0xD4, 0x1F,
    //B
    0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED, 0x09, 0x7B,
    0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED, 0x09,
    0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED,
    0x09, 0x7B, 0x42, 0x5E, 0x71, 0xC7, 0x1C, 0x71,
    0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C,
    0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7,
    0x1C, 0x72, 0xC8, 0x7B, 0x7C, 0xC6, 0x9F, 0x70,
    //x
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0x91,
    //y
    0x7D, 0x23, 0x5D, 0x12, 0x95, 0xF5, 0xB1, 0xF6,
    0x6C, 0x98, 0xAB, 0x6E, 0x58, 0x32, 0x6F, 0xCE,
    0xCB, 0xAE, 0x5D, 0x34, 0xF5, 0x55, 0x45, 0xD0,
    0x60, 0xF7, 0x5D, 0xC2, 0x8D, 0xF3, 0xF6, 0xED,
    0xB8, 0x02, 0x7E, 0x23, 0x46, 0x43, 0x0D, 0x21,
    0x13, 0x12, 0xC4, 0xB1, 0x50, 0x67, 0x7A, 0xF7,
    0x6F, 0xD7, 0x22, 0x3D, 0x45, 0x7B, 0x5B, 0x1A,
    //q
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
    0xC4, 0x4E, 0xDB, 0x49, 0xAE, 0xD6, 0x36, 0x90,
    0x21, 0x6C, 0xC2, 0x72, 0x8D, 0xC5, 0x8F, 0x55,
    0x23, 0x78, 0xC2, 0x92, 0xAB, 0x58, 0x44, 0xF3,
    //h
    0x04,
};
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsW448 = (PCSYMCRYPT_ECURVE_PARAMS) rgbW448;

// Table with the internal curves' parameters and the mapping to PERF_KEYs
const struct {
    UINT32                      exKeyParam;
    PCSYMCRYPT_ECURVE_PARAMS    pParams;
} g_exKeyToCurve[] = {
    { PERF_KEY_NIST192, SymCryptEcurveParamsNistP192 },
    { PERF_KEY_NIST224, SymCryptEcurveParamsNistP224 },
    { PERF_KEY_NIST256, SymCryptEcurveParamsNistP256 },
    { PERF_KEY_NIST384, SymCryptEcurveParamsNistP384 },
    { PERF_KEY_NIST521, SymCryptEcurveParamsNistP521 },

    { PERF_KEY_NUMS256, SymCryptEcurveParamsNumsP256t1 },
    { PERF_KEY_NUMS384, SymCryptEcurveParamsNumsP384t1 },
    { PERF_KEY_NUMS512, SymCryptEcurveParamsNumsP512t1 },

    { PERF_KEY_C255_19, SymCryptEcurveParamsCurve25519 },

    { PERF_KEY_W22519, SymCryptEcurveParamsW25519 },
    { PERF_KEY_W448,   SymCryptEcurveParamsW448   },
};

#define NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS   (100)

VOID
testMontgomery(PSYMCRYPT_ECURVE  pCurve);

template<class Implementation>
VOID
addRsaKeyGenPerfSymCrypt( PrintTable &table );

VOID
addRsaKeyGenPerfMsBignum( PrintTable &table );

// Constants for RSA performance tests (OAEP, PKCS1, PSS modes)
#define PERF_RSA_PKCS1_LESS_BYTES           (11)

#define PERF_RSA_LABEL_LENGTH               (8)
#define PERF_RSA_SALT_LENGTH                (8)

#define PERF_RSA_HASH_ALG_SC                (ScShimSymCryptSha256Algorithm)
#define PERF_RSA_HASH_ALG_CNG               (BCRYPT_SHA256_ALGORITHM)
#define PERF_RSA_HASH_ALG_SIZE              (SYMCRYPT_SHA256_RESULT_SIZE)
#define PERF_RSA_HASH_ALG_OIDS_SC           (ScShimSymCryptSha256OidList)
#define PERF_RSA_HASH_ALG_NOIDS_SC          (SYMCRYPT_SHA256_OID_COUNT)

#define PERF_RSA_OAEP_LESS_BYTES            (2 + 2*SYMCRYPT_SHA256_RESULT_SIZE)


#define MAX_RSA_TESTKEYS    (50)
extern RSAKEY_TESTBLOB g_RsaTestKeyBlobs[ MAX_RSA_TESTKEYS ];
extern UINT32 g_nRsaTestKeyBlobs;

#define MAX_TEST_DLGROUPS   (60)
extern DLGROUP_TESTBLOB g_DlGroup[ MAX_TEST_DLGROUPS ];
extern UINT32 g_nDlgroups;
extern UINT32 g_nDhNamedGroups;

VOID
fprintHex( FILE * f, PCBYTE pbData, SIZE_T cbData );

VOID rsaTestKeysGenerate();

PSYMCRYPT_RSAKEY
rsaKeyFromTestBlob( PCRSAKEY_TESTBLOB pBlob );

PSYMCRYPT_RSAKEY
rsaTestKeyRandom();

PSYMCRYPT_RSAKEY
rsaTestKeyForSize( SIZE_T nBits );

PCDLGROUP_TESTBLOB
dlgroupForSize( SIZE_T nBits, BOOLEAN forDiffieHellman );

VOID generateDlGroups();

template<class Implementation>
PSYMCRYPT_DLGROUP
dlgroupObjectFromTestBlob( PCDLGROUP_TESTBLOB pBlob );  // Must free object after use

VOID
ReverseMemCopy( PBYTE pbDst, PCBYTE pbSrc, SIZE_T cbSrc );

BOOL
SYMCRYPT_CALL
RefIsPrime(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );
