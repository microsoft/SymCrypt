# Version x.y.z
New changes will be listed here as they are developed. The version number is determined
prior to the creation of a new release, based on the changes contained in that release.


- Added Rust implementations of ML-KEM and SHA3
- Rust AES-GCM work in progress: XMM implementation is staged in the tree but is not enabled yet

# Version 103.12.1

- Add ZMM (AVX512) implementation of AES-GCM: improves performance by up to 35% on supported hardware
- Add YMM (AVX256) implementation of AES-CBC: improves performance by up to 45% on supported hardware

# Version 103.12.0

- Add loop bounds to ML-DSA functions which use probabilistic sampling, as defense-in-depth against denial of service by maliciously formed keys
  - There is no known vulnerability associated with this, but adding upper bounds provides additional hardening
  - Also fixes [#55](https://github.com/microsoft/SymCrypt/issues/55); thanks to Sunwoo Lee and Seunghyun Yoon, Korea Institute of Energy Technology (KENTECH) for filing this issue
- Add Elevated Debugger environment
- Add Composite ML-DSA implementation
- Added `SymCryptModuleInitEx` function and `SYMCRYPT_MODULE_INIT_EX` macro. Unlike `SymCryptModuleInit` which calls `SymCryptFatal` on version mismatch, `SymCryptModuleInitEx` returns `SYMCRYPT_INVALID_ARGUMENT`, allowing callers to handle the error gracefully.
- Removed enforcement of minimum hash collision strength for HashML-DSA. Per PQC forum discussions, FIPS 204 recommends that hash algorithms used in HashML-DSA should provide collision resistance at least equal to lambda, but this is a recommendation to the caller, not a requirement for the implementation.

# Version 103.11.0

- Add Composite ML-KEM implementation
- Fix heap buffer overflow in `SymCryptXmssSign` when signing with XMSS^MT parameter sets with a height of 32 or greater
  - Thanks to [Federico Ponzi](https://fponzi.me) for finding this

# Version 103.10.2

- Removed unimplemented function `SymCryptModulusBitsizeOfObject` from `symcrypt_low_level.h`
- Update service indicator
- Replace XMSS self-test with XMSS^MT self-test

# Version 103.10.1

- Remove FIPS PCTs on keypair import
- Removed usage of datatypes with platform-dependent sizes where appropriate to ensure structure/parameter sizes are consistent across platforms
- Added ARM64 ASM support for macOS
- Allow building for unrecognized platforms (e.g. embedded systems)
  - Any platform not listed in [BUILD.md](BUILD.md) is still not officially supported
- Additional minor changes

# Version 103.10.0

- Fixed [#51](https://github.com/microsoft/SymCrypt/issues/51): Added accessor functions for `extern const` data symbols to prevent error `LNK2001` when dynamic linking on Windows

# Version 103.9.1

- Fixed [#48](https://github.com/microsoft/SymCrypt/issues/48): Fix minor interop issue in RSA PKCS1
- Removed dependency on external randomness in ECDSA self-test
- Add FIPS CAST for ML-DSA and pairwise consistency tests for ML-KEM and ML-DSA on key generation

# Version 103.9.0

- Add support for ML-DSA Sign and Verify with External Mu

# Version 103.8.1

- LMS/XMSS fixes
- Build fix for Clang 18+ libc++
- Add dynamic library for macOS

# Version 103.8.0

- Add FIPS approved services indicator

# Version 103.7.0

- Add ML-DSA implementation

# Version 103.6.0

- Add LMS implementation
- Add AES-KW(P) implementation
- Add SHA224, SHA512/224, SHA512/256, and SHA3-224
- Add SymCryptRsakeySetValueFromPrivateExponent
- Fixed a regression in v103.5.0 which erroneously caused a fastfail in FIPS self-test when importing an invalid keypair

# Version 103.5.1

- Additional internal self-test changes to support FIPS 140-3 certification
- Fixed a regression in v103.5.0 which caused FIPS self-tests to be erroneously executed when importing an RSA public key, resulting in a fastfail
- Added parameter validation/removed unnecessary assertions in ECDSA functions to reduce sharp edges

# Version 103.5.0

- Internal self-test changes to support FIPS 140-3 certification
- Add SSKDF implementation
- Add XMSS and XMSS^MT implementations
- Add ML-KEM per final FIPS 203

# Version 103.4.3

- Added preliminary support for macOS (static libraries and unit tests only, no ASM optimizations)
- Performance improvements for RSA for modern Arm64 microarchitecture

# Version 103.4.2

- Add SymCryptEntropyAccumulator to Windows kernel module
- Fix tweak lower 64 bit overflow calculation in SYMCRYPT_XtsAesXxx
- Add OpenSSL implementation for XtsAes and AesGcm to symcryptunittest
- Add OpenSSL implementation for RSA PSS to symcryptunittest
- Add Windows user mode DLL
- Fixed debug assertion failure in AES-GCM with nonce < 12 bytes when ASM is disabled

# Version 103.4.1
- Add retpoline guard flags for undocked Windows build
- Add Windows kernel mode DLL
- Support ARM32 for Linux

# Version 103.4.0

- Extended SymCrypt support for XTS-AES adding support for 128-bit tweak and ciphertext-stealing
- Added support for salt length detection in RSA-PSS verification
- Export various constant time operations from SymCrypt Linux modules
- Added support for nonce sizes other than 12 bytes for AES-GCM
- Add FIPS status indicator

# Version 103.3.2

- Performance improvements for ECC NIST prime curves
- Performance improvements for modular arithmetic
- Added maximum iteration count for (Ec)Dsa signing
- Additional checks for OS support of AVX512 registers on Windows
- Various build system tweaks

# Version 103.3.1

- Temporarily disable use of AVX in SHA-2

# Version 103.3.0

- Add SymCryptEcurveCreate and SymCryptEcurveBufferSizesFromParams
- Address some problems with building for 32-bit platforms
- Update documentation around exceptions
- Fix some Windows test module issues

# Version 103.2.0

- Add HMAC-SHA-3 implementations

# Version 103.1.0

- Add SHA-3 based algorithms: SHAKE, cSHAKE, KMAC

# Version 103.0.1

- Linux RNG improvements and additional testing

# Version 103.0.0

- Add SRTP-KDF and SSH-KDF implementations
- Add optimized SHA-2 implementations
- Add SHA-3 implementation
- Fix integer truncation issue in 32-bit Linux builds
- Refactor CMake files to simplify build steps and increase flexibility
- Fix bug for SymCryptRsakeyGenerate for encrypt-only keys
- Create and test against simple SymCrypt Windows test module (DLL)
- Remove the module export of g_SymCryptFipsSelftestsPerformed and replace it with SymCryptFipsGetSelftestsPerformed
- Enable SymCrypt unit tests to drive a dynamically-linked module
- Fix unit test failure importing DH key to CNG
- Removed Linux embedded module, as generic ARM64 module is the same
- Rejig CPUID logic for VAES and AVX
- Disable AVX2 in Windows boot environment

# Version 102.0.0

- Breaking change to Asymmetric key generation and import handling, sanitizing flags required for FIPS
- Trim symbols exposed in SymCrypt module to those specified in symcrypt.h
- Introduce logic enabling FIPS per-key tests to be deferred to before first use, rather than at generation time

# Version 101.3.0

- Fix for OpenEnclave binary to workaround clang bug
- Fix SymCryptRsaPssVerify to return SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE for invalid signatures, rather than SYMCRYPT_INVALID_ARGUMENT
- Fix for SymCryptShortWeierstrassAddSideChannelUnsafe which is only use in ECDSA verification on SW curves
  - An owner of a private ECC key could create an invalid signature that SymCrypt would verify, leaking their private key in the process

# Version 101.2.0

- Added key pairwise consistency tests for RSA, DSA, DH, ECDSA and ECDH key generation, per FIPS 140-3 requirements
- Added Session APIs for AES-GCM
  - For Encryption, this enables multithreaded IV generation within the SymCrypt FIPS boundary
  - For Decryption, this enables multithreaded replay protection detecting reuse of IVs in received messages

# Version 101.1.0

- Support for Group 20 in SAE method

# Version 101.0.0

- Support stable ABI: change SYMCRYPT_ERROR definition so that error values no longer change with version changes
- Support proper shared library versioning in CMake build scripts
- Support for FIPS integrity verification on ARM64
- Additional CMake build system changes

# Version 100.21

- Fix bug in SymCryptDlkeySizeofPrivateKey
- Add SymCryptDlkeySetPrivateKeyLength API
- Add SymCryptHkdfExtractPrk API
- Add SP800-108 self tests for HMAC-SHA512
- Use _mmXXX_storeu_siXXX intrinsics in AES-XTS w/VAES
- Add macros for volatile memory access to avoid MSVC C4746 warning in unit tests